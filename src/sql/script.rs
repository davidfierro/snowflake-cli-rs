//! Runs the statements of one `snow sql` run as one session (ADR 0004, Decisions 1, 3 and 5).
//!
//! Several statements go out as **one** multi-statement request, so `USE`, variables, temporary
//! tables and transactions carry over as in `snow`. The parent answers once every statement has
//! run; each child's result is then read with its own GET, the first GETs prefetched
//! concurrently and taken in order (Amendment 1), and streamed through [`RowStream`], one
//! statement at a time. A single statement takes the plain path (`SqlClient::query`).

use super::SqlClient;
use super::client::{Inner, Posted, has_ltz, malformed, started, time_zone_from};
use super::prefetch::{CHILD_PREFETCH_WINDOW, Prefetch};
use super::stream::RowStream;
use super::wire::StatementResponse;
use crate::error::{Error, ErrorKind, Result};
use crate::script::split::split_statements;
use jiff::tz::TimeZone;
use std::sync::Arc;

/// Hidden statement added first with [`ScriptOptions::autocommit_off`].
const AUTOCOMMIT_OFF: &str = "ALTER SESSION SET AUTOCOMMIT = FALSE;";
/// Hidden statement added after a user statement that may change the session time zone.
const SHOW_TIMEZONE: &str = "SHOW PARAMETERS LIKE 'TIMEZONE' IN SESSION;";
/// Server code of a multi-statement count mismatch (A1).
const COUNT_MISMATCH: &str = "000008";
/// Server code of a failed multi-statement request (A5).
const MULTI_FAILED: &str = "100132";

#[derive(Debug, Clone, Default)]
pub struct ScriptOptions {
    /// Adds the hidden `ALTER SESSION SET AUTOCOMMIT = FALSE` (Decision 6).
    pub autocommit_off: bool,
    /// `ALL` or `NONE`: adds a hidden `USE SECONDARY ROLES …` first, so the session has the
    /// secondary roles snow sets at sign-in (the SQL API has no sign-in to carry them).
    pub secondary_roles: Option<&'static str>,
}

/// What a statement in the request is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    User,
    SecondaryRoles,
    AutocommitOff,
    ShowTimezone,
}

/// One statement of the request text.
struct Sent<'a> {
    text: &'a str,
    kind: Kind,
}

/// One step of a run, in request order.
enum Step {
    /// A user statement whose result is read from its child handle.
    Child(String),
    /// A user statement already run on the plain path.
    Ready(RowStream),
    /// A hidden `SHOW PARAMETERS LIKE 'TIMEZONE'`: its child sets the zone of what follows.
    Zone(String),
    /// The failing statement.
    Fail(Error),
}

/// The results of a run, one per user statement, in order.
pub struct ScriptRun {
    inner: Arc<Inner>,
    steps: std::vec::IntoIter<Step>,
    /// The first GETs of the `Child` and `Zone` steps, in step order.
    prefetch: Prefetch,
    /// Zone from the closest hidden `SHOW` so far.
    zone: Option<TimeZone>,
    /// Zone from a separate request, fetched at most once, only for an LTZ column.
    default_zone: Option<TimeZone>,
    done: bool,
}

impl SqlClient {
    /// Runs `statements` as one session (Decision 1) and returns once the request has finished.
    /// `Err` only when nothing ran or what ran cannot be told (auth, HTTP, count mismatch, a
    /// non-SQL failure of the single-statement path, the fallback of Decision 5). A failure of
    /// statement k comes out of [`ScriptRun`] at k.
    pub fn run_script(&self, statements: &[String], options: &ScriptOptions) -> Result<ScriptRun> {
        let mut sent = Vec::new();
        let use_secondary_roles = options
            .secondary_roles
            .map(|roles| format!("USE SECONDARY ROLES {roles};"));
        if let Some(text) = &use_secondary_roles {
            sent.push(Sent {
                text,
                kind: Kind::SecondaryRoles,
            });
        }
        if options.autocommit_off {
            sent.push(Sent {
                text: AUTOCOMMIT_OFF,
                kind: Kind::AutocommitOff,
            });
        }
        for (i, text) in statements.iter().enumerate() {
            sent.push(Sent {
                text,
                kind: Kind::User,
            });
            // The zone after the last statement would be read by nobody.
            // Deliberately broad (ADR 0004): a zone change can sit inside a string literal, as in
            // `EXECUTE IMMEDIATE 'ALTER SESSION SET TIMEZONE = ...'`, so a narrower match would
            // miss real changes. A false positive costs one hidden statement in this same
            // multi-statement request, not a round trip.
            if i + 1 < statements.len() && text.to_ascii_uppercase().contains("TIMEZONE") {
                sent.push(Sent {
                    text: SHOW_TIMEZONE,
                    kind: Kind::ShowTimezone,
                });
            }
        }
        let steps = self.run_sent(&sent)?;
        let handles = steps
            .iter()
            .filter_map(|step| match step {
                Step::Child(handle) | Step::Zone(handle) => Some(handle.clone()),
                Step::Ready(_) | Step::Fail(_) => None,
            })
            .collect();
        Ok(ScriptRun {
            prefetch: Prefetch::new(&self.inner, handles, CHILD_PREFETCH_WINDOW),
            inner: Arc::clone(&self.inner),
            steps: steps.into_iter(),
            zone: None,
            default_zone: None,
            done: false,
        })
    }

    /// One statement on the plain path, several as one multi-statement request.
    fn run_sent(&self, sent: &[Sent<'_>]) -> Result<Vec<Step>> {
        match sent {
            [] => Ok(Vec::new()),
            // A hidden statement alone has no session to act on.
            [single] if single.kind != Kind::User => Ok(Vec::new()),
            [single] => match self.query(single.text) {
                Ok(stream) => Ok(vec![Step::Ready(stream)]),
                Err(err) if err.kind() == ErrorKind::Sql => Ok(vec![Step::Fail(err)]),
                Err(err) => Err(err),
            },
            _ => self.run_multi(sent),
        }
    }

    /// A request rejected before anything ran (a syntax error: A14): the statements before the
    /// one at the error's line run as a request, then that one alone, so its error is the one
    /// `snow` prints; if it unexpectedly succeeds, the rest follows as another request.
    fn run_around(&self, sent: &[Sent<'_>], failing: usize) -> Result<Vec<Step>> {
        let mut steps = self.run_sent(&sent[..failing])?;
        if matches!(steps.last(), Some(Step::Fail(_))) {
            return Ok(steps);
        }
        let alone = self.run_sent(&sent[failing..=failing])?;
        let failed = matches!(alone.last(), Some(Step::Fail(_)));
        steps.extend(alone);
        if !failed {
            steps.extend(self.run_sent(&sent[failing + 1..])?);
        }
        Ok(steps)
    }

    fn run_multi(&self, sent: &[Sent<'_>]) -> Result<Vec<Step>> {
        let request = request_text(sent);
        match self.inner.post(&request, Some(sent.len()))? {
            Posted::Done(response) => {
                let handles = response.statement_handles.unwrap_or_default();
                if handles.len() != sent.len() {
                    return Err(malformed("statementHandles do not match the statements"));
                }
                Ok(steps_for(sent, handles, None))
            }
            Posted::Rejected(response, err) => match response.code.as_deref() {
                Some(COUNT_MISMATCH) => Err(count_mismatch(&response, sent.len())),
                Some(MULTI_FAILED) => {
                    let parent = response.statement_handle.clone().unwrap_or_default();
                    match self.locate_failure(&parent, sent) {
                        Ok(Some((ran, failed))) => {
                            let error = self.child_error(&failed)?;
                            Ok(steps_for(sent, ran, Some(error)))
                        }
                        Ok(None) | Err(_) => Err(unwrapped(&response)),
                    }
                }
                _ => match failing_statement(sent, response.message.as_deref()) {
                    Some(failing) => self.run_around(sent, failing),
                    None => Err(err),
                },
            },
        }
    }

    /// Decision 5: finds which child failed from the parent's session history. Returns the
    /// query ids of the statements that ran, in order, and the failing one's id.
    fn locate_failure(
        &self,
        parent: &str,
        sent: &[Sent<'_>],
    ) -> Result<Option<(Vec<String>, String)>> {
        if parent.is_empty() || !parent.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
            return Ok(None);
        }
        let session = self.rows(&format!(
            "SELECT SESSION_ID FROM TABLE(SNOWFLAKE.INFORMATION_SCHEMA.QUERY_HISTORY_BY_USER(\
             END_TIME_RANGE_START => DATEADD('minute', -10, CURRENT_TIMESTAMP()), \
             RESULT_LIMIT => 10000)) WHERE QUERY_ID = '{parent}'"
        ))?;
        let Some(session) = session
            .first()
            .and_then(|r| r.first().cloned().flatten())
            .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()))
        else {
            return Ok(None);
        };
        let history = self.rows(&format!(
            "SELECT QUERY_ID, QUERY_TEXT, EXECUTION_STATUS FROM \
             TABLE(SNOWFLAKE.INFORMATION_SCHEMA.QUERY_HISTORY_BY_SESSION(SESSION_ID => {session}, \
             RESULT_LIMIT => 10000)) ORDER BY START_TIME"
        ))?;
        Ok(match_history(sent, &history, parent))
    }

    /// All rows of a metadata query, as text.
    fn rows(&self, sql: &str) -> Result<Vec<Vec<Option<String>>>> {
        let started = self.inner.start(sql)?;
        RowStream::new(Arc::clone(&self.inner), started, None, None)
            .into_raw()
            .collect()
    }

    /// The failed child's own error (A7), as `snow`'s panel text.
    fn child_error(&self, handle: &str) -> Result<Error> {
        let response = match self.inner.get_statement(handle)? {
            Posted::Done(response) | Posted::Rejected(response, _) => response,
        };
        Ok(child_failure(&response, handle))
    }
}

/// The statements joined with `\n`; one that does not end with `;` gets `\n;` (Decision 1).
fn request_text(sent: &[Sent<'_>]) -> String {
    let mut text = String::new();
    for (i, s) in sent.iter().enumerate() {
        if i > 0 {
            text.push('\n');
        }
        text.push_str(s.text);
        if !s.text.ends_with(';') {
            text.push_str("\n;");
        }
    }
    text
}

/// The statement at the line named by a `syntax error line L at position P` message, counted
/// in the request text.
fn failing_statement(sent: &[Sent<'_>], message: Option<&str>) -> Option<usize> {
    let rest = message?.split_once(" line ")?.1;
    let line: usize = rest.split(' ').next()?.parse().ok()?;
    let mut start = 1usize;
    let mut failing = None;
    for (i, s) in sent.iter().enumerate() {
        if start > line {
            break;
        }
        failing = Some(i);
        start += s.text.matches('\n').count() + 1 + usize::from(!s.text.ends_with(';'));
    }
    failing
}

/// The steps of a run whose first `ids.len()` statements ran; `failure`, if any, is the next.
fn steps_for(sent: &[Sent<'_>], ids: Vec<String>, failure: Option<Error>) -> Vec<Step> {
    let mut steps: Vec<Step> = sent
        .iter()
        .zip(ids)
        .filter_map(|(s, id)| match s.kind {
            Kind::User => Some(Step::Child(id)),
            Kind::ShowTimezone => Some(Step::Zone(id)),
            Kind::AutocommitOff | Kind::SecondaryRoles => None,
        })
        .collect();
    steps.extend(failure.map(Step::Fail));
    steps
}

/// Statement text for matching: comments removed, whitespace collapsed, a final `;` dropped.
fn normalize(text: &str) -> String {
    let pieces: Vec<String> = split_statements(text, true)
        .into_iter()
        .map(|p| p.text)
        .collect();
    let joined = pieces.join(" ");
    let collapsed = joined.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed
        .strip_suffix(';')
        .map_or(collapsed.clone(), |s| s.trim_end().to_string())
}

/// Matches the sent statements to the history rows (`QUERY_ID`, `QUERY_TEXT`,
/// `EXECUTION_STATUS`) in order, by normalised text; rows that match nothing are skipped.
/// Returns the ids of the statements before the first one not `SUCCESS`, and its id.
fn match_history(
    sent: &[Sent<'_>],
    history: &[Vec<Option<String>>],
    parent: &str,
) -> Option<(Vec<String>, String)> {
    let mut rows = history.iter().filter_map(|row| match row.as_slice() {
        [Some(id), text, status] if id != parent => Some((
            id.clone(),
            normalize(text.as_deref().unwrap_or_default()),
            status.as_deref().unwrap_or_default(),
        )),
        _ => None,
    });
    let mut ran = Vec::new();
    for s in sent {
        let wanted = normalize(s.text);
        let (id, _, status) = rows.by_ref().find(|(_, text, _)| *text == wanted)?;
        if status != "SUCCESS" {
            return Some((ran, id));
        }
        ran.push(id);
    }
    None
}

/// `<code> (<sqlState>): <id>: <message>`, without ` (<sqlState>)` when the server gives none.
fn child_failure(response: &StatementResponse, handle: &str) -> Error {
    let code = response.code.as_deref().unwrap_or_default();
    let message = response.message.as_deref().unwrap_or("no error message");
    let id = response.statement_handle.as_deref().unwrap_or(handle);
    let text = match response.sql_state.as_deref().filter(|s| !s.is_empty()) {
        Some(state) => format!("{code} ({state}): {id}: {message}"),
        None => format!("{code}: {id}: {message}"),
    };
    Error::new(ErrorKind::Sql, text)
}

/// The Decision 5 fallback: the parent's error without the `SYSTEM$MULTISTMT` wrapper.
fn unwrapped(response: &StatementResponse) -> Error {
    let message = response.message.as_deref().unwrap_or("no error message");
    let inner = message
        .split_once(").\n")
        .map(|(_, rest)| rest)
        .and_then(|rest| rest.split_once(" in SYSTEM$MULTISTMT at ").map(|(m, _)| m))
        .unwrap_or(message);
    Error::new(
        ErrorKind::Sql,
        format!(
            "{MULTI_FAILED} ({}): {}: {inner}",
            response.sql_state.as_deref().unwrap_or("P0000"),
            response.statement_handle.as_deref().unwrap_or_default()
        ),
    )
}

/// A1: the server split the request differently from the crate.
fn count_mismatch(response: &StatementResponse, client: usize) -> Error {
    let message = response.message.as_deref().unwrap_or_default();
    let server = message
        .strip_prefix("Actual statement count ")
        .and_then(|rest| rest.split(' ').next())
        .unwrap_or("?");
    Error::new(
        ErrorKind::Client,
        format!(
            "The server split the SQL into a different number of statements than snow-rs did \
             ({server} vs {client}). Please report this input."
        ),
    )
}

impl ScriptRun {
    /// The `RowStream` of a finished child.
    fn child(&mut self, handle: &str) -> Result<RowStream> {
        let response = match self.prefetch.take()? {
            Posted::Done(response) => response,
            Posted::Rejected(_, err) => return Err(err),
        };
        if response.result_set_meta_data.is_none() && response.code.is_some() {
            return Err(child_failure(&response, handle));
        }
        let started = started(response)?;
        let zone = if has_ltz(&started.columns) {
            Some(self.zone_for_ltz()?)
        } else {
            None
        };
        Ok(RowStream::new(
            Arc::clone(&self.inner),
            started,
            zone,
            self.inner.options.decimal_precision,
        ))
    }

    fn zone_for_ltz(&mut self) -> Result<TimeZone> {
        if let Some(zone) = &self.zone {
            return Ok(zone.clone());
        }
        if self.default_zone.is_none() {
            self.default_zone = Some(self.inner.session_time_zone()?);
        }
        self.default_zone
            .clone()
            .ok_or_else(|| malformed("no session time zone"))
    }

    fn read_zone(&mut self) -> Result<()> {
        let response = match self.prefetch.take()? {
            Posted::Done(response) => response,
            Posted::Rejected(_, err) => return Err(err),
        };
        self.zone = Some(time_zone_from(&self.inner, started(response)?)?);
        Ok(())
    }
}

impl Iterator for ScriptRun {
    /// `Ok(stream)` for a statement that ran; `Err` for the failing one, then `None`.
    type Item = Result<RowStream>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.done {
            let item = match self.steps.next()? {
                Step::Ready(stream) => Ok(stream),
                Step::Child(handle) => self.child(&handle),
                Step::Zone(_) => match self.read_zone() {
                    Ok(()) => continue,
                    Err(err) => Err(err),
                },
                Step::Fail(err) => Err(err),
            };
            if item.is_err() {
                self.done = true;
                self.prefetch.stop();
            }
            return Some(item);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(text: &str) -> Sent<'_> {
        Sent {
            text,
            kind: Kind::User,
        }
    }

    fn row(id: &str, text: &str, status: &str) -> Vec<Option<String>> {
        vec![Some(id.into()), Some(text.into()), Some(status.into())]
    }

    #[test]
    fn request_text_terminates_every_statement() {
        let sent = [user("select 1;"), user("select 2 -- c"), user("select 3")];
        assert_eq!(
            request_text(&sent),
            "select 1;\nselect 2 -- c\n;\nselect 3\n;"
        );
    }

    #[test]
    fn the_failing_statement_comes_from_the_line_in_the_request() {
        let sent = [user("select 1;"), user("select\n2;"), user("selec 3")];
        let at = |line: usize| {
            failing_statement(
                &sent,
                Some(&format!(
                    "SQL compilation error:\nsyntax error line {line} at position 0 unexpected 'x'."
                )),
            )
        };
        assert_eq!(at(1), Some(0));
        assert_eq!(at(2), Some(1));
        assert_eq!(at(3), Some(1));
        assert_eq!(at(4), Some(2));
        assert_eq!(at(9), Some(2));
        assert_eq!(failing_statement(&sent, Some("no line here")), None);
        assert_eq!(failing_statement(&sent, None), None);
    }

    #[test]
    fn normalize_ignores_comments_whitespace_and_the_final_semicolon() {
        assert_eq!(normalize("select  1 /* c */\n from t ;"), "select 1 from t");
        // Both sides are normalised the same way, strings included.
        assert_eq!(normalize("-- c\nselect 'a  b';"), "select 'a b'");
        assert_eq!(normalize("select 1"), "select 1");
    }

    #[test]
    fn history_matching_skips_unmatched_rows_and_stops_at_the_failure() {
        let sent = [user("select 1;"), user("call p();"), user("select 1/0;")];
        let history = [
            row(
                "p",
                "select 1;\ncall p();\nselect 1/0;",
                "FAILED_WITH_ERROR",
            ),
            row("a", "select 1", "SUCCESS"),
            row("b", "call p()", "SUCCESS"),
            row("x", "insert into t values (1)", "SUCCESS"),
            row("c", "select 1/0", "FAILED_WITH_ERROR"),
        ];
        assert_eq!(
            match_history(&sent, &history, "p"),
            Some((vec!["a".to_string(), "b".to_string()], "c".to_string()))
        );
        assert_eq!(match_history(&sent, &history[..3], "p"), None);
        let all_ok = [row("a", "select 1", "SUCCESS")];
        assert_eq!(match_history(&sent[..1], &all_ok, "p"), None);
    }

    #[test]
    fn child_failure_with_and_without_sql_state() {
        let mut response: StatementResponse = serde_json::from_str(
            r#"{"code":"002003","sqlState":"42S02","message":"m","statementHandle":"h"}"#,
        )
        .unwrap();
        assert_eq!(
            child_failure(&response, "x").message(),
            "002003 (42S02): h: m"
        );
        response.sql_state = None;
        response.statement_handle = None;
        assert_eq!(child_failure(&response, "x").message(), "002003: x: m");
    }

    #[test]
    fn fallback_removes_the_multistmt_wrapper() {
        let response: StatementResponse = serde_json::from_str(
            r#"{"code":"100132","sqlState":"P0000","statementHandle":"p","message":"Execution of multiple statements failed on statement \"select 1/0\" (at line 2, position 0).\nDivision by zero in SYSTEM$MULTISTMT at '    throw `Execution...'"}"#,
        )
        .unwrap();
        assert_eq!(
            unwrapped(&response).message(),
            "100132 (P0000): p: Division by zero"
        );
    }

    #[test]
    fn count_mismatch_names_both_counts() {
        let response: StatementResponse = serde_json::from_str(
            r#"{"code":"000008","message":"Actual statement count 3 did not match the desired statement count 2."}"#,
        )
        .unwrap();
        let err = count_mismatch(&response, 2);
        assert_eq!(err.kind(), ErrorKind::Client);
        assert!(err.message().contains("(3 vs 2)"), "{}", err.message());
    }
}
