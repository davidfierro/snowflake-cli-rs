//! The interactive-session `!` commands of `snow` 3.34.0 (`repl_commands.py`): parsing into a
//! [`ReplCommand`], with `snow`'s error messages. Running them is the caller's job
//! (`commands::sql`), since they act on the run's output settings and its session.

use super::py_repr;
use super::split::py_strip;
use crate::output::format::OutputFormat;
use regex::Regex;
use std::sync::OnceLock;

/// The `!queries` filters that build the `/monitoring/queries` request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QueriesFilter {
    pub from_current_session: bool,
    pub amount: u64,
    pub user: Option<String>,
    pub warehouse: Option<String>,
    pub start_ms: Option<i64>,
    pub end_ms: Option<i64>,
    pub duration: Option<String>,
    pub stmt_type: Option<String>,
    pub status: Option<String>,
}

/// A `!set` option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetOption {
    OutputFormat,
    Quiet,
    Timing,
    TimingInOutputFile,
    Echo,
    OutputFile,
}

/// A compiled `!` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplCommand {
    /// `!queries help`.
    QueriesHelp,
    Queries(QueriesFilter),
    /// `!result <query id>`.
    Result(String),
    /// `!abort <query id>`.
    Abort(String),
    /// `!set <option>=<value>`; the value is checked already (`echo` lower-cased).
    Set(SetOption, String),
    /// `!spool <file>`, or `!spool off` (`None`).
    Spool(Option<String>),
    /// `!edit [sql]`.
    Edit(String),
    /// `!rehash`.
    Rehash,
}

const SET_USAGE: &str = "Usage: `!set output_format=<format>` | `!set quiet=<true|false>` | \
`!set timing=<true|false>` | `!set timing_in_output_file=<true|false>` | \
`!set echo=<true|false>` | `!set output_file=<path>`";
const SET_SUPPORTED: &str =
    "Only output_format, quiet, timing, timing_in_output_file, echo and output_file are supported.";
const SPOOL_USAGE: &str = "Usage: `!spool <file>` | `!spool off`";
const STMT_TYPES: [&str; 15] = [
    "ANY",
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "MERGE",
    "MULTI_TABLE_INSERT",
    "COPY",
    "COMMIT",
    "ROLLBACK",
    "BEGIN_TRANSACTION",
    "SHOW",
    "GRANT",
    "CREATE",
    "ALTER",
];
const STATUSES: [&str; 6] = [
    "RUNNING",
    "SUCCEEDED",
    "FAILED",
    "BLOCKED",
    "QUEUED",
    "ABORTED",
];

fn command_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        #[allow(clippy::unwrap_used)] // a constant pattern, checked by the tests
        Regex::new(r"^(![\w]+)(?:\s+(.*))?$").unwrap()
    })
}

fn uuid_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        #[allow(clippy::unwrap_used)] // a constant pattern, checked by the tests
        Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z").unwrap()
    })
}

/// `detect_command`: the command name (with its `!`) and the raw arguments of `text`.
pub fn detect(text: &str) -> Option<(String, String)> {
    let caps = command_pattern().captures(py_strip(text))?;
    Some((
        caps[1].to_string(),
        caps.get(2).map_or("", |m| m.as_str()).to_string(),
    ))
}

/// `compile_statements` for a `REPL_COMMAND` statement: drops `;>`/`;`, then
/// `compile_repl_command`. `Err` is the message `snow` reports as a compilation error.
pub fn compile(statement: &str) -> Result<ReplCommand, String> {
    let text = statement.strip_suffix(";>").unwrap_or(statement);
    let text = text.strip_suffix(';').unwrap_or(text);
    let Some((name, raw)) = detect(py_strip(text)) else {
        return Err("Not a command".to_string());
    };
    match name.to_lowercase().as_str() {
        "!queries" => queries(&raw),
        "!result" => query_id("result", &raw).map(ReplCommand::Result),
        "!abort" => query_id("abort", &raw).map(ReplCommand::Abort),
        "!set" => set(&raw),
        "!spool" => spool(&raw),
        "!edit" => Ok(ReplCommand::Edit(raw)),
        "!rehash" => Ok(ReplCommand::Rehash),
        _ => Err(format!("Unknown command '{name}'")),
    }
}

/// Positional arguments, and `key=value` pairs in order.
type ParsedArgs = (Vec<String>, Vec<(String, String)>);

/// `ReplCommand._parse_args`: whitespace-separated words; `key=value` words are keyword
/// arguments (key lower-cased), the others positional.
fn parse_args(raw: &str) -> Result<ParsedArgs, String> {
    let mut args = Vec::new();
    let mut kwargs: Vec<(String, String)> = Vec::new();
    for word in raw.split_whitespace() {
        match word.split_once('=') {
            None => args.push(word.to_string()),
            Some((key, value)) => {
                let key = key.to_lowercase();
                if kwargs.iter().any(|(k, _)| *k == key) {
                    return Err(format!("Duplicated argument {}", py_repr(&key)));
                }
                kwargs.push((key, value.to_string()));
            }
        }
    }
    Ok((args, kwargs))
}

fn pop(kwargs: &mut Vec<(String, String)>, key: &str) -> Option<String> {
    let index = kwargs.iter().position(|(k, _)| k == key)?;
    Some(kwargs.remove(index).1)
}

/// `_validate_kwargs_empty`.
fn kwargs_error(command: &str, kwargs: &[(String, String)]) -> Result<(), String> {
    match kwargs {
        [] => Ok(()),
        [(k, v)] => Err(format!(
            "Invalid argument passed to '{command}' command: {k}={v}"
        )),
        many => {
            let listed: Vec<String> = many.iter().map(|(k, v)| format!("{k}={v}")).collect();
            Err(format!(
                "Invalid arguments passed to '{command}' command: {}",
                listed.join(", ")
            ))
        }
    }
}

/// Python's `int()` of a filter value.
fn py_int(value: &str) -> Option<i64> {
    let text = py_strip(value).replace('_', "");
    text.parse().ok()
}

/// `datetime.fromisoformat(value).timestamp()` in milliseconds; a value without an offset is
/// local time.
fn iso_millis(value: &str) -> Option<i64> {
    if let Ok(ts) = value.parse::<jiff::Timestamp>() {
        return Some(ts.as_millisecond());
    }
    let civil = value.parse::<jiff::civil::DateTime>().ok().or_else(|| {
        value
            .parse::<jiff::civil::Date>()
            .ok()
            .map(|d| d.to_datetime(jiff::civil::Time::midnight()))
    })?;
    let zoned = civil.to_zoned(jiff::tz::TimeZone::system()).ok()?;
    Some(zoned.timestamp().as_millisecond())
}

fn queries(raw: &str) -> Result<ReplCommand, String> {
    let (args, mut kwargs) = parse_args(raw)?;
    if args.iter().any(|a| a == "help") {
        return Ok(ReplCommand::QueriesHelp);
    }
    let from_current_session = args.iter().any(|a| a == "session") || kwargs.is_empty();
    let amount = pop(&mut kwargs, "amount").unwrap_or_else(|| "25".into());
    let amount_value = amount
        .chars()
        .all(|c| c.is_ascii_digit())
        .then(|| amount.parse::<u64>().ok())
        .flatten()
        .ok_or_else(|| format!("Invalid argument passed to 'amount' filter: {amount}"))?;
    let user = pop(&mut kwargs, "user");
    let warehouse = pop(&mut kwargs, "warehouse");
    let duration = pop(&mut kwargs, "duration");
    let bound = |kwargs: &mut Vec<(String, String)>, key: &str| -> Result<Option<i64>, String> {
        match pop(kwargs, key).filter(|v| !v.is_empty()) {
            None => Ok(None),
            Some(v) => py_int(&v)
                .map(Some)
                .ok_or_else(|| format!("Invalid argument passed to '{key}' filter: {v}")),
        }
    };
    // A zero bound is falsy in snow: not sent, and not in conflict with a date.
    let mut start_ms = bound(&mut kwargs, "start")?.filter(|v| *v != 0);
    let mut end_ms = bound(&mut kwargs, "end")?.filter(|v| *v != 0);
    for (key, other, target) in [
        ("start_date", "start", &mut start_ms),
        ("end_date", "end", &mut end_ms),
    ] {
        if let Some(date) = pop(&mut kwargs, key).filter(|v| !v.is_empty()) {
            if target.is_some() {
                return Err(format!(
                    "'{key}' filter cannot be used with '{other}' filter"
                ));
            }
            let millis = iso_millis(&date)
                .ok_or_else(|| format!("Invalid date format passed to '{key}' filter: {date}"))?;
            *target = Some(millis).filter(|v| *v != 0);
        }
    }
    let stmt_type = match pop(&mut kwargs, "type").filter(|v| !v.is_empty()) {
        None => None,
        Some(t) => {
            let upper = t.to_uppercase();
            if !STMT_TYPES.contains(&upper.as_str()) {
                return Err(format!("Invalid argument passed to 'type' filter: {upper}"));
            }
            Some(upper)
        }
    };
    let status = match pop(&mut kwargs, "status").filter(|v| !v.is_empty()) {
        None => None,
        Some(s) => {
            let upper = s.to_uppercase();
            if !STATUSES.contains(&upper.as_str()) {
                return Err(format!(
                    "Invalid argument passed to 'status' filter: {upper}"
                ));
            }
            Some(upper)
        }
    };
    if let Some(arg) = args
        .iter()
        .find(|a| !matches!(a.to_lowercase().as_str(), "session" | "help"))
    {
        return Err(format!(
            "Invalid argument passed to 'queries' command: {arg}"
        ));
    }
    kwargs_error("queries", &kwargs)?;
    Ok(ReplCommand::Queries(QueriesFilter {
        from_current_session,
        amount: amount_value,
        user,
        warehouse,
        start_ms,
        end_ms,
        duration,
        stmt_type,
        status,
    }))
}

/// `_validate_only_arg_is_query_id`.
fn query_id(command: &str, raw: &str) -> Result<String, String> {
    let (args, kwargs) = parse_args(raw)?;
    kwargs_error(command, &kwargs)?;
    let [id] = args.as_slice() else {
        let amount = if args.is_empty() { "No" } else { "Too many" };
        return Err(format!(
            "{amount} arguments passed to '{command}' command. Usage: `!{command} <query id>`"
        ));
    };
    if !uuid_pattern().is_match(id) {
        return Err(format!(
            "Invalid query ID passed to '{command}' command: {id}"
        ));
    }
    Ok(id.clone())
}

/// `parse_bool_value`.
pub fn parse_bool(option: &str, value: &str) -> Result<bool, String> {
    match py_strip(value).to_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        _ => Err(format!(
            "Invalid value for {option}: {}. Use true or false.",
            py_repr(value)
        )),
    }
}

/// One pair of matching quotes around `value`, removed.
pub fn strip_matching_quotes(value: &str) -> &str {
    let bytes = value.as_bytes();
    match (bytes.first(), bytes.last()) {
        (Some(&a), Some(&b)) if bytes.len() >= 2 && a == b && (a == b'"' || a == b'\'') => {
            &value[1..value.len() - 1]
        }
        _ => value,
    }
}

/// `OutputFormat.from_string`, with its message.
pub fn parse_format(value: &str) -> Result<OutputFormat, String> {
    OutputFormat::from_name(value).ok_or_else(|| {
        format!(
            "Invalid output format: {}. Must be one of: {}.",
            py_repr(value),
            OutputFormat::ALLOWED
        )
    })
}

fn output_file_value(value: &str) -> Result<ReplCommand, String> {
    let normalized = strip_matching_quotes(py_strip(value));
    if py_strip(normalized).is_empty() {
        return Err(format!(
            "You must specify a value for output_file. {SET_USAGE}"
        ));
    }
    Ok(ReplCommand::Set(
        SetOption::OutputFile,
        normalized.to_string(),
    ))
}

fn set(raw: &str) -> Result<ReplCommand, String> {
    let stripped = py_strip(raw);
    if stripped.to_lowercase().starts_with("output_file=") {
        // Paths may hold spaces or `=`: not split into words.
        return output_file_value(&stripped["output_file=".len()..]);
    }
    let (args, kwargs) = parse_args(raw)?;
    if !args.is_empty() {
        return Err(format!(
            "Too many arguments passed to 'set' command. {SET_USAGE}"
        ));
    }
    if kwargs.is_empty() {
        return Err(format!("No arguments passed to 'set' command. {SET_USAGE}"));
    }
    let option = |key: &str| match key {
        "output_format" => Some(SetOption::OutputFormat),
        "quiet" => Some(SetOption::Quiet),
        "timing" => Some(SetOption::Timing),
        "timing_in_output_file" => Some(SetOption::TimingInOutputFile),
        "echo" => Some(SetOption::Echo),
        "output_file" => Some(SetOption::OutputFile),
        _ => None,
    };
    let unknown: Vec<String> = kwargs
        .iter()
        .filter(|(k, _)| option(k).is_none())
        .map(|(k, _)| py_repr(k))
        .collect();
    if !unknown.is_empty() {
        return Err(format!(
            "Unknown option passed to 'set' command: {}. {SET_SUPPORTED}",
            unknown.join(", ")
        ));
    }
    let [(key, value)] = kwargs.as_slice() else {
        return Err(format!(
            "Too many arguments passed to 'set' command. {SET_USAGE}"
        ));
    };
    let Some(option) = option(key) else {
        return Err(format!(
            "Unknown option passed to 'set' command: {}. {SET_SUPPORTED}",
            py_repr(key)
        ));
    };
    match option {
        SetOption::OutputFile => output_file_value(value),
        SetOption::Quiet | SetOption::Timing | SetOption::TimingInOutputFile => {
            parse_bool(key, value)?;
            Ok(ReplCommand::Set(option, value.clone()))
        }
        SetOption::Echo => {
            let lower = value.to_lowercase();
            if lower != "true" && lower != "false" {
                return Err(format!(
                    "Invalid value for 'echo': {}. Must be true or false.",
                    py_repr(value)
                ));
            }
            Ok(ReplCommand::Set(option, lower))
        }
        SetOption::OutputFormat => {
            parse_format(value)?;
            Ok(ReplCommand::Set(option, value.clone()))
        }
    }
}

fn spool(raw: &str) -> Result<ReplCommand, String> {
    let remainder = strip_matching_quotes(py_strip(raw));
    if remainder.is_empty() {
        return Err(format!(
            "No arguments passed to 'spool' command. {SPOOL_USAGE}"
        ));
    }
    if remainder.to_lowercase() == "off" {
        return Ok(ReplCommand::Spool(None));
    }
    Ok(ReplCommand::Spool(Some(remainder.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(text: &str) -> String {
        compile(text).unwrap_err()
    }

    #[test]
    fn detects_commands_like_snow() {
        assert_eq!(
            detect("  !set  quiet=true "),
            Some(("!set".into(), "quiet=true".into()))
        );
        assert_eq!(detect("!rehash"), Some(("!rehash".into(), String::new())));
        assert_eq!(detect("select 1"), None);
        assert_eq!(detect("!set x\ny"), None, "args stop at a line end");
        assert_eq!(detect("!set\"x\""), None);
    }

    #[test]
    fn compile_drops_the_terminator() {
        assert_eq!(compile("!rehash;"), Ok(ReplCommand::Rehash));
        assert_eq!(compile("!REHASH;>"), Ok(ReplCommand::Rehash));
        assert_eq!(err("!set\"x\";"), "Not a command");
        assert_eq!(err("!nope"), "Unknown command '!nope'");
    }

    #[test]
    fn set_options() {
        assert_eq!(
            compile("!set quiet=Yes"),
            Ok(ReplCommand::Set(SetOption::Quiet, "Yes".into()))
        );
        assert_eq!(
            compile("!set ECHO=TRUE"),
            Ok(ReplCommand::Set(SetOption::Echo, "true".into()))
        );
        assert_eq!(
            compile("!set output_format=json"),
            Ok(ReplCommand::Set(SetOption::OutputFormat, "json".into()))
        );
        assert_eq!(
            compile("!set timing=off"),
            Ok(ReplCommand::Set(SetOption::Timing, "off".into()))
        );
        assert_eq!(
            compile("!set timing_in_output_file=1"),
            Ok(ReplCommand::Set(SetOption::TimingInOutputFile, "1".into()))
        );
        assert_eq!(
            compile("!set Output_File = 'a b=c.txt' "),
            Err(format!(
                "Too many arguments passed to 'set' command. {SET_USAGE}"
            ))
        );
        assert_eq!(
            compile("!set output_file= 'a b=c.txt' "),
            Ok(ReplCommand::Set(SetOption::OutputFile, "a b=c.txt".into()))
        );
        assert_eq!(
            compile("!set OUTPUT_FILE=x"),
            Ok(ReplCommand::Set(SetOption::OutputFile, "x".into()))
        );
    }

    #[test]
    fn set_errors() {
        assert_eq!(
            err("!set"),
            format!("No arguments passed to 'set' command. {SET_USAGE}")
        );
        assert_eq!(
            err("!set a"),
            format!("Too many arguments passed to 'set' command. {SET_USAGE}")
        );
        assert_eq!(
            err("!set quiet=1 echo=true"),
            format!("Too many arguments passed to 'set' command. {SET_USAGE}")
        );
        assert_eq!(
            err("!set header=1 x=2"),
            format!("Unknown option passed to 'set' command: 'header', 'x'. {SET_SUPPORTED}")
        );
        assert_eq!(err("!set quiet=1 QUIET=2"), "Duplicated argument 'quiet'");
        assert_eq!(
            err("!set quiet=maybe"),
            "Invalid value for quiet: 'maybe'. Use true or false."
        );
        assert_eq!(
            err("!set echo=yes"),
            "Invalid value for 'echo': 'yes'. Must be true or false."
        );
        assert_eq!(
            err("!set output_format=xml"),
            "Invalid output format: 'xml'. Must be one of: TABLE, JSON, JSON_EXT, CSV, PLAIN."
        );
        assert_eq!(
            err("!set output_file=''"),
            format!("You must specify a value for output_file. {SET_USAGE}")
        );
    }

    #[test]
    fn spool() {
        assert_eq!(
            compile("!spool \"my file.txt\""),
            Ok(ReplCommand::Spool(Some("my file.txt".into())))
        );
        assert_eq!(compile("!spool OFF"), Ok(ReplCommand::Spool(None)));
        assert_eq!(
            compile("!spool 'off'"),
            Ok(ReplCommand::Spool(None)),
            "quotes go first"
        );
        assert_eq!(
            err("!spool"),
            format!("No arguments passed to 'spool' command. {SPOOL_USAGE}")
        );
    }

    #[test]
    fn query_id_commands() {
        let id = "01b2c3d4-0000-1111-2222-333344445555";
        assert_eq!(
            compile(&format!("!result {id}")),
            Ok(ReplCommand::Result(id.into()))
        );
        assert_eq!(
            compile(&format!("!abort {id}")),
            Ok(ReplCommand::Abort(id.into()))
        );
        assert_eq!(
            err("!abort"),
            "No arguments passed to 'abort' command. Usage: `!abort <query id>`"
        );
        assert_eq!(
            err(&format!("!result {id} {id}")),
            "Too many arguments passed to 'result' command. Usage: `!result <query id>`"
        );
        assert_eq!(
            err("!result ABC"),
            "Invalid query ID passed to 'result' command: ABC"
        );
        assert_eq!(
            err("!result id=1"),
            "Invalid argument passed to 'result' command: id=1"
        );
    }

    #[test]
    fn queries_filters() {
        assert_eq!(compile("!queries help"), Ok(ReplCommand::QueriesHelp));
        assert_eq!(
            compile("!queries"),
            Ok(ReplCommand::Queries(QueriesFilter {
                from_current_session: true,
                amount: 25,
                ..Default::default()
            }))
        );
        assert_eq!(
            compile(
                "!queries amount=3 user=jdoe warehouse=wh duration=10 type=select status=failed start=5 end=0"
            ),
            Ok(ReplCommand::Queries(QueriesFilter {
                from_current_session: false,
                amount: 3,
                user: Some("jdoe".into()),
                warehouse: Some("wh".into()),
                start_ms: Some(5),
                end_ms: None,
                duration: Some("10".into()),
                stmt_type: Some("SELECT".into()),
                status: Some("FAILED".into()),
            }))
        );
        let Ok(ReplCommand::Queries(f)) =
            compile("!queries session start_date=2024-01-02T03:04:05+00:00 end_date=2024-01-03")
        else {
            panic!("not compiled")
        };
        assert!(f.from_current_session);
        assert_eq!(f.start_ms, Some(1_704_164_645_000));
        assert!(f.end_ms.is_some());
    }

    #[test]
    fn queries_errors() {
        assert_eq!(
            err("!queries amount=x"),
            "Invalid argument passed to 'amount' filter: x"
        );
        assert_eq!(
            err("!queries start=x"),
            "Invalid argument passed to 'start' filter: x"
        );
        assert_eq!(
            err("!queries end=x"),
            "Invalid argument passed to 'end' filter: x"
        );
        assert_eq!(
            err("!queries start=1 start_date=2024-01-01"),
            "'start_date' filter cannot be used with 'start' filter"
        );
        assert_eq!(
            err("!queries end_date=nope"),
            "Invalid date format passed to 'end_date' filter: nope"
        );
        assert_eq!(
            err("!queries type=drop"),
            "Invalid argument passed to 'type' filter: DROP"
        );
        assert_eq!(
            err("!queries status=done"),
            "Invalid argument passed to 'status' filter: DONE"
        );
        assert_eq!(
            err("!queries everything"),
            "Invalid argument passed to 'queries' command: everything"
        );
        assert_eq!(
            err("!queries a=1"),
            "Invalid argument passed to 'queries' command: a=1"
        );
        assert_eq!(
            err("!queries a=1 b=2"),
            "Invalid arguments passed to 'queries' command: a=1, b=2"
        );
        assert_eq!(err("!queries a=1 A=2"), "Duplicated argument 'a'");
    }

    #[test]
    fn edit_keeps_its_sql() {
        assert_eq!(
            compile("!edit select a=1"),
            Ok(ReplCommand::Edit("select a=1".into()))
        );
    }
}
