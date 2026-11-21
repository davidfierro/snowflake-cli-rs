//! snow's own connectivity diagnostic (`snowflake/cli/_plugins/connection/diagnostic.py`):
//! probe every endpoint of `SYSTEM$ALLOWLIST()`, then snapshot the network policy.

use super::net::Network;
use super::{Query, Row};
use crate::error::{Error, ErrorKind, Result};
use crate::output::result::Field;
use crate::render::sanitize::sanitize_for_terminal;
use serde_json::Value;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const TLS_PORT: u16 = 443;
const MAX_WORKERS: usize = 8;
const ALLOWLIST_QUERY: &str = "SELECT SYSTEM$ALLOWLIST() AS result";
const ALLOWLIST_PRIVATELINK_QUERY: &str = "SELECT SYSTEM$ALLOWLIST_PRIVATELINK()";
const ALLOWLIST_FILE_LIMIT_BYTES: u64 = 1024 * 1024;
const REPORT_TITLE: &str = "Snowflake CLI connectivity diagnostics";
/// `identifier_to_show_like_pattern("NETWORK_POLICY")`.
const POLICY_PATTERN: &str = r"'NETWORK\\_POLICY'";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Healthy,
    Unhealthy,
    Skipped,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Healthy => "Healthy",
            Status::Unhealthy => "Unhealthy",
            Status::Skipped => "Skipped",
        }
    }
}

fn safe(value: Option<&str>, fallback: &str) -> String {
    match value {
        None | Some("") => fallback.to_string(),
        Some(v) => {
            let clean = sanitize_for_terminal(v);
            if clean.is_empty() {
                fallback.to_string()
            } else {
                clean
            }
        }
    }
}

/// `safe` with an empty fallback, for a value that is always present.
fn clean(value: &str) -> String {
    safe(Some(value), "")
}

fn safe_list(values: &[String]) -> Vec<String> {
    values.iter().map(|v| clean(v)).collect()
}

fn joined(values: &[String], empty: &str) -> String {
    let text = safe_list(values).join(", ");
    if text.is_empty() { empty.into() } else { text }
}

/// Python's `str(float)` for the values here (one decimal).
fn py_float(f: f64) -> String {
    format!("{f:?}")
}

fn opt_str(value: &Option<String>) -> Field {
    match value.as_deref().map(clean).filter(|v| !v.is_empty()) {
        Some(v) => Field::Str(v),
        None => Field::Null,
    }
}

type Pairs = Vec<(String, Field)>;

fn pair(key: &str, value: Field) -> (String, Field) {
    (key.to_string(), value)
}

#[derive(Debug, Clone, PartialEq)]
pub struct EndpointCheck {
    pub host: String,
    pub port: u16,
    pub kind: String,
    pub status: Status,
    pub error: Option<String>,
    pub cert_issuer: Option<String>,
    pub cert_expires: Option<String>,
    pub latency_ms: Option<f64>,
}

impl EndpointCheck {
    fn new(host: &str, port: u16, kind: &str, status: Status) -> Self {
        Self {
            host: host.into(),
            port,
            kind: kind.into(),
            status,
            error: None,
            cert_issuer: None,
            cert_expires: None,
            latency_ms: None,
        }
    }

    /// A TABLE row (callers filter out the skipped ones).
    pub fn to_row(&self) -> Pairs {
        vec![
            pair("url", Field::Str(clean(&self.host))),
            pair("type", Field::Str(clean(&self.kind))),
            pair("status", Field::str(self.status.as_str())),
            pair(
                "latency_ms",
                self.latency_ms.map_or(Field::str(""), Field::Float),
            ),
            pair("issuer", Field::Str(safe(self.cert_issuer.as_deref(), ""))),
            pair(
                "cert_expires",
                Field::Str(safe(self.cert_expires.as_deref(), "")),
            ),
        ]
    }

    pub fn to_dict(&self) -> Field {
        Field::Map(vec![
            pair("host", Field::Str(clean(&self.host))),
            pair("port", Field::Int(i64::from(self.port))),
            pair("type", Field::Str(clean(&self.kind))),
            pair("status", Field::str(self.status.as_str())),
            pair("error", opt_str(&self.error)),
            pair("cert_issuer", opt_str(&self.cert_issuer)),
            pair("cert_expires", opt_str(&self.cert_expires)),
            pair(
                "latency_ms",
                self.latency_ms.map_or(Field::Null, Field::Float),
            ),
        ])
    }

    /// `Checking <TYPE>: <host> <icon>[ (detail)]`, the streamed progress line.
    pub fn status_line(&self) -> String {
        let icon = match self.status {
            Status::Healthy => "✅",
            Status::Unhealthy => "❌",
            Status::Skipped => "⏭",
        };
        let suffix = match (self.status, self.latency_ms, &self.error) {
            (Status::Healthy, Some(ms), _) => format!(" ({} ms)", py_float(ms)),
            (Status::Unhealthy, _, Some(e)) if !e.is_empty() => {
                format!(" ({})", sanitize_for_terminal(e))
            }
            _ => String::new(),
        };
        format!(
            "Checking {}: {} {icon}{suffix}",
            sanitize_for_terminal(&self.kind),
            sanitize_for_terminal(&self.host)
        )
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct DiagnosticReport {
    pub checks: Vec<EndpointCheck>,
}

impl DiagnosticReport {
    fn count(&self, status: Status) -> usize {
        self.checks.iter().filter(|c| c.status == status).count()
    }

    pub fn healthy(&self) -> usize {
        self.count(Status::Healthy)
    }

    pub fn unhealthy(&self) -> usize {
        self.count(Status::Unhealthy)
    }

    pub fn skipped(&self) -> usize {
        self.count(Status::Skipped)
    }

    pub fn tested(&self) -> usize {
        self.healthy() + self.unhealthy()
    }

    pub fn summary_line(&self) -> String {
        format!(
            "Results: {} Healthy, {} Unhealthy out of {} endpoints. {} skipped (non-resolvable \
             patterns).",
            self.healthy(),
            self.unhealthy(),
            self.tested(),
            self.skipped()
        )
    }

    pub fn tested_rows(&self) -> Vec<Pairs> {
        self.checks
            .iter()
            .filter(|c| c.status != Status::Skipped)
            .map(EndpointCheck::to_row)
            .collect()
    }

    /// The `Diagnostic` object of the JSON output.
    pub fn to_dict(&self, policy: &NetworkPolicy) -> Field {
        Field::Map(vec![
            pair(
                "checks",
                Field::List(self.checks.iter().map(EndpointCheck::to_dict).collect()),
            ),
            pair("healthy", Field::Int(self.healthy() as i64)),
            pair("unhealthy", Field::Int(self.unhealthy() as i64)),
            pair("skipped", Field::Int(self.skipped() as i64)),
            pair("tested", Field::Int(self.tested() as i64)),
            pair("network_policy", policy.to_dict()),
        ])
    }

    /// Flat scalars for CSV.
    pub fn csv_summary(&self, policy: &NetworkPolicy) -> Pairs {
        vec![
            pair("healthy", Field::Int(self.healthy() as i64)),
            pair("unhealthy", Field::Int(self.unhealthy() as i64)),
            pair("tested", Field::Int(self.tested() as i64)),
            pair("skipped", Field::Int(self.skipped() as i64)),
            pair("effective_policy", Field::Str(safe(policy.effective(), ""))),
            pair(
                "current_ip",
                Field::Str(safe(policy.current_ip.as_deref(), "")),
            ),
        ]
    }

    /// The section appended to `SnowflakeConnectionTestReport.txt`.
    pub fn to_text(&self, policy: &NetworkPolicy) -> String {
        let bar = "=".repeat(72);
        let dash = "-".repeat(72);
        let mut lines: Vec<String> = vec![
            bar.clone(),
            REPORT_TITLE.into(),
            bar,
            String::new(),
            self.summary_line(),
            String::new(),
        ];
        let tested: Vec<&EndpointCheck> = self
            .checks
            .iter()
            .filter(|c| c.status != Status::Skipped)
            .collect();
        if !tested.is_empty() {
            lines.push("Endpoints".into());
            lines.push(dash.clone());
            for check in tested {
                let mut extra = String::new();
                if let Some(ms) = check.latency_ms {
                    extra += &format!("  {} ms", py_float(ms));
                }
                let issuer = safe(check.cert_issuer.as_deref(), "");
                if !issuer.is_empty() {
                    extra += &format!("  issuer={issuer}");
                }
                let expires = safe(check.cert_expires.as_deref(), "");
                if !expires.is_empty() {
                    extra += &format!("  expires={expires}");
                }
                lines.push(format!(
                    "  {:<10} {:<20} {}{extra}",
                    check.status.as_str(),
                    clean(&check.kind),
                    clean(&check.host)
                ));
                if let Some(error) = check.error.as_deref().filter(|e| !e.is_empty()) {
                    lines.push(format!("    error: {}", clean(error)));
                }
            }
            lines.push(String::new());
        }
        let skipped: Vec<&EndpointCheck> = self
            .checks
            .iter()
            .filter(|c| c.status == Status::Skipped)
            .collect();
        if !skipped.is_empty() {
            lines.push("Skipped".into());
            lines.push(dash.clone());
            for check in skipped {
                lines.push(format!(
                    "  {}  {}  {}",
                    clean(&check.host),
                    clean(&check.kind),
                    safe(check.error.as_deref(), "")
                ));
            }
            lines.push(String::new());
        }
        if policy.has_policy() {
            lines.push("Network policy".into());
            lines.push(dash);
            for (key, value) in policy.summary() {
                lines.push(format!("  {key}: {value}"));
            }
            if !policy.rules.is_empty() {
                lines.push(String::new());
                lines.push("  Rules".into());
                for rule in &policy.rules {
                    lines.push(format!(
                        "    {}  {}  {}  {}",
                        clean(&rule.name),
                        clean(&rule.mode),
                        clean(&rule.kind),
                        joined(&rule.values, "")
                    ));
                }
            }
            lines.push(String::new());
        } else if let Some(message) = policy.no_policy_message() {
            lines.push(message);
            lines.push(String::new());
        }
        lines.join("\n")
    }
}

/// Appends the report to `<dir>/SnowflakeConnectionTestReport.txt`, creating the file if the
/// connector section is missing.
pub fn append_report(dir: &Path, report: &DiagnosticReport, policy: &NetworkPolicy) -> Result<()> {
    use std::io::Write;
    let path = dir.join(super::connector::REPORT_FILENAME);
    let mut body = report.to_text(policy);
    if !body.ends_with('\n') {
        body.push('\n');
    }
    let prefix = match std::fs::metadata(&path) {
        Ok(m) if m.len() > 0 => "\n",
        _ => "",
    };
    super::open_report(&path, true)
        .and_then(|mut f| f.write_all(format!("{prefix}{body}").as_bytes()))
        .map_err(|e| {
            Error::new(
                ErrorKind::Client,
                format!(
                    "Could not append diagnostic report to {}: {e}",
                    dir.display()
                ),
            )
        })
}

// ------------------------------------------------------------------ allowlist

fn json_list_from_query(queries: &dyn Query, sql: &str) -> Vec<Value> {
    let parsed = queries
        .rows(sql)
        .ok()
        .and_then(|rows| rows.into_iter().next())
        .and_then(|row| row.into_iter().next())
        .and_then(|(_, v)| v)
        .filter(|v| !v.is_empty())
        .and_then(|text| serde_json::from_str::<Value>(&text).ok());
    match parsed {
        Some(Value::Array(items)) => items,
        _ => Vec::new(),
    }
}

fn entry_key(entry: &Value) -> (String, String, String) {
    let text = |k: &str| entry.get(k).map(|v| v.to_string()).unwrap_or_default();
    (text("type"), text("host"), text("port"))
}

/// The allowlist from `path` (a JSON array) or from the account.
pub fn load_allowlist(queries: &dyn Query, path: Option<&Path>) -> Result<Vec<Value>> {
    if let Some(path) = path {
        let fail = |why: String| {
            Error::new(
                ErrorKind::Client,
                format!(
                    "Could not read allowlist file {}: {why}. Check the path and that the file \
                     is valid JSON.",
                    path.display()
                ),
            )
        };
        let size = std::fs::metadata(path)
            .map_err(|e| fail(e.to_string()))?
            .len();
        if size > ALLOWLIST_FILE_LIMIT_BYTES {
            return Err(fail(format!(
                "file size {size} bytes exceeds the limit of 1 MB"
            )));
        }
        let text = std::fs::read_to_string(path).map_err(|e| fail(e.to_string()))?;
        return match serde_json::from_str::<Value>(&text).map_err(|e| fail(e.to_string()))? {
            Value::Array(items) => Ok(items),
            _ => Err(Error::new(
                ErrorKind::Client,
                format!(
                    "Allowlist file {} must contain a JSON array of {{type, host, port}} entries.",
                    path.display()
                ),
            )),
        };
    }
    let mut seen = std::collections::HashSet::new();
    let public = json_list_from_query(queries, ALLOWLIST_QUERY);
    let private = json_list_from_query(queries, ALLOWLIST_PRIVATELINK_QUERY);
    Ok(public
        .into_iter()
        .chain(private)
        .filter(|e| seen.insert(entry_key(e)))
        .collect())
}

fn normalise(entries: &[Value]) -> Vec<(String, u16, String)> {
    entries
        .iter()
        .filter_map(|entry| {
            let host = entry.get("host")?.as_str()?.to_string();
            let port = match entry.get("port") {
                None => TLS_PORT,
                Some(Value::Number(n)) => {
                    u16::try_from(n.as_i64().or_else(|| n.as_f64().map(|f| f as i64))?).ok()?
                }
                Some(Value::String(s)) => s.trim().parse().ok()?,
                Some(_) => return None,
            };
            let kind = match entry.get("type") {
                None => "UNKNOWN".to_string(),
                Some(Value::String(s)) => s.clone(),
                Some(other) => other.to_string(),
            };
            Some((host, port, kind))
        })
        .collect()
}

/// False for hostnames the resolver can never satisfy: empty, or a wildcard.
pub fn is_resolvable(host: &str) -> bool {
    !host.is_empty() && !host.contains('*')
}

fn check_endpoint(
    net: &dyn Network,
    host: &str,
    port: u16,
    kind: &str,
    timeout: Duration,
) -> EndpointCheck {
    if !is_resolvable(host) {
        let mut check = EndpointCheck::new(host, port, kind, Status::Skipped);
        check.error = Some("non-resolvable pattern".into());
        return check;
    }
    match net.probe(host, port, timeout) {
        Ok(p) => {
            let mut check = EndpointCheck::new(host, port, kind, Status::Healthy);
            check.cert_issuer = p.issuer_org;
            check.cert_expires = p.not_after;
            check.latency_ms = Some(p.latency_ms);
            check
        }
        Err(e) => {
            let mut check = EndpointCheck::new(host, port, kind, Status::Unhealthy);
            check.error = Some(e);
            check
        }
    }
}

type Callback<'a, T> = Box<dyn FnMut(T) + 'a>;
type CheckCallback<'a> = Box<dyn FnMut(&EndpointCheck) + 'a>;

/// Progress callbacks of [`run`].
#[derive(Default)]
pub struct Progress<'a> {
    pub on_start: Option<Callback<'a, usize>>,
    pub on_skip: Option<Callback<'a, usize>>,
    pub on_check: Option<CheckCallback<'a>>,
}

/// Loads the allowlist, probes each resolvable entry (8 at a time) and returns the report in
/// input order. With no allowlist file and an empty answer from the account, only
/// `fallback_host:443` is checked.
pub fn run(
    net: &dyn Network,
    queries: &dyn Query,
    allowlist_path: Option<&Path>,
    fallback_host: &str,
    mut progress: Progress<'_>,
    timeout: Duration,
) -> Result<DiagnosticReport> {
    let mut allowlist = load_allowlist(queries, allowlist_path)?;
    if allowlist.is_empty() && allowlist_path.is_none() {
        log::debug!(
            "Allowlist empty (query returned no entries or failed to parse); falling back to \
             the connection host."
        );
        allowlist = vec![serde_json::json!({
            "type": "SNOWFLAKE_DEPLOYMENT",
            "host": fallback_host,
            "port": TLS_PORT,
        })];
    }
    let entries = normalise(&allowlist);
    if let Some(f) = progress.on_start.as_mut() {
        f(entries.len());
    }
    let mut checks: Vec<Option<EndpointCheck>> = vec![None; entries.len()];
    let mut to_probe: Vec<usize> = Vec::new();
    let mut skipped = 0;
    for (i, (host, port, kind)) in entries.iter().enumerate() {
        if is_resolvable(host) {
            to_probe.push(i);
        } else {
            checks[i] = Some(check_endpoint(net, host, *port, kind, timeout));
            skipped += 1;
        }
    }
    if skipped > 0
        && let Some(f) = progress.on_skip.as_mut()
    {
        f(skipped);
    }
    if !to_probe.is_empty() {
        let next = AtomicUsize::new(0);
        let (tx, rx) = mpsc::channel::<(usize, EndpointCheck)>();
        std::thread::scope(|scope| {
            for _ in 0..MAX_WORKERS.min(to_probe.len()) {
                let tx = tx.clone();
                let (next, to_probe, entries) = (&next, &to_probe, &entries);
                scope.spawn(move || {
                    loop {
                        let slot = next.fetch_add(1, Ordering::SeqCst);
                        let Some(&i) = to_probe.get(slot) else { break };
                        let (host, port, kind) = &entries[i];
                        let check = check_endpoint(net, host, *port, kind, timeout);
                        if tx.send((i, check)).is_err() {
                            break;
                        }
                    }
                });
            }
            drop(tx);
            for (i, check) in rx {
                if let Some(f) = progress.on_check.as_mut() {
                    f(&check);
                }
                checks[i] = Some(check);
            }
        });
    }
    Ok(DiagnosticReport {
        checks: checks.into_iter().flatten().collect(),
    })
}

// -------------------------------------------------------------- network policy

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkRule {
    pub name: String,
    pub mode: String,
    pub kind: String,
    pub values: Vec<String>,
}

impl NetworkRule {
    pub fn to_row(&self) -> Pairs {
        vec![
            pair("rule", Field::Str(clean(&self.name))),
            pair("mode", Field::Str(clean(&self.mode))),
            pair("type", Field::Str(clean(&self.kind))),
            pair("values", Field::Str(joined(&self.values, ""))),
        ]
    }

    fn to_dict(&self) -> Field {
        Field::Map(vec![
            pair("name", Field::Str(clean(&self.name))),
            pair("mode", Field::Str(clean(&self.mode))),
            pair("type", Field::Str(clean(&self.kind))),
            pair("values", strings(&self.values)),
        ])
    }
}

fn strings(values: &[String]) -> Field {
    Field::List(safe_list(values).into_iter().map(Field::Str).collect())
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkPolicy {
    pub current_ip: Option<String>,
    pub account: Option<String>,
    pub user: Option<String>,
    pub allowed_ips: Vec<String>,
    pub blocked_ips: Vec<String>,
    pub allowed_rules: Vec<String>,
    pub blocked_rules: Vec<String>,
    pub rules: Vec<NetworkRule>,
    pub error: Option<String>,
}

impl NetworkPolicy {
    /// The policy in force: the user's, else the account's.
    pub fn effective(&self) -> Option<&str> {
        self.user.as_deref().or(self.account.as_deref())
    }

    pub fn has_policy(&self) -> bool {
        self.effective().is_some()
    }

    /// The line printed when no policy is in effect; `None` if the current IP is unknown.
    pub fn no_policy_message(&self) -> Option<String> {
        self.current_ip.as_ref().map(|ip| {
            format!(
                "No network policy in effect (current IP: {}).",
                safe(Some(ip), "(unknown)")
            )
        })
    }

    /// The TABLE block for the effective policy, as `(key, text)`.
    pub fn summary(&self) -> Vec<(String, String)> {
        let mut out = vec![
            (
                "Effective network policy".to_string(),
                safe(self.effective(), ""),
            ),
            (
                "Source".into(),
                if self.user.is_some() {
                    "user"
                } else {
                    "account"
                }
                .into(),
            ),
            (
                "Account-level".into(),
                safe(self.account.as_deref(), "(none)"),
            ),
            ("User-level".into(), safe(self.user.as_deref(), "(none)")),
            (
                "Current IP".into(),
                safe(self.current_ip.as_deref(), "(unknown)"),
            ),
            ("Allowed IPs".into(), joined(&self.allowed_ips, "(none)")),
            ("Blocked IPs".into(), joined(&self.blocked_ips, "(none)")),
            (
                "Allowed network rules".into(),
                joined(&self.allowed_rules, "(none)"),
            ),
            (
                "Blocked network rules".into(),
                joined(&self.blocked_rules, "(none)"),
            ),
        ];
        if let Some(error) = &self.error {
            out.push(("Note".into(), clean(error)));
        }
        out
    }

    pub fn summary_object(&self) -> Pairs {
        self.summary()
            .into_iter()
            .map(|(k, v)| (k, Field::Str(v)))
            .collect()
    }

    pub fn to_dict(&self) -> Field {
        Field::Map(vec![
            pair("current_ip", opt_str(&self.current_ip)),
            pair("account_policy", opt_str(&self.account)),
            pair("user_policy", opt_str(&self.user)),
            pair(
                "effective_policy",
                opt_str(&self.effective().map(str::to_string)),
            ),
            pair("allowed_ip_list", strings(&self.allowed_ips)),
            pair("blocked_ip_list", strings(&self.blocked_ips)),
            pair("allowed_network_rule_list", strings(&self.allowed_rules)),
            pair("blocked_network_rule_list", strings(&self.blocked_rules)),
            pair(
                "rules",
                Field::List(self.rules.iter().map(NetworkRule::to_dict).collect()),
            ),
            pair("error", opt_str(&self.error)),
        ])
    }
}

/// Rows of `sql` with lowercase column names; empty on any failure (the role may lack the
/// privilege).
fn query_rows(queries: &dyn Query, sql: &str) -> Vec<Vec<(String, Option<String>)>> {
    match queries.rows(sql) {
        Ok(rows) => rows
            .into_iter()
            .map(|row| {
                row.into_iter()
                    .map(|(k, v)| (k.to_lowercase(), v))
                    .collect()
            })
            .collect(),
        Err(e) => {
            log::debug!("Network-policy query failed: {sql}\n{e}");
            Vec::new()
        }
    }
}

fn cell<'a>(row: &'a Row, column: &str) -> Option<&'a str> {
    row.iter()
        .find(|(k, _)| k == column)
        .and_then(|(_, v)| v.as_deref())
}

fn scalar(rows: &[Row], column: &str) -> Option<String> {
    cell(rows.first()?, column)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

fn split_csv(value: Option<&str>) -> Vec<String> {
    value
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .collect()
}

/// `FQN.from_string(name).sql_identifier`: `IDENTIFIER('<name>')` when `name` is one to three
/// valid identifiers joined by dots, `None` otherwise.
fn sql_identifier(name: &str) -> Option<String> {
    let chars: Vec<char> = name.chars().collect();
    let mut parts = 0;
    let mut i = 0;
    loop {
        match chars.get(i)? {
            '"' => {
                i += 1;
                let mut len = 0;
                loop {
                    match chars.get(i)? {
                        '"' if chars.get(i + 1) == Some(&'"') => i += 2,
                        '"' => break,
                        _ => i += 1,
                    }
                    len += 1;
                }
                if len > 255 {
                    return None;
                }
                i += 1;
            }
            c if c.is_ascii_alphabetic() || *c == '_' => {
                let start = i;
                while chars
                    .get(i)
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
                {
                    i += 1;
                }
                if i - start > 255 {
                    return None;
                }
            }
            _ => return None,
        }
        parts += 1;
        match chars.get(i) {
            None => break,
            Some('.') => i += 1,
            Some(_) => return None,
        }
    }
    (parts <= 3).then(|| format!("IDENTIFIER({})", string_literal(name)))
}

/// snow's `to_string_literal`.
fn string_literal(raw: &str) -> String {
    let mut escaped = String::new();
    let mut backslashes = 0;
    for c in raw.chars() {
        match c {
            '\\' => {
                backslashes += 1;
                escaped.push(c);
            }
            '\'' => {
                escaped.push_str(&"\\".repeat(backslashes));
                escaped.push_str("''");
                backslashes = 0;
            }
            _ => {
                backslashes = 0;
                escaped.push(c);
            }
        }
    }
    let trailing = escaped.len() - escaped.trim_end_matches('\\').len();
    if trailing % 2 == 1 {
        escaped.push('\\');
    }
    format!("'{escaped}'")
}

/// Fills the allowed/blocked lists of `policy` from `DESC NETWORK POLICY`; false when the
/// policy cannot be described.
fn describe_policy(queries: &dyn Query, name: &str, policy: &mut NetworkPolicy) -> bool {
    let Some(id) = sql_identifier(name) else {
        return false;
    };
    let rows = query_rows(queries, &format!("DESC NETWORK POLICY {id}"));
    if rows.is_empty() {
        return false;
    }
    let by_name: std::collections::HashMap<String, String> = rows
        .iter()
        .filter_map(|r| {
            let name = cell(r, "name").filter(|n| !n.is_empty())?;
            Some((name.to_uppercase(), cell(r, "value")?.to_string()))
        })
        .collect();
    let list = |key: &str| split_csv(by_name.get(key).map(String::as_str));
    policy.allowed_ips = list("ALLOWED_IP_LIST");
    policy.blocked_ips = list("BLOCKED_IP_LIST");
    policy.allowed_rules = list("ALLOWED_NETWORK_RULE_LIST");
    policy.blocked_rules = list("BLOCKED_NETWORK_RULE_LIST");
    true
}

fn describe_rule(queries: &dyn Query, name: &str) -> Option<NetworkRule> {
    let id = sql_identifier(name)?;
    let rows = query_rows(queries, &format!("DESC NETWORK RULE {id}"));
    let head = rows.first()?;
    Some(NetworkRule {
        name: name.to_string(),
        mode: cell(head, "mode").unwrap_or("").to_string(),
        kind: cell(head, "type").unwrap_or("").to_string(),
        values: split_csv(Some(cell(head, "value_list").unwrap_or(""))),
    })
}

/// Best-effort snapshot of the active network policy; failures end up in `error`.
pub fn collect_network_policy(queries: &dyn Query, user: Option<&str>) -> NetworkPolicy {
    let mut policy = NetworkPolicy {
        current_ip: scalar(
            &query_rows(queries, "SELECT CURRENT_IP_ADDRESS() AS IP"),
            "ip",
        ),
        account: scalar(
            &query_rows(
                queries,
                &format!("SHOW PARAMETERS LIKE {POLICY_PATTERN} IN ACCOUNT"),
            ),
            "value",
        ),
        ..NetworkPolicy::default()
    };
    if let Some(id) = user
        .filter(|u| !u.trim().is_empty())
        .and_then(sql_identifier)
    {
        policy.user = scalar(
            &query_rows(
                queries,
                &format!("SHOW PARAMETERS LIKE {POLICY_PATTERN} FOR USER {id}"),
            ),
            "value",
        );
    }
    let Some(effective) = policy.effective().map(str::to_string) else {
        return policy;
    };
    if !describe_policy(queries, &effective, &mut policy) {
        policy.error = Some(format!(
            "Could not DESC NETWORK POLICY {effective} (role lacks privilege?). Allowed/blocked \
             lists not shown."
        ));
        return policy;
    }
    let names: Vec<String> = policy
        .allowed_rules
        .iter()
        .chain(&policy.blocked_rules)
        .cloned()
        .collect();
    policy.rules = names
        .iter()
        .filter_map(|n| describe_rule(queries, n))
        .collect();
    policy
}

#[cfg(test)]
mod tests {
    use super::super::net::Probed;
    use super::super::testing::{FakeNetwork, FakeQuery};
    use super::*;
    use crate::output::format::OutputFormat;
    use crate::output::result::CommandResult;

    fn healthy(ms: f64, issuer: Option<&str>, expires: Option<&str>) -> Probed {
        Probed {
            latency_ms: ms,
            issuer_org: issuer.map(str::to_string),
            not_after: expires.map(str::to_string),
        }
    }

    fn allowlist_json() -> &'static str {
        r#"[
            {"type":"SNOWFLAKE_DEPLOYMENT","host":"acct.snowflakecomputing.com","port":443},
            {"type":"STAGE","host":"stage.example.com","port":443},
            {"type":"OCSP_RESPONDER","host":"ocsp.example.com","port":80},
            {"type":"SNOWSQL_REGION","host":"*.apps.example.com","port":443},
            {"type":"STAGE","host":"down.example.com","port":443},
            {"host":"typeless.example.com"},
            {"type":"BAD","port":1}
        ]"#
    }

    fn network() -> FakeNetwork {
        FakeNetwork::default()
            .probe(
                "acct.snowflakecomputing.com",
                443,
                Ok(healthy(
                    12.3,
                    Some("Amazon"),
                    Some("Jun  5 12:00:00 2027 GMT"),
                )),
            )
            .probe(
                "stage.example.com",
                443,
                Ok(healthy(5.0, Some("DigiCert Inc"), None)),
            )
            .probe("ocsp.example.com", 80, Ok(healthy(1.5, None, None)))
            .probe(
                "down.example.com",
                443,
                Err("TLS handshake failed: bad certificate"),
            )
            .probe("typeless.example.com", 443, Ok(healthy(2.0, None, None)))
    }

    fn report() -> DiagnosticReport {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("allowlist.json");
        std::fs::write(&file, allowlist_json()).unwrap();
        run(
            &network(),
            &FakeQuery::default(),
            Some(&file),
            "unused",
            Progress::default(),
            DEFAULT_TIMEOUT,
        )
        .unwrap()
    }

    fn render(result: &CommandResult, format: OutputFormat) -> String {
        let mut out = Vec::new();
        result.write(format, None, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn the_run_keeps_input_order_and_counts_by_status() {
        let report = report();
        let hosts: Vec<&str> = report.checks.iter().map(|c| c.host.as_str()).collect();
        assert_eq!(
            hosts,
            [
                "acct.snowflakecomputing.com",
                "stage.example.com",
                "ocsp.example.com",
                "*.apps.example.com",
                "down.example.com",
                "typeless.example.com"
            ],
            "the entry without a host is dropped; the others stay in input order"
        );
        assert_eq!(report.checks[3].status, Status::Skipped);
        assert_eq!(report.checks[5].kind, "UNKNOWN");
        assert_eq!(
            (
                report.healthy(),
                report.unhealthy(),
                report.skipped(),
                report.tested()
            ),
            (4, 1, 1, 5)
        );
        assert_eq!(
            report.summary_line(),
            "Results: 4 Healthy, 1 Unhealthy out of 5 endpoints. 1 skipped (non-resolvable patterns)."
        );
    }

    #[test]
    fn progress_callbacks_fire_for_start_skip_and_each_probe() {
        use std::cell::RefCell;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("allowlist.json");
        std::fs::write(&file, allowlist_json()).unwrap();
        let started = RefCell::new(0);
        let skipped = RefCell::new(0);
        let checked = RefCell::new(Vec::new());
        let progress = Progress {
            on_start: Some(Box::new(|n| *started.borrow_mut() = n)),
            on_skip: Some(Box::new(|n| *skipped.borrow_mut() = n)),
            on_check: Some(Box::new(|c| checked.borrow_mut().push(c.host.clone()))),
        };
        run(
            &network(),
            &FakeQuery::default(),
            Some(&file),
            "x",
            progress,
            DEFAULT_TIMEOUT,
        )
        .unwrap();
        assert_eq!((*started.borrow(), *skipped.borrow()), (6, 1));
        let mut checked = checked.into_inner();
        checked.sort();
        assert_eq!(checked.len(), 5, "the skipped pattern is not probed");
    }

    #[test]
    fn the_text_section_matches_snows_format() {
        let policy = NetworkPolicy::default();
        let text = report().to_text(&policy);
        let golden = include_str!("../../tests/golden/diagnostics/snow_report.txt");
        assert_eq!(text, golden);
    }

    #[test]
    fn the_text_section_lists_the_network_policy() {
        let policy = NetworkPolicy {
            current_ip: Some("203.0.113.9".into()),
            account: Some("ACCT_POLICY".into()),
            allowed_ips: vec!["10.0.0.0/8".into()],
            allowed_rules: vec!["DB.S.RULE1".into()],
            rules: vec![NetworkRule {
                name: "DB.S.RULE1".into(),
                mode: "INGRESS".into(),
                kind: "IPV4".into(),
                values: vec!["1.2.3.4".into(), "5.6.7.8".into()],
            }],
            ..NetworkPolicy::default()
        };
        let text = DiagnosticReport::default().to_text(&policy);
        let expected = "\
========================================================================
Snowflake CLI connectivity diagnostics
========================================================================

Results: 0 Healthy, 0 Unhealthy out of 0 endpoints. 0 skipped (non-resolvable patterns).

Network policy
------------------------------------------------------------------------
  Effective network policy: ACCT_POLICY
  Source: account
  Account-level: ACCT_POLICY
  User-level: (none)
  Current IP: 203.0.113.9
  Allowed IPs: 10.0.0.0/8
  Blocked IPs: (none)
  Allowed network rules: DB.S.RULE1
  Blocked network rules: (none)

  Rules
    DB.S.RULE1  INGRESS  IPV4  1.2.3.4, 5.6.7.8
";
        assert_eq!(text, expected);
        let no_policy = NetworkPolicy {
            current_ip: Some("203.0.113.9".into()),
            ..NetworkPolicy::default()
        };
        assert!(
            DiagnosticReport::default()
                .to_text(&no_policy)
                .ends_with("No network policy in effect (current IP: 203.0.113.9).\n")
        );
    }

    #[test]
    fn json_nests_the_diagnostic_and_csv_stays_flat() {
        let report = report();
        let policy = NetworkPolicy {
            current_ip: Some("1.2.3.4".into()),
            ..NetworkPolicy::default()
        };
        let json = render(
            &CommandResult::Object(vec![("Diagnostic".into(), report.to_dict(&policy))]),
            OutputFormat::Json,
        );
        let golden = include_str!("../../tests/golden/diagnostics/snow_diagnostic.json");
        assert_eq!(json, golden);
        let csv = render(
            &CommandResult::Object(report.csv_summary(&policy)),
            OutputFormat::Csv,
        );
        assert_eq!(
            csv,
            "healthy,unhealthy,tested,skipped,effective_policy,current_ip\n4,1,5,1,,1.2.3.4\n"
        );
    }

    #[test]
    fn the_table_rows_leave_out_skipped_patterns() {
        let report = report();
        let rows = report.tested_rows();
        assert_eq!(rows.len(), 5);
        let table = render(&CommandResult::Collection(rows), OutputFormat::Table);
        assert!(table.contains("| url "), "{table}");
        assert!(table.contains("Unhealthy"));
        assert!(!table.contains("apps.example.com"));
    }

    #[test]
    fn status_lines_show_latency_or_the_error() {
        let report = report();
        assert_eq!(
            report.checks[0].status_line(),
            "Checking SNOWFLAKE_DEPLOYMENT: acct.snowflakecomputing.com ✅ (12.3 ms)"
        );
        assert_eq!(
            report.checks[3].status_line(),
            "Checking SNOWSQL_REGION: *.apps.example.com ⏭"
        );
        assert_eq!(
            report.checks[4].status_line(),
            "Checking STAGE: down.example.com ❌ (TLS handshake failed: bad certificate)"
        );
    }

    #[test]
    fn terminal_escapes_from_the_server_are_stripped() {
        let check = EndpointCheck {
            host: "evil\x1b[31m.example.com".into(),
            error: Some("\x1b[2Jboom".into()),
            status: Status::Unhealthy,
            ..EndpointCheck::new("", 443, "STAGE\x1b[0m", Status::Unhealthy)
        };
        assert_eq!(
            check.status_line(),
            "Checking STAGE: evil.example.com ❌ (boom)"
        );
        let text = DiagnosticReport {
            checks: vec![check],
        }
        .to_text(&NetworkPolicy::default());
        assert!(!text.contains('\x1b'));
    }

    #[test]
    fn the_account_allowlist_merges_both_queries_without_duplicates() {
        let public =
            r#"[{"type":"STAGE","host":"a","port":443},{"type":"STAGE","host":"b","port":443}]"#;
        let private =
            r#"[{"type":"STAGE","host":"b","port":443},{"type":"STAGE","host":"c","port":443}]"#;
        let queries = FakeQuery::default()
            .answer(
                "SELECT SYSTEM$ALLOWLIST() AS result",
                &[&[("RESULT", Some(public))]],
            )
            .answer(
                "SELECT SYSTEM$ALLOWLIST_PRIVATELINK()",
                &[&[("SYSTEM$ALLOWLIST_PRIVATELINK()", Some(private))]],
            );
        let list = load_allowlist(&queries, None).unwrap();
        let hosts: Vec<&str> = list.iter().map(|e| e["host"].as_str().unwrap()).collect();
        assert_eq!(hosts, ["a", "b", "c"]);
    }

    #[test]
    fn an_empty_account_allowlist_falls_back_to_the_connection_host() {
        let net = FakeNetwork::default().probe(
            "acct.snowflakecomputing.com",
            443,
            Ok(healthy(3.0, None, None)),
        );
        let queries = FakeQuery::default(); // every query fails
        let report = run(
            &net,
            &queries,
            None,
            "acct.snowflakecomputing.com",
            Progress::default(),
            DEFAULT_TIMEOUT,
        )
        .unwrap();
        assert_eq!(report.checks.len(), 1);
        assert_eq!(report.checks[0].kind, "SNOWFLAKE_DEPLOYMENT");
        assert_eq!(report.checks[0].status, Status::Healthy);
    }

    #[test]
    fn a_non_list_answer_from_the_account_is_an_empty_allowlist() {
        let queries = FakeQuery::default()
            .answer(
                "SELECT SYSTEM$ALLOWLIST() AS result",
                &[&[("RESULT", Some("{}"))]],
            )
            .answer("SELECT SYSTEM$ALLOWLIST_PRIVATELINK()", &[&[("X", None)]]);
        assert!(load_allowlist(&queries, None).unwrap().is_empty());
    }

    #[test]
    fn allowlist_file_problems_are_client_errors() {
        let dir = tempfile::tempdir().unwrap();
        let queries = FakeQuery::default();
        let missing = load_allowlist(&queries, Some(&dir.path().join("nope.json"))).unwrap_err();
        assert!(
            missing
                .to_string()
                .contains("Could not read allowlist file"),
            "{missing}"
        );
        let bad = dir.path().join("bad.json");
        std::fs::write(&bad, "{oops").unwrap();
        assert!(
            load_allowlist(&queries, Some(&bad))
                .unwrap_err()
                .to_string()
                .contains("Check the path and that the file is valid JSON.")
        );
        let object = dir.path().join("object.json");
        std::fs::write(&object, "{}").unwrap();
        assert!(
            load_allowlist(&queries, Some(&object))
                .unwrap_err()
                .to_string()
                .contains("must contain a JSON array")
        );
        let big = dir.path().join("big.json");
        std::fs::write(&big, vec![b' '; 1024 * 1024 + 1]).unwrap();
        assert!(
            load_allowlist(&queries, Some(&big))
                .unwrap_err()
                .to_string()
                .contains("exceeds the limit of 1 MB")
        );
    }

    #[test]
    fn a_file_allowlist_never_queries_the_account_or_falls_back() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("empty.json");
        std::fs::write(&file, "[]").unwrap();
        let queries = FakeQuery::default();
        let report = run(
            &FakeNetwork::default(),
            &queries,
            Some(&file),
            "fallback",
            Progress::default(),
            DEFAULT_TIMEOUT,
        )
        .unwrap();
        assert!(report.checks.is_empty());
        assert!(queries.asked().is_empty());
    }

    #[test]
    fn append_report_adds_a_blank_line_after_the_connector_section() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join(crate::diagnostics::connector::REPORT_FILENAME);
        let report = DiagnosticReport::default();
        let policy = NetworkPolicy::default();
        append_report(dir.path(), &report, &policy).unwrap();
        let fresh = std::fs::read_to_string(&path).unwrap();
        assert!(fresh.starts_with("====") && fresh.ends_with('\n'));
        std::fs::write(&path, "connector section\n").unwrap();
        append_report(dir.path(), &report, &policy).unwrap();
        let both = std::fs::read_to_string(&path).unwrap();
        assert!(both.starts_with("connector section\n\n====="), "{both}");
        let err = append_report(&dir.path().join("missing"), &report, &policy).unwrap_err();
        assert!(
            err.to_string()
                .contains("Could not append diagnostic report to")
        );
    }

    fn policy_queries() -> FakeQuery {
        FakeQuery::default()
            .answer(
                "SELECT CURRENT_IP_ADDRESS()",
                &[&[("IP", Some("203.0.113.9"))]],
            )
            .answer(
                r"SHOW PARAMETERS LIKE 'NETWORK\\_POLICY' IN ACCOUNT",
                &[&[
                    ("key", Some("NETWORK_POLICY")),
                    ("value", Some("ACCT_POLICY")),
                ]],
            )
            .answer(
                r"SHOW PARAMETERS LIKE 'NETWORK\\_POLICY' FOR USER IDENTIFIER('tester')",
                &[&[
                    ("key", Some("NETWORK_POLICY")),
                    ("value", Some("USER_POLICY")),
                ]],
            )
            .answer(
                "DESC NETWORK POLICY IDENTIFIER('USER_POLICY')",
                &[
                    &[
                        ("name", Some("ALLOWED_IP_LIST")),
                        ("value", Some("10.0.0.0/8, 192.168.0.0/16")),
                    ],
                    &[
                        ("name", Some("BLOCKED_IP_LIST")),
                        ("value", Some("10.1.0.0/16")),
                    ],
                    &[
                        ("name", Some("ALLOWED_NETWORK_RULE_LIST")),
                        ("value", Some("DB.S.R1")),
                    ],
                    &[
                        ("name", Some("BLOCKED_NETWORK_RULE_LIST")),
                        ("value", Some("DB.S.R2,bad name")),
                    ],
                ],
            )
            .answer(
                "DESC NETWORK RULE IDENTIFIER('DB.S.R1')",
                &[&[
                    ("name", Some("R1")),
                    ("type", Some("IPV4")),
                    ("mode", Some("INGRESS")),
                    ("value_list", Some("1.1.1.1,2.2.2.2")),
                ]],
            )
    }

    #[test]
    fn the_user_policy_wins_and_its_rules_are_described() {
        let queries = policy_queries();
        let policy = collect_network_policy(&queries, Some("tester"));
        assert_eq!(policy.current_ip.as_deref(), Some("203.0.113.9"));
        assert_eq!(policy.account.as_deref(), Some("ACCT_POLICY"));
        assert_eq!(policy.user.as_deref(), Some("USER_POLICY"));
        assert_eq!(policy.effective(), Some("USER_POLICY"));
        assert_eq!(policy.allowed_ips, ["10.0.0.0/8", "192.168.0.0/16"]);
        assert_eq!(policy.blocked_ips, ["10.1.0.0/16"]);
        assert_eq!(policy.allowed_rules, ["DB.S.R1"]);
        assert_eq!(policy.blocked_rules, ["DB.S.R2", "bad name"]);
        // R2 has no answer and "bad name" is not an identifier: only R1 is described.
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].values, ["1.1.1.1", "2.2.2.2"]);
        let summary = policy.summary();
        assert_eq!(summary[1], ("Source".into(), "user".into()));
        assert!(!policy.summary_object().is_empty());
        let json = render(
            &CommandResult::Object(vec![("p".into(), policy.to_dict())]),
            OutputFormat::Json,
        );
        assert!(json.contains("\"effective_policy\": \"USER_POLICY\""));
        assert!(json.contains("\"error\": null"));
        assert_eq!(policy.rules[0].to_row().len(), 4);
    }

    #[test]
    fn effective_policy_is_derived_and_the_no_policy_message_is_shared() {
        let mut policy = NetworkPolicy::default();
        assert_eq!(policy.effective(), None);
        assert_eq!(policy.no_policy_message(), None);
        policy.current_ip = Some("1.2.3.4".into());
        assert_eq!(
            policy.no_policy_message().as_deref(),
            Some("No network policy in effect (current IP: 1.2.3.4).")
        );
        policy.account = Some("A".into());
        assert_eq!(policy.effective(), Some("A"));
        policy.user = Some("U".into());
        assert_eq!(policy.effective(), Some("U"));
        assert!(policy.has_policy());
    }

    #[test]
    fn without_a_user_policy_the_account_policy_applies() {
        let queries = policy_queries();
        let policy = collect_network_policy(&queries, Some("other user"));
        assert_eq!(policy.effective(), Some("ACCT_POLICY"));
        assert_eq!(policy.summary()[1].1, "account");
        assert!(
            policy
                .error
                .as_deref()
                .unwrap()
                .contains("Could not DESC NETWORK POLICY ACCT_POLICY"),
            "the fake has no DESC answer for it"
        );
        assert_eq!(policy.summary().last().unwrap().0, "Note");
    }

    #[test]
    fn with_no_policy_only_the_current_ip_is_known() {
        let queries = FakeQuery::default()
            .answer("SELECT CURRENT_IP_ADDRESS()", &[&[("IP", Some("1.1.1.1"))]]);
        let policy = collect_network_policy(&queries, None);
        assert!(!policy.has_policy());
        assert_eq!(policy.current_ip.as_deref(), Some("1.1.1.1"));
        assert_eq!(policy.summary()[4].1, "1.1.1.1");
        let nothing = collect_network_policy(&FakeQuery::default(), Some("  "));
        assert_eq!(nothing, NetworkPolicy::default());
        assert_eq!(nothing.summary()[4].1, "(unknown)");
    }

    #[test]
    fn identifiers_follow_snows_fqn_rules() {
        assert_eq!(
            sql_identifier("DB.S.P").as_deref(),
            Some("IDENTIFIER('DB.S.P')")
        );
        assert_eq!(
            sql_identifier("\"my \"\"p\"\"\".x").as_deref(),
            Some("IDENTIFIER('\"my \"\"p\"\"\".x')")
        );
        assert_eq!(sql_identifier("o'brien"), None);
        assert_eq!(sql_identifier("a.b.c.d"), None);
        assert_eq!(sql_identifier("1abc"), None);
        assert_eq!(sql_identifier("a..b"), None);
        assert_eq!(sql_identifier("\"unterminated"), None);
        assert_eq!(sql_identifier(""), None);
        assert_eq!(sql_identifier(&"a".repeat(256)), None);
        assert_eq!(sql_identifier(&format!("\"{}\"", "a".repeat(256))), None);
        assert_eq!(string_literal("it's"), "'it''s'");
        assert_eq!(string_literal("a\\'b"), "'a\\\\''b'");
        assert_eq!(string_literal("tail\\"), "'tail\\\\'");
    }

    #[test]
    fn ports_may_be_text_or_floats_and_odd_entries_are_dropped() {
        let entries: Vec<Value> = serde_json::from_str(
            r#"[{"host":"a","port":"8443"},{"host":"b","port":80.0},{"host":"c","port":"x"},
                {"host":"d","port":true},{"host":"e","port":70000},{"host":1},{"host":"f","type":7}]"#,
        )
        .unwrap();
        let got = normalise(&entries);
        assert_eq!(
            got,
            vec![
                ("a".to_string(), 8443, "UNKNOWN".to_string()),
                ("b".to_string(), 80, "UNKNOWN".to_string()),
                ("f".to_string(), 443, "7".to_string()),
            ]
        );
    }
}
