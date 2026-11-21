//! Blocking SQL REST API v2 client (ADR 0001, Decision 5; ADR 0002, Decisions 1 and 4).

use super::prefetch::CHILD_PREFETCH_WINDOW;
use super::result::{Column, QueryResult, SfType, uniquify_column_names};
use super::stream::RowStream;
use super::wire::{PartitionResponse, Rows, StatementResponse};
use crate::auth::Authenticator;
use crate::connection::ConnectionConfig;
use crate::env::Env;
use crate::error::{Error, ErrorKind, Result};
use jiff::tz::TimeZone;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// Test hook: (statement handle, thread) of every partition parse.
#[cfg(test)]
pub(super) static PARSED_ON: std::sync::Mutex<Vec<(String, std::thread::ThreadId)>> =
    std::sync::Mutex::new(Vec::new());

const STATEMENTS_PATH: &str = "/api/v2/statements";
const FIRST_POLL_INTERVAL: Duration = Duration::from_millis(250);
const TIMEZONE_QUERY: &str = "SHOW PARAMETERS LIKE 'TIMEZONE'";
/// Overrides [`ClientOptions::partition_concurrency`] (ADR 0002, Decision 1).
pub const PARTITION_CONCURRENCY_VAR: &str = "SNOW_RS_PARTITION_CONCURRENCY";
pub(crate) const DEFAULT_PARTITION_CONCURRENCY: usize = 8;
const MAX_PARTITION_CONCURRENCY: usize = 64;

#[derive(Debug, Clone)]
pub struct ClientOptions {
    /// TCP + TLS connection setup, default 30 s.
    pub connect_timeout: Duration,
    /// Per HTTP request, default 60 s.
    pub request_timeout: Duration,
    /// Body `timeout`; None = server default.
    pub statement_timeout: Option<Duration>,
    /// Retries after 429/503/504 or a read timeout, default 3.
    pub max_retries: u32,
    /// Upper bound of the 202 poll interval (250 ms doubling), default 2 s.
    pub poll_interval_max: Duration,
    /// Partitions outstanding at once (ADR 0002), default 8; 1 = sequential.
    pub partition_concurrency: usize,
    /// `--decimal-precision`: significant digits decimals are rounded to; None = exact.
    pub decimal_precision: Option<usize>,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            request_timeout: Duration::from_secs(60),
            statement_timeout: None,
            max_retries: 3,
            poll_interval_max: Duration::from_secs(2),
            partition_concurrency: DEFAULT_PARTITION_CONCURRENCY,
            decimal_precision: None,
        }
    }
}

impl ClientOptions {
    /// Defaults, with `SNOW_RS_PARTITION_CONCURRENCY` applied (Client error if invalid).
    pub fn from_env(env: &Env) -> Result<Self> {
        let mut options = Self::default();
        if let Some(value) = env.get(PARTITION_CONCURRENCY_VAR) {
            options.partition_concurrency = value
                .trim()
                .parse::<usize>()
                .ok()
                .filter(|n| (1..=MAX_PARTITION_CONCURRENCY).contains(n))
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::Client,
                        format!(
                            "{PARTITION_CONCURRENCY_VAR} must be an integer from 1 to \
                             {MAX_PARTITION_CONCURRENCY}."
                        ),
                    )
                })?;
        }
        Ok(options)
    }
}

/// Connection context sent with every statement (the SQL API has no session).
#[derive(Debug, Clone, Default)]
struct Context {
    database: Option<String>,
    schema: Option<String>,
    warehouse: Option<String>,
    role: Option<String>,
}

pub struct SqlClient {
    pub(super) inner: Arc<Inner>,
}

/// What partition workers share with the client (ADR 0002, Decision 1).
pub(super) struct Inner {
    base_url: String,
    agent: ureq::Agent,
    auth: Box<dyn Authenticator>,
    pub(super) options: ClientOptions,
    context: Context,
    /// The session `TIMEZONE`, fetched once: each statement is its own session, so it can't change.
    time_zone: OnceLock<TimeZone>,
}

/// The statement as it stands once it has finished: columns and partition 0.
pub(super) struct Started {
    pub handle: String,
    pub columns: Vec<Column>,
    pub rows: super::wire::Rows,
    pub partitions: usize,
}

/// How a statement request ended.
pub(super) enum Posted {
    /// HTTP 200.
    Done(StatementResponse),
    /// HTTP 422: the body, and the error `snow` would print for it.
    Rejected(StatementResponse, Error),
}

impl Posted {
    fn into_result(self) -> Result<StatementResponse> {
        match self {
            Posted::Done(response) => Ok(response),
            Posted::Rejected(_, error) => Err(error),
        }
    }
}

/// A response that reached us, whatever its status.
struct Reply {
    status: u16,
    body: String,
    retry_after: Option<Duration>,
}

/// Why a request got no response.
enum TransportError {
    /// Read timeout: retried like 503.
    Timeout(ureq::Error),
    /// DNS, TCP, TLS: not retried.
    Connect(ureq::Error),
    /// The connection failed while the body was read: retried like a read timeout.
    Body(ureq::Error),
}

impl SqlClient {
    /// Base URL from the connection (Decision 5). No network access.
    pub fn new(
        conn: &ConnectionConfig,
        auth: Box<dyn Authenticator>,
        options: ClientOptions,
    ) -> Result<Self> {
        let base_url = base_url(conn)?;
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_connect(Some(options.connect_timeout))
            .timeout_per_call(Some(options.request_timeout))
            // ureq keeps 3 idle connections per host by default; the partition workers and the
            // child prefetch workers need one each so their TLS connections are reused (ADR 0002,
            // Decision 1; ADR 0004, Amendment 1).
            .max_idle_connections(options.partition_concurrency.max(CHILD_PREFETCH_WINDOW))
            .max_idle_connections_per_host(options.partition_concurrency.max(CHILD_PREFETCH_WINDOW))
            .user_agent(concat!("snowflake-cli-rs/", env!("CARGO_PKG_VERSION")))
            .build();
        Ok(Self {
            inner: Arc::new(Inner {
                base_url,
                agent: config.new_agent(),
                auth,
                options,
                context: Context {
                    database: conn.database.clone(),
                    schema: conn.schema.clone(),
                    warehouse: conn.warehouse.clone(),
                    role: conn.role.clone(),
                },
                time_zone: OnceLock::new(),
            }),
        })
    }

    /// Runs one statement. Returns once the statement has finished and partition 0 has
    /// arrived; the remaining partitions download in the background while the caller iterates.
    /// Errors before the first row (submit, SQL error, auth, session time zone) come from here.
    pub fn query(&self, sql: &str) -> Result<RowStream> {
        let started = self.inner.start(sql)?;
        let ltz_zone = if has_ltz(&started.columns) {
            Some(self.session_time_zone()?)
        } else {
            None
        };
        Ok(RowStream::new(
            Arc::clone(&self.inner),
            started,
            ltz_zone,
            self.inner.options.decimal_precision,
        ))
    }

    /// Runs one statement and returns all rows of all partitions: `query()` collected.
    pub fn execute(&self, sql: &str) -> Result<QueryResult> {
        self.query(sql)?.into_result()
    }

    /// The session `TIMEZONE`, needed to show TIMESTAMP_LTZ values as snow does.
    fn session_time_zone(&self) -> Result<TimeZone> {
        self.inner.session_time_zone()
    }
}

/// Whether a statement's columns need the session time zone.
pub(super) fn has_ltz(columns: &[Column]) -> bool {
    columns
        .iter()
        .any(|c| matches!(c.sf_type, SfType::TimestampLtz { .. }))
}

impl Inner {
    /// The session `TIMEZONE` from a separate `SHOW PARAMETERS` request, cached for the client's
    /// lifetime.
    pub(super) fn session_time_zone(self: &Arc<Self>) -> Result<TimeZone> {
        if let Some(zone) = self.time_zone.get() {
            return Ok(zone.clone());
        }
        let started = self.start(TIMEZONE_QUERY)?;
        let zone = time_zone_from(self, started)?;
        Ok(self.time_zone.get_or_init(|| zone).clone())
    }

    pub(super) fn partition_concurrency(&self) -> usize {
        self.options.partition_concurrency.max(1)
    }

    /// Submits and waits for one statement; partitions after the first are not fetched.
    pub(super) fn start(&self, sql: &str) -> Result<Started> {
        started(self.submit(sql)?)
    }

    /// Downloads and parses partition `partition` (≥ 1) of `handle`; run by the partition workers
    /// so the consumer thread never parses JSON.
    pub(super) fn fetch_partition_rows(&self, handle: &str, partition: usize) -> Result<Rows> {
        let body = self.fetch_partition(handle, partition)?;
        #[cfg(test)]
        PARSED_ON
            .lock()
            .unwrap()
            .push((handle.to_string(), std::thread::current().id()));
        Ok(parse::<PartitionResponse>(&body)?.data)
    }

    /// Downloads partition `partition` (≥ 1) of `handle`; returns its body as raw JSON text.
    fn fetch_partition(&self, handle: &str, partition: usize) -> Result<String> {
        log::debug!("fetching partition {partition}");
        let path = format!("{STATEMENTS_PATH}/{handle}?partition={partition}");
        let reply = self.send(&path, None)?;
        if reply.status != 200 {
            return Err(status_error(&reply));
        }
        Ok(reply.body)
    }

    /// POSTs the statement and polls while it runs; returns the final 200 response.
    fn submit(&self, sql: &str) -> Result<StatementResponse> {
        self.post(sql, None)?.into_result()
    }

    /// POSTs `sql`, with `MULTI_STATEMENT_COUNT` = `count` when given (ADR 0004, Decision 1),
    /// and polls while it runs. A 422 with a readable body is [`Posted::Rejected`].
    pub(super) fn post(&self, sql: &str, count: Option<usize>) -> Result<Posted> {
        let request_id = uuid::Uuid::new_v4();
        let mut body = serde_json::Map::new();
        body.insert("statement".into(), sql.into());
        for (key, value) in [
            ("database", &self.context.database),
            ("schema", &self.context.schema),
            ("warehouse", &self.context.warehouse),
            ("role", &self.context.role),
        ] {
            if let Some(value) = value {
                body.insert(key.into(), value.as_str().into());
            }
        }
        if let Some(timeout) = self.options.statement_timeout {
            // Whole seconds, rounded up: `timeout: 0` would mean "no limit" to Snowflake.
            let secs = timeout.as_secs() + u64::from(timeout.subsec_nanos() > 0);
            body.insert("timeout".into(), secs.into());
        }
        if let Some(count) = count {
            body.insert(
                "parameters".into(),
                serde_json::json!({ "MULTI_STATEMENT_COUNT": count.to_string() }),
            );
        }
        let body = serde_json::Value::Object(body).to_string();
        let path = format!("{STATEMENTS_PATH}?requestId={request_id}");
        let reply = self.send(&path, Some(&body))?;
        self.finish(reply)
    }

    /// `GET /api/v2/statements/{handle}`, polling while it runs (a child of a finished
    /// multi-statement request, ADR 0004 Decision 3).
    pub(super) fn get_statement(&self, handle: &str) -> Result<Posted> {
        let reply = self.send(&format!("{STATEMENTS_PATH}/{handle}"), None)?;
        self.finish(reply)
    }

    /// Polls a 202 until the statement ends; maps the final status.
    fn finish(&self, mut reply: Reply) -> Result<Posted> {
        let mut interval = FIRST_POLL_INTERVAL.min(self.options.poll_interval_max);
        let mut polls = 0u32;
        while reply.status == 202 {
            let pending: StatementResponse = parse(&reply.body)?;
            let handle = pending
                .statement_handle
                .ok_or_else(|| malformed("no statementHandle"))?;
            std::thread::sleep(interval);
            interval = (interval * 2).min(self.options.poll_interval_max);
            polls += 1;
            log::debug!("statement {handle} still running, poll {polls}");
            reply = self.send(&format!("{STATEMENTS_PATH}/{handle}"), None)?;
        }
        if reply.status == 422
            && let Ok(response) = serde_json::from_str::<StatementResponse>(&reply.body)
        {
            return Ok(Posted::Rejected(response, status_error(&reply)));
        }
        if reply.status != 200 {
            return Err(status_error(&reply));
        }
        let response: StatementResponse = parse(&reply.body)?;
        if let Some(handle) = &response.statement_handle {
            log::debug!("statement {handle} succeeded");
        }
        Ok(Posted::Done(response))
    }

    /// Sends one request, retrying 429/503/504 and read timeouts. A retried POST keeps its
    /// `requestId` and adds `retry=true`, so Snowflake runs the statement only once.
    /// A body read cut short is retried the same way (ADR 0002, Decision 4).
    fn send(&self, path: &str, body: Option<&str>) -> Result<Reply> {
        let log_path = path.split_once("?requestId").map_or(path, |(p, _)| p);
        let mut attempt = 0u32;
        loop {
            let url = if attempt > 0 && body.is_some() {
                format!("{}{path}&retry=true", self.base_url)
            } else {
                format!("{}{path}", self.base_url)
            };
            let method = if body.is_some() { "POST" } else { "GET" };
            log::debug!("{method} {log_path}");
            let (failure, wait) = match self.send_once(&url, body) {
                Ok(reply) if matches!(reply.status, 429 | 503 | 504) => {
                    log::debug!("{method} {log_path}: HTTP {}", reply.status);
                    let wait = reply.retry_after;
                    (status_error(&reply), wait)
                }
                Ok(reply) => {
                    log::debug!("{method} {log_path}: HTTP {}", reply.status);
                    return Ok(reply);
                }
                Err(TransportError::Timeout(e)) => {
                    log::debug!("{method} {log_path}: timed out");
                    (
                        Error::new(ErrorKind::Communication, "Request to Snowflake timed out.")
                            .with_source(e),
                        None,
                    )
                }
                Err(TransportError::Body(e)) => {
                    log::debug!("{method} {log_path}: body read failed");
                    (
                        Error::new(
                            ErrorKind::Communication,
                            "The connection to Snowflake failed while reading a response.",
                        )
                        .with_source(e),
                        None,
                    )
                }
                Err(TransportError::Connect(e)) => {
                    return Err(Error::new(
                        ErrorKind::Connection,
                        format!("Failed to connect to Snowflake at {}.", self.base_url),
                    )
                    .with_source(e));
                }
            };
            if attempt >= self.options.max_retries {
                return Err(failure);
            }
            let wait = wait.unwrap_or_else(|| Duration::from_secs(1 << attempt.min(6)));
            attempt += 1;
            log::debug!("retry {attempt}/{} in {wait:?}", self.options.max_retries);
            std::thread::sleep(wait);
        }
    }

    fn send_once(
        &self,
        url: &str,
        body: Option<&str>,
    ) -> std::result::Result<Reply, TransportError> {
        let header = self.auth.authorization().map_err(|e| {
            // Signing never fails with a loaded key; treat it as a connection problem.
            TransportError::Connect(ureq::Error::Other(Box::new(e)))
        })?;
        let bearer = format!("Bearer {}", header.token.expose());
        let response = match body {
            Some(body) => self
                .agent
                .post(url)
                .header("Authorization", &bearer)
                .header("X-Snowflake-Authorization-Token-Type", header.token_type)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .send(body),
            None => self
                .agent
                .get(url)
                .header("Authorization", &bearer)
                .header("X-Snowflake-Authorization-Token-Type", header.token_type)
                .header("Accept", "application/json")
                .call(),
        };
        let mut response = response.map_err(classify)?;
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(Duration::from_secs);
        let body = response
            .body_mut()
            .with_config()
            .limit(u64::MAX)
            .read_to_string()
            .map_err(|e| match classify(e) {
                TransportError::Connect(e) => TransportError::Body(e),
                other => other,
            })?;
        Ok(Reply {
            status,
            body,
            retry_after,
        })
    }
}

/// The `TIMEZONE` row of a finished `SHOW PARAMETERS LIKE 'TIMEZONE' …` statement.
pub(super) fn time_zone_from(inner: &Arc<Inner>, started: Started) -> Result<TimeZone> {
    let index = |name: &str| {
        started
            .columns
            .iter()
            .position(|c| c.name.eq_ignore_ascii_case(name))
    };
    let (Some(key), Some(value)) = (index("key"), index("value")) else {
        return Err(malformed("SHOW PARAMETERS has no key/value columns"));
    };
    let mut rows = RowStream::new(Arc::clone(inner), started, None, None).into_raw();
    let mut name = None;
    for row in &mut rows {
        let row = row?;
        if row.get(key).and_then(Option::as_deref) == Some("TIMEZONE") {
            name = row.get(value).cloned().flatten();
            break;
        }
    }
    let name = name.ok_or_else(|| malformed("SHOW PARAMETERS did not return TIMEZONE"))?;
    TimeZone::get(&name).map_err(|e| {
        Error::new(
            ErrorKind::Client,
            format!("Unknown session time zone '{name}'."),
        )
        .with_source(e)
    })
}

/// The finished statement in a 200 body (of a POST or of a GET): columns and partition 0.
pub(super) fn started(response: StatementResponse) -> Result<Started> {
    let handle = response
        .statement_handle
        .ok_or_else(|| malformed("no statementHandle"))?;
    let metadata = response
        .result_set_meta_data
        .ok_or_else(|| malformed("no resultSetMetaData"))?;
    let names: Vec<String> = metadata.row_type.iter().map(|r| r.name.clone()).collect();
    let columns = uniquify_column_names(&names)
        .into_iter()
        .zip(&metadata.row_type)
        .map(|(name, r)| Column {
            name,
            sf_type: SfType::from_row_type(&r.type_name, r.precision, r.scale),
            nullable: r.nullable,
        })
        .collect();
    Ok(Started {
        handle,
        columns,
        rows: response.data.unwrap_or_default(),
        partitions: metadata.partition_info.len().max(1),
    })
}

fn classify(err: ureq::Error) -> TransportError {
    match &err {
        ureq::Error::Timeout(ureq::Timeout::Connect | ureq::Timeout::Resolve) => {
            TransportError::Connect(err)
        }
        ureq::Error::Timeout(_) => TransportError::Timeout(err),
        ureq::Error::Io(io) if io.kind() == std::io::ErrorKind::TimedOut => {
            TransportError::Timeout(err)
        }
        _ => TransportError::Connect(err),
    }
}

/// `<protocol>://<host>[:<port>]`; host defaults to `<account>.snowflakecomputing.com`
/// (`.cn` when the account's region part starts with `cn-`).
pub(crate) fn base_url(conn: &ConnectionConfig) -> Result<String> {
    let protocol = conn
        .protocol
        .as_deref()
        .unwrap_or("https")
        .to_ascii_lowercase();
    if protocol != "https" && protocol != "http" {
        return Err(Error::new(
            ErrorKind::Client,
            format!("Unsupported protocol '{protocol}'. Use https or http."),
        ));
    }
    let host = host(conn)?;
    Ok(match conn.port {
        Some(port) => format!("{protocol}://{host}:{port}"),
        None => format!("{protocol}://{host}"),
    })
}

/// `host`, else `<account>.snowflakecomputing.com` (`.cn` for a China region).
pub fn host(conn: &ConnectionConfig) -> Result<String> {
    Ok(match conn.host.as_deref().filter(|h| !h.is_empty()) {
        Some(host) => host.to_string(),
        None => {
            let account = conn
                .account
                .as_deref()
                .filter(|a| !a.is_empty())
                .ok_or_else(|| {
                    Error::new(ErrorKind::Client, "The connection has no account or host.")
                })?;
            let china = account
                .split('.')
                .nth(1)
                .is_some_and(|region| region.starts_with("cn-"));
            let domain = if china { "cn" } else { "com" };
            format!("{account}.snowflakecomputing.{domain}")
        }
    })
}

pub(super) fn parse<T: serde::de::DeserializeOwned>(body: &str) -> Result<T> {
    serde_json::from_str(body).map_err(|e| {
        // serde_json's message gives line/column and the expected shape, never the input.
        Error::new(
            ErrorKind::Communication,
            "Snowflake returned a malformed response.",
        )
        .with_source(e)
    })
}

pub(super) fn malformed(what: &str) -> Error {
    Error::new(
        ErrorKind::Communication,
        format!("Snowflake returned a malformed response: {what}."),
    )
}

/// The error for a non-success status (Decision 5's table).
fn status_error(reply: &Reply) -> Error {
    let parsed: Option<StatementResponse> = serde_json::from_str(&reply.body).ok();
    let message = parsed
        .as_ref()
        .and_then(|r| r.message.clone())
        .unwrap_or_else(|| "no error message".into());
    match reply.status {
        401 | 403 => Error::new(
            ErrorKind::Connection,
            format!("Failed to connect to Snowflake: {message}"),
        ),
        408 => Error::new(ErrorKind::Sql, message),
        422 => {
            let field = |v: Option<&String>| v.cloned().unwrap_or_default();
            let r = parsed.as_ref();
            Error::new(
                ErrorKind::Sql,
                format!(
                    "{} ({}): {}: {message}",
                    field(r.and_then(|r| r.code.as_ref())),
                    field(r.and_then(|r| r.sql_state.as_ref())),
                    field(r.and_then(|r| r.statement_handle.as_ref())),
                ),
            )
        }
        status => Error::new(
            ErrorKind::Communication,
            format!("Snowflake returned HTTP {status}: {message}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(account: Option<&str>) -> ConnectionConfig {
        ConnectionConfig {
            account: account.map(String::from),
            ..Default::default()
        }
    }

    #[test]
    fn host_defaults_to_the_account_url() {
        assert_eq!(
            base_url(&conn(Some("myorg-acct"))).unwrap(),
            "https://myorg-acct.snowflakecomputing.com"
        );
        assert_eq!(
            base_url(&conn(Some("xy123.us-east-1"))).unwrap(),
            "https://xy123.us-east-1.snowflakecomputing.com"
        );
        assert_eq!(
            base_url(&conn(Some("xy123.cn-north-1"))).unwrap(),
            "https://xy123.cn-north-1.snowflakecomputing.cn"
        );
    }

    #[test]
    fn host_port_and_protocol_override() {
        let c = ConnectionConfig {
            host: Some("localhost".into()),
            port: Some(8080),
            protocol: Some("HTTP".into()),
            ..conn(None)
        };
        assert_eq!(base_url(&c).unwrap(), "http://localhost:8080");
    }

    #[test]
    fn bad_protocol_or_no_host_is_a_client_error() {
        let c = ConnectionConfig {
            protocol: Some("ftp".into()),
            ..conn(Some("a"))
        };
        assert_eq!(base_url(&c).unwrap_err().kind(), ErrorKind::Client);
        assert_eq!(base_url(&conn(None)).unwrap_err().kind(), ErrorKind::Client);
        assert_eq!(
            base_url(&conn(Some(""))).unwrap_err().kind(),
            ErrorKind::Client
        );
    }

    #[test]
    fn default_options_match_the_adr() {
        let o = ClientOptions::default();
        assert_eq!(o.connect_timeout, Duration::from_secs(30));
        assert_eq!(o.request_timeout, Duration::from_secs(60));
        assert_eq!(o.statement_timeout, None);
        assert_eq!(o.max_retries, 3);
        assert_eq!(o.poll_interval_max, Duration::from_secs(2));
        assert_eq!(o.partition_concurrency, 8);
    }

    #[test]
    fn partition_concurrency_comes_from_the_env() {
        let with = |value: &str| {
            ClientOptions::from_env(&Env::from_pairs([(PARTITION_CONCURRENCY_VAR, value)]))
        };
        assert_eq!(
            ClientOptions::from_env(&Env::default())
                .unwrap()
                .partition_concurrency,
            8
        );
        assert_eq!(with("1").unwrap().partition_concurrency, 1);
        assert_eq!(with(" 64 ").unwrap().partition_concurrency, 64);
        for bad in ["0", "65", "abc", "", "-1"] {
            let err = with(bad).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Client);
            assert_eq!(
                err.message(),
                "SNOW_RS_PARTITION_CONCURRENCY must be an integer from 1 to 64."
            );
        }
    }

    #[test]
    fn new_fails_without_a_host() {
        struct NoAuth;
        impl Authenticator for NoAuth {
            fn authorization(&self) -> Result<crate::auth::AuthHeader> {
                Err(Error::new(ErrorKind::Client, "no"))
            }
        }
        assert!(SqlClient::new(&conn(None), Box::new(NoAuth), ClientOptions::default()).is_err());
    }

    #[test]
    fn timeouts_are_classified() {
        assert!(matches!(
            classify(ureq::Error::Timeout(ureq::Timeout::Connect)),
            TransportError::Connect(_)
        ));
        assert!(matches!(
            classify(ureq::Error::Timeout(ureq::Timeout::PerCall)),
            TransportError::Timeout(_)
        ));
        assert!(matches!(
            classify(ureq::Error::Io(std::io::Error::from(
                std::io::ErrorKind::TimedOut
            ))),
            TransportError::Timeout(_)
        ));
    }
}
