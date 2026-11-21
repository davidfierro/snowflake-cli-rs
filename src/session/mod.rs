//! A connector-protocol session: `login-request`, `query-request` with the session token,
//! renewal and close (ADR 0005, Decisions 1 to 3).
//!
//! The bearer credentials the SQL API already uses (`SNOWFLAKE_JWT`, `OAUTH`,
//! `PROGRAMMATIC_ACCESS_TOKEN`) sign in through `login-request` with their token; the other
//! sign-ins run one of the flows of [`flows`] first (password and MFA, external browser, Okta,
//! OAuth). The heartbeat ([`keepalive`]) and the temporary credential cache ([`cache`]) follow
//! ADR 0005 Decision 3.

pub mod cache;
pub mod callback;
mod flows;
mod keepalive;
mod login;
mod query;

pub use cache::{CredentialCache, FileCache, NoCache};
pub(crate) use login::account_name;
pub use query::{SessionResponse, TransferCommand};

use crate::auth::Authenticator;
use crate::codec::form_encode_plus;
use crate::connection::ConnectionConfig;
use crate::error::{Error, ErrorKind, Result};
use crate::secret::Secret;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

/// The value `snow` sends as `CLIENT_ENVIRONMENT.APPLICATION`.
const APPLICATION: &str = "SNOWFLAKE_CLI";
/// Server code: the session token expired; renew it with the master token.
const SESSION_EXPIRED: &str = "390112";
/// Timeout of the best-effort close request.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
/// Per-request timeout of `login-request`: a Duo push waits for the user (the connector's
/// default authenticator timeout).
const LOGIN_TIMEOUT: Duration = Duration::from_secs(120);

/// How a session talks to Snowflake.
#[derive(Debug, Clone)]
pub struct SessionOptions {
    /// TCP + TLS connection setup, default 30 s.
    pub connect_timeout: Duration,
    /// Per HTTP request, default 60 s.
    pub request_timeout: Duration,
    /// Retries after 429/503/504 or a read timeout, default 3.
    pub max_retries: u32,
    /// Upper bound of the result poll interval (250 ms doubling), default 2 s.
    pub poll_interval_max: Duration,
    /// `--decimal-precision`.
    pub decimal_precision: Option<usize>,
    /// Result chunks downloaded at once: the SQL API's `partition_concurrency`.
    pub partition_concurrency: usize,
    /// `ALL` or `NONE`: sent as `SECONDARY_ROLES` at sign-in, as the connector does.
    pub secondary_roles: Option<&'static str>,
    /// `client_session_keep_alive`: heartbeat while the session is open.
    pub client_session_keep_alive: bool,
    /// `client_session_keep_alive_heartbeat_frequency`, seconds.
    pub heartbeat_frequency: Option<u64>,
    /// `--server-session-keep-alive`: do not close the session when the run ends.
    pub server_session_keep_alive: bool,
    /// How long the browser flows wait for the callback (`external_browser_timeout`, 120 s).
    pub browser_timeout: Duration,
    /// Port of the external-browser callback server (`SF_AUTH_SOCKET_PORT`); 0 picks one.
    pub auth_socket_port: u16,
    /// Tests only: identity-provider requests (Okta) go to this base URL instead.
    pub(crate) idp_override: Option<String>,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            request_timeout: Duration::from_secs(60),
            max_retries: 3,
            poll_interval_max: Duration::from_secs(2),
            decimal_precision: None,
            partition_concurrency: crate::sql::DEFAULT_PARTITION_CONCURRENCY,
            secondary_roles: None,
            client_session_keep_alive: false,
            heartbeat_frequency: None,
            server_session_keep_alive: false,
            browser_timeout: Duration::from_secs(120),
            auth_socket_port: 0,
            idp_override: None,
        }
    }
}

impl SessionOptions {
    /// The connection's keep-alive settings and the callback port from the environment.
    pub fn with_connection(mut self, conn: &ConnectionConfig, env: &crate::env::Env) -> Self {
        self.client_session_keep_alive = conn.client_session_keep_alive == Some(true);
        self.heartbeat_frequency = conn.client_session_keep_alive_heartbeat_frequency;
        self.server_session_keep_alive = conn.server_session_keep_alive == Some(true);
        self.auth_socket_port = env
            .get_non_empty("SF_AUTH_SOCKET_PORT")
            .and_then(|p| p.trim().parse().ok())
            .unwrap_or(0);
        self
    }
}

/// Asks the user for a value, and shows the browser flows' instructions.
pub trait Prompt {
    /// Shows `label` and returns the line typed; `hidden` turns the echo off.
    fn prompt(&self, label: &str, hidden: bool) -> Result<String>;
    /// One line of instructions, on standard error (it must not mix with the results).
    fn say(&self, line: &str);
}

/// Opens a URL in the user's browser; `false` when there is none.
pub trait BrowserOpener {
    fn open(&self, url: &str) -> bool;
}

/// The system browser (`open` crate).
pub struct SystemBrowser;

impl BrowserOpener for SystemBrowser {
    fn open(&self, url: &str) -> bool {
        // Needs a desktop session, so it has no test; the flows are tested with a fake.
        open::that(url).is_ok()
    }
}

/// Where the session talks to, for messages and the URL checks of the flows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub protocol: String,
    pub host: String,
    /// The connection's port; 443 when unset, as the connector reports it.
    pub port: u16,
}

impl Target {
    pub fn of(conn: &ConnectionConfig) -> Result<Self> {
        Ok(Self {
            protocol: conn
                .protocol
                .as_deref()
                .unwrap_or("https")
                .to_ascii_lowercase(),
            host: crate::sql::client::host(conn)?,
            port: conn.port.unwrap_or(443),
        })
    }

    /// `<host>:<port>`, as the connector's sign-in errors show it.
    pub fn host_port(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// A sign-in failure as `snow` shows it: `Could not connect to Snowflake. Reason: ` and the
/// connector's `<errno> (<sqlstate>): <message>` (or `<errno>: <message>` without a state).
pub(crate) fn connect_error(errno: u32, sql_state: Option<&str>, message: &str) -> Error {
    let reason = match sql_state {
        Some(state) => format!("{errno:06} ({state}): {message}"),
        None => format!("{errno:06}: {message}"),
    };
    Error::new(
        ErrorKind::Connection,
        format!("Could not connect to Snowflake. Reason: {reason}"),
    )
}

/// Everything a sign-in needs from the outside world: the test seams (ADR 0005, Decision 2).
pub struct Interaction<'a> {
    /// The bearer credential (key-pair JWT, OAuth token or PAT) the SQL API would use; its
    /// token goes into `login-request` as `TOKEN`. `None`: the connection's authenticator names
    /// a connector flow.
    pub credential: Option<&'a dyn Authenticator>,
    /// Passcodes and the pasted-URL fallbacks of the browser flows.
    pub prompt: &'a dyn Prompt,
    pub browser: &'a dyn BrowserOpener,
    pub cache: &'a dyn CredentialCache,
    pub clock: fn() -> SystemTime,
}

/// A signed-in session. Cheap to clone: transfer workers share it.
#[derive(Clone)]
pub struct Session {
    inner: Arc<Inner>,
}

struct Inner {
    base_url: String,
    agent: ureq::Agent,
    options: SessionOptions,
    tokens: Mutex<Tokens>,
    state: Mutex<State>,
    heartbeat: Mutex<Option<keepalive::Heartbeat>>,
}

struct Tokens {
    session: Secret,
    master: Secret,
}

/// What the server tells the client to keep between requests.
#[derive(Default)]
struct State {
    sequence: u64,
    /// The session `TIMEZONE` from the latest `parameters` (ADR 0005, Decision 2).
    time_zone: Option<String>,
    context: SessionContext,
    /// `sessionId` from the sign-in (`!queries session`).
    session_id: Option<String>,
    /// Set by Ctrl-C in the interactive session: a running statement is cancelled.
    interrupt: Option<Arc<AtomicBool>>,
    /// The ids of the statements submitted with `;>` (the connector's `_async_sfqids`).
    async_ids: Vec<String>,
}

/// The current database, schema, warehouse and role of a session, as the connector tracks
/// them: `sessionInfo` at sign-in, then the `final…Name` fields of each answer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionContext {
    pub database: Option<String>,
    pub schema: Option<String>,
    pub warehouse: Option<String>,
    pub role: Option<String>,
}

impl SessionContext {
    fn from_session_info(info: &serde_json::Value) -> Self {
        let field = |key: &str| info[key].as_str().map(String::from);
        Self {
            database: field("databaseName"),
            schema: field("schemaName"),
            warehouse: field("warehouseName"),
            role: field("roleName"),
        }
    }

    /// `SnowflakeConnection.cmd_query`'s update after a statement (`sql`) answered with `data`:
    /// database and schema change only once set or after `USE`, the role whenever the field is
    /// there.
    fn update(&mut self, sql: &str, data: &serde_json::Value) {
        // Connector parity, not a parser: this is a line-for-line port of
        // `snowflake-connector-python` `SnowflakeCursor` (cursor.py:
        // `is_context_switch = sql.strip().upper().startswith("USE ")`), so `snow` behaves the
        // same. Consequently `/* c */ USE db` (only reachable with `--retain-comments`, since the
        // splitter strips comments by default) is deliberately not a switch. See ADR 0004.
        let switch = sql.trim().to_uppercase().starts_with("USE ");
        let field = |key: &str| data[key].as_str().map(String::from);
        if let Some(db) = field("finalDatabaseName")
            && (self.database.is_some() || switch)
        {
            self.database = Some(db);
        }
        if let Some(schema) = field("finalSchemaName")
            && (self.schema.is_some() || switch)
        {
            self.schema = Some(schema);
        }
        if let Some(warehouse) = field("finalWarehouseName") {
            self.warehouse = Some(warehouse);
        }
        if data.get("finalRoleName").is_some() {
            self.role = field("finalRoleName");
        }
    }
}

/// A response that reached us, whatever its status.
struct Reply {
    status: u16,
    body: String,
}

impl Session {
    /// Signs in with `login-request` after the flow's pre-steps (ADR 0005, Decisions 1 and 4).
    pub fn login(
        conn: &ConnectionConfig,
        options: SessionOptions,
        io: &Interaction,
    ) -> Result<Self> {
        let base_url = crate::sql::client::base_url(conn)?;
        let target = Target::of(conn)?;
        let mut flow = flows::for_connection(conn, io)?;
        let inner = Inner {
            base_url,
            agent: agent(&options, options.request_timeout),
            options,
            tokens: Mutex::new(Tokens {
                session: Secret::new(""),
                master: Secret::new(""),
            }),
            state: Mutex::new(State::default()),
            heartbeat: Mutex::new(None),
        };
        let mut ctx = flows::FlowContext {
            conn,
            io,
            inner: &inner,
            target: &target,
        };
        let data = sign_in(flow.as_mut(), &mut ctx)?;
        inner.update_parameters(&data.parameters);
        {
            let mut state = lock(&inner.state);
            state.context = SessionContext::from_session_info(&data.session_info);
            state.session_id = data.session_id.clone();
        }
        *lock(&inner.tokens) = Tokens {
            session: data.token,
            master: data.master_token,
        };
        let session = Self {
            inner: Arc::new(inner),
        };
        if session.inner.options.client_session_keep_alive {
            let seconds = keepalive::interval(
                session.inner.options.heartbeat_frequency,
                &data.parameters,
                data.master_validity,
            );
            session.start_heartbeat(Duration::from_secs(seconds));
        }
        Ok(session)
    }

    /// `--session-token` / `--master-token`: no sign-in.
    pub fn from_tokens(
        conn: &ConnectionConfig,
        session: Secret,
        master: Secret,
        options: SessionOptions,
    ) -> Result<Self> {
        let base_url = crate::sql::client::base_url(conn)?;
        Ok(Self {
            inner: Arc::new(Inner {
                base_url,
                agent: agent(&options, options.request_timeout),
                options,
                tokens: Mutex::new(Tokens { session, master }),
                state: Mutex::new(State::default()),
                heartbeat: Mutex::new(None),
            }),
        })
    }

    /// Runs one statement and waits for it; renews on 390112 and replays once. A statement
    /// Snowflake rejects is an `Sql` error with `snow`'s text.
    pub fn query(&self, sql: &str) -> Result<SessionResponse> {
        query::run(self, sql)
    }

    /// The id Snowflake gave the session at sign-in.
    pub fn session_id(&self) -> Option<String> {
        lock(&self.inner.state).session_id.clone()
    }

    /// The current database, schema, warehouse and role.
    pub fn context(&self) -> SessionContext {
        lock(&self.inner.state).context.clone()
    }

    /// From now on, a statement stops waiting and is cancelled in Snowflake once `flag` is set
    /// (Ctrl-C in the interactive session).
    pub fn set_interrupt(&self, flag: Arc<AtomicBool>) {
        lock(&self.inner.state).interrupt = Some(flag);
    }

    /// `cursor.execute_async`: submits `sql` without waiting for it (`;>`) and returns its query
    /// id. The session is not ended at close while such a statement still runs.
    pub fn submit_async(&self, sql: &str) -> Result<String> {
        let id = query::submit_async(self, sql)?;
        lock(&self.inner.state).async_ids.push(id.clone());
        Ok(id)
    }

    /// `cursor.query_result(id)`: the result of an earlier statement of this account.
    pub fn query_result(&self, query_id: &str) -> Result<SessionResponse> {
        query::result(self, query_id)
    }

    /// A `GET` of a REST path with the session token, as JSON (`!queries`).
    pub fn get_json(&self, path: &str) -> Result<serde_json::Value> {
        let reply = self.authorized("GET", path, None)?;
        if reply.status != 200 {
            return Err(status_error(reply.status, &reply.body));
        }
        parse(&reply.body)
    }

    /// `POST /queries/v1/abort-request`: cancels the statement `sql` sent with `request_id`.
    fn abort(&self, sql: &str, request_id: &str) -> Result<()> {
        let path = format!(
            "/queries/v1/abort-request?requestId={}",
            uuid::Uuid::new_v4()
        );
        let body = serde_json::json!({ "sqlText": sql, "requestId": request_id }).to_string();
        log::debug!("POST /queries/v1/abort-request");
        self.authorized("POST", &path, Some(&body)).map(drop)
    }

    /// Ends the session (`POST /session?delete=true`); errors are ignored, as the connector.
    /// With `--server-session-keep-alive` the session stays open on the server.
    pub fn close(self) -> Result<()> {
        if let Some(heartbeat) = lock(&self.inner.heartbeat).take() {
            heartbeat.stop();
        }
        if self.inner.options.server_session_keep_alive {
            log::debug!("Leaving the session open (server_session_keep_alive)");
            return Ok(());
        }
        if self.async_still_running() {
            // As the connector: ending the session would cancel them.
            log::debug!("Asynchronous statements are still running, not deleting the session");
            return Ok(());
        }
        let agent = agent(&self.inner.options, CLOSE_TIMEOUT);
        let token = lock(&self.inner.tokens).session.clone();
        let url = format!("{}/session?delete=true", self.inner.base_url);
        log::debug!("POST /session");
        let _ = agent
            .post(&url)
            .header("Authorization", &snowflake_token(&token))
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .send("{}");
        Ok(())
    }

    /// `_all_async_queries_finished`, negated: any `;>` statement of this session still running
    /// per `GET /monitoring/queries/<id>`. A status that cannot be read counts as finished.
    fn async_still_running(&self) -> bool {
        let ids = lock(&self.inner.state).async_ids.clone();
        ids.iter().rev().any(|id| {
            let path = format!("/monitoring/queries/{}", form_encode_plus(id));
            let Ok(value) = self.get_json(&path) else {
                return false;
            };
            // The connector's `_get_query_status` and `is_still_running`: no `queries` is a
            // failure, an empty list is `NO_DATA`.
            let Some(queries) = value["data"]["queries"].as_array() else {
                return false;
            };
            let status = queries
                .first()
                .and_then(|q| q["status"].as_str())
                .unwrap_or("NO_DATA");
            matches!(
                status,
                "RUNNING"
                    | "QUEUED"
                    | "RESUMING_WAREHOUSE"
                    | "QUEUED_REPARING_WAREHOUSE"
                    | "BLOCKED"
                    | "NO_DATA"
            )
        })
    }

    pub(crate) fn options(&self) -> &SessionOptions {
        &self.inner.options
    }

    pub(crate) fn agent(&self) -> &ureq::Agent {
        &self.inner.agent
    }

    /// The session `TIMEZONE` the server reported last, if any.
    pub(crate) fn time_zone(&self) -> Option<String> {
        lock(&self.inner.state).time_zone.clone()
    }

    /// `POST /session/heartbeat` (ADR 0005, Decision 3).
    fn heartbeat(&self) -> Result<()> {
        let path = format!("/session/heartbeat?requestId={}", uuid::Uuid::new_v4());
        let reply = self.authorized("POST", &path, None)?;
        if code_of(&reply.body).is_some() || reply.status != 200 {
            log::warn!(
                "Failed to heartbeat. code: {}",
                code_of(&reply.body).unwrap_or_default()
            );
        }
        Ok(())
    }

    fn start_heartbeat(&self, every: Duration) {
        let weak = Arc::downgrade(&self.inner);
        let beat = move || match weak.upgrade() {
            Some(inner) => {
                let _ = Session { inner }.heartbeat();
                true
            }
            None => false,
        };
        *lock(&self.inner.heartbeat) = Some(keepalive::Heartbeat::start(every, beat));
    }

    /// One request with the session token; a 390112 answer renews the token and replays once.
    fn authorized(&self, method: &str, path: &str, body: Option<&str>) -> Result<Reply> {
        let token = lock(&self.inner.tokens).session.clone();
        let reply = self.inner.send(method, path, body, Some(&token))?;
        if code_of(&reply.body).as_deref() != Some(SESSION_EXPIRED) {
            return Ok(reply);
        }
        self.renew(&token)?;
        let token = lock(&self.inner.tokens).session.clone();
        let reply = self.inner.send(method, path, body, Some(&token))?;
        if code_of(&reply.body).as_deref() == Some(SESSION_EXPIRED) {
            return Err(expired());
        }
        Ok(reply)
    }

    /// `POST /session/token-request` with the master token (ADR 0005, Decision 3).
    fn renew(&self, old: &Secret) -> Result<()> {
        let mut tokens = lock(&self.inner.tokens);
        if tokens.session != *old {
            // Another thread renewed it meanwhile.
            return Ok(());
        }
        let body = Secret::new(
            serde_json::json!({
                "oldSessionToken": tokens.session.expose(),
                "requestType": "RENEW",
            })
            .to_string(),
        );
        let path = format!("/session/token-request?requestId={}", uuid::Uuid::new_v4());
        log::debug!("POST /session/token-request");
        let reply = self
            .inner
            .send("POST", &path, Some(body.expose()), Some(&tokens.master))?;
        let value: serde_json::Value = parse(&reply.body)?;
        let data = &value["data"];
        let Some(session) = data["sessionToken"]
            .as_str()
            .filter(|_| value["success"] == true)
        else {
            return Err(expired());
        };
        tokens.session = Secret::new(session);
        if let Some(master) = data["masterToken"].as_str() {
            tokens.master = Secret::new(master);
        }
        Ok(())
    }
}

impl Inner {
    /// Sends one request, retrying 429/503/504 and read timeouts with the same URL.
    fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        token: Option<&Secret>,
    ) -> Result<Reply> {
        self.send_with(&self.agent, method, path, body, token)
    }

    /// [`Inner::send`] through another agent (the longer sign-in timeout).
    fn send_with(
        &self,
        agent: &ureq::Agent,
        method: &str,
        path: &str,
        body: Option<&str>,
        token: Option<&Secret>,
    ) -> Result<Reply> {
        let url = format!("{}{path}", self.base_url);
        let log_path = path.split('?').next().unwrap_or(path);
        let mut attempt = 0u32;
        loop {
            let failure = match self.send_once(agent, method, &url, body, token) {
                Ok(reply) if matches!(reply.status, 429 | 503 | 504) => Error::new(
                    ErrorKind::Communication,
                    format!("Snowflake returned HTTP {}.", reply.status),
                ),
                Ok(reply) => {
                    log::debug!("{method} {log_path}: HTTP {}", reply.status);
                    return Ok(reply);
                }
                Err((true, e)) => {
                    Error::new(ErrorKind::Communication, "Request to Snowflake timed out.")
                        .with_source(e)
                }
                Err((false, e)) => {
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
            let wait = Duration::from_secs(1 << attempt.min(6));
            attempt += 1;
            log::debug!("{method} {log_path}: retry {attempt} in {wait:?}");
            std::thread::sleep(wait);
        }
    }

    /// `Err((timed_out, error))` when no response arrived.
    fn send_once(
        &self,
        agent: &ureq::Agent,
        method: &str,
        url: &str,
        body: Option<&str>,
        token: Option<&Secret>,
    ) -> std::result::Result<Reply, (bool, ureq::Error)> {
        let auth = token.map(snowflake_token);
        let response = if method == "GET" {
            let mut request = agent.get(url).header("Accept", "application/json");
            if let Some(auth) = &auth {
                request = request.header("Authorization", auth);
            }
            request.call()
        } else {
            let mut request = agent
                .post(url)
                .header("Accept", "application/json")
                .header("Content-Type", "application/json");
            if let Some(auth) = &auth {
                request = request.header("Authorization", auth);
            }
            request.send(body.unwrap_or("{}"))
        };
        let timed_out = |e: &ureq::Error| {
            matches!(e, ureq::Error::Timeout(t) if !matches!(t, ureq::Timeout::Connect | ureq::Timeout::Resolve))
                || matches!(e, ureq::Error::Io(io) if io.kind() == std::io::ErrorKind::TimedOut)
        };
        let mut response = response.map_err(|e| (timed_out(&e), e))?;
        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .with_config()
            .limit(u64::MAX)
            .read_to_string()
            .map_err(|e| (timed_out(&e), e))?;
        Ok(Reply { status, body })
    }

    /// Keeps the session `TIMEZONE` from a `parameters` list (`[{name, value}]`).
    fn update_parameters(&self, parameters: &serde_json::Value) {
        let zone = parameters.as_array().and_then(|list| {
            list.iter()
                .find(|p| p["name"] == "TIMEZONE")
                .and_then(|p| p["value"].as_str())
        });
        if let Some(zone) = zone {
            lock(&self.state).time_zone = Some(zone.to_string());
        }
    }
}

/// The `login-request` exchange: the flow's fields, the Duo push when the server asks for one,
/// and one more attempt when the flow dropped a stale cached token.
fn sign_in(
    flow: &mut dyn flows::LoginFlow,
    ctx: &mut flows::FlowContext<'_>,
) -> Result<login::LoginData> {
    let slow = agent(
        &ctx.inner.options,
        LOGIN_TIMEOUT.max(ctx.inner.options.request_timeout),
    );
    let mut retried = false;
    loop {
        let fields = flow.prepare(ctx)?;
        let body = login::body(ctx.conn, &ctx.inner.options, &fields)?;
        let path = login::path(ctx.conn, &uuid::Uuid::new_v4().to_string());
        log::debug!("POST /session/v1/login-request");
        let reply = ctx
            .inner
            .send_with(&slow, "POST", &path, Some(body.expose()), None)?;
        let mut reply = login::parse_reply(reply.status, &reply.body)?;
        if let login::Reply::Push(in_flight) = reply {
            log::debug!("Waiting for the Duo push to be approved");
            let push = login::push_body(&body, &in_flight)?;
            let answer = ctx
                .inner
                .send_with(&slow, "POST", &path, Some(push.expose()), None)?;
            reply = match login::parse_push_reply(answer.status, &answer.body, ctx.target)? {
                login::PushOutcome::Done(reply) => reply,
                login::PushOutcome::Collect(in_flight) => {
                    let last = login::after_push_body(&body, &in_flight)?;
                    let answer =
                        ctx.inner
                            .send_with(&slow, "POST", &path, Some(last.expose()), None)?;
                    login::parse_reply(answer.status, &answer.body)?
                }
            };
        }
        match reply {
            login::Reply::Success(data) => {
                flow.on_success(&data, ctx)?;
                return Ok(data);
            }
            login::Reply::Failure { code, message } => {
                let retry = flow.on_failure(&code, ctx)?;
                if retry == flows::Retry::Again && !retried {
                    retried = true;
                    continue;
                }
                let error = login::failure(ctx.target, &code, &message);
                return Err(match flow.failure_hint(&code) {
                    Some(hint) => {
                        let text = format!("{}\n{hint}", error.message());
                        Error::new(ErrorKind::Connection, text)
                    }
                    None => error,
                });
            }
            login::Reply::Push(_) => return Err(malformed("a second MFA push request")),
        }
    }
}

fn agent(options: &SessionOptions, timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_connect(Some(options.connect_timeout))
        .timeout_per_call(Some(timeout))
        .user_agent(concat!("snowflake-cli-rs/", env!("CARGO_PKG_VERSION")))
        .build()
        .new_agent()
}

/// `Snowflake Token="<token>"`.
fn snowflake_token(token: &Secret) -> String {
    format!("Snowflake Token=\"{}\"", token.expose())
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // A panic while holding these locks leaves plain data behind; keep using it.
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The top-level `code` of a JSON answer.
fn code_of(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    match &value["code"] {
        serde_json::Value::String(code) => Some(code.clone()),
        serde_json::Value::Number(code) => Some(code.to_string()),
        _ => None,
    }
}

fn expired() -> Error {
    Error::new(
        ErrorKind::Connection,
        "The Snowflake session expired. Sign in again.",
    )
}

pub(crate) fn parse<T: serde::de::DeserializeOwned>(body: &str) -> Result<T> {
    serde_json::from_str(body).map_err(|e| {
        Error::new(
            ErrorKind::Communication,
            "Snowflake returned a malformed response.",
        )
        .with_source(e)
    })
}

pub(crate) fn malformed(what: &str) -> Error {
    Error::new(
        ErrorKind::Communication,
        format!("Snowflake returned a malformed response: {what}."),
    )
}

/// The error for an HTTP status other than 200 (as the SQL API client maps them).
fn status_error(status: u16, body: &str) -> Error {
    let value: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    let message = value["message"].as_str().unwrap_or("no error message");
    match status {
        401 | 403 => Error::new(
            ErrorKind::Connection,
            format!("Failed to connect to Snowflake: {message}"),
        ),
        status => Error::new(
            ErrorKind::Communication,
            format!("Snowflake returned HTTP {status}: {message}"),
        ),
    }
}

#[cfg(test)]
mod flow_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn codes_are_read_as_strings_or_numbers() {
        assert_eq!(code_of(r#"{"code":"390112"}"#).as_deref(), Some("390112"));
        assert_eq!(code_of(r#"{"code":390112}"#).as_deref(), Some("390112"));
        assert_eq!(code_of(r#"{"code":null}"#), None);
        assert_eq!(code_of("not json"), None);
    }

    #[test]
    fn status_errors_map_like_the_sql_api_client() {
        let err = status_error(401, r#"{"message":"bad"}"#);
        assert_eq!(err.kind(), ErrorKind::Connection);
        assert_eq!(err.message(), "Failed to connect to Snowflake: bad");
        let err = status_error(500, "");
        assert_eq!(err.kind(), ErrorKind::Communication);
        assert_eq!(
            err.message(),
            "Snowflake returned HTTP 500: no error message"
        );
    }

    #[test]
    fn use_switches_the_database_but_a_leading_comment_does_not() {
        let answer = json!({"finalDatabaseName": "DB"});
        let mut ctx = SessionContext::default();
        ctx.update("USE db", &answer);
        assert_eq!(ctx.database.as_deref(), Some("DB"));

        // Connector parity: the comment hides `USE` from the prefix check.
        let mut ctx = SessionContext::default();
        ctx.update("/* c */ USE db", &answer);
        assert_eq!(ctx.database, None);
    }

    #[test]
    fn default_options() {
        let o = SessionOptions::default();
        assert_eq!(o.max_retries, 3);
        assert_eq!(o.poll_interval_max, Duration::from_secs(2));
        assert_eq!(o.secondary_roles, None);
        assert_eq!(o.browser_timeout, Duration::from_secs(120));
        assert!(!o.client_session_keep_alive && !o.server_session_keep_alive);
    }

    #[test]
    fn connection_keep_alive_settings_and_the_callback_port() {
        let conn = ConnectionConfig {
            client_session_keep_alive: Some(true),
            client_session_keep_alive_heartbeat_frequency: Some(900),
            server_session_keep_alive: Some(true),
            ..Default::default()
        };
        let env =
            crate::env::Env::from_pairs([("SF_AUTH_SOCKET_PORT".to_string(), "8123".to_string())]);
        let o = SessionOptions::default().with_connection(&conn, &env);
        assert!(o.client_session_keep_alive && o.server_session_keep_alive);
        assert_eq!(o.heartbeat_frequency, Some(900));
        assert_eq!(o.auth_socket_port, 8123);
        let o = SessionOptions::default().with_connection(
            &ConnectionConfig::default(),
            &crate::env::Env::from_pairs(Vec::<(String, String)>::new()),
        );
        assert_eq!(o.auth_socket_port, 0);
    }

    #[test]
    fn targets_and_connect_errors() {
        let conn = ConnectionConfig {
            account: Some("acct".into()),
            protocol: Some("HTTP".into()),
            ..Default::default()
        };
        let t = Target::of(&conn).unwrap();
        assert_eq!(t.protocol, "http");
        assert_eq!(t.host_port(), "acct.snowflakecomputing.com:443");
        assert!(Target::of(&ConnectionConfig::default()).is_err());
        assert_eq!(
            connect_error(251006, None, "Password is empty").message(),
            "Could not connect to Snowflake. Reason: 251006: Password is empty"
        );
        assert_eq!(
            connect_error(250001, Some("08001"), "m").message(),
            "Could not connect to Snowflake. Reason: 250001 (08001): m"
        );
    }
}
