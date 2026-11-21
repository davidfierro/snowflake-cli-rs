# ADR 0001: Stage 0 foundation: transport, module boundaries, errors, crates and testing

- **Status:** Accepted (on merge)
- **Amended by:** [ADR 0002](0002-parallel-partitions-and-streaming.md) (Decision 2 Stream B
  interface, Decisions 5, 6 and 9: parallel partitions and streaming results);
  [ADR 0005](0005-connector-protocol-transport.md) (Decision 1 PUT/GET, Decision 2 shared
  `src/connection.rs` fields)
- **Date:** 2026-11-20
- **Reference implementation:** Snowflake CLI `snow` **3.34.0** (`pip install snowflake-cli==3.34.0`)
  and the `snowflake-connector-python` it pins. "snow" below always means that version.

## Context

This repo ports `snow` to a single native Rust binary, one command group at a time
(`connection` → `sql` → `object` → `stage` → `helpers`). Stage 0 builds the foundation every
command needs: config files, connection resolution, global flags, key-pair JWT sign-in, a SQL
client, a typed result model, the four `--format` renderers, errors and exit codes. It ships no
user command; it is proved by a library-level sandbox test (sign in, `SELECT CURRENT_ROLE()`,
render in all four formats).

Stage 2 builds it as two sub-issues **in parallel**:

- **Stream A:** config files, connection resolution, global flags.
- **Stream B:** key-pair JWT auth, SQL client, result model, renderers, exit codes.

This ADR fixes everything both streams need so neither has to ask or wait: the transport, the
module layout and public interfaces, the shared types (verbatim, in the appendix), the
compatibility rules, the crates, and the testing strategy.

Every compatibility rule below was checked against snow 3.34.0's source, by running snow 3.34.0
locally, and, for the transport and output formats, against the Snowflake sandbox with synthetic
literal queries (`SELECT 1::NUMBER(10,2)`, …; no table data). Where snow differs from what
refinement assumed, the section says so; the full list is under
[Discrepancies](#discrepancies-with-the-refinement-brief).

## Decision 1: Transport is the Snowflake SQL REST API v2

### Options

| | SQL REST API v2 (`/api/v2/statements`) | Internal connector protocol (`/session/v1/login-request`, `/queries/v1/query-request`) |
|---|---|---|
| Documentation | Public, versioned, [documented](https://docs.snowflake.com/en/developer-guide/sql-api/intro) | Undocumented; reverse-engineered from the open-source drivers |
| Stability | Contract Snowflake commits to | Can change with driver releases |
| Auth | Bearer key-pair JWT per request, stateless | Login request → session token + master token, renewal, heartbeat |
| Result format | JSON (`jsonv2`), values as strings, partitions | Arrow (default) or JSON chunks on S3/Azure/GCS presigned URLs |
| Sessions | None: every request is a fresh session | Real session (`USE`, `ALTER SESSION`, temp tables persist) |
| PUT/GET | **Not supported** | Supported (driver uploads to stage storage itself) |
| Effort in Rust | Small: HTTPS + JSON | Large: login flow, token renewal, Arrow decoding, cloud storage clients |

### Decision

Use the **SQL REST API v2** for stage 0 and every command group until one needs something it
cannot do. It is public and stable, stateless key-pair auth fits a CLI exactly, and it is a small
amount of code we can mock completely in tests.

Verified on the sandbox (2026-11-20): `POST /api/v2/statements` with a key-pair JWT returns 200
with `resultSetMetaData` (`rowType`, `numRows`, `partitionInfo`, `format: "jsonv2"`) and `data`
as arrays of strings; a 300 000-row result came back in 8 partitions; a SQL error returns 422
with `code`, `sqlState`, `message`, `statementHandle`; `USE SCHEMA public` returns 422
`Command not supported by SQL API: USE` (code 391911).

### Known limits and how we handle them

From the [SQL API docs](https://docs.snowflake.com/en/developer-guide/sql-api/intro#limitations-of-the-sql-api)
and the sandbox:

- **PUT and GET are not supported.** No stage-0 or `sql`/`object` feature needs them. **The
  PUT/GET transport is decided when the `stage copy` work starts** (options then: implement the
  connector's upload protocol for PUT/GET only, use `COPY FILES`/presigned URLs, or shell out).
  Out of scope here.
  *Amended by [ADR 0005](0005-connector-protocol-transport.md):* PUT/GET (and the sign-ins the
  SQL API cannot do) use the connector protocol on a session transport, decided for `snow sql`.
- **`USE`, `ALTER SESSION`, `BEGIN`/`COMMIT`/`ROLLBACK`, session variables and temporary
  tables/stages work only inside a multi-statement request** (one request with
  `MULTI_STATEMENT_COUNT`), because every request is its own session. Consequence: the
  connection's `database`, `schema`, `role` and `warehouse` are sent as the request body fields
  of every statement, never as `USE` statements. Multi-statement requests (needed by `snow sql`
  with several statements and `!source`) are designed in the `sql` stage; stage 0 executes one
  statement per request.
- **`AUTOCOMMIT` is always TRUE** per statement.
- **Long-running statements are asynchronous:** after ~45 s the API answers 202 with a
  `statementHandle`; the client polls `GET /api/v2/statements/{handle}` (Decision 5).
- **Large results are split into partitions:** partition 0 comes with the metadata; partitions
  1..n are fetched with `GET /api/v2/statements/{handle}?partition=N`, gzip-encoded and without
  metadata (Decision 5).
- **Values are strings** whatever the column type; the client converts them using `rowType`
  (Decision 6).
- Some Python/Java stored procedures returning Arrow result sets may fail through the SQL API.
  Accepted; revisit if a command needs them.

## Decision 2: Module boundaries and interfaces

One crate (lib + `snow` bin), as today. Modules and their owner stream:

| Path | Owner | Content |
|---|---|---|
| `src/lib.rs` | shared | `run()`: parse args → globals → command dispatch (no commands yet) → exit code |
| `src/secret.rs` | **shared, verbatim** | `Secret` (Appendix A) |
| `src/error.rs` | **shared, verbatim** | `Error`, `ErrorKind`, `Result`, default exit codes (Appendix A) |
| `src/connection.rs` | **shared, verbatim** | `ConnectionConfig`: the A → B contract (Appendix A) |
| `src/output/mod.rs`, `src/output/format.rs` | **shared, verbatim** | `OutputFormat` (Appendix A) |
| `src/env.rs` | A | `Env`: injectable snapshot of environment variables |
| `src/config/` | A | config paths, TOML loading, permission checks, `resolve_connection` |
| `src/cli/` | A | `GlobalOptions`, `ConnectionOptions` (clap `Args`), `--config-file` |
| `src/diag.rs` | A | stderr logger behind the `log` facade, `Verbosity` |
| `src/auth/` | B | `Authenticator` trait, `KeyPairAuthenticator` |
| `src/sql/` | B | `SqlClient`, `ClientOptions`, SQL API wire types (private), result model |
| `src/render/` | B | JSON, CSV, TABLE, PLAIN renderers; Python-compatible value formatting |
| `src/report.rs` | B | `report_error`: prints an `Error` to stderr |

### Shared files: how the parallel build avoids conflicts

The four **shared, verbatim** files are given in full in Appendix A. **Both** stage-2 PRs add
them byte-for-byte as written there (they compile on their own: dependencies `clap`, `thiserror`,
`zeroize`). Git merges identical additions cleanly, so whichever PR lands second has nothing to
resolve in them; `Cargo.toml`/`Cargo.lock`/`lib.rs` conflicts are trivial unions. Changing a
shared file needs an amendment to this ADR in the same PR. Each stream may add items to its own
modules freely; it must not add items to a shared file.

### The contract between the streams

```mermaid
flowchart LR
  subgraph A["Stream A"]
    argv["argv"] --> opts["cli::GlobalOptions<br/>cli::ConnectionOptions"]
    envv["process env"] --> env["env::Env"]
    files["config.toml<br/>connections.toml"] --> src["config::ConfigSource::load"]
    opts --> resolve["config::resolve_connection"]
    env --> resolve
    src --> resolve
    opts --> fmt["GlobalOptions::output_format"]
    opts --> diag["diag::init(Verbosity)"]
  end
  resolve --> conn[["ConnectionConfig (shared)"]]
  fmt --> of[["OutputFormat (shared)"]]
  subgraph B["Stream B"]
    conn --> auth["auth::KeyPairAuthenticator::from_connection"]
    conn --> client["sql::SqlClient::new"]
    auth --> client
    client --> qr["SqlClient::execute -> sql::QueryResult"]
    qr --> render["render::render"]
    of --> render
  end
  render --> stdout["stdout"]
  err[["error::Error (shared)"]] --> report["report::report_error + Error::exit_code"] --> stderr["stderr + exit code"]
```

- A produces a fully resolved `ConnectionConfig` and an `OutputFormat`; B consumes only those.
  B never reads environment variables or config files; A never touches HTTP or rendering.
- Both log only through the `log` macros (`log::info!`, `log::debug!`, `log::warn!`); A installs
  the logger. Nobody writes diagnostics with `eprintln!` except `diag` and `report`.
- Both return `error::Error` with the right `ErrorKind`; only `lib::run` turns it into output and
  an exit code.

### Stream A public interface

Signatures are binding; private helpers and extra items are the builder's choice.

```rust
// src/env.rs
/// Snapshot of the process environment. Tests build one from pairs and never touch the real env.
#[derive(Debug, Clone, Default)]
pub struct Env { /* BTreeMap<String, String>; Debug must not print values */ }
impl Env {
    pub fn from_process() -> Self;
    pub fn from_pairs<I, K, V>(pairs: I) -> Self
    where I: IntoIterator<Item = (K, V)>, K: Into<String>, V: Into<String>;
    pub fn get(&self, name: &str) -> Option<&str>;
}

// src/config/mod.rs
/// Where config.toml and connections.toml are read from (Decision 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigPaths {
    pub config_file: std::path::PathBuf,
    pub connections_file: std::path::PathBuf,
    /// true when config_file came from --config-file (permission problems only warn).
    pub config_file_is_custom: bool,
}
impl ConfigPaths {
    pub fn discover(env: &Env, config_file_override: Option<&std::path::Path>) -> Result<Self>;
}

/// Parsed config.toml + connections.toml, after the permission checks.
#[derive(Debug, Clone)]
pub struct ConfigSource { /* private */ }
impl ConfigSource {
    pub fn load(paths: &ConfigPaths) -> Result<Self>;
    /// `default_connection_name`: env SNOWFLAKE_DEFAULT_CONNECTION_NAME > config.toml > "default".
    pub fn default_connection_name(&self, env: &Env) -> String;
    /// Connection names defined in the files, in file order.
    pub fn connection_names(&self) -> Vec<String>;
}

/// Applies the precedence of Decision 3 and returns the connection B uses.
pub fn resolve_connection(
    source: &ConfigSource,
    options: &crate::cli::ConnectionOptions,
    env: &Env,
) -> Result<crate::connection::ConnectionConfig>;

// src/cli/mod.rs: clap `Args` that every future command flattens; root keeps --config-file.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct GlobalOptions {
    /// --format TABLE|JSON|CSV|PLAIN (case-insensitive)
    pub format: Option<crate::output::format::OutputFormat>,
    pub verbose: bool, // --verbose, -v
    pub debug: bool,   // --debug
    pub silent: bool,  // --silent
}
impl GlobalOptions {
    /// --format > env SNOWFLAKE_CLI_OUTPUT_FORMAT > config `[cli] output_format` > TABLE.
    /// An invalid env/config value is a Usage error (exit 2), as in snow.
    pub fn output_format(&self, source: &ConfigSource, env: &Env) -> Result<crate::output::format::OutputFormat>;
    pub fn verbosity(&self) -> crate::diag::Verbosity;
}

#[derive(Debug, Clone, Default, clap::Args)]
pub struct ConnectionOptions {
    pub connection: Option<String>,               // -c, --connection, --environment
    pub temporary_connection: bool,               // -x, --temporary-connection
    pub account: Option<String>,                  // --account, --accountname
    pub user: Option<String>,                     // --user, --username
    pub host: Option<String>,                     // --host
    pub port: Option<u16>,                        // --port
    pub authenticator: Option<String>,            // --authenticator
    pub private_key_file: Option<std::path::PathBuf>, // --private-key-file, --private-key-path
    pub database: Option<String>,                 // --database, --dbname
    pub schema: Option<String>,                   // --schema, --schemaname
    pub role: Option<String>,                     // --role, --rolename
    pub warehouse: Option<String>,                // --warehouse
}

// src/diag.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verbosity { Normal, Verbose, Debug }
/// Installs the stderr logger: Normal = warn, Verbose = info, Debug = debug.
/// Idempotent (tests call it repeatedly).
pub fn init(verbosity: Verbosity);
```

Flag spellings, short options and aliases are snow's (checked in
`snowflake/cli/api/commands/flags.py`). Flags snow has for other auth methods (`--password`,
`--token`, `--oauth-*`, `--mfa-passcode`, …) and `--enhanced-exit-codes`,
`--decimal-precision`, `--protocol` are **not** added in stage 0; clap rejects them with exit 2
until the issue that implements them.

### Stream B public interface

Amended by [ADR 0002](0002-parallel-partitions-and-streaming.md): `SqlClient::query` →
`RowStream`, `ClientOptions::partition_concurrency` and `from_env`, `render_stream`.

```rust
// src/auth/mod.rs
/// Something that can authorize one HTTP request to the SQL API.
pub trait Authenticator: Send + Sync {
    fn authorization(&self) -> Result<AuthHeader>;
}
#[derive(Debug, Clone)]
pub struct AuthHeader {
    pub token: crate::secret::Secret,  // value of `Authorization: Bearer …`
    pub token_type: &'static str,      // `X-Snowflake-Authorization-Token-Type`, "KEYPAIR_JWT"
}

// src/auth/keypair.rs
pub struct KeyPairAuthenticator { /* RSA key, account, user, fingerprint, clock */ }
impl KeyPairAuthenticator {
    /// Fails (Client) unless authenticator is SNOWFLAKE_JWT, account and user are set, and exactly
    /// one of private_key_file / private_key_raw yields a PKCS#8 key (Decision 4).
    pub fn from_connection(conn: &crate::connection::ConnectionConfig) -> Result<Self>;
    /// Test seam: fixed clock for deterministic JWTs.
    pub fn with_clock(self, now: fn() -> std::time::SystemTime) -> Self;
    /// "SHA256:<base64>" of the public key's DER SubjectPublicKeyInfo.
    pub fn public_key_fingerprint(&self) -> &str;
}
impl Authenticator for KeyPairAuthenticator { /* fresh JWT per call */ }

// src/sql/client.rs
#[derive(Debug, Clone)]
pub struct ClientOptions {
    pub connect_timeout: std::time::Duration,       // default 30 s
    pub request_timeout: std::time::Duration,       // per HTTP request, default 60 s
    pub statement_timeout: Option<std::time::Duration>, // body `timeout`; None = server default
    pub max_retries: u32,                           // default 3
    pub poll_interval_max: std::time::Duration,     // default 2 s
}
impl Default for ClientOptions { /* the defaults above */ }

pub struct SqlClient { /* base URL, ureq agent, Box<dyn Authenticator>, options, context */ }
impl SqlClient {
    /// Base URL from the connection (Decision 5). No network access.
    pub fn new(
        conn: &crate::connection::ConnectionConfig,
        auth: Box<dyn crate::auth::Authenticator>,
        options: ClientOptions,
    ) -> Result<Self>;
    /// Runs one statement and returns all rows of all partitions.
    pub fn execute(&self, sql: &str) -> Result<crate::sql::result::QueryResult>;
}

// src/sql/result.rs
#[derive(Debug, Clone, PartialEq)]
pub struct QueryResult {
    pub statement_handle: String,
    pub columns: Vec<Column>,       // names already de-duplicated (Decision 6)
    pub rows: Vec<Vec<Value>>,      // rows[i].len() == columns.len()
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    pub sf_type: SfType,
    pub nullable: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SfType {
    Fixed { precision: u8, scale: u8 },
    Real,
    Decfloat,
    Text,
    Binary,
    Boolean,
    Date,
    Time { scale: u8 },
    TimestampNtz { scale: u8 },
    TimestampLtz { scale: u8 },
    TimestampTz { scale: u8 },
    Variant,
    Object,
    Array,
    /// A rowType the client does not know yet (e.g. "vector", "geography"); values stay Text.
    Other(String),
}
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i128),                // FIXED with scale 0 (NUMBER(38,0) needs i128)
    Decimal(String),          // FIXED with scale > 0, DECFLOAT: the exact digits returned ("1.50")
    Float(f64),               // REAL, incl. NaN and ±inf
    Text(String),
    Binary(Vec<u8>),
    Date(jiff::civil::Date),
    Time(jiff::civil::Time),
    TimestampNtz(jiff::civil::DateTime),
    /// TIMESTAMP_TZ, and TIMESTAMP_LTZ converted to the session time zone.
    TimestampTz { local: jiff::civil::DateTime, offset_seconds: i32 },
    Json(String),             // VARIANT / OBJECT / ARRAY, text exactly as returned
}

// src/render/mod.rs
/// Writes `result` to `out` in `format` (Decision 6). A BrokenPipe write error returns Ok.
pub fn render(
    result: &crate::sql::result::QueryResult,
    format: crate::output::format::OutputFormat,
    out: &mut dyn std::io::Write,
) -> Result<()>;

// src/report.rs
/// Prints `err` to `stderr` as snow does; with `debug`, adds the `source()` chain (no backtrace).
pub fn report_error(err: &crate::error::Error, debug: bool, stderr: &mut dyn std::io::Write);
```

The stage-0 proof is a test in `tests/sandbox.rs` (B) that builds a `ConnectionConfig` from the
sandbox env, runs `SELECT CURRENT_ROLE()` and renders it in all four formats. Once both streams
are merged, the same test switches to `resolve_connection` (a one-line follow-up in whichever PR
merges second, or in stage 1).

## Decision 3: Config compatibility contract

Same files, same precedence, same keys as snow, so a user can switch between both CLIs without
touching their config. Verified in snow 3.34.0's `snowflake/cli/api/config.py`,
`snowflake/cli/_app/snow_connector.py`, `snowflake/connector/{sf_dirs,config_manager}.py`,
and by running snow against temp `SNOWFLAKE_HOME` directories.

### Files

1. **Config directory:** `$SNOWFLAKE_HOME` (default `~/.snowflake`) **if that directory
   exists**; otherwise the platform user config dir + `snowflake`: `$XDG_CONFIG_HOME/snowflake`
   or `~/.config/snowflake` on Linux, `~/Library/Application Support/snowflake` on macOS,
   `%LOCALAPPDATA%\snowflake` on Windows (platformdirs `user_config_dir` with
   `appauthor=False`, `roaming=False`). Implemented with `std::env::home_dir` and env vars; no
   `dirs` crate (Decision 8).
2. **Files:** `<dir>/config.toml` and `<dir>/connections.toml`. `--config-file <path>` replaces
   only `config.toml`; `connections.toml` is still read from `<dir>`.
3. **Where connections come from:** `[connections.<name>]` tables in `config.toml`, **unless
   `connections.toml` exists**: then its top-level `[<name>]` tables replace the whole
   `connections` section of `config.toml` (they are not merged).
4. **Default connection name:** env `SNOWFLAKE_DEFAULT_CONNECTION_NAME` > top-level
   `default_connection_name` in `config.toml` > `"default"`.
5. **Permissions (Unix only):** for the default files, any group/other permission bit
   (`mode & 0o077 != 0`) is an error, exit 1: `Configuration file <path> has too wide
   permissions.` followed by `chmod 0600 "<path>"`. For a `--config-file` file, group/other
   readable is only a warning; group/other writable is an error. A missing file is fine.
6. **Corrupt TOML:** error, exit 1, `Configuration file seems to be corrupted. <parser message>`.
   The parser message must not echo values (only line/column and key names).

### Connection resolution (precedence)

For a named connection (`-c NAME`, else the default connection name):

1. **CLI flags** (`ConnectionOptions`): highest.
2. **`SNOWFLAKE_CONNECTIONS_<NAME>_<KEY>`** env vars (NAME and KEY upper-cased) override the
   same key in the file.
3. **The connection's table in the file.**
4. **`SNOWFLAKE_<KEY>`** generic env vars, **only for keys still unset after 1–3.**

With `-x/--temporary-connection` there is no file layer: flags, then `SNOWFLAKE_<KEY>`.
`-c` together with `-x` is a Usage error.

Then:

- If the named connection is not in the files, error exit 1:
  `Connection <name> is not configured` (for the default connection:
  ``Couldn't find connection for default connection `<name>`. Specify connection name or
  configure default connection.``). A connection defined **only** by
  `SNOWFLAKE_CONNECTIONS_<NAME>_*` env vars is **not** usable (snow behaves the same).
- Key aliases: `private_key_path` → `private_key_file`; `private_key_file_pwd` →
  `private_key_passphrase`.
- `PRIVATE_KEY_PASSPHRASE` env, when set, replaces `private_key_passphrase` from any layer
  (snow applies it when it loads the key; A applies it during resolution so B never reads env).
  Set-but-empty stays `Some("")`; B rejects it for an encrypted key.
- Stage-0 keys, which snow also reads from `SNOWFLAKE_<KEY>`: `account`, `user`, `host`, `port`,
  `protocol`, `authenticator`, `private_key_file`, `private_key_path`, `private_key_raw`,
  `database`, `schema`, `role`, `warehouse`, plus `private_key_passphrase` from files and
  `SNOWFLAKE_CONNECTIONS_*`.
- **Other keys** (`password`, `token`, `oauth_*`, `region`, `session_token`, …, or unknown
  ones) are ignored, with one `log::info!` per key under `--verbose`:
  `Ignoring unsupported connection key '<key>' in connection '<name>'` (key name only, never the
  value).
- A `port` that is not a valid `u16` is a Client error naming the key and its source, not the
  value.

### Output format resolution

`--format` > `SNOWFLAKE_CLI_OUTPUT_FORMAT` > `[cli] output_format` in `config.toml` > `TABLE`,
case-insensitive. `JSON_EXT` is a Usage error until it is implemented.

### Not in stage 0

`[cli.logs]` file logging, `[cli.features]`, `[cli.plugins]`, `SNOWFLAKE_CONNECTIONS` (the whole
connections table as one TOML env var), the `SNOWFLAKE_CLI_CONFIG_V2_ENABLED` alternative
config provider, `region`, and writing config files (that is `snow connection add`, stage 1).

## Decision 4: Key-pair JWT authentication

Only `authenticator = SNOWFLAKE_JWT` (case-insensitive) is accepted in stage 0. Any other or
missing authenticator is a Client error: `Only key-pair authentication (authenticator =
SNOWFLAKE_JWT) is supported in this version.` (snow also refuses a private key unless the
authenticator is `SNOWFLAKE_JWT`).

- **Key source:** `private_key_file` (read from disk) if set, else `private_key_raw` (inline
  PEM). Neither → Client error.
- **Formats:** PEM PKCS#8 only, as snow: `-----BEGIN PRIVATE KEY-----` (unencrypted; a passphrase,
  if any, is ignored) or `-----BEGIN ENCRYPTED PRIVATE KEY-----` (PBES2: PBKDF2 or scrypt with
  AES-128/192/256-CBC, **and DES-EDE3-CBC**, which Snowflake's own key-pair guide uses with
  `openssl pkcs8 -topk8 -v2 des3`). Anything else (PKCS#1 `BEGIN RSA PRIVATE KEY`, PBES1) →
  `Private key provided is not in PKCS#8 format. Please use correct format.`
- **Encrypted key without passphrase, or with an empty one:** Client error asking to set
  `PRIVATE_KEY_PASSPHRASE`. Wrong passphrase: Client error `Failed to decrypt the private key:
  wrong passphrase or unsupported encryption`. Errors never contain the PEM or passphrase.
- **JWT** ([docs](https://docs.snowflake.com/en/developer-guide/sql-api/authenticating)):
  header `{"alg":"RS256","typ":"JWT"}`; claims `iss = <ACCOUNT>.<USER>.SHA256:<fp>`,
  `sub = <ACCOUNT>.<USER>`, `iat = now`, `exp = now + 3540` (seconds; Snowflake caps a JWT at
  one hour). `<ACCOUNT>`: the account up to the first `.` (or, if it contains `.global`, up to
  the first `-`), upper-cased, exactly as `snowflake-connector-python`'s
  `auth/keypair.py`; `<USER>` upper-cased. `<fp>`: base64 (standard, padded) SHA-256 of the
  public key's DER SubjectPublicKeyInfo.
- **A new JWT for every HTTP request** (signing costs ~1 ms), so long polls never hit expiry and
  no renewal logic is needed.
- Headers: `Authorization: Bearer <jwt>`, `X-Snowflake-Authorization-Token-Type: KEYPAIR_JWT`.

The spike for this ADR checked the crate stack: `rsa` 0.10 + `pkcs8` 0.11 decrypts unencrypted,
AES-256 and DES3 PKCS#8 keys generated by openssl, the fingerprint equals openssl's, and a wrong
passphrase fails. A Python prototype of the same JWT signed in to the sandbox.

## Decision 5: SQL client behaviour

- **Base URL:** `<protocol>://<host>[:<port>]`. `protocol` defaults to `https`; `host` defaults
  to `<account>.snowflakecomputing.com` (`.cn` when the account's second dot-part starts with
  `cn-`, as the connector's `construct_hostname`). Tests point `host`/`port`/`protocol=http` at
  the mock server: no hidden test-only seam.
- **Submit:** `POST /api/v2/statements?requestId=<uuid v4>` with JSON body `statement`,
  `database`, `schema`, `warehouse`, `role` (each only if set), `timeout` (if
  `statement_timeout` is set). Headers: auth (Decision 4), `Content-Type`/`Accept:
  application/json`, `User-Agent: snowflake-rs-cli/<version>`.
- **Responses:**

| Status | Meaning | Client action | `ErrorKind` |
|---|---|---|---|
| 200 | Done, partition 0 inline | Parse; fetch partitions 1..n with `GET …/{handle}?partition=N` (gzip handled by ureq), in parallel and yielded in order (ADR 0002) | — |
| 202 | Still running | Poll `GET /api/v2/statements/{handle}`, interval 250 ms doubling to `poll_interval_max` | — |
| 401, 403 | JWT rejected | Fail: `Failed to connect to Snowflake: <server message>` | `Connection` |
| 408 | Statement hit `timeout` | Fail with server message | `Sql` |
| 422 | SQL error | Fail: `<code> (<sqlState>): <statementHandle>: <message>` (snow's format) | `Sql` |
| 429, 503, 504 | Throttled / unavailable | Retry with backoff 1 s, 2 s, 4 s (`Retry-After` if present) up to `max_retries`; POST is resubmitted with the same `requestId` and `retry=true` | `Communication` after the last try |
| other 4xx/5xx | Unexpected | Fail with status and server message | `Communication` |
| DNS / TCP / TLS failure | — | Fail | `Connection` |
| HTTP read timeout | — | Retry like 503, then fail | `Communication` |
| Malformed JSON, missing fields | — | Fail | `Communication` |

- **TIMESTAMP_LTZ:** values arrive as epoch seconds; snow prints them in the session
  `TIMEZONE`. When a result has an LTZ column, the client runs one extra
  `SHOW PARAMETERS LIKE 'TIMEZONE'` (same connection context) and converts LTZ values to
  `Value::TimestampTz` in that zone (IANA names via `jiff`). Verified: a sandbox user with
  `America/Los_Angeles` gets `2024-01-01T19:04:05-08:00` from snow for
  `'2024-01-02 03:04:05 +00:00'::timestamp_ltz`.
- No async runtime: one blocking `ureq::Agent`. Partitions 1..n are downloaded in parallel on
  std threads within a bounded window and streamed in order: see
  [ADR 0002](0002-parallel-partitions-and-streaming.md), which amends this decision.

## Decision 6: Result model and output fidelity

### Fidelity rule

- **JSON and CSV are identical to snow** in structure, keys and value formatting, byte for byte,
  proven by golden tests (Decision 9).
- **TABLE and PLAIN are visually equivalent**, not byte-identical: same columns, same cell text,
  same border style.
- **`JSON_EXT` comes later.**

### Value conversion (SQL API string → `Value`) and rendering

snow renders what `snowflake-connector-python` returns (Python `int`, `Decimal`, `float`,
`datetime`, …) through `json.dumps`, its own CSV writer and `str()`. The renderers reproduce
those Python formatting rules. Rows marked ✓ were verified against snow 3.34.0 on the sandbox:

| Snowflake type (`rowType.type`) | SQL API string | `Value` | JSON | CSV | TABLE / PLAIN | |
|---|---|---|---|---|---|---|
| `fixed`, scale 0 | `"1"` | `Int` | `1` | `1` | `1` | ✓ |
| `fixed`, scale > 0 | `"1.50"` | `Decimal` | `"1.50"` (string) | `1.50` | `1.50` | ✓ |
| same, tiny | `"0.00000010"` | `Decimal` | `"1.0E-7"`: Python `str(Decimal)`, scientific when adjusted exponent < −6 | `1.0E-7` | `1.0E-7` | ✓ |
| `real` | `"1.5"`, `"1e16"`, … | `Float` | Python `repr(float)`: `1.5`, `1e+16`, `1e-05`, `Infinity`, `NaN` | `1.5`, `1e+16`, `inf`, `nan` | as CSV | ✓ |
| `boolean` | `"true"` | `Bool` | `true` | `True` | `True` | ✓ |
| `text` | `"café,\"x\""` | `Text` | `"café,\"x\""` (ASCII-only escaping, `ensure_ascii`) | `"café,""x"""` | `café,"x"` | ✓ |
| `binary` | `"AB"` (upper hex) | `Binary` | `"ab"` (lower hex) | `ab` | `ab` | ✓ |
| `date` | `"19724"` (days) | `Date` | `"2024-01-02"` | `2024-01-02` | `2024-01-02` | ✓ |
| `time` | `"36672.000000000"` | `Time` | `"10:11:12"`; `.ffffff` only if micros ≠ 0, nanos truncated | same | same | ✓ |
| `timestamp_ntz` | `"1704164645.123456789"` | `TimestampNtz` | `"2024-01-02T03:04:05.123456"` (micros, truncated; no fraction if 0) | same | `2024-01-02 03:04:05.123456` (space) | ✓ |
| `timestamp_tz` | `"1704157445.000000000 1560"` (offset + 1440 min) | `TimestampTz` | `"2024-01-02T03:04:05+02:00"` | same | space separator | ✓ |
| `timestamp_ltz` | epoch | `TimestampTz` in session zone | `"2024-01-01T19:04:05-08:00"` | same | space separator | ✓ |
| `variant`/`object`/`array` | `"{\n  \"a\": 1\n}"` | `Json` | the text as a JSON string | the text, CSV-quoted | the text | ✓ |
| any, NULL | `null` | `Null` | `null` | empty | `None` | ✓ |
| `decfloat` | plain or scientific | `Decimal` | as `fixed` scale > 0 | | | golden in Stream B |

### Renderer rules (from `snowflake/cli/_app/printing.py`)

CSV and JSON stream row by row, TABLE and PLAIN buffer:
[ADR 0002](0002-parallel-partitions-and-streaming.md) Decision 3. The output is unchanged.

- **Column names** are de-duplicated as snow does: the second `A` becomes `A_2`, skipping names
  already taken (`QueryResult._uniquify_column_names`).
- **JSON:** an array of objects in column order. `[` newline, each object serialised with
  indent 4 and every line prefixed by 4 spaces, objects separated by `,` newline, then newline
  `]` newline. Key/value separator `": "`. Empty result: `[]` newline. Strings and keys have ANSI
  escape sequences removed (snow's `sanitize_for_terminal` regex) and non-ASCII escaped as
  `\uXXXX` (surrogate pairs above U+FFFF). Written with a small purpose-built writer, not
  `serde_json`'s printer, because Python's float, `Decimal` and `ensure_ascii` rules differ from
  it.
- **CSV:** header from the column names, `\n` line ends, a field is quoted (`"` doubled) when it
  contains `,`, `"`, `\n` or `\r`. Text values (`Text`, `Json`, and headers) go through snow's
  `sanitize_for_csv`: ANSI escapes removed, and a `'` prefix when the text starts with `=`, `+`,
  `-`, `@`, tab or CR (`'=1+1`); numbers are never prefixed (`-5`). Empty result: no output.
- **TABLE:** an ASCII box like rich's `box.ASCII`: `+---+` top and bottom borders without
  column joints, `|` cell separators, `|----+----|` under the header; cells use Python `str()`
  forms (`None`, `True`, space-separated timestamps). No width limit when stdout is not a
  terminal; the terminal width when it is.
- **PLAIN:** the same cells, no borders, columns separated by spaces, header row first.
- `snow sql` prints the statement text before a TABLE/PLAIN result: that is command behaviour,
  decided in the `sql` stage, not part of `render`.

## Decision 7: Errors, exit codes, diagnostics and secrets

- **Exit codes (default, as snow):** `0` success, `1` any error, `2` usage error (clap parse
  errors, invalid `--format` value, `-c` with `-x`). `ErrorKind` already carries snow's enhanced
  classes (`Connection` 3, `Communication` 4, `Sql` 5) so `--enhanced-exit-codes` (deferred)
  only changes `Error::exit_code`.
- **Errors go to stderr**, results to stdout. `report_error` prints snow's panel: a rounded box
  titled `Error`, 80 columns wide, message wrapped inside:

  ```text
  ╭─ Error ──────────────────────────────────────────────────────────────────────╮
  │ Connection nope is not configured                                            │
  ╰──────────────────────────────────────────────────────────────────────────────╯
  ```

  Visual equivalence only; scripts rely on the exit code. Usage errors keep clap's own format.
- **No stack traces, ever.** snow's `--debug` re-raises the Python traceback; ours prints the
  same panel plus a `Caused by:` line per `source()` in the chain. No `RUST_BACKTRACE` output
  (no panics: see the `unwrap`/`expect` rule).
- **Diagnostics:** the `log` facade; `diag` writes to stderr. Default shows warnings,
  `--verbose` info, `--debug` debug. B logs at debug: method and URL path (no query string other
  than `partition`), status, statement handle, partition `i/n`, retries, poll count. Never
  headers, request bodies, statement text, JWTs or response rows. `--silent` turns off
  intermediate output (nothing produces any in stage 0) but not errors.
- **Secrets never appear in any output or log, including `--debug`.** By construction:
  - every credential (private key PEM or path contents, passphrase, JWT) is a `Secret`: no
    `Display`, masked `Debug`, zeroed on drop;
  - `ConnectionConfig`'s `Debug` therefore masks them; `Env`'s `Debug` prints names only;
  - error messages are built from names, paths, codes and server messages, never from values
    read from config or env;
  - tests assert it: a key and passphrase with recognisable markers go through resolution,
    auth, a failing request and `--debug`; stdout and stderr must not contain the markers.

## Decision 8: Crates

All licenses are permissive and pass the `cargo-deny` policy below (checked with
`cargo-deny 0.22.0` on the full dependency set, 2026-11-20). Use the major versions shown; the
lock file pins the rest.

| Purpose | Crate | Version | License | Why / alternatives |
|---|---|---|---|---|
| CLI parsing | `clap` (derive) | 4.6 | MIT OR Apache-2.0 | Already used. |
| HTTP + TLS | `ureq` (default `rustls` with `ring`, `gzip`; + `json`) | 3.5 | MIT OR Apache-2.0 | Blocking, small, rustls with webpki roots (like the connector's `certifi`), gzip for partitions. `reqwest` rejected: needs a tokio runtime for nothing a sequential CLI uses. `native-tls` rejected: system OpenSSL dependency breaks the single static binary. |
| RSA, PKCS#8 | `rsa` (`pkcs5`, `pkcs1v15`) + `pkcs8` (`3des`) + `sha2` | 0.10 / 0.11 / 0.11 | MIT OR Apache-2.0 | One RustCrypto stack: decrypts encrypted PKCS#8 incl. DES3, signs RS256, encodes SPKI for the fingerprint. `rsa` 0.10 fixes RUSTSEC-2023-0071 (Marvin). `ring` rejected: cannot decrypt encrypted PKCS#8 or produce SPKI on its own. `jsonwebtoken` rejected: a JWT is two base64url segments and a signature; the crate adds a crypto backend choice for no gain. |
| Base64 | `base64` | 0.23 | MIT OR Apache-2.0 | JWT segments, fingerprint. |
| JSON (API wire format) | `serde` + `serde_json` | 1 | MIT OR Apache-2.0 | Parsing responses, building request bodies. Output JSON uses the custom writer (Decision 6). |
| TOML | `toml` | 1.2 | MIT OR Apache-2.0 | Reads `config.toml`/`connections.toml` into tables; unknown keys preserved for the `--verbose` warning. `toml_edit` not needed until stage 1 writes config files. |
| Dates, time zones | `jiff` | 0.2 | Unlicense OR MIT | Epoch → civil conversion and IANA zones for LTZ (system tzdb, bundled fallback on Windows). `chrono` + `chrono-tz` rejected: two crates and a compiled-in tz database. |
| Table rendering | `unicode-width` (amended during Stream B; was `comfy-table` 8) | 0.2 | MIT OR Apache-2.0 | snow 3.34.0 draws TABLE/PLAIN with its own writer (`snowflake/cli/_app/ascii_table.py`), not rich; a ~150-line port of it reproduces snow's layout and terminal folding exactly, and only needs display widths of wide characters. `comfy-table` would need a custom preset and still wrap differently. |
| Errors | `thiserror` | 2 | MIT OR Apache-2.0 | `Error` derive (shared file). |
| Secret wiping | `zeroize` | 1 | Apache-2.0 OR MIT | `Secret` (shared file). |
| Logging facade | `log` | 0.4 | MIT OR Apache-2.0 | Decouples B's log calls from A's logger. `tracing` rejected: more than a CLI needs. |
| Request ids | `uuid` (`v4`) | 1 | Apache-2.0 OR MIT | `requestId` for idempotent retries. |
| Mock HTTP server (dev) | `httpmock` (`default-features = false`) | 0.9 | MIT | Synchronous API that fits blocking `ureq` tests; matchers on path, query, headers and body; can delay responses for timeout tests. `wiremock` (MIT/Apache) is the fallback if httpmock blocks something; it needs tokio in tests. |
| CLI tests (dev) | `assert_cmd`, `predicates` | 2 / 3 | MIT OR Apache-2.0 | Already used. |
| Temp dirs (dev) | `tempfile` | 3 | MIT OR Apache-2.0 | Temp `SNOWFLAKE_HOME` per test. |

Rejected: `dirs` (pulls `option-ext`, MPL-2.0; the fallback directory is ten lines of std code),
`secrecy` (one small type does the job and keeps the shared file dependency-light).

Transitive licenses found (all allowed below): Apache-2.0, MIT, Apache-2.0 WITH LLVM-exception,
BSD-3-Clause (`subtle`), ISC (`ring`, `rustls`, `rustls-webpki`, `untrusted`), Unicode-3.0,
Zlib, CDLA-Permissive-2.0 (`webpki-roots`). Unlicense (`jiff`, `memchr`), 0BSD (`adler2`) and
LGPL-2.1-or-later (`r-efi`) appear only as alternatives in dual/tri-licensed crates, where an
allowed license (MIT or Apache-2.0) is taken.

## Decision 9: Testing strategy

Applies to both stage-2 PRs and every later PR.

### Rules

- **Test-first:** each behaviour starts as a failing test.
- **Coverage ≥ 90 % lines** (`cargo llvm-cov`, existing CI job), no exclusions.
- **No `unwrap`/`expect` outside tests**, enforced by clippy: `Cargo.toml` gets
  `[lints.clippy] unwrap_used = "deny"` and `expect_used = "deny"`, and a `clippy.toml` with
  `allow-unwrap-in-tests = true` and `allow-expect-in-tests = true`. Files under `tests/` that
  need helpers outside `#[test]` functions start with
  `#![allow(clippy::unwrap_used, clippy::expect_used)] // test crate`. Whichever stage-2 PR
  merges first adds these lints; both PRs must pass them.
- **Tests never read the real environment or home:** config tests use `Env::from_pairs` and a
  `tempfile` `SNOWFLAKE_HOME`; CLI tests use `assert_cmd` with `env_clear()` plus explicit vars.
  This matters: a developer's shell or CI may export `SNOWFLAKE_ACCOUNT`, `SNOWFLAKE_USER`, `SNOWFLAKE_ROLE`, …,
  which are also snow's generic overrides.
- **`cargo-deny`** runs as a CI job (below).

### Seams

| Seam | Used by |
|---|---|
| `Env::from_pairs`, `ConfigPaths::discover(env, override)` with temp dirs | A: every precedence level, default connection, permissions, corrupt files |
| `ConnectionConfig { host, port, protocol: "http" }` → `httpmock::MockServer` | B: every API path |
| `KeyPairAuthenticator::with_clock` + test keys in `tests/fixtures/keys/` (generated for tests only, unencrypted / AES-256 / DES3, passphrase in the test) | B: JWT claims, fingerprint, key errors |
| `render(&QueryResult, format, &mut Vec<u8>)` | B: renderers over fixtures and goldens |
| `report_error(&err, debug, &mut Vec<u8>)` | B: error panel, `--debug` chain, secret absence |

### Mocked HTTP unit tests (B), at least

Partition concurrency, ordering and mid-stream failures add the tests in
[ADR 0002](0002-parallel-partitions-and-streaming.md) Decision 6.

200 single partition; 200 with partitions 1..n (gzip bodies, checked in order); 202 → polls →
200; 202 → polls → 422; 401; 403; 408; 422 (message format); 429 then 200 (retry with same
`requestId` and `retry=true`); 503 until retries run out; read timeout (delayed mock response
with a short `request_timeout`); connection refused; malformed JSON; LTZ column triggering the
`SHOW PARAMETERS` request. Each test asserts the request too: path, `requestId`, headers
`Authorization: Bearer <three segments>` and token type, body fields.

### Golden tests against the official snow

Goal: JSON and CSV byte-identical to snow, checked offline in CI.

- **Capture** (B adds `scripts/capture-goldens.sh`, run by the builder, not CI): creates a venv,
  `pip install snowflake-cli==3.34.0`, and for each case in `tests/golden/cases.toml`
  (name + SQL) runs, against the sandbox with a temporary connection
  (`snow sql -x -q <sql> --format json|csv`, `SNOWFLAKE_AUTHENTICATOR=SNOWFLAKE_JWT`,
  `SNOWFLAKE_PRIVATE_KEY_FILE` written from `SNOWFLAKE_PRIVATE_KEY_B64` to a 0600 temp file
  deleted on exit):
  - `tests/golden/<case>.json` and `tests/golden/<case>.csv`: snow's stdout;
  - `tests/golden/<case>.sqlapi.json`: the raw SQL API v2 response for the same SQL (all
    partitions, `statementHandle` replaced by a fixed UUID), plus the session `TIMEZONE` when the
    case has LTZ columns.
- **Cases use synthetic literals only** (`SELECT 1.50::NUMBER(10,2) AS d, …`, `GENERATOR` rows),
  never tables, so goldens contain no production or personal data. Minimum set: every row of the
  Decision 6 table, NULLs, duplicate column names, ANSI escapes, CSV formula prefixes,
  non-ASCII and astral characters, embedded newlines/quotes/commas, empty result, a
  multi-partition result.
- **Check (CI, offline):** a test replays each `<case>.sqlapi.json` through `httpmock` and
  `SqlClient::execute`, renders JSON and CSV, and asserts byte equality with the stored snow
  output. Refreshing goldens is a deliberate PR (new snow version or new cases).

### Sandbox integration tests

- `#[ignore]` tests in `tests/sandbox.rs`, using the sandbox env (`SNOWFLAKE_ACCOUNT`,
  `SNOWFLAKE_USER`, `SNOWFLAKE_ROLE`, `SNOWFLAKE_WAREHOUSE`, `SNOWFLAKE_DATABASE`,
  `SNOWFLAKE_PRIVATE_KEY_B64`; FactorIA ADR 0051). Never print the key; write it to a 0600 temp
  file or pass it as `private_key_raw`.
- Run by the builder before each PR: `cargo test -- --ignored sandbox`; paste the output (no
  secrets) in the PR. Not run in CI (no credentials there).
- Stage 0 test: sign in, `SELECT CURRENT_ROLE()`, render in all four formats.

### CI: `cargo-deny` job

Added by whichever stage-2 PR merges first (both may include it; the content is fixed here), and
listed in the `ci` aggregate's `needs`:

```yaml
  deny:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: EmbarkStudios/cargo-deny-action@v2
        with:
          command: check advisories bans licenses sources
```

`deny.toml` at the repo root:

```toml
[graph]
all-features = false

[advisories]
version = 2
yanked = "deny"
ignore = []

[licenses]
version = 2
confidence-threshold = 0.9
private = { ignore = true }
allow = [
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "MIT",
    "BSD-3-Clause",
    "ISC",
    "Unicode-3.0",
    "Zlib",
    "CDLA-Permissive-2.0",
]

[bans]
multiple-versions = "warn"
wildcards = "deny"
allow-wildcard-paths = true

[sources]
unknown-registry = "deny"
unknown-git = "deny"
```

Copyleft licenses (GPL, LGPL, MPL, AGPL) are not allowed; adding one needs an ADR amendment.
An advisory without a fix may be added to `ignore` only with a comment saying why it does not
apply, reviewed by `security`. Adding `deny` to `CLAUDE.md`'s CI table is part of that PR.

## Discrepancies with the refinement brief

| Brief said | snow 3.34.0 actually does | Decision |
|---|---|---|
| Precedence CLI flags > `SNOWFLAKE_CONNECTIONS_<NAME>_<KEY>` / `SNOWFLAKE_<KEY>` env > file | `SNOWFLAKE_CONNECTIONS_<NAME>_<KEY>` beats the file, but generic `SNOWFLAKE_<KEY>` applies **only to keys the flags and the file left unset** (`resolve_connection_parameters`) | Follow snow (Decision 3). The brief's goal is compatibility; copying the assumed order would make the same files and env resolve differently in each CLI. |
| Files in `~/.snowflake` or `SNOWFLAKE_HOME` | Only if that directory exists; else the platform config dir (`~/.config/snowflake`, …) | Follow snow. |
| `config.toml` / `connections.toml` | `connections.toml`, when present, replaces all connections of `config.toml` | Follow snow. |
| Unsupported keys ignored with a warning under `--verbose` | snow passes unknown keys to the connector silently | Keep the brief's rule: we cannot pass them anywhere, and saying so helps. Key names only. |
| No stack traces | `--debug` prints the Python traceback | No traces; `--debug` shows the error's cause chain instead. |
| — | Default config files with group/other permissions are a hard error | Follow snow (Decision 3). |
| — | A connection defined only by `SNOWFLAKE_CONNECTIONS_<NAME>_*` env is "not configured" | Follow snow. |

## Consequences

- Stage 2 builds in parallel from this document alone: shared files verbatim, signatures fixed,
  rules verified. Each stream's PR is reviewed against its section.
- PUT/GET (`stage copy`) will need a second transport or a workaround; that decision is
  explicitly deferred to the start of that work.
- Multi-statement execution, session state across statements and `snow sql` specifics are
  designed in the `sql` stage on top of this client.
- Other auth methods add `Authenticator` implementations and connection keys; the
  `ConnectionConfig` change for each needs an amendment to this ADR.
- Output fidelity depends on goldens; a new snow version means re-capturing them and reviewing
  the diff.
- Risk: the SQL API may format a type differently from the connector in a case the goldens do not
  cover. Mitigation: the golden case list in Decision 9, extended whenever a difference is found.

## Appendix A: shared files (verbatim)

Both stage-2 PRs add these four files exactly as below (they pass `cargo fmt --check` and
`cargo clippy -- -D warnings` with the pinned toolchain). `src/lib.rs` declares
`pub mod connection; pub mod error; pub mod output; pub mod secret;`.

### `src/secret.rs`

```rust
//! A string that must never reach any output or log.

use std::fmt;
use zeroize::Zeroizing;

/// Private key PEM, passphrase, JWT or any other credential.
///
/// It has no `Display`, `Debug` prints a fixed mask, and the memory is wiped
/// on drop. Code reads the value only through [`Secret::expose`], right where
/// it is used (signing, the HTTP header).
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// Wraps a credential.
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// The raw value. Never pass it to a formatter, logger or error.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(****)")
    }
}
```

### `src/error.rs`

```rust
//! Error type shared by every module, and the process exit code.

use std::fmt;

/// Failure class. The default exit code is 2 for `Usage`, 1 for the rest;
/// the variants match `snow`'s error classes so `--enhanced-exit-codes`
/// (later) only changes [`Error::exit_code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Bad command-line arguments (enhanced: 2).
    Usage,
    /// Config, key or other client-side problem (enhanced: 1).
    Client,
    /// Could not reach Snowflake: DNS, TCP, TLS (enhanced: 3).
    Connection,
    /// Unexpected HTTP status, malformed response, timeout, 401 (enhanced: 4).
    Communication,
    /// Snowflake rejected the statement: HTTP 422 (enhanced: 5).
    Sql,
}

/// An error with a user-facing message.
///
/// `message` is printed on stderr. It and every `source` in the chain must be
/// free of secrets: build them from names, paths, codes and server messages,
/// never from a [`crate::secret::Secret`] or a request header/body.
#[derive(Debug, thiserror::Error)]
pub struct Error {
    kind: ErrorKind,
    message: String,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl Error {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            source: None,
        }
    }

    /// Attaches the underlying cause, shown only under `--debug`.
    pub fn with_source(mut self, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    /// Exit code without `--enhanced-exit-codes`: 2 for usage, else 1.
    pub fn exit_code(&self) -> i32 {
        match self.kind {
            ErrorKind::Usage => 2,
            _ => 1,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
```

### `src/connection.rs`

```rust
//! The resolved connection: the contract between config resolution and auth/client.

use crate::secret::Secret;
use std::path::PathBuf;

/// A connection after every precedence rule has been applied.
///
/// Built only by `config::resolve_connection`; read by `auth` and `sql`.
/// Field names and meanings are those of `snow`'s `connections.toml` keys.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectionConfig {
    /// Connection name; `None` for `-x/--temporary-connection`.
    pub name: Option<String>,
    pub account: Option<String>,
    pub user: Option<String>,
    /// Overrides `<account>.snowflakecomputing.com`.
    pub host: Option<String>,
    pub port: Option<u16>,
    /// `https` (default) or `http`.
    pub protocol: Option<String>,
    /// Must be `SNOWFLAKE_JWT` (case-insensitive) in stage 0.
    pub authenticator: Option<String>,
    /// `private_key_file`, alias `private_key_path`.
    pub private_key_file: Option<PathBuf>,
    /// Inline PEM (`private_key_raw`).
    pub private_key_raw: Option<Secret>,
    /// `PRIVATE_KEY_PASSPHRASE` env if set, else `private_key_passphrase`
    /// (alias `private_key_file_pwd`) from the connection.
    pub private_key_passphrase: Option<Secret>,
    pub database: Option<String>,
    pub schema: Option<String>,
    pub role: Option<String>,
    pub warehouse: Option<String>,
}
```

### `src/output/mod.rs`

```rust
//! Output formats.

pub mod format;
```

### `src/output/format.rs`

```rust
//! `--format` values.

use clap::ValueEnum;

/// Output format of a command result. `JSON_EXT` comes in a later stage.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "UPPER")]
pub enum OutputFormat {
    #[default]
    Table,
    Json,
    Csv,
    Plain,
}
```
