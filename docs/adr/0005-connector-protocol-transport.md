# ADR 0005: Connector-protocol transport: session sign-in, query-request and PUT/GET file transfer

- **Status:** Proposed (Accepted on merge)
- **Amends:** [ADR 0001](0001-stage-0-foundation.md) Decision 1 (the PUT/GET transport is decided
  here, not at `stage copy`) and Decision 2 (new fields in the shared `src/connection.rs`)
- **Date:** 2026-11-21
- **Builds on it:** Amendment 2 (connector-protocol sign-ins), Amendment 1 (`PUT`/`GET` in `sql`),
  Amendment 3 (the interactive session; see Decision 1), and Amendment 4 (asynchronous statements;
  Amendment 4)
- **Reference implementation:** `snow` 3.34.0 and the `snowflake-connector-python` **4.8.1** it pins
  (`snowflake-cli` `pyproject.toml`). "Connector" below means that version; `C/` is its
  `snowflake/connector/` package, `S/` is `snowflake/cli/` in `snow`.

## Context

Everything goes through the SQL REST API v2 (ADR 0001 Decision 1). Per Snowflake's docs it has no
password sign-in, no MFA, external browser or Okta, and no `PUT`/`GET`. `snow` gets all of those
from the connector, which talks Snowflake's own driver protocol: `login-request` → session
token, `query-request` with that token, and, for `PUT`/`GET`, direct transfers to the stage's
cloud storage.

The refinement of the port of `snow connection` and `snow sql` (accepted by the maintainer) sets the frame:

- keep the SQL API for queries where it works; use the connector protocol only where required;
- sign-ins that need a human (MFA push, external browser, interactive Okta, OAuth authorization
  code) are built and tested against a mocked server and flagged **"mock-tested only"** in the
  README matrix;
- this ADR ships an idempotent sandbox-extension SQL. The maintainer runs it once. That is the only host
  step.

Out of scope here: implementing anything. The `Authenticator`/`AuthHeader` path and the flows
that already work over the SQL API (`SNOWFLAKE_JWT`; `OAUTH`, `PROGRAMMATIC_ACCESS_TOKEN`,
`WORKLOAD_IDENTITY`) stay as they are.

### What the connector does (read from its source)

| Topic | Behaviour | Source |
|---|---|---|
| Sign-in | `POST /session/v1/login-request?request_id=<uuid>[&databaseName&schemaName&warehouse&roleName]`, JSON `{"data": {...}}` with `CLIENT_APP_ID`, `CLIENT_APP_VERSION`, `ACCOUNT_NAME`, `LOGIN_NAME`, `CLIENT_ENVIRONMENT`, `SESSION_PARAMETERS`, plus per-authenticator fields (Decision 4). Response `data`: `token`, `masterToken`, `masterValidityInSeconds`, `sessionId`, `sessionInfo`, `parameters`, `idToken`, `mfaToken`. | `C/auth/_auth.py:146-274,532-554` |
| Multi-step sign-in | `nextAction` `EXT_AUTHN_DUO_ALL`/`EXT_AUTHN_DUO_PUSH_N_PASSCODE` → resend with `inFlightCtx`, `EXT_AUTHN_DUO_METHOD=push`; `PWD_CHANGE` → resend with `CHOSEN_NEW_PASSWORD`. | `C/auth/_auth.py:318-405` |
| Requests with a session | `Authorization: Snowflake Token="<session token>"`. | `C/network.py:307-322` |
| Renewal | Any response code `390112` → `POST /session/token-request?requestId=` with the **master** token, body `{"oldSessionToken", "requestType": "RENEW"}` → new session (and master) token, then replay. `390114` = master expired: only `EXTERNALBROWSER` signs in again, others fail. | `C/network.py:583-642,755-836` |
| Heartbeat | `POST /session/heartbeat?requestId=` every `CLIENT_SESSION_KEEP_ALIVE_HEARTBEAT_FREQUENCY`, clamped to [master validity / 16, master validity / 4], only when `client_session_keep_alive`. | `C/connection.py:1792-1796,2470-2524` |
| Close | `POST /session?delete=true`, ignored errors, skipped with `server_session_keep_alive`. | `C/connection.py:1346-1385` |
| Queries | `POST /queries/v1/query-request?requestId=` body `sqlText`, `asyncExec`, `sequenceId`, `querySubmissionTime`, `parameters`, `queryContextDTO`. `333333`/`333334` → poll `data.getResultUrl`. Large results: inline `rowset` + `chunks[{url,rowCount,uncompressedSize,compressedSize}]` downloaded with `chunkHeaders` (SSE-C). | `C/connection.py:2087-2155`, `C/network.py:842-864`, `C/result_batch.py:87-290` |
| Credential cache | `ID_TOKEN`, `MFA_TOKEN`, `OAUTH_ACCESS_TOKEN`, `OAUTH_REFRESH_TOKEN`; key `sha256_hex("<A>:<B>:<TYPE>")` (upper-cased); keyring on macOS/Windows, `credential_cache_v1.json` (dir 0700, file 0600, `.lck` dir lock) on Linux. | `C/token_cache.py:24-422`, `C/file_lock.py` |
| `PUT`/`GET` | The statement goes through `query-request`; `data.command` `UPLOAD`/`DOWNLOAD` with `stageInfo`, `encryptionMaterial`, `src_locations`, `parallel`, `overwrite`, `autoCompress`, `sourceCompression`, `threshold`, `presignedUrls`; the client transfers the files itself (Decision 5). | `C/cursor.py:1079-1103`, `C/file_transfer_agent.py` |

`snow` passes `--authenticator` through unchanged and maps `--mfa-passcode` → `passcode`,
`--client-store-temporary-credential`, `--server-session-keep-alive`, the `--oauth-*` options and
`--session-token`/`--master-token` (the latter forces both keep-alives and a 3600 s heartbeat)
(`S/_app/snow_connector.py:212-472`, `S/api/commands/flags.py`). Connection keys such as
`client_session_keep_alive` and `passcode_in_password` reach the connector only through
`connections.toml`. For `USERNAME_PASSWORD_MFA`, `snow` always sets `client_request_mfa_token`.

### What the sandbox showed (spike, 2026-11-21)

A throwaway Python spike (not committed) signed in to the sandbox with the test key pair,
synthetic SQL only, and printed only status codes, error codes and field names.

| # | Finding |
|---|---|
| S1 | `login-request` with `AUTHENTICATOR=SNOWFLAKE_JWT` + the same JWT as ADR 0001 Decision 4 succeeds. `validityInSeconds` 3599, `masterValidityInSeconds` 14399. A custom `CLIENT_APP_ID` (`snowflake-rs-cli` / `0.1.0`) is accepted for sign-in, queries and `PUT`. |
| S2 | `query-request` with the session token works. With session parameter `PYTHON_CONNECTOR_QUERY_RESULT_FORMAT=json` (sent in `SESSION_PARAMETERS` at sign-in) `queryResultFormat` is `json` and rows come as `rowset` (no Arrow). `rowtype` has the same fields as the SQL API's `rowType`. |
| S3 | Session state carries across `query-request`s: `SET v = 41` then `SELECT $v + 1` → `42`. |
| S4 | **The SQL API does not accept a session token.** `Authorization: Snowflake Token=…` → 400 `390146` "Bearer token is missing"; `Bearer <session token>` → 401 `390303` "Invalid OAuth access token"; token types `SNOWFLAKE`/`SESSION` → 400 `391912`. |
| S5 | Values in `rowset` are byte-identical to the SQL API's `data` for NUMBER, FLOAT, TEXT, DATE, TIME, TIMESTAMP_NTZ/TZ/LTZ, BINARY, VARIANT and NULL, **except BOOLEAN**: `"1"`/`"0"` instead of `"true"`/`"false"`. |
| S6 | A 200 000-row result: 1 907 rows inline, 7 chunks; `chunkHeaders` carries the two SSE-C headers; a chunk GET returns gzip JSON rows **without the enclosing `[`…`]`** (`"[…],[…]"`). |
| S7 | `SELECT SYSTEM$WAIT(50)` answers `333334` with `getResultUrl`; one GET of it after 2 s returned the rows. |
| S8 | `PUT` with `Accept: application/snowflake` fails with `000002` "Unsupported feature 'unsupported_requested_format:snowflake'"; with `Accept: application/json` it returns `command: UPLOAD`. Ordinary queries also work with `application/json`. |
| S9 | The sandbox's user stage is `locationType: S3` (`eu-west-3`), client-side encrypted, temporary `AWS_KEY_ID`/`AWS_SECRET_KEY`/`AWS_TOKEN`, `encryptionMaterial {queryStageMasterKey, queryId, smkId}`. `GET` answers `command: DOWNLOAD` with `presignedUrls`. |
| S10 | `/session/heartbeat` and `POST /session?delete=true` answer `success: true`. |
| S11 | The test user has no network policy and no user-level authentication policy. A PAT needs one or the other (Decision 8). |

## Decision 1: Two transports, chosen once per run

### Options

| | A. SQL API only, plus a separate PUT/GET path | **B. SQL API by default; a connector session when the run needs one (chosen)** | C. Connector protocol for everything |
|---|---|---|---|
| Password / MFA / browser / Okta | Impossible: the SQL API only takes JWT, OAuth, PAT (and WIF) | Session transport | Session transport |
| `PUT`/`GET` | Needs a session anyway (the command comes back from `query-request`), and a `PUT` must share the session of e.g. a preceding `CREATE TEMPORARY STAGE` | Whole run on the session | Yes |
| Existing code | Kept | Kept; ADR 0002/0004 stay the default path | ADR 0002's partitions and ADR 0004's multi-statement design thrown away |
| Matches `snow` | — | `snow` always uses a session; B matches its output and its statement-by-statement semantics where a session is used | Closest, but loses the measured SQL API paths |
| Risk | — | Two paths to keep equivalent (mitigated: one result model, S5) | Undocumented protocol on every run |

### Decision

**B.** A run picks its transport once, before the first statement:

1. **Session transport** (`login-request` + `query-request`) when **any** of these holds:
   - the authenticator cannot be presented to the SQL API: `SNOWFLAKE` (password),
     `USERNAME_PASSWORD_MFA`, `EXTERNALBROWSER`, native Okta (an `https://…okta.com` URL),
     `OAUTH_AUTHORIZATION_CODE`, `OAUTH_CLIENT_CREDENTIALS`;
   - `--session-token`/`--master-token` are given (no sign-in; `snow`'s forced keep-alive applies);
   - the run contains a `PUT` or `GET` statement (detected after templating by the statement
     splitter with the connector's rule: the first word after leading comments, case-insensitive,
     `C/_sql_util.py:15-40`);
   - the run is the interactive session (Amendment 3): statements typed one by one must share `USE`,
     `SET` and temporary objects, which only a session gives. *Recommendation to Amendment 3*: run the
     REPL on the session transport whatever the authenticator.
2. **SQL API** otherwise: `SNOWFLAKE_JWT`, `OAUTH`, `PROGRAMMATIC_ACCESS_TOKEN`,
   `WORKLOAD_IDENTITY` with no `PUT`/`GET` and not interactive. Nothing changes for them.

On the session transport **every statement of the run goes through `query-request`** with the
session token (S4: the SQL API cannot use it). The bearer credentials sign in with
`login-request` too (S1): `SNOWFLAKE_JWT` (`AUTHENTICATOR=SNOWFLAKE_JWT, TOKEN=<jwt>`), `OAUTH`
(`AUTHENTICATOR=OAUTH, TOKEN`), PAT (`AUTHENTICATOR=PROGRAMMATIC_ACCESS_TOKEN, TOKEN`), so a
`PUT` works with the key pair the tests already use.

Why not send OAuth-code/client-credentials access tokens to the SQL API: the connector signs in
with them through `login-request` (`C/auth/_oauth_base.py:431-441`), `snow`'s error hints key on
the `login-request` codes `390303`/`390318`, and these flows are mock-tested only, so a path the
sandbox cannot verify would gain nothing.

### Statements on the session transport

- One `query-request` per statement, in order, as `snow` does; a failing statement stops the
  run with the same error output as ADR 0004 Decision 5 (the session gives the failing
  statement's own `code`, `sqlState`, `queryId`, so no `QUERY_HISTORY_BY_SESSION` lookup).
- `--single-transaction`: as `snow` (`S/_plugins/sql/manager.py:178-186`): autocommit off
  (`ALTER SESSION SET AUTOCOMMIT = FALSE`, not shown), then `BEGIN` before the first statement
  and `COMMIT` after the last, sent as ordinary statements; on failure nothing is committed and
  the session close discards the open transaction.
- `Accept: application/json` on every request (S8); `SESSION_PARAMETERS` at sign-in always
  include `PYTHON_CONNECTOR_QUERY_RESULT_FORMAT=json` (S2), so there is no Arrow decoder.
- `333333`/`333334` → GET `getResultUrl`, interval 250 ms doubling to `poll_interval_max`
  (ADR 0001 Decision 5 values).
- `CLIENT_APP_ID=snowflake-rs-cli`, `CLIENT_APP_VERSION=<crate version>`,
  `CLIENT_ENVIRONMENT.APPLICATION=SNOWFLAKE_CLI` (`snow`'s value) (S1). We do not impersonate
  `PythonConnector`.

## Decision 2: Module boundaries

New modules, each owned by one later sub-issue so Amendment 2 and Amendment 1 can be built in parallel:

| Path | Owner | Content |
|---|---|---|
| `src/session/mod.rs` | Amendment 2 (skeleton first, see below) | `Session`: tokens, `query()`, renewal, close; `SessionOptions` |
| `src/session/login.rs` | Amendment 2 | `login-request` body/response, `nextAction` loop, error-code mapping |
| `src/session/query.rs` | Amendment 2 | `query-request`, polling, chunk download feeding `RowStream` |
| `src/session/keepalive.rs` | Amendment 2 | heartbeat thread |
| `src/session/flows/*.rs` | Amendment 2 | one file per sign-in flow (Decision 4) |
| `src/session/cache.rs` | Amendment 2 | temporary credential cache (Decision 3) |
| `src/session/callback.rs` | Amendment 2 | localhost HTTP callback server (browser, OAuth code) |
| `src/transfer/` | Amendment 1 | `PUT`/`GET`: plan, local files, compression, encryption, storage clients (Decision 5) |
| `src/sql/executor.rs` | Amendment 2 | `Executor`: the transport choice of Decision 1 |

Interfaces (binding signatures; private helpers are the builder's choice):

```rust
// src/sql/executor.rs
/// The transport of one run (ADR 0005 Decision 1).
pub enum Executor {
    SqlApi(crate::sql::SqlClient),
    Session(crate::session::Session),
}
#[derive(Debug, Clone, Copy, Default)]
pub struct RunNeeds {
    pub session: bool, // a PUT/GET statement, or the interactive session
}
impl Executor {
    /// Picks and signs in. No network access for the SQL API (as `SqlClient::new`).
    pub fn connect(conn: &ConnectionConfig, needs: RunNeeds, io: &crate::session::Interaction)
        -> Result<Self>;
    /// Same contract as ADR 0004's `SqlClient::run_script`; PUT/GET items are rows too.
    pub fn run_script(&self, statements: &[String], options: &ScriptOptions) -> Result<ScriptRun>;
}

// src/session/mod.rs
pub struct Session { /* agent, base URL, Secret tokens behind a Mutex, keep-alive handle, … */ }
impl Session {
    pub fn login(conn: &ConnectionConfig, options: SessionOptions, io: &Interaction) -> Result<Self>;
    /// `--session-token` / `--master-token`: no sign-in.
    pub fn from_tokens(conn: &ConnectionConfig, session: Secret, master: Secret,
        options: SessionOptions) -> Result<Self>;
    /// One statement; renews on 390112 and replays once.
    pub fn query(&self, sql: &str) -> Result<SessionResponse>;
    /// The raw `data` object of a PUT/GET answer is handed to `transfer`.
    pub fn close(self) -> Result<()>;
}
/// Everything a flow needs from the outside world: the test seams.
pub struct Interaction<'a> {
    pub prompt: &'a dyn Prompt,              // passcodes, Okta/browser fallbacks
    pub browser: &'a dyn BrowserOpener,      // `open` crate in production
    pub cache: &'a dyn CredentialCache,      // file cache in production
    pub clock: fn() -> std::time::SystemTime,
}
pub trait LoginFlow {
    /// Pre-steps (authenticator-request, browser, Okta, OAuth token endpoint), then the fields
    /// added to `data` (AUTHENTICATOR, TOKEN, PASSWORD, PASSCODE, PROOF_KEY, RAW_SAML_RESPONSE, …).
    fn prepare(&mut self, ctx: &mut FlowContext<'_>) -> Result<LoginFields>;
    /// A failed sign-in; `Retry::Again` after e.g. dropping a stale cached ID/MFA/OAuth token.
    fn on_failure(&mut self, code: &str, ctx: &mut FlowContext<'_>) -> Result<Retry>;
    /// Stores idToken / mfaToken / OAuth tokens when caching is on.
    fn on_success(&mut self, data: &LoginData, ctx: &mut FlowContext<'_>) -> Result<()>;
}

// src/transfer/mod.rs
/// Executes the transfer a PUT/GET `query-request` answer describes; returns snow's rows.
pub fn execute(session: &Session, statement: &str, data: &serde_json::Value,
    options: &TransferOptions) -> Result<crate::sql::QueryResult>;
```

- `RowStream` gets a third page source next to SQL API partitions (ADR 0002): the session's
  inline `rowset` + chunk URLs (S6), downloaded by the same bounded parallel window, and an
  in-memory source for `PUT`/`GET` rows. Renderers do not change.
- `sql::convert` accepts BOOLEAN as `"1"`/`"0"` as well as `"true"`/`"false"` (S5); that is the
  only conversion difference. TIMESTAMP_LTZ uses the session `TIMEZONE` from the latest
  `parameters` the server returned (sign-in response, then each query response) instead of the
  extra `SHOW PARAMETERS` of ADR 0001 Decision 5; Amendment 2 verifies this on the sandbox.
- **Shared file amendment (ADR 0001 Decision 2):** Amendment 2 may add to `src/connection.rs` the
  fields below, named exactly as `snow`'s `connections.toml` keys and resolved like the others:
  `password`, `passcode` (from `--mfa-passcode`), `passcode_in_password`, `token`,
  `token_file_path`, `session_token`, `master_token`, `oauth_client_id`, `oauth_client_secret`,
  `oauth_authorization_url`, `oauth_token_request_url`, `oauth_redirect_uri`, `oauth_scope`,
  `oauth_disable_pkce`, `oauth_enable_refresh_tokens`, `oauth_enable_single_use_refresh_tokens`,
  `client_store_temporary_credential`, `client_session_keep_alive`,
  `client_session_keep_alive_heartbeat_frequency`, `server_session_keep_alive`. Every credential
  among them is a `Secret`. The SQL API sign-in build adds the ones it needs (`token`, `token_file_path`, …) under
  the same names; whichever merges second keeps the first one's field.
- `config::resolve` stops rejecting authenticators other than `SNOWFLAKE_JWT` for the flows of
  Decision 4; the "only key-pair" Client error of ADR 0001 Decision 4 remains for unknown values,
  with `snow`'s wording.

## Decision 3: Session lifecycle and credential storage

- **Tokens** (`token`, `masterToken`, ID/MFA/OAuth tokens) are `Secret`s and never logged;
  `--debug` logs method, path (no query string) and the server `code`.
- **Renewal:** on `390112` from any request, one `token-request` with the master token, then the
  request is replayed once (a second `390112` fails). `390114` or a failed renewal is a
  `Connection` error ("session expired, sign in again"); only `EXTERNALBROWSER` signs in again
  by itself, as the connector.
- **Heartbeat** (`client_session_keep_alive`, or forced by `--session-token`/`--master-token`):
  one std thread, interval clamped as the connector, stopped when the session drops. A CLI run is
  short, so in practice this matters for the REPL and long scripts.
- **Close:** `POST /session?delete=true` when the run ends, errors ignored with a 5 s timeout,
  skipped with `--server-session-keep-alive`.
- **Temporary credential cache** (`--client-store-temporary-credential`; MFA tokens always on for
  `USERNAME_PASSWORD_MFA`, as `snow`): **a file cache on every OS**, same format, key derivation
  (both key orders the connector uses: `"<USER>:<HOST>:<TYPE>"` for ID/MFA tokens and
  `"<HOST>:<USER>:<TYPE>"` for OAuth tokens, `C/auth/_auth.py:562,606,640`,
  `C/auth/_oauth_base.py:119-211`), directory chain (`$SF_TEMPORARY_CREDENTIAL_CACHE_DIR`,
  `$XDG_CACHE_HOME/snowflake`, `~/.cache/snowflake`; our choice where the connector uses the
  keychain: `%LOCALAPPDATA%\snowflake` on Windows, `~/.cache/snowflake` on macOS),
  0700/0600 permission checks and `.lck` directory lock as the connector's Linux backend. On
  Linux the cache is therefore shared with `snow`. A cache with wrong permissions or owner is
  ignored with a warning, never written.
  - Rejected: the `keyring` crate. On Linux it needs D-Bus/Secret Service (C library or a large
    async stack, breaks the single static binary); on macOS/Windows it would share `snow`'s
    keychain entries but adds platform code for a convenience feature. Deviation from `snow` on
    macOS/Windows (file instead of keychain), recorded in the README matrix notes. Revisit if
    asked.

## Decision 4: Sign-in flows

All flows end in the same `login-request`; the table lists what each adds. Live = tested on the
sandbox; Mock = tested only against the mocked server (README: **mock-tested only**).

| `authenticator` | Pre-steps | `data` fields | Cache | Test |
|---|---|---|---|---|
| `SNOWFLAKE` | — | `PASSWORD`; with `--mfa-passcode`: `EXT_AUTHN_DUO_METHOD=passcode`, `PASSCODE`; with `passcode_in_password`: passcode appended to the password; otherwise Duo push via `nextAction` (`inFlightCtx`, `EXT_AUTHN_DUO_METHOD=push`) | — | Live without MFA (if the account allows it, Decision 8); MFA passcode and push: Mock |
| `USERNAME_PASSWORD_MFA` | read cached MFA token | `PASSWORD`, `TOKEN=<mfa token>` if cached, `CLIENT_REQUEST_MFA_TOKEN=true` | MFA token (stored on success, dropped on failure) | Mock |
| `EXTERNALBROWSER` | bind `127.0.0.1:0` (or `SF_AUTH_SOCKET_PORT`), `POST /session/authenticator-request` → `ssoUrl`, `proofKey`; open browser; wait for `?token=` (GET) or JSON POST; paste-the-URL fallback when no browser | `AUTHENTICATOR=EXTERNALBROWSER`, `TOKEN`, `PROOF_KEY`; or `AUTHENTICATOR=ID_TOKEN`, `TOKEN=<id token>` when cached (fallback to the browser on `390195`) | ID token | Mock |
| Okta URL (`https://<org>.okta.com`) | `authenticator-request` → `tokenUrl`, `ssoUrl` (must share the authenticator's scheme+host+port); `POST tokenUrl {username,password}` → one-time token; `GET ssoUrl?RelayState=…&onetimetoken=…`; SAML form postback must match Snowflake's host unless `disable_saml_url_check` | `RAW_SAML_RESPONSE=<html>` | — | Mock |
| `OAUTH_AUTHORIZATION_CODE` | cached access token → refresh grant → browser: PKCE S256 (unless `--oauth-disable-pkce`), 43-byte `state`, callback server on the redirect port (default `http://127.0.0.1`), token endpoint with Basic auth; Snowflake defaults `/oauth/authorize`, `/oauth/token-request`, client `LOCAL_APPLICATION` when none is given; scope default `session:role:<role>` | `AUTHENTICATOR=OAUTH`, `TOKEN=<access token>`, `CLIENT_ENVIRONMENT.OAUTH_TYPE=oauth_authorization_code` | access + refresh tokens | Mock |
| `OAUTH_CLIENT_CREDENTIALS` | `grant_type=client_credentials` to `--oauth-token-request-url` (Basic auth, or in the body) | as above, `OAUTH_TYPE=oauth_client_credentials` | access token | Mock (Snowflake OAuth has no client-credentials grant; it needs an External OAuth IdP) |
| `SNOWFLAKE_JWT`, `OAUTH`, `PROGRAMMATIC_ACCESS_TOKEN` (session runs only) | — | `AUTHENTICATOR=…`, `TOKEN` | — | Live (JWT today, PAT after Decision 8) |

Security rules for the flows (all are review points for the security review of Amendment 2):

- The callback server binds `127.0.0.1` only, answers one request, checks `state` (OAuth) and
  closes; the browser wait has the connector's timeout (`external_browser_timeout`, 120 s
  default, `C/connection.py:266`).
- PKCE S256 by default; authorization and token URLs must be `https` unless they point at the
  configured Snowflake host with `protocol=http` (tests).
- Okta URL prefix and SAML postback checks are on by default (they stop a phishing IdP from
  receiving the password or posting a SAML response elsewhere).
- Passwords, passcodes, OAuth codes, verifiers, client secrets, access/refresh/ID/MFA tokens,
  Okta one-time tokens, proof keys and SAML responses are `Secret`s; error messages use server
  codes and messages only. The secret-marker test of ADR 0001 Decision 7 extends to each flow.

## Decision 5: `PUT`/`GET` file transfer (`src/transfer/`)

A reusable module that Amendment 1 wires into `sql` and `stage copy` reuses later (it builds the
`PUT`/`GET` statement text the way `snow stage` quotes paths, `S/_plugins/stage/manager.py:202,440-446`,
then calls the same `transfer::execute`).

| Piece | Rule (from `C/file_transfer_agent.py`, `C/storage_client.py`, `C/*_storage_client.py`, `C/encryption_util.py`) |
|---|---|
| Plan | Parse `data`: `command`, `src_locations`, `parallel`, `overwrite`, `autoCompress`, `sourceCompression`, `threshold` (default 64 MiB), `stageInfo` (`locationType` `S3`/`AZURE`/`GCS`/`LOCAL_FS`, `location`, `region`, `endPoint`, `storageAccount`, `useS3RegionalUrl`, `useRegionalUrl`, `useVirtualUrl`, `creds`), `encryptionMaterial` (object for PUT, list per file for GET), `presignedUrls`, `localLocation`. |
| Local files (PUT) | `~` expansion, absolute path, glob (`glob` crate); no match → "File doesn't exist"; a directory → error. |
| Compression | `sourceCompression=auto_detect`: extension, then magic bytes (`ORC`, `PAR1`, zstd); `.br` → brotli; GZIP, DEFLATE, RAW_DEFLATE, BZIP2, ZSTD, BROTLI, PARQUET, ORC pass through; LZIP/LZMA/LZO/XZ/COMPRESS → error. `autoCompress` gzips uncompressed files (`.gz` suffix, mtime 0, empty name for a stable digest). |
| Digest | SHA-256 (base64) of the compressed bytes before encryption, sent as `sfc-digest` metadata. |
| Encryption | When `encryptionMaterial` is present: random file key (size of the decoded master key) and 16-byte IV, AES-CBC/PKCS#7 content, file key wrapped with AES-ECB under `queryStageMasterKey`; `matdesc` `{"queryId","smkId","keySize"}`. GET reverses it. No GCM (the connector has none). |
| S3 | Own SigV4 signer (`hmac` + `sha2`) with `x-amz-security-token`; virtual-host URLs (`s3.<region>` when regional, `.amazonaws.com.cn`, or `endPoint`); up to 5 redirects; metadata `x-amz-meta-sfc-digest`, `-x-amz-key`, `-x-amz-iv`, `-x-amz-matdesc`; multipart (8 MiB parts, scaled to ≤ 10 000) at `threshold`; ranged GETs. |
| Azure | SAS token on `https://<account>.blob.<endpoint>/<container>/<path>`; `BlockBlob` single PUT or `comp=block` + `comp=blocklist` (`x-ms-blob-content-md5`); metadata `sfcdigest`, `matdesc`, `encryptiondata` JSON. |
| GCS | Presigned URL or `Authorization: Bearer <GCS_ACCESS_TOKEN>`; never chunked; `x-goog-meta-*`. PUT without a token re-issues the `PUT` per file to get `presignedUrl`. |
| `LOCAL_FS` | Copy into `location` (tests and on-prem; 4 MiB chunks). |
| Overwrite | `overwrite=false`: HEAD; existing object → `SKIPPED` (no digest comparison, as the connector). |
| Credentials expiry | S3 `ExpiredToken` (400), Azure 403 auth failure, GCS 401 → re-run the same statement through the session for fresh `creds`, once per expiry, shared across threads. |
| Retries | 5 per chunk, backoff `min(2^n, 16)` s, on 408/429/5xx and transient errors. |
| Parallelism | std threads, `min(parallel, files × chunks)` network workers, at most 2 × workers chunks queued; GET writes `<name>.part` (0600) at chunk offsets, then decrypts and renames. |
| Rows | PUT: `source, target, source_size, target_size, source_compression, target_compression, status, message` (`UPLOADED`/`SKIPPED`/`ERROR`), sorted; GET: `file, size, status, message` (`DOWNLOADED`/`ERROR`). With `snow`'s defaults an error fails the statement instead of a row. Exact types and rendering come from goldens against `snow` (Amendment 1). |

Security rules (review points for Amendment 1): stage credentials, SAS tokens, GCS tokens,
`queryStageMasterKey`, `qrmk`/`chunkHeaders` and presigned URLs are `Secret`s; debug logs show the
host and object path only. GET writes **only the base name** of each remote file inside the target
directory and rejects names that are empty, `.`/`..` or contain a path separator after
normalisation; it never follows a symlink at the destination. Downloaded data is written 0600
until complete.

## Decision 6: Crates

Checked with `cargo-deny 0.22` on the full graph with these additions (2026-11-21):
`advisories ok, bans ok, licenses ok, sources ok` (only the existing `getrandom`/`windows-sys`
duplicate warnings). All need Rust ≤ 1.89; the toolchain is 1.100.

| Purpose | Crate | Version | License | Why / alternatives |
|---|---|---|---|---|
| AES block cipher | `aes` | 0.9 | MIT OR Apache-2.0 | RustCrypto, same generation as `rsa` 0.10/`sha2` 0.11 (`cipher` 0.5). |
| CBC / ECB modes | `cbc`, `ecb` | 0.2 | MIT OR Apache-2.0 | File encryption and key wrapping (Decision 5). `openssl` rejected: C dependency. `ring` rejected: no CBC/ECB. |
| HMAC (SigV4) | `hmac` | 0.13 | MIT OR Apache-2.0 | ~80 lines of SigV4 on top. `aws-sigv4`/`aws-sdk-s3` rejected: tokio + a large tree for one signer. |
| MD5 (Azure block list) | `md-5` | 0.11 | MIT OR Apache-2.0 | Only `x-ms-blob-content-md5`. |
| gzip | `flate2` (rust backend) | 1 | MIT OR Apache-2.0 | Already a dev-dependency; becomes a dependency for `autoCompress` and chunk bodies not decoded by ureq. |
| Randomness | `getrandom` | 0.4 | MIT OR Apache-2.0 | File keys, IVs, PKCE verifier, `state`, block ids. Already in the tree. |
| Glob | `glob` | 0.3 | MIT OR Apache-2.0 | `file://` wildcards as Python's `glob.glob`. |
| Open the browser | `open` | 5 | MIT | One call; behind `BrowserOpener` so tests never open one. `webbrowser` crate: same job, larger. |
| HTTP, JSON, base64, sha2, uuid | existing | — | — | `ureq` serves the session, storage and IdP calls; no async runtime. |

Rejected: an Arrow decoder (`arrow`, huge; JSON results are forced, S2), `keyring` (Decision 3),
`tiny_http`/`hyper` for the callback (one request on a `TcpListener` is ~60 lines of std),
`quick-xml` (S3 multipart bodies and error `Code` are three fixed shapes; a string builder and a
tag scan do it).

## Decision 7: Test strategy

ADR 0001 Decision 9 rules apply (test-first, ≥ 90 % lines, no real env/home, `httpmock`).

### Mocked server

- `tests/fixtures/connector/` holds response bodies for every exchange: `login-request` (success,
  each `nextAction`, each error code in the tables above), `authenticator-request`,
  `token-request`, heartbeat, close, `query-request` (inline, chunked, `333334` + result, error,
  `390112` then success), PUT/GET answers for S3, Azure, GCS and `LOCAL_FS`, Okta `authn` and SSO
  HTML, OAuth token responses. Shapes come from the connector source cited above and from the
  sandbox (S1–S10).
- `scripts/capture-connector-fixtures.py` (Amendment 2 writes it; run by hand like
  `scripts/capture-goldens.sh`) signs in with the sandbox key pair, runs synthetic SQL, a chunked
  query, a `SYSTEM$WAIT(50)` and PUT/GET metadata requests, and writes the bodies with **every**
  token, credential, key, URL query string and id replaced by fixed markers. Flows the sandbox
  cannot run are written by hand from the connector code, with the source line in a comment.
- Each test asserts the request too: path, query parameters, `Authorization` form, `Accept`, and
  the `data` fields of the flow (Decision 4).
- Storage: `httpmock` plays S3, Azure and GCS. Storage clients take their base URL from
  `TransferOptions::endpoint_override` (crate-private, set only by tests; production derives it
  from `stageInfo`). SigV4 has known-answer tests from AWS's published test suite.
- Encryption: known-answer vectors (fixed key, IV, master key) produced once with Python
  `cryptography` following `C/encryption_util.py`, plus round trips.
- Interactive flows: `Prompt`, `BrowserOpener` and `CredentialCache` fakes. The fake browser
  sends the redirect to the callback server the way the IdP would; the OAuth fake checks
  `code_challenge` against the verifier the token request sends.

### Live on the sandbox (`#[ignore]`, `tests/sandbox.rs`, run by the builder before each PR)

| Test | Needs |
|---|---|
| Session sign-in with the key pair; `SET`/`$v` across statements; chunked result; `SYSTEM$WAIT(50)` polling; heartbeat; explicit `token-request` renewal; close | today's env |
| `PUT` to `@~/<random prefix>/` (S3, encrypted), server-side read `SELECT $1 FROM @~/…` (proves Snowflake decrypts our files), `GET` back (byte-identical), `GET` of a file Snowflake wrote with `COPY INTO @~/…` (proves we decrypt theirs), `REMOVE` | today's env |
| Password sign-in, wrong password error | `SNOWFLAKE_TEST_PASSWORD_USER`, `SNOWFLAKE_TEST_PASSWORD` |
| PAT over the SQL API and over `login-request` | `SNOWFLAKE_TEST_PAT` |

Tests skip with a printed reason when their variables are missing, so they pass before that
host step.

### Mock-tested only (README matrix flag)

MFA push (Duo) and MFA passcode / `passcode_in_password` (no second factor the tests can
produce), `USERNAME_PASSWORD_MFA` and its MFA-token cache, `EXTERNALBROWSER` and its ID-token
cache, native Okta, `OAUTH_AUTHORIZATION_CODE` (with refresh and cache),
`OAUTH_CLIENT_CREDENTIALS` (needs an External OAuth IdP), Azure and GCS stage transfers (the
sandbox is on AWS), and re-sign-in after the master token expires. `SNOWFLAKE` password sign-in
joins the list only if the account rejects single-factor passwords (Decision 8).

### Benchmarks

Amendment 1 adds `put-*`/`get-*` scenarios (both CLIs, synthetic files, key pair); Amendment 2 adds a
password `connection-test` scenario once the password user exists. Mock-tested-only flows have
no scenario; the matrix shows the flag instead of a time.

## Decision 8: Sandbox extension

`scripts/sandbox/0005-connector-protocol.sql`, run once by the maintainer as `ACCOUNTADMIN` after setting
the test user and role at the top of its block. It is idempotent: `CREATE … IF NOT EXISTS` /
`CREATE OR ALTER` for every object, `FORCE` to re-attach policies, and remove-then-add for the PAT.
Re-running it **rotates** the password and the PAT. It creates:

1. `SNOW_RS_CLI_ADMIN.POLICIES` (database + schema for the two policies only).
2. Authentication policy `PASSWORD_TEST_POLICY`: `AUTHENTICATION_METHODS = ('PASSWORD')`,
   `MFA_ENROLLMENT = 'OPTIONAL'`.
3. User `SNOW_RS_CLI_PASSWORD_TEST`, `TYPE = PERSON`, role `PUBLIC`, no warehouse, no grants, a
   random 34-character password, that policy. It can sign in and run `SELECT CURRENT_USER()`;
   nothing else.
4. Authentication policy `AGENT_PAT_POLICY` on the test user:
   `PAT_POLICY = (MAX_EXPIRY_IN_DAYS = 365, NETWORK_POLICY_EVALUATION = ENFORCED_NOT_REQUIRED)`,
   all sign-in methods still allowed (the key pair keeps working). Needed because a PAT needs a
   network policy by default (S11), and the CI runner's egress IP is not fixed. The block stops
   without changes if that user already has another authentication policy.
5. PAT `SNOW_RS_CLI_TESTS` on the test user, `ROLE_RESTRICTION` = the test role,
   365 days.

Its last result is the env-var table. **Env vars the tests read** (names only):

| Variable | Value |
|---|---|
| `SNOWFLAKE_TEST_PASSWORD_USER` | `SNOW_RS_CLI_PASSWORD_TEST` |
| `SNOWFLAKE_TEST_PASSWORD` | the generated password |
| `SNOWFLAKE_TEST_PAT` | the PAT secret |

(Not `SNOWFLAKE_PASSWORD`/`SNOWFLAKE_TOKEN`: those are `snow`'s own connection overrides.)
The existing `SNOWFLAKE_ACCOUNT`, `SNOWFLAKE_USER`, `SNOWFLAKE_ROLE`, `SNOWFLAKE_WAREHOUSE`,
`SNOWFLAKE_DATABASE` and `SNOWFLAKE_PRIVATE_KEY_B64` are unchanged.

Not included, with reasons:

- **OAuth client-credentials integration:** Snowflake OAuth (`TYPE = OAUTH`) supports the
  authorization-code, refresh-token and JWT-bearer grants, not client credentials; that grant
  needs `TYPE = EXTERNAL_OAUTH` with an outside IdP (Okta, Entra ID). None exists for the
  sandbox, so the flow is mock-tested only.
- **An MFA user:** the second factor (passkey, TOTP app, Duo) is enrolled by the user in
  Snowsight; there is no SQL to give tests a TOTP secret, and OTP codes from
  `ADD MFA METHOD OTP` are single-use.

**Known risk:** Snowflake's MFA rollout ends password-only sign-in for human users in
"Phase 3" (planned August to October 2026, per account). `MFA_ENROLLMENT = 'OPTIONAL'` is
"retained for backward compatibility only". If the sandbox account already enforces Phase 3,
the password user's sign-in fails with an MFA-required error. Amendment 2 then records the error
code here as an amendment, flags `SNOWFLAKE` password sign-in "mock-tested only" and drops
`SNOWFLAKE_TEST_PASSWORD*`. The maintainer has nothing more to do either way.

## Consequences

- Password, MFA, browser, Okta and both OAuth flows become possible, at the cost of a second
  transport built from an undocumented protocol. It is pinned by fixtures from connector 4.8.1
  and by live tests; a new `snow`/connector version means re-reading the cited files and
  refreshing the fixtures (like `scripts/snapshot-snow-surface.sh`).
- The default path keeps ADR 0002/0004's measured performance. A session run pays one extra
  round trip (`login-request`), as `snow` always does.
- Session runs execute statement by statement, so `USE`/`ALTER SESSION`/temporary objects work as
  in `snow`; SQL API runs keep ADR 0004's multi-statement request. Two paths must render the same
  output: one result model and shared goldens cover it.
- `PUT`/`GET` work with the key pair today; `stage copy` gets the transfer module without a
  redesign.
- `src/connection.rs` grows (Decision 2); `config::resolve` accepts the new authenticators.
- The credential cache lives in a file on macOS/Windows too (Decision 3), unlike `snow`.
- Sub-issue boundaries: **Amendment 2** owns `src/session/`, `src/sql/executor.rs`, the
  `RowStream` chunk source, the connection fields and the capture script; it lands the
  `Session` + `query()` skeleton with key-pair sign-in in its first commit series. **Amendment 1**
  owns `src/transfer/` and the `sql` wiring; it can build and test the whole module against
  `LOCAL_FS` and `httpmock` storage in parallel, and only `Executor` integration waits for
  Amendment 2's `Session::query`. If Amendment 1 starts first, it lands that minimal key-pair `Session`
  itself, exactly as specified in Decision 2, and Amendment 2 extends it. **Amendment 3** runs the REPL on
  `Executor::Session`.

## Amendment 1: what the PUT/GET build settled

The PUT/GET work started first, so it landed the key-pair `Session` skeleton. Where the build had to pick,
it chose as below; Amendment 2 extends these types without a redesign.

- **Transport choice:** the statement splitter already flags `PUT`/`GET` with the connector's rule
  (Decision 1); `Statement::put_or_get` carries it, and `RunNeeds { session }` is set from it. The
  "PUT and GET are not supported yet" rejection is gone.
- **`Executor::connect`** takes what the SQL API path already builds (`Box<dyn Authenticator>`,
  `ClientOptions`, `ScriptOptions`) plus the `TransferOptions`, instead of an `Interaction`: the
  bearer credential (JWT, OAuth token, PAT) signs in through `login-request`
  (`AUTHENTICATOR` + `TOKEN`). `Interaction` has only `credential` and `clock` for now; Amendment 2
  adds the prompt, browser and cache. `Executor::Session` also holds the `TransferOptions`.
- **`--secondary-roles`** on a session goes in the `login-request` body as `SECONDARY_ROLES`, as
  the connector sends it.
- **No `queryContextDTO`:** echoing the server's `queryContext` back made the next
  `query-request` fail with HTTP 400 on the sandbox; the connector's query-context cache is an
  optimisation the server does not require, so it is left out.
- **Result chunks** (S6) download one at a time as the rows are read (`RowStream::from_pages`);
  Amendment 2 may add the bounded parallel window.
- **Session errors** use `snow`'s panel text (`<code> (<sqlState>): <query id>: <message>`);
  transfer errors are the connector's (`<errno>: <errno>: <message>`), `Sql` class (exit 5 with
  `--enhanced-exit-codes`, as `snow`).
- **Transfer:** a HEAD only when `overwrite` is false; one `<name>.<n>.part` per downloaded file
  (two stage files with the same base name must not share one); the decrypted file is written
  next to the target and renamed over it; a single-part download whose size differs from the
  HEAD's fails (it guards against a transparently decompressed body). Messages and logs show
  storage URLs without their query string, and transport errors without their own text.

## Amendment 2: what the sign-in build settled

The sign-in work built Decisions 2 to 4 on Amendment 1's `Session`. Where the connector 4.8.1 code and this
ADR's wording differed, the build follows the connector; the other open points it decided as below.

- **Transport choice:** `auth::Method::needs_session()` is true for `SNOWFLAKE`,
  `USERNAME_PASSWORD_MFA`, `EXTERNALBROWSER`, Okta and both OAuth flows; the commands turn it
  into `auth::Credential::Connector`, and `Executor::connect` then signs in on a session whatever
  the statements are. `connection test` uses the same `Executor`, so every sign-in works there.
  `Executor::connect` also takes a `SignInIo` (prompt, browser opener, credential cache, and the
  connection's session options) instead of Decision 2's `Interaction`, which stays the seam of
  `Session::login`. `PAT_WITH_EXTERNAL_SESSION` still fails with "not supported yet": `snow` has
  no option for its external session id.
- **Flags:** `snow` 3.34.0's surface has `--password`, `--mfa-passcode` (a value, or a prompt
  when given alone, as click's `prompt_required=False`), `--protocol`, the nine `--oauth-*`,
  `--client-store-temporary-credential` and `--server-session-keep-alive`, on `connection test`,
  `generate-jwt`, `generate-workload-identity-token` and `sql`. There is no
  `--mfa-passcode-in-password`, `--session-token` or `--master-token` flag in 3.34.0, so
  `passcode_in_password`, `client_session_keep_alive` and its heartbeat frequency are
  connection keys only, and `session_token`/`master_token` are left unsupported (ignored with
  the usual "unsupported connection key" log line).
- **`passcode_in_password`:** the connector only sends `EXT_AUTHN_DUO_METHOD=passcode`; the user
  appends the passcode to the password. Decision 4's "passcode appended to the password" means
  that, not that the client appends it.
- **Duo push:** the tokens are collected with the `inFlightCtx` of the `EXT_AUTHN_SUCCESS`
  answer, as the connector; that last request keeps `SESSION_PARAMETERS` so results stay JSON.
  `login-request` uses a 120 s per-request timeout (the push waits for the user).
- **Error text:** a rejected sign-in reads as `snow` prints it, checked against `snow` 3.34.0 on
  the sandbox (a wrong password for a user that does not exist):
  `Could not connect to Snowflake. Reason: 390100 (28000): Failed to connect to DB: <host>:<port>. <message>`
  (`28000` for the connector's credential-rejection codes, `08001` otherwise). Pre-checks use the
  connector's codes (`251005` user empty, `251006` password empty, `251013`/`251020` OAuth client
  id/secret, `251007` URL schemes), and `snow`'s OAuth hints follow a `390303`/`390318`.
- **Client credentials** are never cached or refreshed (the connector passes no token cache to
  `AuthByOauthCredentials`); Decision 4's "access token" cache column applies to the
  authorization code only. A rejected OAuth token (`390303`/`390318`) is dropped from memory and
  cache, and the flow gets a new one once (refresh token first, else the IdP), as the
  connector's reauthentication.
- **URL rules:** besides the connector's `https` check on the authorization URL, the token URL
  must be `https` too (Decision 4's security rule); plain `http` is accepted only for a URL on the
  configured Snowflake host when the connection itself uses `protocol=http` (the mocked tests).
  The `{host}`/`{port}` placeholders of both URLs are expanded as the connector does.
- **Browser instructions** go to standard error for both browser flows (`snow` mirrors them
  there for `EXTERNALBROWSER` and swallows them for the OAuth code flow, which would hide the
  paste-the-URL fallback). The external-browser wait has the 120 s timeout of Decision 4 (the
  connector waits forever); the callback accepts a `GET ?token=` or a `POST` from Snowflake's own
  origin (scheme, host and port), answers CORS preflights only from that origin, and ignores
  everything else.
- **Credential cache:** as Decision 3, in `src/session/cache.rs`; `USERNAME_PASSWORD_MFA` always
  uses it (`snow` sets `client_request_mfa_token`), `EXTERNALBROWSER` follows
  `client_store_temporary_credential` on Linux and is on elsewhere (the connector's rule), and the
  authorization-code flow follows `client_store_temporary_credential`.
- **Booleans in `connections.toml`:** a TOML boolean, or `true`/`false`/`1`/`0` in any case
  (`snow`'s `try_cast_to_bool`). Anything else is a Client error naming the key: `snow` passes it
  on as a string the connector treats as true, which this build does not reproduce.
- **Not built:** signing in again by itself after `390114` (master token expired) for
  `EXTERNALBROWSER`; a CLI run ends long before the 4-hour master token.
- **Fixtures:** `scripts/capture-connector-fixtures.py` wrote `tests/fixtures/connector/`
  (sign-in, select, error, `333334` + result, chunked first page, `PUT` metadata, heartbeat,
  renewal, close) with every token, key, URL, id and sandbox name masked; the flows the sandbox
  cannot run are mocked in `src/session/flow_tests.rs` from the connector code.
- **Sandbox:** the extension script had not been run when Amendment 2 was built, so the password and
  PAT live tests (`tests/it/sandbox.rs`) skip with their reason and both stay "mock-tested only"
  in the matrix; no MFA-required code has been observed, so Decision 8's known risk is still
  open. The key-pair session with `client_session_keep_alive` and
  `--server-session-keep-alive` passes live.

## Amendment 3: the interactive session

Decision 1 put the interactive session on the session transport whatever the authenticator. The
build (`src/commands/repl.rs`, `src/repl/`) settled these points:

- **Start:** the banner, the sign-in (`Executor::connect` with `RunNeeds { session: true }`), then
  `select current_version();`, as `snow` runs it before the first prompt: a broken connection fails
  there, with the usual panel and exit 1.
- **One input, one compiled list:** an input goes through the same compiler as `-q` (templating,
  `!source`/`!load`), so `!` commands are statements too (`Statement::command`). They are compiled
  with `snow`'s messages (`src/script/command.rs`) and run between the requests of a run. That
  also makes them work in `-q`, `-f` and `-i` runs; a run with `!queries`, `!result` or `!abort`
  (which call the REST API with the session token, or run `SYSTEM$CANCEL_QUERY`) picks the
  session transport.
- **Settings:** `!set`/`!spool` change the run's output (`Sink`: format, `quiet`, `timing`,
  `timing_in_output_file`, `echo`, spool file); `-o` sets their starting values. As in `snow`, the
  shape of a run's results (JSON list, CSV blank lines) follows the format when printing starts,
  and the console (banner, errors, `Time Elapsed`, goodbye) is muted in JSON, JSON_EXT and CSV.
- **Context:** the session keeps `sessionInfo` from the sign-in and each answer's
  `final…Name` fields as the connector does (database and schema only once set or after `USE`),
  for the `--prompt-format` placeholders.
- **Ctrl-C:** a SIGINT handler (`signal-hook`) is installed once signed in. With it set on the
  session, `query` waits on a worker thread; Ctrl-C returns at once and sends
  `POST /queries/v1/abort-request` (`sqlText`, `requestId` of the statement), as the connector's
  handler does, and nothing more is printed. It also stops a result being printed. At the prompt
  the terminal is raw, so Ctrl-C is a key that clears the input.
- **Line editor:** `rustyline` (MIT), with `snow`'s Enter rule (submit on `;`, a `!` command or
  `exit`/`quit`; otherwise a new line; Ctrl-J always a new line), and a separate one-key
  yes/no question. The history file is prompt_toolkit's `FileHistory` format, loaded at start and
  appended per input. A non-terminal stdin (blank, since non-blank piped input is a query) reads
  lines instead, after `snow`'s `Warning: Input is not a terminal (fd=0).`.
- **Not ported:** syntax highlighting and the SQL completer (object catalog); `!rehash` prints
  `Autocomplete is disabled.`, which `snow` prints when completion is off.

## Amendment 4: asynchronous statements (`;>`)

A statement ending in `;>` runs as `snow` runs it (`S/_plugins/sql/manager.py`,
`_execute_compiled_statements`): `cursor.execute_async` on the run's connection, then
`print_result(CollectionResult([{"scheduled query ID": <id>}]))`, and the run goes on.

- **Transport:** a run with a `;>` statement takes the session transport, as one with a
  `PUT`/`GET` does (Decision 1, rule 1). The SQL API cannot do it: `async=true` applies to a
  whole multi-statement request, so a statement could not be detached while the ones around it
  keep the session (`USE`, temporary tables) and their order.
- **Submission:** one `query-request` with `asyncExec: true` and the statement without `;>`
  (stripped, not split again: `compile_statements` hands it to `execute_async` whole). The
  server answers `333334` with the `queryId` at once, without checking the statement, so a
  syntax error is not reported and the exit code stays 0 (seen on the sandbox). Any other
  answer is waited for and checked as a plain statement (`C/network.py`, `_post_request`).
- **Output:** the echo (`VerboseCursor`, or the interactive `!set echo`), then the one-row
  collection in the current format, printed on its own wherever the output stands: inside the
  JSON list of a multi-statement run it lands between two results, exactly as `snow` prints it.
  It has no result of its own, so it does not count towards the single-result / list choice
  (`expected_results_cnt`).
- **Close:** the session is not ended while a submitted statement still runs
  (`_all_async_queries_finished`: `GET /monitoring/queries/<id>`, still running for `RUNNING`,
  `QUEUED`, `RESUMING_WAREHOUSE`, `QUEUED_REPARING_WAREHOUSE`, `BLOCKED` or no row yet), so it
  is not cancelled; it expires on the server as the connector leaves it.
- **Tests:** `tests/golden/async/cases.json` (`scripts/capture-goldens.sh --async`: `-q`, `-f`,
  `-i`, mixed with other statements, `--single-transaction`, `--retain-comments`, `--silent`, all
  four formats), replayed by `tests/it/sql_async.rs`; the interactive session in
  `tests/it/repl.rs`; live on the sandbox in `tests/it/sandbox.rs`.
