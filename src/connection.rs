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
    /// `SNOWFLAKE_JWT`, `OAUTH`, `PROGRAMMATIC_ACCESS_TOKEN` or `WORKLOAD_IDENTITY`
    /// (case-insensitive); see `auth::Method`.
    pub authenticator: Option<String>,
    /// `private_key_file`, alias `private_key_path`.
    pub private_key_file: Option<PathBuf>,
    /// Inline PEM (`private_key_raw`).
    pub private_key_raw: Option<Secret>,
    /// `PRIVATE_KEY_PASSPHRASE` env if set, else `private_key_passphrase`
    /// (alias `private_key_file_pwd`) from the connection.
    pub private_key_passphrase: Option<Secret>,
    /// OAuth token, PAT or OIDC ID token (`token`).
    pub token: Option<Secret>,
    /// File holding the token (`token_file_path`); it wins over `token`, as in the connector.
    pub token_file_path: Option<PathBuf>,
    /// `AWS`, `AZURE`, `GCP` or `OIDC`, for `WORKLOAD_IDENTITY`.
    pub workload_identity_provider: Option<String>,
    /// `ALL` or `NONE`: the session's secondary roles.
    pub secondary_roles: Option<String>,
    pub database: Option<String>,
    pub schema: Option<String>,
    pub role: Option<String>,
    pub warehouse: Option<String>,
    /// `password`, for `SNOWFLAKE`, `USERNAME_PASSWORD_MFA` and Okta.
    pub password: Option<Secret>,
    /// MFA passcode (`--mfa-passcode`, or `passcode`).
    pub passcode: Option<Secret>,
    /// The passcode is already appended to the password (`passcode_in_password`).
    pub passcode_in_password: Option<bool>,
    pub oauth_client_id: Option<String>,
    pub oauth_client_secret: Option<Secret>,
    pub oauth_authorization_url: Option<String>,
    pub oauth_token_request_url: Option<String>,
    pub oauth_redirect_uri: Option<String>,
    pub oauth_scope: Option<String>,
    pub oauth_disable_pkce: Option<bool>,
    pub oauth_enable_refresh_tokens: Option<bool>,
    pub oauth_enable_single_use_refresh_tokens: Option<bool>,
    /// Cache ID and OAuth tokens between runs (ADR 0005, Decision 3).
    pub client_store_temporary_credential: Option<bool>,
    /// Heartbeat the session while it is open.
    pub client_session_keep_alive: Option<bool>,
    /// Heartbeat interval in seconds, clamped as the connector does.
    pub client_session_keep_alive_heartbeat_frequency: Option<u64>,
    /// Leave the session open on the server when the run ends.
    pub server_session_keep_alive: Option<bool>,
}
