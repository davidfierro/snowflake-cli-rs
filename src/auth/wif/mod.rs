//! Workload identity federation (WIF): the attestation each provider gives, obtained the way the
//! Python connector's `wif_util` obtains it, sent to the SQL API as
//! `Authorization: Bearer WIF.<provider>.<attestation>` with token type
//! `WORKLOAD_IDENTITY_FEDERATION` (Snowflake's SQL API authentication docs).

mod aws;
mod azure;
mod jwt;

use super::token::{TokenAuthenticator, WORKLOAD_IDENTITY_FEDERATION, connection_token};
use crate::codec::percent_encode;
use crate::connection::ConnectionConfig;
use crate::env::Env;
use crate::error::{Error, ErrorKind, Result};
use crate::secret::Secret;
use std::time::{Duration, SystemTime};

pub use aws::AwsToken;

/// The connector's `ER_INVALID_WIF_SETTINGS`.
pub const INVALID_WIF_SETTINGS: u32 = 251017;
/// The connector's `ER_WIF_CREDENTIALS_NOT_FOUND`.
pub const WIF_CREDENTIALS_NOT_FOUND: u32 = 251018;
/// The connector's `ER_WIF_UNTRUSTED_HOST`.
pub const WIF_UNTRUSTED_HOST: u32 = 251021;

/// The audience Snowflake expects in AWS, GCP and GitHub tokens.
pub const SNOWFLAKE_AUDIENCE: &str = "snowflakecomputing.com";
const ALLOWED_HOST_SUFFIXES: [&str; 3] = [
    "snowflakecomputing.com",
    "snowflakecomputing.cn",
    "snowflakecomputing.mil",
];
const EXTRA_SUFFIXES_VAR: &str = "SNOWFLAKE_WIF_ALLOWED_HOST_SUFFIXES";
/// A JWT expiring within this many seconds counts as expired (snow's
/// `_OIDC_TOKEN_EXPIRY_MARGIN_SECONDS`).
const OIDC_EXPIRY_MARGIN_SECS: u64 = 60;

/// A workload identity provider (snow's `AttestationProvider`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Aws,
    Azure,
    Gcp,
    Oidc,
}

impl Provider {
    pub const ALL: [Provider; 4] = [
        Provider::Aws,
        Provider::Azure,
        Provider::Gcp,
        Provider::Oidc,
    ];

    /// Case-insensitive, as the connector's `AttestationProvider.from_string`.
    pub fn parse(value: &str) -> std::result::Result<Self, WifError> {
        Self::ALL
            .into_iter()
            .find(|p| p.as_str().eq_ignore_ascii_case(value))
            .ok_or_else(|| {
                WifError::new(
                    INVALID_WIF_SETTINGS,
                    format!(
                        "Unknown workload_identity_provider: '{value}'. Expected one of: AWS, AZURE, GCP, OIDC"
                    ),
                )
            })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Provider::Aws => "AWS",
            Provider::Azure => "AZURE",
            Provider::Gcp => "GCP",
            Provider::Oidc => "OIDC",
        }
    }
}

/// A connector `ProgrammingError`: its code and message. The message never holds a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifError {
    pub code: u32,
    pub message: String,
}

impl WifError {
    pub fn new(code: u32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// As `snow connection generate-workload-identity-token` prints it
    /// (`ClickException(str(err))`: the code appears twice).
    pub fn into_generate_error(self) -> Error {
        Error::new(
            ErrorKind::Client,
            format!("{0}: {0}: {1}", self.code, self.message),
        )
    }

    /// As a failed sign-in prints it (`SnowflakeConnectionError`).
    pub fn into_connect_error(self) -> Error {
        connect_error(self.code, &self.message)
    }
}

/// `Could not connect to Snowflake. Reason: <code>: <message>`, snow's sign-in failure text.
pub fn connect_error(code: u32, message: &str) -> Error {
    Error::new(
        ErrorKind::Client,
        format!("Could not connect to Snowflake. Reason: {code}: {message}"),
    )
}

/// Where the metadata services are. Real addresses by default; tests point them at mock servers.
#[derive(Debug, Clone)]
pub struct Endpoints {
    /// GCP metadata server, up to `…/service-accounts/default`.
    pub gcp_service_account: String,
    /// Azure IMDS token endpoint (without query).
    pub azure_imds_token: String,
    /// Microsoft Entra ID authority, used on AKS (`AZURE_AUTHORITY_HOST` overrides it).
    pub azure_authority: String,
    /// EC2 instance metadata service (`AWS_EC2_METADATA_SERVICE_ENDPOINT` overrides it).
    pub aws_imds: String,
    /// ECS/EKS container credentials host, for `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`.
    pub aws_container: String,
    /// STS base URL; `None` = the regional endpoint.
    pub aws_sts: Option<String>,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            gcp_service_account:
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default"
                    .into(),
            azure_imds_token: "http://169.254.169.254/metadata/identity/oauth2/token".into(),
            azure_authority: "https://login.microsoftonline.com/".into(),
            aws_imds: "http://169.254.169.254".into(),
            aws_container: "http://169.254.170.2".into(),
            aws_sts: None,
        }
    }
}

/// An attestation: the provider and the credential Snowflake verifies.
#[derive(Debug, Clone)]
pub struct Attestation {
    pub provider: Provider,
    pub credential: Secret,
}

/// One HTTP response from a metadata service, token endpoint or STS.
pub(crate) struct Reply {
    pub status: u16,
    pub body: String,
}

/// Obtains attestations. Holds the environment, the endpoints and the clock.
pub struct Attester<'a> {
    env: &'a Env,
    endpoints: Endpoints,
    /// For link-local metadata services: never through a proxy.
    local: ureq::Agent,
    /// For STS, Entra ID and GitHub.
    remote: ureq::Agent,
    now: fn() -> SystemTime,
}

impl<'a> Attester<'a> {
    pub fn new(env: &'a Env, endpoints: Endpoints) -> Self {
        let config = |proxy: bool| {
            let builder = ureq::Agent::config_builder()
                .http_status_as_error(false)
                .max_redirects(0)
                .timeout_connect(Some(Duration::from_secs(5)))
                .timeout_global(Some(Duration::from_secs(30)))
                .user_agent(concat!("snowflake-cli-rs/", env!("CARGO_PKG_VERSION")));
            if proxy {
                builder.build().new_agent()
            } else {
                builder.proxy(None).build().new_agent()
            }
        };
        Self {
            env,
            endpoints,
            local: config(false),
            remote: config(true),
            now: SystemTime::now,
        }
    }

    /// Test seam: a fixed clock (AWS signatures, JWT expiry).
    pub fn with_clock(mut self, now: fn() -> SystemTime) -> Self {
        self.now = now;
        self
    }

    /// The attestation of `provider`. `token` is the OIDC ID token; AWS gives `aws`.
    pub fn attest(
        &self,
        provider: Provider,
        token: Option<&Secret>,
        aws: AwsToken,
    ) -> std::result::Result<Attestation, WifError> {
        let credential = match provider {
            Provider::Aws => self.aws_attestation(aws)?,
            Provider::Azure => self.azure_attestation()?,
            Provider::Gcp => self.gcp_attestation()?,
            Provider::Oidc => {
                let token = token.ok_or_else(|| {
                    WifError::new(
                        WIF_CREDENTIALS_NOT_FOUND,
                        "token must be provided if workload_identity_provider=OIDC",
                    )
                })?;
                jwt::issuer_and_subject(token.expose())?;
                token.clone()
            }
        };
        Ok(Attestation {
            provider,
            credential,
        })
    }

    /// The GCP metadata server's ID token for the default service account.
    fn gcp_attestation(&self) -> std::result::Result<Secret, WifError> {
        let url = format!(
            "{}/identity?audience={SNOWFLAKE_AUDIENCE}",
            self.endpoints.gcp_service_account
        );
        let failed = |why: String| {
            WifError::new(
                WIF_CREDENTIALS_NOT_FOUND,
                format!(
                    "Error fetching GCP identity token: {why}. Ensure the application is running on GCP."
                ),
            )
        };
        let reply = self
            .get(&self.local, &url, &[("Metadata-Flavor", "Google")])
            .map_err(failed)?;
        if reply.status != 200 {
            return Err(failed(status_text(&reply)));
        }
        let token = Secret::new(reply.body);
        jwt::issuer_and_subject(token.expose())?;
        Ok(token)
    }

    pub(crate) fn get(
        &self,
        agent: &ureq::Agent,
        url: &str,
        headers: &[(&str, &str)],
    ) -> std::result::Result<Reply, String> {
        let mut request = agent.get(url);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        read(request.call())
    }

    pub(crate) fn send(
        &self,
        agent: &ureq::Agent,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> std::result::Result<Reply, String> {
        let mut request = if method == "PUT" {
            agent.put(url)
        } else {
            agent.post(url)
        };
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        read(request.send(body))
    }

    /// snow's `_maybe_update_oidc_token`: with no token file, and no token or an expired JWT,
    /// a token from the CI environment (GitHub Actions) replaces it. Failures are only logged.
    fn ambient_oidc_token(&self, conn: &ConnectionConfig) -> Option<Secret> {
        if conn.token_file_path.is_some() {
            return None;
        }
        if let Some(token) = &conn.token {
            if !jwt::is_expired(token.expose(), self.now_secs() + OIDC_EXPIRY_MARGIN_SECS) {
                return None;
            }
            log::info!(
                "Supplied WORKLOAD_IDENTITY token has expired or expires within {OIDC_EXPIRY_MARGIN_SECS} seconds; trying to obtain a new one"
            );
        }
        match self.github_token() {
            Ok(token) => {
                log::info!("WORKLOAD_IDENTITY token acquired automatically");
                Some(token)
            }
            Err(why) => {
                log::info!("No token found during WORKLOAD_IDENTITY auto-detection: {why}");
                None
            }
        }
    }

    /// The GitHub Actions OIDC token (the `id` package snow uses).
    fn github_token(&self) -> std::result::Result<Secret, String> {
        if self.env.get("GITHUB_ACTIONS") != Some("true") {
            return Err("not running in GitHub Actions".into());
        }
        let missing = |var: &str| {
            format!(
                "GitHub: missing or insufficient OIDC token permissions, the {var} environment variable was unset"
            )
        };
        let request_token = self
            .env
            .get_non_empty("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
            .ok_or_else(|| missing("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))?;
        let request_url = self
            .env
            .get_non_empty("ACTIONS_ID_TOKEN_REQUEST_URL")
            .ok_or_else(|| missing("ACTIONS_ID_TOKEN_REQUEST_URL"))?;
        let audience = self
            .env
            .get_non_empty("SNOWFLAKE_AUDIENCE")
            .unwrap_or(SNOWFLAKE_AUDIENCE);
        let separator = if request_url.contains('?') { '&' } else { '?' };
        let url = format!(
            "{request_url}{separator}audience={}",
            percent_encode(audience, b"")
        );
        let bearer = Secret::new(format!("bearer {request_token}"));
        let reply = self.get(&self.remote, &url, &[("Authorization", bearer.expose())])?;
        if reply.status != 200 {
            return Err(format!(
                "GitHub: OIDC token request failed (code={})",
                reply.status
            ));
        }
        let body: serde_json::Value = serde_json::from_str(&reply.body)
            .map_err(|_| "GitHub: malformed OIDC token response".to_string())?;
        body.get("value")
            .and_then(serde_json::Value::as_str)
            .map(Secret::new)
            .ok_or_else(|| "GitHub: malformed OIDC token response".to_string())
    }

    fn now_secs(&self) -> u64 {
        (self.now)()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}

fn read(
    response: std::result::Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> std::result::Result<Reply, String> {
    let mut response = response.map_err(|e| e.to_string())?;
    let status = response.status().as_u16();
    let body = response
        .body_mut()
        .with_config()
        .limit(1 << 20)
        .read_to_string()
        .map_err(|e| e.to_string())?;
    Ok(Reply { status, body })
}

/// `HTTP <status>`: the status only, since a body may carry a credential.
pub(crate) fn status_text(reply: &Reply) -> String {
    format!("HTTP {}", reply.status)
}

/// The connector's `normalize_host`: trimmed, ASCII lower case, no port, no final dot.
fn normalize_host(host: &str) -> String {
    let host = host.trim().to_ascii_lowercase();
    let host = host.split(':').next().unwrap_or_default();
    host.strip_suffix('.').unwrap_or(host).to_string()
}

/// Whether `host` (as it goes into `<protocol>://{host}`) is only a DNS name, optionally with a
/// `:port`: every label non-empty and made of `[A-Za-z0-9_-]` (the connector's `is_ldh_host`).
/// Anything else (`/`, `#`, `?`, `@`, `\`, spaces, …) could make the URL's real host differ from
/// the one the allowlist checked.
fn is_ldh_authority(host: &str) -> bool {
    let (name, port) = match host.split_once(':') {
        Some((name, port)) => (name, Some(port)),
        None => (host, None),
    };
    let name = name.strip_suffix('.').unwrap_or(name);
    let labels_ok = !name.is_empty()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    let port_ok = port.is_none_or(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    labels_ok && port_ok
}

/// The connector's WIF host allowlist: an ambient cloud credential only goes to a Snowflake
/// host, or to one of the suffixes `SNOWFLAKE_WIF_ALLOWED_HOST_SUFFIXES` adds. `host` must be
/// the exact authority the SQL client connects to (`sql::client::host`).
pub fn verify_host(host: &str, env: &Env) -> std::result::Result<(), WifError> {
    let normalized = if is_ldh_authority(host) {
        normalize_host(host)
    } else {
        String::new()
    };
    let extra: Vec<String> = env
        .get(EXTRA_SUFFIXES_VAR)
        .unwrap_or_default()
        .split(',')
        .map(normalize_host)
        .filter(|s| !s.is_empty())
        .collect();
    if !extra.is_empty() {
        log::info!(
            "{EXTRA_SUFFIXES_VAR} is set; extending the WORKLOAD_IDENTITY recognized-host allow-list with additional suffixes: {extra:?}."
        );
    }
    let allowed = !normalized.is_empty()
        && ALLOWED_HOST_SUFFIXES
            .iter()
            .copied()
            .chain(extra.iter().map(String::as_str))
            .any(|s| normalized == s || normalized.ends_with(&format!(".{s}")));
    if allowed {
        Ok(())
    } else {
        Err(WifError::new(
            WIF_UNTRUSTED_HOST,
            format!(
                "WORKLOAD_IDENTITY requires a recognized Snowflake host (*.snowflakecomputing.com, .cn or .mil). Got: '{host}'."
            ),
        ))
    }
}

/// Signs in with `authenticator = WORKLOAD_IDENTITY`: checks the settings and the host as the
/// connector does, obtains the attestation once, and sends it with every request.
pub fn authenticator(
    conn: &ConnectionConfig,
    host: &str,
    attester: &Attester<'_>,
) -> Result<TokenAuthenticator> {
    let provider = conn
        .workload_identity_provider
        .as_deref()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| {
            connect_error(
                INVALID_WIF_SETTINGS,
                "workload_identity_provider must be set to one of AWS,AZURE,GCP,OIDC when authenticator is WORKLOAD_IDENTITY.",
            )
        })?;
    let provider = Provider::parse(provider).map_err(WifError::into_connect_error)?;
    let mut token = None;
    if provider == Provider::Oidc {
        token = attester
            .ambient_oidc_token(conn)
            .map_or_else(|| connection_token(conn), |t| Ok(Some(t)))?;
    }
    verify_host(host, attester.env).map_err(WifError::into_connect_error)?;
    // The SQL API documents an AWS JWT (STS `GetWebIdentityToken`), not the signed request the
    // connector's login-request takes by default.
    let attestation = attester
        .attest(provider, token.as_ref(), AwsToken::OutboundJwt)
        .map_err(WifError::into_connect_error)?;
    let header = Secret::new(format!(
        "WIF.{}.{}",
        attestation.provider.as_str(),
        attestation.credential.expose()
    ));
    TokenAuthenticator::new(header, WORKLOAD_IDENTITY_FEDERATION)
}

#[cfg(test)]
mod tests;
