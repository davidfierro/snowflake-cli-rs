//! The sign-in flows of ADR 0005 Decision 4, one file each. Every flow ends in the same
//! `login-request`; a flow only says what to add to it ([`LoginFlow::prepare`]), what to do when
//! it is rejected ([`LoginFlow::on_failure`]) and what to keep when it succeeds
//! ([`LoginFlow::on_success`]).

mod bearer;
mod browser;
mod oauth;
mod okta;
mod password;

use super::login::{LoginData, LoginFields, NOT_ESTABLISHED};
use super::{Inner, Interaction, Target, connect_error};
use crate::auth::Method;
use crate::connection::ConnectionConfig;
use crate::error::Result;
use crate::secret::Secret;

/// The connector's `ER_IDP_CONNECTION_ERROR`.
const IDP_CONNECTION_ERROR: u32 = 250006;
/// The connector's `ER_INVALID_VALUE`.
const INVALID_VALUE: u32 = 251007;
/// The connector's `ER_UNABLE_TO_OPEN_BROWSER`.
const UNABLE_TO_OPEN_BROWSER: u32 = 250008;

/// What a flow may use while it runs.
pub(in crate::session) struct FlowContext<'a> {
    pub conn: &'a ConnectionConfig,
    pub io: &'a Interaction<'a>,
    pub inner: &'a Inner,
    pub target: &'a Target,
}

/// After a rejected sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::session) enum Retry {
    /// Sign in once more (a stale cached token was dropped).
    Again,
    Fail,
}

pub(in crate::session) trait LoginFlow {
    /// Pre-steps (authenticator-request, browser, Okta, OAuth token endpoint), then the fields
    /// added to `data`.
    fn prepare(&mut self, ctx: &mut FlowContext<'_>) -> Result<LoginFields>;
    /// A rejected sign-in with this server code.
    fn on_failure(&mut self, _code: &str, _ctx: &mut FlowContext<'_>) -> Result<Retry> {
        Ok(Retry::Fail)
    }
    /// Keeps the ID / MFA token when caching is on.
    fn on_success(&mut self, _data: &LoginData, _ctx: &mut FlowContext<'_>) -> Result<()> {
        Ok(())
    }
    /// `snow`'s hint after a final rejection with `code`, if any.
    fn failure_hint(&self, _code: &str) -> Option<String> {
        None
    }
}

/// The flow of `conn`: the bearer credential when the caller has one, else the connector flow
/// its authenticator names.
pub(in crate::session) fn for_connection<'a>(
    conn: &ConnectionConfig,
    io: &Interaction<'a>,
) -> Result<Box<dyn LoginFlow + 'a>> {
    if let Some(credential) = io.credential {
        return Ok(Box::new(bearer::Bearer::new(credential)));
    }
    validate(conn)?;
    Ok(match Method::of(conn)? {
        Method::Password => Box::new(password::Password),
        Method::UsernamePasswordMfa => Box::new(password::UsernamePasswordMfa),
        Method::ExternalBrowser => Box::new(browser::ExternalBrowser::default()),
        Method::Okta => Box::new(okta::Okta),
        Method::OAuthAuthorizationCode => Box::new(oauth::OAuth::authorization_code(conn)?),
        Method::OAuthClientCredentials => Box::new(oauth::OAuth::client_credentials(conn)?),
        other => {
            return Err(crate::error::Error::new(
                crate::error::ErrorKind::Client,
                format!("The {other:?} sign-in needs a credential."),
            ));
        }
    })
}

/// The connector's checks before a sign-in (`SnowflakeConnection.__config`).
fn validate(conn: &ConnectionConfig) -> Result<()> {
    let method = Method::of(conn)?;
    let empty = |v: &Option<String>| v.as_deref().is_none_or(str::is_empty);
    let user_optional = matches!(
        method,
        Method::OAuthAuthorizationCode | Method::OAuthClientCredentials
    );
    if empty(&conn.user) && !user_optional {
        return Err(connect_error(
            251005,
            None,
            "User is empty, but it must be provided unless authenticator is one of OAUTH, NO_AUTH, WORKLOAD_IDENTITY, PROGRAMMATIC_ACCESS_TOKEN, PAT_WITH_EXTERNAL_SESSION, OAUTH_AUTHORIZATION_CODE, OAUTH_CLIENT_CREDENTIALS.",
        ));
    }
    let needs_password = matches!(
        method,
        Method::Password | Method::UsernamePasswordMfa | Method::Okta
    );
    if needs_password && password(conn).is_none() {
        return Err(connect_error(251006, None, "Password is empty"));
    }
    Ok(())
}

fn password(conn: &ConnectionConfig) -> Option<Secret> {
    conn.password.clone().filter(|p| !p.expose().is_empty())
}

/// The connector's `_handle_failure`: `Failed to connect to DB: <host>:<port>, <message>`.
fn handle_failure(target: &Target, errno: u32, message: &str) -> crate::error::Error {
    connect_error(
        errno,
        Some(NOT_ESTABLISHED),
        &format!("Failed to connect to DB: {}, {message}", target.host_port()),
    )
}

/// `POST /session/authenticator-request` with `AUTHENTICATOR` and `extra`; the answer's `data`.
fn authenticator_request(
    ctx: &FlowContext<'_>,
    authenticator: &str,
    extra: &[(&str, String)],
) -> Result<serde_json::Value> {
    let mut data = super::login::base_data(ctx.conn)?;
    data["AUTHENTICATOR"] = authenticator.into();
    for (name, value) in extra {
        data[*name] = value.as_str().into();
    }
    let body = serde_json::json!({ "data": data }).to_string();
    log::debug!("POST /session/authenticator-request");
    let reply = ctx
        .inner
        .send("POST", "/session/authenticator-request", Some(&body), None)?;
    if reply.status != 200 {
        return Err(super::status_error(reply.status, &reply.body));
    }
    let value: serde_json::Value = super::parse(&reply.body)?;
    if value["success"] != true {
        let code = match &value["code"] {
            serde_json::Value::String(c) => c.parse().unwrap_or(super::login::FAILED_TO_CONNECT),
            serde_json::Value::Number(n) => n
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .unwrap_or(super::login::FAILED_TO_CONNECT),
            _ => super::login::FAILED_TO_CONNECT,
        };
        let message = value["message"].as_str().unwrap_or("no error message");
        return Err(handle_failure(ctx.target, code, message));
    }
    Ok(value["data"].clone())
}

/// Scheme, host and port of a URL, the port defaulted for `https` (the connector's
/// `_is_prefix_equal`).
fn prefix(url: &str) -> Option<(String, String, Option<u16>)> {
    let uri: ureq::http::Uri = url.parse().ok()?;
    let scheme = uri.scheme_str()?.to_ascii_lowercase();
    let host = uri.host()?.to_ascii_lowercase();
    let port = uri
        .port_u16()
        .or_else(|| (scheme == "https").then_some(443));
    Some((scheme, host, port))
}

fn same_prefix(a: &str, b: &str) -> bool {
    matches!((prefix(a), prefix(b)), (Some(x), Some(y)) if x == y)
}

/// An agent for identity-provider requests (Okta, OAuth token endpoints): TLS as for Snowflake,
/// statuses as values, and `redirects` hops at most.
fn idp_agent(ctx: &FlowContext<'_>, redirects: u32) -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(redirects)
        .timeout_connect(Some(ctx.inner.options.connect_timeout))
        .timeout_per_call(Some(ctx.inner.options.request_timeout))
        .user_agent(concat!("snowflake-cli-rs/", env!("CARGO_PKG_VERSION")))
        .build()
        .new_agent()
}

/// `scheme://`, the authority, and the rest of a URL.
fn split_url(url: &str) -> (&str, &str, &str) {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    (scheme, &rest[..end], &rest[end..])
}

/// The URL an identity-provider request goes to (tests point it at the mock server).
fn idp_url(ctx: &FlowContext<'_>, url: &str) -> String {
    match &ctx.inner.options.idp_override {
        Some(base) => format!("{base}{}", split_url(url).2),
        None => url.to_string(),
    }
}

/// 43 random bytes, base64url without padding: Python's `secrets.token_urlsafe(43)`.
fn token_urlsafe() -> Result<String> {
    use base64::Engine;
    let mut bytes = [0u8; 43];
    getrandom::fill(&mut bytes).map_err(|e| {
        crate::error::Error::new(
            crate::error::ErrorKind::Client,
            "The system random number generator failed.",
        )
        .with_source(std::io::Error::other(e.to_string()))
    })?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_compare_scheme_host_and_port() {
        assert!(same_prefix(
            "https://org.okta.com",
            "https://ORG.okta.com:443/app/sso"
        ));
        assert!(!same_prefix("https://org.okta.com", "http://org.okta.com"));
        assert!(!same_prefix("https://org.okta.com", "https://evil.com"));
        assert!(!same_prefix(
            "https://org.okta.com",
            "https://org.okta.com:8443"
        ));
        assert!(same_prefix("http://h:80/a", "http://h:80/b"));
        assert!(!same_prefix("not a url", "not a url"));
    }

    #[test]
    fn random_tokens_are_long_and_url_safe() {
        let a = token_urlsafe().unwrap();
        assert_eq!(a.len(), 58);
        assert!(
            a.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        assert_ne!(a, token_urlsafe().unwrap());
    }

    #[test]
    fn the_connector_checks_user_and_password_first() {
        let mut c = ConnectionConfig {
            account: Some("a".into()),
            authenticator: Some("SNOWFLAKE".into()),
            ..Default::default()
        };
        let err = validate(&c).unwrap_err();
        assert!(
            err.message()
                .starts_with("Could not connect to Snowflake. Reason: 251005: User is empty")
        );
        c.user = Some("u".into());
        assert_eq!(
            validate(&c).unwrap_err().message(),
            "Could not connect to Snowflake. Reason: 251006: Password is empty"
        );
        c.password = Some(Secret::new(""));
        assert!(validate(&c).is_err());
        c.password = Some(Secret::new("pw"));
        assert!(validate(&c).is_ok());
        let oauth = ConnectionConfig {
            authenticator: Some("OAUTH_CLIENT_CREDENTIALS".into()),
            ..Default::default()
        };
        assert!(validate(&oauth).is_ok(), "no user needed");
        let browser = ConnectionConfig {
            user: Some("u".into()),
            authenticator: Some("EXTERNALBROWSER".into()),
            ..Default::default()
        };
        assert!(validate(&browser).is_ok(), "no password needed");
    }
}
