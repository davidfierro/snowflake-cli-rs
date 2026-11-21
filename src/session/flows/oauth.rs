//! `OAUTH_AUTHORIZATION_CODE` and `OAUTH_CLIENT_CREDENTIALS` (ADR 0005, Decision 4;
//! `C/auth/_oauth_base.py`, `C/auth/oauth_code.py`, `C/auth/oauth_credentials.py`): an access
//! token from the identity provider, then `login-request` with `AUTHENTICATOR=OAUTH`.
//!
//! The authorization-code flow uses PKCE S256 unless disabled, a random `state` it checks on the
//! callback, and the localhost callback server on the redirect URI's port. Access and refresh
//! tokens are cached when `client_store_temporary_credential` is on.

use super::{
    FlowContext, IDP_CONNECTION_ERROR, INVALID_VALUE, LoginFlow, Retry, UNABLE_TO_OPEN_BROWSER,
    handle_failure, idp_agent, split_url, token_urlsafe,
};
use crate::codec::form_encode_plus;
use crate::connection::ConnectionConfig;
use crate::error::Result;
use crate::secret::Secret;
use crate::session::Target;
use crate::session::cache::{TokenKey, TokenType};
use crate::session::callback::{CallbackServer, query_param};
use crate::session::connect_error;
use crate::session::login::LoginFields;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

/// The connector's error codes (`C/errorcode.py`).
const FAILED_TO_REQUEST: u32 = 250003;
const NO_CLIENT_ID: u32 = 251013;
const STATE_CHANGED: u32 = 251014;
const CALLBACK_ERROR: u32 = 251015;
const SERVER_TIMEOUT: u32 = 251016;
const NO_CLIENT_SECRET: u32 = 251020;
/// The client Snowflake registers for its own OAuth when none is given.
const LOCAL_APPLICATION: &str = "LOCAL_APPLICATION";
const TOKEN_REQUEST_ATTEMPTS: u32 = 3;

/// Server codes for a rejected OAuth access token: expired (390318) or invalid (390303).
pub(super) fn is_token_rejection(code: &str) -> bool {
    matches!(code, "390303" | "390318")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Grant {
    AuthorizationCode,
    ClientCredentials,
}

pub(in crate::session) struct OAuth {
    grant: Grant,
    client_id: String,
    client_secret: Secret,
    authorization_url: String,
    token_url: String,
    redirect_uri: String,
    scope: String,
    pkce: bool,
    refresh_enabled: bool,
    single_use_refresh_tokens: bool,
    /// Access/refresh tokens go to the credential cache (authorization code only).
    cache_enabled: bool,
    /// `client_store_temporary_credential` was explicitly turned off (for `snow`'s hint).
    cache_disabled: bool,
    idp_host: String,
    access: Option<Secret>,
    refresh: Option<Secret>,
    loaded: bool,
    /// The access token was rejected: get a new one, not the cached one.
    stale: bool,
}

impl OAuth {
    pub fn authorization_code(conn: &ConnectionConfig) -> Result<Self> {
        let target = Target::of(conn)?;
        let authorization_url = expand(
            conn.oauth_authorization_url
                .as_deref()
                .unwrap_or("https://{host}:{port}/oauth/authorize"),
            &target,
        );
        let token_url = token_url(conn, &target);
        let redirect_uri = conn
            .oauth_redirect_uri
            .clone()
            .unwrap_or_else(|| "http://127.0.0.1".into());
        check_https(&authorization_url, &target, "authorization")?;
        check_https(&token_url, &target, "token request")?;
        if !(redirect_uri.starts_with("http://") || redirect_uri.starts_with("https://")) {
            return Err(connect_error(
                INVALID_VALUE,
                None,
                "OAuth supports only authorization urls that use 'http(s)' scheme",
            ));
        }
        let snowflake_idp = [&authorization_url, &token_url]
            .iter()
            .all(|url| host_of(url).is_some_and(|h| h == target.host.to_ascii_lowercase()));
        let empty = |v: Option<&str>| v.is_none_or(str::is_empty);
        let secret = conn.oauth_client_secret.as_ref().map(Secret::expose);
        let (client_id, client_secret) =
            if empty(conn.oauth_client_id.as_deref()) && empty(secret) && snowflake_idp {
                (
                    LOCAL_APPLICATION.to_string(),
                    Secret::new(LOCAL_APPLICATION),
                )
            } else {
                client_credentials_of(conn)?
            };
        let mut flow = Self::new(
            Grant::AuthorizationCode,
            conn,
            client_id,
            client_secret,
            token_url,
        );
        flow.authorization_url = authorization_url;
        flow.redirect_uri = redirect_uri;
        flow.pkce = conn.oauth_disable_pkce != Some(true);
        flow.cache_enabled = conn.client_store_temporary_credential == Some(true);
        Ok(flow)
    }

    pub fn client_credentials(conn: &ConnectionConfig) -> Result<Self> {
        let target = Target::of(conn)?;
        let (client_id, client_secret) = client_credentials_of(conn)?;
        let token_url = token_url(conn, &target);
        check_https(&token_url, &target, "token request")?;
        let mut flow = Self::new(
            Grant::ClientCredentials,
            conn,
            client_id,
            client_secret,
            token_url,
        );
        // The connector never caches or refreshes client-credentials tokens.
        flow.refresh_enabled = false;
        flow.scope = default_scope(conn);
        Ok(flow)
    }

    fn new(
        grant: Grant,
        conn: &ConnectionConfig,
        client_id: String,
        client_secret: Secret,
        token_url: String,
    ) -> Self {
        let idp_host = host_of(&token_url).unwrap_or_default();
        let refresh_enabled = conn.oauth_enable_refresh_tokens == Some(true);
        let mut scope = default_scope(conn);
        let snowflake_token_host = idp_host.ends_with(".snowflakecomputing.com")
            || idp_host.ends_with(".snowflakecomputing.cn");
        if refresh_enabled
            && !snowflake_token_host
            && !scope.split_whitespace().any(|s| s == "refresh_token")
        {
            if !scope.is_empty() {
                scope.push(' ');
            }
            scope.push_str("offline_access");
        }
        Self {
            grant,
            client_id,
            client_secret,
            authorization_url: String::new(),
            token_url,
            redirect_uri: String::new(),
            scope,
            pkce: false,
            refresh_enabled,
            single_use_refresh_tokens: conn.oauth_enable_single_use_refresh_tokens == Some(true),
            cache_enabled: false,
            cache_disabled: conn.client_store_temporary_credential == Some(false),
            idp_host,
            access: None,
            refresh: None,
            loaded: false,
            stale: false,
        }
    }

    fn key(&self, ctx: &FlowContext<'_>, kind: TokenType) -> Option<TokenKey> {
        let user = ctx.conn.user.as_deref().filter(|u| !u.is_empty())?;
        self.cache_enabled
            .then(|| TokenKey::oauth(&self.idp_host, user, kind))
    }

    fn store(&mut self, ctx: &FlowContext<'_>, access: Secret, refresh: Option<Secret>) {
        if let Some(key) = self.key(ctx, TokenType::OAuthAccessToken) {
            ctx.io.cache.store(&key, &access);
        }
        self.access = Some(access);
        if self.refresh_enabled
            && let Some(refresh) = refresh
        {
            if let Some(key) = self.key(ctx, TokenType::OAuthRefreshToken) {
                ctx.io.cache.store(&key, &refresh);
            }
            self.refresh = Some(refresh);
        }
    }

    /// The `refresh_token` grant; a failure drops the refresh token and leaves no access token.
    fn refresh(&mut self, ctx: &FlowContext<'_>) {
        let Some(refresh) = self.refresh.clone() else {
            return;
        };
        log::debug!("Exchanging the refresh token for a new OAuth access token");
        let mut fields = vec![
            ("grant_type", Secret::new("refresh_token")),
            ("refresh_token", refresh),
        ];
        if !self.scope.is_empty() {
            fields.push(("scope", Secret::new(self.scope.as_str())));
        }
        match self.token_request(ctx, &fields) {
            Ok((access, refresh)) => self.store(ctx, access, refresh),
            Err(_) => {
                log::info!("Failed to exchange the refresh token for a new OAuth access token");
                self.refresh = None;
                if let Some(key) = self.key(ctx, TokenType::OAuthRefreshToken) {
                    ctx.io.cache.remove(&key);
                }
            }
        }
    }

    /// New tokens from the IdP: the browser for the authorization code, one request for client
    /// credentials.
    fn request_tokens(&mut self, ctx: &FlowContext<'_>) -> Result<()> {
        let fields = match self.grant {
            Grant::ClientCredentials => vec![
                ("grant_type", Secret::new("client_credentials")),
                ("scope", Secret::new(self.scope.as_str())),
            ],
            Grant::AuthorizationCode => self.authorization_code_fields(ctx)?,
        };
        let (access, refresh) = self.token_request(ctx, &fields)?;
        self.store(ctx, access, refresh);
        Ok(())
    }

    fn authorization_code_fields(
        &self,
        ctx: &FlowContext<'_>,
    ) -> Result<Vec<(&'static str, Secret)>> {
        let local = is_local(&self.redirect_uri);
        let server = CallbackServer::bind(if local {
            port_of(&self.redirect_uri)
        } else {
            0
        })?;
        let redirect_uri = if local {
            with_port(&self.redirect_uri, server.port())
        } else {
            self.redirect_uri.clone()
        };
        let state = token_urlsafe()?;
        let verifier = if self.pkce {
            Some(Secret::new(token_urlsafe()?))
        } else {
            None
        };
        let mut params = vec![
            ("response_type", "code".to_string()),
            ("client_id", self.client_id.clone()),
            ("redirect_uri", redirect_uri.clone()),
            ("state", state.clone()),
        ];
        if !self.scope.is_empty() {
            params.push(("scope", self.scope.clone()));
        }
        if let Some(verifier) = &verifier {
            params.push(("code_challenge", challenge(verifier)));
            params.push(("code_challenge_method", "S256".into()));
        }
        let query: Vec<String> = params
            .iter()
            .map(|(k, v)| format!("{k}={}", form_encode_plus(v)))
            .collect();
        let url = format!("{}?{}", self.authorization_url, query.join("&"));
        ctx.io.prompt.say(
            "Initiating login request with your identity provider. A browser window should have opened for you to complete the login. If you can't see it, check existing browser windows, or your OS settings. Press CTRL+C to abort and try again...",
        );
        let redirected = if ctx.io.browser.open(&url) {
            let timeout = ctx.inner.options.browser_timeout;
            let target = receive(&server, Instant::now() + timeout).ok_or_else(|| {
                handle_failure(
                    ctx.target,
                    SERVER_TIMEOUT,
                    "Unable to receive the OAuth message within a given timeout. Please check the redirect URI and try again.",
                )
            })?;
            let (code, got_state) = parse_redirect(&target, ctx.target)?;
            let code = code.ok_or_else(|| {
                handle_failure(
                    ctx.target,
                    UNABLE_TO_OPEN_BROWSER,
                    "Unable to open a browser in this environment and OAuth URL contained no authorization code.",
                )
            })?;
            (code, got_state)
        } else {
            ctx.io.prompt.say(&format!(
                "We were unable to open a browser window for you, please open the URL manually then paste the URL you are redirected to into the terminal:\n{url}"
            ));
            let pasted = ctx
                .io
                .prompt
                .prompt("Enter the URL the OAuth flow redirected you to: ", false)?;
            let (code, got_state) = parse_redirect(&pasted, ctx.target)?;
            let code = code.ok_or_else(|| {
                handle_failure(
                    ctx.target,
                    UNABLE_TO_OPEN_BROWSER,
                    "Unable to open a browser in this environment and OAuth URL contained no code",
                )
            })?;
            (code, got_state)
        };
        let (code, got_state) = redirected;
        if got_state.as_deref() != Some(state.as_str()) {
            return Err(handle_failure(
                ctx.target,
                STATE_CHANGED,
                "State changed during OAuth process.",
            ));
        }
        let mut fields = vec![
            ("grant_type", Secret::new("authorization_code")),
            ("code", code),
            ("redirect_uri", Secret::new(redirect_uri)),
        ];
        if self.single_use_refresh_tokens {
            fields.push(("enable_single_use_refresh_tokens", Secret::new("true")));
        }
        if let Some(verifier) = verifier {
            fields.push(("code_verifier", verifier));
        }
        Ok(fields)
    }

    /// `POST` to the token endpoint with Basic client authentication; retried on transport
    /// errors, 408, 429 and 5xx. Error messages never carry the IdP's answer.
    fn token_request(
        &self,
        ctx: &FlowContext<'_>,
        fields: &[(&str, Secret)],
    ) -> Result<(Secret, Option<Secret>)> {
        let body = Secret::new(
            fields
                .iter()
                .map(|(k, v)| format!("{k}={}", form_encode_plus(v.expose())))
                .collect::<Vec<_>>()
                .join("&"),
        );
        let basic = Secret::new(format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!(
                "{}:{}",
                self.client_id,
                self.client_secret.expose()
            ))
        ));
        let agent = idp_agent(ctx, 0);
        let mut attempt = 0;
        let text = loop {
            attempt += 1;
            log::debug!("POST OAuth token endpoint (attempt {attempt})");
            let result = agent
                .post(&self.token_url)
                .header("Authorization", basic.expose())
                .header("Accept", "application/json")
                .header(
                    "Content-Type",
                    "application/x-www-form-urlencoded; charset=UTF-8",
                )
                .send(body.expose())
                .and_then(|mut r| {
                    let status = r.status().as_u16();
                    r.body_mut().read_to_string().map(|t| (status, t))
                });
            let retry = match &result {
                Ok((status, _)) => matches!(status, 408 | 429 | 500..=599),
                Err(_) => true,
            };
            if !retry || attempt >= TOKEN_REQUEST_ATTEMPTS {
                break result.map_err(|e| {
                    handle_failure(
                        ctx.target,
                        FAILED_TO_REQUEST,
                        "Failed to request OAuth access token from IdP.",
                    )
                    .with_source(e)
                })?;
            }
            std::thread::sleep(Duration::from_secs(1 << (attempt - 1)));
        };
        let (status, text) = text;
        log::debug!("OAuth token endpoint: HTTP {status}");
        let value: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
        let invalid = || {
            handle_failure(
                ctx.target,
                IDP_CONNECTION_ERROR,
                "Invalid HTTP request from web browser. Idp authentication could have failed.",
            )
        };
        let access = value["access_token"]
            .as_str()
            .filter(|t| !t.is_empty())
            .map(Secret::new)
            .ok_or_else(invalid)?;
        Ok((access, value["refresh_token"].as_str().map(Secret::new)))
    }

    fn invalidate_access(&mut self, ctx: &FlowContext<'_>) {
        self.access = None;
        if let Some(key) = self.key(ctx, TokenType::OAuthAccessToken) {
            ctx.io.cache.remove(&key);
        }
    }
}

impl LoginFlow for OAuth {
    fn prepare(&mut self, ctx: &mut FlowContext<'_>) -> Result<LoginFields> {
        if !self.loaded {
            self.loaded = true;
            if let Some(key) = self.key(ctx, TokenType::OAuthAccessToken) {
                self.access = ctx.io.cache.retrieve(&key);
            }
            if self.refresh_enabled
                && let Some(key) = self.key(ctx, TokenType::OAuthRefreshToken)
            {
                self.refresh = ctx.io.cache.retrieve(&key);
            }
        }
        if self.access.is_none() && self.refresh_enabled {
            self.refresh(ctx);
        }
        if self.access.is_none() {
            self.request_tokens(ctx)?;
        }
        let oauth_type = match self.grant {
            Grant::AuthorizationCode => "oauth_authorization_code",
            Grant::ClientCredentials => "oauth_client_credentials",
        };
        Ok(LoginFields {
            client_environment: vec![("OAUTH_TYPE", oauth_type)],
            ..LoginFields::default()
        }
        .with("AUTHENTICATOR", "OAUTH")
        .with("TOKEN", self.access.clone().unwrap_or_default()))
    }

    /// A rejected access token is dropped (memory and cache); the first time, the flow gets a
    /// new one (refresh, else the IdP) and signs in again, as the connector's reauthentication.
    fn on_failure(&mut self, code: &str, ctx: &mut FlowContext<'_>) -> Result<Retry> {
        if !is_token_rejection(code) {
            return Ok(Retry::Fail);
        }
        self.invalidate_access(ctx);
        if self.stale {
            return Ok(Retry::Fail);
        }
        self.stale = true;
        Ok(Retry::Again)
    }

    /// `snow`'s hint after a rejected token for `OAUTH_AUTHORIZATION_CODE`.
    fn failure_hint(&self, code: &str) -> Option<String> {
        if self.grant != Grant::AuthorizationCode || !is_token_rejection(code) {
            return None;
        }
        let mut hints = Vec::new();
        if !self.refresh_enabled {
            hints.push("Silent OAuth refresh is disabled. To enable it, set oauth_enable_refresh_tokens = true in this connection, or pass --oauth-enable-refresh-tokens for this invocation.");
        }
        if self.cache_disabled {
            hints.push("Credential caching is disabled. To reuse refresh tokens between commands, set client_store_temporary_credential = true.");
        }
        hints.push("Sign in again if no usable refresh token is available. Enabling refresh does not restore revoked credentials.");
        Some(hints.join(" "))
    }
}

/// Waits for the redirect (a `GET` carrying `code` or `error`), answers it with the connector's
/// page, returns its target. Any other request (`/`, `/favicon.ico`, a scanner) is closed
/// unanswered.
fn receive(server: &CallbackServer, deadline: Instant) -> Option<String> {
    loop {
        let (request, responder) = server.next(deadline)?;
        if request.method != "GET"
            || (query_param(&request.target, "code").is_none()
                && query_param(&request.target, "error").is_none())
        {
            responder.close();
            continue;
        }
        responder.ok(&[("Content-Type", "text/html")], OAUTH_PAGE);
        return Some(request.target);
    }
}

const OAUTH_PAGE: &str = "\n<!DOCTYPE html><html><head><meta charset=\"UTF-8\"/>\n<link rel=\"icon\" href=\"data:,\">\n<title>OAuth Response for Snowflake</title></head>\n<body>\nYour identity was confirmed and propagated to Snowflake Snowflake CLI.\nYou can close this window now and go back where you started from.\n</body></html>";

/// `(code, state)` of a redirect URL; an `error` parameter fails with the IdP's error.
fn parse_redirect(url: &str, target: &Target) -> Result<(Option<Secret>, Option<String>)> {
    if let Some(error) = query_param(url, "error") {
        let detail = match query_param(url, "error_description") {
            Some(d) => format!(": {d}"),
            None => ".".into(),
        };
        return Err(handle_failure(
            target,
            CALLBACK_ERROR,
            &format!("Oauth callback returned an {error} error{detail}"),
        ));
    }
    Ok((
        query_param(url, "code").map(Secret::new),
        query_param(url, "state"),
    ))
}

/// `base64url(sha256(verifier))` without padding.
fn challenge(verifier: &Secret) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.expose().as_bytes()))
}

fn client_credentials_of(conn: &ConnectionConfig) -> Result<(String, Secret)> {
    let id = conn
        .oauth_client_id
        .clone()
        .filter(|i| !i.is_empty())
        .ok_or_else(|| {
            connect_error(
                NO_CLIENT_ID,
                None,
                "Oauth code flow requirement 'client_id' is empty",
            )
        })?;
    let secret = conn
        .oauth_client_secret
        .clone()
        .filter(|s| !s.expose().is_empty())
        .ok_or_else(|| {
            connect_error(
                NO_CLIENT_SECRET,
                None,
                "Oauth code flow requirement 'client_secret' is empty",
            )
        })?;
    Ok((id, secret))
}

fn token_url(conn: &ConnectionConfig, target: &Target) -> String {
    expand(
        conn.oauth_token_request_url
            .as_deref()
            .unwrap_or("https://{host}:{port}/oauth/token-request"),
        target,
    )
}

/// `session:role:<role>` when a role is known and no scope is given.
fn default_scope(conn: &ConnectionConfig) -> String {
    match (conn.oauth_scope.as_deref(), conn.role.as_deref()) {
        (Some(scope), _) if !scope.is_empty() => scope.to_string(),
        (_, Some(role)) if !role.is_empty() => format!("session:role:{role}"),
        _ => String::new(),
    }
}

/// The connector formats both URLs with `host` and `port`.
fn expand(url: &str, target: &Target) -> String {
    url.replace("{host}", &target.host)
        .replace("{port}", &target.port.to_string())
}

/// `https`, except a URL on the configured Snowflake host when the connection itself uses `http`
/// (tests): an IdP must never see the code, secret or tokens in the clear.
fn check_https(url: &str, target: &Target, what: &str) -> Result<()> {
    let lower = url.to_ascii_lowercase();
    let local_http = target.protocol == "http"
        && lower.starts_with("http://")
        && host_of(url).is_some_and(|h| h == target.host.to_ascii_lowercase());
    if lower.starts_with("https://") || local_http {
        return Ok(());
    }
    Err(connect_error(
        INVALID_VALUE,
        None,
        &format!("OAuth supports only {what} urls that use 'https' scheme"),
    ))
}

fn host_of(url: &str) -> Option<String> {
    let uri: ureq::http::Uri = url.parse().ok()?;
    uri.host().map(str::to_ascii_lowercase)
}

fn host_and_port(authority: &str) -> (&str, Option<u16>) {
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.ends_with(']') || authority.starts_with('[') => {
            (host, port.parse().ok())
        }
        _ => (authority, None),
    }
}

fn is_local(url: &str) -> bool {
    let (_, authority, _) = split_url(url);
    matches!(host_and_port(authority).0, "localhost" | "127.0.0.1")
}

fn port_of(url: &str) -> u16 {
    let (_, authority, _) = split_url(url);
    host_and_port(authority).1.unwrap_or(0)
}

/// The URL with its port replaced (the redirect URI must name the port the server got).
fn with_port(url: &str, port: u16) -> String {
    let (scheme, authority, rest) = split_url(url);
    let (host, _) = host_and_port(authority);
    format!("{scheme}://{host}:{port}{rest}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(protocol: &str) -> Target {
        Target {
            protocol: protocol.into(),
            host: "acct.snowflakecomputing.com".into(),
            port: 443,
        }
    }

    fn conn() -> ConnectionConfig {
        ConnectionConfig {
            account: Some("acct".into()),
            user: Some("me".into()),
            role: Some("ANALYST".into()),
            ..Default::default()
        }
    }

    #[test]
    fn snowflake_defaults_for_the_authorization_code() {
        let flow = OAuth::authorization_code(&conn()).unwrap();
        assert_eq!(
            flow.authorization_url,
            "https://acct.snowflakecomputing.com:443/oauth/authorize"
        );
        assert_eq!(
            flow.token_url,
            "https://acct.snowflakecomputing.com:443/oauth/token-request"
        );
        assert_eq!(flow.redirect_uri, "http://127.0.0.1");
        assert_eq!(flow.client_id, LOCAL_APPLICATION);
        assert_eq!(flow.client_secret.expose(), LOCAL_APPLICATION);
        assert_eq!(flow.scope, "session:role:ANALYST");
        assert!(flow.pkce);
        assert!(!flow.cache_enabled);
    }

    #[test]
    fn an_external_idp_needs_client_credentials_and_https() {
        let mut c = conn();
        c.oauth_authorization_url = Some("https://idp.example/authorize".into());
        c.oauth_token_request_url = Some("https://idp.example/token".into());
        let err = OAuth::authorization_code(&c).err().unwrap();
        assert_eq!(
            err.message(),
            "Could not connect to Snowflake. Reason: 251013: Oauth code flow requirement 'client_id' is empty"
        );
        c.oauth_client_id = Some("id".into());
        let err = OAuth::authorization_code(&c).err().unwrap();
        assert!(err.message().contains("251020"));
        c.oauth_client_secret = Some(Secret::new("s"));
        c.oauth_enable_refresh_tokens = Some(true);
        let flow = OAuth::authorization_code(&c).unwrap();
        assert_eq!(flow.idp_host, "idp.example");
        assert_eq!(flow.scope, "session:role:ANALYST offline_access");
        c.oauth_authorization_url = Some("http://idp.example/authorize".into());
        let err = OAuth::authorization_code(&c).err().unwrap();
        assert_eq!(
            err.message(),
            "Could not connect to Snowflake. Reason: 251007: OAuth supports only authorization urls that use 'https' scheme"
        );
        c.oauth_authorization_url = Some("https://idp.example/authorize".into());
        c.oauth_token_request_url = Some("http://idp.example/token".into());
        assert!(OAuth::authorization_code(&c).is_err());
        c.oauth_token_request_url = Some("https://idp.example/token".into());
        c.oauth_redirect_uri = Some("ftp://x".into());
        assert!(OAuth::authorization_code(&c).is_err());
    }

    #[test]
    fn refresh_scope_rules() {
        let mut c = conn();
        c.oauth_enable_refresh_tokens = Some(true);
        c.oauth_scope = Some("refresh_token".into());
        c.oauth_client_id = Some("id".into());
        c.oauth_client_secret = Some(Secret::new("s"));
        c.oauth_token_request_url = Some("https://idp.example/token".into());
        assert_eq!(
            OAuth::authorization_code(&c).unwrap().scope,
            "refresh_token"
        );
        c.oauth_scope = None;
        c.role = None;
        assert_eq!(
            OAuth::authorization_code(&c).unwrap().scope,
            "offline_access"
        );
        // Snowflake's own token endpoint takes no `offline_access`.
        c.oauth_token_request_url = None;
        assert_eq!(OAuth::authorization_code(&c).unwrap().scope, "");
    }

    #[test]
    fn client_credentials_need_both_and_never_refresh() {
        let mut c = conn();
        assert!(OAuth::client_credentials(&c).is_err());
        c.oauth_client_id = Some("id".into());
        c.oauth_client_secret = Some(Secret::new("s"));
        c.oauth_enable_refresh_tokens = Some(true);
        c.oauth_token_request_url = Some("https://idp.example/token".into());
        let flow = OAuth::client_credentials(&c).unwrap();
        assert!(!flow.refresh_enabled);
        assert_eq!(flow.scope, "session:role:ANALYST");
        c.oauth_token_request_url = Some("http://idp.example/token".into());
        assert!(OAuth::client_credentials(&c).is_err());
    }

    #[test]
    fn plain_http_is_only_for_the_snowflake_host_of_an_http_connection() {
        assert!(check_https("http://acct.snowflakecomputing.com/t", &target("http"), "x").is_ok());
        assert!(
            check_https(
                "http://acct.snowflakecomputing.com/t",
                &target("https"),
                "x"
            )
            .is_err()
        );
        assert!(check_https("http://other/t", &target("http"), "x").is_err());
        assert!(check_https("HTTPS://other/t", &target("https"), "x").is_ok());
    }

    #[test]
    fn redirect_uris() {
        assert!(is_local("http://127.0.0.1"));
        assert!(is_local("http://localhost:8001/cb"));
        assert!(!is_local("https://app.example/cb"));
        assert_eq!(port_of("http://localhost:8001/cb"), 8001);
        assert_eq!(port_of("http://127.0.0.1"), 0);
        assert_eq!(with_port("http://127.0.0.1", 5000), "http://127.0.0.1:5000");
        assert_eq!(
            with_port("http://localhost:1/cb?x=1", 5000),
            "http://localhost:5000/cb?x=1"
        );
        assert_eq!(host_and_port("u@h:1"), ("h", Some(1)));
        assert_eq!(split_url("noscheme"), ("", "noscheme", ""));
    }

    #[test]
    fn redirects_and_hints() {
        let t = target("https");
        let (code, state) = parse_redirect("/?code=c1&state=s1", &t).unwrap();
        assert_eq!(code.unwrap().expose(), "c1");
        assert_eq!(state.as_deref(), Some("s1"));
        let err = parse_redirect("/?error=access_denied&error_description=No+way", &t)
            .err()
            .unwrap();
        assert_eq!(
            err.message(),
            "Could not connect to Snowflake. Reason: 251015 (08001): Failed to connect to DB: acct.snowflakecomputing.com:443, Oauth callback returned an access_denied error: No way"
        );
        let err = parse_redirect("/?error=x", &t).err().unwrap();
        assert!(err.message().ends_with("returned an x error."));
        // RFC 7636, appendix B.
        assert_eq!(
            challenge(&Secret::new("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        let mut c = conn();
        c.client_store_temporary_credential = Some(false);
        let flow = OAuth::authorization_code(&c).unwrap();
        let hint = flow.failure_hint("390318").unwrap();
        assert!(hint.starts_with("Silent OAuth refresh is disabled."));
        assert!(hint.contains("Credential caching is disabled."));
        assert!(flow.failure_hint("390100").is_none());
        c.oauth_client_id = Some("i".into());
        c.oauth_client_secret = Some(Secret::new("s"));
        assert!(
            OAuth::client_credentials(&c)
                .unwrap()
                .failure_hint("390318")
                .is_none()
        );
    }
}
