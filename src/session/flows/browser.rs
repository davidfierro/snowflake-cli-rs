//! `EXTERNALBROWSER` (ADR 0005, Decision 4; `C/auth/webbrowser.py`, `C/auth/idtoken.py`): a
//! cached ID token when there is one, else SAML through the browser and the localhost callback.

use super::{
    FlowContext, IDP_CONNECTION_ERROR, INVALID_VALUE, LoginFlow, Retry, UNABLE_TO_OPEN_BROWSER,
    authenticator_request, handle_failure,
};
use crate::error::Result;
use crate::secret::Secret;
use crate::session::Target;
use crate::session::cache::{TokenKey, TokenType};
use crate::session::callback::{CallbackServer, Request, form_param, query_param};
use crate::session::login::{LoginData, LoginFields};
use std::time::Instant;

/// Server code: the cached ID token is no longer valid.
const ID_TOKEN_INVALID: &str = "390195";

#[derive(Default)]
pub(in crate::session) struct ExternalBrowser {
    /// The last attempt presented a cached ID token.
    used_id_token: bool,
    /// The cached token was rejected; go through the browser.
    skip_cache: bool,
    /// The browser page may refuse that its ID token be cached.
    consent: Option<bool>,
}

/// Linux follows `client_store_temporary_credential`; the connector turns caching on elsewhere.
fn store_enabled(ctx: &FlowContext<'_>) -> bool {
    !cfg!(target_os = "linux") || ctx.conn.client_store_temporary_credential == Some(true)
}

fn id_key(ctx: &FlowContext<'_>) -> TokenKey {
    TokenKey::sign_in(
        ctx.conn.user.as_deref().unwrap_or_default(),
        &ctx.target.host,
        TokenType::IdToken,
    )
}

impl LoginFlow for ExternalBrowser {
    fn prepare(&mut self, ctx: &mut FlowContext<'_>) -> Result<LoginFields> {
        let store = store_enabled(ctx);
        let fields = LoginFields {
            session_parameters: vec![("CLIENT_STORE_TEMPORARY_CREDENTIAL", store.into())],
            ..LoginFields::default()
        };
        self.used_id_token = false;
        if store
            && !self.skip_cache
            && let Some(token) = ctx.io.cache.retrieve(&id_key(ctx))
        {
            log::debug!("Using the cached ID token");
            self.used_id_token = true;
            return Ok(fields
                .with("AUTHENTICATOR", "ID_TOKEN")
                .with("TOKEN", token));
        }
        let (token, proof_key) = self.browser(ctx)?;
        Ok(fields
            .with("AUTHENTICATOR", "EXTERNALBROWSER")
            .with("TOKEN", token)
            .with("PROOF_KEY", proof_key))
    }

    fn on_failure(&mut self, code: &str, ctx: &mut FlowContext<'_>) -> Result<Retry> {
        if self.used_id_token && code == ID_TOKEN_INVALID {
            ctx.io.cache.remove(&id_key(ctx));
            self.skip_cache = true;
            return Ok(Retry::Again);
        }
        Ok(Retry::Fail)
    }

    fn on_success(&mut self, data: &LoginData, ctx: &mut FlowContext<'_>) -> Result<()> {
        if store_enabled(ctx)
            && self.consent != Some(false)
            && let Some(token) = &data.id_token
        {
            ctx.io.cache.store(&id_key(ctx), token);
        }
        Ok(())
    }
}

impl ExternalBrowser {
    /// The SAML token and proof key, through the browser or a pasted URL.
    fn browser(&mut self, ctx: &FlowContext<'_>) -> Result<(Secret, Secret)> {
        let server = CallbackServer::bind(ctx.inner.options.auth_socket_port)?;
        let data = authenticator_request(
            ctx,
            "EXTERNALBROWSER",
            &[("BROWSER_MODE_REDIRECT_PORT", server.port().to_string())],
        )?;
        let sso_url = data["ssoUrl"].as_str().unwrap_or_default().to_string();
        let proof_key = Secret::new(data["proofKey"].as_str().unwrap_or_default());
        if !is_valid_url(&sso_url) {
            return Err(handle_failure(
                ctx.target,
                INVALID_VALUE,
                &format!("The SSO URL provided {sso_url} is invalid"),
            ));
        }
        let say = |line: &str| ctx.io.prompt.say(line);
        say(
            "Initiating login request with your identity provider. Press CTRL+C to abort and try again...",
        );
        say(&format!("Going to open: {sso_url} to authenticate..."));
        if ctx.io.browser.open(&sso_url) {
            say(
                "A browser window should have opened for you to complete the login. If you can't see it, check existing browser windows, or your OS settings.",
            );
            let timeout = ctx.inner.options.browser_timeout;
            return match self.receive(&server, ctx.target, Instant::now() + timeout) {
                Some(token) => Ok((token, proof_key)),
                None => Err(handle_failure(
                    ctx.target,
                    IDP_CONNECTION_ERROR,
                    &format!(
                        "Timed out after {} second(s) waiting for the browser to return the SAML token.",
                        timeout.as_secs()
                    ),
                )),
            };
        }
        say(
            "We were unable to open a browser window for you, please open the url above manually then paste the URL you are redirected to into the terminal.",
        );
        let url = ctx
            .io
            .prompt
            .prompt("Enter the URL the SSO URL redirected you to: ", false)?;
        match query_param(&url, "token").filter(|t| !t.is_empty()) {
            Some(token) => Ok((Secret::new(token), proof_key)),
            None => Err(handle_failure(
                ctx.target,
                UNABLE_TO_OPEN_BROWSER,
                "Unable to open a browser in this environment and SSO URL contained no token",
            )),
        }
    }

    /// Serves the callback until a request carries the token: CORS preflights from Snowflake's
    /// own origin are answered, anything from another origin is ignored.
    fn receive(
        &mut self,
        server: &CallbackServer,
        target: &Target,
        deadline: Instant,
    ) -> Option<Secret> {
        let mut origin: Option<String> = None;
        loop {
            let (request, responder) = server.next(deadline)?;
            match request.method.as_str() {
                "OPTIONS" => {
                    let requested = request.header("Origin").map(str::to_string);
                    let method_ok = request
                        .header("Access-Control-Request-Method")
                        .is_some_and(|m| m.eq_ignore_ascii_case("POST"));
                    let headers_ok = request
                        .header("Access-Control-Request-Headers")
                        .unwrap_or_default()
                        .split(',')
                        .map(str::trim)
                        .all(|h| h.is_empty() || h.eq_ignore_ascii_case("content-type"));
                    match requested {
                        Some(o) if method_ok && headers_ok && origin_ok(&o, target) => {
                            responder.ok(
                                &[
                                    ("Access-Control-Allow-Methods", "POST"),
                                    ("Access-Control-Allow-Headers", "Content-Type"),
                                    ("Access-Control-Max-Age", "86400"),
                                    ("Access-Control-Allow-Origin", &o),
                                ],
                                "",
                            );
                            origin = Some(o);
                        }
                        _ => responder.close(),
                    }
                }
                "GET" | "POST" => {
                    let requested = request.header("Origin");
                    let allowed = match requested {
                        None => request.method == "GET",
                        Some(o) if o.eq_ignore_ascii_case("null") => request.method == "GET",
                        Some(o) => origin_ok(o, target),
                    };
                    if !allowed {
                        responder.close();
                        continue;
                    }
                    let cors = requested
                        .filter(|o| !o.eq_ignore_ascii_case("null"))
                        .map(str::to_string)
                        .or_else(|| origin.clone().filter(|_| requested.is_some()));
                    let Some(token) = self.token_of(&request) else {
                        responder.close();
                        continue;
                    };
                    match cors {
                        Some(o) => {
                            let consent =
                                serde_json::json!({ "consent": self.consent != Some(false) });
                            responder.ok(
                                &[
                                    ("Content-Type", "text/html"),
                                    ("Access-Control-Allow-Origin", &o),
                                    ("Vary", "Accept-Encoding, Origin"),
                                ],
                                &consent.to_string(),
                            );
                        }
                        None => responder.ok(&[("Content-Type", "text/html")], SAML_PAGE),
                    }
                    return Some(token);
                }
                _ => responder.close(),
            }
        }
    }

    fn token_of(&mut self, request: &Request) -> Option<Secret> {
        let token = if request.method == "GET" {
            query_param(&request.target, "token")
        } else if let Ok(json) = serde_json::from_str::<serde_json::Value>(&request.body) {
            self.consent = json["consent"].as_bool();
            json["token"].as_str().map(str::to_string)
        } else {
            form_param(&request.body, "token")
        };
        token.filter(|t| !t.is_empty()).map(Secret::new)
    }
}

const SAML_PAGE: &str = "\n<!DOCTYPE html><html><head><meta charset=\"UTF-8\"/>\n<link rel=\"icon\" href=\"data:,\">\n<title>SAML Response for Snowflake</title></head>\n<body>\nYour identity was confirmed and propagated to Snowflake Snowflake CLI.\nYou can close this window now and go back where you started from.\n</body></html>";

/// The connector's `is_valid_url`: `http(s)` with a host and no blanks or control characters.
fn is_valid_url(url: &str) -> bool {
    if url.chars().any(|c| c <= ' ') {
        return false;
    }
    matches!(super::prefix(url), Some((scheme, host, _)) if (scheme == "https" || scheme == "http") && !host.is_empty())
}

/// An `Origin` is Snowflake's own: same scheme, host and port, nothing else.
fn origin_ok(origin: &str, target: &Target) -> bool {
    let Ok(uri) = origin.parse::<ureq::http::Uri>() else {
        return false;
    };
    let scheme = uri.scheme_str().unwrap_or_default().to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "https" => Some(443),
        "http" => Some(80),
        _ => None,
    };
    let path_ok = uri
        .path_and_query()
        .is_none_or(|pq| (pq.path() == "/" || pq.path().is_empty()) && pq.query().is_none());
    scheme == target.protocol
        && uri
            .host()
            .is_some_and(|h| h.eq_ignore_ascii_case(&target.host))
        && uri.port_u16().or(default_port) == Some(target.port)
        && !uri.authority().is_some_and(|a| a.as_str().contains('@'))
        && path_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target {
            protocol: "https".into(),
            host: "acct.snowflakecomputing.com".into(),
            port: 443,
        }
    }

    #[test]
    fn only_snowflakes_own_origin_is_accepted() {
        let t = target();
        assert!(origin_ok("https://acct.snowflakecomputing.com", &t));
        assert!(origin_ok("https://ACCT.snowflakecomputing.com:443/", &t));
        assert!(!origin_ok("http://acct.snowflakecomputing.com", &t));
        assert!(!origin_ok("https://evil.example", &t));
        assert!(!origin_ok("https://acct.snowflakecomputing.com:8443", &t));
        assert!(!origin_ok("https://u@acct.snowflakecomputing.com", &t));
        assert!(!origin_ok("https://acct.snowflakecomputing.com/x", &t));
        assert!(!origin_ok("https://acct.snowflakecomputing.com/?q", &t));
        assert!(!origin_ok("::", &t));
    }

    #[test]
    fn sso_urls_must_be_http_urls() {
        assert!(is_valid_url("https://idp.example/sso?x=1"));
        assert!(is_valid_url("http://localhost:1/"));
        assert!(!is_valid_url("javascript:alert(1)"));
        assert!(!is_valid_url("https://idp.example/a b"));
        assert!(!is_valid_url(""));
    }
}
