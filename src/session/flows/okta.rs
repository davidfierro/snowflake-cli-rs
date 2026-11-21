//! Native Okta (ADR 0005, Decision 4; `C/auth/okta.py`): the authenticator is the
//! `https://<org>.okta.com` URL. Both IdP URLs Snowflake names must share its scheme, host and
//! port, and the SAML form must post back to Snowflake's own URL: the checks that keep a
//! phishing IdP from receiving the password or a SAML response from going elsewhere.

use super::{
    FlowContext, IDP_CONNECTION_ERROR, LoginFlow, authenticator_request, idp_agent, idp_url,
    same_prefix,
};
use crate::codec::form_encode_plus;
use crate::error::{Error, ErrorKind, Result};
use crate::secret::Secret;
use crate::session::connect_error;
use crate::session::login::{LoginFields, NOT_ESTABLISHED};

/// The connector's `ER_INCORRECT_DESTINATION`.
const INCORRECT_DESTINATION: u32 = 250007;

pub(in crate::session) struct Okta;

impl LoginFlow for Okta {
    fn prepare(&mut self, ctx: &mut FlowContext<'_>) -> Result<LoginFields> {
        let authenticator = ctx.conn.authenticator.clone().unwrap_or_default();
        let user = ctx.conn.user.clone().unwrap_or_default();
        // Step 1: Snowflake names the IdP's token and SSO URLs.
        let data = authenticator_request(ctx, &authenticator, &[])?;
        let token_url = data["tokenUrl"].as_str().unwrap_or_default().to_string();
        let sso_url = data["ssoUrl"].as_str().unwrap_or_default().to_string();
        // Step 2: both must be the IdP the user named.
        if !same_prefix(&authenticator, &token_url) || !same_prefix(&authenticator, &sso_url) {
            return Err(connect_error(
                IDP_CONNECTION_ERROR,
                Some(NOT_ESTABLISHED),
                &format!(
                    "The specified authenticator is not supported: {authenticator}, token_url: {token_url}, sso_url: {sso_url}"
                ),
            ));
        }
        // Step 3: the password buys a one-time token.
        let failed = || {
            connect_error(
                IDP_CONNECTION_ERROR,
                Some(NOT_ESTABLISHED),
                &format!("The authentication failed for {user} by {token_url}."),
            )
        };
        let credentials = Secret::new(
            serde_json::json!({
                "username": user,
                "password": super::password(ctx.conn).unwrap_or_default().expose(),
            })
            .to_string(),
        );
        log::debug!("POST Okta token URL");
        let mut response = idp_agent(ctx, 0)
            .post(&idp_url(ctx, &token_url))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .send(credentials.expose())
            .map_err(|e| failed().with_source(e))?;
        let body = response
            .body_mut()
            .read_to_string()
            .map_err(|e| failed().with_source(e))?;
        let answer: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        let one_time = answer["sessionToken"]
            .as_str()
            .or_else(|| answer["cookieToken"].as_str())
            .filter(|t| !t.is_empty())
            .map(Secret::new)
            .ok_or_else(failed)?;
        // Step 4: the one-time token buys the SAML response (an HTML form).
        let url = format!(
            "{sso_url}?RelayState={}&onetimetoken={}",
            form_encode_plus("/some/deep/link"),
            form_encode_plus(one_time.expose())
        );
        log::debug!("GET Okta SSO URL");
        let html = idp_agent(ctx, 5)
            .get(&idp_url(ctx, &url))
            .header("Accept", "*/*")
            .call()
            .and_then(|mut r| r.body_mut().read_to_string())
            // No source: a transport error could quote the URL, which carries the one-time token.
            .map_err(|_| {
                Error::new(
                    ErrorKind::Connection,
                    "Failed to get the SAML response from the identity provider.",
                )
            })?;
        // Step 5: the form must post back to this Snowflake.
        let post_back = post_back_url(&html);
        let expected = format!(
            "{}://{}:{}",
            ctx.target.protocol, ctx.target.host, ctx.target.port
        );
        if !same_prefix(&post_back, &expected) {
            return Err(connect_error(
                INCORRECT_DESTINATION,
                Some(NOT_ESTABLISHED),
                &format!(
                    "The specified authenticator and destination URL in the SAML assertion do not match: expected: {expected}, post back: {post_back}"
                ),
            ));
        }
        Ok(LoginFields::default().with("RAW_SAML_RESPONSE", html.as_str()))
    }
}

/// The `action` of the first `<form`, HTML entities decoded (the connector's
/// `_get_post_back_url_from_html`).
fn post_back_url(html: &str) -> String {
    let start = html.find("<form").unwrap_or(0);
    let Some(action) = html[start..].find("action=\"") else {
        return String::new();
    };
    let rest = &html[start + action + 8..];
    let end = rest.find('"').unwrap_or(rest.len());
    unescape(&rest[..end])
}

/// The entities a SAML form action uses.
fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let Some(end) = rest.find(';').filter(|&e| e <= 10) else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let entity = &rest[1..end];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            e if e.starts_with("#x") || e.starts_with("#X") => u32::from_str_radix(&e[2..], 16)
                .ok()
                .and_then(char::from_u32),
            e if e.starts_with('#') => e[1..].parse().ok().and_then(char::from_u32),
            _ => None,
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_post_back_url_is_the_first_form_action() {
        let html = r#"<html><a action="x"><form method="post" action="https&#x3a;&#x2f;&#x2f;acct.snowflakecomputing.com&#x2f;fed&#x2f;login?a=1&amp;b=2"><form action="https://other">"#;
        assert_eq!(
            post_back_url(html),
            "https://acct.snowflakecomputing.com/fed/login?a=1&b=2"
        );
        assert_eq!(post_back_url("<p>no form</p>"), "");
        assert_eq!(
            unescape("a &lt;b&gt; &quot;c&apos; &#65; & &bogus; &"),
            "a <b> \"c' A & &bogus; &"
        );
    }
}
