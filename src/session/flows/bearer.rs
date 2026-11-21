//! The bearer credentials the SQL API also takes, on a session: `SNOWFLAKE_JWT`, `OAUTH`,
//! `PROGRAMMATIC_ACCESS_TOKEN` (ADR 0005, Decision 4, last row).

use super::{FlowContext, LoginFlow};
use crate::auth::Authenticator;
use crate::error::{Error, ErrorKind, Result};
use crate::session::login::LoginFields;

pub(in crate::session) struct Bearer<'a> {
    credential: &'a dyn Authenticator,
    authenticator: &'static str,
}

impl<'a> Bearer<'a> {
    pub fn new(credential: &'a dyn Authenticator) -> Self {
        Self {
            credential,
            authenticator: "",
        }
    }
}

impl LoginFlow for Bearer<'_> {
    fn prepare(&mut self, _ctx: &mut FlowContext<'_>) -> Result<LoginFields> {
        let header = self.credential.authorization()?;
        self.authenticator = match header.token_type {
            "KEYPAIR_JWT" => "SNOWFLAKE_JWT",
            crate::auth::token::OAUTH => "OAUTH",
            crate::auth::token::PROGRAMMATIC_ACCESS_TOKEN => "PROGRAMMATIC_ACCESS_TOKEN",
            other => {
                return Err(Error::new(
                    ErrorKind::Client,
                    format!("A Snowflake session does not support the {other} sign-in yet."),
                ));
            }
        };
        Ok(LoginFields::default()
            .with("AUTHENTICATOR", self.authenticator)
            .with("TOKEN", header.token))
    }

    /// `snow`'s hint for a raw OAuth token it cannot renew.
    fn failure_hint(&self, code: &str) -> Option<String> {
        (self.authenticator == "OAUTH" && super::oauth::is_token_rejection(code)).then(|| {
            "Snowflake CLI cannot renew a raw OAuth token supplied by its caller. Refresh it in the application or credential provider that supplied it, then retry. The refresh-token flag does not apply to authenticator=oauth.".to_string()
        })
    }
}
