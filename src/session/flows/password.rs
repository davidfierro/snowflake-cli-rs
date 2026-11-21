//! `SNOWFLAKE` (password, with the passcode or Duo push `login::body` and `Session::login`
//! handle) and `USERNAME_PASSWORD_MFA` (password plus a cached MFA token), ADR 0005 Decision 4.

use super::{FlowContext, LoginFlow, Retry};
use crate::error::Result;
use crate::session::cache::{TokenKey, TokenType};
use crate::session::login::{LoginData, LoginFields};

/// `SNOWFLAKE`: the connector sends no `AUTHENTICATOR` for it.
pub(in crate::session) struct Password;

impl LoginFlow for Password {
    fn prepare(&mut self, ctx: &mut FlowContext<'_>) -> Result<LoginFields> {
        Ok(LoginFields::default().with("PASSWORD", super::password(ctx.conn).unwrap_or_default()))
    }
}

/// `USERNAME_PASSWORD_MFA`. `snow` always asks for the MFA token (`client_request_mfa_token`),
/// so it is read from and written to the cache whatever `client_store_temporary_credential` is.
pub(in crate::session) struct UsernamePasswordMfa;

fn mfa_key(ctx: &FlowContext<'_>) -> TokenKey {
    TokenKey::sign_in(
        ctx.conn.user.as_deref().unwrap_or_default(),
        &ctx.target.host,
        TokenType::MfaToken,
    )
}

impl LoginFlow for UsernamePasswordMfa {
    fn prepare(&mut self, ctx: &mut FlowContext<'_>) -> Result<LoginFields> {
        let mut fields = LoginFields {
            session_parameters: vec![("CLIENT_REQUEST_MFA_TOKEN", true.into())],
            ..LoginFields::default()
        }
        .with("PASSWORD", super::password(ctx.conn).unwrap_or_default());
        if let Some(token) = ctx.io.cache.retrieve(&mfa_key(ctx)) {
            log::debug!("Using the cached MFA token");
            fields = fields.with("TOKEN", token);
        }
        Ok(fields)
    }

    /// A rejected sign-in drops the cached MFA token, as the connector.
    fn on_failure(&mut self, _code: &str, ctx: &mut FlowContext<'_>) -> Result<Retry> {
        ctx.io.cache.remove(&mfa_key(ctx));
        Ok(Retry::Fail)
    }

    fn on_success(&mut self, data: &LoginData, ctx: &mut FlowContext<'_>) -> Result<()> {
        if let Some(token) = &data.mfa_token {
            ctx.io.cache.store(&mfa_key(ctx), token);
        }
        Ok(())
    }
}
