//! Authorization of SQL API requests (ADR 0001, Decision 4).
//!
//! The SQL API takes a key-pair JWT, an OAuth access token, a programmatic access token or a
//! workload identity attestation. [`Method::of`] picks one from the connection as the Python
//! connector picks its auth plugin; the sign-ins that need the connector's login protocol run
//! on a session instead (ADR 0005, Decisions 1 and 4).

pub mod keypair;
pub mod token;
pub mod wif;

pub use keypair::{KeyPairAuthenticator, is_missing_passphrase};
pub use token::TokenAuthenticator;

use crate::connection::ConnectionConfig;
use crate::error::{Error, ErrorKind, Result};

/// Something that can authorize one HTTP request to the SQL API.
pub trait Authenticator: Send + Sync {
    fn authorization(&self) -> Result<AuthHeader>;
}

/// How a run signs in: a credential the SQL API takes, or a connector flow that needs a session
/// (ADR 0005, Decision 1).
pub enum Credential {
    Bearer(Box<dyn Authenticator>),
    /// The connection's authenticator names a connector flow ([`Method::needs_session`]).
    Connector,
}

/// Values of the two authorization headers of one request.
#[derive(Debug, Clone)]
pub struct AuthHeader {
    /// Value of `Authorization: Bearer …`.
    pub token: crate::secret::Secret,
    /// Value of `X-Snowflake-Authorization-Token-Type`, e.g. `KEYPAIR_JWT`.
    pub token_type: &'static str,
}

/// How a connection signs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    KeyPair,
    OAuth,
    ProgrammaticAccessToken,
    WorkloadIdentity,
    /// `SNOWFLAKE`: password, with an optional MFA passcode or Duo push.
    Password,
    /// `USERNAME_PASSWORD_MFA`: password plus a cached MFA token.
    UsernamePasswordMfa,
    /// `EXTERNALBROWSER`: SAML through the browser, or a cached ID token.
    ExternalBrowser,
    /// Native Okta: the authenticator is the `https://<org>.okta.com` URL.
    Okta,
    OAuthAuthorizationCode,
    OAuthClientCredentials,
}

impl Method {
    /// Whether the SQL API cannot take this sign-in, so the run needs a session (ADR 0005,
    /// Decision 1).
    pub fn needs_session(self) -> bool {
        matches!(
            self,
            Method::Password
                | Method::UsernamePasswordMfa
                | Method::ExternalBrowser
                | Method::Okta
                | Method::OAuthAuthorizationCode
                | Method::OAuthClientCredentials
        )
    }
}

/// The connector's error code for an unknown authenticator (`ER_INVALID_VALUE`).
const UNKNOWN_AUTHENTICATOR: u32 = 251007;

/// A connector authenticator this CLI does not offer (`snow` has no option for its external
/// session id).
const NOT_SUPPORTED: &str = "PAT_WITH_EXTERNAL_SESSION";

impl Method {
    /// The connector's choice: the authenticator must be known; a private key, when the
    /// connection has one, makes it key-pair whatever the authenticator says; a workload
    /// identity provider needs `WORKLOAD_IDENTITY`. An unset authenticator is `SNOWFLAKE`
    /// (password).
    pub fn of(conn: &ConnectionConfig) -> Result<Method> {
        let given = conn
            .authenticator
            .as_deref()
            .filter(|a| !a.is_empty())
            .unwrap_or("snowflake");
        let upper = given.to_ascii_uppercase();
        let named = match upper.as_str() {
            "SNOWFLAKE_JWT" => Some(Method::KeyPair),
            "OAUTH" => Some(Method::OAuth),
            "PROGRAMMATIC_ACCESS_TOKEN" => Some(Method::ProgrammaticAccessToken),
            "WORKLOAD_IDENTITY" => Some(Method::WorkloadIdentity),
            "SNOWFLAKE" => Some(Method::Password),
            "USERNAME_PASSWORD_MFA" => Some(Method::UsernamePasswordMfa),
            "EXTERNALBROWSER" => Some(Method::ExternalBrowser),
            "OAUTH_AUTHORIZATION_CODE" => Some(Method::OAuthAuthorizationCode),
            "OAUTH_CLIENT_CREDENTIALS" => Some(Method::OAuthClientCredentials),
            other if other.starts_with("HTTPS://") => Some(Method::Okta),
            NOT_SUPPORTED => None,
            _ => {
                return Err(wif::connect_error(
                    UNKNOWN_AUTHENTICATOR,
                    &format!("Unknown authenticator: {given}"),
                ));
            }
        };
        let has_key = conn.private_key_file.is_some() || conn.private_key_raw.is_some();
        let method = if has_key {
            Some(Method::KeyPair)
        } else {
            named
        };
        if conn
            .workload_identity_provider
            .as_deref()
            .is_some_and(|p| !p.is_empty())
            && method != Some(Method::WorkloadIdentity)
        {
            return Err(wif::connect_error(
                wif::INVALID_WIF_SETTINGS,
                "workload_identity_provider was set but authenticator was not set to WORKLOAD_IDENTITY",
            ));
        }
        method.ok_or_else(|| {
            Error::new(
                ErrorKind::Client,
                format!("authenticator {given} is not supported yet"),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn conn(authenticator: Option<&str>) -> ConnectionConfig {
        ConnectionConfig {
            authenticator: authenticator.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn the_authenticator_names_the_method() {
        for (name, method) in [
            ("SNOWFLAKE_JWT", Method::KeyPair),
            ("snowflake_jwt", Method::KeyPair),
            ("oauth", Method::OAuth),
            ("OAUTH", Method::OAuth),
            ("programmatic_access_token", Method::ProgrammaticAccessToken),
            ("Workload_Identity", Method::WorkloadIdentity),
        ] {
            assert_eq!(Method::of(&conn(Some(name))).unwrap(), method, "{name}");
        }
    }

    #[test]
    fn a_private_key_means_key_pair_as_in_the_connector() {
        let mut c = conn(Some("OAUTH"));
        c.private_key_file = Some(PathBuf::from("/k.p8"));
        assert_eq!(Method::of(&c).unwrap(), Method::KeyPair);
        let mut c = conn(None);
        c.private_key_raw = Some(crate::secret::Secret::new("pem"));
        assert_eq!(Method::of(&c).unwrap(), Method::KeyPair);
    }

    #[test]
    fn connector_protocol_sign_ins_need_a_session() {
        for (authenticator, method) in [
            (None, Method::Password),
            (Some(""), Method::Password),
            (Some("snowflake"), Method::Password),
            (Some("externalbrowser"), Method::ExternalBrowser),
            (Some("USERNAME_PASSWORD_MFA"), Method::UsernamePasswordMfa),
            (
                Some("oauth_authorization_code"),
                Method::OAuthAuthorizationCode,
            ),
            (
                Some("oauth_client_credentials"),
                Method::OAuthClientCredentials,
            ),
            (Some("https://example.okta.com"), Method::Okta),
        ] {
            let got = Method::of(&conn(authenticator)).unwrap();
            assert_eq!(got, method, "{authenticator:?}");
            assert!(got.needs_session());
        }
        for method in [
            Method::KeyPair,
            Method::OAuth,
            Method::ProgrammaticAccessToken,
            Method::WorkloadIdentity,
        ] {
            assert!(!method.needs_session());
        }
        let err = Method::of(&conn(Some("pat_with_external_session"))).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Client);
        assert_eq!(
            err.message(),
            "authenticator pat_with_external_session is not supported yet"
        );
    }

    #[test]
    fn unknown_authenticators_and_stray_providers_fail_like_the_connector() {
        let err = Method::of(&conn(Some("foo"))).unwrap_err();
        assert_eq!(
            err.message(),
            "Could not connect to Snowflake. Reason: 251007: Unknown authenticator: foo"
        );
        let mut c = conn(Some("OAUTH"));
        c.workload_identity_provider = Some("OIDC".into());
        let err = Method::of(&c).unwrap_err();
        assert_eq!(
            err.message(),
            "Could not connect to Snowflake. Reason: 251017: workload_identity_provider was set but authenticator was not set to WORKLOAD_IDENTITY"
        );
        c.authenticator = Some("WORKLOAD_IDENTITY".into());
        assert_eq!(Method::of(&c).unwrap(), Method::WorkloadIdentity);
    }
}
