//! Key-pair JWT authentication (ADR 0001, Decision 4).

use super::{AuthHeader, Authenticator};
use crate::connection::ConnectionConfig;
use crate::error::{Error, ErrorKind, Result};
use crate::secret::Secret;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use pkcs8::{DecodePrivateKey, EncodePublicKey};
use rsa::PrivateKey as RsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Lifetime of a JWT in seconds: Snowflake rejects tokens valid for more than one hour.
const JWT_LIFETIME_SECS: u64 = 3540;
/// A cached JWT is re-signed once fewer than this many seconds of its lifetime are left.
const JWT_REFRESH_MARGIN_SECS: u64 = 60;
const TOKEN_TYPE: &str = "KEYPAIR_JWT";
const PLAIN_PEM: &str = "-----BEGIN PRIVATE KEY-----";
const ENCRYPTED_PEM: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----";

const NOT_PKCS8: &str = "Private key provided is not in PKCS#8 format. Please use correct format.";
const NEEDS_PASSPHRASE: &str =
    "The private key is encrypted. Set PRIVATE_KEY_PASSPHRASE to its passphrase.";
const WRONG_PASSPHRASE: &str =
    "Failed to decrypt the private key: wrong passphrase or unsupported encryption";

/// Signs an RS256 JWT with the connection's private key and reuses it until it is about to expire.
pub struct KeyPairAuthenticator {
    signing_key: SigningKey<Sha256>,
    /// `<ACCOUNT>.<USER>`, the `sub` claim.
    qualified_user: String,
    /// `SHA256:<base64>` of the public key.
    fingerprint: String,
    now: fn() -> SystemTime,
    /// The last signed JWT and its `exp` (seconds since the epoch).
    cached: Mutex<Option<(Secret, u64)>>,
}

impl fmt::Debug for KeyPairAuthenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPairAuthenticator")
            .field("qualified_user", &self.qualified_user)
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

impl KeyPairAuthenticator {
    /// Fails (Client) unless account and user are set, and exactly
    /// one of private_key_file / private_key_raw yields a PKCS#8 key (Decision 4).
    pub fn from_connection(conn: &ConnectionConfig) -> Result<Self> {
        let account = non_empty(conn.account.as_deref())
            .ok_or_else(|| client("The connection has no account. Set `account`."))?;
        let user = non_empty(conn.user.as_deref())
            .ok_or_else(|| client("The connection has no user. Set `user`."))?;
        let pem = read_pem(conn)?;
        let key = decode_key(&pem, conn.private_key_passphrase.as_ref())?;
        let fingerprint = fingerprint(&key)?;
        Ok(Self {
            signing_key: SigningKey::new(key),
            qualified_user: format!("{}.{}", account_for_jwt(account), user.to_uppercase()),
            fingerprint,
            now: SystemTime::now,
            cached: Mutex::new(None),
        })
    }

    /// Test seam: fixed clock for deterministic JWTs.
    pub fn with_clock(mut self, now: fn() -> SystemTime) -> Self {
        self.now = now;
        self
    }

    /// "SHA256:<base64>" of the public key's DER SubjectPublicKeyInfo.
    pub fn public_key_fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The cached JWT, re-signed when fewer than `JWT_REFRESH_MARGIN_SECS` of it are left.
    fn jwt(&self) -> Result<Secret> {
        let now = (self.now)()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| client("The system clock is before 1970."))?
            .as_secs();
        let mut cached = self.cached.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((token, exp)) = cached.as_ref()
            && exp.saturating_sub(now) >= JWT_REFRESH_MARGIN_SECS
        {
            return Ok(token.clone());
        }
        let token = self.sign(now)?;
        *cached = Some((token.clone(), now + JWT_LIFETIME_SECS));
        Ok(token)
    }

    fn sign(&self, iat: u64) -> Result<Secret> {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = serde_json::json!({
            "iss": format!("{}.{}", self.qualified_user, self.fingerprint),
            "sub": self.qualified_user,
            "iat": iat,
            "exp": iat + JWT_LIFETIME_SECS,
        });
        let claims = URL_SAFE_NO_PAD.encode(claims.to_string());
        let signing_input = format!("{header}.{claims}");
        let signature = self
            .signing_key
            .try_sign(signing_input.as_bytes())
            .map_err(|e| client("Failed to sign the JWT.").with_source(e))?;
        let signature = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        Ok(Secret::new(format!("{signing_input}.{signature}")))
    }
}

impl Authenticator for KeyPairAuthenticator {
    fn authorization(&self) -> Result<AuthHeader> {
        Ok(AuthHeader {
            token: self.jwt()?,
            token_type: TOKEN_TYPE,
        })
    }
}

/// Whether `err` is the "encrypted key, no passphrase" failure, so a command can ask for one.
pub fn is_missing_passphrase(err: &Error) -> bool {
    err.kind() == ErrorKind::MissingPassphrase
}

fn client(message: &str) -> Error {
    Error::new(ErrorKind::Client, message)
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.filter(|v| !v.is_empty())
}

/// `<ACCOUNT>` of the JWT claims, as `snowflake-connector-python`'s `auth/keypair.py`: the account
/// up to the first `.` (up to the first `-` if it contains `.global`), upper-cased.
fn account_for_jwt(account: &str) -> String {
    let separator = if account.contains(".global") {
        '-'
    } else {
        '.'
    };
    let base = account.split(separator).next().unwrap_or(account);
    base.to_uppercase()
}

/// The PEM text: `private_key_file` if set, else `private_key_raw`.
fn read_pem(conn: &ConnectionConfig) -> Result<Secret> {
    if let Some(path) = &conn.private_key_file {
        return std::fs::read_to_string(path).map(Secret::new).map_err(|e| {
            Error::new(
                ErrorKind::Client,
                format!(
                    "Could not read the private key file {}: {}",
                    path.display(),
                    e.kind()
                ),
            )
        });
    }
    conn.private_key_raw.clone().ok_or_else(|| {
        client("Key-pair authentication needs `private_key_file` or `private_key_raw`.")
    })
}

fn decode_key(pem: &Secret, passphrase: Option<&Secret>) -> Result<RsaPrivateKey> {
    let text = pem.expose().trim();
    if text.starts_with(ENCRYPTED_PEM) {
        let passphrase = passphrase
            .map(Secret::expose)
            .filter(|p| !p.is_empty())
            .ok_or_else(|| Error::new(ErrorKind::MissingPassphrase, NEEDS_PASSPHRASE))?;
        // The error says nothing about the key or passphrase: it is an enum of failure kinds.
        RsaPrivateKey::from_pkcs8_encrypted_pem(text, passphrase)
            .map_err(|e| client(WRONG_PASSPHRASE).with_source(e))
    } else if text.starts_with(PLAIN_PEM) {
        RsaPrivateKey::from_pkcs8_pem(text).map_err(|e| {
            client("Failed to load the private key: it is not a valid RSA PKCS#8 key.")
                .with_source(e)
        })
    } else {
        Err(client(NOT_PKCS8))
    }
}

fn fingerprint(key: &RsaPrivateKey) -> Result<String> {
    let der = key
        .to_public_key()
        .to_public_key_der()
        .map_err(|e| client("Failed to encode the public key.").with_source(e))?;
    Ok(format!(
        "SHA256:{}",
        STANDARD.encode(Sha256::digest(der.as_bytes()))
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    use std::path::PathBuf;
    use std::time::Duration;

    const PASSPHRASE: &str = "test-passphrase";

    fn key_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/keys")
            .join(name)
    }

    fn expected_fingerprint() -> String {
        let fp = std::fs::read_to_string(key_path("fingerprint.txt")).unwrap();
        format!("SHA256:{}", fp.trim())
    }

    fn conn(key_file: &str) -> ConnectionConfig {
        ConnectionConfig {
            account: Some("myorg-acct1.eu-west-1".into()),
            user: Some("jdoe".into()),
            authenticator: Some("snowflake_jwt".into()),
            private_key_file: Some(key_path(key_file)),
            ..Default::default()
        }
    }

    fn fixed_now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    fn err_of(conn: &ConnectionConfig) -> Error {
        KeyPairAuthenticator::from_connection(conn).unwrap_err()
    }

    fn decode_segment(segment: &str) -> serde_json::Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segment).unwrap()).unwrap()
    }

    #[test]
    fn jwt_has_snowflake_claims_and_a_valid_signature() {
        let auth = KeyPairAuthenticator::from_connection(&conn("unencrypted.p8"))
            .unwrap()
            .with_clock(fixed_now);
        let header = auth.authorization().unwrap();
        assert_eq!(header.token_type, "KEYPAIR_JWT");
        let jwt = header.token.expose().to_string();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(
            decode_segment(parts[0]),
            serde_json::json!({"alg": "RS256", "typ": "JWT"})
        );
        let fp = expected_fingerprint();
        assert_eq!(
            decode_segment(parts[1]),
            serde_json::json!({
                "iss": format!("MYORG-ACCT1.JDOE.{fp}"),
                "sub": "MYORG-ACCT1.JDOE",
                "iat": 1_700_000_000u64,
                "exp": 1_700_003_540u64,
            })
        );

        let pem = std::fs::read_to_string(key_path("unencrypted.p8")).unwrap();
        let public = RsaPrivateKey::from_pkcs8_pem(&pem).unwrap().to_public_key();
        let signature =
            Signature::try_from(URL_SAFE_NO_PAD.decode(parts[2]).unwrap().as_slice()).unwrap();
        VerifyingKey::<Sha256>::new(public)
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .unwrap();
    }

    #[test]
    fn fingerprint_matches_openssl() {
        let auth = KeyPairAuthenticator::from_connection(&conn("unencrypted.p8")).unwrap();
        assert_eq!(auth.public_key_fingerprint(), expected_fingerprint());
    }

    #[test]
    fn first_call_signs_with_the_current_time() {
        let auth = KeyPairAuthenticator::from_connection(&conn("unencrypted.p8")).unwrap();
        let jwt = auth.authorization().unwrap().token;
        let claims = decode_segment(jwt.expose().split('.').nth(1).unwrap());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let iat = claims["iat"].as_u64().unwrap();
        assert!(iat <= now && now - iat < 60);
    }

    static FAKE_NOW: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn fake_now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(FAKE_NOW.load(std::sync::atomic::Ordering::SeqCst))
    }

    fn set_now(secs: u64) {
        FAKE_NOW.store(secs, std::sync::atomic::Ordering::SeqCst);
    }

    #[test]
    fn jwt_is_signed_once_within_its_lifetime_and_again_near_expiry() {
        let auth = KeyPairAuthenticator::from_connection(&conn("unencrypted.p8"))
            .unwrap()
            .with_clock(fake_now);
        let token = |auth: &KeyPairAuthenticator| auth.authorization().unwrap().token;
        set_now(1_000);
        let first = token(&auth);
        // N requests until 60 s before expiry reuse the same JWT (no new signature).
        for t in [1_000, 1_500, 2_000, 1_000 + JWT_LIFETIME_SECS - 60] {
            set_now(t);
            assert!(token(&auth) == first, "re-signed at t={t}");
        }
        // With less than 60 s left a new JWT is signed, with a fresh `iat`.
        set_now(1_000 + JWT_LIFETIME_SECS - 59);
        let second = token(&auth);
        assert!(second != first);
        let claims = decode_segment(second.expose().split('.').nth(1).unwrap());
        assert_eq!(
            claims["iat"].as_u64().unwrap(),
            1_000 + JWT_LIFETIME_SECS - 59
        );
        // The new one is cached in turn.
        assert!(token(&auth) == second);
    }

    #[test]
    fn account_rules_follow_the_python_connector() {
        assert_eq!(account_for_jwt("xy12345.us-east-1"), "XY12345");
        assert_eq!(account_for_jwt("myorg-acct"), "MYORG-ACCT");
        assert_eq!(account_for_jwt("myorg-acct.global"), "MYORG");
    }

    #[test]
    fn encrypted_keys_decrypt_with_the_passphrase() {
        for file in ["aes256.p8", "des3.p8"] {
            let mut c = conn(file);
            c.private_key_passphrase = Some(Secret::new(PASSPHRASE));
            let auth = KeyPairAuthenticator::from_connection(&c).unwrap();
            assert_eq!(
                auth.public_key_fingerprint(),
                expected_fingerprint(),
                "{file}"
            );
        }
    }

    #[test]
    fn inline_key_is_used_when_no_file_is_set() {
        let mut c = conn("unencrypted.p8");
        c.private_key_file = None;
        c.private_key_raw = Some(Secret::new(
            std::fs::read_to_string(key_path("unencrypted.p8")).unwrap(),
        ));
        let auth = KeyPairAuthenticator::from_connection(&c).unwrap();
        assert_eq!(auth.public_key_fingerprint(), expected_fingerprint());
        assert!(format!("{auth:?}").contains("MYORG-ACCT1.JDOE"));
    }

    #[test]
    fn passphrase_is_ignored_for_an_unencrypted_key() {
        let mut c = conn("unencrypted.p8");
        c.private_key_passphrase = Some(Secret::new("whatever"));
        assert!(KeyPairAuthenticator::from_connection(&c).is_ok());
    }

    #[test]
    fn the_authenticator_setting_is_not_its_concern() {
        // `auth::Method::of` decides; a key signs whatever the authenticator says.
        for authenticator in [None, Some("externalbrowser"), Some("OAUTH")] {
            let mut c = conn("unencrypted.p8");
            c.authenticator = authenticator.map(String::from);
            assert!(KeyPairAuthenticator::from_connection(&c).is_ok());
        }
    }

    #[test]
    fn account_and_user_are_required() {
        let mut c = conn("unencrypted.p8");
        c.account = Some(String::new());
        assert!(err_of(&c).message().contains("account"));
        let mut c = conn("unencrypted.p8");
        c.user = None;
        assert!(err_of(&c).message().contains("user"));
    }

    #[test]
    fn a_key_source_is_required() {
        let mut c = conn("unencrypted.p8");
        c.private_key_file = None;
        let err = err_of(&c);
        assert_eq!(err.kind(), ErrorKind::Client);
        assert!(err.message().contains("private_key_file"));
    }

    #[test]
    fn missing_key_file_names_the_path() {
        let err = err_of(&conn("does-not-exist.p8"));
        assert_eq!(err.kind(), ErrorKind::Client);
        assert!(err.message().contains("does-not-exist.p8"));
    }

    #[test]
    fn pkcs1_and_garbage_are_not_pkcs8() {
        let err = err_of(&conn("pkcs1.pem"));
        assert_eq!(err.message(), NOT_PKCS8);
        let mut c = conn("unencrypted.p8");
        c.private_key_file = None;
        c.private_key_raw = Some(Secret::new("not a key"));
        assert_eq!(err_of(&c).message(), NOT_PKCS8);
    }

    #[test]
    fn corrupt_pkcs8_body_is_a_client_error() {
        let mut c = conn("unencrypted.p8");
        c.private_key_file = None;
        c.private_key_raw = Some(Secret::new(
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        ));
        let err = err_of(&c);
        assert_eq!(err.kind(), ErrorKind::Client);
        assert!(err.message().contains("not a valid RSA PKCS#8 key"));
    }

    #[test]
    fn encrypted_key_needs_a_non_empty_passphrase() {
        let mut c = conn("aes256.p8");
        assert_eq!(err_of(&c).message(), NEEDS_PASSPHRASE);
        assert!(is_missing_passphrase(&err_of(&c)));
        c.private_key_passphrase = Some(Secret::new(""));
        assert_eq!(err_of(&c).message(), NEEDS_PASSPHRASE);
        assert!(is_missing_passphrase(&err_of(&c)));
    }

    #[test]
    fn missing_passphrase_is_a_typed_error_not_a_message_match() {
        // Same text, other kind: not a missing passphrase.
        assert!(!is_missing_passphrase(&Error::new(
            ErrorKind::Client,
            NEEDS_PASSPHRASE
        )));
        // A wrong passphrase and an unencrypted key are other failures.
        let mut c = conn("des3.p8");
        c.private_key_passphrase = Some(Secret::new("nope"));
        assert!(!is_missing_passphrase(&err_of(&c)));
        assert_eq!(err_of(&c).exit_code(), 1);
    }

    #[test]
    fn wrong_passphrase_is_reported_without_secrets() {
        let mut c = conn("des3.p8");
        c.private_key_passphrase = Some(Secret::new("MARKER-wrong-passphrase"));
        let err = err_of(&c);
        assert_eq!(err.message(), WRONG_PASSPHRASE);
        let mut chain = format!("{err:?}");
        let mut source = std::error::Error::source(&err);
        while let Some(s) = source {
            chain.push_str(&s.to_string());
            source = s.source();
        }
        assert!(!chain.contains("MARKER"));
        assert!(!chain.contains("BEGIN"));
    }

    #[test]
    fn clock_before_epoch_is_an_error() {
        fn before_epoch() -> SystemTime {
            UNIX_EPOCH - Duration::from_secs(1)
        }
        let auth = KeyPairAuthenticator::from_connection(&conn("unencrypted.p8"))
            .unwrap()
            .with_clock(before_epoch);
        assert_eq!(auth.authorization().unwrap_err().kind(), ErrorKind::Client);
    }
}
