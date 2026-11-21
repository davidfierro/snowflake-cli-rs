//! Bearer tokens the SQL API takes as they are: OAuth access tokens, programmatic access tokens
//! (PAT) and workload identity attestations.

use super::{AuthHeader, Authenticator};
use crate::connection::ConnectionConfig;
use crate::error::{Error, ErrorKind, Result};
use crate::secret::Secret;
use std::path::Path;

/// `X-Snowflake-Authorization-Token-Type` of an OAuth access token.
pub const OAUTH: &str = "OAUTH";
/// … of a programmatic access token.
pub const PROGRAMMATIC_ACCESS_TOKEN: &str = "PROGRAMMATIC_ACCESS_TOKEN";
/// … of `WIF.<provider>.<attestation>`.
pub const WORKLOAD_IDENTITY_FEDERATION: &str = "WORKLOAD_IDENTITY_FEDERATION";

/// A token larger than this is not a token: refuse to read it into memory.
const MAX_TOKEN_FILE_BYTES: u64 = 1 << 20;

/// Sends the same token with every request.
#[derive(Debug, Clone)]
pub struct TokenAuthenticator {
    token: Secret,
    token_type: &'static str,
}

impl TokenAuthenticator {
    /// Fails (Client) when the token cannot travel in an HTTP header.
    pub fn new(token: Secret, token_type: &'static str) -> Result<Self> {
        if token.expose().is_empty() {
            return Err(Error::new(ErrorKind::Client, "The token is empty."));
        }
        if !token
            .expose()
            .bytes()
            .all(|b| b == b'\t' || (b' '..=b'~').contains(&b))
        {
            // Never the value: only that it is unusable.
            return Err(Error::new(
                ErrorKind::Client,
                "The token contains characters that are not allowed in an HTTP header.",
            ));
        }
        Ok(Self { token, token_type })
    }

    /// `OAUTH` or `PROGRAMMATIC_ACCESS_TOKEN` with the connection's token (Client error when it
    /// has none).
    pub fn from_connection(conn: &ConnectionConfig, token_type: &'static str) -> Result<Self> {
        let token = connection_token(conn)?.ok_or_else(|| {
            Error::new(
                ErrorKind::Client,
                "The connection has no token. Set `token` or `token_file_path`.",
            )
        })?;
        Self::new(token, token_type)
    }
}

impl Authenticator for TokenAuthenticator {
    fn authorization(&self) -> Result<AuthHeader> {
        Ok(AuthHeader {
            token: self.token.clone(),
            token_type: self.token_type,
        })
    }
}

/// The connector's rule: the content of `token_file_path` when set, else `token`. Surrounding
/// whitespace (a final newline) is dropped, since an HTTP header cannot carry it.
pub fn connection_token(conn: &ConnectionConfig) -> Result<Option<Secret>> {
    let token = match &conn.token_file_path {
        Some(path) => Some(read_token_file(path)?),
        None => conn.token.clone(),
    };
    Ok(token
        .map(|t| trimmed(&t))
        .filter(|t| !t.expose().is_empty()))
}

/// The token in `path`, as it is (no trimming).
pub fn read_token_file(path: &Path) -> Result<Secret> {
    let unreadable = |e: std::io::Error| {
        Error::new(
            ErrorKind::Client,
            format!("Couldn't read the token file {}.", path.display()),
        )
        .with_source(e)
    };
    let meta = std::fs::metadata(path).map_err(unreadable)?;
    if meta.len() > MAX_TOKEN_FILE_BYTES {
        return Err(Error::new(
            ErrorKind::Client,
            format!(
                "The token file {} is larger than {MAX_TOKEN_FILE_BYTES} bytes.",
                path.display()
            ),
        ));
    }
    let bytes = std::fs::read(path).map_err(unreadable)?;
    let text = String::from_utf8(bytes).map_err(|_| {
        Error::new(
            ErrorKind::Client,
            format!("The token file {} is not UTF-8 text.", path.display()),
        )
    })?;
    Ok(Secret::new(text))
}

pub(crate) fn trimmed(token: &Secret) -> Secret {
    Secret::new(token.expose().trim())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn conn(token: Option<&str>, file: Option<&Path>) -> ConnectionConfig {
        ConnectionConfig {
            token: token.map(Secret::new),
            token_file_path: file.map(Path::to_path_buf),
            ..Default::default()
        }
    }

    #[test]
    fn oauth_and_pat_send_the_token_with_their_type() {
        for token_type in [OAUTH, PROGRAMMATIC_ACCESS_TOKEN] {
            let auth =
                TokenAuthenticator::from_connection(&conn(Some(" tok-1 \n"), None), token_type)
                    .unwrap();
            let header = auth.authorization().unwrap();
            assert_eq!(header.token.expose(), "tok-1");
            assert_eq!(header.token_type, token_type);
        }
    }

    #[test]
    fn the_token_file_wins_over_the_token() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("t");
        std::fs::write(&path, "from-file\n").unwrap();
        let token = connection_token(&conn(Some("inline"), Some(&path)))
            .unwrap()
            .unwrap();
        assert_eq!(token.expose(), "from-file");
    }

    #[test]
    fn missing_empty_or_unusable_tokens_fail_without_the_value() {
        let err = TokenAuthenticator::from_connection(&conn(None, None), OAUTH).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Client);
        assert!(err.message().contains("no token"));
        let err = TokenAuthenticator::from_connection(&conn(Some("  "), None), OAUTH).unwrap_err();
        assert!(err.message().contains("no token"));
        let err = TokenAuthenticator::new(Secret::new(""), OAUTH).unwrap_err();
        assert!(err.message().contains("empty"));
        let err = TokenAuthenticator::new(Secret::new("SECRET\nX"), OAUTH).unwrap_err();
        assert!(!err.message().contains("SECRET"));
        let err = TokenAuthenticator::new(Secret::new("SECRET\u{e9}"), OAUTH).unwrap_err();
        assert!(err.message().contains("not allowed"));
    }

    #[test]
    fn token_file_errors_name_the_path_only() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("missing");
        let err = connection_token(&conn(None, Some(&missing))).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Client);
        assert!(err.message().contains("missing"));

        let big = dir.path().join("big");
        std::fs::write(&big, vec![b'a'; (MAX_TOKEN_FILE_BYTES + 1) as usize]).unwrap();
        let err = connection_token(&conn(None, Some(&big))).unwrap_err();
        assert!(err.message().contains("larger than"));

        let binary = dir.path().join("bin");
        std::fs::write(&binary, [0xff, 0xfe, b'S']).unwrap();
        let err = connection_token(&conn(None, Some(&binary))).unwrap_err();
        assert!(err.message().contains("not UTF-8"));
    }
}
