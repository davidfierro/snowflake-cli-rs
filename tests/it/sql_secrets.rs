//! Secrets never reach any output or log (ADR 0001, Decision 7): a key and passphrase with
//! recognisable markers go through auth, a failing request and `--debug` error reporting; the
//! captured log and stderr must not contain them, nor the JWT.

use crate::common;

use snowflake_cli_rs::auth::{Authenticator, KeyPairAuthenticator};
use snowflake_cli_rs::connection::ConnectionConfig;
use snowflake_cli_rs::diag::{self, Verbosity};
use snowflake_cli_rs::report::report_error;
use snowflake_cli_rs::secret::Secret;
use snowflake_cli_rs::sql::SqlClient;
use std::io::Write;
use std::sync::{Arc, Mutex};

/// Collects what the real `diag` logger writes.
#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Write for Buffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

const MARKER_PASSPHRASE: &str = "MARKER-PASSPHRASE-7f3a";

/// The DES3 fixture key; PEM has no room for a marker, so the check looks for its base64 lines.
fn encrypted_key() -> String {
    std::fs::read_to_string(common::key_path("des3.p8")).unwrap()
}

/// A one-shot HTTP server (not httpmock, whose own logs would land in the captured log) that
/// answers the first request with 401.
fn reject_with_401() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut chunk = [0u8; 4096];
        // Read headers and the JSON body (it ends with `}`).
        while !request.ends_with(b"}") {
            let n = std::io::Read::read(&mut stream, &mut chunk).unwrap();
            if n == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..n]);
        }
        let body = r#"{"code":"390144","message":"JWT token is invalid."}"#;
        let response = format!(
            "HTTP/1.1 401 Unauthorized\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
    });
    port
}

fn assert_clean(output: &str, key: &str, jwt: Option<&str>) {
    assert!(
        !output.contains(MARKER_PASSPHRASE),
        "passphrase leaked:\n{output}"
    );
    assert!(
        !output.contains("test-passphrase"),
        "passphrase leaked:\n{output}"
    );
    for line in key.lines().filter(|l| !l.starts_with("-----")) {
        assert!(!output.contains(line), "key material leaked:\n{output}");
    }
    if let Some(jwt) = jwt {
        for segment in jwt.split('.') {
            assert!(!output.contains(segment), "JWT leaked:\n{output}");
        }
    }
}

#[test]
fn secrets_never_reach_logs_or_errors() {
    let _log = crate::common::logger_guard();
    // `--debug`: the most verbose level the CLI offers (Decision 7).
    let buffer = Buffer::default();
    diag::init_with_sink(Verbosity::Debug, Box::new(buffer.clone()));
    let key = encrypted_key();

    // Wrong passphrase: the error and its debug chain hold neither the key nor the passphrase.
    let port = reject_with_401();
    let mut conn = ConnectionConfig {
        private_key_file: None,
        private_key_raw: Some(Secret::new(key.clone())),
        private_key_passphrase: Some(Secret::new(MARKER_PASSPHRASE)),
        host: Some("127.0.0.1".into()),
        port: Some(port),
        protocol: Some("http".into()),
        account: Some("testacct".into()),
        user: Some("tester".into()),
        authenticator: Some("SNOWFLAKE_JWT".into()),
        ..Default::default()
    };
    let err = KeyPairAuthenticator::from_connection(&conn).unwrap_err();
    let mut stderr = Vec::new();
    report_error(&err, true, &mut stderr);
    assert_clean(&String::from_utf8(stderr).unwrap(), &key, None);
    assert!(!format!("{conn:?}").contains(MARKER_PASSPHRASE));

    // Right passphrase, failing request: logs, the error panel and its chain stay clean.
    conn.private_key_passphrase = Some(Secret::new("test-passphrase"));
    let auth = KeyPairAuthenticator::from_connection(&conn).unwrap();
    let jwt = auth.authorization().unwrap().token.expose().to_string();
    assert_eq!(
        format!("{:?}", auth.authorization().unwrap().token),
        "Secret(****)"
    );
    let client = SqlClient::new(&conn, Box::new(auth), common::fast_options()).unwrap();
    let err = client.execute("SELECT 'MARKER-STATEMENT'").unwrap_err();
    let mut stderr = Vec::new();
    report_error(&err, true, &mut stderr);
    let stderr = String::from_utf8(stderr).unwrap();
    assert!(stderr.contains("JWT token is invalid."));

    // The logger is process-global: the mock servers of concurrent tests in this binary log their
    // own (test-side) requests into the sink too. Drop `httpmock` records, which are not output
    // of the CLI; continuation lines (no `LEVEL [target]` prefix) follow their record.
    let mut from_mock = false;
    let log: String = String::from_utf8(buffer.0.lock().unwrap().clone())
        .unwrap()
        .lines()
        .filter(|l| {
            if l.starts_with("DEBUG [") || l.starts_with("INFO [") || l.starts_with("WARN [") {
                from_mock = l.contains(" [httpmock::");
            }
            !from_mock
        })
        .map(|l| format!("{l}\n"))
        .collect();
    assert!(log.contains("POST /api/v2/statements"), "{log}");
    let ours: String = log
        .lines()
        .filter(|l| l.contains("[snowflake_cli_rs::"))
        .collect();
    assert!(!ours.contains("requestId"), "{ours}");
    assert!(
        !log.contains("MARKER-STATEMENT"),
        "statement text logged:\n{log}"
    );
    for output in [&stderr, &log] {
        assert_clean(output, &key, Some(&jwt));
    }
}
