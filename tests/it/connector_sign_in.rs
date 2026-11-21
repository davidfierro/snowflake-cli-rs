//! Connector-protocol sign-ins end to end (ADR 0005 Decisions 1, 3 and 4): the binary
//! against a mocked Snowflake that checks the `login-request` it receives, for the flows that
//! need no browser (password, MFA passcode, `USERNAME_PASSWORD_MFA` with its file cache,
//! `OAUTH_CLIENT_CREDENTIALS`), plus `--server-session-keep-alive`, the `--password` warning and
//! no secret in any output, `--debug` included. The browser, Okta and authorization-code flows are
//! covered against the same mocked exchanges in `src/session/flow_tests.rs`.

use crate::common;
use assert_cmd::Command;
use httpmock::{HttpMockRequest, Method::POST, Mock, MockServer};
use serde_json::{Value, json};
use snowflake_cli_rs::commands::Prompter;
use snowflake_cli_rs::env::Env;
use tempfile::TempDir;

const LOGIN: &str = "/session/v1/login-request";
const QUERY: &str = "/queries/v1/query-request";
const PASSWORD: &str = "PASSWORD-SECRET-MARKER";
const WARNING: &str =
    "WARNING! Using --password via the CLI is insecure. Use environment variables instead.";

struct Home {
    dir: TempDir,
}

impl Home {
    fn new() -> Self {
        Self {
            dir: TempDir::new().unwrap(),
        }
    }

    /// A `0700` credential cache directory inside the home.
    fn cache_dir(&self) -> std::path::PathBuf {
        let dir = self.dir.path().join("cache");
        std::fs::create_dir(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir
    }
}

fn data(req: &HttpMockRequest) -> Value {
    let body: Value = serde_json::from_str(&req.body_string()).unwrap_or_default();
    body["data"].clone()
}

fn login_ok(token: &str) -> Value {
    json!({"success": true, "data": {
        "token": token, "masterToken": "master", "masterValidityInSeconds": 14400,
        "parameters": [{"name": "TIMEZONE", "value": "UTC"}],
    }})
}

/// `SELECT 1` (and `connection test`'s probe) on the session.
fn select_one(server: &MockServer) -> Mock<'_> {
    server.mock(|when, then| {
        when.method(POST)
            .path(QUERY)
            .header("authorization", "Snowflake Token=\"session-token\"")
            .body_includes("SELECT 1");
        then.status(200).json_body(json!({"success": true, "data": {
            "queryId": "01-q",
            "rowtype": [{"name": "1", "type": "fixed", "precision": 1, "scale": 0, "nullable": false}],
            "rowset": [["1"]],
        }}));
    })
}

fn close(server: &MockServer) -> Mock<'_> {
    server.mock(|when, then| {
        when.method(POST)
            .path("/session")
            .query_param("delete", "true");
        then.status(200).json_body(json!({"success": true}));
    })
}

fn output(assert: &assert_cmd::assert::Assert) -> (String, String) {
    let out = assert.get_output();
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn password_sign_in_for_connection_test_and_sql_with_debug_logs_free_of_secrets() {
    let home = Home::new();
    let server = MockServer::start();
    let login = server.mock(|when, then| {
        when.method(POST).path(LOGIN).is_true(|req| {
            let d = data(req);
            d["PASSWORD"] == PASSWORD && d.get("AUTHENTICATOR").is_none()
        });
        then.status(200).json_body(login_ok("session-token"));
    });
    let query = select_one(&server);
    let close = close(&server);

    let assert = home
        .snow_cmd(&server, &["connection", "test"])
        .args(["--password", PASSWORD, "--format", "json", "--debug"])
        .assert()
        .success();
    let (stdout, stderr) = output(&assert);
    assert!(stdout.starts_with(WARNING), "{stdout}");
    let json: Value = serde_json::from_str(stdout.trim_start_matches(WARNING).trim()).unwrap();
    assert_eq!(json["Status"], "OK");
    assert!(
        stderr.contains("POST /session/v1/login-request"),
        "{stderr}"
    );
    for text in [&stdout, &stderr] {
        assert!(!text.contains(PASSWORD), "the password leaked:\n{text}");
        assert!(
            !text.contains("session-token"),
            "the session token leaked:\n{text}"
        );
    }

    let assert = home
        .snow_cmd(&server, &["sql", "-q", "SELECT 1", "--format", "csv"])
        .env("SNOWFLAKE_PASSWORD", PASSWORD)
        .assert()
        .success();
    let (stdout, _) = output(&assert);
    assert_eq!(stdout, "1\n1\n", "no warning without --password");
    login.assert_calls(2);
    query.assert_calls(2);
    close.assert_calls(2);
}

impl Home {
    /// `snow <args> -x …` against `server` (the connection flags after the subcommand).
    fn snow_cmd(&self, server: &MockServer, args: &[&str]) -> Command {
        let mut cmd = Command::cargo_bin("snow-rs").unwrap();
        cmd.env_clear()
            .env("SNOWFLAKE_HOME", self.dir.path())
            .env("HOME", self.dir.path())
            .env("SNOWFLAKE_PROTOCOL", "http")
            .current_dir(self.dir.path());
        if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
            cmd.env("LLVM_PROFILE_FILE", profile);
        }
        cmd.args(args).args([
            "-x",
            "--account",
            "testacct",
            "--user",
            "tester",
            "--host",
            &server.host(),
            "--port",
            &server.port().to_string(),
        ]);
        cmd
    }
}

#[test]
fn a_wrong_password_fails_like_snow() {
    let home = Home::new();
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path(LOGIN);
        then.status(200).json_body(json!({
            "success": false, "code": "390100",
            "message": "Incorrect username or password was specified.",
        }));
    });
    let assert = home
        .snow_cmd(&server, &["sql", "-q", "SELECT 1"])
        .args(["--password", PASSWORD, "--enhanced-exit-codes"])
        .assert()
        .failure();
    let (stdout, stderr) = output(&assert);
    assert!(stdout.starts_with(WARNING));
    assert!(
        stderr.contains(
            "Could not connect to Snowflake. Reason: 390100 (28000): Failed to connect to"
        ),
        "{stderr}"
    );
    assert!(stderr.contains("Incorrect username or password was specified."));
    assert!(!stderr.contains(PASSWORD) && !stdout.contains(PASSWORD));
}

#[test]
fn mfa_passcode_from_the_flag_and_the_server_session_kept_alive() {
    let home = Home::new();
    let server = MockServer::start();
    let login = server.mock(|when, then| {
        when.method(POST).path(LOGIN).is_true(|req| {
            let d = data(req);
            d["PASSWORD"] == PASSWORD
                && d["EXT_AUTHN_DUO_METHOD"] == "passcode"
                && d["PASSCODE"] == "654321"
        });
        then.status(200).json_body(login_ok("session-token"));
    });
    select_one(&server);
    let close = close(&server);
    home.snow_cmd(&server, &["sql", "-q", "SELECT 1"])
        .args(["--mfa-passcode", "654321", "--server-session-keep-alive"])
        .env("SNOWFLAKE_PASSWORD", PASSWORD)
        .assert()
        .success();
    login.assert();
    close.assert_calls(0);
}

/// Answers every prompt with the passcode.
struct Passcode;
impl Prompter for Passcode {
    fn prompt(&mut self, label: &str, hidden: bool) -> snowflake_cli_rs::error::Result<String> {
        assert_eq!((label, hidden), ("MFA passcode: ", false));
        Ok("112233".into())
    }
}

#[test]
fn mfa_passcode_without_a_value_is_prompted_for() {
    let server = MockServer::start();
    let login = server.mock(|when, then| {
        when.method(POST)
            .path(LOGIN)
            .is_true(|req| data(req)["PASSCODE"] == "112233");
        then.status(200).json_body(login_ok("session-token"));
    });
    select_one(&server);
    close(&server);
    let home = TempDir::new().unwrap();
    let env = Env::from_pairs([
        (
            "SNOWFLAKE_HOME".to_string(),
            home.path().display().to_string(),
        ),
        ("SNOWFLAKE_PASSWORD".into(), PASSWORD.into()),
        ("SNOWFLAKE_PROTOCOL".into(), "http".into()),
    ]);
    let port = server.port().to_string();
    let host = server.host();
    let args = [
        "snow-rs",
        "sql",
        "-q",
        "SELECT 1",
        "-x",
        "--account",
        "testacct",
        "--user",
        "tester",
        "--host",
        &host,
        "--port",
        &port,
        "--mfa-passcode",
        "--format",
        "csv",
    ];
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut input: &[u8] = b"";
    let _log = common::logger_guard();
    let code = snowflake_cli_rs::run_with(
        args,
        env,
        snowflake_cli_rs::Stdin {
            is_tty: true,
            reader: &mut input,
        },
        &mut Passcode,
        None,
        &mut out,
        &mut err,
    );
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&err));
    assert_eq!(String::from_utf8(out).unwrap(), "1\n1\n");
    login.assert();
}

#[test]
fn username_password_mfa_keeps_the_mfa_token_in_the_file_cache() {
    let home = Home::new();
    let cache = home.cache_dir();
    let server = MockServer::start();
    let mut first = server.mock(|when, then| {
        when.method(POST).path(LOGIN).is_true(|req| {
            let d = data(req);
            d["SESSION_PARAMETERS"]["CLIENT_REQUEST_MFA_TOKEN"] == true && d.get("TOKEN").is_none()
        });
        then.status(200).json_body(json!({"success": true, "data": {
            "token": "session-token", "masterToken": "m", "mfaToken": "MFA-TOKEN-MARKER",
        }}));
    });
    select_one(&server);
    close(&server);
    let run = || {
        home.snow_cmd(&server, &["sql", "-q", "SELECT 1"])
            .args(["--authenticator", "USERNAME_PASSWORD_MFA"])
            .env("SNOWFLAKE_PASSWORD", PASSWORD)
            .env("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", &cache)
            .assert()
    };
    let (stdout, stderr) = output(&run().success());
    assert!(!stdout.contains("MFA-TOKEN-MARKER") && !stderr.contains("MFA-TOKEN-MARKER"));
    first.assert();
    let file = cache.join("credential_cache_v1.json");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the connector's file permissions");
    }
    assert!(
        std::fs::read_to_string(&file)
            .unwrap()
            .contains("MFA-TOKEN-MARKER")
    );
    first.delete();

    let second = server.mock(|when, then| {
        when.method(POST)
            .path(LOGIN)
            .is_true(|req| data(req)["TOKEN"] == "MFA-TOKEN-MARKER");
        then.status(200).json_body(login_ok("session-token"));
    });
    run().success();
    second.assert();
}

#[test]
fn oauth_client_credentials_through_the_cli() {
    let home = Home::new();
    let server = MockServer::start();
    let token_url = format!(
        "http://{}:{}/oauth/token-request",
        server.host(),
        server.port()
    );
    let grant = server.mock(|when, then| {
        when.method(POST)
            .path("/oauth/token-request")
            .header("authorization", "Basic Y2xpZW50OkNMSUVOVC1TRUNSRVQ=")
            .body("grant_type=client_credentials&scope=session%3Arole%3AR1");
        then.status(200)
            .json_body(json!({"access_token": "ACCESS-TOKEN-MARKER"}));
    });
    let login = server.mock(|when, then| {
        when.method(POST).path(LOGIN).is_true(|req| {
            let d = data(req);
            d["AUTHENTICATOR"] == "OAUTH"
                && d["TOKEN"] == "ACCESS-TOKEN-MARKER"
                && d["CLIENT_ENVIRONMENT"]["OAUTH_TYPE"] == "oauth_client_credentials"
        });
        then.status(200).json_body(login_ok("session-token"));
    });
    select_one(&server);
    close(&server);
    let assert = home
        .snow_cmd(&server, &["sql", "-q", "SELECT 1", "--debug"])
        .args([
            "--authenticator",
            "OAUTH_CLIENT_CREDENTIALS",
            "--role",
            "R1",
            "--oauth-client-id",
            "client",
            "--oauth-client-secret",
            "CLIENT-SECRET",
            "--oauth-token-request-url",
            &token_url,
        ])
        .assert()
        .success();
    let (stdout, stderr) = output(&assert);
    for text in [&stdout, &stderr] {
        assert!(
            !text.contains("ACCESS-TOKEN-MARKER") && !text.contains("CLIENT-SECRET"),
            "{text}"
        );
    }
    grant.assert();
    login.assert();
}

#[test]
fn generate_jwt_accepts_the_new_flags_and_warns_about_password() {
    let home = Home::new();
    let server = MockServer::start();
    let assert = home
        .snow_cmd(&server, &["connection", "generate-jwt"])
        .args([
            "--password",
            PASSWORD,
            "--oauth-disable-pkce",
            "--protocol",
            "http",
        ])
        .args([
            "--private-key-file",
            common::key_path("unencrypted.p8").to_str().unwrap(),
        ])
        .assert()
        .success();
    let (stdout, _) = output(&assert);
    assert!(stdout.starts_with(WARNING), "{stdout}");
    assert!(!stdout.contains(PASSWORD));
}
