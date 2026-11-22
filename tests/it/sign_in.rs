//! Sign-in over the SQL API: `OAUTH`, `PROGRAMMATIC_ACCESS_TOKEN`, `WORKLOAD_IDENTITY`
//! and `--secondary-roles`, the binary end to end against a mocked SQL API that checks the exact
//! headers; `generate-workload-identity-token`; and no token in any output, `--debug` included.

use crate::common;

use assert_cmd::Command;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use common::{STATEMENTS, key_path, one_int_body};
use httpmock::{Mock, MockServer};
use serde_json::json;
use tempfile::TempDir;

const SECRET: &str = "TOKEN-SECRET-MARKER-9c1d";

/// A JWT-shaped OIDC token whose payload carries the marker.
fn oidc_token() -> String {
    let enc = |v: &str| URL_SAFE_NO_PAD.encode(v);
    format!(
        "{}.{}.{}",
        enc(r#"{"alg":"RS256"}"#),
        enc(&format!(
            r#"{{"iss":"https://issuer","sub":"workload","exp":4102444800,"m":"{SECRET}"}}"#
        )),
        enc("sig")
    )
}

struct Home {
    dir: TempDir,
}

impl Home {
    fn new() -> Self {
        Self {
            dir: TempDir::new().unwrap(),
        }
    }

    fn file(&self, name: &str, text: &str) -> String {
        let path = self.dir.path().join(name);
        std::fs::write(&path, text).unwrap();
        path.display().to_string()
    }

    fn snow(&self) -> Command {
        let mut cmd = Command::cargo_bin("snow-rs").unwrap();
        cmd.env_clear()
            .env("SNOWFLAKE_HOME", self.dir.path())
            .current_dir(self.dir.path());
        crate::common::keep_system_env(&mut cmd);
        if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
            cmd.env("LLVM_PROFILE_FILE", profile);
        }
        cmd
    }
}

/// `-x` against the mock server, plain HTTP.
fn target(server: &MockServer) -> Vec<String> {
    [
        "-x",
        "--account",
        "testacct",
        "--host",
        &server.host(),
        "--port",
        &server.port().to_string(),
    ]
    .map(String::from)
    .into()
}

/// A `SELECT 1` POST carrying exactly these authorization headers.
fn select_one<'a>(server: &'a MockServer, bearer: &str, token_type: &str) -> Mock<'a> {
    let bearer = format!("Bearer {bearer}");
    server.mock(|when, then| {
        when.method("POST")
            .path(STATEMENTS)
            .header("authorization", bearer)
            .header("x-snowflake-authorization-token-type", token_type)
            .json_body_includes(json!({"statement": "SELECT 1"}).to_string());
        then.status(200).json_body(one_int_body("1"));
    })
}

fn output(assert: &assert_cmd::assert::Assert) -> String {
    let out = assert.get_output();
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn oauth_token_from_the_flag_the_file_or_the_environment() {
    let home = Home::new();
    let server = MockServer::start();
    let mock = select_one(&server, SECRET, "OAUTH");
    let file = home.file("token.txt", &format!("{SECRET}\n"));
    // (flags, environment) of each run.
    type Run<'a> = (Vec<String>, Vec<(&'a str, String)>);
    let runs: Vec<Run> = vec![
        (
            vec![
                "--authenticator".into(),
                "OAUTH".into(),
                "--token".into(),
                SECRET.into(),
            ],
            vec![],
        ),
        (
            vec![
                "--authenticator".into(),
                "oauth".into(),
                "--token-file-path".into(),
                file,
            ],
            vec![],
        ),
        (
            vec![],
            vec![
                ("SNOWFLAKE_AUTHENTICATOR", "OAUTH".into()),
                ("SNOWFLAKE_TOKEN", SECRET.into()),
            ],
        ),
    ];
    for (args, env) in runs {
        let assert = home
            .snow()
            .env("SNOWFLAKE_PROTOCOL", "http")
            .envs(env)
            .args(["connection", "test", "--debug"])
            .args(target(&server))
            .args(args)
            .assert()
            .success();
        let text = output(&assert);
        assert!(text.contains("Status"), "{text}");
        assert!(!text.contains(SECRET), "{text}");
    }
    mock.assert_calls(3);
}

#[test]
fn programmatic_access_token_in_a_named_connection() {
    let home = Home::new();
    let server = MockServer::start();
    let mock = select_one(&server, SECRET, "PROGRAMMATIC_ACCESS_TOKEN");
    home.file(
        "config.toml",
        &format!(
            "[connections.pat]\naccount = \"testacct\"\nauthenticator = \"PROGRAMMATIC_ACCESS_TOKEN\"\nhost = \"{}\"\nport = {}\nprotocol = \"http\"\n",
            server.host(),
            server.port()
        ),
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = home.dir.path().join("config.toml");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let assert = home
        .snow()
        .env("SNOWFLAKE_CONNECTIONS_PAT_TOKEN", SECRET)
        .args([
            "sql", "-c", "pat", "-q", "SELECT 1", "--format", "json", "--debug",
        ])
        .assert()
        .success();
    let text = output(&assert);
    assert!(text.contains("\"N\": 1"), "{text}");
    assert!(!text.contains(SECRET), "{text}");
    mock.assert_calls(1);
}

#[test]
fn a_rejected_token_is_reported_without_the_token() {
    let home = Home::new();
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method("POST").path(STATEMENTS);
        then.status(401)
            .json_body(json!({"code": "390303", "message": "Invalid OAuth access token."}));
    });
    for authenticator in ["OAUTH", "PROGRAMMATIC_ACCESS_TOKEN"] {
        let assert = home
            .snow()
            .env("SNOWFLAKE_PROTOCOL", "http")
            .args(["sql", "-q", "SELECT 1", "--debug", "-v"])
            .args(target(&server))
            .args(["--authenticator", authenticator, "--token", SECRET])
            .assert()
            .failure();
        let text = output(&assert);
        assert!(!text.contains(SECRET), "{text}");
    }
}

#[test]
fn a_missing_token_or_token_file_is_a_clear_error() {
    let home = Home::new();
    let server = MockServer::start();
    home.snow()
        .args(["connection", "test"])
        .args(target(&server))
        .args(["--authenticator", "OAUTH"])
        .assert()
        .code(1)
        .stderr(predicates::str::contains(
            "The connection has no token. Set `token` or `token_file_path`.",
        ));
    home.snow()
        .args(["connection", "test"])
        .args(target(&server))
        .args([
            "--authenticator",
            "OAUTH",
            "--token-file-path",
            "missing.txt",
        ])
        .assert()
        .code(1)
        .stderr(predicates::str::contains(
            "Couldn't read the token file missing.txt.",
        ));
}

#[test]
fn a_private_key_signs_in_with_key_pair_whatever_the_authenticator() {
    let home = Home::new();
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        common::authorized(when).method("POST").path(STATEMENTS);
        then.status(200).json_body(one_int_body("1"));
    });
    for authenticator in [None, Some("OAUTH")] {
        let mut cmd = home.snow();
        cmd.env("SNOWFLAKE_PROTOCOL", "http")
            .args(["sql", "-q", "SELECT 1"])
            .args(target(&server))
            .args(["--user", "tester", "--private-key-file"])
            .arg(key_path("unencrypted.p8"));
        if let Some(a) = authenticator {
            cmd.args(["--authenticator", a]);
        }
        cmd.assert().success();
    }
    mock.assert_calls(2);
}

#[test]
fn unknown_and_connector_only_authenticators() {
    let home = Home::new();
    let server = MockServer::start();
    home.snow()
        .args(["sql", "-q", "SELECT 1"])
        .args(target(&server))
        .args(["--authenticator", "foo"])
        .assert()
        .code(1)
        .stderr(predicates::str::contains(
            "Could not connect to Snowflake. Reason: 251007: Unknown authenticator: foo",
        ));
    home.snow()
        .args(["sql", "-q", "SELECT 1"])
        .args(target(&server))
        .args(["--authenticator", "PAT_WITH_EXTERNAL_SESSION"])
        .assert()
        .code(1)
        .stderr(predicates::str::contains(
            "authenticator PAT_WITH_EXTERNAL_SESSION is not supported yet",
        ));
}

#[test]
fn workload_identity_oidc_sends_the_wif_header() {
    let home = Home::new();
    let server = MockServer::start();
    let token = oidc_token();
    let mock = select_one(
        &server,
        &format!("WIF.OIDC.{token}"),
        "WORKLOAD_IDENTITY_FEDERATION",
    );
    let assert = home
        .snow()
        .env("SNOWFLAKE_PROTOCOL", "http")
        .env("SNOWFLAKE_WIF_ALLOWED_HOST_SUFFIXES", "127.0.0.1,localhost")
        .args(["connection", "test", "--debug", "--format", "json"])
        .args(target(&server))
        .args([
            "--authenticator",
            "WORKLOAD_IDENTITY",
            "--workload-identity-provider",
            "OIDC",
            "--token",
            &token,
        ])
        .assert()
        .success();
    let text = output(&assert);
    assert!(!text.contains(SECRET), "{text}");
    assert!(!text.contains(&token), "{text}");
    mock.assert_calls(1);
}

#[test]
fn workload_identity_azure_functions_end_to_end() {
    let home = Home::new();
    let server = MockServer::start();
    let token = oidc_token();
    let identity = server.mock(|when, then| {
        when.method("GET")
            .path("/msi/token")
            .header("x-identity-header", "ID-HEADER");
        then.status(200).json_body(json!({"access_token": token}));
    });
    let mock = select_one(
        &server,
        &format!("WIF.AZURE.{token}"),
        "WORKLOAD_IDENTITY_FEDERATION",
    );
    let assert = home
        .snow()
        .env("SNOWFLAKE_PROTOCOL", "http")
        .env("SNOWFLAKE_WIF_ALLOWED_HOST_SUFFIXES", "127.0.0.1,localhost")
        .env(
            "IDENTITY_ENDPOINT",
            format!("{}/msi/token", server.base_url()),
        )
        .env("IDENTITY_HEADER", "ID-HEADER")
        .env("SNOWFLAKE_AUTHENTICATOR", "WORKLOAD_IDENTITY")
        .env("SNOWFLAKE_WORKLOAD_IDENTITY_PROVIDER", "azure")
        .args(["connection", "test", "--debug"])
        .args(target(&server))
        .assert()
        .success();
    assert!(!output(&assert).contains(SECRET));
    identity.assert_calls(1);
    mock.assert_calls(1);
}

#[test]
fn workload_identity_refuses_hosts_outside_snowflake() {
    let home = Home::new();
    let server = MockServer::start();
    home.snow()
        .args(["connection", "test"])
        .args(target(&server))
        .args([
            "--authenticator",
            "WORKLOAD_IDENTITY",
            "--workload-identity-provider",
            "GCP",
        ])
        .assert()
        .code(1)
        .stderr(predicates::str::contains(
            "251021: WORKLOAD_IDENTITY requires a",
        ));
    home.snow()
        .args(["connection", "test"])
        .args(target(&server))
        .args(["--workload-identity-provider", "oidc"])
        .assert()
        .code(1)
        .stderr(predicates::str::contains(
            "Invalid workload identity provider 'oidc'. Valid values are: AWS, AZURE,",
        ));
}

#[test]
fn secondary_roles_run_first_in_the_session() {
    let home = Home::new();
    let server = MockServer::start();
    let parent = server.mock(|when, then| {
        common::submit(when, "USE SECONDARY ROLES NONE;\nSELECT 1\n;")
            .json_body_includes(json!({"parameters": {"MULTI_STATEMENT_COUNT": "2"}}).to_string());
        then.status(200).json_body(json!({
            "statementHandle": "p", "statementHandles": ["c1", "c2"], "code": "090001",
            "message": "Statement executed successfully.",
        }));
    });
    let child = server.mock(|when, then| {
        common::authorized(when)
            .method("GET")
            .path(format!("{STATEMENTS}/c2"));
        then.status(200).json_body(one_int_body("1"));
    });
    let args = |extra: &[&str]| {
        let mut args: Vec<String> = target(&server);
        args.extend(
            [
                "--user",
                "tester",
                "--authenticator",
                "SNOWFLAKE_JWT",
                "--private-key-file",
                key_path("unencrypted.p8").to_str().unwrap(),
                "--database",
                "TEST_DB",
                "--schema",
                "PUBLIC",
                "--role",
                "TEST_ROLE",
                "--warehouse",
                "TEST_WH",
            ]
            .map(String::from),
        );
        args.extend(extra.iter().map(|s| s.to_string()));
        args
    };
    let out = home
        .snow()
        .env("SNOWFLAKE_PROTOCOL", "http")
        .args(["sql", "-q", "SELECT 1", "--format", "json"])
        .args(args(&["--secondary-roles", "none"]))
        .assert()
        .success();
    assert!(String::from_utf8_lossy(&out.get_output().stdout).contains("\"N\": 1"));
    home.snow()
        .env("SNOWFLAKE_PROTOCOL", "http")
        .env("SNOWFLAKE_SECONDARY_ROLES", "NONE")
        .args(["connection", "test"])
        .args(args(&[]))
        .assert()
        .success();
    parent.assert_calls(2);
    child.assert_calls(2);

    home.snow()
        .args(["sql", "-q", "SELECT 1"])
        .args(args(&["--secondary-roles", "R1, R2"]))
        .assert()
        .code(1)
        .stderr(predicates::str::contains(
            "Invalid secondary_roles value 'R1, R2'. Supported values are ALL and NONE.",
        ));
}

#[test]
fn generate_workload_identity_token_oidc() {
    let home = Home::new();
    let token = oidc_token();
    let out = home
        .snow()
        .args([
            "connection",
            "generate-workload-identity-token",
            "-x",
            "--workload-identity-provider",
            "OIDC",
            "--token",
            &token,
        ])
        .assert()
        .success();
    assert_eq!(
        String::from_utf8_lossy(&out.get_output().stdout),
        format!("{token}\n")
    );
    let file = home.file("t", &format!("  {token}\n"));
    let out = home
        .snow()
        .env("SNOWFLAKE_WORKLOAD_IDENTITY_PROVIDER", "oidc")
        .args(["connection", "generate-workload-identity-token", "-x"])
        .args(["--token-file-path", &file])
        .assert()
        .success();
    assert_eq!(
        String::from_utf8_lossy(&out.get_output().stdout),
        format!("{token}\n")
    );
}

#[test]
fn generate_workload_identity_token_aws_signed_request() {
    let home = Home::new();
    let out = home
        .snow()
        .env("AWS_REGION", "eu-west-1")
        .env("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
        .env("AWS_SECRET_ACCESS_KEY", SECRET)
        .args([
            "connection",
            "generate-workload-identity-token",
            "-x",
            "--workload-identity-provider",
            "AWS",
        ])
        .assert()
        .success();
    let printed = String::from_utf8_lossy(&out.get_output().stdout)
        .trim()
        .to_string();
    let json: serde_json::Value =
        serde_json::from_slice(&STANDARD.decode(&printed).unwrap()).unwrap();
    assert_eq!(
        json["url"],
        "https://sts.eu-west-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15"
    );
    assert_eq!(json["method"], "POST");
    assert_eq!(
        json["headers"]["X-Snowflake-Audience"],
        "snowflakecomputing.com"
    );
    assert!(!printed.contains(SECRET));
}

/// snow 3.34.0's messages and exit codes, captured with `snow connection
/// generate-workload-identity-token -x …` in an empty home.
#[test]
fn generate_workload_identity_token_errors_match_snow() {
    let home = Home::new();
    let run = |args: &[&str]| {
        home.snow()
            .args(["connection", "generate-workload-identity-token", "-x"])
            .args(args)
            .assert()
    };
    run(&[]).code(2).stderr(predicates::str::contains(
        "Workload identity provider is not set in the connection context, but",
    ));
    run(&["--workload-identity-provider", "foo"])
        .code(1)
        .stderr(predicates::str::contains(
            "Invalid workload identity provider 'foo'. Valid values are: AWS, AZURE, GCP,",
        ));
    run(&["--workload-identity-provider", "OIDC"])
        .code(2)
        .stderr(predicates::str::contains(
            "OIDC provider requires a token. Set --token-file-path or configure 'token'",
        ));
    run(&["--workload-identity-provider", "OIDC", "--token", "abc"])
        .code(1)
        .stderr(predicates::str::contains(
            "251017: 251017: Invalid JWT token: Not enough segments",
        ));
    let no_sub = format!(
        "{}.{}.c2ln",
        URL_SAFE_NO_PAD.encode("{}"),
        URL_SAFE_NO_PAD.encode(r#"{"iss":"https://i"}"#)
    );
    run(&["--workload-identity-provider", "OIDC", "--token", &no_sub])
        .code(1)
        .stderr(predicates::str::contains(
            "251018: 251018: Token is missing 'iss' or 'sub' claims.",
        ));
    home.snow()
        .env("SNOWFLAKE_WORKLOAD_IDENTITY_PROVIDER", "k8s")
        .args(["connection", "generate-workload-identity-token", "-x"])
        .assert()
        .code(1)
        .stderr(predicates::str::contains(
            "Unknown workload_identity_provider: 'k8s'",
        ));
}

/// Review finding: a `host` or `account` with a URL delimiter must not pass the
/// Snowflake-host allowlist, and no cloud credential may be fetched for it.
#[test]
fn workload_identity_rejects_url_delimiters_in_host_and_account() {
    let home = Home::new();
    let server = MockServer::start();
    let identity = server.mock(|when, then| {
        when.any_request();
        then.status(200)
            .json_body(json!({"access_token": oidc_token()}));
    });
    for delimiter in ["/", "#", "?", "@", "\\"] {
        for (flag, value) in [
            (
                "--host",
                format!("{}{delimiter}.snowflakecomputing.com", server.host()),
            ),
            ("--account", format!("{}{delimiter}x", server.host())),
        ] {
            home.snow()
                .env(
                    "IDENTITY_ENDPOINT",
                    format!("{}/msi/token", server.base_url()),
                )
                .env("IDENTITY_HEADER", "ID-HEADER")
                .args(["connection", "test", "-x", flag, &value])
                .args([
                    "--authenticator",
                    "WORKLOAD_IDENTITY",
                    "--workload-identity-provider",
                    "AZURE",
                ])
                .assert()
                .code(1)
                .stderr(predicates::str::contains("251021"));
        }
    }
    identity.assert_calls(0);
}
