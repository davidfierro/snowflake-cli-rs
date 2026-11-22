//! `--enable-diag`, `--diag-log-path`, `--diag-allowlist-path` and `connection test
//! --print-diag`. The command runs in-process against an httpmock SQL API and a canned
//! `Network`; two tests drive the binary against local sockets.

use crate::common;

use assert_cmd::Command;
use clap::Parser;
use common::{STATEMENTS, key_path, one_int_body, row_type, submit, success_body};
use httpmock::MockServer;
use predicates::str::contains;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use snowflake_cli_rs::commands::{Context, Prompter};
use snowflake_cli_rs::config::{ConfigPaths, ConfigSource};
use snowflake_cli_rs::diagnostics::net::{NetError, Network, Probed, TlsFloor};
use snowflake_cli_rs::env::Env;
use snowflake_cli_rs::error::Result;
use snowflake_cli_rs::output::format::OutputFormat;
use snowflake_cli_rs::{Cli, Command as Cmd};
use std::path::Path;
use std::time::Duration;

fn leaf_der() -> Vec<u8> {
    CertificateDer::from_pem_file(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/certs/leaf.pem"
    ))
    .unwrap()
    .as_ref()
    .to_vec()
}

/// Everything resolves and answers, except `down.example.com`.
struct Canned;

impl Network for Canned {
    fn lookup(&self, host: &str) -> std::result::Result<Vec<String>, NetError> {
        if host.ends_with(".invalid") {
            return Err(NetError::Other(
                "[Errno -2] Name or service not known".into(),
            ));
        }
        Ok(vec!["54.0.0.1".into()])
    }

    fn peer_cert(
        &self,
        _host: &str,
        _port: u16,
        _timeout: Duration,
        _floor: TlsFloor,
    ) -> std::result::Result<Vec<u8>, NetError> {
        Ok(leaf_der())
    }

    fn http_get(
        &self,
        _host: &str,
        _port: u16,
        _timeout: Duration,
    ) -> std::result::Result<String, NetError> {
        Ok("HTTP/1.1 200 OK".into())
    }

    fn probe(
        &self,
        host: &str,
        _port: u16,
        _timeout: Duration,
    ) -> std::result::Result<Probed, String> {
        if host == "down.example.com" {
            return Err("[Errno 111] Connection refused".into());
        }
        Ok(Probed {
            latency_ms: 4.2,
            issuer_org: Some("Amazon".into()),
            not_after: Some("Jun  5 12:00:00 2027 GMT".into()),
        })
    }
}

struct NoPrompt;

impl Prompter for NoPrompt {
    fn prompt(&mut self, _label: &str, _hidden: bool) -> Result<String> {
        panic!("no prompt expected");
    }
}

struct Run {
    out: String,
    result: Result<()>,
}

/// Runs `snow connection test -x <connection flags> <extra>` in process.
fn run(server: &MockServer, extra: &[&str], format: OutputFormat) -> Run {
    let key = key_path("unencrypted.p8");
    let mut args: Vec<String> = [
        "snow-rs",
        "connection",
        "test",
        "-x",
        "--account",
        "testacct",
        "--user",
        "tester",
        "--authenticator",
        "SNOWFLAKE_JWT",
        "--private-key-file",
        key.to_str().unwrap(),
        "--host",
        &server.host(),
        "--port",
        &server.port().to_string(),
        "--role",
        "TEST_ROLE",
        "--warehouse",
        "TEST_WH",
        "--database",
        "TEST_DB",
        "--schema",
        "PUBLIC",
    ]
    .map(String::from)
    .into();
    args.extend(extra.iter().map(|a| a.to_string()));
    let home = tempfile::tempdir().unwrap();
    let env = Env::from_pairs([
        ("SNOWFLAKE_HOME", home.path().to_str().unwrap()),
        ("SNOWFLAKE_PROTOCOL", "http"),
    ]);
    let cli = Cli::try_parse_from(&args).unwrap();
    let Some(Cmd::Connection(connection)) = cli.command else {
        panic!("not a connection command");
    };
    let paths = ConfigPaths::discover(&env, None).unwrap();
    let source = ConfigSource::load(&paths).unwrap();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut prompter = NoPrompt;
    let mut ctx = Context {
        env,
        config_file: None,
        enhanced_exit_codes: false,
        decimal_precision: None,
        stdin_is_tty: false,
        prompter: &mut prompter,
        stdout: &mut out,
        stderr: &mut err,
        terminal_width: None,
    };
    let result = connection
        .command
        .run_with_network(&paths, &source, format, &Canned, &mut ctx)
        .and_then(|r| r.write(format, None, ctx.stdout));
    drop(ctx);
    Run {
        out: String::from_utf8(out).unwrap(),
        result,
    }
}

fn mock_select_1(server: &MockServer) {
    server.mock(|when, then| {
        common::authorized(when)
            .method("POST")
            .path(STATEMENTS)
            .json_body_includes(serde_json::json!({"statement": "SELECT 1"}).to_string());
        then.status(200).json_body(one_int_body("1"));
    });
}

fn text_body(column: &str, value: &str) -> serde_json::Value {
    success_body(
        vec![row_type(column, "text", None)],
        serde_json::json!([[value]]),
        1,
    )
}

fn mock_text(server: &MockServer, sql: &str, column: &str, value: &str) {
    let body = text_body(column, value);
    server.mock(|when, then| {
        submit(when, sql);
        then.status(200).json_body(body);
    });
}

const ALLOWLIST: &str = r#"[
    {"type":"SNOWFLAKE_DEPLOYMENT","host":"testacct.snowflakecomputing.com","port":443},
    {"type":"STAGE","host":"down.example.com","port":443},
    {"type":"OCSP_RESPONDER","host":"ocsp.example.com","port":80},
    {"type":"SNOWSQL_REGION","host":"*.apps.example.com","port":443}
]"#;

fn write_allowlist(dir: &Path) -> String {
    let path = dir.join("allowlist.json");
    std::fs::write(&path, ALLOWLIST).unwrap();
    path.to_str().unwrap().to_string()
}

#[test]
fn without_diag_options_the_output_is_unchanged() {
    let server = MockServer::start();
    mock_select_1(&server);
    let run = run(&server, &[], OutputFormat::Json);
    run.result.unwrap();
    assert!(!run.out.contains("Diag"), "{}", run.out);
}

#[test]
fn enable_diag_writes_both_report_sections_and_prints_the_location() {
    let server = MockServer::start();
    mock_select_1(&server);
    let dir = tempfile::tempdir().unwrap();
    let allowlist = write_allowlist(dir.path());
    let log_dir = dir.path().join("logs/nested");
    let r = run(
        &server,
        &[
            "--enable-diag",
            "--diag-log-path",
            log_dir.to_str().unwrap(),
            "--diag-allowlist-path",
            &allowlist,
            "--format",
            "json",
        ],
        OutputFormat::Json,
    );
    r.result.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&r.out).unwrap();
    let report_path = log_dir.join("SnowflakeConnectionTestReport.txt");
    assert_eq!(
        // Compared as paths: on Windows the report mixes `/` and `\\`.
        std::path::Path::new(parsed["Diag Report Location"].as_str().unwrap()),
        report_path
    );
    assert_eq!(parsed["Status"], "OK");
    assert!(
        parsed.get("Diagnostic").is_none(),
        "that needs --print-diag"
    );
    let report = std::fs::read_to_string(&report_path).unwrap();
    // The connector's part: from the allowlist file, not from SYSTEM$ALLOWLIST().
    assert!(report.starts_with(
        "=========Connectivity diagnostic report================================\n\
         INITIAL: Specified snowflake account: testacct\n"
    ));
    assert!(
        report
            .contains("=========Snowflake Stage information===================================\n")
    );
    assert!(
        report.contains("OCSP_RESPONDER: ocsp.example.com:80: URL Check: Connected Successfully")
    );
    // snow's part, appended after a blank line.
    let marker = "\n========================================================================\nSnowflake CLI connectivity diagnostics\n";
    assert!(report.contains(marker), "{report}");
    assert!(report.contains("  Unhealthy  STAGE                down.example.com\n    error: [Errno 111] Connection refused\n"));
    assert!(report.contains("  *.apps.example.com  SNOWSQL_REGION  non-resolvable pattern"));
    assert!(report.contains(
        "Results: 2 Healthy, 1 Unhealthy out of 3 endpoints. 1 skipped (non-resolvable patterns)."
    ));
}

#[test]
fn the_report_never_contains_credentials() {
    let server = MockServer::start();
    mock_select_1(&server);
    let dir = tempfile::tempdir().unwrap();
    let allowlist = write_allowlist(dir.path());
    let r = run(
        &server,
        &[
            "--enable-diag",
            "--diag-log-path",
            dir.path().to_str().unwrap(),
            "--diag-allowlist-path",
            &allowlist,
            "--print-diag",
        ],
        OutputFormat::Table,
    );
    r.result.unwrap();
    let report =
        std::fs::read_to_string(dir.path().join("SnowflakeConnectionTestReport.txt")).unwrap();
    for text in [&report, &r.out] {
        assert!(!text.contains("BEGIN PRIVATE KEY"));
        assert!(!text.contains("Bearer"));
        assert!(!text.contains("eyJ"), "a JWT showed up");
    }
}

#[test]
fn print_diag_streams_progress_then_the_tables_in_table_format() {
    let server = MockServer::start();
    mock_select_1(&server);
    let dir = tempfile::tempdir().unwrap();
    let allowlist = write_allowlist(dir.path());
    let r = run(
        &server,
        &["--print-diag", "--diag-allowlist-path", &allowlist],
        OutputFormat::Table,
    );
    r.result.unwrap();
    let out = r.out;
    assert!(
        out.starts_with("Fetching allowlist from Snowflake...\n"),
        "{out}"
    );
    assert!(
        !out.contains("Running connector connectivity probe"),
        "needs --enable-diag too"
    );
    for line in [
        "Discovered 4 endpoint(s). Running diagnostics...\n",
        "Skipping 1 non-resolvable pattern(s).\n",
        "Checking STAGE: down.example.com ❌ ([Errno 111] Connection refused)\n",
        "Checking OCSP_RESPONDER: ocsp.example.com ✅ (4.2 ms)\n",
        "Inspecting network policies...\n",
    ] {
        assert!(out.contains(line), "{line:?} missing from:\n{out}");
    }
    assert!(out.contains("| Connection name | testacct") || out.contains("Connection name"));
    assert!(out.contains("| url "), "{out}");
    assert!(out.contains("Unhealthy"));
    assert!(
        !out.contains("apps.example.com |"),
        "skipped patterns have no row"
    );
    assert!(out.ends_with(
        "Results: 2 Healthy, 1 Unhealthy out of 3 endpoints. 1 skipped (non-resolvable patterns).\n"
    ));
    assert!(!out.contains("Diag Report Location"));
}

#[test]
fn print_diag_with_enable_diag_announces_the_connector_probe() {
    let server = MockServer::start();
    mock_select_1(&server);
    let dir = tempfile::tempdir().unwrap();
    let allowlist = write_allowlist(dir.path());
    let r = run(
        &server,
        &[
            "--enable-diag",
            "--print-diag",
            "--diag-log-path",
            dir.path().to_str().unwrap(),
            "--diag-allowlist-path",
            &allowlist,
        ],
        OutputFormat::Table,
    );
    r.result.unwrap();
    assert!(
        r.out
            .starts_with("Running connector connectivity probe...\nFetching allowlist"),
        "{}",
        r.out
    );
    assert!(r.out.contains("Diag Report Location"));
}

#[test]
fn print_diag_json_nests_the_diagnostic_and_is_silent_on_progress() {
    let server = MockServer::start();
    mock_select_1(&server);
    let dir = tempfile::tempdir().unwrap();
    let allowlist = write_allowlist(dir.path());
    let r = run(
        &server,
        &["--print-diag", "--diag-allowlist-path", &allowlist],
        OutputFormat::Json,
    );
    r.result.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&r.out).unwrap();
    let diagnostic = &parsed["Diagnostic"];
    assert_eq!(diagnostic["healthy"], 2);
    assert_eq!(diagnostic["unhealthy"], 1);
    assert_eq!(diagnostic["skipped"], 1);
    assert_eq!(diagnostic["tested"], 3);
    assert_eq!(diagnostic["checks"].as_array().unwrap().len(), 4);
    assert_eq!(
        diagnostic["checks"][1]["error"],
        "[Errno 111] Connection refused"
    );
    assert_eq!(diagnostic["checks"][0]["latency_ms"], 4.2);
    assert!(diagnostic["network_policy"].is_object());
}

#[test]
fn print_diag_csv_has_flat_scalar_columns() {
    let server = MockServer::start();
    mock_select_1(&server);
    let dir = tempfile::tempdir().unwrap();
    let allowlist = write_allowlist(dir.path());
    let r = run(
        &server,
        &["--print-diag", "--diag-allowlist-path", &allowlist],
        OutputFormat::Csv,
    );
    r.result.unwrap();
    let header = r.out.lines().next().unwrap();
    assert!(
        header.ends_with(",healthy,unhealthy,tested,skipped,effective_policy,current_ip"),
        "{header}"
    );
    assert_eq!(r.out.lines().count(), 2, "{}", r.out);
}

#[test]
fn silent_mutes_the_progress_lines() {
    let server = MockServer::start();
    mock_select_1(&server);
    let dir = tempfile::tempdir().unwrap();
    let allowlist = write_allowlist(dir.path());
    let r = run(
        &server,
        &[
            "--print-diag",
            "--silent",
            "--diag-allowlist-path",
            &allowlist,
        ],
        OutputFormat::Table,
    );
    r.result.unwrap();
    assert!(!r.out.contains("Fetching allowlist"), "{}", r.out);
    assert!(!r.out.contains("Checking STAGE"), "{}", r.out);
    assert!(r.out.contains("Results: 2 Healthy"));
}

#[test]
fn the_allowlist_and_the_network_policy_come_from_the_account_by_default() {
    let server = MockServer::start();
    mock_select_1(&server);
    mock_text(
        &server,
        "SELECT SYSTEM$ALLOWLIST() AS result",
        "RESULT",
        r#"[{"type":"STAGE","host":"stage.example.com","port":443}]"#,
    );
    mock_text(
        &server,
        "SELECT CURRENT_IP_ADDRESS() AS IP",
        "IP",
        "203.0.113.9",
    );
    mock_text(
        &server,
        r"SHOW PARAMETERS LIKE 'NETWORK\\_POLICY' IN ACCOUNT",
        "value",
        "ACCT_POLICY",
    );
    let r = run(&server, &["--print-diag"], OutputFormat::Table);
    r.result.unwrap();
    assert!(r.out.contains("Discovered 1 endpoint(s)"), "{}", r.out);
    assert!(r.out.contains("Checking STAGE: stage.example.com ✅"));
    assert!(r.out.contains("Effective network policy"), "{}", r.out);
    assert!(r.out.contains("ACCT_POLICY"));
    assert!(r.out.contains("203.0.113.9"));
    assert!(r.out.contains("Could not DESC NETWORK POLICY ACCT_POLICY"));
}

#[test]
fn without_a_network_policy_the_current_ip_is_reported() {
    let server = MockServer::start();
    mock_select_1(&server);
    mock_text(
        &server,
        "SELECT CURRENT_IP_ADDRESS() AS IP",
        "IP",
        "203.0.113.9",
    );
    let r = run(&server, &["--print-diag"], OutputFormat::Table);
    r.result.unwrap();
    // The allowlist query is unmocked (404), so the connection host is checked.
    assert!(
        r.out.contains("Checking SNOWFLAKE_DEPLOYMENT:"),
        "{}",
        r.out
    );
    assert!(
        r.out
            .contains("No network policy in effect (current IP: 203.0.113.9).\n"),
        "{}",
        r.out
    );
}

#[test]
fn a_missing_allowlist_file_is_a_usage_error() {
    let server = MockServer::start();
    mock_select_1(&server);
    let r = run(
        &server,
        &["--diag-allowlist-path", "/nonexistent/allowlist.json"],
        OutputFormat::Table,
    );
    let err = r.result.unwrap_err();
    assert!(
        err.to_string()
            .contains("Invalid value for '--diag-allowlist-path'")
    );
    assert_eq!(err.exit_code(), 2);
}

#[test]
fn an_unreadable_allowlist_file_fails_the_command_after_the_connection_works() {
    let server = MockServer::start();
    mock_select_1(&server);
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("bad.json");
    std::fs::write(&bad, "{").unwrap();
    let r = run(
        &server,
        &[
            "--print-diag",
            "--diag-allowlist-path",
            bad.to_str().unwrap(),
        ],
        OutputFormat::Table,
    );
    assert!(
        r.result
            .unwrap_err()
            .to_string()
            .contains("Could not read allowlist file")
    );
}

#[test]
fn a_failed_connection_still_writes_the_connector_report() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method("POST").path(STATEMENTS);
        then.status(401).body("{}");
    });
    let dir = tempfile::tempdir().unwrap();
    let r = run(
        &server,
        &[
            "--enable-diag",
            "--diag-log-path",
            dir.path().to_str().unwrap(),
        ],
        OutputFormat::Table,
    );
    assert!(r.result.is_err());
    let report =
        std::fs::read_to_string(dir.path().join("SnowflakeConnectionTestReport.txt")).unwrap();
    assert!(
        report.contains("Snowflake Stage information - Unavailable"),
        "{report}"
    );
    assert!(!report.contains("Snowflake CLI connectivity diagnostics"));
}

// ------------------------------------------------------------ the binary

fn snow() -> Command {
    let mut cmd = Command::cargo_bin("snow-rs").unwrap();
    cmd.env_clear();
    crate::common::keep_system_env(&mut cmd);
    if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
        cmd.env("LLVM_PROFILE_FILE", profile);
    }
    cmd
}

#[test]
fn the_binary_probes_local_sockets_listed_in_the_allowlist_file() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let server = MockServer::start();
    mock_select_1(&server);
    let dir = tempfile::tempdir().unwrap();
    let allowlist = dir.path().join("allowlist.json");
    std::fs::write(
        &allowlist,
        format!(
            r#"[{{"type":"STAGE","host":"127.0.0.1","port":{port}}},
                {{"type":"OUT_OF_BAND_TELEMETRY","host":"127.0.0.1","port":{closed}}}]"#
        ),
    )
    .unwrap();
    let key = key_path("unencrypted.p8");
    let out = snow()
        .env("SNOWFLAKE_HOME", dir.path())
        .env("SNOWFLAKE_PROTOCOL", "http")
        .args([
            "connection",
            "test",
            "-x",
            "--account",
            "acct",
            "--user",
            "u",
            "--authenticator",
            "SNOWFLAKE_JWT",
            "--private-key-file",
            key.to_str().unwrap(),
            "--host",
            &server.host(),
            "--port",
            &server.port().to_string(),
            "--print-diag",
            "--diag-allowlist-path",
            allowlist.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .stderr("")
        .get_output()
        .stdout
        .clone();
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let checks = parsed["Diagnostic"]["checks"].as_array().unwrap();
    assert_eq!(checks[0]["status"], "Healthy");
    assert!(checks[0]["latency_ms"].is_number());
    assert_eq!(checks[1]["status"], "Unhealthy");
    assert!(
        checks[1]["error"].as_str().unwrap().starts_with("[Errno "),
        "{}",
        checks[1]["error"]
    );
}

#[test]
fn the_binary_lists_the_diag_options_in_help() {
    snow()
        .args(["connection", "test", "--help"])
        .assert()
        .success()
        .stdout(contains("--enable-diag"))
        .stdout(contains("--diag-log-path"))
        .stdout(contains("--diag-allowlist-path"))
        .stdout(contains("--print-diag"));
}

#[test]
fn a_failed_sign_in_wins_over_an_unwritable_report() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method("POST").path(STATEMENTS);
        then.status(401).body("{}");
    });
    let dir = tempfile::tempdir().unwrap();
    // A directory where the report file should go: writing it fails.
    std::fs::create_dir(dir.path().join("SnowflakeConnectionTestReport.txt")).unwrap();
    let r = run(
        &server,
        &[
            "--enable-diag",
            "--diag-log-path",
            dir.path().to_str().unwrap(),
        ],
        OutputFormat::Table,
    );
    let message = r.result.unwrap_err().to_string();
    assert!(!message.contains("diagnostic report"), "{message}");
}
