//! Asynchronous statements (`;>`) in `snow sql`, end to end: the CLI runs in-process
//! against a mocked Snowflake (`login-request`, `query-request`, `/monitoring/queries`). The goldens
//! in `tests/golden/async/cases.json` hold what snow 3.34.0 printed for the same inputs on the
//! sandbox (`scripts/capture-goldens.sh --async`), query ids replaced by a token.

use crate::common;
use httpmock::{Method, MockServer};
use serde_json::{Value, json};
use snowflake_cli_rs::commands::TerminalPrompter;
use snowflake_cli_rs::env::Env;
use std::path::Path;

const LOGIN: &str = "/session/v1/login-request";
const QUERY: &str = "/queries/v1/query-request";
const ASYNC_ID: &str = "01c890e3-0002-73e5-0002-fee60001ecda";
const ID_TOKEN: &str = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";

/// Runs `snow sql -x <args>` against `server`, with `stdin` piped when given.
fn run(
    server: &MockServer,
    args: &[String],
    stdin: Option<&str>,
    extra_env: &[(&str, &str)],
) -> (i32, String, String) {
    let home = tempfile::tempdir().unwrap();
    let mut pairs = vec![
        (
            "SNOWFLAKE_HOME".to_string(),
            home.path().display().to_string(),
        ),
        ("SNOWFLAKE_ACCOUNT".into(), "testacct".into()),
        ("SNOWFLAKE_USER".into(), "tester".into()),
        ("SNOWFLAKE_HOST".into(), server.host()),
        ("SNOWFLAKE_PORT".into(), server.port().to_string()),
        ("SNOWFLAKE_PROTOCOL".into(), "http".into()),
        ("SNOWFLAKE_AUTHENTICATOR".into(), "SNOWFLAKE_JWT".into()),
        (
            "SNOWFLAKE_PRIVATE_KEY_FILE".into(),
            common::key_path("unencrypted.p8").display().to_string(),
        ),
    ];
    pairs.extend(
        extra_env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string())),
    );
    let env = Env::from_pairs(pairs);
    let argv = ["snow-rs", "sql", "-x"]
        .iter()
        .map(|s| s.to_string())
        .chain(args.iter().cloned());
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut input: &[u8] = stdin.unwrap_or("").as_bytes();
    let _log = common::logger_guard();
    let code = snowflake_cli_rs::run_with(
        argv,
        env,
        snowflake_cli_rs::Stdin {
            is_tty: stdin.is_none(),
            reader: &mut input,
        },
        &mut TerminalPrompter,
        None,
        &mut out,
        &mut err,
    );
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn mock_login(server: &MockServer) -> httpmock::Mock<'_> {
    server.mock(|when, then| {
        when.method(Method::POST).path(LOGIN);
        then.status(200).json_body(json!({
            "success": true,
            "data": {
                "token": "session-token", "masterToken": "master-token",
                "parameters": [{"name": "TIMEZONE", "value": "UTC"}],
            },
        }));
    })
}

fn mock_close(server: &MockServer) -> httpmock::Mock<'_> {
    server.mock(|when, then| {
        when.method(Method::POST)
            .path("/session")
            .query_param("delete", "true");
        then.status(200).json_body(json!({"success": true}));
    })
}

/// The status of the submitted statement, checked before the session is ended.
fn mock_status<'a>(server: &'a MockServer, status: &str) -> httpmock::Mock<'a> {
    let body = json!({"success": true, "data": {"queries": [{"id": ASYNC_ID, "status": status}]}});
    server.mock(|when, then| {
        when.method(Method::GET)
            .path(format!("/monitoring/queries/{ASYNC_ID}"))
            .header("authorization", "Snowflake Token=\"session-token\"");
        then.status(200).json_body(body);
    })
}

/// `asyncExec: true` is answered at once with `333334` (the statement is detached).
fn mock_submit(server: &MockServer) -> httpmock::Mock<'_> {
    server.mock(|when, then| {
        when.method(Method::POST)
            .path(QUERY)
            .query_param_matches("requestId", common::UUID)
            .body_includes("\"asyncExec\":true");
        then.status(200).json_body(json!({
            "success": true, "code": "333334", "message": null,
            "data": {"queryId": ASYNC_ID, "getResultUrl": format!("/queries/{ASYNC_ID}/result")},
        }));
    })
}

/// Answers the waited-for `query-request` whose `sqlText` starts with `prefix`.
fn mock_rows<'a>(server: &'a MockServer, prefix: &str, column: &str, value: &str, fixed: bool) {
    let needle = format!(
        "\"sqlText\":{}",
        serde_json::to_string(prefix).unwrap().trim_end_matches('"')
    );
    let row_type = if fixed {
        json!([{"name": column, "type": "fixed", "precision": 1, "scale": 0, "nullable": false}])
    } else {
        json!([{"name": column, "type": "text", "length": 256, "nullable": true}])
    };
    let data = json!({
        "queryId": "01c890e3-0002-73e5-0002-000000000001",
        "rowtype": row_type, "rowset": [[value]], "total": 1,
    });
    let _: httpmock::Mock<'a> = server.mock(|when, then| {
        when.method(Method::POST)
            .path(QUERY)
            .body_includes("\"asyncExec\":false")
            .body_includes(needle);
        then.status(200)
            .json_body(json!({"success": true, "code": null, "message": null, "data": data}));
    });
}

/// Every statement the goldens wait for.
fn arrange(server: &MockServer) {
    mock_login(server);
    mock_close(server);
    mock_submit(server);
    mock_status(server, "SUCCESS");
    for (n, column) in [("1", "A"), ("2", "B"), ("3", "C")] {
        mock_rows(
            server,
            &format!("select {n} as {}", column.to_lowercase()),
            column,
            n,
            true,
        );
    }
    let done = "Statement executed successfully.";
    for statement in ["BEGIN", "COMMIT", "ALTER SESSION SET AUTOCOMMIT"] {
        mock_rows(server, statement, "status", done, false);
    }
}

fn ids_replaced(text: &str) -> String {
    text.replace(ASYNC_ID, ID_TOKEN)
}

#[test]
fn async_output_matches_snow() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/async/cases.json");
    let cases: Vec<Value> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert!(cases.len() >= 12);
    let server = MockServer::start();
    arrange(&server);
    let mut failures = Vec::new();
    for case in &cases {
        let name = case["name"].as_str().unwrap();
        let work = tempfile::tempdir().unwrap();
        let w = work.path().display().to_string();
        let mut args: Vec<String> = Vec::new();
        if let Some(query) = case["query"].as_str() {
            args.extend(["-q".into(), query.into()]);
        }
        for (i, text) in case["files"].as_array().into_iter().flatten().enumerate() {
            let file = work.path().join(format!("input{}.sql", i + 1));
            std::fs::write(&file, text.as_str().unwrap()).unwrap();
            args.extend(["-f".into(), file.display().to_string()]);
        }
        let stdin = case["stdin"].as_str();
        if stdin.is_some() {
            args.push("-i".into());
        }
        for extra in case["args"].as_array().into_iter().flatten() {
            args.push(extra.as_str().unwrap().into());
        }
        for (format, expected) in case["runs"].as_object().unwrap() {
            let mut argv = args.clone();
            argv.extend(["--format".into(), format.clone()]);
            let (code, stdout, stderr) = run(&server, &argv, stdin, &[]);
            let restore = |text: &str| ids_replaced(text).replace(&w, "{WORK}");
            let actual =
                json!({"stdout": restore(&stdout), "stderr": restore(&stderr), "exit": code});
            if &actual != expected {
                failures.push(format!(
                    "{name} {format}\n--- snow\n{}{}\n--- snow-rs\n{}{}",
                    expected["stdout"].as_str().unwrap(),
                    expected["stderr"].as_str().unwrap(),
                    actual["stdout"].as_str().unwrap(),
                    actual["stderr"].as_str().unwrap(),
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

#[test]
fn the_statement_is_submitted_without_its_suffix_on_a_session() {
    let server = MockServer::start();
    let login = mock_login(&server);
    let close = mock_close(&server);
    let status = mock_status(&server, "SUCCESS");
    let submit = server.mock(|when, then| {
        when.method(Method::POST)
            .path(QUERY)
            .json_body_includes(json!({"sqlText": "select 1 as a", "asyncExec": true}).to_string());
        then.status(200).json_body(json!({
            "success": true, "code": "333334",
            "data": {"queryId": ASYNC_ID, "getResultUrl": "/x"},
        }));
    });
    // With the key pair a run without `;>` would use the SQL API: `;>` needs the session.
    let args = vec!["-q".to_string(), " select 1 as a ;>".into()];
    let (code, stdout, stderr) = run(&server, &args, None, &[]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.contains(ASYNC_ID));
    login.assert();
    submit.assert();
    status.assert();
    close.assert();
}

#[test]
fn the_session_stays_open_while_a_submitted_statement_runs() {
    for (status, closed) in [("RUNNING", 0), ("QUEUED", 0), ("FAILED_WITH_ERROR", 1)] {
        let server = MockServer::start();
        mock_login(&server);
        mock_submit(&server);
        let close = mock_close(&server);
        let check = mock_status(&server, status);
        let args = vec!["-q".to_string(), "select 1 as a;>".into()];
        let (code, _, stderr) = run(&server, &args, None, &[]);
        assert_eq!(code, 0, "{stderr}");
        check.assert();
        close.assert_calls(closed);
    }
    // No row yet is still running; no `queries` at all is a failure, so the session ends.
    for (body, closed) in [
        (json!({"success": true, "data": {"queries": []}}), 0),
        (json!({"success": true, "data": {}}), 1),
    ] {
        let server = MockServer::start();
        mock_login(&server);
        mock_submit(&server);
        let close = mock_close(&server);
        server.mock(|when, then| {
            when.method(Method::GET)
                .path_includes("/monitoring/queries/");
            then.status(200).json_body(body);
        });
        let args = vec!["-q".to_string(), "select 1 as a;>".into()];
        run(&server, &args, None, &[]);
        close.assert_calls(closed);
    }
}

#[test]
fn a_submission_that_is_not_detached_is_waited_for_and_errors_are_reported() {
    // A statement the server answers at once (no `333334`) is waited for like any other.
    let server = MockServer::start();
    mock_login(&server);
    mock_close(&server);
    mock_status(&server, "SUCCESS");
    server.mock(|when, then| {
        when.method(Method::POST)
            .path(QUERY)
            .body_includes("\"asyncExec\":true");
        then.status(200).json_body(json!({
            "success": true, "code": "333333",
            "data": {"queryId": ASYNC_ID, "getResultUrl": "/queries/q/result"},
        }));
    });
    let result = server.mock(|when, then| {
        when.method(Method::GET).path("/queries/q/result");
        then.status(200).json_body(json!({
            "success": true, "code": null, "data": {"queryId": ASYNC_ID, "rowtype": [], "rowset": []},
        }));
    });
    let args = vec![
        "-q".to_string(),
        "select 1 as a;>".into(),
        "--format".into(),
        "csv".into(),
    ];
    let (code, stdout, stderr) = run(&server, &args, None, &[]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout, format!("scheduled query ID\n{ASYNC_ID}\n"));
    result.assert();

    // A rejected submission stops the run with the server's error.
    let server = MockServer::start();
    mock_login(&server);
    mock_close(&server);
    server.mock(|when, then| {
        when.method(Method::POST)
            .path(QUERY)
            .body_includes("\"asyncExec\":true");
        then.status(200).json_body(json!({
            "success": false, "code": "002003", "message": "Object does not exist.",
            "data": {"queryId": ASYNC_ID, "sqlState": "02000"},
        }));
    });
    mock_rows(&server, "select 2 as b", "B", "2", true);
    let args = vec!["-q".to_string(), "select 1 as a;> select 2 as b".into()];
    let (code, stdout, stderr) = run(&server, &args, None, &[]);
    assert_eq!(code, 1);
    assert_eq!(stdout, "select 1 as a\n");
    assert!(stderr.contains("002003 (02000)"), "{stderr}");
}

#[test]
fn server_session_keep_alive_skips_the_status_check() {
    let server = MockServer::start();
    mock_login(&server);
    mock_submit(&server);
    let close = mock_close(&server);
    let check = mock_status(&server, "SUCCESS");
    let args = vec![
        "-q".to_string(),
        "select 1 as a;>".into(),
        "--server-session-keep-alive".into(),
    ];
    let (code, _, stderr) = run(&server, &args, None, &[]);
    assert_eq!(code, 0, "{stderr}");
    check.assert_calls(0);
    close.assert_calls(0);
}
