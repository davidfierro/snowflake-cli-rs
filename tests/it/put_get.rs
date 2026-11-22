//! `PUT`/`GET` in `snow sql`, end to end (ADR 0005, Decisions 1, 5 and 7): the CLI runs
//! in-process against a mocked Snowflake (`login-request`, `query-request`) whose `PUT`/`GET`
//! answers name a `LOCAL_FS` stage, so the files really move. The goldens in
//! `tests/golden/put_get/cases.json` hold what snow 3.34.0 printed for the same statements on the
//! sandbox's encrypted S3 stage (`scripts/capture-goldens.sh --put-get`); with the same encryption
//! material the sizes match byte for byte.

use crate::common;
use httpmock::{Method, MockServer};
use serde_json::{Value, json};
use snowflake_cli_rs::commands::TerminalPrompter;
use snowflake_cli_rs::env::Env;
use std::path::Path;

const LOGIN: &str = "/session/v1/login-request";
const QUERY: &str = "/queries/v1/query-request";
const STAGE: &str = "goldens_test";
// Used only by the Unix-only golden test below.
#[cfg(unix)]
/// `gzip.compress(b"x\n", mtime=0)`: the 22-byte `g.csv.gz` of the goldens.
const G_CSV_GZ: &str = "1f8b08000000000002ffabe002001f08ea4602000000";

fn material() -> Value {
    json!({"queryStageMasterKey": "BwcHBwcHBwcHBwcHBwcHBw==", "queryId": "q", "smkId": 1})
}

/// Runs `snow sql -x <args>` against `server`; returns `(exit code, stdout, stderr)`.
fn run(server: &MockServer, args: &[&str], extra_env: &[(&str, &str)]) -> (i32, String, String) {
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
    let args = ["snow-rs", "sql", "-x"].iter().chain(args).copied();
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

/// A successful sign-in, checked as ADR 0005 Decision 4 describes it.
fn mock_login(server: &MockServer) -> httpmock::Mock<'_> {
    server.mock(|when, then| {
        when.method(Method::POST)
            .path(LOGIN)
            .query_param_matches("request_id", common::UUID)
            .header("accept", "application/json")
            .json_body_includes(
                json!({"data": {
                    "ACCOUNT_NAME": "testacct",
                    "LOGIN_NAME": "tester",
                    "AUTHENTICATOR": "SNOWFLAKE_JWT",
                    "CLIENT_APP_ID": "snowflake-cli-rs",
                    "SESSION_PARAMETERS": {"PYTHON_CONNECTOR_QUERY_RESULT_FORMAT": "json"},
                }})
                .to_string(),
            )
            .body_matches(r#""TOKEN":"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+""#);
        then.status(200).json_body(json!({
            "success": true,
            "data": {
                "token": "session-token", "masterToken": "master-token",
                "parameters": [{"name": "TIMEZONE", "value": "UTC"}],
            },
        }));
    })
}

/// Answers the `query-request` whose `sqlText` starts with `prefix`.
fn mock_query<'a>(server: &'a MockServer, prefix: &str, data: Value) -> httpmock::Mock<'a> {
    let needle = format!(
        "\"sqlText\":{}",
        serde_json::to_string(prefix).unwrap().trim_end_matches('"')
    );
    server.mock(|when, then| {
        when.method(Method::POST)
            .path(QUERY)
            .header_matches("authorization", r#"^Snowflake Token="[a-z-]+"$"#)
            .query_param_matches("requestId", common::UUID)
            .body_includes(needle);
        then.status(200)
            .json_body(json!({"success": true, "code": null, "message": null, "data": data}));
    })
}

fn mock_close(server: &MockServer) -> httpmock::Mock<'_> {
    server.mock(|when, then| {
        when.method(Method::POST)
            .path("/session")
            .query_param("delete", "true")
            .header("authorization", "Snowflake Token=\"session-token\"");
        then.status(200).json_body(json!({"success": true}));
    })
}

fn upload(sources: &[String], stage: &Path, extra: Value) -> Value {
    let mut data = json!({
        "command": "UPLOAD", "src_locations": sources, "parallel": 4, "overwrite": false,
        "autoCompress": true, "sourceCompression": "auto_detect",
        "stageInfo": {"locationType": "LOCAL_FS", "location": stage.display().to_string(), "creds": {}},
        "encryptionMaterial": material(), "queryId": "01-put",
    });
    for (k, v) in extra.as_object().unwrap() {
        data[k] = v.clone();
    }
    data
}

fn download(sources: &[&str], stage: &Path, local: &str) -> Value {
    json!({
        "command": "DOWNLOAD", "src_locations": sources, "parallel": 10,
        "stageInfo": {"locationType": "LOCAL_FS", "location": stage.display().to_string(), "creds": {}},
        "localLocation": local, "queryId": "01-get",
    })
}

/// The files of the goldens, in a fresh directory.
fn data_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("f1.csv"), b"a,b\n1,2\n").unwrap();
    std::fs::write(dir.path().join("f2.csv"), b"x\n").unwrap();
    let gz: Vec<u8> = (0..G_CSV_GZ.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&G_CSV_GZ[i..i + 2], 16).unwrap())
        .collect();
    std::fs::write(dir.path().join("g.csv.gz"), gz).unwrap();
    std::fs::write(dir.path().join("z.xz"), b"x").unwrap();
    std::fs::create_dir(dir.path().join("out")).unwrap();
    dir
}

// Used only by the Unix-only golden test below.
#[cfg(unix)]
/// Sets up the mocked answers of one golden case.
fn arrange(name: &str, server: &MockServer, data: &Path, stage: &Path) {
    let d = data.display().to_string();
    let stage_files = stage.join(STAGE);
    std::fs::create_dir_all(&stage_files).unwrap();
    match name {
        "put_wildcard" => {
            mock_query(
                server,
                "PUT",
                upload(&[format!("{d}/f*.csv")], &stage_files, json!({})),
            );
        }
        "put_existing_skipped" => {
            std::fs::write(stage_files.join("f1.csv.gz"), b"old").unwrap();
            std::fs::write(stage_files.join("f2.csv.gz"), b"old").unwrap();
            mock_query(
                server,
                "PUT",
                upload(&[format!("{d}/f*.csv")], &stage_files, json!({})),
            );
        }
        "put_no_compress_overwrite" => {
            mock_query(
                server,
                "PUT",
                upload(
                    &[format!("{d}/f1.csv")],
                    &stage_files,
                    json!({"autoCompress": false, "overwrite": true}),
                ),
            );
        }
        "put_already_gzip" => {
            mock_query(
                server,
                "PUT",
                upload(&[format!("{d}/g.csv.gz")], &stage_files, json!({})),
            );
        }
        "get_files" => {
            std::fs::write(stage_files.join("f1.csv.gz"), vec![1u8; 37]).unwrap();
            std::fs::write(stage_files.join("f2.csv.gz"), vec![2u8; 31]).unwrap();
            let sources = [format!("{STAGE}/f1.csv.gz"), format!("{STAGE}/f2.csv.gz")];
            let sources: Vec<&str> = sources.iter().map(String::as_str).collect();
            mock_query(
                server,
                "GET",
                download(&sources, stage, &format!("{d}/out/")),
            );
        }
        "select_then_put" => {
            mock_query(
                server,
                "SELECT",
                json!({
                    "rowtype": [{"name": "A", "type": "fixed", "precision": 1, "scale": 0, "nullable": false}],
                    "rowset": [["1"]], "queryId": "01-select",
                }),
            );
            mock_query(
                server,
                "PUT",
                upload(
                    &[format!("{d}/f2.csv")],
                    &stage_files.join("sub"),
                    json!({"overwrite": true}),
                ),
            );
        }
        "error_missing_file" => {
            mock_query(
                server,
                "PUT",
                upload(&["/nonexistent/x.csv".into()], &stage_files, json!({})),
            );
        }
        "error_directory" => {
            mock_query(
                server,
                "PUT",
                upload(&["/tmp".into()], &stage_files, json!({})),
            );
        }
        "error_unsupported_compression" => {
            mock_query(
                server,
                "PUT",
                upload(&[format!("{d}/z.xz")], &stage_files, json!({})),
            );
        }
        "error_local_path" => {
            mock_query(server, "GET", download(&["x/a"], stage, "/nonexistent/"));
        }
        "error_nothing_to_get" => {
            mock_query(server, "GET", download(&[], stage, &format!("{d}/out/")));
        }
        other => panic!("no arrangement for golden case {other}"),
    }
}

// The goldens are snow's output for POSIX paths (`file:///tmp`).
#[cfg(unix)]
#[test]
fn put_get_output_matches_snow() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/put_get/cases.json");
    let cases: Vec<Value> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert!(cases.len() >= 10);
    let mut failures = Vec::new();
    for case in &cases {
        let name = case["name"].as_str().unwrap();
        for (format, expected) in case["runs"].as_object().unwrap() {
            let server = MockServer::start();
            let data = data_dir();
            let stage = tempfile::tempdir().unwrap();
            mock_login(&server);
            mock_close(&server);
            arrange(name, &server, data.path(), stage.path());
            let d = data.path().display().to_string();
            let sql = case["sql"]
                .as_str()
                .unwrap()
                .replace("{DATA}", &d)
                .replace("{STAGE}", STAGE);
            let (code, stdout, stderr) = run(&server, &["-q", &sql, "--format", format], &[]);
            let restore = |text: &str| text.replace(&d, "{DATA}").replace(STAGE, "{STAGE}");
            let actual = json!({
                "stdout": restore(&stdout), "stderr": restore(&stderr), "exit": code,
            });
            if &actual != expected {
                failures.push(format!(
                    "{name} {format}\n--- snow\n{}\n{}\n--- snow-rs\n{}\n{}",
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
fn put_then_get_round_trips_the_bytes() {
    let server = MockServer::start();
    let data = data_dir();
    let stage = tempfile::tempdir().unwrap();
    let login = mock_login(&server);
    let close = mock_close(&server);
    let d = data.path().display().to_string();
    mock_query(
        &server,
        "PUT",
        upload(
            &[format!("{d}/f1.csv")],
            stage.path(),
            json!({"encryptionMaterial": null, "autoCompress": false}),
        ),
    );
    mock_query(
        &server,
        "GET",
        download(&["f1.csv"], stage.path(), &format!("{d}/out")),
    );
    let sql = format!("PUT file://{d}/f1.csv @~; GET @~ file://{d}/out");
    let (code, stdout, stderr) = run(&server, &["-q", &sql, "--format", "csv"], &[]);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stdout.contains("f1.csv,f1.csv,8,8,NONE,NONE,UPLOADED,"),
        "{stdout}"
    );
    assert!(stdout.contains("f1.csv,8,DOWNLOADED,"), "{stdout}");
    assert_eq!(
        std::fs::read(data.path().join("out/f1.csv")).unwrap(),
        b"a,b\n1,2\n"
    );
    // One sign-in for the whole run, and the session is closed at the end.
    login.assert_calls(1);
    close.assert_calls(1);
}

#[test]
fn runs_without_put_or_get_stay_on_the_sql_api() {
    let server = MockServer::start();
    let login = mock_login(&server);
    let api = server.mock(|when, then| {
        common::submit(when, "SELECT 1");
        then.status(200).json_body(common::one_int_body("1"));
    });
    let (code, stdout, stderr) = run(
        &server,
        &["-q", "SELECT 1", "--format", "csv"],
        &[
            ("SNOWFLAKE_DATABASE", "TEST_DB"),
            ("SNOWFLAKE_SCHEMA", "PUBLIC"),
            ("SNOWFLAKE_ROLE", "TEST_ROLE"),
            ("SNOWFLAKE_WAREHOUSE", "TEST_WH"),
        ],
    );
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout, "N\n1\n");
    api.assert();
    login.assert_calls(0);
}

#[test]
fn session_statements_poll_renew_and_page_through_chunks() {
    let server = MockServer::start();
    mock_login(&server);
    mock_close(&server);
    let data = data_dir();
    let d = data.path().display().to_string();
    // The SELECT is still running at first: poll its result URL.
    server.mock(|when, then| {
        when.method(Method::POST)
            .path(QUERY)
            .body_includes("\"sqlText\":\"SELECT");
        then.status(200).json_body(json!({
            "success": true, "code": "333334", "message": "running",
            "data": {"getResultUrl": "/queries/01-sel/result", "queryId": "01-sel"},
        }));
    });
    // The first poll finds the session token expired: renew with the master token, replay.
    server.mock(|when, then| {
        when.method(Method::GET)
            .path("/queries/01-sel/result")
            .header("authorization", "Snowflake Token=\"session-token\"");
        then.status(200)
            .json_body(json!({"success": false, "code": "390112", "message": "expired"}));
    });
    let renew = server.mock(|when, then| {
        when.method(Method::POST)
            .path("/session/token-request")
            .header("authorization", "Snowflake Token=\"master-token\"")
            .json_body_includes(json!({"oldSessionToken": "session-token", "requestType": "RENEW"}).to_string());
        then.status(200).json_body(json!({"success": true, "data": {"sessionToken": "fresh-token", "masterToken": "master-2"}}));
    });
    let chunk_url = server.url("/chunks/0");
    server.mock(|when, then| {
        when.method(Method::GET)
            .path("/queries/01-sel/result")
            .header("authorization", "Snowflake Token=\"fresh-token\"");
        then.status(200).json_body(json!({"success": true, "data": {
            "queryId": "01-sel",
            "rowtype": [
                {"name": "N", "type": "fixed", "precision": 38, "scale": 0, "nullable": false},
                {"name": "B", "type": "boolean", "nullable": true},
                {"name": "T", "type": "timestamp_ltz", "scale": 3, "nullable": true},
            ],
            "rowset": [["1", "1", "0.000"]],
            "chunks": [{"url": chunk_url, "rowCount": 2}],
            "qrmk": "chunk-key",
            "parameters": [{"name": "TIMEZONE", "value": "Europe/Madrid"}],
        }}));
    });
    let chunk = server.mock(|when, then| {
        when.method(Method::GET)
            .path("/chunks/0")
            .header("x-amz-server-side-encryption-customer-key", "chunk-key");
        then.status(200)
            .body(r#"["2","0",null],["3",null,"86400.500"]"#);
    });
    let close = server.mock(|when, then| {
        when.method(Method::POST)
            .path("/session")
            .header("authorization", "Snowflake Token=\"fresh-token\"");
        then.status(200).json_body(json!({"success": true}));
    });
    let stage = tempfile::tempdir().unwrap();
    mock_query(
        &server,
        "PUT",
        upload(&[format!("{d}/f2.csv")], stage.path(), json!({})),
    );
    let sql = format!("SELECT n FROM t; PUT file://{d}/f2.csv @~");
    let (code, stdout, stderr) = run(&server, &["-q", &sql, "--format", "csv"], &[]);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stdout.starts_with(
            "N,B,T\n1,True,1970-01-01T01:00:00+01:00\n2,False,\n3,,1970-01-02T01:00:00.500000+01:00\n\n"
        ),
        "{stdout}"
    );
    renew.assert_calls(1);
    chunk.assert();
    close.assert();
}

#[test]
fn session_sql_errors_and_sign_in_failures() {
    let server = MockServer::start();
    mock_login(&server);
    mock_close(&server);
    server.mock(|when, then| {
        when.method(Method::POST).path(QUERY);
        then.status(200).json_body(json!({
            "success": false, "code": "002003", "message": "Stage 'NOPE' does not exist.",
            "data": {"sqlState": "02000", "queryId": "01c8-0000"},
        }));
    });
    let (code, stdout, stderr) = run(
        &server,
        &["-q", "PUT file:///x @nope", "--format", "json"],
        &[],
    );
    assert_eq!(code, 1);
    assert_eq!(stdout, "");
    assert!(
        stderr.contains("002003 (02000): 01c8-0000: Stage 'NOPE' does not exist."),
        "{stderr}"
    );
    let (code, _, _) = run(
        &server,
        &[
            "-q",
            "GET @nope file:///tmp",
            "--format",
            "json",
            "--enhanced-exit-codes",
        ],
        &[],
    );
    assert_eq!(code, 5);

    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(Method::POST).path(LOGIN);
        then.status(200).json_body(
            json!({"success": false, "code": "390144", "message": "JWT token is invalid."}),
        );
    });
    let (code, _, stderr) = run(&server, &["-q", "PUT file:///x @~"], &[]);
    assert_eq!(code, 1);
    // snow's text: `Could not connect to Snowflake. Reason: 390144 (28000): Failed to connect to
    // DB: <host>:<port>. JWT token is invalid.` (the panel wraps it).
    assert!(
        stderr.contains("Reason: 390144 (28000): Failed to connect to"),
        "{stderr}"
    );
    assert!(stderr.contains("JWT token is invalid."), "{stderr}");
}

#[test]
fn single_transaction_and_secondary_roles_on_a_session() {
    let server = MockServer::start();
    let login = server.mock(|when, then| {
        when.method(Method::POST)
            .path(LOGIN)
            .json_body_includes(json!({"data": {"SECONDARY_ROLES": "ALL"}}).to_string());
        then.status(200).json_body(
            json!({"success": true, "data": {"token": "session-token", "masterToken": "m"}}),
        );
    });
    mock_close(&server);
    let ok = json!({"rowtype": [{"name": "status", "type": "text"}], "rowset": [["ok"]], "queryId": "1"});
    let autocommit = mock_query(&server, "ALTER SESSION SET AUTOCOMMIT = FALSE", ok.clone());
    let begin = mock_query(&server, "BEGIN", ok.clone());
    let commit = mock_query(&server, "COMMIT", ok);
    let data = data_dir();
    let stage = tempfile::tempdir().unwrap();
    let d = data.path().display().to_string();
    mock_query(
        &server,
        "PUT",
        upload(&[format!("{d}/f2.csv")], stage.path(), json!({})),
    );
    let sql = format!("PUT file://{d}/f2.csv @~");
    let (code, stdout, stderr) = run(
        &server,
        &[
            "-q",
            &sql,
            "--single-transaction",
            "--secondary-roles",
            "all",
            "--format",
            "csv",
        ],
        &[],
    );
    assert_eq!(code, 0, "{stderr}");
    assert!(stdout.starts_with("status\nok\n\nsource,"), "{stdout}");
    login.assert();
    autocommit.assert();
    begin.assert();
    commit.assert();
}

#[test]
fn session_failures_are_reported() {
    // An HTTP error from query-request.
    let server = MockServer::start();
    mock_login(&server);
    mock_close(&server);
    server.mock(|when, then| {
        when.method(Method::POST).path(QUERY);
        then.status(500).json_body(json!({"message": "boom"}));
    });
    let (code, _, stderr) = run(&server, &["-q", "GET @~ file:///tmp"], &[]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("Snowflake returned HTTP 500: boom"),
        "{stderr}"
    );

    // The session expired and cannot be renewed.
    let server = MockServer::start();
    mock_login(&server);
    mock_close(&server);
    server.mock(|when, then| {
        when.method(Method::POST).path(QUERY);
        then.status(200)
            .json_body(json!({"success": false, "code": 390112, "message": "expired"}));
    });
    server.mock(|when, then| {
        when.method(Method::POST).path("/session/token-request");
        then.status(200)
            .json_body(json!({"success": false, "code": "390114", "message": "master expired"}));
    });
    let (code, _, stderr) = run(&server, &["-q", "GET @~ file:///tmp"], &[]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("The Snowflake session expired. Sign in again."),
        "{stderr}"
    );

    // Renewed, but the replay is rejected again.
    let server = MockServer::start();
    mock_login(&server);
    mock_close(&server);
    server.mock(|when, then| {
        when.method(Method::POST).path(QUERY);
        then.status(200)
            .json_body(json!({"success": false, "code": "390112", "message": "expired"}));
    });
    server.mock(|when, then| {
        when.method(Method::POST).path("/session/token-request");
        then.status(200)
            .json_body(json!({"success": true, "data": {"sessionToken": "t2"}}));
    });
    let (code, _, stderr) = run(&server, &["-q", "GET @~ file:///tmp"], &[]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("The Snowflake session expired."),
        "{stderr}"
    );

    // A running statement without a result URL.
    let server = MockServer::start();
    mock_login(&server);
    mock_close(&server);
    server.mock(|when, then| {
        when.method(Method::POST).path(QUERY);
        then.status(200)
            .json_body(json!({"success": true, "code": "333333", "data": {}}));
    });
    let (code, _, stderr) = run(&server, &["-q", "GET @~ file:///tmp"], &[]);
    assert_eq!(code, 1);
    assert!(stderr.contains("no getResultUrl"), "{stderr}");

    // Sign-in refused with an HTTP status; nothing listens at all.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(Method::POST).path(LOGIN);
        then.status(403).body("forbidden");
    });
    let (code, _, stderr) = run(&server, &["-q", "PUT file:///x @~"], &[]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("Failed to connect to Snowflake: no error message"),
        "{stderr}"
    );
    let (code, _, stderr) = run(
        &server,
        &["-q", "PUT file:///x @~"],
        &[("SNOWFLAKE_PORT", "1")],
    );
    assert_eq!(code, 1);
    assert!(
        stderr.contains("Failed to connect to Snowflake at http://"),
        "{stderr}"
    );
}

#[test]
fn a_session_from_existing_tokens_queries_and_closes() {
    use snowflake_cli_rs::secret::Secret;
    use snowflake_cli_rs::session::{Session, SessionOptions};
    let server = MockServer::start();
    let query = server.mock(|when, then| {
        when.method(Method::POST)
            .path(QUERY)
            .header("authorization", "Snowflake Token=\"given\"");
        then.status(200).json_body(json!({"success": true, "data": {
            "queryId": "01-q", "rowtype": [{"name": "X", "type": "text"}], "rowset": [["v"]],
        }}));
    });
    let close = server.mock(|when, then| {
        when.method(Method::POST)
            .path("/session")
            .query_param("delete", "true");
        then.status(200).json_body(json!({"success": true}));
    });
    let conn = common::connection(&server);
    let session = Session::from_tokens(
        &conn,
        Secret::new("given"),
        Secret::new("master"),
        SessionOptions::default(),
    )
    .unwrap();
    let response = session.query("SELECT 'v' AS x").unwrap();
    assert_eq!(response.query_id, "01-q");
    assert!(response.transfer_command().is_none());
    let rows = response.into_rows(&session).unwrap().into_result().unwrap();
    assert_eq!(rows.rows.len(), 1);
    session.close().unwrap();
    query.assert();
    close.assert();
}
