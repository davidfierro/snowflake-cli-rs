//! `SqlClient::run_script` against mocked SQL API responses (ADR 0004, Decisions 1, 3, 5 and 7).

use crate::common;

use httpmock::{Mock, MockServer};
use serde_json::{Value as Json, json};
use snowflake_cli_rs::error::ErrorKind;
use snowflake_cli_rs::sql::{RowStream, ScriptOptions, ScriptRun, Value};
use std::time::{Duration, Instant};

const PARENT: &str = "aaaaaaaa-0000-0000-0000-000000000000";

fn child(n: usize) -> String {
    format!("cccccccc-0000-0000-0000-{n:012}")
}

fn statements(texts: &[&str]) -> Vec<String> {
    texts.iter().map(|s| s.to_string()).collect()
}

/// The multi-statement POST of `request` with `count`, answered with `status` and `body`.
fn multi<'a>(
    server: &'a MockServer,
    request: &str,
    count: usize,
    status: u16,
    body: Json,
) -> Mock<'a> {
    server.mock(|when, then| {
        common::submit(when, request).json_body_includes(
            json!({"parameters": {"MULTI_STATEMENT_COUNT": count.to_string()}}).to_string(),
        );
        then.status(status).json_body(body);
    })
}

fn parent_ok(children: usize) -> Json {
    json!({
        "statementHandle": PARENT,
        "statementHandles": (1..=children).map(child).collect::<Vec<_>>(),
        "code": "090001",
        "message": "Statement executed successfully.",
        "resultSetMetaData": {"rowType": [{"name": "multiple statement execution", "type": "text"}]},
        "data": [["Multiple statements executed successfully."]],
    })
}

/// `GET /api/v2/statements/{handle}` answered with `body`.
fn get<'a>(server: &'a MockServer, handle: &str, body: Json) -> Mock<'a> {
    let path = format!("{}/{handle}", common::STATEMENTS);
    server.mock(|when, then| {
        common::authorized(when)
            .method("GET")
            .path(path)
            .query_param_missing("partition");
        then.status(200).json_body(body);
    })
}

/// `get`, answered after `delay`.
fn get_delayed<'a>(server: &'a MockServer, handle: &str, body: Json, delay: Duration) -> Mock<'a> {
    let path = format!("{}/{handle}", common::STATEMENTS);
    server.mock(|when, then| {
        common::authorized(when)
            .method("GET")
            .path(path)
            .query_param_missing("partition");
        then.status(200).delay(delay).json_body(body);
    })
}

/// Waits up to 10 s for `done`.
fn wait_until(done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "timed out");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn int_result(handle: &str, name: &str, value: &str) -> Json {
    let mut body = common::success_body(
        vec![common::row_type(name, "fixed", Some(0))],
        json!([[value]]),
        1,
    );
    body["statementHandle"] = json!(handle);
    body
}

fn ltz_result(handle: &str) -> Json {
    let mut body = common::success_body(
        vec![common::row_type("T", "timestamp_ltz", Some(0))],
        json!([["0"]]),
        1,
    );
    body["statementHandle"] = json!(handle);
    body
}

fn timezone_result(handle: &str, zone: &str) -> Json {
    let mut body = common::success_body(
        vec![
            common::row_type("key", "text", None),
            common::row_type("value", "text", None),
        ],
        json!([["TIMEZONE", zone]]),
        1,
    );
    body["statementHandle"] = json!(handle);
    body
}

fn first_value(stream: RowStream) -> Value {
    stream.into_result().unwrap().rows[0][0].clone()
}

fn all_ok(run: ScriptRun) -> Vec<Value> {
    run.map(|item| first_value(item.unwrap())).collect()
}

#[test]
fn several_statements_are_one_request_and_each_child_is_read_in_order() {
    let server = MockServer::start();
    let post = multi(&server, "select 1;\nselect 2\n;", 2, 200, parent_ok(2));
    let c1 = get(&server, &child(1), int_result(&child(1), "A", "1"));
    let c2 = get(&server, &child(2), int_result(&child(2), "B", "2"));
    let run = common::client(&server)
        .run_script(
            &statements(&["select 1;", "select 2"]),
            &ScriptOptions::default(),
        )
        .unwrap();
    assert_eq!(all_ok(run), vec![Value::Int(1), Value::Int(2)]);
    post.assert_calls(1);
    c1.assert_calls(1);
    c2.assert_calls(1);
}

#[test]
fn a_single_statement_takes_the_plain_path() {
    let server = MockServer::start();
    let plain = server.mock(|when, then| {
        common::submit(when, "select 1;").body_excludes("MULTI_STATEMENT_COUNT");
        then.status(200).json_body(common::one_int_body("7"));
    });
    let run = common::client(&server)
        .run_script(&statements(&["select 1;"]), &ScriptOptions::default())
        .unwrap();
    assert_eq!(all_ok(run), vec![Value::Int(7)]);
    plain.assert_calls(1);
    // Nothing to prefetch: no GET at all.
    assert_eq!(
        server
            .mock(|when, _| {
                when.method("GET");
            })
            .calls(),
        0
    );
}

#[test]
fn a_single_statement_sql_error_comes_out_of_the_run() {
    let server = MockServer::start();
    server.mock(|when, then| {
        common::submit(when, "selec 1;");
        then.status(422).json_body(json!({
            "code": "001003", "sqlState": "42000", "statementHandle": PARENT,
            "message": "SQL compilation error:\nsyntax error",
        }));
    });
    let mut run = common::client(&server)
        .run_script(&statements(&["selec 1;"]), &ScriptOptions::default())
        .unwrap();
    let err = run.next().unwrap().err().unwrap();
    assert_eq!(
        err.message(),
        format!("001003 (42000): {PARENT}: SQL compilation error:\nsyntax error")
    );
    assert!(run.next().is_none());
}

#[test]
fn a_non_sql_failure_of_the_plain_path_is_an_error_of_the_run() {
    let server = MockServer::start();
    server.mock(|when, then| {
        common::submit(when, "select 1;");
        then.status(401).json_body(json!({"message": "bad token"}));
    });
    let err = common::client(&server)
        .run_script(&statements(&["select 1;"]), &ScriptOptions::default())
        .err()
        .unwrap();
    assert_eq!(err.kind(), ErrorKind::Connection);
}

#[test]
fn hidden_statements_are_sent_but_never_returned() {
    let server = MockServer::start();
    let request = "ALTER SESSION SET AUTOCOMMIT = FALSE;\nalter session set timezone = 'Asia/Tokyo';\n\
                   SHOW PARAMETERS LIKE 'TIMEZONE' IN SESSION;\nselect t;";
    multi(&server, request, 4, 200, parent_ok(4));
    let status = get(&server, &child(2), int_result(&child(2), "status", "0"));
    let zone = get(&server, &child(3), timezone_result(&child(3), "Asia/Tokyo"));
    get(&server, &child(4), ltz_result(&child(4)));
    let options = ScriptOptions {
        autocommit_off: true,
        ..ScriptOptions::default()
    };
    let run = common::client(&server)
        .run_script(
            &statements(&["alter session set timezone = 'Asia/Tokyo';", "select t;"]),
            &options,
        )
        .unwrap();
    let values = all_ok(run);
    assert_eq!(values.len(), 2);
    // Epoch 0 in the zone of the hidden SHOW, not the session default (never asked).
    match &values[1] {
        Value::TimestampTz { offset_seconds, .. } => assert_eq!(*offset_seconds, 9 * 3600),
        other => panic!("unexpected {other:?}"),
    }
    status.assert_calls(1);
    zone.assert_calls(1);
}

#[test]
fn a_timezone_in_a_literal_gets_the_hidden_show_unless_it_is_last() {
    let server = MockServer::start();
    // `EXECUTE IMMEDIATE` sets the zone from inside a literal, so the match is deliberately broad.
    let request = "EXECUTE IMMEDIATE 'ALTER SESSION SET TIMEZONE = ''UTC'''\n;\n\
                   SHOW PARAMETERS LIKE 'TIMEZONE' IN SESSION;\nselect 1;";
    let parent = multi(&server, request, 3, 200, parent_ok(3));
    get(&server, &child(1), int_result(&child(1), "status", "0"));
    get(&server, &child(2), timezone_result(&child(2), "UTC"));
    get(&server, &child(3), int_result(&child(3), "1", "1"));
    let run = common::client(&server)
        .run_script(
            &statements(&[
                "EXECUTE IMMEDIATE 'ALTER SESSION SET TIMEZONE = ''UTC'''",
                "select 1;",
            ]),
            &ScriptOptions::default(),
        )
        .unwrap();
    all_ok(run);
    parent.assert_calls(1);
}

#[test]
fn a_timezone_word_in_a_literal_gets_the_hidden_show_too() {
    let server = MockServer::start();
    // Accepted false positive: the match is on the text, not on what the statement does.
    let request = "select 'timezone';\nSHOW PARAMETERS LIKE 'TIMEZONE' IN SESSION;\nselect 1;";
    let parent = multi(&server, request, 3, 200, parent_ok(3));
    get(&server, &child(1), int_result(&child(1), "x", "1"));
    get(&server, &child(2), timezone_result(&child(2), "UTC"));
    get(&server, &child(3), int_result(&child(3), "1", "1"));
    let run = common::client(&server)
        .run_script(
            &statements(&["select 'timezone';", "select 1;"]),
            &ScriptOptions::default(),
        )
        .unwrap();
    all_ok(run);
    parent.assert_calls(1);
}

#[test]
fn no_hidden_show_after_the_last_statement() {
    let server = MockServer::start();
    let request = "select 1;\nEXECUTE IMMEDIATE 'ALTER SESSION SET TIMEZONE = ''UTC'''\n;";
    let parent = multi(&server, request, 2, 200, parent_ok(2));
    get(&server, &child(1), int_result(&child(1), "1", "1"));
    get(&server, &child(2), int_result(&child(2), "status", "0"));
    let run = common::client(&server)
        .run_script(
            &statements(&[
                "select 1;",
                "EXECUTE IMMEDIATE 'ALTER SESSION SET TIMEZONE = ''UTC'''",
            ]),
            &ScriptOptions::default(),
        )
        .unwrap();
    all_ok(run);
    parent.assert_calls(1);
}

#[test]
fn secondary_roles_go_first_and_make_one_statement_a_session() {
    let server = MockServer::start();
    let request = "USE SECONDARY ROLES NONE;\nALTER SESSION SET AUTOCOMMIT = FALSE;\nselect 1;";
    let parent = multi(&server, request, 3, 200, parent_ok(3));
    get(&server, &child(3), int_result(&child(3), "1", "1"));
    let options = ScriptOptions {
        autocommit_off: true,
        secondary_roles: Some("NONE"),
    };
    let run = common::client(&server)
        .run_script(&statements(&["select 1;"]), &options)
        .unwrap();
    assert_eq!(all_ok(run).len(), 1);
    parent.assert_calls(1);
}

#[test]
fn ltz_before_any_zone_change_uses_one_session_lookup() {
    let server = MockServer::start();
    multi(&server, "select t;\nselect t;", 2, 200, parent_ok(2));
    get(&server, &child(1), ltz_result(&child(1)));
    get(&server, &child(2), ltz_result(&child(2)));
    let show = server.mock(|when, then| {
        common::submit(when, "SHOW PARAMETERS LIKE 'TIMEZONE'");
        then.status(200)
            .json_body(timezone_result(common::HANDLE, "America/New_York"));
    });
    let run = common::client(&server)
        .run_script(
            &statements(&["select t;", "select t;"]),
            &ScriptOptions::default(),
        )
        .unwrap();
    assert_eq!(all_ok(run).len(), 2);
    show.assert_calls(1);
}

#[test]
fn a_count_mismatch_is_a_client_error() {
    let server = MockServer::start();
    multi(
        &server,
        "select 1;\nselect 2;",
        2,
        422,
        json!({"code": "000008", "sqlState": "0A000", "statementHandle": PARENT,
               "message": "Actual statement count 3 did not match the desired statement count 2."}),
    );
    let err = common::client(&server)
        .run_script(
            &statements(&["select 1;", "select 2;"]),
            &ScriptOptions::default(),
        )
        .err()
        .unwrap();
    assert_eq!(err.kind(), ErrorKind::Client);
    assert_eq!(
        err.message(),
        "The server split the SQL into a different number of statements than snow-rs did (3 vs 2). Please report this input."
    );
}

fn multi_failed() -> Json {
    json!({
        "code": "100132", "sqlState": "P0000", "statementHandle": PARENT,
        "message": "JavaScript execution error: Uncaught Execution of multiple statements failed on statement \"select 1/0;\" (at line 3, position 0).\nDivision by zero in SYSTEM$MULTISTMT at '    throw `Execution...' position 4\nstackstrace: \nSYSTEM$MULTISTMT line: 10",
    })
}

/// The two history lookups of Decision 5.
fn history<'a>(server: &'a MockServer, rows: Json) -> (Mock<'a>, Mock<'a>) {
    let by_user = server.mock(|when, then| {
        common::authorized(when)
            .method("POST")
            .path(common::STATEMENTS)
            .body_includes("QUERY_HISTORY_BY_USER")
            .body_includes(PARENT);
        then.status(200).json_body(common::success_body(
            vec![common::row_type("SESSION_ID", "fixed", Some(0))],
            json!([["123456"]]),
            1,
        ));
    });
    let by_session = server.mock(|when, then| {
        common::authorized(when)
            .method("POST")
            .path(common::STATEMENTS)
            .body_includes("QUERY_HISTORY_BY_SESSION(SESSION_ID => 123456");
        then.status(200).json_body(common::success_body(
            vec![
                common::row_type("QUERY_ID", "text", None),
                common::row_type("QUERY_TEXT", "text", None),
                common::row_type("EXECUTION_STATUS", "text", None),
            ],
            rows,
            1,
        ));
    });
    (by_user, by_session)
}

#[test]
fn a_failing_child_is_found_in_the_session_history() {
    let server = MockServer::start();
    multi(
        &server,
        "select 1;\ncall p();\nselect 1/0;\nselect 3;",
        4,
        422,
        multi_failed(),
    );
    let (by_user, by_session) = history(
        &server,
        json!([
            [
                PARENT,
                "select 1;\ncall p();\nselect 1/0;\nselect 3;",
                "FAILED_WITH_ERROR"
            ],
            [child(1), "select 1;", "SUCCESS"],
            [child(2), "call p();", "SUCCESS"],
            [
                "dddddddd-0000-0000-0000-000000000000",
                "insert into t values (1)",
                "SUCCESS"
            ],
            [child(3), "select 1/0;", "FAILED_WITH_ERROR"],
        ]),
    );
    get(&server, &child(1), int_result(&child(1), "A", "1"));
    get(&server, &child(2), int_result(&child(2), "B", "2"));
    let failed = get(
        &server,
        &child(3),
        json!({"code": "100051", "message": "Division by zero", "statementHandle": child(3)}),
    );
    let mut run = common::client(&server)
        .run_script(
            &statements(&["select 1;", "call p();", "select 1/0;", "select 3;"]),
            &ScriptOptions::default(),
        )
        .unwrap();
    assert_eq!(first_value(run.next().unwrap().unwrap()), Value::Int(1));
    assert_eq!(first_value(run.next().unwrap().unwrap()), Value::Int(2));
    let err = run.next().unwrap().err().unwrap();
    assert_eq!(err.kind(), ErrorKind::Sql);
    assert_eq!(
        err.message(),
        format!("100051: {}: Division by zero", child(3))
    );
    assert!(run.next().is_none());
    by_user.assert_calls(1);
    by_session.assert_calls(1);
    failed.assert_calls(1);
}

#[test]
fn without_history_the_parent_error_is_reported_unwrapped() {
    let server = MockServer::start();
    multi(&server, "select 1;\nselect 1/0;", 2, 422, multi_failed());
    // The history shows no failure (e.g. not visible yet): nothing can be attributed.
    history(&server, json!([[child(1), "select 1;", "SUCCESS"]]));
    let err = common::client(&server)
        .run_script(
            &statements(&["select 1;", "select 1/0;"]),
            &ScriptOptions::default(),
        )
        .err()
        .unwrap();
    assert_eq!(err.kind(), ErrorKind::Sql);
    assert_eq!(
        err.message(),
        format!("100132 (P0000): {PARENT}: Division by zero")
    );
}

#[test]
fn a_failed_history_lookup_falls_back_too() {
    let server = MockServer::start();
    multi(&server, "select 1;\nselect 1/0;", 2, 422, multi_failed());
    server.mock(|when, then| {
        common::authorized(when)
            .method("POST")
            .path(common::STATEMENTS)
            .body_includes("QUERY_HISTORY_BY_USER");
        then.status(422)
            .json_body(json!({"code": "002003", "message": "no access"}));
    });
    let err = common::client(&server)
        .run_script(
            &statements(&["select 1;", "select 1/0;"]),
            &ScriptOptions::default(),
        )
        .err()
        .unwrap();
    assert!(
        err.message().starts_with("100132 (P0000): "),
        "{}",
        err.message()
    );
}

#[test]
fn a_syntax_error_runs_the_statements_before_it_then_the_failing_one_alone() {
    let server = MockServer::start();
    multi(
        &server,
        "select 1;\nselect 2;\nselec 3;\nselect 4;",
        4,
        422,
        json!({"code": "001003", "sqlState": "42000", "statementHandle": PARENT,
               "message": "SQL compilation error:\nsyntax error line 3 at position 0 unexpected 'selec'."}),
    );
    let before = multi(&server, "select 1;\nselect 2;", 2, 200, parent_ok(2));
    get(&server, &child(1), int_result(&child(1), "A", "1"));
    get(&server, &child(2), int_result(&child(2), "B", "2"));
    let alone = server.mock(|when, then| {
        common::submit(when, "selec 3;").body_excludes("MULTI_STATEMENT_COUNT");
        then.status(422).json_body(json!({
            "code": "001003", "sqlState": "42000", "statementHandle": child(9),
            "message": "SQL compilation error:\nsyntax error line 1 at position 0 unexpected 'selec'.",
        }));
    });
    let mut run = common::client(&server)
        .run_script(
            &statements(&["select 1;", "select 2;", "selec 3;", "select 4;"]),
            &ScriptOptions::default(),
        )
        .unwrap();
    assert!(run.next().unwrap().is_ok());
    assert!(run.next().unwrap().is_ok());
    let err = run.next().unwrap().err().unwrap();
    assert!(
        err.message().contains("syntax error line 1"),
        "{}",
        err.message()
    );
    assert!(run.next().is_none());
    before.assert_calls(1);
    alone.assert_calls(1);
}

#[test]
fn a_statement_that_passes_alone_lets_the_rest_run() {
    let server = MockServer::start();
    multi(
        &server,
        "select 1;\nselect 2;\nselect 3;",
        3,
        422,
        json!({"code": "001003", "sqlState": "42000", "statementHandle": PARENT,
               "message": "SQL compilation error:\nsyntax error line 1 at position 0."}),
    );
    server.mock(|when, then| {
        common::submit(when, "select 1;").body_excludes("MULTI_STATEMENT_COUNT");
        then.status(200).json_body(common::one_int_body("1"));
    });
    multi(&server, "select 2;\nselect 3;", 2, 200, parent_ok(2));
    get(&server, &child(1), int_result(&child(1), "B", "2"));
    get(&server, &child(2), int_result(&child(2), "C", "3"));
    let run = common::client(&server)
        .run_script(
            &statements(&["select 1;", "select 2;", "select 3;"]),
            &ScriptOptions::default(),
        )
        .unwrap();
    assert_eq!(
        all_ok(run),
        vec![Value::Int(1), Value::Int(2), Value::Int(3)]
    );
}

#[test]
fn other_rejections_and_bad_parents_are_errors() {
    let server = MockServer::start();
    multi(
        &server,
        "select 1;\nselect 2;",
        2,
        422,
        json!({"code": "390000", "message": "something else"}),
    );
    let err = common::client(&server)
        .run_script(
            &statements(&["select 1;", "select 2;"]),
            &ScriptOptions::default(),
        )
        .err()
        .unwrap();
    assert_eq!(err.kind(), ErrorKind::Sql);

    let server = MockServer::start();
    multi(&server, "select 1;\nselect 2;", 2, 200, parent_ok(1));
    let err = common::client(&server)
        .run_script(
            &statements(&["select 1;", "select 2;"]),
            &ScriptOptions::default(),
        )
        .err()
        .unwrap();
    assert_eq!(err.kind(), ErrorKind::Communication);
}

#[test]
fn a_child_that_reports_an_error_ends_the_run() {
    let server = MockServer::start();
    multi(&server, "select 1;\nselect 2;", 2, 200, parent_ok(2));
    get(
        &server,
        &child(1),
        json!({"code": "000603", "sqlState": "XX000", "message": "boom"}),
    );
    let mut run = common::client(&server)
        .run_script(
            &statements(&["select 1;", "select 2;"]),
            &ScriptOptions::default(),
        )
        .unwrap();
    let err = run.next().unwrap().err().unwrap();
    assert_eq!(err.message(), format!("000603 (XX000): {}: boom", child(1)));
    assert!(run.next().is_none());
}

#[test]
fn an_empty_list_is_an_empty_run() {
    let server = MockServer::start();
    let mut run = common::client(&server)
        .run_script(&[], &ScriptOptions::default())
        .unwrap();
    assert!(run.next().is_none());
}

/// `n` statements `select <i>;` as one request, child `i` answering `i`. Returns the mocks of
/// the child GETs, in order.
fn many_children(server: &MockServer, n: usize) -> (Vec<String>, Vec<Mock<'_>>) {
    let texts: Vec<String> = (1..=n).map(|i| format!("select {i};")).collect();
    multi(server, &texts.join("\n"), n, 200, parent_ok(n));
    let gets = (1..=n)
        .map(|i| {
            get(
                server,
                &child(i),
                int_result(&child(i), "N", &i.to_string()),
            )
        })
        .collect();
    (texts, gets)
}

/// Amendment 1: the first GETs run at once, and replies arriving in reverse order still come
/// out in statement order.
#[test]
fn child_results_are_fetched_concurrently_and_returned_in_statement_order() {
    let server = MockServer::start();
    let texts: Vec<String> = (1..=5).map(|i| format!("select {i};")).collect();
    multi(&server, &texts.join("\n"), 5, 200, parent_ok(5));
    for i in 1..=5 {
        // Child 1 answers last.
        let delay = Duration::from_millis(200 * (6 - i as u64));
        get_delayed(
            &server,
            &child(i),
            int_result(&child(i), "N", &i.to_string()),
            delay,
        );
    }
    let started = Instant::now();
    let run = common::client(&server)
        .run_script(&texts, &ScriptOptions::default())
        .unwrap();
    assert_eq!(all_ok(run), (1..=5).map(Value::Int).collect::<Vec<_>>());
    // One after the other they would take 3 s; together about 1 s (margin for a loaded runner).
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_millis(2400), "{elapsed:?}");
}

#[test]
fn at_most_16_child_gets_are_outstanding() {
    let server = MockServer::start();
    let (texts, gets) = many_children(&server, 30);
    let mut run = common::client(&server)
        .run_script(&texts, &ScriptOptions::default())
        .unwrap();
    wait_until(|| gets[..16].iter().all(|g| g.calls() >= 1));
    std::thread::sleep(Duration::from_millis(200));
    assert!(gets[16..].iter().all(|g| g.calls() == 0));
    // Taking one result frees one slot.
    assert_eq!(first_value(run.next().unwrap().unwrap()), Value::Int(1));
    wait_until(|| gets[16].calls() >= 1);
    std::thread::sleep(Duration::from_millis(100));
    assert!(gets[17..].iter().all(|g| g.calls() == 0));
    let rest: Vec<Value> = run.map(|item| first_value(item.unwrap())).collect();
    assert_eq!(rest, (2..=30).map(Value::Int).collect::<Vec<_>>());
    for g in &gets {
        g.assert_calls(1);
    }
}

#[test]
fn a_failing_child_get_is_reported_at_its_statement_and_stops_dispatching() {
    let server = MockServer::start();
    let texts: Vec<String> = (1..=30).map(|i| format!("select {i};")).collect();
    multi(&server, &texts.join("\n"), 30, 200, parent_ok(30));
    let first = get(&server, &child(1), int_result(&child(1), "N", "1"));
    let failing = server.mock(|when, then| {
        common::authorized(when)
            .method("GET")
            .path(format!("{}/{}", common::STATEMENTS, child(2)));
        then.status(500).body("internal error");
    });
    let rest: Vec<Mock<'_>> = (3..=30)
        .map(|i| {
            get(
                &server,
                &child(i),
                int_result(&child(i), "N", &i.to_string()),
            )
        })
        .collect();
    let mut run = common::client(&server)
        .run_script(&texts, &ScriptOptions::default())
        .unwrap();
    assert_eq!(first_value(run.next().unwrap().unwrap()), Value::Int(1));
    assert!(run.next().unwrap().is_err());
    assert!(run.next().is_none());
    std::thread::sleep(Duration::from_millis(200));
    // At least once: the HTTP client may resend a GET whose pooled connection the mock server
    // closed, which counts twice under load.
    assert!(first.calls() >= 1);
    assert!(failing.calls() >= 1);
    // Children 3..=18 at most (the window, plus the slots freed by children 1 and 2).
    assert!(rest[16..].iter().all(|g| g.calls() == 0));
}

#[test]
fn dropping_the_run_early_stops_dispatching() {
    let server = MockServer::start();
    let (texts, gets) = many_children(&server, 30);
    let mut run = common::client(&server)
        .run_script(&texts, &ScriptOptions::default())
        .unwrap();
    assert_eq!(first_value(run.next().unwrap().unwrap()), Value::Int(1));
    drop(run);
    std::thread::sleep(Duration::from_millis(300));
    assert!(gets[17..].iter().all(|g| g.calls() == 0));
}

#[test]
fn a_zone_reply_that_arrives_last_still_sets_the_zone_of_what_follows() {
    let server = MockServer::start();
    let request = "alter session set timezone = 'Asia/Tokyo';\n\
                   SHOW PARAMETERS LIKE 'TIMEZONE' IN SESSION;\nselect t;";
    multi(&server, request, 3, 200, parent_ok(3));
    get(&server, &child(1), int_result(&child(1), "status", "0"));
    let zone = get_delayed(
        &server,
        &child(2),
        timezone_result(&child(2), "Asia/Tokyo"),
        Duration::from_millis(300),
    );
    get(&server, &child(3), ltz_result(&child(3)));
    let run = common::client(&server)
        .run_script(
            &statements(&["alter session set timezone = 'Asia/Tokyo';", "select t;"]),
            &ScriptOptions::default(),
        )
        .unwrap();
    let values = all_ok(run);
    match &values[1] {
        Value::TimestampTz { offset_seconds, .. } => assert_eq!(*offset_seconds, 9 * 3600),
        other => panic!("unexpected {other:?}"),
    }
    zone.assert_calls(1);
}
