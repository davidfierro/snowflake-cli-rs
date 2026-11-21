//! Mocked HTTP tests of `SqlClient` (ADR 0001, Decision 9): every API path, each asserting the
//! request too (path, `requestId`, JWT headers, body).

use crate::common;

use common::*;
use flate2::Compression;
use flate2::write::GzEncoder;
use httpmock::{HttpMockRequest, MockServer};
use serde_json::json;
use snowflake_cli_rs::error::ErrorKind;
use snowflake_cli_rs::sql::{ClientOptions, Column, SfType, Value};
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SQL: &str = "SELECT 1 AS N";

fn gzip(body: &serde_json::Value) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body.to_string().as_bytes()).unwrap();
    encoder.finish().unwrap()
}

fn request_id(req: &HttpMockRequest) -> Option<String> {
    req.query_params()
        .into_iter()
        .find(|(k, _)| k == "requestId")
        .map(|(_, v)| v)
}

fn sql_error_body(code: &str, message: &str) -> serde_json::Value {
    json!({"code": code, "sqlState": "42000", "message": message, "statementHandle": HANDLE})
}

#[test]
fn single_partition_result() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        submit(when, SQL);
        then.status(200).json_body(one_int_body("1"));
    });
    let result = client(&server).execute(SQL).unwrap();
    mock.assert_calls(1);
    assert_eq!(result.statement_handle, HANDLE);
    assert_eq!(
        result.columns,
        vec![Column {
            name: "N".into(),
            sf_type: SfType::Fixed {
                precision: 38,
                scale: 0
            },
            nullable: true
        }]
    );
    assert_eq!(result.rows, vec![vec![Value::Int(1)]]);
}

#[test]
fn context_fields_are_sent_only_when_set_and_timeout_when_configured() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        authorized(when)
            .method("POST")
            .path(STATEMENTS)
            .json_body(json!({"statement": SQL, "timeout": 30}));
        then.status(200).json_body(one_int_body("1"));
    });
    let conn = snowflake_cli_rs::connection::ConnectionConfig {
        database: None,
        schema: None,
        role: None,
        warehouse: None,
        ..connection(&server)
    };
    let options = ClientOptions {
        statement_timeout: Some(Duration::from_millis(29_001)),
        ..fast_options()
    };
    client_with(&conn, options).execute(SQL).unwrap();
    mock.assert_calls(1);
}

#[test]
fn partitions_are_fetched_in_order_and_gunzipped() {
    let server = MockServer::start();
    let submit_mock = server.mock(|when, then| {
        submit(when, SQL);
        then.status(200).json_body(success_body(
            vec![row_type("N", "fixed", Some(0))],
            json!([["1"]]),
            3,
        ));
    });
    let partition_mocks: Vec<_> = [("1", "2"), ("2", "3")]
        .into_iter()
        .map(|(partition, value)| {
            server.mock(|when, then| {
                authorized(when)
                    .method("GET")
                    .path(format!("{STATEMENTS}/{HANDLE}"))
                    .query_param("partition", partition)
                    .header_matches("accept-encoding", "gzip");
                then.status(200)
                    .header("content-encoding", "gzip")
                    .header("content-type", "application/json")
                    .body(gzip(&json!({"data": [[value]]})));
            })
        })
        .collect();
    let result = client(&server).execute(SQL).unwrap();
    submit_mock.assert_calls(1);
    for mock in &partition_mocks {
        mock.assert_calls(1);
    }
    assert_eq!(
        result.rows,
        vec![
            vec![Value::Int(1)],
            vec![Value::Int(2)],
            vec![Value::Int(3)]
        ]
    );
}

#[test]
fn failing_partition_is_an_error() {
    let server = MockServer::start();
    server.mock(|when, then| {
        submit(when, SQL);
        then.status(200).json_body(success_body(
            vec![row_type("N", "fixed", Some(0))],
            json!([["1"]]),
            2,
        ));
    });
    server.mock(|when, then| {
        when.method("GET").path(format!("{STATEMENTS}/{HANDLE}"));
        then.status(500).json_body(json!({"message": "boom"}));
    });
    let err = client(&server).execute(SQL).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Communication);
    assert_eq!(err.message(), "Snowflake returned HTTP 500: boom");
}

fn async_submission(server: &MockServer) -> httpmock::Mock<'_> {
    server.mock(|when, then| {
        submit(when, SQL);
        then.status(202).json_body(json!({
            "code": "333334",
            "message": "Asynchronous execution in progress.",
            "statementHandle": HANDLE,
            "statementStatusUrl": format!("{STATEMENTS}/{HANDLE}"),
        }));
    })
}

/// Answers the first `pending` polls with 202, then `final_status` with `final_body`.
fn poll_mock<'a>(
    server: &'a MockServer,
    pending: usize,
    final_status: u16,
    final_body: serde_json::Value,
) -> (httpmock::Mock<'a>, httpmock::Mock<'a>) {
    let polls = Arc::new(Mutex::new(0usize));
    let counter = Arc::clone(&polls);
    let still_running = server.mock(move |when, then| {
        authorized(when)
            .method("GET")
            .path(format!("{STATEMENTS}/{HANDLE}"))
            .query_param_missing("partition")
            .is_true(move |_| {
                let mut n = counter.lock().unwrap();
                *n += 1;
                *n <= pending
            });
        then.status(202)
            .json_body(json!({"code": "333334", "statementHandle": HANDLE}));
    });
    let done = server.mock(|when, then| {
        authorized(when)
            .method("GET")
            .path(format!("{STATEMENTS}/{HANDLE}"))
            .query_param_missing("partition");
        then.status(final_status).json_body(final_body);
    });
    (still_running, done)
}

#[test]
fn async_statement_is_polled_until_done() {
    let server = MockServer::start();
    let submitted = async_submission(&server);
    let (running, done) = poll_mock(&server, 2, 200, one_int_body("7"));
    let result = client(&server).execute(SQL).unwrap();
    submitted.assert_calls(1);
    running.assert_calls(2);
    done.assert_calls(1);
    assert_eq!(result.rows, vec![vec![Value::Int(7)]]);
}

#[test]
fn async_statement_failing_reports_the_sql_error() {
    let server = MockServer::start();
    async_submission(&server);
    let (running, _) = poll_mock(
        &server,
        1,
        422,
        sql_error_body("100038", "Numeric value 'x' is not recognized"),
    );
    let err = client(&server).execute(SQL).unwrap_err();
    running.assert_calls(1);
    assert_eq!(err.kind(), ErrorKind::Sql);
    assert_eq!(
        err.message(),
        format!("100038 (42000): {HANDLE}: Numeric value 'x' is not recognized")
    );
}

#[test]
fn poll_interval_doubles_up_to_the_maximum() {
    let server = MockServer::start();
    async_submission(&server);
    poll_mock(&server, 2, 200, one_int_body("1"));
    let options = ClientOptions {
        poll_interval_max: Duration::from_millis(300),
        ..fast_options()
    };
    let started = Instant::now();
    client_with(&connection(&server), options)
        .execute(SQL)
        .unwrap();
    // 250 ms, then min(500, 300) twice.
    assert!(started.elapsed() >= Duration::from_millis(850));
}

fn status_error(status: u16, body: serde_json::Value) -> snowflake_cli_rs::error::Error {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        submit(when, SQL);
        then.status(status).json_body(body);
    });
    let err = client(&server).execute(SQL).unwrap_err();
    mock.assert_calls(1);
    err
}

#[test]
fn unauthorized_is_a_connection_error() {
    let err = status_error(
        401,
        json!({"code": "390144", "message": "JWT token is invalid."}),
    );
    assert_eq!(err.kind(), ErrorKind::Connection);
    assert_eq!(
        err.message(),
        "Failed to connect to Snowflake: JWT token is invalid."
    );
}

#[test]
fn forbidden_is_a_connection_error() {
    let err = status_error(403, json!({"message": "Role not granted."}));
    assert_eq!(err.kind(), ErrorKind::Connection);
    assert_eq!(
        err.message(),
        "Failed to connect to Snowflake: Role not granted."
    );
}

#[test]
fn statement_timeout_is_a_sql_error() {
    let err = status_error(
        408,
        json!({"code": "000630", "message": "Statement reached its statement or warehouse timeout of 1 second(s) and was canceled."}),
    );
    assert_eq!(err.kind(), ErrorKind::Sql);
    assert!(err.message().starts_with("Statement reached its statement"));
}

#[test]
fn sql_error_uses_snow_format() {
    let err = status_error(
        422,
        sql_error_body(
            "001003",
            "SQL compilation error:\nsyntax error line 1 at position 0 unexpected 'SELEC'.",
        ),
    );
    assert_eq!(err.kind(), ErrorKind::Sql);
    assert_eq!(
        err.message(),
        format!(
            "001003 (42000): {HANDLE}: SQL compilation error:\nsyntax error line 1 at position 0 unexpected 'SELEC'."
        )
    );
}

#[test]
fn unexpected_status_without_json_is_a_communication_error() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method("POST");
        then.status(400).body("<html>bad</html>");
    });
    let err = client(&server).execute(SQL).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Communication);
    assert_eq!(
        err.message(),
        "Snowflake returned HTTP 400: no error message"
    );
}

#[test]
fn throttled_post_is_retried_with_the_same_request_id() {
    let server = MockServer::start();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (first_seen, retry_seen) = (Arc::clone(&seen), Arc::clone(&seen));
    let throttled = server.mock(move |when, then| {
        submit(when, SQL)
            .query_param_missing("retry")
            .is_true(move |req| {
                first_seen.lock().unwrap().push(request_id(req));
                true
            });
        then.status(429)
            .header("Retry-After", "0")
            .json_body(json!({"message": "Too many requests"}));
    });
    let retried = server.mock(move |when, then| {
        submit(when, SQL)
            .query_param("retry", "true")
            .is_true(move |req| {
                retry_seen.lock().unwrap().push(request_id(req));
                true
            });
        then.status(200).json_body(one_int_body("1"));
    });
    let result = client(&server).execute(SQL).unwrap();
    throttled.assert_calls(1);
    retried.assert_calls(1);
    assert_eq!(result.rows, vec![vec![Value::Int(1)]]);
    let ids = seen.lock().unwrap();
    assert!(
        ids.len() >= 2 && ids.iter().all(|id| id.is_some() && *id == ids[0]),
        "{ids:?}"
    );
}

#[test]
fn unavailable_until_retries_run_out() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method("POST").path(STATEMENTS);
        then.status(503)
            .header("Retry-After", "0")
            .json_body(json!({"message": "Service Unavailable"}));
    });
    let err = client(&server).execute(SQL).unwrap_err();
    mock.assert_calls(4);
    assert_eq!(err.kind(), ErrorKind::Communication);
    assert_eq!(
        err.message(),
        "Snowflake returned HTTP 503: Service Unavailable"
    );
}

#[test]
fn retry_without_retry_after_backs_off_one_second() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method("POST").path(STATEMENTS);
        then.status(504).body("gateway timeout");
    });
    let options = ClientOptions {
        max_retries: 1,
        ..fast_options()
    };
    let started = Instant::now();
    let err = client_with(&connection(&server), options)
        .execute(SQL)
        .unwrap_err();
    assert!(started.elapsed() >= Duration::from_secs(1));
    mock.assert_calls(2);
    assert_eq!(err.kind(), ErrorKind::Communication);
}

#[test]
fn read_timeout_is_retried_then_fails() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method("POST").path(STATEMENTS);
        then.status(200)
            .json_body(one_int_body("1"))
            .delay(Duration::from_secs(3));
    });
    let options = ClientOptions {
        request_timeout: Duration::from_millis(200),
        max_retries: 1,
        ..fast_options()
    };
    let err = client_with(&connection(&server), options)
        .execute(SQL)
        .unwrap_err();
    mock.assert_calls(2);
    assert_eq!(err.kind(), ErrorKind::Communication);
    assert_eq!(err.message(), "Request to Snowflake timed out.");
}

#[test]
fn connection_refused_is_a_connection_error() {
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let conn = snowflake_cli_rs::connection::ConnectionConfig {
        host: Some("127.0.0.1".into()),
        port: Some(port),
        protocol: Some("http".into()),
        ..connection(&MockServer::start())
    };
    let err = client_with(&conn, fast_options()).execute(SQL).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Connection);
    assert_eq!(
        err.message(),
        format!("Failed to connect to Snowflake at http://127.0.0.1:{port}.")
    );
}

#[test]
fn malformed_json_is_a_communication_error() {
    let server = MockServer::start();
    server.mock(|when, then| {
        submit(when, SQL);
        then.status(200).body("{not json");
    });
    let err = client(&server).execute(SQL).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Communication);
    assert_eq!(err.message(), "Snowflake returned a malformed response.");
    assert!(std::error::Error::source(&err).is_some());
}

#[test]
fn missing_fields_are_communication_errors() {
    for (body, what) in [
        (json!({"message": "ok"}), "no statementHandle"),
        (json!({"statementHandle": HANDLE}), "no resultSetMetaData"),
        (
            success_body(
                vec![row_type("N", "fixed", Some(0))],
                json!([["1", "2"]]),
                1,
            ),
            "a row has the wrong number of values",
        ),
    ] {
        let server = MockServer::start();
        server.mock(|when, then| {
            submit(when, SQL);
            then.status(200).json_body(body.clone());
        });
        let err = client(&server).execute(SQL).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Communication);
        assert_eq!(
            err.message(),
            format!("Snowflake returned a malformed response: {what}.")
        );
    }
}

#[test]
fn async_answer_without_handle_is_malformed() {
    let server = MockServer::start();
    server.mock(|when, then| {
        submit(when, SQL);
        then.status(202).json_body(json!({"code": "333334"}));
    });
    let err = client(&server).execute(SQL).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Communication);
}

fn ltz_server(timezone_rows: serde_json::Value) -> (MockServer, &'static str) {
    let sql = "SELECT '2024-01-02 03:04:05 +00:00'::TIMESTAMP_LTZ AS LTZ";
    let server = MockServer::start();
    server.mock(|when, then| {
        submit(when, sql);
        then.status(200).json_body(success_body(
            vec![row_type("LTZ", "timestamp_ltz", Some(9))],
            json!([["1704164645.000000000"]]),
            1,
        ));
    });
    server.mock(|when, then| {
        submit(when, "SHOW PARAMETERS LIKE 'TIMEZONE'");
        then.status(200).json_body(success_body(
            vec![
                row_type("key", "text", None),
                row_type("value", "text", None),
                row_type("default", "text", None),
            ],
            timezone_rows,
            1,
        ));
    });
    (server, sql)
}

#[test]
fn ltz_column_triggers_the_time_zone_lookup() {
    let (server, sql) = ltz_server(json!([[
        "TIMEZONE",
        "America/Los_Angeles",
        "America/Los_Angeles"
    ]]));
    let result = client(&server).execute(sql).unwrap();
    assert_eq!(
        result.rows,
        vec![vec![Value::TimestampTz {
            local: jiff::civil::date(2024, 1, 1).at(19, 4, 5, 0),
            offset_seconds: -8 * 3600,
        }]]
    );
}

#[test]
fn the_time_zone_is_looked_up_once_per_client() {
    let sql = "SELECT '2024-01-02 03:04:05 +00:00'::TIMESTAMP_LTZ AS LTZ";
    let server = MockServer::start();
    server.mock(|when, then| {
        submit(when, sql);
        then.status(200).json_body(success_body(
            vec![row_type("LTZ", "timestamp_ltz", Some(9))],
            json!([["1704164645.000000000"]]),
            1,
        ));
    });
    let show = server.mock(|when, then| {
        submit(when, "SHOW PARAMETERS LIKE 'TIMEZONE'");
        then.status(200).json_body(success_body(
            vec![
                row_type("key", "text", None),
                row_type("value", "text", None),
                row_type("default", "text", None),
            ],
            json!([["TIMEZONE", "UTC", "UTC"]]),
            1,
        ));
    });
    let client = client(&server);
    client.execute(sql).unwrap();
    client.execute(sql).unwrap();
    show.assert_calls(1);
}

#[test]
fn unknown_or_missing_time_zone_is_an_error() {
    let (server, sql) = ltz_server(json!([["TIMEZONE", "Mars/Olympus", ""]]));
    let err = client(&server).execute(sql).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Client);
    assert_eq!(err.message(), "Unknown session time zone 'Mars/Olympus'.");

    let (server, sql) = ltz_server(json!([]));
    let err = client(&server).execute(sql).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Communication);
}

#[test]
fn rows_without_metadata_columns_need_no_lookup() {
    let server = MockServer::start();
    server.mock(|when, then| {
        submit(when, SQL);
        then.status(200).json_body(json!({
            "statementHandle": HANDLE,
            "resultSetMetaData": {"rowType": []},
        }));
    });
    let result = client(&server).execute(SQL).unwrap();
    assert!(result.columns.is_empty() && result.rows.is_empty());
}
