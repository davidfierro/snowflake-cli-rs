//! Golden tests (ADR 0001, Decision 9): replays the SQL API responses captured from the sandbox
//! through `httpmock` and `SqlClient::execute` (and `query` + `render_stream`), renders JSON and CSV, and compares them byte for
//! byte with what snow 3.34.0 printed for the same SQL. Capture: `scripts/capture-goldens.sh`.

use crate::common;

use httpmock::MockServer;
use snowflake_cli_rs::output::format::OutputFormat;
use snowflake_cli_rs::render::{render, render_stream};
use std::path::{Path, PathBuf};

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

fn case_names() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(golden_dir())
        .unwrap()
        .filter_map(|e| {
            let name = e.unwrap().file_name().into_string().unwrap();
            name.strip_suffix(".sqlapi.json").map(String::from)
        })
        .collect();
    names.sort();
    names
}

/// What `replay` needs to serve one golden case.
struct Case {
    sql: String,
    record: serde_json::Value,
}

fn load(dir: &Path, name: &str) -> Case {
    let record: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join(format!("{name}.sqlapi.json"))).unwrap(),
    )
    .unwrap();
    Case {
        sql: record["sql"].as_str().unwrap().to_string(),
        record,
    }
}

/// Renders `format` through `query()` + `render_stream()` (ADR 0002, Decision 3).
fn replay_stream(dir: &Path, name: &str, format: OutputFormat) -> Vec<u8> {
    let Case { sql, record } = load(dir, name);
    let server = MockServer::start();
    server.mock(|when, then| {
        common::submit(when, &sql);
        then.status(200).json_body(record["response"].clone());
    });
    for (i, part) in record["partitions"].as_array().unwrap().iter().enumerate() {
        server.mock(|when, then| {
            common::authorized(when)
                .method("GET")
                .path(format!("{}/{}", common::STATEMENTS, common::HANDLE))
                .query_param("partition", (i + 1).to_string());
            then.status(200).json_body(part.clone());
        });
    }
    if let Some(params) = record.get("show_parameters") {
        server.mock(|when, then| {
            common::submit(when, "SHOW PARAMETERS LIKE 'TIMEZONE'");
            then.status(200).json_body(params.clone());
        });
    }
    let mut stream = common::client(&server).query(&sql).unwrap();
    let columns = stream.columns().to_vec();
    let mut out = Vec::new();
    render_stream(&columns, &mut stream, format, None, &mut out).unwrap();
    out
}

fn replay(dir: &Path, name: &str) -> snowflake_cli_rs::sql::QueryResult {
    let Case { sql, record } = load(dir, name);
    let sql = sql.as_str();
    let server = MockServer::start();
    let main = server.mock(|when, then| {
        common::submit(when, sql);
        then.status(200).json_body(record["response"].clone());
    });
    let partitions = record["partitions"].as_array().unwrap();
    let partition_mocks: Vec<_> = partitions
        .iter()
        .enumerate()
        .map(|(i, part)| {
            server.mock(|when, then| {
                common::authorized(when)
                    .method("GET")
                    .path(format!("{}/{}", common::STATEMENTS, common::HANDLE))
                    .query_param("partition", (i + 1).to_string());
                then.status(200).json_body(part.clone());
            })
        })
        .collect();
    let show = record.get("show_parameters").map(|params| {
        let query = "SHOW PARAMETERS LIKE 'TIMEZONE'";
        server.mock(|when, then| {
            common::submit(when, query);
            then.status(200).json_body(params.clone());
        })
    });

    let result = common::client(&server).execute(sql).unwrap();
    main.assert_calls(1);
    for mock in &partition_mocks {
        mock.assert_calls(1);
    }
    if let Some(mock) = show {
        mock.assert_calls(1);
    }
    result
}

#[test]
fn json_and_csv_match_snow_byte_for_byte() {
    let dir = golden_dir();
    let names = case_names();
    assert!(names.len() >= 15, "golden cases missing: {names:?}");
    let mut failures = Vec::new();
    for name in &names {
        let result = replay(&dir, name);
        for (format, ext) in [(OutputFormat::Json, "json"), (OutputFormat::Csv, "csv")] {
            let expected = std::fs::read(dir.join(format!("{name}.{ext}"))).unwrap();
            let mut actual = Vec::new();
            render(&result, format, &mut actual).unwrap();
            if actual != expected {
                failures.push(format!(
                    "{name}.{ext}:\n--- snow\n{}\n--- ours\n{}",
                    String::from_utf8_lossy(&expected),
                    String::from_utf8_lossy(&actual)
                ));
            }
            let streamed = replay_stream(&dir, name, format);
            if streamed != expected {
                failures.push(format!(
                    "{name}.{ext} (streamed):\n--- snow\n{}\n--- ours\n{}",
                    String::from_utf8_lossy(&expected),
                    String::from_utf8_lossy(&streamed)
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
