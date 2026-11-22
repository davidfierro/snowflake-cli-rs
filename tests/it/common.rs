//! Helpers shared by the mocked-HTTP integration tests.
#![allow(dead_code)] // each test module uses a different subset of the helpers

use httpmock::{MockServer, When};
use snowflake_cli_rs::auth::KeyPairAuthenticator;
use snowflake_cli_rs::connection::ConnectionConfig;
use snowflake_cli_rs::sql::{ClientOptions, SqlClient};
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

static LOGGER: Mutex<()> = Mutex::new(());

/// The `log` logger is process-global and the in-process CLI runs reinstall it: hold this guard
/// in every test that runs the CLI in-process or captures log output, so they never interleave.
pub fn logger_guard() -> MutexGuard<'static, ()> {
    LOGGER.lock().unwrap_or_else(|e| e.into_inner())
}

pub const STATEMENTS: &str = "/api/v2/statements";
pub const HANDLE: &str = "01234567-0000-0000-0000-000000000000";
/// `Authorization: Bearer <header>.<claims>.<signature>`.
pub const BEARER_JWT: &str = r"^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$";
pub const UUID: &str = r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";

pub fn key_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/keys")
        .join(name)
}

/// [`key_path`] as it goes inside a TOML string: forward slashes, because on Windows a backslash
/// starts an escape.
pub fn key_path_toml(name: &str) -> String {
    key_path(name).display().to_string().replace('\\', "/")
}

/// A connection pointing at the mock server, signed with the unencrypted fixture key.
pub fn connection(server: &MockServer) -> ConnectionConfig {
    ConnectionConfig {
        account: Some("testacct".into()),
        user: Some("tester".into()),
        host: Some(server.host()),
        port: Some(server.port()),
        protocol: Some("http".into()),
        authenticator: Some("SNOWFLAKE_JWT".into()),
        private_key_file: Some(key_path("unencrypted.p8")),
        database: Some("TEST_DB".into()),
        schema: Some("PUBLIC".into()),
        role: Some("TEST_ROLE".into()),
        warehouse: Some("TEST_WH".into()),
        ..Default::default()
    }
}

/// Options for fast tests: no real waiting between polls.
pub fn fast_options() -> ClientOptions {
    ClientOptions {
        poll_interval_max: Duration::from_millis(1),
        request_timeout: Duration::from_secs(10),
        ..ClientOptions::default()
    }
}

pub fn client_with(conn: &ConnectionConfig, options: ClientOptions) -> SqlClient {
    let auth = KeyPairAuthenticator::from_connection(conn).unwrap();
    SqlClient::new(conn, Box::new(auth), options).unwrap()
}

pub fn client(server: &MockServer) -> SqlClient {
    client_with(&connection(server), fast_options())
}

/// Every SQL API request carries the JWT headers and accepts JSON.
pub fn authorized(when: When) -> When {
    when.header_matches("authorization", BEARER_JWT)
        .header("x-snowflake-authorization-token-type", "KEYPAIR_JWT")
        .header("accept", "application/json")
        .header(
            "user-agent",
            concat!("snowflake-cli-rs/", env!("CARGO_PKG_VERSION")),
        )
}

/// A statement submission: path, a v4 `requestId`, JSON headers and the context fields.
pub fn submit(when: When, sql: &str) -> When {
    authorized(when)
        .method("POST")
        .path(STATEMENTS)
        .query_param_matches("requestId", UUID)
        .header("content-type", "application/json")
        .json_body_includes(
            serde_json::json!({
                "statement": sql,
                "database": "TEST_DB",
                "schema": "PUBLIC",
                "role": "TEST_ROLE",
                "warehouse": "TEST_WH",
            })
            .to_string(),
        )
}

pub fn row_type(name: &str, type_name: &str, scale: Option<i64>) -> serde_json::Value {
    serde_json::json!({
        "name": name, "type": type_name, "precision": 38, "scale": scale, "nullable": true,
        "database": "", "schema": "", "table": "", "byteLength": null, "length": null,
    })
}

/// A 200 body with `partitions` partitions (rows only for partition 0).
pub fn success_body(
    row_types: Vec<serde_json::Value>,
    data: serde_json::Value,
    partitions: usize,
) -> serde_json::Value {
    let partition_info: Vec<_> = (0..partitions)
        .map(|_| serde_json::json!({"rowCount": 1, "uncompressedSize": 10}))
        .collect();
    serde_json::json!({
        "resultSetMetaData": {
            "numRows": 1, "format": "jsonv2",
            "partitionInfo": partition_info,
            "rowType": row_types,
        },
        "data": data,
        "code": "090001",
        "sqlState": "00000",
        "statementHandle": HANDLE,
        "message": "Statement executed successfully.",
    })
}

pub fn one_int_body(value: &str) -> serde_json::Value {
    success_body(
        vec![row_type("N", "fixed", Some(0))],
        serde_json::json!([[value]]),
        1,
    )
}

/// Tests run the binary with `env_clear()`; on Windows it then needs `SystemRoot` back, or
/// Winsock cannot start and every connection fails.
pub fn keep_system_env(cmd: &mut assert_cmd::Command) {
    if cfg!(windows)
        && let Some(root) = std::env::var_os("SystemRoot")
    {
        cmd.env("SystemRoot", root);
    }
}
