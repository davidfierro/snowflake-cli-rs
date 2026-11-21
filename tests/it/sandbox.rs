//! Stage-0 proof against the Snowflake sandbox (ADR 0001, Decision 9). Not run in CI (no
//! credentials there); the builder runs `cargo test -- --ignored sandbox --nocapture` before each
//! PR. Needs SNOWFLAKE_ACCOUNT, SNOWFLAKE_USER, SNOWFLAKE_PRIVATE_KEY_B64 and optionally
//! SNOWFLAKE_ROLE, SNOWFLAKE_WAREHOUSE, SNOWFLAKE_DATABASE. The connection is a temporary one
//! (`-x`) resolved by `config::resolve_connection` from those variables, with the key passed
//! inline as `SNOWFLAKE_PRIVATE_KEY_RAW`; it is never printed.

use base64::Engine;
use snowflake_cli_rs::auth::KeyPairAuthenticator;
use snowflake_cli_rs::cli::ConnectionOptions;
use snowflake_cli_rs::config::{ConfigPaths, ConfigSource, resolve_connection};
use snowflake_cli_rs::connection::ConnectionConfig;
use snowflake_cli_rs::env::Env;
use snowflake_cli_rs::error::ErrorKind;
use snowflake_cli_rs::output::format::OutputFormat;
use snowflake_cli_rs::render::render;
use snowflake_cli_rs::sql::{ClientOptions, SqlClient, Value};

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// `snow -x` with the sandbox variables: flags none, then generic `SNOWFLAKE_<KEY>` variables.
fn sandbox_connection() -> ConnectionConfig {
    let key = base64::engine::general_purpose::STANDARD
        .decode(var("SNOWFLAKE_PRIVATE_KEY_B64").expect("SNOWFLAKE_PRIVATE_KEY_B64 is not set"))
        .expect("SNOWFLAKE_PRIVATE_KEY_B64 is not base64");
    let home = tempfile::tempdir().unwrap();
    let mut pairs: Vec<(String, String)> = [
        "SNOWFLAKE_ACCOUNT",
        "SNOWFLAKE_USER",
        "SNOWFLAKE_ROLE",
        "SNOWFLAKE_WAREHOUSE",
        "SNOWFLAKE_DATABASE",
    ]
    .into_iter()
    .filter_map(|name| var(name).map(|v| (name.to_string(), v)))
    .collect();
    pairs.push(("SNOWFLAKE_HOME".into(), home.path().display().to_string()));
    pairs.push(("SNOWFLAKE_AUTHENTICATOR".into(), "SNOWFLAKE_JWT".into()));
    pairs.push((
        "SNOWFLAKE_PRIVATE_KEY_RAW".into(),
        String::from_utf8(key).expect("key is not UTF-8 PEM"),
    ));
    let env = Env::from_pairs(pairs);
    let source = ConfigSource::load(&ConfigPaths::discover(&env, None).unwrap()).unwrap();
    let options = ConnectionOptions {
        temporary_connection: true,
        ..Default::default()
    };
    resolve_connection(&source, &options, &env).unwrap()
}

fn sandbox_client() -> SqlClient {
    let conn = sandbox_connection();
    let auth = KeyPairAuthenticator::from_connection(&conn).unwrap();
    SqlClient::new(&conn, Box::new(auth), ClientOptions::default()).unwrap()
}

#[test]
#[ignore = "needs the Snowflake sandbox"]
fn sandbox_current_role_in_all_formats() {
    let result = sandbox_client().execute("SELECT CURRENT_ROLE()").unwrap();
    assert_eq!(result.columns.len(), 1);
    assert_eq!(result.columns[0].name, "CURRENT_ROLE()");
    if let Some(role) = var("SNOWFLAKE_ROLE") {
        assert_eq!(result.rows, vec![vec![Value::Text(role.to_uppercase())]]);
    }
    for format in [
        OutputFormat::Table,
        OutputFormat::Json,
        OutputFormat::Csv,
        OutputFormat::Plain,
    ] {
        let mut out = Vec::new();
        render(&result, format, &mut out).unwrap();
        println!("--format {format:?}\n{}", String::from_utf8(out).unwrap());
    }
}

#[test]
#[ignore = "needs the Snowflake sandbox"]
fn sandbox_sql_error_is_reported_in_snow_format() {
    let err = sandbox_client().execute("SELEC 1").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Sql);
    assert!(
        err.message().starts_with("001003 (42000): "),
        "{}",
        err.message()
    );
    let mut stderr = Vec::new();
    snowflake_cli_rs::report::report_error(&err, false, &mut stderr);
    println!("{}", String::from_utf8(stderr).unwrap());
}

// ---- `snow connection test` and `generate-jwt` through the binary ----

/// The binary with the sandbox variables and the key in a temp file; returns the home too.
fn sandbox_snow() -> (assert_cmd::Command, tempfile::TempDir) {
    let key = base64::engine::general_purpose::STANDARD
        .decode(var("SNOWFLAKE_PRIVATE_KEY_B64").expect("SNOWFLAKE_PRIVATE_KEY_B64 is not set"))
        .unwrap();
    let home = tempfile::tempdir().unwrap();
    let key_file = home.path().join("key.p8");
    std::fs::write(&key_file, key).unwrap();
    let mut cmd = assert_cmd::Command::cargo_bin("snow-rs").unwrap();
    cmd.env_clear().env("SNOWFLAKE_HOME", home.path());
    if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
        cmd.env("LLVM_PROFILE_FILE", profile);
    }
    for name in [
        "SNOWFLAKE_ACCOUNT",
        "SNOWFLAKE_USER",
        "SNOWFLAKE_ROLE",
        "SNOWFLAKE_WAREHOUSE",
        "SNOWFLAKE_DATABASE",
    ] {
        if let Some(value) = var(name) {
            cmd.env(name, value);
        }
    }
    cmd.env("SNOWFLAKE_AUTHENTICATOR", "SNOWFLAKE_JWT")
        .env("SNOWFLAKE_PRIVATE_KEY_FILE", &key_file);
    (cmd, home)
}

#[test]
#[ignore = "needs the Snowflake sandbox"]
fn sandbox_connection_test_prints_the_connection_in_every_format() {
    for format in ["table", "json", "csv", "plain"] {
        let (mut cmd, _home) = sandbox_snow();
        let out = cmd
            .args(["connection", "test", "-x", "--format", format])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("Status") && out.contains("OK"),
            "{format}: {out}"
        );
        if format == "json" {
            let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
            assert_eq!(parsed["Status"], "OK");
            if let Some(role) = var("SNOWFLAKE_ROLE") {
                assert_eq!(parsed["Role"], role.as_str());
            }
        }
    }
}

#[test]
#[ignore = "needs the Snowflake sandbox"]
fn sandbox_generate_jwt_token_is_accepted_by_the_sql_api() {
    let (mut cmd, _home) = sandbox_snow();
    let out = cmd
        .args(["connection", "generate-jwt", "-x"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let token = String::from_utf8(out).unwrap();
    assert_eq!(token.matches('\n').count(), 1);
    let url = format!(
        "https://{}.snowflakecomputing.com/api/v2/statements",
        var("SNOWFLAKE_ACCOUNT").unwrap()
    );
    let mut response = ureq::post(&url)
        .header("Authorization", format!("Bearer {}", token.trim_end()))
        .header("X-Snowflake-Authorization-Token-Type", "KEYPAIR_JWT")
        .send_json(serde_json::json!({"statement": "SELECT 1"}))
        .expect("the SQL API rejected the generated JWT");
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.body_mut().read_json().unwrap();
    assert_eq!(body["data"][0][0], "1");
}

/// ADR 0004, Decision 7: session context carries over between the statements of one run.
#[test]
#[ignore = "needs the Snowflake sandbox"]
fn sandbox_use_schema_affects_a_later_statement_of_the_same_run() {
    use snowflake_cli_rs::sql::ScriptOptions;
    let statements = vec![
        "USE SCHEMA INFORMATION_SCHEMA;".to_string(),
        "SELECT CURRENT_SCHEMA();".to_string(),
    ];
    let mut run = sandbox_client()
        .run_script(&statements, &ScriptOptions::default())
        .unwrap();
    let status = run.next().unwrap().unwrap().into_result().unwrap();
    assert_eq!(status.columns[0].name, "status");
    let schema = run.next().unwrap().unwrap().into_result().unwrap();
    assert_eq!(
        schema.rows,
        vec![vec![Value::Text("INFORMATION_SCHEMA".into())]]
    );
    assert!(run.next().is_none());
}

/// With the child results prefetched concurrently (ADR 0004, Amendment 1), `USE`,
/// `SET` variables, a temporary table, `ALTER SESSION` and an explicit transaction still carry
/// over between the statements of one run, and the results come out in statement order.
#[test]
#[ignore = "needs the Snowflake sandbox"]
fn sandbox_session_state_carries_over_with_concurrent_child_fetches() {
    use snowflake_cli_rs::sql::ScriptOptions;
    let table = format!("PUBLIC.SNOW_RS_TMP_{}", std::process::id());
    let statements: Vec<String> = [
        "USE SCHEMA INFORMATION_SCHEMA;".to_string(),
        "SET v = 41;".to_string(),
        format!("CREATE TEMPORARY TABLE {table} (n INT);"),
        "ALTER SESSION SET QUERY_TAG = 'snow_rs_dfi154';".to_string(),
        "BEGIN;".to_string(),
        format!("INSERT INTO {table} VALUES ($v + 1);"),
        "SELECT CURRENT_TRANSACTION() IS NOT NULL AS in_tx;".to_string(),
        "COMMIT;".to_string(),
        format!("SELECT n, CURRENT_SCHEMA() AS s FROM {table};"),
        "SHOW PARAMETERS LIKE 'QUERY_TAG' IN SESSION;".to_string(),
        "SELECT CURRENT_TRANSACTION() IS NULL AS no_tx, $v AS v;".to_string(),
    ]
    .into();
    let results: Vec<_> = sandbox_client()
        .run_script(&statements, &ScriptOptions::default())
        .unwrap()
        .map(|item| item.unwrap().into_result().unwrap())
        .collect();
    assert_eq!(results.len(), statements.len());
    assert_eq!(results[6].rows, vec![vec![Value::Bool(true)]]);
    assert_eq!(
        results[8].rows,
        vec![vec![
            Value::Int(42),
            Value::Text("INFORMATION_SCHEMA".into())
        ]]
    );
    let value = results[9]
        .columns
        .iter()
        .position(|c| c.name == "value")
        .unwrap();
    assert_eq!(
        results[9].rows[0][value],
        Value::Text("snow_rs_dfi154".into())
    );
    assert_eq!(
        results[10].rows,
        vec![vec![Value::Bool(true), Value::Int(41)]]
    );
}

/// Runs `snow sql -x --format csv -q <query>` against the sandbox; returns (exit code, stdout).
fn sandbox_sql(query: &str, extra: &[&str]) -> (i32, String) {
    let (mut cmd, _home) = sandbox_snow();
    let out = cmd
        .args(["sql", "-x", "--format", "csv", "-q", query])
        .args(extra)
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8(out.stdout).unwrap(),
    )
}

/// Drops the table when the test ends, even if it failed.
struct TableGuard(String);

impl Drop for TableGuard {
    fn drop(&mut self) {
        sandbox_sql(&format!("DROP TABLE IF EXISTS {}", self.0), &[]);
    }
}

/// With `--single-transaction` a failing statement leaves no change from the earlier
/// ones (a failure of the statement itself and a syntax error); without it the change stays.
#[test]
#[ignore = "needs the Snowflake sandbox"]
fn sandbox_single_transaction_rolls_back_and_without_it_the_change_stays() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let table = format!("PUBLIC.SNOW_RS_TX_{}_{nanos}", std::process::id());
    let _guard = TableGuard(table.clone());
    let (code, _) = sandbox_sql(&format!("CREATE TABLE {table} (n INT)"), &[]);
    assert_eq!(code, 0);
    let count = || {
        let (code, out) = sandbox_sql(&format!("SELECT COUNT(*) AS c FROM {table}"), &[]);
        assert_eq!(code, 0);
        out.lines().nth(1).unwrap().parse::<u32>().unwrap()
    };
    let flag = "--single-transaction";
    for failing in ["SELECT 1/0", "SELECT bad syntax here ("] {
        let sql = format!("INSERT INTO {table} VALUES (1); {failing}");
        let (code, _) = sandbox_sql(&sql, &[flag]);
        assert_eq!(code, 1, "{failing}");
        assert_eq!(count(), 0, "rolled back after {failing}");
    }
    // A run that succeeds commits.
    let (code, _) = sandbox_sql(
        &format!("INSERT INTO {table} VALUES (2); INSERT INTO {table} VALUES (3)"),
        &[flag],
    );
    assert_eq!(code, 0);
    assert_eq!(count(), 2);
    // Without the option the earlier change stays.
    let (code, _) = sandbox_sql(
        &format!("INSERT INTO {table} VALUES (4); SELECT 1/0"),
        &["--no-single-transaction"],
    );
    assert_eq!(code, 1);
    assert_eq!(count(), 3);
}

/// Variables reach the server rendered, in both syntaxes.
#[test]
#[ignore = "needs the Snowflake sandbox"]
fn sandbox_variables_are_rendered_before_the_sql_is_sent() {
    let (code, out) = sandbox_sql(
        "SELECT '<% x %>' AS a, &y AS b",
        &["-D", "x=hi", "-D", "y=2"],
    );
    assert_eq!(code, 1, "the two syntaxes cannot be mixed: {out}");
    let (code, out) = sandbox_sql(
        "SELECT '<% x %>' AS a, <% y %> AS b",
        &["-D", "x=hi", "-D", "y=2"],
    );
    assert_eq!((code, out.as_str()), (0, "A,B\nhi,2\n"));
    // The warning of the deprecated syntax goes to stdout first, as in snow.
    let (code, out) = sandbox_sql("SELECT '&&x' AS a, &y AS b", &["-D", "y=2"]);
    assert!(out.ends_with("A,B\n&x,2\n"), "{out}");
    assert_eq!(code, 0);
}

/// `--secondary-roles` sets the session's secondary roles (`ALL` / `NONE`), in a single
/// statement and with several, and `connection test` accepts it.
#[test]
#[ignore = "needs the Snowflake sandbox"]
fn sandbox_secondary_roles_apply_to_the_session() {
    let mode = "SELECT PARSE_JSON(CURRENT_SECONDARY_ROLES()):value::STRING AS v";
    for query in [mode.to_string(), format!("SELECT 1 AS a; {mode}")] {
        let (code, out) = sandbox_sql(&query, &["--secondary-roles", "NONE"]);
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("V\n\n"), "{query}: {out:?}");
        let (code, out) = sandbox_sql(&query, &["--secondary-roles", "all"]);
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("V\nALL\n"), "{query}: {out:?}");
    }
    let (mut cmd, _home) = sandbox_snow();
    let out = cmd
        .args(["connection", "test", "-x", "--secondary-roles", "none"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
}

/// Removes a user-stage prefix when the test ends, even if it failed.
struct StageGuard(String);

impl Drop for StageGuard {
    fn drop(&mut self) {
        sandbox_sql(&format!("REMOVE @~/{}/", self.0), &[]);
    }
}

fn sandbox_sql_format(query: &str, format: &str) -> (i32, String, String) {
    let (mut cmd, _home) = sandbox_snow();
    let out = cmd
        .args(["sql", "-x", "--format", format, "-q", query])
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

/// ADR 0005, Decision 7: `PUT` to the encrypted S3 user stage prints snow's table,
/// Snowflake reads (decrypts) what we uploaded, `GET` returns the same bytes, we decrypt a file
/// Snowflake wrote itself, a file past the multipart threshold round-trips, and the session
/// carries `SET` across the statements of the run.
#[test]
#[ignore = "needs the Snowflake sandbox"]
fn sandbox_put_get_round_trip() {
    let prefix = format!("snow_rs_test_{}", uuid::Uuid::new_v4().simple());
    let _guard = StageGuard(prefix.clone());
    let data = tempfile::tempdir().unwrap();
    std::fs::write(data.path().join("f1.csv"), b"a,b\n1,2\n").unwrap();
    std::fs::write(data.path().join("f2.csv"), b"x\n").unwrap();
    let d = data.path().display().to_string();

    // The table matches snow's golden for the same statement.
    let sql = format!("PUT file://{d}/f*.csv @~/{prefix}/");
    let (code, stdout, stderr) = sandbox_sql_format(&sql, "TABLE");
    assert_eq!(code, 0, "{stderr}");
    let goldens: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/golden/put_get/cases.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let expected = goldens
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "put_wildcard")
        .unwrap()["runs"]["TABLE"]["stdout"]
        .as_str()
        .unwrap()
        .replace("{DATA}", &d)
        .replace("{STAGE}", &prefix);
    assert_eq!(stdout, expected);

    // Snowflake decrypts what we uploaded; the session keeps SET across statements.
    let (code, stdout) = sandbox_sql(
        &format!(
            "SET v = 41; SELECT $v + 1 AS n; PUT file://{d}/f1.csv @~/{prefix}/again/; SELECT $1, $2 FROM @~/{prefix}/f1.csv.gz"
        ),
        &[],
    );
    assert_eq!(code, 0, "{stdout}");
    assert!(stdout.contains("N\n42\n"), "{stdout}");
    assert!(stdout.contains("$1,$2\na,b\n1,2\n"), "{stdout}");

    // GET returns what went up.
    let out = tempfile::tempdir().unwrap();
    let o = out.path().display().to_string();
    let (code, stdout) = sandbox_sql(
        &format!("GET @~/{prefix}/ file://{o}/ PATTERN='.*[0-9a-f]/f[12][.]csv[.]gz'"),
        &[],
    );
    assert_eq!(code, 0, "{stdout}");
    assert_eq!(
        stdout,
        "file,size,status,message\nf1.csv.gz,37,DOWNLOADED,\nf2.csv.gz,31,DOWNLOADED,\n"
    );
    let mut text = String::new();
    std::io::Read::read_to_string(
        &mut flate2::read::GzDecoder::new(
            std::fs::File::open(out.path().join("f1.csv.gz")).unwrap(),
        ),
        &mut text,
    )
    .unwrap();
    assert_eq!(text, "a,b\n1,2\n");

    // A file Snowflake wrote (COPY INTO) decrypts.
    let (code, stdout) = sandbox_sql(
        &format!(
            "COPY INTO @~/{prefix}/copy/data FROM (SELECT SEQ4() AS n FROM TABLE(GENERATOR(ROWCOUNT => 1000))) SINGLE = TRUE"
        ),
        &[],
    );
    assert_eq!(code, 0, "{stdout}");
    let copied = tempfile::tempdir().unwrap();
    let (code, stdout) = sandbox_sql(
        &format!("GET @~/{prefix}/copy/ file://{}/", copied.path().display()),
        &[],
    );
    assert_eq!(code, 0, "{stdout}");
    let entry = std::fs::read_dir(copied.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let mut text = String::new();
    std::io::Read::read_to_string(
        &mut flate2::read::GzDecoder::new(std::fs::File::open(entry.path()).unwrap()),
        &mut text,
    )
    .unwrap();
    assert_eq!(text.lines().count(), 1000);

    // Past the 64 MiB threshold: multipart up, ranged parts down.
    let big: Vec<u8> = (0..70u32 << 20)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    std::fs::write(data.path().join("big.bin"), &big).unwrap();
    let (code, stdout) = sandbox_sql(
        &format!("PUT file://{d}/big.bin @~/{prefix}/big/ AUTO_COMPRESS=FALSE"),
        &[],
    );
    assert_eq!(code, 0, "{stdout}");
    let (code, stdout) = sandbox_sql(&format!("GET @~/{prefix}/big/ file://{o}/"), &[]);
    assert_eq!(code, 0, "{stdout}");
    assert!(std::fs::read(out.path().join("big.bin")).unwrap() == big);
}

// ---- connector-protocol sign-ins (ADR 0005, Decisions 7 and 8) ----

/// The binary against the sandbox account with `extra` environment and no key.
fn sandbox_snow_without_key(extra: &[(&str, String)]) -> (assert_cmd::Command, tempfile::TempDir) {
    let home = tempfile::tempdir().unwrap();
    let mut cmd = assert_cmd::Command::cargo_bin("snow-rs").unwrap();
    cmd.env_clear().env("SNOWFLAKE_HOME", home.path());
    if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
        cmd.env("LLVM_PROFILE_FILE", profile);
    }
    if let Some(account) = var("SNOWFLAKE_ACCOUNT") {
        cmd.env("SNOWFLAKE_ACCOUNT", account);
    }
    for (name, value) in extra {
        cmd.env(name, value);
    }
    (cmd, home)
}

/// Password sign-in with the sandbox-extension user (`scripts/sandbox/0005-connector-protocol.sql`).
/// Skips, with the reason, until the maintainer has run that script and set its variables.
#[test]
#[ignore = "needs the Snowflake sandbox and the 0005 sandbox extension"]
fn sandbox_password_sign_in_and_a_wrong_password() {
    let (Some(user), Some(password)) = (
        var("SNOWFLAKE_TEST_PASSWORD_USER"),
        var("SNOWFLAKE_TEST_PASSWORD"),
    ) else {
        eprintln!(
            "skipped: SNOWFLAKE_TEST_PASSWORD_USER / SNOWFLAKE_TEST_PASSWORD are not set (run scripts/sandbox/0005-connector-protocol.sql)"
        );
        return;
    };
    let (mut cmd, _home) = sandbox_snow_without_key(&[
        ("SNOWFLAKE_USER", user.clone()),
        ("SNOWFLAKE_PASSWORD", password.clone()),
    ]);
    let out = cmd
        .args([
            "sql",
            "-x",
            "-q",
            "SELECT CURRENT_USER() AS U",
            "--format",
            "csv",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stdout.contains(&password) && !stderr.contains(&password));
    assert!(
        out.status.success(),
        "password sign-in failed (an MFA-required code here means ADR 0005 Decision 8's known risk):\n{stderr}"
    );
    assert_eq!(stdout, format!("U\n{}\n", user.to_uppercase()));

    let (mut cmd, _home) = sandbox_snow_without_key(&[
        ("SNOWFLAKE_USER", user),
        ("SNOWFLAKE_PASSWORD", format!("{password}-wrong")),
    ]);
    let out = cmd.args(["connection", "test", "-x"]).output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr.contains("390100 (28000)"), "{stderr}");
}

/// A PAT signs in through `login-request` (the session transport) as well as over the SQL API.
#[test]
#[ignore = "needs the Snowflake sandbox and the 0005 sandbox extension"]
fn sandbox_pat_over_login_request() {
    use snowflake_cli_rs::auth::{TokenAuthenticator, token};
    use snowflake_cli_rs::session::{
        BrowserOpener, Interaction, NoCache, Prompt, Session, SessionOptions,
    };
    let Some(pat) = var("SNOWFLAKE_TEST_PAT") else {
        eprintln!(
            "skipped: SNOWFLAKE_TEST_PAT is not set (run scripts/sandbox/0005-connector-protocol.sql)"
        );
        return;
    };
    struct Silent;
    impl Prompt for Silent {
        fn prompt(&self, _: &str, _: bool) -> snowflake_cli_rs::error::Result<String> {
            Ok(String::new())
        }
        fn say(&self, _: &str) {}
    }
    impl BrowserOpener for Silent {
        fn open(&self, _: &str) -> bool {
            false
        }
    }
    let mut conn = sandbox_connection();
    conn.private_key_raw = None;
    conn.authenticator = Some("PROGRAMMATIC_ACCESS_TOKEN".into());
    conn.token = Some(snowflake_cli_rs::secret::Secret::new(pat));
    let auth =
        TokenAuthenticator::from_connection(&conn, token::PROGRAMMATIC_ACCESS_TOKEN).unwrap();
    let io = Interaction {
        credential: Some(&auth),
        prompt: &Silent,
        browser: &Silent,
        cache: &NoCache,
        clock: std::time::SystemTime::now,
    };
    let session = Session::login(&conn, SessionOptions::default(), &io).unwrap();
    let rows = session
        .query("SELECT CURRENT_USER() AS U")
        .unwrap()
        .into_rows(&session)
        .unwrap()
        .into_result()
        .unwrap();
    assert_eq!(rows.rows.len(), 1);
    session.close().unwrap();
}

/// The key pair on a session with the new session options: `--server-session-keep-alive` and
/// `client_session_keep_alive` are accepted by Snowflake, and `--protocol https` works.
#[test]
#[ignore = "needs the Snowflake sandbox"]
fn sandbox_session_options_with_the_key_pair() {
    let (mut cmd, home) = sandbox_snow();
    let prefix = format!("snow_rs_test_{}", uuid::Uuid::new_v4().simple());
    let file = home.path().join("one.csv");
    std::fs::write(&file, b"1\n").unwrap();
    let config = home.path().join("config.toml");
    std::fs::write(
        &config,
        "[connections.live]\nclient_session_keep_alive = true\nclient_session_keep_alive_heartbeat_frequency = 900\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let out = cmd
        .args([
            "sql",
            "-c",
            "live",
            "--protocol",
            "https",
            "--server-session-keep-alive",
            "--format",
            "csv",
            "-q",
            // A PUT puts the run on the session transport (ADR 0005, Decision 1).
            &format!(
                "SELECT 1 AS N; PUT file://{} @~/{prefix}/; REMOVE @~/{prefix}/",
                file.display()
            ),
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.starts_with("N\n1\n"), "{stdout}");
}

/// A `;>` statement is submitted without waiting (the run ends before it does), prints
/// its query id, and really runs: `!result` of that id later returns its rows.
#[test]
#[ignore = "needs the Snowflake sandbox"]
fn sandbox_asynchronous_statement_runs_in_the_background() {
    let started = std::time::Instant::now();
    let (code, out) = sandbox_sql("SELECT SYSTEM$WAIT(6) AS w;> SELECT 1 AS a", &[]);
    assert_eq!(code, 0, "{out}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(6),
        "the run waited for the asynchronous statement"
    );
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "scheduled query ID");
    assert_eq!(&lines[2..], ["A", "1"], "{out}");
    let id = lines[1];
    assert!(
        id.len() == 36 && id.chars().all(|c| c.is_ascii_hexdigit() || c == '-'),
        "{id}"
    );
    let (code, out) = sandbox_sql(&format!("!result {id}"), &[]);
    assert_eq!((code, out.as_str()), (0, "W\nwaited 6 seconds\n"));
}
