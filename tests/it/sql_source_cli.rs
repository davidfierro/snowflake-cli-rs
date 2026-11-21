//! `!source`/`!load` and `--local-only` through the CLI, offline: every case fails (or stops)
//! before a connection is made. Expected texts captured from snow 3.34.0.

use httpmock::MockServer;
use snowflake_cli_rs::commands::TerminalPrompter;
use snowflake_cli_rs::env::Env;

const FEEDBACK: &str = "To send feedback about Snowflake CLI: snow feedback\n";
const RENDERING_ERROR: &str = "╭─ Error ──────────────────────────────────────────────────────────────────────╮\n\
     │ SQL rendering error                                                          │\n\
     ╰──────────────────────────────────────────────────────────────────────────────╯\n";

fn run(args: &[&str], env: &[(&str, &str)], config: Option<&str>) -> (i32, String, String) {
    let home = tempfile::tempdir().unwrap();
    if let Some(config) = config {
        let path = home.path().join("config.toml");
        std::fs::write(&path, config).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    let mut pairs = vec![(
        "SNOWFLAKE_HOME".to_string(),
        home.path().display().to_string(),
    )];
    pairs.extend(env.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    let args = ["snow-rs", "sql", "-x"].iter().chain(args).copied();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut input: &[u8] = b"";
    let _log = crate::common::logger_guard();
    let code = snowflake_cli_rs::run_with(
        args,
        Env::from_pairs(pairs),
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

/// The run fails while compiling: the lines on stdout, then snow's error panel.
fn fails(args: &[&str], expected_stdout: &str) {
    let (code, out, err) = run(args, &[], None);
    assert_eq!(out, expected_stdout, "{args:?}");
    assert_eq!(code, 1, "{args:?}");
    assert_eq!(err, format!("{RENDERING_ERROR}{FEEDBACK}"), "{args:?}");
}

#[test]
fn a_missing_file_is_reported_with_the_path_as_written() {
    fails(
        &["-q", "!source /nonexistent/a.sql"],
        "Could not read: /nonexistent/a.sql\n",
    );
}

#[test]
fn a_cycle_is_reported_with_the_chain() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.sql");
    let b = dir.path().join("b.sql");
    std::fs::write(&a, format!("select 1;\n!source {}\n", b.display())).unwrap();
    std::fs::write(&b, format!("!load {}\n", a.display())).unwrap();
    let canon = |p: &std::path::Path| std::fs::canonicalize(p).unwrap().display().to_string();
    fails(
        &["-f", a.to_str().unwrap()],
        &format!("Recursion detected: {} -> {}\n", canon(&a), canon(&b)),
    );
}

#[test]
fn http_and_other_schemes_are_refused_without_a_request() {
    let server = MockServer::start();
    let any = server.mock(|when, then| {
        when.any_request();
        then.status(200).body("select 1;");
    });
    let url = server.url("/a.sql");
    fails(
        &["-q", &format!("!source {url}")],
        &format!(
            "Plaintext http:// sources are not allowed: {url}. Use https:// or a local file.\n"
        ),
    );
    fails(
        &["-q", "!source ftp://h/a.sql"],
        "Unknown source: ftp://h/a.sql\n",
    );
    assert_eq!(any.calls(), 0);
}

#[test]
fn an_unreachable_https_url_is_a_fetch_error() {
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let url = format!("https://127.0.0.1:{port}/a.sql");
    fails(
        &["-q", &format!("!source {url}")],
        &format!("Could not fetch {url}: <urlopen error [Errno 111] Connection refused>\n"),
    );
}

#[test]
fn local_only_refuses_urls_from_the_flag_the_env_and_the_config() {
    let query = "!source https://example.invalid/a.sql";
    let expected =
        "Loading SQL from URLs is disabled (--local-only): https://example.invalid/a.sql\n";
    fails(&["-q", query, "--local-only"], expected);
    let check = |env: &[(&str, &str)], config: Option<&str>| {
        let (code, out, _) = run(&["-q", query], env, config);
        assert_eq!((code, out.as_str()), (1, expected), "{env:?} {config:?}");
    };
    check(&[("SNOWFLAKE_CLI_SQL_LOCAL_ONLY", "true")], None);
    check(&[("SNOWFLAKE_CLI_SQL_LOCAL_ONLY", "1")], None);
    check(&[], Some("[cli]\nsql_local_only = true\n"));
    check(&[], Some("[cli]\nsql_local_only = \"true\"\n"));
    // Not set, or set to false: the URL is fetched (and fails here, as the host is invalid).
    for (env, config) in [
        (vec![("SNOWFLAKE_CLI_SQL_LOCAL_ONLY", "false")], None),
        (vec![], Some("[cli]\nsql_local_only = false\n")),
        (vec![], None),
    ] {
        let (_, out, _) = run(&["-q", query], &env, config);
        assert!(
            out.starts_with("Could not fetch https://example.invalid/a.sql"),
            "{out}"
        );
    }
}

#[test]
fn an_invalid_local_only_setting_is_an_error() {
    let (code, _, err) = run(
        &["-q", "select 1"],
        &[("SNOWFLAKE_CLI_SQL_LOCAL_ONLY", "maybe")],
        None,
    );
    assert_eq!(code, 1);
    assert!(
        err.contains("Expected boolean value for cli.sql_local_only option."),
        "{err}"
    );
    let (code, _, err) = run(
        &["-q", "select 1"],
        &[],
        Some("[cli]\nsql_local_only = [1]\n"),
    );
    assert_eq!(code, 1);
    assert!(err.contains("Expected boolean value"), "{err}");
}

#[test]
fn escape_bytes_in_a_notice_are_not_printed_raw() {
    let (_, out, _) = run(&["-q", "!source /nonexistent/\u{1b}[2Ja.sql"], &[], None);
    assert!(!out.contains('\u{1b}'), "{out:?}");
    assert!(out.starts_with("Could not read: /nonexistent/"), "{out:?}");
}
