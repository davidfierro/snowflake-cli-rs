//! The interactive session (`snow sql` with no query source), end to end on a pseudo-terminal
//! against a mocked Snowflake (`login-request`, `query-request`): the prompt, multi-line input,
//! history, each `!` command, Ctrl-C (at the prompt and cancelling a statement) and leaving.
//! The texts are what `snow` 3.34.0 prints for the same keystrokes on the sandbox.

#![cfg(unix)]

use crate::common;
use httpmock::{Method, MockServer};
use rexpect::session::PtySession;
use serde_json::{Value, json};
use std::path::Path;
use std::process::Command;

const LOGIN: &str = "/session/v1/login-request";
const QUERY: &str = "/queries/v1/query-request";
/// Bracketed paste on: the line editor starts reading (a new prompt).
const READING: &str = "\x1b[?2004h";
/// The end of a screen update: the prompt is drawn and the terminal is raw.
const DRAWN: &str = "\x1b[?2026l";
/// Bracketed paste off: the input was submitted.
const SUBMITTED: &str = "\x1b[?2004l";
const ENTER: &str = "\r";
const UP: &str = "\x1b[A";
const ID: &str = "01b2c3d4-0000-1111-2222-333344445555";

/// A mocked account: sign-in, `select current_version()` and close.
fn server() -> MockServer {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(Method::POST).path(LOGIN);
        then.status(200).json_body(json!({
            "success": true,
            "data": {
                "token": "session-token", "masterToken": "master-token", "sessionId": 4242,
                "parameters": [{"name": "TIMEZONE", "value": "UTC"}],
                "sessionInfo": {"databaseName": "TEST_DB", "schemaName": null,
                                "warehouseName": "TEST_WH", "roleName": "TEST_ROLE"},
            },
        }));
    });
    query(
        &server,
        "select current_version()",
        rows("CURRENT_VERSION()", &["9.0.0"]),
    );
    server.mock(|when, then| {
        when.method(Method::POST)
            .path("/session")
            .query_param("delete", "true");
        then.status(200).json_body(json!({"success": true}));
    });
    server
}

/// One text column `name` with `values`.
fn rows(name: &str, values: &[&str]) -> Value {
    json!({
        "queryId": ID,
        "rowtype": [{"name": name, "type": "text", "nullable": true}],
        "rowset": values.iter().map(|v| vec![*v]).collect::<Vec<_>>(),
    })
}

/// Answers the statement whose text starts with `prefix`.
fn query<'a>(server: &'a MockServer, prefix: &str, data: Value) -> httpmock::Mock<'a> {
    let needle = format!(
        "\"sqlText\":{}",
        serde_json::to_string(prefix).unwrap().trim_end_matches('"')
    );
    server.mock(|when, then| {
        when.method(Method::POST).path(QUERY).body_includes(needle);
        then.status(200)
            .json_body(json!({"success": true, "code": null, "data": data}));
    })
}

/// `snow sql -x <args>` on a pseudo-terminal, with `home` as SNOWFLAKE_HOME and the working
/// directory.
fn spawn(server: &MockServer, home: &Path, args: &[&str], env: &[(&str, &str)]) -> PtySession {
    let mut command = Command::new(env!("CARGO_BIN_EXE_snow-rs"));
    command
        .args(["sql", "-x"])
        .args(args)
        .current_dir(home)
        .env_clear()
        .env("TERM", "xterm-256color")
        .env("HOME", home)
        .env("SNOWFLAKE_HOME", home)
        .env("SNOWFLAKE_ACCOUNT", "testacct")
        .env("SNOWFLAKE_USER", "tester")
        .env("SNOWFLAKE_HOST", server.host())
        .env("SNOWFLAKE_PORT", server.port().to_string())
        .env("SNOWFLAKE_PROTOCOL", "http")
        .env("SNOWFLAKE_AUTHENTICATOR", "SNOWFLAKE_JWT")
        .env(
            "SNOWFLAKE_PRIVATE_KEY_FILE",
            common::key_path("unencrypted.p8"),
        );
    // Coverage runs hand their profile settings to the binary.
    for (key, value) in std::env::vars().filter(|(k, _)| k.starts_with("LLVM_PROFILE")) {
        command.env(key, value);
    }
    for (key, value) in env {
        command.env(key, value);
    }
    rexpect::session::spawn_command(command, Some(20_000)).unwrap()
}

/// Waits for the banner and the first prompt.
fn started(p: &mut PtySession) {
    p.exp_string(" Welcome to Snowflake-CLI REPL ").unwrap();
    p.exp_string(" Type 'exit' or 'quit' to leave ").unwrap();
    ready(p);
}

/// Waits until the next prompt is drawn and keys can be typed.
fn ready(p: &mut PtySession) {
    p.exp_string(READING).unwrap();
    p.exp_string(DRAWN).unwrap();
}

/// Types `text` and Enter, and returns what was printed up to the next prompt.
fn submit(p: &mut PtySession, text: &str) -> String {
    p.send(&format!("{text}{ENTER}")).unwrap();
    p.flush().unwrap();
    // The output is what comes between the submitted input and the next prompt.
    let printed = p.exp_string(READING).unwrap();
    p.exp_string(DRAWN).unwrap();
    let output = printed.rsplit(SUBMITTED).next().unwrap_or_default();
    let text = utf8(&strip_ansi(output)).replace('\r', "");
    text.strip_prefix('\n').unwrap_or(&text).to_string()
}

fn strip_ansi(text: &str) -> String {
    let pattern = regex::Regex::new(r"\x1b\[[0-9;?]*[A-Za-z]").unwrap();
    pattern.replace_all(text, "").into_owned()
}

/// rexpect reads one char per byte: the UTF-8 text back.
fn utf8(text: &str) -> String {
    let bytes: Vec<u8> = text.chars().map(|c| c as u32 as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Types `text` (rexpect buffers what it sends until a flush).
fn keys(p: &mut PtySession, text: &str) {
    p.send(text).unwrap();
    p.flush().unwrap();
}

fn leave(p: &mut PtySession) {
    keys(p, "\x04");
    p.exp_string("Do you want to leave? (y/n): ").unwrap();
    keys(p, "y");
    p.exp_string("Leaving REPL, bye ...").unwrap();
    p.exp_eof().unwrap();
}

#[test]
fn prompt_multi_line_history_and_leaving() {
    let server = server();
    query(&server, "select\n1 as a\n;", rows("A", &["1"]));
    let home = tempfile::tempdir().unwrap();
    let mut p = spawn(&server, home.path(), &[], &[]);
    started(&mut p);
    // Enter adds a line until the input ends with `;`; Ctrl-J always adds one.
    keys(&mut p, &format!("select{ENTER}"));
    keys(&mut p, "1 as a\n");
    let out = submit(&mut p, ";");
    assert!(
        out.contains("+---+\n| A |\n|---|\n| 1 |\n+---+\n\nTime Elapsed: "),
        "{out:?}"
    );
    // Enter on an empty input does nothing; Ctrl-C drops what was typed.
    keys(&mut p, ENTER);
    keys(&mut p, "select nothing");
    p.send_control('c').unwrap();
    p.flush().unwrap();
    ready(&mut p);
    // `exit` asks first; `n` stays.
    keys(&mut p, &format!("exit{ENTER}"));
    p.exp_string("Do you want to leave? (y/n): ").unwrap();
    keys(&mut p, "n");
    ready(&mut p);
    // The up arrow recalls earlier inputs, multi-line ones whole.
    keys(&mut p, &format!("{UP}{UP}"));
    let out = submit(&mut p, "");
    assert!(out.contains("| 1 |"), "{out:?}");
    // Ctrl-D asks too; Ctrl-C answers no, Enter yes.
    keys(&mut p, "\x04");
    p.exp_string("Do you want to leave? (y/n): ").unwrap();
    p.send_control('c').unwrap();
    p.flush().unwrap();
    ready(&mut p);
    keys(&mut p, "\x04");
    p.exp_string("Do you want to leave? (y/n): ").unwrap();
    keys(&mut p, ENTER);
    p.exp_string("\nLeaving REPL, bye ...").unwrap();
    p.exp_eof().unwrap();
    let status = format!("{:?}", p.process_mut().wait().unwrap());
    assert!(
        status.starts_with("Exited(") && status.ends_with(", 0)"),
        "{status}"
    );
    // The history file is prompt_toolkit's, next to the config file.
    let history = std::fs::read_to_string(home.path().join("repl_history")).unwrap();
    let entries: Vec<&str> = history
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .collect();
    assert_eq!(
        entries,
        [
            "+select", "+1 as a", "+;", "+exit", "+select", "+1 as a", "+;"
        ],
        "{history}"
    );
    // A new session starts with that history; with --no-prompt-exit-repl, `quit` just leaves.
    let mut p = spawn(&server, home.path(), &["--no-prompt-exit-repl"], &[]);
    started(&mut p);
    keys(&mut p, UP);
    let out = submit(&mut p, "");
    assert!(out.contains("| 1 |"), "{out:?}");
    keys(&mut p, &format!("quit{ENTER}"));
    p.exp_string("Leaving REPL, bye ...").unwrap();
    p.exp_eof().unwrap();
}

#[test]
fn ctrl_c_cancels_the_running_statement_in_snowflake() {
    let server = server();
    // The statement keeps running until it is cancelled.
    server.mock(|when, then| {
        when.method(Method::POST)
            .path(QUERY)
            .body_includes("system$wait");
        then.status(200).json_body(json!({
            "success": true, "code": "333334", "message": "running",
            "data": {"getResultUrl": "/queries/01-wait/result", "queryId": "01-wait"},
        }));
    });
    server.mock(|when, then| {
        when.method(Method::GET).path("/queries/01-wait/result");
        then.status(200).json_body(json!({
            "success": true, "code": "333334", "message": "running",
            "data": {"getResultUrl": "/queries/01-wait/result", "queryId": "01-wait"},
        }));
    });
    let abort = server.mock(|when, then| {
        when.method(Method::POST)
            .path("/queries/v1/abort-request")
            .query_param_matches("requestId", common::UUID)
            .header("authorization", "Snowflake Token=\"session-token\"")
            .body_includes("\"sqlText\":\"select system$wait(30);\"")
            .body_matches(r#""requestId":"[0-9a-f-]{36}""#);
        then.status(200).json_body(json!({"success": true}));
    });
    query(&server, "select 2", rows("B", &["2"]));
    let home = tempfile::tempdir().unwrap();
    let mut p = spawn(&server, home.path(), &["--no-prompt-exit-repl"], &[]);
    started(&mut p);
    keys(&mut p, &format!("select system$wait(30);{ENTER}"));
    std::thread::sleep(std::time::Duration::from_millis(700));
    // rexpect's child has no controlling terminal, so the line discipline cannot turn ^C into
    // SIGINT: send the signal a terminal would.
    p.process_mut()
        .signal(rexpect::process::Signal::SIGINT)
        .unwrap();
    let printed = p.exp_string(READING).unwrap();
    p.exp_string(DRAWN).unwrap();
    assert!(!printed.contains("Error occurred"), "{printed:?}");
    assert!(!printed.contains("Time Elapsed"), "{printed:?}");
    abort.assert_calls(1);
    // The session goes on.
    let out = submit(&mut p, "select 2 as b;");
    assert!(out.contains("| 2 |"), "{out:?}");
    keys(&mut p, &format!("quit{ENTER}"));
    p.exp_eof().unwrap();
}

#[test]
fn set_spool_and_errors() {
    let server = server();
    query(&server, "select 1", rows("A", &["1"]));
    server.mock(|when, then| {
        when.method(Method::POST)
            .path(QUERY)
            .body_includes("select nope");
        then.status(200).json_body(json!({
            "success": false, "code": "000904", "message": "SQL compilation error:\ninvalid identifier 'NOPE'",
            "data": {"queryId": "01-bad", "sqlState": "42000"},
        }));
    });
    let home = tempfile::tempdir().unwrap();
    let mut p = spawn(&server, home.path(), &["--no-prompt-exit-repl"], &[]);
    started(&mut p);
    // JSON: a list of results; the console (time, errors) is muted.
    assert_eq!(submit(&mut p, "!set output_format=json"), "");
    let out = submit(&mut p, "select 1 as a;");
    assert!(
        out.ends_with("[\n  [\n    {\n      \"A\"  :   \"1\"\n    }\n  ]\n]\n\n"),
        "{out:?}"
    );
    assert_eq!(submit(&mut p, "select nope;"), "[\n");
    let out = submit(&mut p, "!set output_format=table");
    assert!(out.ends_with("[\n\n]\n\n"), "{out:?}");
    // An error is reported and the session goes on.
    let out = submit(&mut p, "select nope;");
    assert!(
        out.contains(
            "\nError occurred: 000904 (42000): 01-bad: SQL compilation error:\ninvalid identifier 'NOPE'\nTime Elapsed: "
        ),
        "{out:?}"
    );
    // A bad command is a rendering error, reported before anything runs.
    let out = submit(&mut p, "!set colour=red");
    assert!(
        out.contains(
            "Unknown option passed to 'set' command: 'colour'. Only output_format, quiet, timing, timing_in_output_file, echo and output_file are supported.\n\nError occurred: SQL rendering error\n"
        ),
        "{out:?}"
    );
    assert!(!out.contains("Time Elapsed"), "{out:?}");
    // echo, timing, quiet.
    submit(&mut p, "!set echo=true");
    let out = submit(&mut p, "select 1 as a;");
    assert!(out.contains("select 1 as a;\n+---+"), "{out:?}");
    submit(&mut p, "!set echo=false");
    submit(&mut p, "!set timing=false");
    let out = submit(&mut p, "select 1 as a;");
    assert!(
        out.contains("| 1 |") && !out.contains("Time Elapsed"),
        "{out:?}"
    );
    submit(&mut p, "!set timing=true");
    submit(&mut p, "!set quiet=true");
    let out = submit(&mut p, "select 1 as a;");
    assert!(
        !out.contains("| 1 |") && !out.contains("Time Elapsed"),
        "{out:?}"
    );
    // A spool gets the results even when quiet, and the time with timing_in_output_file.
    submit(&mut p, "!spool 'out one.txt'");
    submit(&mut p, "!set timing_in_output_file=on");
    let out = submit(&mut p, "select 1 as a;");
    assert!(!out.contains("| 1 |"), "{out:?}");
    submit(&mut p, "!set quiet=false");
    submit(&mut p, "!spool off");
    submit(&mut p, "!set timing_in_output_file=off");
    submit(&mut p, "!set output_file=two.txt");
    submit(&mut p, "select 1 as a;");
    submit(&mut p, "!spool off");
    keys(&mut p, &format!("quit{ENTER}"));
    p.exp_eof().unwrap();
    let one = std::fs::read_to_string(home.path().join("out one.txt")).unwrap();
    assert!(
        one.starts_with("+---+\n| A |\n|---|\n| 1 |\n+---+\nTime Elapsed: "),
        "{one:?}"
    );
    let two = std::fs::read_to_string(home.path().join("two.txt")).unwrap();
    assert_eq!(two, "+---+\n| A |\n|---|\n| 1 |\n+---+\n");
}

#[test]
fn queries_result_abort_rehash_and_source() {
    let server = server();
    let monitoring = server.mock(|when, then| {
        when.method(Method::GET)
            .path("/monitoring/queries")
            .query_param("includeDDL", "false")
            .query_param("max", "25")
            .query_param("session_id", "4242")
            .query_param_exists("_dc")
            .header("authorization", "Snowflake Token=\"session-token\"");
        then.status(200).json_body(json!({"data": {"queries": [
            {"id": ID, "sqlText": "select 1", "state": "SUCCEEDED", "totalDuration": 27},
        ]}}));
    });
    let filtered = server.mock(|when, then| {
        when.method(Method::GET)
            .path("/monitoring/queries")
            .query_param("max", "3")
            .query_param("user", "jdoe")
            .query_param("subset", "FAILED")
            .query_param("stmt_type", "SELECT");
        then.status(200).json_body(json!({"data": {"queries": []}}));
    });
    let result = server.mock(|when, then| {
        when.method(Method::GET)
            .path(format!("/queries/{ID}/result"));
        then.status(200)
            .json_body(json!({"success": true, "code": null, "data": rows("R", &["from before"])}));
    });
    let abort = query(
        &server,
        &format!("SELECT SYSTEM$CANCEL_QUERY('{ID}')"),
        rows("SYSTEM$CANCEL_QUERY", &["query aborted"]),
    );
    query(&server, "select 'sourced'", rows("S", &["sourced"]));
    let home = tempfile::tempdir().unwrap();
    std::fs::write(home.path().join("in.sql"), "select 'sourced' as s;\n").unwrap();
    let mut p = spawn(&server, home.path(), &["--no-prompt-exit-repl"], &[]);
    started(&mut p);
    let out = submit(&mut p, "!queries");
    assert!(
        out.contains(&format!("| QUERY ID                             | SQL TEXT | STATUS    | DURATION_MS |\n|--------------------------------------+----------+-----------+-------------|\n| {ID} | select 1 | SUCCEEDED | 27          |")),
        "{out:?}"
    );
    assert_eq!(
        submit(
            &mut p,
            "!queries amount=3 user=jdoe status=failed type=select"
        ),
        ""
    );
    let out = submit(&mut p, "!queries help");
    assert!(out.contains("| session    | No arguments "), "{out:?}");
    let out = submit(&mut p, &format!("!result {ID}"));
    assert!(out.contains("| from before |"), "{out:?}");
    let out = submit(&mut p, &format!("!abort {ID}"));
    assert!(out.contains("| query aborted       |"), "{out:?}");
    let out = submit(&mut p, "!rehash");
    assert!(out.ends_with("Autocomplete is disabled.\n"), "{out:?}");
    let out = submit(&mut p, "!source in.sql");
    assert!(out.contains("| sourced |"), "{out:?}");
    keys(&mut p, &format!("quit{ENTER}"));
    p.exp_eof().unwrap();
    monitoring.assert();
    filtered.assert();
    result.assert();
    abort.assert();
}

#[test]
fn edit_loads_the_edited_statement_into_the_prompt() {
    let server = server();
    query(&server, "select 40", rows("X", &["40"]));
    query(&server, "select 41", rows("X", &["41"]));
    let home = tempfile::tempdir().unwrap();
    // No editor.
    let mut p = spawn(&server, home.path(), &["--no-prompt-exit-repl"], &[]);
    started(&mut p);
    let out = submit(&mut p, "!edit select 1;");
    assert!(
        out.contains(
            "\nError occurred: No editor is set. Please set the EDITOR environment variable.\n"
        ),
        "{out:?}"
    );
    keys(&mut p, &format!("quit{ENTER}"));
    p.exp_eof().unwrap();
    // BSD sed (macOS) needs an explicit empty backup suffix after -i.
    let sed_in_place = if cfg!(target_os = "macos") {
        "sed -i '' s/41/40/"
    } else {
        "sed -i s/41/40/"
    };
    // An editor that rewrites the file: the last statement is edited, then run with Enter.
    let mut p = spawn(
        &server,
        home.path(),
        &["--no-prompt-exit-repl"],
        &[("EDITOR", sed_in_place), ("PATH", "/usr/bin:/bin")],
    );
    started(&mut p);
    let out = submit(&mut p, "select 41 as x;");
    assert!(out.contains("| 41 |"), "{out:?}");
    let out = submit(&mut p, "!edit");
    assert!(
        out.ends_with(
            "✓ Edited SQL loaded into prompt. Modify as needed or press Enter to execute.\n"
        ),
        "{out:?}"
    );
    let out = submit(&mut p, "");
    assert!(out.contains("| 40 |"), "{out:?}");
    // An editor that empties the file; one that fails.
    keys(&mut p, &format!("quit{ENTER}"));
    p.exp_eof().unwrap();
    for (editor, message) in [
        ("truncate -s 0", "Editor closed with no content."),
        ("false", "Error occurred: false: Editing failed"),
    ] {
        let mut p = spawn(
            &server,
            home.path(),
            &["--no-prompt-exit-repl"],
            &[("EDITOR", editor), ("PATH", "/usr/bin:/bin")],
        );
        started(&mut p);
        let out = submit(&mut p, "!edit select 1;");
        assert!(out.contains(message), "{editor}: {out:?}");
        keys(&mut p, &format!("quit{ENTER}"));
        p.exp_eof().unwrap();
    }
}

#[test]
fn the_prompt_format_follows_use_and_colours() {
    let server = server();
    query(
        &server,
        "use schema s",
        json!({"queryId": ID, "finalDatabaseName": "TEST_DB", "finalSchemaName": "S",
               "finalRoleName": "TEST_ROLE",
               "rowtype": [{"name": "status", "type": "text", "nullable": true}],
               "rowset": [["Statement executed successfully."]]}),
    );
    let home = tempfile::tempdir().unwrap();
    let mut p = spawn(
        &server,
        home.path(),
        &[
            "--no-prompt-exit-repl",
            "--prompt-format",
            "[user]@[database].[schema] [connection]> ",
        ],
        &[],
    );
    p.exp_string("Welcome to Snowflake-CLI REPL").unwrap();
    p.exp_string("tester@TEST_DB.(no schema) (no connection)> ")
        .unwrap();
    p.exp_string(DRAWN).unwrap();
    keys(&mut p, &format!("use schema s;{ENTER}"));
    p.exp_string("Statement executed successfully.").unwrap();
    p.exp_string("tester@TEST_DB.S (no connection)> ").unwrap();
    p.exp_string(DRAWN).unwrap();
    keys(&mut p, &format!("quit{ENTER}"));
    p.exp_eof().unwrap();
    // Colours, in the 256-colour palette by default.
    let mut p = spawn(
        &server,
        home.path(),
        &["--prompt-format", "[#ff0000][role]> "],
        &[],
    );
    p.exp_string("\x1b[0;38;5;196mTEST_ROLE> \x1b[0m").unwrap();
    p.exp_string(DRAWN).unwrap();
    leave(&mut p);
}

#[test]
fn one_shot_runs_take_the_commands_too() {
    let server = server();
    query(&server, "select 1", rows("A", &["1"]));
    query(&server, "select 2", rows("B", &["2"]));
    query(
        &server,
        &format!("SELECT SYSTEM$CANCEL_QUERY('{ID}')"),
        rows("C", &["aborted"]),
    );
    let home = tempfile::tempdir().unwrap();
    let run = |sql: &str| {
        let mut p = spawn(&server, home.path(), &["-q", sql], &[]);
        let out = utf8(&p.exp_eof().unwrap()).replace('\r', "");
        drop(p);
        out
    };
    // `!abort` needs a session, so the run signs in and runs everything on it. The echo is
    // console output: it stops once the format is CSV.
    assert_eq!(
        run(&format!(
            "!abort {ID}\nselect 1 as a;\n!set output_format=csv\nselect 2 as b"
        )),
        "+---------+\n| C       |\n|---------|\n| aborted |\n+---------+\n\
         select 1 as a;\n+---+\n| A |\n|---|\n| 1 |\n+---+\nB\n2\n"
    );
    // A spool file opened by a command; `!rehash` on the console.
    let out = run(&format!(
        "!abort {ID}\n!spool spooled.txt\nselect 1 as a;\n!spool off\n!rehash"
    ));
    assert!(
        out.ends_with("+---+\nAutocomplete is disabled.\n"),
        "{out:?}"
    );
    assert_eq!(
        std::fs::read_to_string(home.path().join("spooled.txt")).unwrap(),
        "+---+\n| A |\n|---|\n| 1 |\n+---+\n"
    );
    // `!edit` needs the interactive session.
    let out = run("!edit");
    assert!(
        out.contains("The edit command can only be used in interactive mode."),
        "{out:?}"
    );
}

#[test]
fn asynchronous_statements_print_their_query_id() {
    let server = server();
    let submit_mock = server.mock(|when, then| {
        when.method(Method::POST)
            .path(QUERY)
            .json_body_includes(json!({"sqlText": "select 1 as a", "asyncExec": true}).to_string());
        then.status(200).json_body(json!({
            "success": true, "code": "333334", "data": {"queryId": ID, "getResultUrl": "/x"},
        }));
    });
    query(&server, "select 2 as b;", rows("B", &["2"]));
    server.mock(|when, then| {
        when.method(Method::GET)
            .path(format!("/monitoring/queries/{ID}"));
        then.status(200)
            .json_body(json!({"success": true, "data": {"queries": [{"status": "SUCCESS"}]}}));
    });
    let home = tempfile::tempdir().unwrap();
    let mut p = spawn(&server, home.path(), &[], &[]);
    started(&mut p);
    // As in snow: the query id as a table (and rich's empty line on a terminal), then the
    // next statement. An input ending in `;>` does not submit on Enter.
    keys(&mut p, &format!("select 1 as a;>{ENTER}"));
    let out = submit(&mut p, "select 2 as b;");
    let id_table = format!(
        "+--------------------------------------+\n\
         | scheduled query ID                   |\n\
         |--------------------------------------|\n\
         | {ID} |\n\
         +--------------------------------------+\n\n"
    );
    assert!(out.contains(&id_table), "{out:?}");
    assert!(
        out.contains("+---+\n| B |\n|---|\n| 2 |\n+---+\n\nTime Elapsed: "),
        "{out:?}"
    );
    assert!(out.find(&id_table) < out.find("| 2 |"), "{out:?}");
    submit_mock.assert();
    leave(&mut p);
}
