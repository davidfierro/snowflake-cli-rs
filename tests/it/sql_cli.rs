//! `snow sql` input rules, offline (ADR 0004, Decision 1). Expected texts captured from snow
//! 3.34.0 (`snow sql -x …` in an empty SNOWFLAKE_HOME).

use snowflake_cli_rs::commands::TerminalPrompter;
use snowflake_cli_rs::env::Env;

const TOP: &str =
    "╭─ Error ──────────────────────────────────────────────────────────────────────╮\n";
const BOTTOM: &str =
    "╰──────────────────────────────────────────────────────────────────────────────╯\n";
const USAGE: &str = "Usage: snow-rs sql [OPTIONS]\nTry 'snow-rs sql --help' for help.\n";
const FEEDBACK: &str = "To send feedback about Snowflake CLI: snow feedback\n";

/// Runs `snow sql -x <args>` in-process with `stdin`; returns `(exit code, stdout, stderr)`.
fn run(args: &[&str], stdin: Option<&str>) -> (i32, String, String) {
    let home = tempfile::tempdir().unwrap();
    let env = Env::from_pairs([("SNOWFLAKE_HOME", home.path().display().to_string())]);
    let args = ["snow-rs", "sql", "-x"].iter().chain(args).copied();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut input = stdin.unwrap_or_default().as_bytes();
    let _log = crate::common::logger_guard();
    let code = snowflake_cli_rs::run_with(
        args,
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

fn panel(lines: &[&str]) -> String {
    let mut text = TOP.to_string();
    for line in lines {
        text.push_str(&format!("│ {line:<76} │\n"));
    }
    text.push_str(BOTTOM);
    text
}

#[test]
fn sources_are_mutually_exclusive_and_named_in_command_line_order() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let path = file.path().to_str().unwrap();
    let conflict = |second: &str, first: &str| {
        let message = format!(
            "Parameters '{second}' and '{first}' are incompatible and cannot be used simultaneously."
        );
        let (head, tail) = message.split_at(message[..77].rfind(' ').unwrap());
        format!("{USAGE}{}", panel(&[head, tail.trim_start()]))
    };
    for (args, second, first) in [
        (vec!["-q", "select 1", "-f", path], "--filename", "--query"),
        (vec!["-f", path, "-q", "select 1"], "--query", "--filename"),
        (vec!["-f", path, "-i"], "--stdin", "--filename"),
        (vec!["-i", "-q", "select 1"], "--query", "--stdin"),
    ] {
        let (code, out, err) = run(&args, Some(""));
        assert_eq!(code, 2, "{args:?}");
        assert_eq!(out, "");
        assert_eq!(err, conflict(second, first), "{args:?}");
    }
}

#[test]
fn a_missing_file_or_a_directory_is_a_usage_error() {
    let (code, _, err) = run(&["-f", "missing.sql"], None);
    assert_eq!(code, 2);
    assert_eq!(
        err,
        format!(
            "{USAGE}{}",
            panel(&["Invalid value for '--filename' / '-f': File 'missing.sql' does not exist."])
        )
    );
    let (code, _, err) = run(&["-f", "."], None);
    assert_eq!(code, 2);
    assert_eq!(
        err,
        format!(
            "{USAGE}{}",
            panel(&["Invalid value for '--filename' / '-f': File '.' is a directory."])
        )
    );
}

#[test]
fn no_statement_left_is_an_error() {
    let (code, out, err) = run(&["-i", "--format", "json"], Some("-- only\n"));
    assert_eq!((code, out.as_str()), (1, ""));
    assert_eq!(err, panel(&["No SQL statements found to execute."]));
    // TABLE adds the feedback line.
    let (code, _, err) = run(&["-q", "/* nothing */"], None);
    assert_eq!(code, 1);
    assert_eq!(
        err,
        format!(
            "{}{FEEDBACK}",
            panel(&["No SQL statements found to execute."])
        )
    );
}

#[test]
fn empty_stdin_with_dash_i_is_an_error() {
    let (code, _, err) = run(&["-i"], Some(""));
    assert_eq!(code, 1);
    assert_eq!(
        err,
        format!(
            "{}{FEEDBACK}",
            panel(&["Use either query, filename or input option."])
        )
    );
}

#[test]
fn without_a_source_the_interactive_session_starts() {
    // The banner, then the sign-in, which `-x` without an account cannot do.
    for (args, stdin) in [
        (vec![], None),
        (vec![], Some("  \n")),
        (vec!["-q", ""], None),
    ] {
        let (code, out, err) = run(&args, stdin);
        assert_eq!(code, 1, "{args:?} {stdin:?}");
        assert!(out.starts_with("╭───"), "{args:?} {stdin:?}: {out}");
        assert!(out.contains("│ Welcome to Snowflake-CLI REPL "), "{out}");
        assert!(
            err.contains("│ The connection has no account or host."),
            "{err}"
        );
    }
    // The banner is console output: not in JSON.
    let (_, out, _) = run(&["--format", "json"], None);
    assert_eq!(out, "");
}

#[test]
fn the_interactive_session_refuses_a_single_transaction() {
    let (code, out, err) = run(&["--single-transaction"], None);
    assert_eq!(code, 1);
    assert_eq!(out, "");
    assert_eq!(
        err,
        format!(
            "{}{FEEDBACK}",
            panel(&["single transaction cannot be used with REPL"])
        )
    );
}

#[test]
fn piped_stdin_without_a_flag_is_the_query() {
    // It gets as far as the connection, which `-x` without an account cannot build.
    let (code, _, err) = run(&[], Some("select 1"));
    assert_eq!(code, 1);
    assert!(!err.contains("interactive"), "{err}");
}

#[test]
fn bad_interactive_commands_are_rendering_errors() {
    let (code, out, err) = run(&["-q", "!set nope=1;\n!abort"], None);
    assert_eq!(code, 1);
    assert_eq!(
        out,
        "Unknown option passed to 'set' command: 'nope'. Only output_format, quiet, timing, \
         timing_in_output_file, echo and output_file are supported.\n\
         No arguments passed to 'abort' command. Usage: `!abort <query id>`\n"
    );
    assert_eq!(
        err,
        format!("{}{FEEDBACK}", panel(&["SQL rendering error"]))
    );
}

#[test]
fn edit_needs_the_interactive_session() {
    // Commands that need no session run before the connection would be needed.
    let (code, _, err) = run(&["-q", "!edit"], None);
    assert_eq!(code, 1);
    assert!(
        err.contains("│ The connection has no account or host."),
        "{err}"
    );
}

#[test]
fn files_are_read_in_order() {
    let a = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(a.path(), "-- nothing here\n").unwrap();
    let (code, _, err) = run(&["-f", a.path().to_str().unwrap(), "--format", "csv"], None);
    assert_eq!(code, 1);
    assert_eq!(err, panel(&["No SQL statements found to execute."]));
}

#[test]
fn undefined_variables_are_all_reported_on_stdout_before_anything_runs() {
    let (code, out, err) = run(&["-q", "select &a; select <% b %>; select 1"], None);
    assert_eq!(code, 1);
    assert_eq!(
        out,
        "Warning: &{ ... } syntax is deprecated and will no longer be supported. \
         Use <% ... %> syntax instead.\n\
         SQL template rendering error: 'a' is undefined\n\
         SQL template rendering error: 'b' is undefined\n"
    );
    assert_eq!(
        err,
        format!("{}{FEEDBACK}", panel(&["SQL rendering error"]))
    );
}

#[test]
fn mixing_the_syntaxes_is_an_error_and_a_mode_left_out_is_not_rendered() {
    let (code, out, err) = run(&["-q", "select &a <% b %>", "-D", "a=1", "-D", "b=2"], None);
    assert_eq!((code, out.as_str()), (1, ""));
    assert_eq!(
        err,
        format!(
            "{}{FEEDBACK}",
            panel(&["The SQL query mixes &{ ... } syntax and <% ... %> syntax."])
        )
    );
    // With STANDARD only, `&b` is plain text: the first error is the undefined `<% a %>`.
    let (code, out, _) = run(
        &["-q", "select &b <% a %>", "--enable-templating", "standard"],
        None,
    );
    assert_eq!(code, 1);
    assert_eq!(out, "SQL template rendering error: 'a' is undefined\n");
}

#[test]
fn variables_must_be_key_value_pairs_and_ctx_and_fn_are_reserved() {
    let (code, out, err) = run(&["-q", "select 1", "-D", "novalue"], None);
    assert_eq!((code, out.as_str()), (1, ""));
    // A plain click exception in snow: no feedback line.
    assert_eq!(err, panel(&["Invalid variable: 'novalue'"]));
    let (code, _, err) = run(&["-q", "select 1", "-D", "ctx=1"], None);
    assert_eq!(code, 1);
    assert_eq!(
        err,
        panel(&["ctx in user defined data. The `ctx` variable is reserved for CLI usage."])
    );
}

#[test]
fn enable_templating_values_are_checked() {
    let (code, out, err) = run(
        &[
            "-q",
            "select 1",
            "--enable-templating",
            "NONE",
            "--enable-templating",
            "LEGACY",
        ],
        None,
    );
    assert_eq!((code, out.as_str()), (2, ""));
    assert_eq!(
        err,
        format!(
            "{USAGE}{}",
            panel(&["ALL and NONE template syntax options should not be used with other options."])
        )
    );
    // clap rejects an unknown value itself (exit 2).
    let (code, _, _) = run(&["-q", "select 1", "--enable-templating", "bogus"], None);
    assert_eq!(code, 2);
}

/// Runs `snow sql -x <args>` with `config` as config.toml, in a temporary directory that is
/// also the working directory of relative spool paths; returns `(code, stdout, stderr, dir)`.
fn run_in(
    args: &[&str],
    config: &str,
    stdin: Option<&str>,
) -> (i32, String, String, tempfile::TempDir) {
    let home = tempfile::tempdir().unwrap();
    let config_path = home.path().join("config.toml");
    std::fs::write(&config_path, config).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let env = Env::from_pairs([("SNOWFLAKE_HOME", home.path().display().to_string())]);
    let args = ["snow-rs", "sql", "-x"].iter().chain(args).copied();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut input = stdin.unwrap_or_default().as_bytes();
    let _log = crate::common::logger_guard();
    let code = snowflake_cli_rs::run_with(
        args,
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
        home,
    )
}

#[test]
fn the_spool_file_is_created_only_once_the_arguments_and_config_are_valid() {
    let dir = tempfile::tempdir().unwrap();
    let spool = dir.path().join("out.txt");
    let output_file = format!("output_file={}", spool.display());
    let missing = dir.path().join("missing.sql");
    for (args, config, message) in [
        (
            vec!["-q", "select 1"],
            "[cli]\nsql_local_only = \"maybe\"\n",
            "Expected boolean value for cli.sql_local_only option.",
        ),
        (
            vec!["-q", "select 1"],
            "[cli]\nno_prompt_exit_repl = \"maybe\"\n",
            "Expected boolean value for cli.no_prompt_exit_repl option.",
        ),
        (
            vec!["-q", "select 1", "-o", "quiet=maybe"],
            "",
            "Invalid value for quiet",
        ),
        (vec!["-f", missing.to_str().unwrap()], "", "does not exist"),
        (
            vec!["-q", "select 1", "-D", "novalue"],
            "",
            "Invalid variable",
        ),
        (
            vec!["--single-transaction"],
            "",
            "single transaction cannot be used with REPL",
        ),
        (
            vec![],
            "[cli]\nprompt_format = 5\n",
            "Expected a string for cli.prompt_format, got int.",
        ),
    ] {
        let mut args = args.clone();
        args.extend(["-o", output_file.as_str()]);
        let (code, _, err, _home) = run_in(&args, config, None);
        assert_ne!(code, 0, "{args:?}: {err}");
        assert!(err.contains(message), "{args:?}: {err}");
        assert!(!spool.exists(), "{args:?} created the spool");
    }
    // A rendering error comes after the spool opened, as in snow: the file is there.
    let (code, out, _, _home) = run_in(
        &["-q", "select <% x %>", "-o", output_file.as_str()],
        "",
        None,
    );
    assert_eq!(code, 1);
    assert_eq!(out, "SQL template rendering error: 'x' is undefined\n");
    assert!(spool.exists());
}

#[test]
fn config_bool_errors_have_no_feedback_line() {
    let (code, _, err, _home) = run_in(
        &["-q", "select 1"],
        "[cli]\nno_prompt_exit_repl = \"maybe\"\n",
        None,
    );
    assert_eq!(code, 1);
    assert_eq!(
        err,
        panel(&["Expected boolean value for cli.no_prompt_exit_repl option."])
    );
}

#[test]
fn the_prompt_format_is_checked_and_its_unknown_tokens_reported_on_stderr() {
    let (code, out, err, _home) = run_in(&[], "[cli]\nprompt_format = [1]\n", None);
    assert_eq!(code, 1);
    assert_eq!(out, "", "before the banner");
    assert_eq!(
        err,
        format!(
            "{}{FEEDBACK}",
            panel(&[
                "Expected a string for cli.prompt_format, got list. Use a quoted value, for",
                "example prompt_format = \"[user]> \".",
            ])
        )
    );
    let warning = "Ignoring unknown prompt placeholder(s) '[nope]'. Supported placeholders are \
        [user], [host], [account], [role], [warehouse], [database], [schema], [connection]. Use \
        \\[ \\] \\\\ for literal brackets and backslash.\n";
    // From the config, and from the flag (which wins).
    let (_, _, err, _home) = run_in(&[], "[cli]\nprompt_format = \"[nope]> \"\n", None);
    assert!(err.starts_with(warning), "{err}");
    let (_, _, err, _home) = run_in(
        &["--prompt-format", "[nope]> "],
        "[cli]\nprompt_format = \"[user]> \"\n",
        None,
    );
    assert!(err.starts_with(warning), "{err}");
    let (_, _, err, _home) = run_in(&["--prompt-format", "[user]> "], "", None);
    assert!(!err.contains("Ignoring"), "{err}");
    // Not in JSON (the console is muted), and not with a query source.
    let (_, _, err, _home) = run_in(&["--prompt-format", "[nope]", "--format", "json"], "", None);
    assert!(!err.contains("Ignoring"), "{err}");
    let (_, _, err, _home) = run_in(&["--prompt-format", "[nope]", "-q", "select 1"], "", None);
    assert!(!err.contains("Ignoring"), "{err}");
}

#[test]
fn a_blank_pipe_starts_the_session_with_a_warning() {
    let (code, out, err, _home) = run_in(&[], "", Some("\n"));
    assert_eq!(code, 1);
    assert!(
        err.starts_with("Warning: Input is not a terminal (fd=0).\n"),
        "{err}"
    );
    assert!(out.contains("Welcome to Snowflake-CLI REPL"), "{out}");
}
