//! The global options: `--version`, `--info`, `--structure`, completion,
//! `--no-auto-upgrade`, `--enhanced-exit-codes` and `--decimal-precision`. Expected texts and
//! codes captured from snow 3.34.0.

use crate::common;

use clap::CommandFactory;
use httpmock::MockServer;
use snowflake_cli_rs::Cli;
use snowflake_cli_rs::commands::TerminalPrompter;
use snowflake_cli_rs::completion;
use snowflake_cli_rs::env::Env;
use snowflake_cli_rs::matrix::{Snapshot, ported_surface};
use snowflake_cli_rs::output::format::OutputFormat;
use snowflake_cli_rs::render::render;
use snowflake_cli_rs::sql::ClientOptions;
use std::collections::BTreeSet;

/// Runs the CLI in-process with `pairs` as the whole environment; `(code, stdout, stderr)`.
fn run(args: &[&str], pairs: &[(&str, String)]) -> (i32, String, String) {
    let env = Env::from_pairs(pairs.iter().cloned());
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let _log = crate::common::logger_guard();
    let code = snowflake_cli_rs::run_with(
        std::iter::once("snow-rs").chain(args.iter().copied()),
        env,
        snowflake_cli_rs::Stdin {
            is_tty: true,
            reader: &mut std::io::empty(),
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

fn home() -> (tempfile::TempDir, Vec<(&'static str, String)>) {
    let dir = tempfile::tempdir().unwrap();
    let pairs = vec![
        ("SNOWFLAKE_HOME", dir.path().display().to_string()),
        ("HOME", dir.path().display().to_string()),
    ];
    (dir, pairs)
}

#[test]
fn version_prints_snows_line() {
    let (code, out, err) = run(&["--version"], &[]);
    assert_eq!(
        (code, out.as_str(), err.as_str()),
        (
            0,
            concat!("Snowflake CLI version: ", env!("CARGO_PKG_VERSION"), "\n"),
            ""
        )
    );
}

#[test]
fn info_is_json_key_value_pairs_in_snows_layout() {
    let (dir, env) = home();
    let (code, out, _) = run(&["--info"], &env);
    assert_eq!(code, 0);
    let items: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
    let keys: Vec<&str> = items.iter().map(|i| i["key"].as_str().unwrap()).collect();
    assert_eq!(
        keys,
        [
            "version",
            "compatible_snow_version",
            "default_config_file_path",
            "system_info",
            "installation_source",
            "feature_flags",
            "SNOWFLAKE_HOME"
        ]
    );
    let value = |k: &str| items.iter().find(|i| i["key"] == k).unwrap()["value"].clone();
    assert_eq!(value("version"), env!("CARGO_PKG_VERSION"));
    assert_eq!(value("compatible_snow_version"), "3.34.0");
    assert_eq!(value("feature_flags"), serde_json::json!({}));
    assert_eq!(value("SNOWFLAKE_HOME"), dir.path().display().to_string());
    assert_eq!(
        value("default_config_file_path"),
        dir.path().join("config.toml").display().to_string()
    );
    // snow's layout: a JSON array, four-space indent, always JSON whatever the format.
    assert!(
        out.starts_with("[\n    {\n        \"key\": \"version\","),
        "{out}"
    );
    let (_, with_format, _) = run(&["--info", "--no-auto-upgrade"], &env);
    assert_eq!(with_format, out);
}

#[test]
fn info_without_snowflake_home_says_null() {
    let (_, out, _) = run(&["--info"], &[("HOME", "/nonexistent-home".into())]);
    assert!(
        out.contains("\"key\": \"SNOWFLAKE_HOME\",\n        \"value\": null"),
        "{out}"
    );
}

#[test]
fn no_auto_upgrade_is_accepted_and_does_nothing() {
    assert_eq!(
        run(&["--no-auto-upgrade"], &[]),
        (0, String::new(), String::new())
    );
    let help = Cli::command().render_help().to_string();
    assert!(help.contains("no auto-upgrade"), "{help}");
}

// --- --structure -------------------------------------------------------------------------

fn structure() -> serde_json::Value {
    let (code, out, err) = run(&["--structure"], &[]);
    assert_eq!((code, err.as_str()), (0, ""));
    serde_json::from_str(&out).unwrap()
}

fn keys(v: &serde_json::Value) -> BTreeSet<&str> {
    v.as_object().unwrap().keys().map(String::as_str).collect()
}

/// Every node has `name` and `help`, plus `arguments`, `options` and `commands` when it has
/// any; every option has `name`, `help`, `required` and `flags`.
fn check_shape(node: &serde_json::Value) {
    let allowed = BTreeSet::from(["name", "help", "arguments", "options", "commands"]);
    let ks = keys(node);
    assert!(ks.contains("name") && ks.contains("help"), "{ks:?}");
    assert!(ks.is_subset(&allowed), "{ks:?}");
    for opt in node["options"].as_array().into_iter().flatten() {
        let ks = keys(opt);
        for required in ["name", "help", "required", "flags"] {
            assert!(ks.contains(required), "{ks:?}");
        }
        assert!(
            opt["flags"]
                .as_array()
                .unwrap()
                .iter()
                .all(|f| f.is_string())
        );
    }
    for arg in node["arguments"].as_array().into_iter().flatten() {
        let ks = keys(arg);
        assert!(ks.contains("name") && ks.contains("help") && ks.contains("required"));
    }
    for child in node["commands"].as_array().into_iter().flatten() {
        check_shape(child);
    }
}

#[test]
fn structure_is_printed_as_snow_does() {
    let (_, out, _) = run(&["--structure"], &[]);
    assert!(
        out.starts_with("{\n    \"name\": \"snow-rs\",\n    \"help\": "),
        "{}",
        &out[..80]
    );
    assert!(out.ends_with("}\n"));
    assert!(out.contains("\n            \"name\": \"connection\","));
}

fn leaves(
    node: &serde_json::Value,
    path: &mut Vec<String>,
    out: &mut Vec<(Vec<String>, serde_json::Value)>,
) {
    match node["commands"].as_array() {
        Some(children) => {
            for child in children {
                path.push(child["name"].as_str().unwrap().to_string());
                leaves(child, path, out);
                path.pop();
            }
        }
        None => out.push((path.clone(), node.clone())),
    }
}

#[test]
fn structure_has_snows_shape_and_lists_every_ported_command() {
    let root = structure();
    check_shape(&root);
    assert_eq!(root["name"], "snow-rs");
    let root_flags: Vec<&str> = root["options"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        root_flags,
        [
            "custom_help",
            "version",
            "structure",
            "info",
            "no_auto_upgrade",
            "config_file",
            "install_completion",
            "show_completion"
        ]
    );
    let mut found = Vec::new();
    leaves(&root, &mut Vec::new(), &mut found);
    let listed: BTreeSet<Vec<String>> = found.iter().map(|(p, _)| p.clone()).collect();
    let ported = ported_surface(&Cli::command());
    let ported_paths: BTreeSet<Vec<String>> = ported.commands.keys().cloned().collect();
    assert_eq!(listed, ported_paths);
}

#[test]
fn structure_options_are_options_of_the_same_command_in_snow() {
    let snapshot: Snapshot = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/snow-surface.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let mut found = Vec::new();
    leaves(&structure(), &mut Vec::new(), &mut found);
    for (path, node) in found {
        let snow = snapshot
            .commands
            .iter()
            .find(|c| c.path == path)
            .unwrap_or_else(|| panic!("{path:?} is not a snow command"));
        for opt in node["options"].as_array().unwrap() {
            let flags: BTreeSet<&str> = opt["flags"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| f.as_str().unwrap())
                .collect();
            assert!(
                snow.options
                    .iter()
                    .any(|o| flags.iter().all(|f| o.flags.iter().any(|g| g == f))),
                "{path:?}: {flags:?} is not an option of snow"
            );
        }
    }
}

#[test]
fn structure_marks_flags_choices_and_defaults() {
    let mut found = Vec::new();
    leaves(&structure(), &mut Vec::new(), &mut found);
    let (_, list) = found
        .iter()
        .find(|(p, _)| p == &["connection", "list"])
        .unwrap();
    let opt = |name: &str| {
        list["options"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["name"] == name)
            .unwrap()
            .clone()
    };
    let verbose = opt("verbose");
    assert_eq!(verbose["flags"], serde_json::json!(["--verbose", "-v"]));
    assert_eq!(verbose["is_flag"], true);
    assert_eq!(verbose["default"], false);
    assert_eq!(
        opt("format")["choices"],
        serde_json::json!(["TABLE", "JSON", "JSON_EXT", "CSV", "PLAIN"])
    );
    assert!(opt("decimal_precision").get("is_flag").is_none());
    assert_eq!(
        opt("enhanced_exit_codes")["flags"],
        serde_json::json!(["--enhanced-exit-codes"])
    );
}

// --- completion --------------------------------------------------------------------------

fn with_shell(shell: &str) -> Vec<(&'static str, String)> {
    vec![("SHELL", shell.to_string())]
}

#[test]
fn show_completion_prints_a_script_for_each_shell() {
    for (shell, marker) in [
        ("/bin/bash", "complete -F _snow__rs"),
        ("/usr/bin/zsh", "#compdef snow-rs"),
        ("/usr/bin/fish", "complete -c snow-rs"),
        (
            "/usr/bin/pwsh",
            "Register-ArgumentCompleter -Native -CommandName 'snow-rs'",
        ),
        (
            "C:\\Windows\\powershell.exe",
            "Register-ArgumentCompleter -Native -CommandName 'snow-rs'",
        ),
    ] {
        let (code, out, err) = run(&["--show-completion"], &with_shell(shell));
        assert_eq!((code, err.as_str()), (0, ""), "{shell}");
        assert!(out.contains(marker), "{shell}: {out}");
        assert!(out.ends_with('\n') && !out.ends_with("\n\n"), "{shell}");
        // Generated from clap: it knows the commands and the root options.
        assert!(
            out.contains("connection") && out.contains("show-completion"),
            "{shell}"
        );
    }
}

#[test]
fn show_completion_for_an_unsupported_or_unknown_shell_fails() {
    for (shell, name) in [("/bin/tcsh", "tcsh"), ("", "")] {
        let (code, out, err) = run(&["--show-completion"], &with_shell(shell));
        assert_eq!(code, 1);
        assert_eq!(out, "");
        assert_eq!(err, format!("Shell {name} not supported.\n"));
    }
}

#[test]
fn install_completion_writes_where_snow_writes() {
    for (shell, expected, rc, script) in [
        (
            "/bin/bash",
            ".bash_completions/snow-rs.sh",
            ".bashrc",
            "complete -F _snow__rs",
        ),
        ("/bin/zsh", ".zfunc/_snow-rs", ".zshrc", "#compdef snow-rs"),
        (
            "/bin/fish",
            ".config/fish/completions/snow-rs.fish",
            "",
            "complete -c snow-rs",
        ),
    ] {
        let (dir, mut env) = home();
        env.push(("SHELL", shell.to_string()));
        let (code, out, err) = run(&["--install-completion"], &env);
        assert_eq!((code, err.as_str()), (0, ""), "{shell}");
        let path = dir.path().join(expected);
        let name = shell.rsplit('/').next().unwrap();
        assert_eq!(
            out,
            format!(
                "{name} completion installed in {}\nCompletion will take effect once you restart the terminal\n",
                path.display()
            )
        );
        assert!(
            std::fs::read_to_string(&path).unwrap().contains(script),
            "{shell}"
        );
        match rc {
            ".bashrc" => {
                let rc = std::fs::read_to_string(dir.path().join(rc)).unwrap();
                assert!(rc.contains(&format!("source '{}'", path.display())));
                // Installing again does not repeat the line.
                run(&["--install-completion"], &env);
                let again = std::fs::read_to_string(dir.path().join(".bashrc")).unwrap();
                assert_eq!(again.matches("source '").count(), 1);
            }
            ".zshrc" => {
                let rc = std::fs::read_to_string(dir.path().join(rc)).unwrap();
                assert!(rc.contains("fpath+=~/.zfunc; autoload -Uz compinit; compinit"));
                assert!(rc.contains("zstyle ':completion:*' menu select"));
            }
            _ => {}
        }
    }
}

#[test]
fn install_completion_keeps_a_zshrc_that_has_a_zstyle() {
    let (dir, mut env) = home();
    env.push(("SHELL", "/bin/zsh".into()));
    std::fs::write(
        dir.path().join(".zshrc"),
        "zstyle ':completion:*' menu no\n",
    )
    .unwrap();
    run(&["--install-completion"], &env);
    let rc = std::fs::read_to_string(dir.path().join(".zshrc")).unwrap();
    assert_eq!(rc.matches("zstyle").count(), 1, "{rc}");
}

#[test]
fn install_completion_for_powershell_appends_to_the_profile() {
    let dir = tempfile::tempdir().unwrap();
    let profile = dir.path().join("Documents/PowerShell/profile.ps1");
    let env = Env::from_pairs([
        ("SHELL", "/usr/bin/pwsh"),
        ("HOME", dir.path().to_str().unwrap()),
    ]);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let ask = |program: &str| {
        assert_eq!(program, "pwsh");
        Ok(profile.clone())
    };
    for _ in 0..2 {
        let code = completion::install(&Cli::command(), &env, &ask, &mut out, &mut err);
        assert_eq!(code, 0);
    }
    let text = String::from_utf8(out).unwrap();
    assert!(text.starts_with("pwsh completion installed in "), "{text}");
    assert_eq!(
        std::fs::read_to_string(&profile)
            .unwrap()
            .matches("Register-ArgumentCompleter")
            .count(),
        2
    );
    assert!(err.is_empty());
}

#[test]
fn install_completion_reports_failures() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::from_pairs([
        ("SHELL", "/usr/bin/pwsh"),
        ("HOME", dir.path().to_str().unwrap()),
    ]);
    let fail = |_: &str| {
        Err(std::io::Error::other(
            "Couldn't get PowerShell user profile",
        ))
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = completion::install(&Cli::command(), &env, &fail, &mut out, &mut err);
    assert_eq!(code, 1);
    assert!(
        String::from_utf8(err)
            .unwrap()
            .contains("Couldn't get PowerShell user profile")
    );

    // The home directory is a file: nothing can be created under it.
    let file = dir.path().join("file");
    std::fs::write(&file, "").unwrap();
    let env = Env::from_pairs([("SHELL", "/bin/fish"), ("HOME", file.to_str().unwrap())]);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = completion::install(&Cli::command(), &env, &fail, &mut out, &mut err);
    assert_eq!(code, 1);
    assert!(
        String::from_utf8(err)
            .unwrap()
            .starts_with("Could not install the completion")
    );
}

#[test]
fn install_completion_for_an_unsupported_shell_prints_to_stdout() {
    let (code, out, err) = run(&["--install-completion"], &with_shell("/bin/tcsh"));
    assert_eq!(
        (code, out.as_str(), err.as_str()),
        (1, "Shell tcsh is not supported.\n", "")
    );
}

// --- --enhanced-exit-codes ---------------------------------------------------------------

/// Failure classes reachable offline, with the codes snow 3.34.0 gives them.
fn exit_codes(extra: &[&str], extra_env: &[(&str, &str)]) -> [i32; 3] {
    let (_dir, mut env) = home();
    env.extend(extra_env.iter().map(|(k, v)| (*k, v.to_string())));
    let code = |args: &[&str]| {
        let args: Vec<&str> = args.iter().chain(extra).copied().collect();
        run(&args, &env).0
    };
    [
        // SQL failure: a template that cannot be rendered (snow: "SQL rendering error").
        code(&["sql", "-x", "-q", "select <% a %>"]),
        // Client failure: an unknown connection.
        code(&["connection", "test", "-c", "nope"]),
        // Usage failure.
        code(&["connection", "list", "--format", "xml"]),
    ]
}

#[test]
fn enhanced_exit_codes_tell_the_failure_classes_apart() {
    assert_eq!(exit_codes(&[], &[]), [1, 1, 2]);
    assert_eq!(exit_codes(&["--enhanced-exit-codes"], &[]), [5, 1, 2]);
}

#[test]
fn enhanced_exit_codes_from_the_environment_use_clicks_booleans() {
    for value in ["1", "true", "TRUE", "yes", "on", "t", "y", " true "] {
        let codes = exit_codes(&[], &[("SNOWFLAKE_ENHANCED_EXIT_CODES", value)]);
        assert_eq!(codes, [5, 1, 2], "{value}");
    }
    for value in ["0", "false", "no", "off", "f", "n", ""] {
        let codes = exit_codes(&[], &[("SNOWFLAKE_ENHANCED_EXIT_CODES", value)]);
        assert_eq!(codes, [1, 1, 2], "{value:?}");
    }
}

#[test]
fn an_invalid_enhanced_exit_codes_variable_is_a_usage_error() {
    let (_dir, mut env) = home();
    env.push(("SNOWFLAKE_ENHANCED_EXIT_CODES", "bogus".into()));
    let (code, _, err) = run(&["connection", "list"], &env);
    assert_eq!(code, 2);
    assert!(
        err.contains("Invalid value for '--enhanced-exit-codes': 'bogus' is not a valid boolean."),
        "{err}"
    );
}

// --- --decimal-precision -----------------------------------------------------------------

#[test]
fn decimal_precision_must_be_a_positive_integer() {
    let (dir, env) = home();
    for bad in ["0", "-3"] {
        let (code, _, err) = run(&["connection", "list", "--decimal-precision", bad], &env);
        assert_eq!(code, 1, "{bad}");
        assert!(
            err.contains(&format!(
                "Invalid value for decimal_precision: '{bad}'. Must be a positive integer."
            )),
            "{err}"
        );
    }
    let (code, _, _) = run(&["connection", "list", "--decimal-precision", "abc"], &env);
    assert_eq!(code, 2);
    let (code, out, _) = run(
        &[
            "connection",
            "list",
            "--decimal-precision",
            "3",
            "--format",
            "json",
        ],
        &env,
    );
    assert_eq!((code, out.as_str()), (0, "[]\n"));

    // From the environment, then from the config file: the same message, exit 1.
    let mut with_env = env.clone();
    with_env.push(("SNOWFLAKE_DECIMAL_PRECISION", "x".into()));
    let (code, _, err) = run(&["connection", "list"], &with_env);
    assert_eq!(code, 1);
    assert!(err.contains("Invalid value for decimal_precision: 'x'. Must be a positive integer."));
    std::fs::write(
        dir.path().join("config.toml"),
        "[cli]\ndecimal_precision = 0\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            dir.path().join("config.toml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let (code, _, err) = run(&["connection", "list"], &env);
    assert_eq!(code, 1);
    assert!(err.contains("decimal_precision: '0'"), "{err}");
    // The environment overrides the config file; the flag overrides both.
    let mut valid_env = env.clone();
    valid_env.push(("SNOWFLAKE_DECIMAL_PRECISION", "5".into()));
    assert_eq!(run(&["connection", "list"], &valid_env).0, 0);
    assert_eq!(
        run(&["connection", "list", "--decimal-precision", "2"], &env).0,
        0
    );
}

fn column(name: &str, precision: i64, scale: i64) -> serde_json::Value {
    let mut c = common::row_type(name, "fixed", Some(scale));
    c["precision"] = precision.into();
    c
}

const QUERY: &str = "select numbers";

/// The sandbox result of `select 1.2345::number(10,4) a, 123456.789::number(12,3) b,
/// 1/3 c, 12345678901234567890.123::number(38,3) d, 1.5::float e` with `snow sql` 3.34.0,
/// replayed through the SQL API mock.
fn result_with(precision: Option<usize>) -> snowflake_cli_rs::sql::QueryResult {
    let server = MockServer::start();
    server.mock(|when, then| {
        common::submit(when, QUERY);
        then.status(200).json_body(common::success_body(
            vec![
                column("A", 10, 4),
                column("B", 12, 3),
                column("C", 8, 6),
                column("D", 38, 3),
                common::row_type("E", "real", None),
            ],
            serde_json::json!([[
                "1.2345",
                "123456.789",
                "0.333333",
                "12345678901234567890.123",
                "1.5"
            ]]),
            1,
        ));
    });
    let options = ClientOptions {
        decimal_precision: precision,
        ..common::fast_options()
    };
    common::client_with(&common::connection(&server), options)
        .execute(QUERY)
        .unwrap()
}

fn rendered(precision: Option<usize>, format: OutputFormat) -> String {
    let mut out = Vec::new();
    render(&result_with(precision), format, &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

#[test]
fn decimal_precision_rounds_in_every_output_format() {
    assert_eq!(
        rendered(Some(3), OutputFormat::Json),
        "[\n    {\n        \"A\": \"1.23\",\n        \"B\": \"1.23E+5\",\n        \"C\": \"0.333\",\n        \"D\": \"12345678901234567890.123\",\n        \"E\": 1.5\n    }\n]\n"
    );
    assert_eq!(
        rendered(Some(3), OutputFormat::Csv),
        "A,B,C,D,E\n1.23,1.23E+5,0.333,12345678901234567890.123,1.5\n"
    );
    assert_eq!(
        rendered(Some(3), OutputFormat::Table),
        "+---------------------------------------------------------+\n| A    | B       | C     | D                        | E   |\n|------+---------+-------+--------------------------+-----|\n| 1.23 | 1.23E+5 | 0.333 | 12345678901234567890.123 | 1.5 |\n+---------------------------------------------------------+\n"
    );
    assert_eq!(
        rendered(Some(1), OutputFormat::Csv),
        "A,B,C,D,E\n1,1E+5,0.3,12345678901234567890.123,1.5\n"
    );
    // Without the option the digits are exact.
    assert_eq!(
        rendered(None, OutputFormat::Csv),
        "A,B,C,D,E\n1.2345,123456.789,0.333333,12345678901234567890.123,1.5\n"
    );
}
