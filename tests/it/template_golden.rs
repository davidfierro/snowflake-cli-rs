//! `snow sql` templating goldens (ADR 0006): each case in `tests/golden/template/` holds what the
//! official snow 3.34.0 compiled (the statements it would send) and printed (stdout, stderr, exit
//! code) for one input, captured offline by `scripts/capture-template-goldens.sh`.
//!
//! A case snow ran is compared on its statements and the notices printed before them; a case it
//! stopped is run through the whole CLI in-process (it fails before connecting) and compared
//! byte for byte.

use clap::Parser;
use snowflake_cli_rs::commands::sql::statements;
use snowflake_cli_rs::commands::{Prompter, TerminalPrompter};
use snowflake_cli_rs::config::{ConfigPaths, ConfigSource};
use snowflake_cli_rs::env::Env;
use snowflake_cli_rs::{Cli, Command};
use std::path::{Path, PathBuf};

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/template")
}

/// The argument list of a case, as the capture builds it.
fn case_args(case: &serde_json::Value, work: &Path, format: &str) -> Vec<String> {
    let mut args = vec!["snow-rs".to_string(), "sql".into(), "-x".into()];
    let strings = |key: &str| -> Vec<String> {
        case[key]
            .as_array()
            .into_iter()
            .flatten()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    };
    if let Some(query) = case["query"].as_str() {
        args.extend(["-q".to_string(), query.to_string()]);
    }
    for (i, text) in strings("files").iter().enumerate() {
        let path = work.join(format!("input{}.sql", i + 1));
        std::fs::write(&path, text).unwrap();
        args.extend(["-f".to_string(), path.display().to_string()]);
    }
    for v in strings("variables") {
        args.extend(["-D".to_string(), v]);
    }
    for t in strings("templating") {
        args.extend(["--enable-templating".to_string(), t]);
    }
    for e in strings("env") {
        args.extend(["--env".to_string(), e]);
    }
    if case.get("project").is_some() || case["project_arg"].as_bool() == Some(true) {
        args.extend([
            "--project".to_string(),
            work.join("project").display().to_string(),
        ]);
    }
    if case["silent"].as_bool() == Some(true) {
        args.push("--silent".into());
    }
    if case["enhanced_exit_codes"].as_bool() == Some(true) {
        args.push("--enhanced-exit-codes".into());
    }
    args.extend(["--format".to_string(), format.to_string()]);
    args
}

/// A fresh work directory with the case's project files, and the environment of the run.
fn setup(case: &serde_json::Value) -> (tempfile::TempDir, PathBuf, Env) {
    let dir = tempfile::tempdir().unwrap();
    let work = std::fs::canonicalize(dir.path()).unwrap();
    let project = work.join("project");
    std::fs::create_dir(&project).unwrap();
    for (name, text) in case["project"].as_object().into_iter().flatten() {
        let path = project.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text.as_str().unwrap()).unwrap();
    }
    let home = work.join("home");
    std::fs::create_dir(&home).unwrap();
    for (name, text) in case["home_files"].as_object().into_iter().flatten() {
        let path = home.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text.as_str().unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    let mut pairs: Vec<(String, String)> = vec![
        ("SNOWFLAKE_ACCOUNT".into(), "testacct".into()),
        ("SNOWFLAKE_USER".into(), "tester".into()),
        ("HOME".into(), home.display().to_string()),
    ];
    if case["unset_snowflake_home"].as_bool() != Some(true) {
        pairs.push(("SNOWFLAKE_HOME".into(), home.display().to_string()));
    }
    for (k, v) in case["os_env"].as_object().into_iter().flatten() {
        pairs.push((k.clone(), v.as_str().unwrap().to_string()));
    }
    (dir, work, Env::from_pairs(pairs))
}

fn check(name: &str, record: &serde_json::Value, failures: &mut Vec<String>) {
    let case = &record["case"];
    for (format, expected) in record["outputs"].as_object().unwrap() {
        let (_dir, work, env) = setup(case);
        let tokens = |s: &str| {
            s.replace("<PROJECT>", &work.join("project").display().to_string())
                .replace("<WORK>", &work.display().to_string())
        };
        let want_out = tokens(expected["stdout"].as_str().unwrap());
        let want_err = tokens(expected["stderr"].as_str().unwrap());
        let want_code = expected["exit"].as_i64().unwrap() as i32;
        let args = case_args(case, &work, format);
        if want_code == 0 {
            let Some(Command::Sql(sql)) = Cli::try_parse_from(&args).unwrap().command else {
                panic!("{name}: not a sql command");
            };
            let mut notices = Vec::new();
            let source = ConfigSource::load(&ConfigPaths {
                config_file: work.join("home/config.toml"),
                connections_file: work.join("home/connections.toml"),
                config_file_is_custom: false,
            })
            .unwrap();
            let got = statements(
                &sql,
                &source,
                None,
                &mut "".as_bytes(),
                &env,
                false,
                &mut notices,
            )
            .and_then(|r| r)
            .map(|s| s.into_iter().map(|s| s.text).collect::<Vec<_>>());
            let want: Vec<String> = expected["statements"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| tokens(s.as_str().unwrap()))
                .collect();
            let printed: String = notices.iter().map(|n| format!("{n}\n")).collect();
            let printed = if matches!(format.as_str(), "table" | "plain")
                && case["silent"].as_bool() != Some(true)
            {
                printed
            } else {
                String::new()
            };
            if got.as_ref().ok() != Some(&want) || printed != want_out {
                failures.push(format!(
                    "{name} --format {format}:\n  snow {want:?}\n  ours {got:?}\n  snow stdout {want_out:?}\n  ours stdout {printed:?}"
                ));
            }
            continue;
        }
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let prompter: &mut dyn Prompter = &mut TerminalPrompter;
        let code = snowflake_cli_rs::run_with(
            args,
            env,
            snowflake_cli_rs::Stdin {
                is_tty: false,
                reader: &mut "".as_bytes(),
            },
            prompter,
            None,
            &mut out,
            &mut err,
        );
        let (out, err) = (
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        );
        if code != want_code || out != want_out || err != want_err {
            failures.push(format!(
                "{name} --format {format}: exit {code} (snow {want_code})\n--- snow stdout\n{want_out}\n--- ours\n{out}\n--- snow stderr\n{want_err}\n--- ours\n{err}"
            ));
        }
    }
}

// The goldens hold snow's POSIX path texts (`PosixPath('…/project/nope.txt')`) and read `HOME`; Windows paths and `USERPROFILE` differ.
#[cfg(unix)]
#[test]
fn templating_matches_snow() {
    let mut names: Vec<String> = std::fs::read_dir(golden_dir())
        .unwrap()
        .filter_map(|e| {
            let name = e.unwrap().file_name().into_string().unwrap();
            name.strip_suffix(".json").map(String::from)
        })
        .collect();
    names.sort();
    assert!(
        names.len() >= 50,
        "template golden cases missing: {names:?}"
    );
    let mut failures = Vec::new();
    for name in &names {
        let record: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(golden_dir().join(format!("{name}.json"))).unwrap(),
        )
        .unwrap();
        check(name, &record, &mut failures);
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases differ:\n{}",
        failures.len(),
        names.len(),
        failures.join("\n\n")
    );
}
