//! `snow sql` golden tests (ADR 0004, Decision 7): each case in `tests/golden/sql/` holds what
//! snow 3.34.0 printed (stdout, stderr, exit code, per format) and the SQL API exchanges of this
//! crate's own requests for the same input. The exchanges are replayed by `httpmock`, the CLI
//! runs in-process, and its output must match snow's byte for byte (query ids aside).
//! Capture: `scripts/capture-goldens.sh --sql`.

use crate::common;

use httpmock::MockServer;
use snowflake_cli_rs::commands::{Prompter, TerminalPrompter};
use snowflake_cli_rs::env::Env;
use std::collections::BTreeMap;
use std::path::PathBuf;

const ID_TOKEN: &str = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/sql")
}

fn case_names() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(golden_dir())
        .unwrap()
        .filter_map(|e| {
            let name = e.unwrap().file_name().into_string().unwrap();
            name.strip_suffix(".json").map(String::from)
        })
        .collect();
    names.sort();
    names
}

/// Query ids replaced by a token of the same length (the panel wraps the same).
fn without_ids(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        if i + 36 <= text.len() && is_uuid(&bytes[i..i + 36]) {
            out.push_str(ID_TOKEN);
            i += 36;
        } else {
            let c = text[i..].chars().next().unwrap();
            out.push(c);
            i += c.len_utf8();
        }
    }
    out
}

fn is_uuid(b: &[u8]) -> bool {
    b.iter().enumerate().all(|(i, c)| match i {
        8 | 13 | 18 | 23 => *c == b'-',
        _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
    })
}

/// Serves the recorded exchanges: the last response for each request.
fn serve(server: &MockServer, exchanges: &[serde_json::Value]) {
    let mut last: BTreeMap<String, &serde_json::Value> = BTreeMap::new();
    for e in exchanges {
        last.insert(
            format!(
                "{} {} {} {}",
                e["method"], e["path"], e["partition"], e["statement"]
            ),
            e,
        );
    }
    for e in last.values() {
        let status = u16::try_from(e["status"].as_u64().unwrap()).unwrap();
        let response = e["response"].clone();
        server.mock(|when, then| {
            let mut when = common::authorized(when).path(e["path"].as_str().unwrap());
            if e["method"] == "POST" {
                let mut body = serde_json::json!({ "statement": e["statement"] });
                if let Some(params) = e.get("parameters") {
                    body["parameters"] = params.clone();
                }
                when = when.method("POST").json_body_includes(body.to_string());
            } else if let Some(partition) = e["partition"].as_str() {
                when = when.method("GET").query_param("partition", partition);
            } else {
                when = when.method("GET").query_param_missing("partition");
            }
            let _ = when;
            then.status(status).json_body(response);
        });
    }
}

struct Outcome {
    code: i32,
    stdout: String,
    stderr: String,
    /// What the spool file (`{spool}` in the case options) holds after the run, if it exists.
    spool: Option<String>,
}

fn run_case(case: &serde_json::Value, server: &MockServer, format: &str) -> Outcome {
    let home = tempfile::tempdir().unwrap();
    let spool = home.path().join("spool.out");
    let mut args = vec!["snow-rs".to_string(), "sql".to_string(), "-x".to_string()];
    if let Some(query) = case["query"].as_str() {
        args.extend(["-q".to_string(), query.to_string()]);
    }
    for (i, text) in case["files"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .enumerate()
    {
        let path = home.path().join(format!("input{}.sql", i + 1));
        std::fs::write(&path, text.as_str().unwrap()).unwrap();
        args.extend(["-f".to_string(), path.display().to_string()]);
    }
    let stdin = case["stdin"].as_str();
    if stdin.is_some() {
        args.push("-i".into());
    }
    if case["retain_comments"].as_bool() == Some(true) {
        args.push("--retain-comments".into());
    }
    if case["silent"].as_bool() == Some(true) {
        args.push("--silent".into());
    }
    for variable in case["variables"].as_array().into_iter().flatten() {
        args.extend(["-D".to_string(), variable.as_str().unwrap().to_string()]);
    }
    for mode in case["templating"].as_array().into_iter().flatten() {
        args.extend([
            "--enable-templating".to_string(),
            mode.as_str().unwrap().to_string(),
        ]);
    }
    if case["single_transaction"].as_bool() == Some(true) {
        args.push("--single-transaction".into());
    }
    for option in case["options"].as_array().into_iter().flatten() {
        let option = option.as_str().unwrap();
        args.push(option.replace("{spool}", &spool.display().to_string()));
    }
    // `bare` cases take the format from `-o output_format`.
    if format != "default" {
        args.extend(["--format".to_string(), format.to_string()]);
    }
    let env = Env::from_pairs([
        ("SNOWFLAKE_HOME", home.path().display().to_string()),
        ("SNOWFLAKE_ACCOUNT", "testacct".into()),
        ("SNOWFLAKE_USER", "tester".into()),
        ("SNOWFLAKE_HOST", server.host()),
        ("SNOWFLAKE_PORT", server.port().to_string()),
        ("SNOWFLAKE_PROTOCOL", "http".into()),
        ("SNOWFLAKE_AUTHENTICATOR", "SNOWFLAKE_JWT".into()),
        (
            "SNOWFLAKE_PRIVATE_KEY_FILE",
            common::key_path("unencrypted.p8").display().to_string(),
        ),
    ]);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut input = stdin.unwrap_or_default().as_bytes();
    let prompter: &mut dyn Prompter = &mut TerminalPrompter;
    let _log = crate::common::logger_guard();
    let code = snowflake_cli_rs::run_with(
        args,
        env,
        snowflake_cli_rs::Stdin {
            is_tty: false,
            reader: &mut input,
        },
        prompter,
        None,
        &mut out,
        &mut err,
    );
    Outcome {
        code,
        stdout: String::from_utf8(out).unwrap(),
        stderr: String::from_utf8(err).unwrap(),
        spool: std::fs::read_to_string(&spool).ok(),
    }
}

#[test]
fn sql_output_matches_snow() {
    let names = case_names();
    assert!(names.len() >= 15, "sql golden cases missing: {names:?}");
    let mut failures = Vec::new();
    let mut formats_seen = std::collections::BTreeSet::new();
    for name in &names {
        let record: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(golden_dir().join(format!("{name}.json"))).unwrap(),
        )
        .unwrap();
        let server = MockServer::start();
        serve(&server, record["exchanges"].as_array().unwrap());
        for (format, expected) in record["outputs"].as_object().unwrap() {
            formats_seen.insert(format.clone());
            let actual = run_case(&record["case"], &server, format);
            let want_code = i32::try_from(expected["exit"].as_i64().unwrap()).unwrap();
            let want_out = expected["stdout"].as_str().unwrap();
            let mut want_err = expected["stderr"].as_str().unwrap().to_string();
            let mut got_err = without_ids(&actual.stderr);
            // The documented deviation: snow-rs lacks this text; the panel padding differs.
            if let Some(missing) = record["case"]["deviation"].as_str() {
                want_err = unpadded(&want_err.replace(missing, ""));
                got_err = unpadded(&got_err);
            }
            // The capture records a missing spool file as empty.
            let want_spool = expected.get("spool").map(|v| v.as_str().unwrap());
            let spool_matches =
                want_spool.is_none_or(|want| actual.spool.as_deref().unwrap_or_default() == want);
            if actual.code != want_code
                || actual.stdout != want_out
                || got_err != want_err
                || !spool_matches
            {
                failures.push(format!(
                    "{name} --format {format}: exit {} (snow {want_code})\n--- snow stdout\n{want_out}\n--- ours\n{}\n--- snow stderr\n{want_err}\n--- ours\n{got_err}\n--- snow spool\n{want_spool:?}\n--- ours\n{:?}",
                    actual.code, actual.stdout, actual.spool
                ));
            }
        }
    }
    assert_eq!(
        formats_seen.into_iter().collect::<Vec<_>>(),
        vec!["csv", "default", "json", "json_ext", "plain", "table"]
    );
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

/// Panel lines without the padding before their right border.
fn unpadded(text: &str) -> String {
    text.lines()
        .map(|line| match line.strip_suffix('│') {
            Some(body) => format!("{}│", body.trim_end()),
            None => line.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn ids_are_replaced_by_a_token_of_the_same_length() {
    assert_eq!(
        without_ids("a 01c88ebd-0002-713f-0002-fee6000173ce: é"),
        format!("a {ID_TOKEN}: é")
    );
    assert_eq!(without_ids("01c88ebd-0002"), "01c88ebd-0002");
}
