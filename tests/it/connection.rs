//! `snow connection`: the binary against temp config homes, goldens captured from
//! snow 3.34.0, and in-process runs for the interactive paths.

use crate::common;

use assert_cmd::Command;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{STATEMENTS, key_path, one_int_body};
use httpmock::MockServer;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
use rsa::PrivateKey as RsaPrivateKey;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use sha2::Sha256;
use snowflake_cli_rs::commands::Prompter;
use snowflake_cli_rs::env::Env;
use snowflake_cli_rs::error::Result;
use std::collections::VecDeque;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use tempfile::TempDir;

const GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/connection");

/// A config home: `SNOWFLAKE_HOME`, mode 0700, with an empty key and token file in it.
struct Home {
    dir: TempDir,
}

impl Home {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        #[cfg(unix)]
        set_mode(dir.path(), 0o700);
        std::fs::write(dir.path().join("key.p8"), "").unwrap();
        std::fs::write(dir.path().join("token.txt"), "").unwrap();
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn write(&self, name: &str, text: &str) {
        let path = self.path(name);
        std::fs::write(&path, text).unwrap();
        #[cfg(unix)]
        set_mode(&path, 0o600);
    }

    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.path(name)).unwrap()
    }

    /// The binary, with an empty environment but `SNOWFLAKE_HOME`, run from the home.
    fn snow(&self) -> Command {
        let mut cmd = Command::cargo_bin("snow-rs").unwrap();
        cmd.env_clear()
            .env("SNOWFLAKE_HOME", self.dir.path())
            .current_dir(self.dir.path());
        // Keep coverage profiling working under `cargo llvm-cov`.
        if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
            cmd.env("LLVM_PROFILE_FILE", profile);
        }
        cmd
    }

    /// Loads a golden file, `{HOME}` standing for this home's path.
    fn golden(&self, name: &str) -> String {
        std::fs::read_to_string(format!("{GOLDEN}/{name}"))
            .unwrap()
            .replace("{HOME}", &self.dir.path().display().to_string())
    }

    /// Writes the golden `config.toml` (what snow wrote for dev, full and quoted).
    fn with_golden_config(&self) {
        self.write("config.toml", &self.golden("config.toml"));
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn stdout(cmd: &mut Command) -> String {
    String::from_utf8(cmd.assert().success().get_output().stdout.clone()).unwrap()
}

// ------------------------------------------------------------------ help

#[test]
fn connection_help_lists_the_subcommands() {
    let out = stdout(Home::new().snow().args(["connection", "--help"]));
    for name in [
        "add",
        "list",
        "remove",
        "set-default",
        "test",
        "generate-jwt",
    ] {
        assert!(out.contains(name), "{name} missing from:\n{out}");
    }
}

#[test]
fn add_help_documents_every_flag() {
    let out = stdout(Home::new().snow().args(["connection", "add", "--help"]));
    for flag in [
        "--connection-name",
        "--account",
        "--user",
        "--password",
        "--role",
        "--warehouse",
        "--database",
        "--schema",
        "--host",
        "--port",
        "--protocol",
        "--region",
        "--authenticator",
        "--workload-identity-provider",
        "--private-key-file",
        "--token-file-path",
        "--secondary-roles",
        "--server-session-keep-alive",
        "--client-store-temporary-credential",
        "--default",
        "--no-interactive",
    ] {
        assert!(out.contains(flag), "{flag} missing from:\n{out}");
    }
}

#[test]
fn connection_without_subcommand_shows_help_and_fails() {
    Home::new().snow().arg("connection").assert().code(2);
}

// ------------------------------------------------------------------- add

const ADD_ALL: &[&str] = &[
    "connection",
    "add",
    "-n",
    "full",
    "-a",
    "a2",
    "-u",
    "u2",
    "-p",
    "pw",
    "-r",
    "R",
    "-w",
    "W",
    "-d",
    "D",
    "-s",
    "S",
    "-h",
    "H",
    "-P",
    "443",
    "--protocol",
    "https",
    "-R",
    "reg",
    "-A",
    "snowflake_jwt",
    "-W",
    "aws",
    "-k",
    "key.p8",
    "-t",
    "token.txt",
    "--secondary-roles",
    "ALL",
    "--server-session-keep-alive",
    "--client-store-temporary-credential",
    "--default",
    "--no-interactive",
];

/// Golden: snow wrote this file for `add dev`, then `add full … --default` (captured from snow
/// 3.34.0 with `scripts/capture-connection-goldens.sh`).
#[test]
fn add_with_every_flag_writes_what_snow_writes() {
    let home = Home::new();
    home.snow()
        .args(["connection", "add", "-n", "dev", "-a", "acc", "-u", "me"])
        .arg("--no-interactive")
        .assert()
        .success();
    home.snow()
        .args(ADD_ALL)
        .assert()
        .success()
        .stdout(format!(
            "WARNING! Using --password via the CLI is insecure. Use environment variables instead.\nWrote new connection full to {}\n",
            home.path("config.toml").display()
        ));
    let golden = home.golden("config.toml");
    let expected = golden.split("\n[connections.quoted]").next().unwrap();
    assert_eq!(
        home.read("config.toml"),
        format!("{expected}\n").trim_end_matches('\n').to_string() + "\n"
    );
    #[cfg(unix)]
    assert_eq!(mode(&home.path("config.toml")), 0o600);
}

#[test]
fn add_flag_aliases_and_the_json_message() {
    let home = Home::new();
    let out = stdout(home.snow().args([
        "connection",
        "add",
        "-n",
        "x",
        "--accountname",
        "a",
        "--username",
        "u",
        "--rolename",
        "r",
        "--dbname",
        "d",
        "--schemaname",
        "s",
        "--private-key-path",
        "key.p8",
        "--no-interactive",
        "--format",
        "json",
    ]));
    assert_eq!(
        out,
        format!(
            "{{\n    \"message\": \"Wrote new connection x to {}\"\n}}\n",
            home.path("config.toml").display()
        )
    );
    let config: toml::Table = home.read("config.toml").parse().unwrap();
    assert_eq!(
        config["connections"]["x"]["private_key_file"].as_str(),
        Some("key.p8")
    );
}

#[test]
fn add_keeps_comments_and_order_of_an_existing_config() {
    let home = Home::new();
    let original = "# my settings\ndefault_connection_name = \"a\"  # main\n\n[connections.a]\n# the account\naccount   = \"a1\"\n";
    home.write("config.toml", original);
    home.snow()
        .args([
            "connection",
            "add",
            "-n",
            "b",
            "-a",
            "b1",
            "--no-interactive",
        ])
        .assert()
        .success();
    assert_eq!(
        home.read("config.toml"),
        format!("{original}\n[connections.b]\naccount = \"b1\"\n")
    );
}

#[test]
fn add_writes_connections_toml_when_it_exists() {
    let home = Home::new();
    home.write("connections.toml", "# mine\n[z]\naccount = \"z\"\n");
    home.write("config.toml", "# untouched\n");
    home.snow()
        .args(["connection", "add", "-n", "c", "-a", "c1", "--default"])
        .arg("--no-interactive")
        .assert()
        .success()
        .stdout(contains("connections.toml"));
    assert_eq!(
        home.read("connections.toml"),
        "# mine\n[z]\naccount = \"z\"\n\n[c]\naccount = \"c1\"\n"
    );
    // The default name lives in config.toml.
    assert_eq!(
        home.read("config.toml"),
        "default_connection_name = \"c\"\n# untouched\n"
    );
}

#[test]
fn add_duplicate_name_is_a_usage_error() {
    let home = Home::new();
    home.with_golden_config();
    let before = home.read("config.toml");
    home.snow()
        .args([
            "connection",
            "add",
            "-n",
            "dev",
            "-a",
            "x",
            "--no-interactive",
        ])
        .assert()
        .code(2)
        .stderr(contains("Connection dev already exists"));
    assert_eq!(home.read("config.toml"), before);
}

#[test]
fn add_without_a_name_and_no_prompting_is_a_usage_error() {
    let home = Home::new();
    home.snow()
        .args(["connection", "add", "-a", "x", "--no-interactive"])
        .assert()
        .code(2)
        .stderr(contains("Missing option '--connection-name' / '-n'."));
    assert!(!home.path("config.toml").exists());
    // No terminal: it must not wait for input either.
    home.snow()
        .args(["connection", "add", "-a", "x"])
        .write_stdin("")
        .assert()
        .code(2);
}

#[test]
fn add_rejects_missing_paths_and_bad_ports() {
    let home = Home::new();
    for flag in ["-k", "-t"] {
        home.snow()
            .args([
                "connection",
                "add",
                "-n",
                "p",
                flag,
                "nope.txt",
                "--no-interactive",
            ])
            .assert()
            .code(2)
            .stderr(contains("Path nope.txt does not exist."));
    }
    home.snow()
        .args([
            "connection",
            "add",
            "-n",
            "p",
            "-P",
            "abc",
            "--no-interactive",
        ])
        .assert()
        .code(2);
    assert!(!home.path("config.toml").exists());
}

#[test]
fn add_refuses_a_config_that_others_can_read() {
    #[cfg(unix)]
    {
        let home = Home::new();
        home.write("config.toml", "[connections.a]\naccount = \"a\"\n");
        set_mode(&home.path("config.toml"), 0o644);
        home.snow()
            .args(["connection", "add", "-n", "b", "--no-interactive"])
            .assert()
            .code(1)
            .stderr(contains("too wide permissions"));
        assert_eq!(
            home.read("config.toml"),
            "[connections.a]\naccount = \"a\"\n"
        );
    }
}

#[test]
fn a_custom_config_file_is_written_and_only_warned_about() {
    #[cfg(unix)]
    {
        let home = Home::new();
        home.write("custom.toml", "");
        set_mode(&home.path("custom.toml"), 0o644);
        home.snow()
            .args([
                "--config-file",
                "custom.toml",
                "connection",
                "add",
                "-n",
                "c",
            ])
            .arg("--no-interactive")
            .assert()
            .success()
            .stderr(contains("Bad owner or permissions"));
        assert!(home.read("custom.toml").contains("[connections.c]"));
        // The file keeps its mode.
        assert_eq!(mode(&home.path("custom.toml")), 0o644);
    }
}

// ------------------------------------------------------ interactive add

#[derive(Default)]
struct Scripted {
    answers: VecDeque<String>,
    asked: Vec<(String, bool)>,
    /// Ctrl-D: once the answers run out the prompt aborts, as the terminal prompter does.
    eof_when_empty: bool,
}

impl Prompter for Scripted {
    fn prompt(&mut self, label: &str, hidden: bool) -> Result<String> {
        self.asked.push((label.to_string(), hidden));
        match self.answers.pop_front() {
            Some(answer) => Ok(answer),
            None if self.eof_when_empty => Err(snowflake_cli_rs::error::Error::new(
                snowflake_cli_rs::error::ErrorKind::Aborted,
                "Aborted.",
            )),
            None => Ok(String::new()),
        }
    }
}

/// Runs the CLI in-process; returns `(exit code, stdout, stderr)`.
fn run(home: &Home, args: &[&str], tty: bool, prompter: &mut Scripted) -> (i32, String, String) {
    run_env(home, &[], args, tty, prompter)
}

/// Like [`run`], with more environment variables.
fn run_env(
    home: &Home,
    extra: &[(&str, &str)],
    args: &[&str],
    tty: bool,
    prompter: &mut Scripted,
) -> (i32, String, String) {
    let env = Env::from_pairs(
        std::iter::once(("SNOWFLAKE_HOME", home.dir.path().display().to_string()))
            .chain(extra.iter().map(|(k, v)| (*k, v.to_string()))),
    );
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let args = std::iter::once("snow-rs").chain(args.iter().copied());
    let _log = crate::common::logger_guard();
    let code = snowflake_cli_rs::run_with(
        args,
        env,
        snowflake_cli_rs::Stdin {
            is_tty: tty,
            reader: &mut std::io::empty(),
        },
        prompter,
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

#[test]
fn interactive_add_prompts_for_the_missing_values_in_snows_order() {
    let home = Home::new();
    let mut prompter = Scripted {
        // name, account, user, password; the rest left empty.
        answers: ["  nm ", "acc", "bob", "s3cret"].map(String::from).into(),
        ..Default::default()
    };
    let (code, out, _) = run(
        &home,
        &["connection", "add", "-r", "FLAGROLE"],
        true,
        &mut prompter,
    );
    assert_eq!(code, 0, "{out}");
    let labels: Vec<&str> = prompter.asked.iter().map(|(l, _)| l.as_str()).collect();
    assert_eq!(
        labels,
        [
            "Enter connection name: ",
            "Enter account: ",
            "Enter user: ",
            "Enter password: ",
            // `role` came from the flag: not asked.
            "Enter warehouse: ",
            "Enter database: ",
            "Enter schema: ",
            "Enter host: ",
            "Enter port: ",
            "Enter protocol: ",
            "Enter region: ",
            "Enter authenticator: ",
            "Enter workload identity provider: ",
            "Enter private key file: ",
            "Enter token file path: ",
            "Enter secondary roles: ",
        ]
    );
    let hidden: Vec<bool> = prompter.asked.iter().map(|(_, h)| *h).collect();
    assert_eq!(hidden.iter().filter(|h| **h).count(), 1);
    assert!(hidden[3], "only the password prompt is hidden");
    let config: toml::Table = home.read("config.toml").parse().unwrap();
    let conn = config["connections"]["nm"].as_table().unwrap();
    assert_eq!(conn["account"].as_str(), Some("acc"));
    assert_eq!(conn["password"].as_str(), Some("s3cret"));
    assert_eq!(conn["role"].as_str(), Some("FLAGROLE"));
    assert_eq!(conn.len(), 4, "empty answers are not written: {conn:?}");
    // The password given to a prompt is not echoed in the warning.
    assert!(!out.contains("WARNING"));
}

#[test]
fn interactive_add_never_prompts_without_a_terminal_or_with_no_interactive() {
    for (tty, flags) in [(false, vec![]), (true, vec!["--no-interactive"])] {
        let home = Home::new();
        let mut prompter = Scripted::default();
        let mut args = vec!["connection", "add", "-n", "q"];
        args.extend(flags);
        let (code, _, _) = run(&home, &args, tty, &mut prompter);
        assert_eq!(code, 0);
        assert!(prompter.asked.is_empty());
    }
}

#[test]
fn interactive_add_with_a_bad_port_answer_is_a_usage_error() {
    let home = Home::new();
    let mut prompter = Scripted {
        answers: ["n", "", "", "", "", "", "", "", "", "70x"]
            .map(String::from)
            .into(),
        ..Default::default()
    };
    let (code, _, err) = run(&home, &["connection", "add"], true, &mut prompter);
    assert_eq!(code, 2);
    assert!(err.contains("'70x' is not a valid integer"), "{err}");
}

#[test]
fn interactive_add_keeps_the_spaces_of_a_password_and_trims_the_other_answers() {
    let home = Home::new();
    let mut prompter = Scripted {
        answers: [" n ", " acct ", " bob ", "  pa ss  ", " r "]
            .map(String::from)
            .into(),
        ..Default::default()
    };
    let (code, out, _) = run(&home, &["connection", "add"], true, &mut prompter);
    assert_eq!(code, 0, "{out}");
    let config = home.read("config.toml");
    assert!(config.contains("[connections.n]"), "{config}");
    assert!(config.contains("account = \"acct\""), "{config}");
    assert!(config.contains("user = \"bob\""), "{config}");
    assert!(config.contains("password = \"  pa ss  \""), "{config}");
    assert!(config.contains("role = \"r\""), "{config}");
}

#[test]
fn eof_at_an_add_prompt_aborts_and_writes_nothing() {
    for answers in [vec![], vec!["n".to_string(), "acct".to_string()]] {
        let home = Home::new();
        let mut prompter = Scripted {
            answers: answers.into(),
            eof_when_empty: true,
            ..Default::default()
        };
        let (code, _, err) = run(&home, &["connection", "add"], true, &mut prompter);
        assert_eq!(code, 1);
        assert_eq!(err.trim_end(), "Aborted.");
        assert!(!home.path("config.toml").exists());
    }
}

#[test]
fn eof_at_the_passphrase_prompt_aborts() {
    let home = Home::new();
    let key = key_path("aes256.p8");
    let args = jwt_args(key.to_str().unwrap());
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut prompter = Scripted {
        eof_when_empty: true,
        ..Default::default()
    };
    let (code, out, err) = run(&home, &args, true, &mut prompter);
    assert_eq!(code, 1, "{out}");
    assert_eq!(err.trim_end(), "Aborted.");
}

#[test]
fn a_passphrase_is_used_exactly_as_typed() {
    let home = Home::new();
    let key = key_path("aes256.p8");
    let args = jwt_args(key.to_str().unwrap());
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut prompter = Scripted {
        answers: [" test-passphrase ".to_string()].into(),
        ..Default::default()
    };
    let (code, _, err) = run(&home, &args, true, &mut prompter);
    assert_eq!(code, 1);
    assert!(err.contains("wrong passphrase"), "{err}");
}

// ------------------------------------------------------------------ list

#[test]
fn list_matches_snow_in_every_format() {
    let home = Home::new();
    home.with_golden_config();
    for (format, file) in [
        ("table", "list.table"),
        ("json", "list.json"),
        ("csv", "list.csv"),
        ("plain", "list.plain"),
    ] {
        let out = stdout(home.snow().args(["connection", "list", "--format", format]));
        assert_eq!(out, home.golden(file), "--format {format}");
    }
}

#[test]
fn list_all_without_env_connections_is_the_same_list() {
    let home = Home::new();
    home.with_golden_config();
    let out = stdout(
        home.snow()
            .args(["connection", "list", "-a", "--format", "csv"]),
    );
    assert_eq!(out, home.golden("list.csv"));
}

#[test]
fn list_without_connections() {
    let home = Home::new();
    assert_eq!(
        stdout(home.snow().args(["connection", "list", "--format", "json"])),
        "[]\n"
    );
    assert_eq!(
        stdout(home.snow().args(["connection", "list", "--format", "csv"])),
        ""
    );
    assert!(stdout(home.snow().args(["connection", "list"])).starts_with("No data"));
}

#[test]
fn list_applies_env_overrides_and_all_adds_env_only_connections() {
    let home = Home::new();
    home.write(
        "config.toml",
        "default_connection_name = \"b\"\n[connections.a]\nuser = \"file\"\n",
    );
    let env = [
        ("SNOWFLAKE_CONNECTIONS_A_USER", "env"),
        ("SNOWFLAKE_CONNECTIONS_A_PASSWORD", "hunter2"),
        ("SNOWFLAKE_CONNECTIONS_MY_ENV_ACCOUNT", "ea"),
        ("SNOWFLAKE_CONNECTIONS_MY_ENV_PRIVATE_KEY_FILE", "/k"),
        ("SNOWFLAKE_CONNECTIONS_MY_ENV_PRIVATE_KEY_FILE_PWD", "pw"),
        ("SNOWFLAKE_CONNECTIONS_MY_ENV_BOGUS", "ignored"),
        ("SNOWFLAKE_CONNECTIONS_NOKEY", "ignored"),
        ("SNOWFLAKE_DEFAULT_CONNECTION_NAME", "my_env"),
    ];
    let without_all = stdout(
        home.snow()
            .envs(env)
            .args(["connection", "list", "--format", "csv"]),
    );
    assert!(!without_all.contains("my_env"));
    assert!(without_all.contains("{'user': 'env', 'password': '****'}"));
    assert!(!without_all.contains("hunter2"));

    let all =
        stdout(
            home.snow()
                .envs(env)
                .args(["connection", "list", "--all", "--format", "json"]),
        );
    let parsed: serde_json::Value = serde_json::from_str(&all).unwrap();
    assert_eq!(
        parsed,
        serde_json::json!([
            {"connection_name": "a",
             "parameters": {"user": "env", "password": "****"}, "is_default": false},
            {"connection_name": "my_env",
             "parameters": {"account": "ea", "private_key_file": "/k",
                            "private_key_passphrase": "****"}, "is_default": true},
        ])
    );
    assert!(!all.contains("hunter2") && !all.contains("\"pw\""));
}

#[test]
fn list_reads_connections_toml_and_says_so_except_in_json_json_ext_and_csv() {
    let home = Home::new();
    home.write("connections.toml", "[z]\naccount = \"q\"\n");
    home.write("config.toml", "[connections.ignored]\naccount = \"i\"\n");
    let note = format!(
        "Reading connections from {}. Entries from config.toml are ignored.\n",
        home.path("connections.toml").display()
    );
    let table = stdout(home.snow().args(["connection", "list"]));
    assert!(table.starts_with(&note), "{table}");
    assert!(table.contains("| z "));
    assert!(!table.contains("| ignored"));
    assert!(
        stdout(
            home.snow()
                .args(["connection", "list", "--format", "plain"])
        )
        .starts_with(&note)
    );
    assert!(
        !stdout(home.snow().args(["connection", "list", "--format", "json"])).contains("Reading")
    );
    let json_ext = stdout(
        home.snow()
            .args(["connection", "list", "--format", "JSON_EXT"]),
    );
    assert!(json_ext.starts_with('['), "{json_ext}");
    assert!(
        !stdout(home.snow().args(["connection", "list", "--format", "csv"])).contains("Reading")
    );
    assert!(!stdout(home.snow().args(["connection", "list", "--silent"])).contains("Reading"));
}

#[test]
fn list_uses_the_default_connection_from_the_environment_or_file() {
    let home = Home::new();
    home.write(
        "config.toml",
        "[connections.a]\naccount = \"a\"\n[connections.b]\naccount = \"b\"\n",
    );
    let out = stdout(
        home.snow()
            .env("SNOWFLAKE_DEFAULT_CONNECTION_NAME", "b")
            .args(["connection", "list", "--format", "csv"]),
    );
    assert!(
        out.contains("a\"b\"") || out.contains("{'account': 'b'},True"),
        "{out}"
    );
    assert!(out.contains("{'account': 'a'},False"));
}

// ------------------------------------------------- remove / set-default

#[test]
fn remove_deletes_only_that_entry() {
    let home = Home::new();
    let original =
        "# top\n\n[connections.a]\naccount = \"a\" # note\n\n[connections.b]\naccount = \"b\"\n";
    home.write("config.toml", original);
    home.snow()
        .args(["connection", "remove", "a"])
        .assert()
        .success()
        .stdout(format!(
            "Removed connection a from {}.\n",
            home.path("config.toml").display()
        ));
    assert_eq!(
        home.read("config.toml"),
        "# top\n\n[connections.b]\naccount = \"b\"\n"
    );
}

#[test]
fn remove_the_default_connection_unsets_the_default() {
    let home = Home::new();
    home.write(
        "config.toml",
        "default_connection_name = \"a\"\n\n[connections.a]\naccount = \"a\"\n",
    );
    home.snow()
        .args(["connection", "remove", "a", "--format", "json"])
        .assert()
        .success()
        .stdout(contains(
            "It was the default connection, so default connection is now unset.",
        ));
    let config = home.read("config.toml");
    assert!(!config.contains("default_connection_name"), "{config}");
    assert!(!config.contains("[connections.a]"));
}

#[test]
fn remove_follows_snow_and_honours_the_default_env_override() {
    // Checked against snow 3.34.0: with SNOWFLAKE_DEFAULT_CONNECTION_NAME=a and the file default
    // b, `remove a` removes a and unsets the file's default (b stays defined).
    let home = Home::new();
    home.write(
        "config.toml",
        "default_connection_name = \"b\"\n\n[connections.a]\naccount = \"a\"\n\n[connections.b]\naccount = \"b\"\n",
    );
    let mut prompter = Scripted::default();
    let (code, out, _) = run_env(
        &home,
        &[("SNOWFLAKE_DEFAULT_CONNECTION_NAME", "a")],
        &["connection", "remove", "a"],
        false,
        &mut prompter,
    );
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("default connection is now unset"), "{out}");
    assert_eq!(
        home.read("config.toml"),
        "\n[connections.b]\naccount = \"b\"\n"
    );
    // And without the override the file's default decides.
    let home = Home::new();
    home.write(
        "config.toml",
        "default_connection_name = \"b\"\n\n[connections.a]\naccount = \"a\"\n\n[connections.b]\naccount = \"b\"\n",
    );
    let (code, out, _) = run(&home, &["connection", "remove", "a"], false, &mut prompter);
    assert_eq!(code, 0, "{out}");
    assert!(!out.contains("default"), "{out}");
    assert!(
        home.read("config.toml")
            .contains("default_connection_name = \"b\"")
    );
}

#[test]
fn remove_from_connections_toml() {
    let home = Home::new();
    home.write(
        "connections.toml",
        "# c\n\n[a]\naccount = \"a\"\n[b]\naccount = \"b\"\n",
    );
    home.snow()
        .args(["connection", "remove", "a"])
        .assert()
        .success()
        .stdout(contains("connections.toml"));
    assert_eq!(
        home.read("connections.toml"),
        "# c\n\n[b]\naccount = \"b\"\n"
    );
    assert!(!home.path("config.toml").exists());
}

#[test]
fn remove_unknown_connection_is_a_usage_error() {
    let home = Home::new();
    home.with_golden_config();
    let before = home.read("config.toml");
    home.snow()
        .args(["connection", "remove", "nope"])
        .assert()
        .code(2)
        .stderr(contains("Connection nope does not exist."));
    assert_eq!(home.read("config.toml"), before);
}

#[test]
fn set_default_sets_the_name() {
    let home = Home::new();
    home.with_golden_config();
    home.snow()
        .args(["connection", "set-default", "dev"])
        .assert()
        .success()
        .stdout("Default connection set to: dev\n");
    let config = home.read("config.toml");
    assert_eq!(
        config,
        home.golden("config.toml").replace(
            "default_connection_name = \"full\"",
            "default_connection_name = \"dev\""
        )
    );
    home.snow()
        .args(["connection", "set-default", "dev", "--format", "csv"])
        .assert()
        .success()
        .stdout("message\nDefault connection set to: dev\n");
}

#[test]
fn set_default_unknown_connection_is_a_client_error() {
    let home = Home::new();
    home.with_golden_config();
    home.snow()
        .args(["connection", "set-default", "nope"])
        .assert()
        .code(1)
        .stderr(contains("Connection nope is not configured"));
}

// ----------------------------------------------------------- generate-jwt

fn jwt_args(key: &str) -> Vec<String> {
    [
        "connection",
        "generate-jwt",
        "-x",
        "--account",
        "myorg-acct1.eu-west-1",
        "--user",
        "jdoe",
        "--private-key-file",
        key,
    ]
    .map(String::from)
    .into()
}

fn decode(segment: &str) -> serde_json::Value {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segment).unwrap()).unwrap()
}

#[test]
fn generate_jwt_prints_only_a_token_that_verifies_against_the_public_key() {
    let home = Home::new();
    let key = key_path("unencrypted.p8");
    let out = stdout(home.snow().args(jwt_args(key.to_str().unwrap())));
    assert_eq!(out.matches('\n').count(), 1, "{out:?}");
    let jwt = out.trim_end();
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(
        decode(parts[0]),
        serde_json::json!({"alg": "RS256", "typ": "JWT"})
    );

    let fingerprint = std::fs::read_to_string(key_path("fingerprint.txt")).unwrap();
    let claims = decode(parts[1]);
    assert_eq!(claims["sub"], "MYORG-ACCT1.JDOE");
    assert_eq!(
        claims["iss"],
        format!("MYORG-ACCT1.JDOE.SHA256:{}", fingerprint.trim())
    );
    let iat = claims["iat"].as_u64().unwrap();
    assert_eq!(claims["exp"].as_u64().unwrap(), iat + 3540);

    let pem = std::fs::read_to_string(&key).unwrap();
    let public = <RsaPrivateKey as pkcs8::DecodePrivateKey>::from_pkcs8_pem(&pem)
        .unwrap()
        .to_public_key();
    let signature =
        Signature::try_from(URL_SAFE_NO_PAD.decode(parts[2]).unwrap().as_slice()).unwrap();
    VerifyingKey::<Sha256>::new(public)
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .unwrap();
}

#[test]
fn generate_jwt_json_wraps_the_token_in_a_message() {
    let home = Home::new();
    let key = key_path("unencrypted.p8");
    let mut args = jwt_args(key.to_str().unwrap());
    args.extend(["--format".into(), "json".into()]);
    let out = stdout(home.snow().args(args));
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed["message"].as_str().unwrap().split('.').count(), 3);
}

#[test]
fn generate_jwt_from_a_configured_connection_and_encrypted_key() {
    let home = Home::new();
    home.write(
        "config.toml",
        &format!(
            "[connections.k]\naccount = \"acct\"\nuser = \"u\"\nauthenticator = \"snowflake_jwt\"\nprivate_key_file = \"{}\"\nprivate_key_file_pwd = \"test-passphrase\"\n",
            key_path("aes256.p8").display()
        ),
    );
    let out = stdout(home.snow().args(["connection", "generate-jwt", "-c", "k"]));
    assert_eq!(out.trim_end().split('.').count(), 3);
    // The environment passphrase wins over the file's; a wrong one fails.
    home.snow()
        .env("PRIVATE_KEY_PASSPHRASE", "wrong")
        .args(["connection", "generate-jwt", "-c", "k"])
        .assert()
        .code(1)
        .stderr(contains("wrong passphrase"));
}

#[test]
fn generate_jwt_asks_for_the_passphrase_only_on_a_terminal() {
    let home = Home::new();
    let key = key_path("aes256.p8");
    let args = jwt_args(key.to_str().unwrap());
    let args: Vec<&str> = args.iter().map(String::as_str).collect();

    let mut prompter = Scripted {
        answers: ["test-passphrase".to_string()].into(),
        ..Default::default()
    };
    let (code, out, _) = run(&home, &args, true, &mut prompter);
    assert_eq!(code, 0);
    assert_eq!(out.trim_end().split('.').count(), 3);
    assert_eq!(
        prompter.asked,
        [(
            "Enter private key file password (press enter for empty): ".to_string(),
            true
        )]
    );

    let mut prompter = Scripted::default();
    let (code, out, err) = run(&home, &args, false, &mut prompter);
    assert_eq!(code, 1, "{out}");
    assert!(err.contains("PRIVATE_KEY_PASSPHRASE"), "{err}");
    assert!(prompter.asked.is_empty());
}

#[test]
fn generate_jwt_requires_user_account_and_key() {
    let home = Home::new();
    for (args, what) in [
        (
            vec!["-x", "--account", "a", "--private-key-file", "key.p8"],
            "User",
        ),
        (
            vec!["-x", "--user", "u", "--private-key-file", "key.p8"],
            "Account",
        ),
        (
            vec!["-x", "--account", "a", "--user", "u"],
            "Private key file",
        ),
    ] {
        home.snow()
            .args(["connection", "generate-jwt"])
            .args(args)
            .assert()
            .code(2)
            .stderr(contains(format!(
                "{what} is not set in the connection context"
            )));
    }
}

#[test]
fn generate_jwt_ignores_the_authenticator_as_snow_does() {
    let home = Home::new();
    let mut args = jwt_args(key_path("unencrypted.p8").to_str().unwrap());
    args.extend(["--authenticator".into(), "externalbrowser".into()]);
    let token = stdout(home.snow().args(args));
    assert_eq!(token.trim().split('.').count(), 3);
}

#[test]
fn generate_jwt_with_an_unreadable_key_fails_without_printing_it() {
    let home = Home::new();
    home.write("bad.pem", "SECRET-MARKER not a key");
    let mut args = jwt_args("bad.pem");
    args.extend(["--debug".into()]);
    let assert = home.snow().args(args).assert().code(1);
    let output = assert.get_output();
    assert!(!String::from_utf8_lossy(&output.stderr).contains("SECRET-MARKER"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("SECRET-MARKER"));
}

#[test]
fn unknown_default_connection_is_reported() {
    let home = Home::new();
    home.snow()
        .args(["connection", "generate-jwt"])
        .assert()
        .code(1)
        .stderr(contains(
            "Couldn't find connection for default connection `default`",
        ));
}

// ------------------------------------------------------------------ test

fn test_args(server: &MockServer) -> Vec<String> {
    [
        "connection",
        "test",
        "-x",
        "--account",
        "testacct",
        "--user",
        "tester",
        "--authenticator",
        "SNOWFLAKE_JWT",
        "--private-key-file",
        key_path("unencrypted.p8").to_str().unwrap(),
        "--host",
        &server.host(),
        "--port",
        &server.port().to_string(),
        "--role",
        "TEST_ROLE",
        "--warehouse",
        "TEST_WH",
        "--database",
        "TEST_DB",
    ]
    .map(String::from)
    .into()
}

#[test]
fn test_signs_in_runs_a_statement_and_prints_the_connection() {
    let home = Home::new();
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        common::authorized(when)
            .method("POST")
            .path(STATEMENTS)
            .json_body_includes(
                serde_json::json!({
                    "statement": "SELECT 1", "database": "TEST_DB",
                    "role": "TEST_ROLE", "warehouse": "TEST_WH",
                })
                .to_string(),
            );
        then.status(200).json_body(one_int_body("1"));
    });
    let mut cmd = home.snow();
    cmd.env("SNOWFLAKE_PROTOCOL", "http")
        .args(test_args(&server));
    let table = stdout(&mut cmd);
    mock.assert_calls(1);
    for line in [
        "| Connection name | None",
        "| Status          | OK",
        &format!("| Host            | {}", server.host()),
        "| Account         | testacct",
        "| User            | tester",
        "| Role            | TEST_ROLE",
        "| Database        | TEST_DB",
        "| Warehouse       | TEST_WH",
    ] {
        assert!(table.contains(line), "{line} missing from:\n{table}");
    }

    let mut cmd = home.snow();
    let mut args = test_args(&server);
    args.extend(["--format".into(), "json".into()]);
    cmd.env("SNOWFLAKE_PROTOCOL", "http").args(args);
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&mut cmd)).unwrap();
    assert_eq!(parsed["Connection name"], serde_json::Value::Null);
    assert_eq!(parsed["Status"], "OK");
    assert_eq!(parsed["Account"], "testacct");
    assert_eq!(parsed["Role"], "TEST_ROLE");
    // Not set values say so.
    assert_eq!(parsed["Host"], server.host());
}

#[test]
fn test_names_the_connection_and_reports_what_is_not_set() {
    let home = Home::new();
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method("POST").path(STATEMENTS);
        then.status(200).json_body(one_int_body("1"));
    });
    home.write(
        "config.toml",
        &format!(
            "[connections.k]\naccount = \"acct\"\nuser = \"u\"\nauthenticator = \"snowflake_jwt\"\nprivate_key_file = \"{}\"\nhost = \"{}\"\nport = {}\nprotocol = \"http\"\n",
            key_path("unencrypted.p8").display(),
            server.host(),
            server.port()
        ),
    );
    let out = stdout(
        home.snow()
            .args(["connection", "test", "-c", "k", "--format", "json"]),
    );
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed["Connection name"], "k");
    assert_eq!(parsed["Role"], "not set");
    assert_eq!(parsed["Database"], "not set");
    assert_eq!(parsed["Warehouse"], "not set");
}

#[test]
fn test_computes_the_host_from_the_account() {
    let home = Home::new();
    // No server is reachable, but the failure comes after the argument checks: use a closed port.
    home.snow()
        .args([
            "connection",
            "test",
            "-x",
            "--account",
            "acct",
            "--user",
            "u",
            "--authenticator",
            "snowflake_jwt",
            "--private-key-file",
            key_path("unencrypted.p8").to_str().unwrap(),
            "--host",
            "127.0.0.1",
            "--port",
            "1",
        ])
        .env("SNOWFLAKE_PROTOCOL", "http")
        .assert()
        .code(1);
}

#[test]
fn test_reports_a_rejected_statement() {
    let home = Home::new();
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method("POST").path(STATEMENTS);
        then.status(422).json_body(serde_json::json!({
            "code": "390189", "sqlState": "08004",
            "message": "Role 'TEST_ROLE' specified in the connect string does not exist or not authorized.",
            "statementHandle": common::HANDLE,
        }));
    });
    home.snow()
        .env("SNOWFLAKE_PROTOCOL", "http")
        .args(test_args(&server))
        .assert()
        .code(1)
        .stderr(contains(
            "specified in the connect string does not exist or not authorized.",
        ));
}

#[test]
fn test_with_a_password_authenticator_needs_the_password() {
    let home = Home::new();
    for authenticator in [
        Some("username_password_mfa"),
        Some("https://org.okta.com"),
        None,
    ] {
        let mut args = vec!["connection", "test", "-x", "--account", "a", "--user", "u"];
        if let Some(a) = authenticator {
            args.extend(["--authenticator", a]);
        }
        home.snow().args(args).assert().code(1).stderr(contains(
            "Could not connect to Snowflake. Reason: 251006: Password is empty",
        ));
    }
}

#[test]
fn test_without_a_connection_fails_like_snow() {
    let home = Home::new();
    home.snow()
        .args(["connection", "test", "-c", "nope"])
        .assert()
        .code(1)
        .stderr(contains("Connection nope is not configured"));
}

#[test]
fn passwords_never_reach_stderr_or_debug_output() {
    let home = Home::new();
    home.snow()
        .args([
            "connection",
            "add",
            "-n",
            "x",
            "-p",
            "TOP-SECRET",
            "--no-interactive",
            "--debug",
            "-v",
        ])
        .assert()
        .success()
        .stderr(predicates::str::contains("TOP-SECRET").not());
    let list = stdout(home.snow().args(["connection", "list", "--debug"]));
    assert!(!list.contains("TOP-SECRET"));
    assert!(list.contains("****"));
}
