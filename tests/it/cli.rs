use assert_cmd::Command;
use predicates::str::contains;

/// The environment may export `SNOWFLAKE_*` variables (snow's generic overrides): never inherit them.
fn snow() -> Command {
    let mut cmd = Command::cargo_bin("snow-rs").unwrap();
    cmd.env_clear();
    crate::common::keep_system_env(&mut cmd);
    // Keep coverage profiling working under `cargo llvm-cov`.
    if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
        cmd.env("LLVM_PROFILE_FILE", profile);
    }
    cmd
}

#[test]
fn version_prints_crate_version() {
    snow()
        .arg("--version")
        .assert()
        .success()
        .stdout(contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_prints_usage() {
    snow()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("Usage: snow-rs"));
}

#[test]
fn unknown_flag_fails() {
    snow().arg("--nope").assert().code(2);
}

#[test]
fn usage_error_names_snow_rs() {
    snow()
        .args(["sql", "--bogus"])
        .assert()
        .code(2)
        // clap prints the executable name: `snow-rs.exe` on Windows.
        .stderr(contains(format!(
            "Usage: snow-rs{} sql [OPTIONS]",
            std::env::consts::EXE_SUFFIX
        )));
}

#[test]
fn completions_reference_snow_rs() {
    snow()
        .arg("--show-completion")
        .env("SHELL", "/bin/bash")
        .assert()
        .success()
        .stdout(contains("snow-rs"));
}

#[test]
fn config_file_flag_is_accepted() {
    snow()
        .args(["--config-file", "/nonexistent/config.toml"])
        .assert()
        .success();
}

#[test]
fn config_file_flag_is_listed_in_help() {
    snow()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("--config-file"));
}
