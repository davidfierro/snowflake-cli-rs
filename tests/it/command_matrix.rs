//! The README command matrix: generated from `docs/snow-surface.json` (the official
//! snow), the clap tree and `bench/results.json`. `UPDATE_README=1 cargo test --test it
//! command_matrix` rewrites the README.

use clap::CommandFactory;
use snowflake_cli_rs::Cli;
use snowflake_cli_rs::matrix::{
    Results, Snapshot, declared_commands, diff, ported_surface, render, splice, unbenchmarked,
};
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> String {
    std::fs::read_to_string(root().join(path)).unwrap_or_else(|e| panic!("cannot read {path}: {e}"))
}

fn results() -> Results {
    serde_json::from_str(&read("bench/results.json")).expect("bench/results.json is invalid")
}

#[test]
fn readme_matrix_is_up_to_date() {
    let snapshot: Snapshot =
        serde_json::from_str(&read("docs/snow-surface.json")).expect("snapshot is invalid");
    let matrix = render(&snapshot, &ported_surface(&Cli::command()), &results())
        .unwrap_or_else(|e| panic!("{e}"));
    let readme = read("README.md");
    let expected = splice(&readme, &matrix).unwrap_or_else(|e| panic!("{e}"));
    if std::env::var_os("UPDATE_README").is_some() {
        std::fs::write(root().join("README.md"), expected).expect("cannot write README.md");
        return;
    }
    assert!(
        expected == readme,
        "README.md command matrix is out of date; run `UPDATE_README=1 cargo test --test it command_matrix` and commit it.\n{}",
        diff(&expected, &readme)
    );
}

#[test]
fn every_ported_command_has_a_benchmark_scenario() {
    let declared = declared_commands(&read("bench/run.sh"));
    let missing = unbenchmarked(&ported_surface(&Cli::command()), &results(), &declared);
    assert!(
        missing.is_empty(),
        "ported commands without a scenario in bench/run.sh: {}. Add one to bench/run.sh; a maintainer runs it and commits the results.",
        missing.join(", ")
    );
}
