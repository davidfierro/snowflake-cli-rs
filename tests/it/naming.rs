//! The naming rules of CONTRIBUTING.md, as `scripts/check-naming.sh` enforces them on every pull
//! request (`.github/workflows/naming.yml`).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn check_in(dir: &Path, mode: &str, value: &str) -> Output {
    Command::new("bash")
        .arg(repo_root().join("scripts/check-naming.sh"))
        .args([mode, value])
        .current_dir(dir)
        .output()
        .unwrap()
}

fn check(mode: &str, value: &str) -> Output {
    check_in(&repo_root(), mode, value)
}

fn assert_accepted(mode: &str, value: &str) {
    let out = check(mode, value);
    assert!(
        out.status.success(),
        "{mode} {value:?} should be accepted: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

fn assert_rejected(mode: &str, value: &str) {
    let out = check(mode, value);
    assert_eq!(
        out.status.code(),
        Some(1),
        "{mode} {value:?} should be rejected"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("error: "), "{stdout}");
    assert!(stdout.contains(value), "{stdout}");
}

#[test]
fn titles_follow_conventional_commits() {
    for title in [
        "feat: support --retain-comments",
        "feat(sql): support --retain-comments",
        "fix(put-get)!: drop the legacy flag",
        "refactor!: rename the binary",
        "chore: release v0.1.0",
        "docs: ADR 0007",
        "build: bump the toolchain",
        "ci: test on Windows",
        "perf: stream partitions",
        "revert: feat(sql): support --retain-comments",
        "style: reflow comments",
        "test: cover CRLF goldens",
    ] {
        assert_accepted("title", title);
    }
}

#[test]
fn titles_off_the_format_are_rejected() {
    for title in [
        "Cross-platform CI: test on Linux, macOS and Windows",
        "Add --retain-comments",
        "feature: support --retain-comments",
        "Feat: support --retain-comments",
        "feat:support --retain-comments",
        "feat:  two spaces",
        "feat(SQL): uppercase scope",
        "feat(): empty scope",
        "feat (sql): space before the scope",
        "feat: ",
        "fix: keep CRLF in goldens.",
        "fixup! fix: keep CRLF in goldens",
        "Merge branch 'main' into feat/x",
    ] {
        assert_rejected("title", title);
    }
}

#[test]
fn titles_are_at_most_100_characters() {
    let prefix = "feat: ";
    let fits = format!("{prefix}{}", "a".repeat(100 - prefix.len()));
    assert_accepted("title", &fits);
    let too_long = format!("{fits}a");
    assert_rejected("title", &too_long);
    let out = check("title", &too_long);
    assert!(String::from_utf8_lossy(&out.stdout).contains("101 characters"));
}

#[test]
fn branches_are_type_slash_slug_with_an_optional_issue_key() {
    for branch in [
        "feat/retain-comments",
        "feat/DFI-190-naming-conventions",
        "fix/GH-12-crlf-goldens",
        "docs/adr-0007",
        "chore/bump-toolchain-1-100",
        // release-plz names its own release PR branch.
        "release-plz-2026-11-22T07-47-51Z",
    ] {
        assert_accepted("branch", branch);
    }
}

#[test]
fn branches_off_the_format_are_rejected() {
    for branch in [
        "main",
        "retain-comments",
        "agent/DFI-190-naming-conventions",
        "feature/retain-comments",
        "feat/Retain-Comments",
        "feat/retain_comments",
        "feat/dfi-190-",
        "feat/",
        "feat/sql/retain-comments",
        "feat/DFI-190",
        "feat/-retain-comments",
    ] {
        assert_rejected("branch", branch);
    }
}

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
        .args(["-c", "commit.gpgsign=false"])
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn commit(dir: &Path, subject: &str) {
    git(dir, &["commit", "-q", "--allow-empty", "-m", subject]);
}

/// A repository with a `base` commit on `main` and a `feat/x` branch checked out on top of it.
fn repo_with_branch() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q", "-b", "main"]);
    commit(dir.path(), "Initial public release");
    git(dir.path(), &["checkout", "-q", "-b", "feat/x"]);
    dir
}

#[test]
fn commits_checks_every_subject_of_the_range_and_nothing_before_it() {
    let dir = repo_with_branch();
    commit(dir.path(), "feat: one");
    commit(dir.path(), "test: cover one");
    // The pre-existing `main` commit is off the format but outside the range.
    let out = check_in(dir.path(), "commits", "main..HEAD");
    assert!(out.status.success());

    commit(dir.path(), "WIP");
    commit(dir.path(), "Address review");
    commit(dir.path(), "fix: two");
    let out = check_in(dir.path(), "commits", "main..HEAD");
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.lines().count(), 2, "{stdout}");
    assert!(stdout.contains("commit subject \"WIP\""), "{stdout}");
    assert!(
        stdout.contains("commit subject \"Address review\""),
        "{stdout}"
    );
}

#[test]
fn commits_ignores_merge_commits() {
    let dir = repo_with_branch();
    commit(dir.path(), "feat: one");
    git(dir.path(), &["checkout", "-q", "main"]);
    commit(dir.path(), "fix: on main meanwhile");
    git(dir.path(), &["checkout", "-q", "feat/x"]);
    git(dir.path(), &["merge", "-q", "--no-ff", "--no-edit", "main"]);
    let out = check_in(dir.path(), "commits", "main..HEAD");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn commits_fails_on_a_range_git_cannot_resolve() {
    let dir = repo_with_branch();
    let out = check_in(dir.path(), "commits", "no-such-ref..HEAD");
    assert!(!out.status.success());
}

#[test]
fn a_wrong_invocation_prints_the_usage_and_exits_2() {
    for args in [&[][..], &["title"], &["nope", "x"], &["title", "a", "b"]] {
        let out = Command::new("bash")
            .arg(repo_root().join("scripts/check-naming.sh"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("Usage:"));
    }
}

/// The PR title and branch are written by the PR author: interpolating them into a `run` script
/// would let a title inject shell. They must reach the script through `env`.
#[test]
fn the_workflow_never_interpolates_expressions_into_run_steps() {
    let workflow =
        std::fs::read_to_string(repo_root().join(".github/workflows/naming.yml")).unwrap();
    let runs: Vec<&str> = workflow
        .lines()
        .filter(|line| line.trim_start().starts_with("run:"))
        .collect();
    assert_eq!(runs.len(), 3, "title, commits and branch: {runs:?}");
    for run in runs {
        assert!(run.contains("scripts/check-naming.sh"), "{run}");
        assert!(!run.contains("${{"), "{run}");
    }
    assert!(!workflow.contains("pull_request_target"));
    assert!(workflow.contains("types: [opened, edited, reopened, synchronize]"));
}
