//! Guards the release pipeline's settled decisions (ADR 0007). None of it runs before a real
//! release, so a config edit that breaks one would otherwise only show up then.

use std::path::Path;

fn read(path: &str) -> String {
    let full = Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    std::fs::read_to_string(&full).unwrap_or_else(|e| panic!("read {}: {e}", full.display()))
}

fn toml(path: &str) -> toml::Table {
    read(path).parse().expect("valid TOML")
}

fn strings(value: &toml::Value) -> Vec<&str> {
    value
        .as_array()
        .expect("array")
        .iter()
        .map(|v| v.as_str().expect("string"))
        .collect()
}

#[test]
fn the_crate_is_publishable_as_snowflake_cli_rs_with_binary_snow_rs() {
    let cargo = toml("Cargo.toml");
    let package = cargo["package"].as_table().expect("[package]");
    assert_eq!(package["name"].as_str(), Some("snowflake-cli-rs"));
    assert!(
        !package.contains_key("publish"),
        "`publish` must stay unset"
    );
    for key in [
        "repository",
        "readme",
        "keywords",
        "categories",
        "rust-version",
    ] {
        assert!(package.contains_key(key), "[package] lacks `{key}`");
    }
    let bins = cargo["bin"].as_array().expect("[[bin]]");
    assert_eq!(bins.len(), 1);
    assert_eq!(bins[0]["name"].as_str(), Some("snow-rs"));
}

#[test]
fn the_published_crate_leaves_out_tests_bench_and_docs() {
    let cargo = toml("Cargo.toml");
    let include = strings(&cargo["package"]["include"]);
    for path in &include {
        for excluded in ["/tests", "/bench", "/docs", "/scripts"] {
            assert!(
                !path.starts_with(excluded),
                "`{path}` would ship {excluded}"
            );
        }
    }
    assert!(include.contains(&"/src/**/*.rs"));
    assert!(include.contains(&"/LICENSE") && include.contains(&"/NOTICE"));
}

#[test]
fn dist_builds_the_agreed_targets_and_installers() {
    let dist = toml("dist-workspace.toml");
    let dist = dist["dist"].as_table().expect("[dist]");
    let mut targets = strings(&dist["targets"]);
    targets.sort_unstable();
    assert_eq!(
        targets,
        [
            "aarch64-apple-darwin",
            "aarch64-unknown-linux-gnu",
            "x86_64-apple-darwin",
            "x86_64-pc-windows-msvc",
            "x86_64-unknown-linux-gnu",
        ]
    );
    assert_eq!(strings(&dist["installers"]), ["shell", "powershell"]);
    assert_eq!(dist["install-updater"].as_bool(), Some(false));
}

#[test]
fn the_wheel_wraps_the_binary_and_takes_its_version_from_cargo() {
    let pyproject = toml("pyproject.toml");
    let project = pyproject["project"].as_table().expect("[project]");
    assert_eq!(project["name"].as_str(), Some("snowflake-cli-rs"));
    assert!(
        !project.contains_key("version"),
        "the version must come from Cargo.toml"
    );
    assert_eq!(strings(&project["dynamic"]), ["version"]);
    let maturin = pyproject["tool"]["maturin"]
        .as_table()
        .expect("[tool.maturin]");
    assert_eq!(maturin["bindings"].as_str(), Some("bin"));
}

#[test]
fn only_dist_creates_the_github_release() {
    let release_plz = toml("release-plz.toml");
    let workspace = release_plz["workspace"].as_table().expect("[workspace]");
    assert_eq!(workspace["git_release_enable"].as_bool(), Some(false));
    assert_eq!(workspace["release_always"].as_bool(), Some(false));
}

#[test]
fn no_secret_reaches_a_pull_request() {
    for name in ["ci.yml", "release.yml", "release-plz.yml", "pypi.yml"] {
        let workflow = read(&format!(".github/workflows/{name}"));
        assert!(
            !workflow.contains("pull_request_target"),
            "{name} uses pull_request_target"
        );
        let on_pull_request = workflow.lines().any(|l| l.trim() == "pull_request:");
        // dist's plan job runs on PRs with `GITHUB_TOKEN` only.
        let secrets: Vec<&str> = workflow
            .lines()
            .filter(|l| l.contains("secrets.") && !l.contains("secrets.GITHUB_TOKEN"))
            .collect();
        assert!(
            !(on_pull_request && !secrets.is_empty()),
            "{name} runs on pull requests and reads {secrets:?}"
        );
    }
}

#[test]
fn only_the_publish_jobs_get_an_oidc_token() {
    for (name, publishing_jobs) in [("release-plz.yml", 1), ("pypi.yml", 1), ("release.yml", 0)] {
        let workflow = read(&format!(".github/workflows/{name}"));
        assert_eq!(
            workflow.matches("id-token: write").count(),
            publishing_jobs,
            "{name}"
        );
    }
}

#[test]
fn a_tag_whose_commit_is_not_on_main_publishes_nothing() {
    let check = r#"git merge-base --is-ancestor "$GITHUB_SHA" origin/main"#;

    // pypi.yml: a `guard` job that every other job waits for.
    let pypi = read(".github/workflows/pypi.yml");
    let guard = pypi.split("\n  wheels:").next().expect("jobs");
    assert!(guard.contains("\n  guard:") && guard.contains(check));
    assert!(
        guard.contains("fetch-depth: 0"),
        "the guard needs main's history"
    );
    assert_eq!(
        pypi.matches("    needs: guard\n").count(),
        2,
        "wheels and sdist"
    );
    assert!(pypi.contains("    needs: [guard, wheels, sdist]\n"));

    // release.yml: the same check, injected by dist into every build job before `dist build`,
    // so `host` (which creates the GitHub Release) never runs.
    let dist = toml("dist-workspace.toml");
    assert_eq!(
        dist["dist"]["github-build-setup"].as_str(),
        Some("../release-guard.yml")
    );
    assert!(read(".github/release-guard.yml").contains(check));
    let release = read(".github/workflows/release.yml");
    let build = release
        .split("\n  build-local-artifacts:")
        .nth(1)
        .and_then(|rest| rest.split("\n  build-global-artifacts:").next())
        .expect("build-local-artifacts job");
    let guard_at = build.find(check).expect("guard in the build job");
    let build_at = build.find("dist build ").expect("dist build step");
    assert!(
        guard_at < build_at,
        "the guard must run before `dist build`"
    );
}
