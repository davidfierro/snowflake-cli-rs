//! `!source`/`!load` goldens: the statements and the errors must be what snow 3.34.0's
//! own statement reader gives for the same scripts.
//! Capture: `scripts/capture-source-goldens.sh` (no network).

use snowflake_cli_rs::env::Env;
use snowflake_cli_rs::project::ProjectSource;
use snowflake_cli_rs::script::source::resolve;
use snowflake_cli_rs::script::template::{Syntaxes, Templater, Variables};
use snowflake_cli_rs::script::{CompileOptions, FsSources, Input, Sources, compile_inputs};
use std::path::{Path, PathBuf};

/// Paths relative to the fixture directory, as snow sees them with it as the working directory.
struct Rooted {
    root: PathBuf,
    fs: FsSources,
}

impl Sources for Rooted {
    fn canonical(&self, path: &str) -> String {
        resolve(&self.root.join(path)).display().to_string()
    }
    fn read_file(&self, path: &str, path_part: &str) -> Result<String, String> {
        self.fs
            .read_file(&self.root.join(path).display().to_string(), path_part)
    }
    fn fetch_url(&self, url: &str, path_part: &str) -> Result<String, String> {
        self.fs.fetch_url(url, path_part)
    }
}

#[test]
fn sources_match_snow() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/source");
    let cases: toml::Table = std::fs::read_to_string(root.join("cases.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let cases = cases["case"].as_array().unwrap();
    assert!(cases.len() >= 15, "source cases missing");
    let sources = Rooted {
        root: root.clone(),
        fs: FsSources::default(),
    };
    let mut failures = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let flag = |key: &str| case.get(key).and_then(|v| v.as_bool()).unwrap_or(false);
        let input = match case.get("file").and_then(|f| f.as_str()) {
            Some(file) => Input {
                text: std::fs::read_to_string(root.join(file)).unwrap(),
                file: Some(root.join(file)),
            },
            None => Input {
                text: case["text"].as_str().unwrap().to_string(),
                file: None,
            },
        };
        let mut variables = Variables::new();
        if let Some(table) = case.get("variables").and_then(|v| v.as_table()) {
            for (k, v) in table {
                variables.insert(k.clone(), v.as_str().unwrap().to_string());
            }
        }
        let options = CompileOptions {
            retain_comments: flag("retain_comments"),
            local_only: flag("local_only"),
            ..CompileOptions::default()
        };
        let project = ProjectSource::new(None, Variables::new(), Env::default());
        let templater = Templater::new(&variables, Syntaxes::default(), &project);
        let mut notices = Vec::new();
        let result = compile_inputs(&[input], &options, &templater, &mut notices, &sources);

        let expected: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(root.join(format!("{name}.json"))).unwrap(),
        )
        .unwrap();
        let strings = |key: &str| -> Vec<String> {
            expected[key]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect()
        };
        let errors = strings("errors");
        let notices: Vec<String> = notices.iter().map(|n| normalize(n, &root)).collect();
        if notices != errors {
            failures.push(format!("{name}: errors {notices:?}, snow {errors:?}"));
        }
        match result {
            Ok(statements) => {
                let texts: Vec<String> = statements.into_iter().map(|s| s.text).collect();
                if !errors.is_empty() || texts != strings("statements") {
                    failures.push(format!("{name}: statements {texts:?}"));
                }
            }
            Err(err) => {
                if errors.is_empty() && !strings("statements").is_empty() {
                    failures.push(format!("{name}: unexpected error {}", err.message()));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn normalize(text: &str, root: &Path) -> String {
    text.replace(&root.display().to_string(), "<root>")
}
