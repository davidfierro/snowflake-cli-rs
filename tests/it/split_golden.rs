//! Statement splitter goldens (ADR 0004, Decision 7): the Rust port of `split_statements` must
//! yield what the pinned connector yields, for both `remove_comments` values.
//! Capture: `scripts/capture-split-goldens.sh` (no network).

use snowflake_cli_rs::script::split::split_statements;
use std::path::PathBuf;

#[test]
fn splitter_matches_the_connector() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/split");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| {
            let name = e.unwrap().file_name().into_string().unwrap();
            name.strip_suffix(".json").map(String::from)
        })
        .collect();
    names.sort();
    assert!(names.len() >= 15, "splitter cases missing: {names:?}");
    let mut failures = Vec::new();
    for name in &names {
        let record: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join(format!("{name}.json"))).unwrap(),
        )
        .unwrap();
        let text = record["text"].as_str().unwrap();
        for (key, remove) in [("remove_comments", true), ("keep_comments", false)] {
            let expected: Vec<(String, Option<bool>)> = record[key]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| (p[0].as_str().unwrap().to_string(), p[1].as_bool()))
                .collect();
            let actual: Vec<(String, Option<bool>)> = split_statements(text, remove)
                .into_iter()
                .map(|p| (p.text, p.put_or_get))
                .collect();
            if actual != expected {
                failures.push(format!(
                    "{name} ({key}):\n  connector {expected:?}\n  ours      {actual:?}"
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
