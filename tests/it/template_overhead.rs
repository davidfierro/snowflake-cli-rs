//! Templating overhead (ADR 0006): `compile` on a large script with templating off (`NONE`), with
//! the default syntaxes on text without template markers, and with a marker in every statement.
//! A measurement, not a check: `cargo test --release --test it template_overhead -- --ignored
//! --nocapture` prints the table pasted into the PR.

use snowflake_cli_rs::env::Env;
use snowflake_cli_rs::project::ProjectSource;
use snowflake_cli_rs::script::template::{Syntaxes, Templater, Variables};
use snowflake_cli_rs::script::{CompileOptions, compile};
use std::time::{Duration, Instant};

const STATEMENTS: usize = 20_000;

fn script(marker: bool) -> String {
    (0..STATEMENTS)
        .map(|i| {
            let value = if marker {
                "<% n %>".to_string()
            } else {
                i.to_string()
            };
            format!("SELECT {value} AS n, 'text & more' AS s -- comment {i}\n;\n")
        })
        .collect()
}

fn median(syntaxes: Syntaxes, text: &str) -> Duration {
    let variables: Variables = [("n".to_string(), "1".to_string())].into();
    let project = ProjectSource::new(None, Variables::new(), Env::default());
    let mut times: Vec<Duration> = (0..7)
        .map(|_| {
            let templater = Templater::new(&variables, syntaxes, &project);
            let start = Instant::now();
            let statements = compile(
                &[text.to_string()],
                &CompileOptions::default(),
                &templater,
                &mut Vec::new(),
            )
            .unwrap();
            let elapsed = start.elapsed();
            assert_eq!(statements.len(), STATEMENTS);
            elapsed
        })
        .collect();
    times.sort();
    times[times.len() / 2]
}

#[test]
#[ignore = "measurement; run by hand with --release"]
fn templating_overhead() {
    let plain = script(false);
    let marked = script(true);
    let none = Syntaxes {
        legacy: false,
        standard: false,
        jinja: false,
    };
    let jinja = Syntaxes {
        legacy: false,
        standard: false,
        jinja: true,
    };
    let rows = [
        ("NONE, no markers", median(none, &plain)),
        (
            "default (LEGACY+STANDARD), no markers",
            median(Syntaxes::default(), &plain),
        ),
        (
            "default, `<% n %>` in every statement",
            median(Syntaxes::default(), &marked),
        ),
        ("JINJA, no markers", median(jinja, &plain)),
    ];
    println!(
        "\n{STATEMENTS} statements ({} KiB), median of 7:\n\n| Templating | compile |\n|---|---|",
        plain.len() / 1024
    );
    for (name, time) in rows {
        println!("| {name} | {:.1} ms |", time.as_secs_f64() * 1000.0);
    }
}
