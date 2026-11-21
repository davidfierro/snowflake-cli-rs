//! Error output (ADR 0001, Decision 7): snow's `Error` panel on stderr, no stack traces.

use crate::error::{Error, ErrorKind};
use crate::render::sanitize::sanitize_for_terminal;
use std::io::Write;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Total panel width, as snow's (rich's) default for a non-terminal console.
const PANEL_WIDTH: usize = 80;
/// Text width inside `│ ` and ` │`.
const TEXT_WIDTH: usize = PANEL_WIDTH - 4;

/// Prints `err` to `stderr` as snow does; with `debug`, adds the `source()` chain (no backtrace).
pub fn report_error(err: &Error, debug: bool, stderr: &mut dyn Write) {
    // snow's `typer.Abort`: a bare line, no panel.
    let mut text = match err.usage() {
        Some(command) => {
            format!(
                "Usage: snow-rs {command} [OPTIONS]\nTry 'snow-rs {command} --help' for help.\n"
            )
        }
        None => String::new(),
    };
    if err.kind() == ErrorKind::Aborted {
        text.push_str(&format!("{}\n", err.message()));
    } else if err.kind() == ErrorKind::Unexpected {
        // Already printed on stdout by the command.
    } else {
        text.push_str(&panel(err.message()));
    }
    if debug {
        let mut source = std::error::Error::source(err);
        while let Some(cause) = source {
            text.push_str(&format!("Caused by: {}\n", clean(&cause.to_string())));
            source = cause.source();
        }
    }
    // Nothing useful can be done if stderr itself is gone.
    let _ = stderr
        .write_all(text.as_bytes())
        .and_then(|()| stderr.flush());
}

/// The line snow prints after an error panel in TABLE and PLAIN output (not after a usage error
/// or an abort).
pub const FEEDBACK: &str = "To send feedback about Snowflake CLI: snow feedback\n";

/// Whether [`FEEDBACK`] follows the panel of `err` in `format`.
pub fn wants_feedback(err: &Error, format: crate::output::format::OutputFormat) -> bool {
    use crate::output::format::OutputFormat;
    !matches!(err.kind(), ErrorKind::Usage | ErrorKind::Aborted)
        && err.has_feedback()
        && matches!(format, OutputFormat::Table | OutputFormat::Plain)
}

/// ANSI escapes removed and control characters (other than newline) replaced by spaces, so a
/// server message cannot drive the terminal or break the panel.
fn clean(text: &str) -> String {
    sanitize_for_terminal(text)
        .chars()
        .map(|c| if c.is_control() && c != '\n' { ' ' } else { c })
        .collect()
}

fn panel(message: &str) -> String {
    let title = "╭─ Error ";
    let mut out = format!("{title}{}╮\n", "─".repeat(PANEL_WIDTH - title.width() - 1));
    for line in wrap(&clean(message)) {
        out.push_str(&format!(
            "│ {line}{} │\n",
            " ".repeat(TEXT_WIDTH - line.width())
        ));
    }
    out.push_str(&format!("╰{}╯\n", "─".repeat(PANEL_WIDTH - 2)));
    out
}

/// Word-wraps `text` to [`TEXT_WIDTH`] columns; words longer than a line are folded.
fn wrap(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    for paragraph in text.split('\n') {
        let mut line = String::new();
        for word in paragraph.split(' ').filter(|w| !w.is_empty()) {
            let needed = if line.is_empty() {
                word.width()
            } else {
                line.width() + 1 + word.width()
            };
            if needed <= TEXT_WIDTH {
                if !line.is_empty() {
                    line.push(' ');
                }
                line.push_str(word);
                continue;
            }
            if !line.is_empty() {
                lines.push(std::mem::take(&mut line));
            }
            for c in word.chars() {
                if line.width() + c.width().unwrap_or(0) > TEXT_WIDTH {
                    lines.push(std::mem::take(&mut line));
                }
                line.push(c);
            }
        }
        lines.push(line);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reported(err: &Error, debug: bool) -> String {
        let mut out = Vec::new();
        report_error(err, debug, &mut out);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn an_abort_is_a_bare_line_as_in_snow() {
        let err = Error::new(ErrorKind::Aborted, "Aborted.");
        assert_eq!(reported(&err, false), "Aborted.\n");
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn usage_errors_start_with_the_usage_lines() {
        let err = Error::new(ErrorKind::Usage, "Bad.").with_usage("sql");
        assert!(reported(&err, false).starts_with(
            "Usage: snow-rs sql [OPTIONS]\nTry 'snow-rs sql --help' for help.\n╭─ Error"
        ));
    }

    #[test]
    fn feedback_follows_non_usage_errors_in_table_and_plain() {
        use crate::output::format::OutputFormat;
        let sql = Error::new(ErrorKind::Sql, "x");
        assert!(wants_feedback(&sql, OutputFormat::Table));
        assert!(wants_feedback(&sql, OutputFormat::Plain));
        assert!(!wants_feedback(&sql, OutputFormat::Json));
        assert!(!wants_feedback(&sql, OutputFormat::Csv));
        assert!(!wants_feedback(
            &Error::new(ErrorKind::Usage, "x"),
            OutputFormat::Table
        ));
        assert!(!wants_feedback(
            &Error::new(ErrorKind::Aborted, "x"),
            OutputFormat::Table
        ));
    }

    #[test]
    fn short_message_matches_snow_panel() {
        let err = Error::new(ErrorKind::Client, "Connection nope is not configured");
        assert_eq!(
            reported(&err, false),
            "\
╭─ Error ──────────────────────────────────────────────────────────────────────╮
│ Connection nope is not configured                                            │
╰──────────────────────────────────────────────────────────────────────────────╯
"
        );
    }

    /// Captured from snow 3.34.0 (`snow sql -x -q "SELEC 1"`).
    #[test]
    fn long_message_wraps_like_snow() {
        let err = Error::new(
            ErrorKind::Sql,
            "001003 (42000): 01c88b7d-0002-713f-0000-0002fee66355: SQL compilation error:\nsyntax error line 1 at position 0 unexpected 'SELEC'.",
        );
        assert_eq!(
            reported(&err, false),
            "\
╭─ Error ──────────────────────────────────────────────────────────────────────╮
│ 001003 (42000): 01c88b7d-0002-713f-0000-0002fee66355: SQL compilation error: │
│ syntax error line 1 at position 0 unexpected 'SELEC'.                        │
╰──────────────────────────────────────────────────────────────────────────────╯
"
        );
    }

    #[test]
    fn long_words_are_folded_and_lines_wrapped() {
        let lines = wrap(&format!("{} short {}", "x".repeat(80), "word ".repeat(20)));
        assert_eq!(lines[0], "x".repeat(76));
        assert!(lines[1].starts_with("xxxx short word"));
        assert!(lines.iter().all(|l| l.width() <= TEXT_WIDTH));
        assert_eq!(wrap(""), vec![String::new()]);
    }

    #[test]
    fn debug_adds_the_cause_chain_without_backtrace() {
        let io = std::io::Error::other("disk on fire");
        let err = Error::new(ErrorKind::Client, "Failed").with_source(io);
        let plain = reported(&err, false);
        assert!(!plain.contains("Caused by"));
        let debug = reported(&err, true);
        assert!(debug.ends_with("Caused by: disk on fire\n"));
        assert!(!debug.contains("backtrace"));
    }

    #[test]
    fn escapes_and_controls_are_removed() {
        let err = Error::new(ErrorKind::Sql, "bad\x1b[31m red\rline");
        let out = reported(&err, false);
        assert!(out.contains("│ bad red line "));
        assert!(!out.contains('\x1b'));
    }
}
