//! The interactive-session history: `repl_history` next to the config file, in
//! prompt_toolkit's `FileHistory` format so `snow` and this CLI share it.
//!
//! Each entry is a `# <timestamp>` line followed by its lines, each prefixed with `+`.

use std::io::Write;
use std::path::PathBuf;

/// The history entries, oldest first, and the file new ones are appended to.
#[derive(Debug, Clone)]
pub struct History {
    path: Option<PathBuf>,
    entries: Vec<String>,
}

impl History {
    /// Reads `path`, if it exists. A file that cannot be read is an empty history.
    pub fn load(path: Option<PathBuf>) -> Self {
        let entries = path
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .map(|bytes| parse(&String::from_utf8_lossy(&bytes)))
            .unwrap_or_default();
        Self { path, entries }
    }

    pub fn entries(&self) -> &[String] {
        &self.entries
    }

    /// Adds a submitted input, unless it is empty or the same as the last entry
    /// (prompt_toolkit's `Buffer.append_to_history`). Returns whether it was added. A write
    /// failure does not stop the session.
    pub fn append(&mut self, text: &str) -> bool {
        if text.is_empty() || self.entries.last().is_some_and(|last| last == text) {
            return false;
        }
        self.entries.push(text.to_string());
        if let Some(path) = &self.path {
            let stamp = jiff::Zoned::now().strftime("%Y-%m-%d %H:%M:%S%.6f");
            let mut record = format!("\n# {stamp}\n");
            for line in text.split('\n') {
                record.push('+');
                record.push_str(line);
                record.push('\n');
            }
            let written = crate::fsutil::private_options()
                .create(true)
                .append(true)
                .open(path)
                .and_then(|mut f| f.write_all(record.as_bytes()));
            if let Err(e) = written {
                log::debug!("could not write the history file: {e}");
            }
        }
        true
    }
}

/// `FileHistory.load_history_strings`, oldest first.
fn parse(text: &str) -> Vec<String> {
    let mut entries = Vec::new();
    let mut lines: Vec<&str> = Vec::new();
    let mut flush = |lines: &mut Vec<&str>| {
        if !lines.is_empty() {
            // Each line kept its line end; the last character is dropped (Python's `[:-1]`,
            // so a truncated last line loses a character, and an empty one stays empty).
            let mut joined: String = lines.concat();
            joined.pop();
            entries.push(joined);
            lines.clear();
        }
    };
    for line in text.split_inclusive('\n') {
        match line.strip_prefix('+') {
            Some(rest) => lines.push(rest),
            None => flush(&mut lines),
        }
    }
    flush(&mut lines);
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_prompt_toolkit_files() {
        let text = "\n# 2024-01-01 10:00:00.000001\n+select 1;\n\n# x\n+select\n+  2;\n";
        assert_eq!(parse(text), vec!["select 1;", "select\n  2;"]);
        assert_eq!(parse("+no end"), vec!["no en"], "as prompt_toolkit");
        assert!(parse("").is_empty());
        // A truncated file: a bare `+`, or a last line ending in a multi-byte character.
        assert_eq!(parse("#V2\n+select 1;\n+"), vec!["select 1;"]);
        assert_eq!(parse("+caf\u{e9}"), vec!["caf"]);
        assert_eq!(parse("+\u{e9}\u{e9}"), vec!["\u{e9}"]);
    }

    #[test]
    fn appends_in_the_same_format_and_skips_repeats() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("repl_history");
        let mut history = History::load(Some(path.clone()));
        assert!(history.entries().is_empty());
        assert!(history.append("select\n1;"));
        assert!(!history.append("select\n1;"));
        assert!(!history.append(""));
        assert!(history.append("exit"));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("\n# "), "{text}");
        assert!(text.contains("\n+select\n+1;\n\n# "), "{text}");
        assert!(text.ends_with("\n+exit\n"), "{text}");
        assert_eq!(History::load(Some(path)).entries(), ["select\n1;", "exit"]);
    }

    #[test]
    fn no_file_means_memory_only() {
        let mut history = History::load(None);
        assert!(history.append("a"));
        assert_eq!(history.entries(), ["a"]);
        let dir = tempfile::tempdir().unwrap();
        let mut unwritable = History::load(Some(dir.path().join("missing/h")));
        assert!(unwritable.append("a"), "kept in memory");
    }

    #[cfg(unix)]
    #[test]
    fn a_new_history_file_is_owner_only_and_an_existing_one_keeps_its_mode() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("repl_history");
        History::load(Some(path.clone())).append("a");
        assert_eq!(mode(&path), 0o600);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        History::load(Some(path.clone())).append("b");
        assert_eq!(mode(&path), 0o644);
    }
}
