//! The user-facing command groups.

pub mod connection;
mod repl;
pub mod sql;

use crate::env::Env;
use crate::error::{Error, ErrorKind, Result};
use std::io::Write;
use std::path::PathBuf;

/// Asks the user for a value on the terminal. A seam so interactive paths are testable.
pub trait Prompter {
    /// Shows `label` and returns the line typed; `hidden` turns the echo off.
    fn prompt(&mut self, label: &str, hidden: bool) -> Result<String>;
}

/// Prompts on the real terminal.
pub struct TerminalPrompter;

impl Prompter for TerminalPrompter {
    fn prompt(&mut self, label: &str, hidden: bool) -> Result<String> {
        let read = if hidden {
            // No echo: needs the real terminal, so it has no unit test.
            rpassword::prompt_password(label)
        } else {
            read_line(label, &mut std::io::stdin().lock(), &mut std::io::stdout())
        };
        read.map_err(|e| Error::new(ErrorKind::Aborted, "Aborted.").with_source(e))
    }
}

/// [`Prompter`] and standard error, as a sign-in's [`crate::session::Prompt`].
pub(crate) struct PromptBridge<'a> {
    prompter: std::cell::RefCell<&'a mut dyn Prompter>,
    stderr: std::cell::RefCell<&'a mut dyn Write>,
}

impl<'a> PromptBridge<'a> {
    pub fn new(prompter: &'a mut dyn Prompter, stderr: &'a mut dyn Write) -> Self {
        Self {
            prompter: std::cell::RefCell::new(prompter),
            stderr: std::cell::RefCell::new(stderr),
        }
    }
}

impl crate::session::Prompt for PromptBridge<'_> {
    fn prompt(&self, label: &str, hidden: bool) -> Result<String> {
        self.prompter.borrow_mut().prompt(label, hidden)
    }

    fn say(&self, line: &str) {
        // Instructions are best effort, like snow's console.
        let _ = writeln!(self.stderr.borrow_mut(), "{line}");
    }
}

/// Writes `label` to `out`, then reads one line from `input` without its line ending.
fn read_line(
    label: &str,
    input: &mut dyn std::io::BufRead,
    out: &mut dyn Write,
) -> std::io::Result<String> {
    out.write_all(label.as_bytes())?;
    out.flush()?;
    let mut line = String::new();
    // EOF (Ctrl-D) aborts, as in snow, instead of answering with an empty line.
    if input.read_line(&mut line)? == 0 {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Everything a command needs from the process, injectable for tests.
pub struct Context<'a> {
    pub env: Env,
    /// `--config-file`.
    pub config_file: Option<PathBuf>,
    /// `--enhanced-exit-codes` (or its variable), once resolved.
    pub enhanced_exit_codes: bool,
    /// `--decimal-precision` (flag, variable or config), once resolved.
    pub decimal_precision: Option<usize>,
    pub stdin_is_tty: bool,
    pub prompter: &'a mut dyn Prompter,
    /// Standard output: snow prints its warnings here, ahead of the result.
    pub stdout: &'a mut dyn Write,
    /// Standard error: what must not mix with the results (warnings, the browser sign-ins'
    /// instructions).
    pub stderr: &'a mut dyn Write,
    pub terminal_width: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Prompt;

    struct Answer(&'static str);
    impl Prompter for Answer {
        fn prompt(&mut self, label: &str, hidden: bool) -> Result<String> {
            assert_eq!((label, hidden), ("Code: ", false));
            Ok(self.0.to_string())
        }
    }

    #[test]
    fn the_bridge_prompts_and_writes_instructions_to_stderr() {
        let mut answer = Answer("42");
        let mut err = Vec::new();
        {
            let bridge = PromptBridge::new(&mut answer, &mut err);
            assert_eq!(bridge.prompt("Code: ", false).unwrap(), "42");
            bridge.say("Open the browser.");
        }
        assert_eq!(String::from_utf8(err).unwrap(), "Open the browser.\n");
    }

    #[test]
    fn read_line_shows_the_label_and_strips_the_line_ending() {
        let mut out = Vec::new();
        let mut input = "first\r\nsecond\n".as_bytes();
        assert_eq!(
            read_line("Enter x: ", &mut input, &mut out).unwrap(),
            "first"
        );
        assert_eq!(
            read_line("Enter y: ", &mut input, &mut out).unwrap(),
            "second"
        );
        assert_eq!(
            read_line("Enter z: ", &mut input, &mut out)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::UnexpectedEof,
            "EOF is an error, not an empty answer"
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "Enter x: Enter y: Enter z: "
        );
    }

    #[test]
    fn read_line_keeps_an_empty_line_and_the_spaces_of_an_answer() {
        let mut out = Vec::new();
        let mut input = "
  pad  
"
        .as_bytes();
        assert_eq!(read_line("a: ", &mut input, &mut out).unwrap(), "");
        assert_eq!(read_line("b: ", &mut input, &mut out).unwrap(), "  pad  ");
    }
}
