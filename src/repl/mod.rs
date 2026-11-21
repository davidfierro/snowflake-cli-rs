//! Pieces of the interactive SQL session (`snow sql` with no query source): the line reader,
//! the prompt and the history. The session loop itself is in `commands::repl`.

pub mod history;
pub mod prompt;
pub mod terminal;

use prompt::Prompt;
use std::io;

/// What reading one input gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadLine {
    /// A submitted input (possibly several lines).
    Line(String),
    /// Ctrl-C at the prompt.
    Interrupted,
    /// Ctrl-D on an empty input, or the end of the input.
    Eof,
}

/// Reads the inputs of the session: the seam between the loop and the terminal.
pub trait LineReader {
    /// Shows `prompt` with `initial` already typed (`!edit`), and reads one input: Enter submits
    /// it when it ends with `;`, is a `!` command or `exit`/`quit`, and adds a line otherwise.
    fn read_line(&mut self, prompt: &Prompt, initial: &str) -> io::Result<ReadLine>;
    /// A yes/no question: Enter, Ctrl-D or `y` answer yes; `n` or Ctrl-C answer no.
    fn ask_yes_no(&mut self, question: &str) -> io::Result<bool>;
    /// A new history entry, for the up arrow.
    fn add_history(&mut self, entry: &str);
    /// The width of the terminal, when there is one.
    fn width(&mut self) -> Option<usize> {
        None
    }
}

/// `snow`'s Enter key in the session (`_setup_key_bindings`): does `text` submit?
pub fn submits(text: &str) -> bool {
    let stripped = crate::script::py_strip(text);
    !stripped.is_empty()
        && (matches!(stripped.to_lowercase().as_str(), "exit" | "quit")
            || crate::script::command::detect(stripped).is_some()
            || stripped.ends_with(';'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enter_submits_like_snow() {
        assert!(submits("select 1;"));
        assert!(submits("select\n 1;  \n"));
        assert!(submits(" EXIT "));
        assert!(submits("quit"));
        assert!(submits("!set quiet=true"));
        assert!(submits("!rehash"));
        assert!(!submits("select 1"));
        assert!(!submits("exit now"));
        assert!(!submits("   "));
        assert!(!submits("!set a\nb"));
    }
}
