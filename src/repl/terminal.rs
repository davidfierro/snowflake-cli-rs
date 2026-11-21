//! The line readers of the interactive session: [`TerminalReader`] edits on the terminal
//! (rustyline: multi-line input, history, Ctrl-C/Ctrl-D as `snow`'s prompt_toolkit session),
//! [`PlainReader`] reads lines from a non-terminal input.

use super::prompt::Prompt;
use super::{LineReader, ReadLine, submits};
use rustyline::error::ReadlineError;
use rustyline::history::{DefaultHistory, History as _};
use rustyline::{
    Cmd, ConditionalEventHandler, Config, Editor, Event, EventContext, EventHandler, KeyCode,
    KeyEvent, Modifiers, RepeatCount,
};
use std::io::{self, BufRead, Write};
use std::sync::{Arc, Mutex};

/// The Enter key of the session: nothing on an empty input, submit when [`submits`], a new
/// line otherwise. Ctrl-J always adds a line.
struct EnterKey;

impl ConditionalEventHandler for EnterKey {
    fn handle(&self, _: &Event, _: RepeatCount, _: bool, ctx: &EventContext) -> Option<Cmd> {
        Some(enter_command(ctx.line()))
    }
}

fn enter_command(line: &str) -> Cmd {
    if crate::script::py_strip(line).is_empty() {
        Cmd::Noop
    } else if submits(line) {
        Cmd::AcceptLine
    } else {
        Cmd::Newline
    }
}

/// The yes/no question's keys (`_setup_yn_key_bindings`): one key answers.
struct YesNoKeys(Arc<Mutex<Option<bool>>>);

impl ConditionalEventHandler for YesNoKeys {
    fn handle(&self, evt: &Event, _: RepeatCount, _: bool, _: &EventContext) -> Option<Cmd> {
        let answer = match evt {
            Event::KeySeq(keys) => keys.first().and_then(|k| yes_no_answer(*k)),
            _ => None,
        };
        match answer {
            Some(answer) => {
                *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(answer);
                Some(Cmd::AcceptLine)
            }
            None => Some(Cmd::Noop),
        }
    }
}

fn yes_no_answer(key: KeyEvent) -> Option<bool> {
    match key {
        KeyEvent(KeyCode::Enter, _) | KeyEvent(KeyCode::Char('y'), Modifiers::NONE) => Some(true),
        KeyEvent(KeyCode::Char('D'), Modifiers::CTRL) => Some(true),
        KeyEvent(KeyCode::Char('n'), Modifiers::NONE)
        | KeyEvent(KeyCode::Char('C'), Modifiers::CTRL) => Some(false),
        _ => None,
    }
}

/// Coloured prompts need a highlighter; everything else is rustyline's default.
struct PromptHelper;

impl rustyline::Helper for PromptHelper {}
impl rustyline::highlight::Highlighter for PromptHelper {}
impl rustyline::validate::Validator for PromptHelper {}
impl rustyline::hint::Hinter for PromptHelper {
    type Hint = String;
}
impl rustyline::completion::Completer for PromptHelper {
    type Candidate = String;
}

/// The session on the terminal.
pub struct TerminalReader {
    editor: Editor<PromptHelper, DefaultHistory>,
    question: Editor<(), DefaultHistory>,
    answer: Arc<Mutex<Option<bool>>>,
}

impl TerminalReader {
    /// `history`: the entries so far, oldest first.
    pub fn new(history: &[String]) -> io::Result<Self> {
        let config = Config::builder()
            .auto_add_history(false)
            .max_history_size(usize::MAX)
            .map_err(other)?
            .history_ignore_dups(false)
            .map_err(other)?
            .build();
        let mut editor = Editor::with_config(config.clone()).map_err(other)?;
        editor.set_helper(Some(PromptHelper));
        editor.bind_sequence(
            KeyEvent(KeyCode::Enter, Modifiers::NONE),
            EventHandler::Conditional(Box::new(EnterKey)),
        );
        editor.bind_sequence(KeyEvent::ctrl('J'), EventHandler::Simple(Cmd::Newline));
        for entry in history {
            editor.history_mut().add(entry).map_err(other)?;
        }
        let answer = Arc::new(Mutex::new(None));
        let mut question = Editor::with_config(config).map_err(other)?;
        question.bind_sequence(
            Event::Any,
            EventHandler::Conditional(Box::new(YesNoKeys(answer.clone()))),
        );
        Ok(Self {
            editor,
            question,
            answer,
        })
    }
}

fn other(e: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::other(e)
}

impl LineReader for TerminalReader {
    fn read_line(&mut self, prompt: &Prompt, initial: &str) -> io::Result<ReadLine> {
        let shown = (prompt.raw.as_str(), prompt.styled.as_str());
        match self.editor.readline_with_initial(&shown, (initial, "")) {
            Ok(line) => Ok(ReadLine::Line(line)),
            Err(ReadlineError::Interrupted) => Ok(ReadLine::Interrupted),
            Err(ReadlineError::Eof) => Ok(ReadLine::Eof),
            Err(e) => Err(other(e)),
        }
    }

    fn ask_yes_no(&mut self, question: &str) -> io::Result<bool> {
        *self.answer.lock().unwrap_or_else(|e| e.into_inner()) = None;
        let label = format!("{question} (y/n): ");
        match self.question.readline(label.as_str()) {
            Ok(_) | Err(ReadlineError::Eof) => {}
            // Ctrl-C answers no (`ask_yn`'s KeyboardInterrupt).
            Err(ReadlineError::Interrupted) => return Ok(false),
            Err(e) => return Err(other(e)),
        }
        Ok(self
            .answer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .unwrap_or(true))
    }

    fn add_history(&mut self, entry: &str) {
        // An in-memory history: adding cannot fail.
        let _ = self.editor.history_mut().add(entry);
    }

    fn width(&mut self) -> Option<usize> {
        self.editor
            .dimensions()
            .map(|(columns, _)| usize::from(columns))
            .filter(|c| *c > 0)
    }
}

/// The session on an input that is not a terminal: one input per line, the prompt written to
/// `out` before each.
pub struct PlainReader<'a> {
    input: &'a mut dyn BufRead,
    out: &'a mut dyn Write,
}

impl<'a> PlainReader<'a> {
    pub fn new(input: &'a mut dyn BufRead, out: &'a mut dyn Write) -> Self {
        Self { input, out }
    }

    fn line(&mut self, label: &str) -> io::Result<Option<String>> {
        self.out.write_all(label.as_bytes())?;
        self.out.flush()?;
        let mut line = String::new();
        if self.input.read_line(&mut line)? == 0 {
            // The prompt line ends, as on a terminal.
            self.out.write_all(b"\n")?;
            return Ok(None);
        }
        Ok(Some(line.trim_end_matches(['\r', '\n']).to_string()))
    }
}

impl LineReader for PlainReader<'_> {
    fn read_line(&mut self, prompt: &Prompt, initial: &str) -> io::Result<ReadLine> {
        let mut text = initial.to_string();
        let mut label = prompt.raw.clone();
        loop {
            let Some(line) = self.line(&label)? else {
                return Ok(if text.is_empty() {
                    ReadLine::Eof
                } else {
                    ReadLine::Line(text)
                });
            };
            if !text.is_empty() {
                text.push('\n');
            }
            text.push_str(&line);
            match enter_command(&text) {
                Cmd::AcceptLine => return Ok(ReadLine::Line(text)),
                // Enter on an empty input does nothing: the same prompt again.
                Cmd::Noop => text.clear(),
                _ => label = " ".repeat(prompt.raw.chars().count()),
            }
        }
    }

    fn ask_yes_no(&mut self, question: &str) -> io::Result<bool> {
        let Some(line) = self.line(&format!("{question} (y/n): "))? else {
            return Ok(true);
        };
        // The first `y` or `n` answers; Enter alone is yes.
        Ok(line.chars().find(|c| matches!(c, 'y' | 'n')) != Some('n'))
    }

    fn add_history(&mut self, _entry: &str) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enter_key() {
        assert_eq!(enter_command("  "), Cmd::Noop);
        assert_eq!(enter_command("select 1;"), Cmd::AcceptLine);
        assert_eq!(enter_command("select 1"), Cmd::Newline);
    }

    #[test]
    fn yes_no_keys() {
        assert_eq!(
            yes_no_answer(KeyEvent(KeyCode::Enter, Modifiers::NONE)),
            Some(true)
        );
        assert_eq!(yes_no_answer(KeyEvent::from('y')), Some(true));
        assert_eq!(yes_no_answer(KeyEvent::ctrl('D')), Some(true));
        assert_eq!(yes_no_answer(KeyEvent::from('n')), Some(false));
        assert_eq!(yes_no_answer(KeyEvent::ctrl('C')), Some(false));
        assert_eq!(yes_no_answer(KeyEvent::from('x')), None);
        assert_eq!(yes_no_answer(KeyEvent::from('Y')), None);
    }

    fn plain(input: &str) -> (Vec<ReadLine>, bool, String) {
        let mut bytes = input.as_bytes();
        let mut out = Vec::new();
        let mut reader = PlainReader::new(&mut bytes, &mut out);
        let prompt = Prompt::plain(" > ");
        let mut lines = Vec::new();
        loop {
            let line = reader.read_line(&prompt, "").unwrap();
            let end = line == ReadLine::Eof;
            lines.push(line);
            if end {
                break;
            }
        }
        let answer = reader.ask_yes_no("Leave?").unwrap();
        reader.add_history("x");
        (lines, answer, String::from_utf8(out).unwrap())
    }

    #[test]
    fn plain_reader_reads_multi_line_inputs() {
        let (lines, answer, out) = plain("select\n1;\n\nexit\nselect 2");
        assert_eq!(
            lines,
            vec![
                ReadLine::Line("select\n1;".into()),
                ReadLine::Line("exit".into()),
                ReadLine::Line("select 2".into()),
                ReadLine::Eof
            ]
        );
        assert!(answer, "EOF answers yes");
        assert_eq!(out, " >     >  >  >    \n > \nLeave? (y/n): \n");
    }

    #[test]
    fn plain_reader_answers() {
        let mut out = Vec::new();
        for (input, want) in [
            ("n\n", false),
            ("\n", true),
            ("xy\n", true),
            ("no\n", false),
        ] {
            let mut bytes = input.as_bytes();
            let mut reader = PlainReader::new(&mut bytes, &mut out);
            assert_eq!(reader.ask_yes_no("Q").unwrap(), want, "{input:?}");
        }
        let mut bytes = "!rehash\n".as_bytes();
        let mut reader = PlainReader::new(&mut bytes, &mut out);
        assert_eq!(
            reader.read_line(&Prompt::plain(" > "), "!edit").unwrap(),
            ReadLine::Line("!edit\n!rehash".into()),
            "the initial text is the start of the input"
        );
    }

    #[test]
    fn terminal_reader_builds_with_a_history() {
        // No terminal in unit tests: rustyline falls back, but building must work.
        let mut reader = TerminalReader::new(&["select 1;".into()]).unwrap();
        reader.add_history("select 2;");
        assert_eq!(reader.editor.history().len(), 2);
    }
}
