//! The interactive SQL session: `snow sql` with no query source (`repl.py` of `snow` 3.34.0).
//! It runs on the connector session whatever the authenticator (ADR 0005, Decision 1), so
//! `USE`, `SET` and temporary objects last between inputs.

use super::Context;
use super::connection::{resolve_for_sign_in, script_options};
use super::sql::{Compiler, Interactive, OutputStart, Printer, Sink, SqlArgs, console_on};
use crate::config::ConfigSource;
use crate::connection::ConnectionConfig;
use crate::error::{Error, ErrorKind, Result};
use crate::repl::history::History;
use crate::repl::prompt::{self, ColorDepth, PromptValues};
use crate::repl::terminal::{PlainReader, TerminalReader};
use crate::repl::{LineReader, ReadLine};
use crate::script::{Input, py_strip};
use crate::sql::{ClientOptions, Executor, RunNeeds, ScriptOptions};
use std::io::{BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

const BANNER: [&str; 2] = [
    "Welcome to Snowflake-CLI REPL",
    "Type 'exit' or 'quit' to leave",
];
const LEAVING: &str = "\nLeaving REPL, bye ...";
/// The first statement, run before the first prompt so a broken connection fails at once.
const FIRST_STATEMENT: &str = "select current_version();";

/// What the session takes from the command line and the config.
pub(super) struct ReplOptions {
    pub prompt_format: Option<String>,
    pub no_prompt_exit_repl: bool,
    /// `repl_history` next to the config file.
    pub history: Option<PathBuf>,
}

/// Starts the session: banner, sign-in, then the loop until the user leaves.
pub(super) fn run(
    args: &SqlArgs,
    source: &ConfigSource,
    compiler: &Compiler,
    start: OutputStart,
    options: ReplOptions,
    stdin: &mut dyn Read,
    ctx: &mut Context<'_>,
) -> Result<()> {
    let history = History::load(options.history.clone());
    let mut input;
    let mut prompts = std::io::stdout();
    let mut reader: Box<dyn LineReader + '_>;
    if ctx.stdin_is_tty {
        reader = Box::new(TerminalReader::new(history.entries()).map_err(read_error)?);
    } else {
        // prompt_toolkit's warning, when the session starts.
        let _ = ctx
            .stderr
            .write_all(b"Warning: Input is not a terminal (fd=0).\n");
        input = BufReader::new(stdin);
        reader = Box::new(PlainReader::new(&mut input, &mut prompts));
    }
    let width = reader.width().or(ctx.terminal_width);
    if console_on(start.format, args.global.silent) {
        let banner = panel(&BANNER, width.unwrap_or(80));
        let _ = ctx.stdout.write_all(banner.as_bytes());
        let _ = ctx.stdout.flush();
    }
    let conn = resolve_for_sign_in(source, &args.connection, ctx)?;
    let script = ScriptOptions {
        autocommit_off: false,
        ..script_options(&conn)?
    };
    let client_options = ClientOptions {
        decimal_precision: ctx.decimal_precision,
        ..ClientOptions::from_env(&ctx.env)?
    };
    let transfer =
        crate::transfer::TransferOptions::new(ctx.env.get_non_empty("HOME").map(PathBuf::from));
    let executor = super::connection::connect(
        &conn,
        RunNeeds { session: true },
        client_options,
        &script,
        transfer,
        ctx,
    )?;
    let session = Setup {
        executor: &executor,
        conn: &conn,
        compiler,
        options,
        script,
        history,
        width,
    };
    let outcome = session.start(args.global.silent, start, reader.as_mut(), ctx);
    let _ = executor.close();
    outcome
}

/// Everything a session needs once signed in.
struct Setup<'a> {
    executor: &'a Executor,
    conn: &'a ConnectionConfig,
    compiler: &'a Compiler,
    options: ReplOptions,
    script: ScriptOptions,
    history: History,
    width: Option<usize>,
}

impl Setup<'_> {
    fn start(
        self,
        silent: bool,
        start: OutputStart,
        reader: &mut dyn LineReader,
        ctx: &mut Context<'_>,
    ) -> Result<()> {
        let session = self
            .executor
            .session()
            .ok_or_else(|| Error::new(ErrorKind::Client, "The session did not start."))?;
        session.query(FIRST_STATEMENT)?;
        let interrupt = Arc::new(AtomicBool::new(false));
        // Ctrl-C while a statement runs cancels it; at the prompt the terminal is raw, so it
        // is a key there. A handler that cannot be installed only loses the cancellation.
        let handler = signal_hook::flag::register(signal_hook::consts::SIGINT, interrupt.clone());
        session.set_interrupt(interrupt.clone());
        let mut repl = Repl {
            executor: self.executor,
            compiler: self.compiler,
            printer: Printer {
                verbose_echo: false,
                repl: true,
                multi: true,
                script: self.script,
                interrupt: Some(interrupt.clone()),
            },
            options: self.options,
            history: self.history,
            next_input: None,
            values: base_values(self.conn),
            depth: ColorDepth::from_env(&ctx.env),
            editor: ctx.env.get("EDITOR").map(String::from),
            run_editor: &run_editor,
            interrupt,
        };
        let mut out = Sink::new(&mut *ctx.stdout, start, silent, ctx.env.clone(), self.width);
        out.table_trailer = true;
        let outcome = repl.run(reader, &mut out);
        let _ = out.flush();
        if let Ok(id) = handler {
            signal_hook::low_level::unregister(id);
        }
        outcome
    }
}

fn read_error(e: std::io::Error) -> Error {
    Error::new(ErrorKind::Client, "Could not read the input.").with_source(e)
}

/// The placeholders that do not change during the session.
fn base_values(conn: &ConnectionConfig) -> PromptValues {
    let host = crate::sql::client::base_url(conn).ok().map(|url| {
        let rest = url.split_once("://").map_or(url.as_str(), |(_, r)| r);
        rest.split([':', '/']).next().unwrap_or(rest).to_string()
    });
    PromptValues {
        user: conn.user.clone(),
        host,
        account: conn
            .account
            .as_deref()
            .map(|a| crate::session::account_name(a).to_string()),
        connection: conn.name.clone(),
        ..PromptValues::default()
    }
}

/// rich's `Panel` around `lines`, `width` wide.
fn panel(lines: &[&str], width: usize) -> String {
    let inner = width.saturating_sub(2);
    let mut text = format!("╭{}╮\n", "─".repeat(inner));
    for line in lines {
        let pad = inner.saturating_sub(2 + unicode_width::UnicodeWidthStr::width(*line));
        text.push_str(&format!("│ {line}{} │\n", " ".repeat(pad)));
    }
    text.push_str(&format!("╰{}╯\n", "─".repeat(inner)));
    text
}

/// `click.edit(text, editor)`: `text` in a temporary `.sql` file, the editor run on it through
/// the shell, and the file read back.
fn run_editor(editor: &str, text: &str) -> Result<String> {
    edit_in(&std::env::temp_dir(), editor, text)
}

/// [`run_editor`] with the buffer created in `dir`. The buffer is created exclusively and
/// owner-only, so a file or link planted under its name fails the edit instead of being followed.
fn edit_in(dir: &std::path::Path, editor: &str, text: &str) -> Result<String> {
    let mut content = text.to_string();
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    let path = dir.join(format!("editor-{}.sql", uuid::Uuid::new_v4()));
    let failed = |detail: String| Error::new(ErrorKind::Client, format!("{editor}: {detail}"));
    crate::fsutil::private_options()
        .write(true)
        .create_new(true)
        .open(&path)
        .and_then(|mut file| std::io::Write::write_all(&mut file, content.as_bytes()))
        .map_err(|e| failed(format!("Editing failed: {e}")))?;
    let command = format!("{editor} \"{}\"", path.display());
    #[cfg(unix)]
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(&command)
        .status();
    #[cfg(not(unix))]
    let status = std::process::Command::new("cmd")
        .arg("/C")
        .arg(&command)
        .status();
    let edited = match status {
        Ok(status) if status.success() => {
            std::fs::read_to_string(&path).map_err(|e| failed(format!("Editing failed: {e}")))
        }
        Ok(_) => Err(failed("Editing failed".into())),
        Err(e) => Err(failed(format!("Editing failed: {e}"))),
    };
    let _ = std::fs::remove_file(&path);
    edited
}

type EditorFn = dyn Fn(&str, &str) -> Result<String>;

/// The state of one session.
struct Repl<'a> {
    executor: &'a Executor,
    compiler: &'a Compiler,
    printer: Printer,
    options: ReplOptions,
    history: History,
    /// The text `!edit` queued for the next prompt.
    next_input: Option<String>,
    values: PromptValues,
    depth: ColorDepth,
    /// `$EDITOR`.
    editor: Option<String>,
    run_editor: &'a EditorFn,
    interrupt: Arc<AtomicBool>,
}

/// What one input asks for.
enum Next {
    Continue,
    Leave,
}

impl Repl<'_> {
    /// `_repl_loop`, then the goodbye line.
    fn run(&mut self, reader: &mut dyn LineReader, out: &mut Sink<'_>) -> Result<()> {
        loop {
            out.flush().map_err(read_error)?;
            if let Some(width) = reader.width() {
                out.set_terminal_width(Some(width));
            }
            let prompt = self.prompt();
            let initial = self.next_input.take().unwrap_or_default();
            let next = match reader.read_line(&prompt, &initial).map_err(read_error)? {
                ReadLine::Interrupted => Next::Continue,
                ReadLine::Eof => self.ask_to_leave(reader)?,
                ReadLine::Line(text) => {
                    if self.history.append(&text) {
                        reader.add_history(&text);
                    }
                    let input = py_strip(&text);
                    if input.is_empty() {
                        Next::Continue
                    } else if matches!(input.to_lowercase().as_str(), "exit" | "quit") {
                        self.ask_to_leave(reader)?
                    } else {
                        self.submit(input, out)?;
                        Next::Continue
                    }
                }
            };
            if let Next::Leave = next {
                out.console(LEAVING)?;
                return Ok(());
            }
        }
    }

    fn ask_to_leave(&self, reader: &mut dyn LineReader) -> Result<Next> {
        if self.options.no_prompt_exit_repl
            || reader
                .ask_yes_no("Do you want to leave?")
                .map_err(read_error)?
        {
            Ok(Next::Leave)
        } else {
            Ok(Next::Continue)
        }
    }

    fn prompt(&self) -> prompt::Prompt {
        if self.options.prompt_format.is_none() {
            return prompt::Prompt::plain(prompt::DEFAULT_PROMPT);
        }
        let mut values = self.values.clone();
        if let Some(session) = self.executor.session() {
            let context = session.context();
            values.database = context.database;
            values.schema = context.schema;
            values.warehouse = context.warehouse;
            values.role = context.role;
        }
        prompt::render(self.options.prompt_format.as_deref(), &values, self.depth)
    }

    /// Runs one input and prints its results; a failure is reported and the session goes on.
    fn submit(&mut self, text: &str, out: &mut Sink<'_>) -> Result<()> {
        self.interrupt.store(false, Ordering::SeqCst);
        let started = Instant::now();
        let mut notices = Vec::new();
        let input = Input {
            text: text.to_string(),
            file: None,
        };
        let compiled = self.compiler.compile(&[input], &mut notices);
        for notice in &notices {
            out.console(&crate::render::sanitize::sanitize_for_terminal(notice))?;
        }
        let statements = match compiled {
            Ok(statements) => statements,
            Err(err) => return out.console(&format!("\nError occurred: {}", err.message())),
        };
        let expected = statements.iter().filter(|s| s.command.is_none()).count();
        let mut hooks = Hooks {
            history: &self.history,
            next_input: &mut self.next_input,
            editor: self.editor.as_deref(),
            run_editor: self.run_editor,
        };
        let outcome = self
            .printer
            .print(self.executor, &statements, out, &mut hooks);
        let _ = out.flush();
        if self.interrupt.swap(false, Ordering::SeqCst) {
            // Ctrl-C: the statement is cancelled; nothing more is printed.
            return Ok(());
        }
        if let Err(err) = outcome {
            out.console(&format!("\nError occurred: {}", err.message()))?;
        }
        if expected > 0 {
            elapsed(started, out)?;
        }
        Ok(())
    }
}

/// `_print_sql_elapsed`.
fn elapsed(started: Instant, out: &mut Sink<'_>) -> Result<()> {
    if !out.timing || out.format.is_json() || out.format == crate::output::format::OutputFormat::Csv
    {
        return Ok(());
    }
    let line = format!("Time Elapsed: {:.3}s", started.elapsed().as_secs_f64());
    if !out.quiet {
        out.console(&line)?;
    }
    if out.timing_in_output_file && out.has_spool() {
        out.spool_only(&format!("{line}\n"))?;
    }
    Ok(())
}

/// The session's side of the `!` commands.
struct Hooks<'h> {
    history: &'h History,
    next_input: &'h mut Option<String>,
    editor: Option<&'h str>,
    run_editor: &'h EditorFn,
}

impl Interactive for Hooks<'_> {
    fn edit(&mut self, sql: &str, out: &mut Sink<'_>) -> Result<()> {
        let editor = self.editor.filter(|e| !e.is_empty()).ok_or_else(|| {
            Error::new(
                ErrorKind::Client,
                "No editor is set. Please set the EDITOR environment variable.",
            )
        })?;
        let content = if sql.is_empty() {
            self.history
                .entries()
                .iter()
                .rev()
                .map(|e| py_strip(e))
                .find(|e| !e.is_empty() && !e.starts_with('!'))
                .unwrap_or_default()
                .to_string()
        } else {
            sql.to_string()
        };
        let edited = (self.run_editor)(editor, &content)?;
        let edited = py_strip(&edited);
        if edited.is_empty() {
            out.console("Editor closed with no content.")
        } else {
            *self.next_input = Some(edited.to_string());
            out.console(
                "✓ Edited SQL loaded into prompt. Modify as needed or press Enter to execute.",
            )
        }
    }
}

// Every test in it runs a POSIX shell editor, so there is nothing to compile on Windows.
#[cfg(all(test, unix))]
mod tests;
