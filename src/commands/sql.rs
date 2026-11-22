//! `snow sql -q/-f/-i` (ADR 0004): statements from a query, files or stdin, run as one session,
//! printed as `snow` 3.34.0 prints them.

use super::Context;
use super::connection::{resolve_for_sign_in, script_options};
use crate::cli::{ConnectionOptions, GlobalOptions};
use crate::config::ConfigSource;
use crate::error::{Error, ErrorKind, Result};
use crate::output::format::OutputFormat;
use crate::output::result::{CommandResult, Field};
use crate::project::ProjectSource;
use crate::render::sanitize::sanitize_for_terminal;
use crate::render::{render_json_multi, render_stream};
use crate::repl::prompt;
use crate::script::command::{self, QueriesFilter, ReplCommand, SetOption};
use crate::script::template::{Syntaxes, Templater, Variables};
use crate::script::{
    CompileOptions, FsSources, Input, Statement, compile_inputs, py_repr, py_strip,
};
use crate::sql::{ClientOptions, Executor, RunNeeds, ScriptOptions};
use clap::{ArgMatches, Args, ValueEnum};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// `snow sql`.
#[derive(Debug, Args)]
#[command(
    about = "Executes SQL statements against Snowflake interactively or from a query, file, or standard input."
)]
pub struct SqlArgs {
    /// Query to execute.
    // A query may start with `-` (a `--` comment), as click accepts.
    #[arg(short = 'q', long, allow_hyphen_values = true)]
    pub query: Option<String>,
    /// File to execute.
    #[arg(
        short = 'f',
        long = "filename",
        value_name = "FILE",
        allow_hyphen_values = true
    )]
    pub files: Vec<PathBuf>,
    /// Read the query from standard input. Use it when piping input to this command.
    #[arg(short = 'i', long = "stdin")]
    pub stdin: bool,
    /// String in format of key=value. If provided the SQL content will be treated as template
    /// and rendered using provided data.
    #[arg(short = 'D', long = "variable", value_name = "TEXT")]
    pub variables: Vec<String>,
    /// Retains comments in queries passed to Snowflake
    #[arg(long)]
    pub retain_comments: bool,
    /// Connects with autocommit disabled. Wraps BEGIN/COMMIT around statements to execute them
    /// as a single transaction, ensuring all commands complete successfully or no change is
    /// applied.
    #[arg(long, overrides_with = "no_single_transaction")]
    pub single_transaction: bool,
    #[arg(long, overrides_with = "single_transaction", hide = true)]
    pub no_single_transaction: bool,
    /// Syntax used to resolve variables before passing queries to Snowflake.
    #[arg(
        long = "enable-templating",
        value_enum,
        ignore_case = true,
        default_values_t = [Templating::Legacy, Templating::Standard]
    )]
    pub enable_templating: Vec<Templating>,
    /// Restrict !source and !load to local files. When set, !source/!load directives that
    /// reference https:// URLs are rejected instead of being fetched. Use this flag in
    /// environments where SQL inputs should not trigger outbound network requests, or when
    /// running SQL files whose content should be reviewed locally before execution.
    /// [env var: SNOWFLAKE_CLI_SQL_LOCAL_ONLY | config: cli.sql_local_only]
    #[arg(long)]
    pub local_only: bool,
    /// Path where the Snowflake project is stored. Defaults to the current working directory.
    #[arg(short = 'p', long, value_name = "TEXT")]
    pub project: Option<PathBuf>,
    /// String in the format key=value. Overrides variables from the env section used for
    /// templates.
    #[arg(long = "env", value_name = "TEXT")]
    pub env_overrides: Vec<String>,
    /// Do not prompt before exiting the REPL.
    #[arg(long)]
    pub no_prompt_exit_repl: bool,
    /// Format string for the interactive SQL REPL prompt. Ignored with -q, -f, or -i. Unset
    /// keeps the default prompt. Placeholders: \[user\], \[host\], \[account\], \[role\],
    /// \[warehouse\], \[database\], \[schema\], and \[connection\] (the -c connection name).
    /// They update after USE. Missing values render as (no user), (no database), and so on. A
    /// backslash followed by n is a newline; prefix a bracket or backslash with a backslash to
    /// make it literal. Use \[#rrggbb\] for foreground colour and \[bg:#rrggbb\] for background
    /// colour; each applies to following prompt text only. Unknown tokens are dropped with a
    /// warning. Quoted prompt_format in the \[cli\] section of config.toml sets the default.
    #[arg(long, value_name = "TEXT")]
    pub prompt_format: Option<String>,
    /// The source flags in the order they were given (filled in after parsing).
    #[arg(skip)]
    pub source_order: Vec<SourceFlag>,
    /// Sets a SnowSQL-style option for this run. Supported options are output_file, quiet and
    /// output_format. -o output_file=\<path\> appends query results to the file and still prints
    /// them, like !spool \<path\>. An empty output_file turns spooling off, and output_file=off
    /// writes to a file named off. -o quiet=true hides query results on the terminal, like !set
    /// quiet=true; an open spool file still receives them. -o output_format=\<format\> sets the
    /// starting output format, like !set output_format, and overrides the config key and
    /// environment variable. It cannot be combined with --format, and !set output_format can
    /// still change it later. Repeat -o to set several options. The last value of an option wins.
    #[arg(short = 'o', long = "option", value_name = "KEY=VALUE")]
    pub options: Vec<String>,
    #[command(flatten)]
    pub connection: ConnectionOptions,
    #[command(flatten)]
    pub global: GlobalOptions,
}

/// A value of `--enable-templating`, with snow's names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "UPPER")]
pub enum Templating {
    Legacy,
    Standard,
    Jinja,
    All,
    None,
}

/// `-D` / `--env` `key=value` pairs as snow parses them (`key` and `value` stripped, later ones
/// win); a pair without `=` is a plain click exception (no feedback line).
fn parse_variables(raw: &[String]) -> Result<Variables> {
    let mut variables = Variables::new();
    for item in raw {
        let Some((key, value)) = item.split_once('=') else {
            return Err(
                Error::new(ErrorKind::Client, format!("Invalid variable: '{item}'"))
                    .without_feedback(),
            );
        };
        variables.insert(py_strip(key).to_string(), py_strip(value).to_string());
    }
    Ok(variables)
}

/// `snow`'s `_parse_template_syntax_config`.
fn parse_syntaxes(modes: &[Templating]) -> Result<Syntaxes> {
    let alone = |mode| modes.contains(&mode);
    if (alone(Templating::All) || alone(Templating::None)) && modes.len() > 1 {
        return Err(Error::new(
            ErrorKind::Usage,
            "ALL and NONE template syntax options should not be used with other options.",
        )
        .with_usage(USAGE_NAME));
    }
    if alone(Templating::All) || alone(Templating::None) {
        let all = alone(Templating::All);
        return Ok(Syntaxes {
            legacy: all,
            standard: all,
            jinja: all,
        });
    }
    Ok(Syntaxes {
        legacy: alone(Templating::Legacy),
        standard: alone(Templating::Standard),
        jinja: alone(Templating::Jinja),
    })
}

/// The subcommand name, as the usage line of its errors names it.
pub const USAGE_NAME: &str = "sql";

impl SqlArgs {
    /// Records the order the source flags were given in, from the `sql` subcommand's matches
    /// (clap derive cannot report it; snow names the conflicting flags in that order).
    pub fn fill_source_order(&mut self, matches: &ArgMatches) {
        let mut given: Vec<(usize, SourceFlag)> = SourceFlag::ALL
            .into_iter()
            .filter_map(|flag| matches.index_of(flag.id()).map(|i| (i, flag)))
            .collect();
        given.sort_unstable_by_key(|(i, _)| *i);
        self.source_order = given.into_iter().map(|(_, flag)| flag).collect();
    }
}

/// The mutually exclusive source flags, with snow's names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceFlag {
    Query,
    Files,
    Stdin,
}

impl SourceFlag {
    /// The clap argument id.
    pub fn id(self) -> &'static str {
        match self {
            SourceFlag::Query => "query",
            SourceFlag::Files => "files",
            SourceFlag::Stdin => "stdin",
        }
    }

    fn name(self) -> &'static str {
        match self {
            SourceFlag::Query => "--query",
            SourceFlag::Files => "--filename",
            SourceFlag::Stdin => "--stdin",
        }
    }

    pub const ALL: [SourceFlag; 3] = [SourceFlag::Query, SourceFlag::Files, SourceFlag::Stdin];
}

/// The templating arguments, parsed in `snow`'s order (`--env` in its option callback first).
struct TemplatingArgs {
    env_overrides: Variables,
    variables: Variables,
    syntaxes: Syntaxes,
}

/// `config_file` is the `--config-file` override, which the config files' `[variables]` follow.
fn parse_templating(
    args: &SqlArgs,
    env: &crate::env::Env,
    config_file: Option<&Path>,
    source: &ConfigSource,
) -> Result<TemplatingArgs> {
    let env_overrides = parse_variables(&args.env_overrides)?;
    // `get_merged_variables`: the config files' `[variables]`, then `-D` over them.
    let cwd = std::env::current_dir().unwrap_or_default();
    let mut variables = crate::config::config_variables(env, config_file, &cwd, Some(source));
    variables.extend(parse_variables(&args.variables)?);
    Ok(TemplatingArgs {
        env_overrides,
        variables,
        syntaxes: parse_syntaxes(&args.enable_templating)?,
    })
}

/// The statements of a run, rendered, as `snow` compiles them before connecting. `notices`
/// receives what `snow` prints on stdout meanwhile (warnings, rendering errors). The outer
/// error is an argument error, reported before any notice; the inner one comes after them.
pub fn statements(
    args: &SqlArgs,
    source: &ConfigSource,
    config_file: Option<&Path>,
    stdin: &mut dyn Read,
    env: &crate::env::Env,
    stdin_is_tty: bool,
    notices: &mut Vec<String>,
) -> Result<Result<Vec<Statement>>> {
    let templating = parse_templating(args, env, config_file, source)?;
    let local_only = local_only(args.local_only, source, env)?;
    check_sources(args)?;
    let piped = if !stdin_is_tty && !any_source(args) {
        Some(read_stdin(stdin)?)
    } else {
        None
    };
    let inputs = read_inputs(args, stdin, piped)?;
    let compiler = Compiler::new(args, templating, local_only, env);
    Ok(compiler.compile(&inputs, notices))
}

/// How the inputs of a run are compiled: the options and templating of the command line.
pub(super) struct Compiler {
    options: CompileOptions,
    sources: FsSources,
    variables: Variables,
    syntaxes: Syntaxes,
    project: ProjectSource,
}

impl Compiler {
    fn new(
        args: &SqlArgs,
        templating: TemplatingArgs,
        local_only: bool,
        env: &crate::env::Env,
    ) -> Self {
        Self {
            options: CompileOptions {
                retain_comments: args.retain_comments,
                single_transaction: args.single_transaction,
                local_only,
            },
            sources: FsSources {
                home: env.get("HOME").map(PathBuf::from),
            },
            variables: templating.variables,
            syntaxes: templating.syntaxes,
            project: ProjectSource::new(
                args.project.as_deref(),
                templating.env_overrides,
                env.clone(),
            ),
        }
    }

    pub(super) fn compile(
        &self,
        inputs: &[Input],
        notices: &mut Vec<String>,
    ) -> Result<Vec<Statement>> {
        let templater = Templater::new(&self.variables, self.syntaxes, &self.project);
        compile_inputs(inputs, &self.options, &templater, notices, &self.sources)
    }
}

/// The `-q` text, when it is not empty.
fn query(args: &SqlArgs) -> Option<&str> {
    args.query.as_deref().filter(|q| !q.is_empty())
}

/// Whether one of `-q`, `-f`, `-i` is given.
fn any_source(args: &SqlArgs) -> bool {
    query(args).is_some() || !args.files.is_empty() || args.stdin
}

/// snow's console (`cli_console`) prints only in TABLE and PLAIN, and not with `--silent`.
pub(super) fn console_on(format: OutputFormat, silent: bool) -> bool {
    !silent && matches!(format, OutputFormat::Table | OutputFormat::Plain)
}

/// Runs `snow sql`: everything goes to `ctx.stdout`; the caller reports the returned error.
pub fn run(
    args: &SqlArgs,
    paths: &crate::config::ConfigPaths,
    source: &ConfigSource,
    format: &mut OutputFormat,
    stdin: &mut dyn Read,
    ctx: &mut Context<'_>,
) -> Result<()> {
    let custom = paths
        .config_file_is_custom
        .then_some(paths.config_file.as_path());
    let templating = parse_templating(args, &ctx.env, custom, source)?;
    check_sources(args)?;
    // What snow checks in option callbacks and at the top of the command, before the spool.
    let local_only = local_only(args.local_only, source, &ctx.env)?;
    let no_prompt_exit_repl =
        args.no_prompt_exit_repl || cli_bool(source, &ctx.env, "no_prompt_exit_repl")?;
    // No source: a non-blank piped stdin is the query (ADR 0004, Decision 1); otherwise this
    // is the interactive session.
    let piped = if any_source(args) || ctx.stdin_is_tty {
        None
    } else {
        Some(read_stdin(stdin)?).filter(|text| !py_strip(text).is_empty())
    };
    let interactive = !any_source(args) && piped.is_none();
    let mut prompt_format = None;
    if interactive {
        prompt_format = match &args.prompt_format {
            Some(text) => Some(text.clone()),
            None => config_prompt_format(source)?,
        };
        let unknown = prompt_format
            .as_deref()
            .map(prompt::unknown_tokens)
            .unwrap_or_default();
        if !unknown.is_empty() && console_on(*format, args.global.silent) {
            let line = format!("{}\n", prompt::unknown_token_warning(&unknown));
            let _ = ctx.stderr.write_all(line.as_bytes());
        }
        if args.single_transaction {
            return Err(usage(
                "single transaction cannot be used with REPL".to_string(),
            ));
        }
    }
    // Every `-o` is validated before any is applied; the spool is opened before anything runs.
    let startup = StartupOptions::parse(&args.options)?;
    startup.check_format_conflict(args.global.format.is_some())?;
    if let Some(chosen) = startup.output_format {
        *format = chosen;
    }
    let format = *format;
    let console = console_on(format, args.global.silent);
    let spool = match &startup.output_file {
        Some(path) => Some(open_spool(path, &ctx.env, console, ctx.stdout)?),
        None => None,
    };
    let compiler = Compiler::new(args, templating, local_only, &ctx.env);
    if interactive {
        let repl = super::repl::ReplOptions {
            prompt_format,
            no_prompt_exit_repl,
            history: paths.config_file.parent().map(|d| d.join("repl_history")),
        };
        let start = OutputStart {
            format,
            quiet: startup.quiet == Some(true),
            spool,
        };
        return super::repl::run(args, source, &compiler, start, repl, stdin, ctx);
    }
    let inputs = read_inputs(args, stdin, piped)?;
    let mut notices = Vec::new();
    let compiled = compiler.compile(&inputs, &mut notices);
    if console {
        for notice in &notices {
            let line = format!("{}\n", sanitize_for_terminal(notice));
            write(ctx.stdout, line.as_bytes())?;
        }
    }
    let statements = compiled?;
    let conn = resolve_for_sign_in(source, &args.connection, ctx)?;
    let script = ScriptOptions {
        autocommit_off: args.single_transaction,
        ..script_options(&conn)?
    };
    let options = ClientOptions {
        decimal_precision: ctx.decimal_precision,
        ..ClientOptions::from_env(&ctx.env)?
    };
    let transfer =
        crate::transfer::TransferOptions::new(ctx.env.get_non_empty("HOME").map(PathBuf::from));
    let executor = super::connection::connect(
        &conn,
        RunNeeds {
            session: statements.iter().any(|s| {
                s.put_or_get || s.asynchronous || s.command.as_ref().is_some_and(needs_session)
            }),
        },
        options,
        &script,
        transfer,
        ctx,
    )?;
    let printer = Printer {
        // snow's `VerboseCursor` echoes each statement on the console.
        verbose_echo: true,
        repl: false,
        // snow's `expected_results_cnt`: `;>` statements have no result of their own.
        multi: statements
            .iter()
            .filter(|s| s.command.is_none() && !s.asynchronous)
            .count()
            >= 2,
        script,
        interrupt: None,
    };
    let mut out = Sink::new(
        &mut *ctx.stdout,
        OutputStart {
            format,
            quiet: startup.quiet == Some(true),
            spool,
        },
        args.global.silent,
        ctx.env.clone(),
        ctx.terminal_width,
    );
    let outcome = printer.print(&executor, &statements, &mut out, &mut Batch);
    let flushed = out.flush();
    let _ = executor.close();
    outcome?;
    match flushed {
        Err(e) if e.kind() != io::ErrorKind::BrokenPipe => Err(write_error(e)),
        _ => Ok(()),
    }
}

/// The commands that talk to Snowflake outside a statement, so need a session.
fn needs_session(command: &ReplCommand) -> bool {
    matches!(
        command,
        ReplCommand::Queries(_) | ReplCommand::Result(_) | ReplCommand::Abort(_)
    )
}

/// `[cli] prompt_format`, read without its environment variable (snow keeps it env-free).
fn config_prompt_format(source: &ConfigSource) -> Result<Option<String>> {
    let type_name = match source.cli_value("prompt_format") {
        None => return Ok(None),
        Some(toml::Value::String(text)) => return Ok(Some(text.clone())),
        Some(toml::Value::Integer(_)) => "int",
        Some(toml::Value::Float(_)) => "float",
        Some(toml::Value::Boolean(_)) => "bool",
        Some(toml::Value::Array(_)) => "list",
        Some(toml::Value::Table(_)) => "dict",
        Some(toml::Value::Datetime(_)) => "datetime",
    };
    Err(Error::new(
        ErrorKind::Client,
        format!(
            "Expected a string for cli.prompt_format, got {type_name}. Use a quoted value, for example prompt_format = \"[user]> \"."
        ),
    ))
}

const SUPPORTED_OPTIONS: &str = "Only output_file, quiet and output_format are supported.";

/// The `-o key=value` options of `snow sql` (`_resolve_startup_options`): the last value of each
/// key wins. They are the starting values of settings the interactive session changes later.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct StartupOptions {
    /// `None`: no spool (not given, or an empty value).
    pub output_file: Option<String>,
    pub quiet: Option<bool>,
    pub output_format: Option<OutputFormat>,
}

impl StartupOptions {
    pub fn parse(raw: &[String]) -> Result<Self> {
        let mut options = Self::default();
        for item in raw {
            let text = py_strip(item);
            let Some((key, value)) = text.split_once('=') else {
                return Err(usage(format!(
                    "Invalid option '{text}'. Use -o <option>=<value>."
                )));
            };
            let key = py_strip(key);
            match key.to_lowercase().as_str() {
                "output_file" => {
                    let path = strip_matching_quotes(py_strip(value));
                    options.output_file = (!py_strip(path).is_empty()).then(|| path.to_string());
                }
                "quiet" => options.quiet = Some(parse_bool("quiet", value)?),
                "output_format" => {
                    options.output_format =
                        Some(OutputFormat::from_name(value).ok_or_else(|| {
                            usage(format!(
                                "Invalid output format: {}. Must be one of: {}.",
                                py_repr(value),
                                OutputFormat::ALLOWED
                            ))
                        })?);
                }
                _ => {
                    return Err(usage(format!(
                        "Unknown option '{key}'. {SUPPORTED_OPTIONS}"
                    )));
                }
            }
        }
        Ok(options)
    }

    /// `--format` and `-o output_format` set the same thing; only an explicit `--format`
    /// conflicts (the config key and the variable are defaults the option overrides).
    pub fn check_format_conflict(&self, format_flag_given: bool) -> Result<()> {
        if self.output_format.is_some() && format_flag_given {
            return Err(usage(
                "--format cannot be combined with -o output_format. Use only one of them."
                    .to_string(),
            ));
        }
        Ok(())
    }
}

/// A `CliArgumentError`.
fn usage(message: String) -> Error {
    Error::new(ErrorKind::Argument, message)
}

use crate::script::command::strip_matching_quotes;

/// `parse_bool_value`.
fn parse_bool(option: &str, value: &str) -> Result<bool> {
    command::parse_bool(option, value).map_err(usage)
}

/// How the output of a run starts: the format and `quiet` after `-o`, and the spool it opened.
pub(super) struct OutputStart {
    pub format: OutputFormat,
    pub quiet: bool,
    pub spool: Option<BufWriter<std::fs::File>>,
}

/// Where the results of a run go: the terminal (not when quiet) and the spool file, if any,
/// with the settings `!set` and `!spool` change as the run goes. The statement echo of a
/// one-shot run is not a result: it only goes to the terminal.
pub(super) struct Sink<'a> {
    stdout: BufWriter<&'a mut dyn Write>,
    spool: Option<BufWriter<std::fs::File>>,
    pub quiet: bool,
    pub format: OutputFormat,
    /// `--silent`.
    silent: bool,
    /// The `Time Elapsed` line of the interactive session (on by default, as in snow).
    pub timing: bool,
    pub timing_in_output_file: bool,
    /// The interactive session's echo of each statement.
    pub echo: bool,
    /// The interactive session: on a terminal, rich leaves an empty line after a table.
    pub table_trailer: bool,
    env: crate::env::Env,
    terminal_width: Option<usize>,
}

impl<'a> Sink<'a> {
    pub(super) fn new(
        stdout: &'a mut dyn Write,
        start: OutputStart,
        silent: bool,
        env: crate::env::Env,
        terminal_width: Option<usize>,
    ) -> Self {
        Self {
            stdout: BufWriter::with_capacity(1 << 16, stdout),
            spool: start.spool,
            quiet: start.quiet,
            format: start.format,
            silent,
            timing: true,
            timing_in_output_file: false,
            echo: false,
            table_trailer: false,
            env,
            terminal_width,
        }
    }

    /// The empty line rich prints after a non-empty table on a terminal (interactive session).
    fn trailer(&mut self, format: OutputFormat, rows: usize) -> Result<()> {
        if self.table_trailer && format == OutputFormat::Table && self.width().is_some() && rows > 0
        {
            write(self, b"\n")?;
        }
        Ok(())
    }

    fn echo(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.stdout.write_all(bytes)
    }

    /// Whether snow's console prints now (the format may change during the run).
    pub(super) fn console_on(&self) -> bool {
        console_on(self.format, self.silent)
    }

    /// A console line (`cli_console.message`/`warning`): stdout only, when the console is on.
    pub(super) fn console(&mut self, text: &str) -> Result<()> {
        if !self.console_on() {
            return Ok(());
        }
        let line = format!("{text}\n");
        write(&mut self.stdout, line.as_bytes())
    }

    /// `print_raw`: text on the terminal and in the spool, whatever `quiet` says.
    pub(super) fn raw(&mut self, text: &str) -> Result<()> {
        let mut text = sanitize_for_terminal(text);
        if !text.ends_with('\n') {
            text.push('\n');
        }
        write(&mut self.stdout, text.as_bytes())?;
        self.spool_only(&text)
    }

    /// Text for the spool file only, if one is open.
    pub(super) fn spool_only(&mut self, text: &str) -> Result<()> {
        match self.spool.as_mut() {
            Some(spool) => spool
                .write_all(text.as_bytes())
                .and_then(|()| spool.flush())
                .map_err(write_error),
            None => Ok(()),
        }
    }

    /// The terminal was resized (the interactive session checks before each prompt).
    pub(super) fn set_terminal_width(&mut self, width: Option<usize>) {
        self.terminal_width = width;
    }

    pub(super) fn has_spool(&self) -> bool {
        self.spool.is_some()
    }

    /// The width TABLE and PLAIN fold to: the terminal's, unless quiet or spooling (snow gives
    /// those the layout of a pipe).
    pub(super) fn width(&self) -> Option<usize> {
        self.terminal_width
            .filter(|_| self.spool.is_none() && !self.quiet)
    }

    /// `open_spool` (`!spool <file>`, `!set output_file`): closes the open one first.
    pub(super) fn open_spool(&mut self, path: &str) -> Result<()> {
        self.close_spool()?;
        let warn = self.console_on();
        let file = open_spool(path, &self.env, warn, &mut self.stdout)?;
        self.spool = Some(file);
        Ok(())
    }

    pub(super) fn close_spool(&mut self) -> Result<()> {
        match self.spool.take() {
            Some(mut spool) => spool.flush().map_err(write_error),
            None => Ok(()),
        }
    }
}

impl Write for Sink<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // A closed terminal must not stop the spool: write both, report the first error.
        let terminal = if self.quiet {
            Ok(())
        } else {
            self.stdout.write_all(buf)
        };
        let file = match self.spool.as_mut() {
            Some(spool) => spool.write_all(buf),
            None => Ok(()),
        };
        terminal.and(file).map(|()| buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let terminal = self.stdout.flush();
        let file = match self.spool.as_mut() {
            Some(spool) => spool.flush(),
            None => Ok(()),
        };
        terminal.and(file)
    }
}

/// `open_spool`: opens `path` for append, creating it owner-only, after warning (when
/// the console is on: TABLE or PLAIN, not `--silent`) when an existing file is broader than that.
fn open_spool(
    path: &str,
    env: &crate::env::Env,
    warn: bool,
    stdout: &mut dyn Write,
) -> Result<BufWriter<std::fs::File>> {
    let path = expand_user(path, env);
    let existed = path.exists();
    let mut options = crate::fsutil::private_options();
    options.append(true).create(true);
    let shown = sanitize_for_terminal(&path.display().to_string());
    let file = options.open(&path).map_err(|e| {
        let detail = e.to_string();
        let detail = detail.split(" (os error").next().unwrap_or(&detail);
        Error::new(
            ErrorKind::Client,
            format!("Cannot write spool file '{shown}': {detail}"),
        )
        .with_source(e)
    })?;
    if existed
        && warn
        && let Some(detail) = broader_than_owner_only(&path)
    {
        let line = format!("Spool file '{shown}' is broader than owner-only. {detail}\n");
        write(stdout, line.as_bytes())?;
    }
    Ok(BufWriter::with_capacity(1 << 16, file))
}

/// `os.path.expanduser`: a leading `~` or `~/` is the home directory.
fn expand_user(path: &str, env: &crate::env::Env) -> PathBuf {
    crate::config::expand_user_with(path, crate::config::home_dir(env).ok().as_deref())
}

#[cfg(unix)]
fn broader_than_owner_only(path: &Path) -> Option<&'static str> {
    use std::os::unix::fs::MetadataExt;
    let mode = std::fs::metadata(path).ok()?.mode();
    match (mode & 0o044 != 0, mode & 0o022 != 0) {
        (true, true) => Some(
            "Other users on this machine can read query results written to this file, and can write to it.",
        ),
        (true, false) => {
            Some("Other users on this machine can read query results written to this file.")
        }
        (false, true) => Some("Other users on this machine can write to this file."),
        (false, false) => None,
    }
}

#[cfg(not(unix))]
fn broader_than_owner_only(_path: &Path) -> Option<&'static str> {
    None
}

/// The inputs as `snow` reads them (after `check_sources`): the `-q` text, each `-f` file, or stdin (`-i`, or the
/// non-blank text piped without a source flag, already read).
fn read_inputs(args: &SqlArgs, stdin: &mut dyn Read, piped: Option<String>) -> Result<Vec<Input>> {
    if let Some(query) = query(args) {
        return Ok(vec![text_input(query.to_string())]);
    }
    if !args.files.is_empty() {
        return args
            .files
            .iter()
            .map(|path| {
                Ok(Input {
                    text: read_file(path)?,
                    file: Some(path.clone()),
                })
            })
            .collect();
    }
    if args.stdin {
        let text = read_stdin(stdin)?;
        if text.is_empty() {
            return Err(Error::new(
                ErrorKind::Client,
                "Use either query, filename or input option.",
            ));
        }
        return Ok(vec![text_input(text)]);
    }
    match piped.map(|text| py_strip(&text).to_string()) {
        Some(text) if !text.is_empty() => Ok(vec![text_input(text)]),
        _ => Err(Error::new(
            ErrorKind::Client,
            "Use either query, filename or input option.",
        )),
    }
}

fn text_input(text: String) -> Input {
    Input { text, file: None }
}

/// `--local-only`: the flag, else env `SNOWFLAKE_CLI_SQL_LOCAL_ONLY`, else `[cli] sql_local_only`.
fn local_only(flag: bool, source: &ConfigSource, env: &crate::env::Env) -> Result<bool> {
    Ok(flag || cli_bool(source, env, "sql_local_only")?)
}

/// `get_config_bool_value("cli", key)`: env `SNOWFLAKE_CLI_<KEY>`, else `[cli] <key>`, else
/// false.
fn cli_bool(source: &ConfigSource, env: &crate::env::Env, key: &str) -> Result<bool> {
    // A plain click exception in snow: no feedback line.
    let invalid = || {
        Error::new(
            ErrorKind::Client,
            format!("Expected boolean value for cli.{key} option."),
        )
        .without_feedback()
    };
    let cast = |value: &str| match value.to_lowercase().as_str() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(invalid()),
    };
    let variable = format!("SNOWFLAKE_CLI_{}", key.to_uppercase());
    if let Some(value) = env.get_non_empty(&variable) {
        return cast(value);
    }
    match source.cli_value(key) {
        None => Ok(false),
        Some(toml::Value::Boolean(b)) => Ok(*b),
        Some(toml::Value::String(s)) => cast(s),
        Some(toml::Value::Integer(i)) => cast(&i.to_string()),
        Some(_) => Err(invalid()),
    }
}

/// click's processing of the source flags, in command-line order: each `-f` path is checked
/// when `-f` is processed, and the second source given conflicts with the first.
fn check_sources(args: &SqlArgs) -> Result<()> {
    let given = |flag: SourceFlag| match flag {
        SourceFlag::Query => query(args).is_some(),
        SourceFlag::Files => !args.files.is_empty(),
        SourceFlag::Stdin => args.stdin,
    };
    let mut order: Vec<SourceFlag> = args.source_order.clone();
    for flag in SourceFlag::ALL {
        if !order.contains(&flag) {
            order.push(flag);
        }
    }
    let mut seen: Option<SourceFlag> = None;
    for flag in order.into_iter().filter(|f| given(*f)) {
        if flag == SourceFlag::Files {
            for path in &args.files {
                check_file(path)?;
            }
        }
        if let Some(first) = seen {
            return Err(Error::new(
                ErrorKind::Usage,
                format!(
                    "Parameters '{}' and '{}' are incompatible and cannot be used simultaneously.",
                    flag.name(),
                    first.name()
                ),
            )
            .with_usage(USAGE_NAME));
        }
        seen = Some(flag);
    }
    Ok(())
}

/// click's `Path(exists=True, dir_okay=False, readable=True)` check of a `-f` value.
fn check_file(path: &Path) -> Result<()> {
    let problem = match std::fs::metadata(path) {
        Err(_) => "does not exist",
        Ok(meta) if meta.is_dir() => "is a directory",
        Ok(_) if std::fs::File::open(path).is_err() => "is not readable",
        Ok(_) => return Ok(()),
    };
    Err(Error::new(
        ErrorKind::Usage,
        format!(
            "Invalid value for '--filename' / '-f': File {} {problem}.",
            py_repr(&path.display().to_string())
        ),
    )
    .with_usage(USAGE_NAME))
}

fn read_file(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| {
        Error::new(
            ErrorKind::Client,
            format!("Could not read: {}", path.display()),
        )
        .with_source(e)
    })
}

fn read_stdin(stdin: &mut dyn Read) -> Result<String> {
    let mut text = String::new();
    stdin.read_to_string(&mut text).map_err(|e| {
        Error::new(ErrorKind::Client, "Could not read standard input.").with_source(e)
    })?;
    Ok(text)
}

fn write_error(e: io::Error) -> Error {
    Error::new(ErrorKind::Client, "Failed to write the result.").with_source(e)
}

/// Writes `bytes`; a closed pipe is not an error (the rest of the output is dropped).
fn write(out: &mut dyn Write, bytes: &[u8]) -> Result<()> {
    match out.write_all(bytes) {
        Err(e) if e.kind() != io::ErrorKind::BrokenPipe => Err(write_error(e)),
        _ => Ok(()),
    }
}

/// What the interactive session lends to its `!` commands (`!edit`).
pub(super) trait Interactive {
    /// `!edit`: edits `sql` (the last statement when empty) and queues it for the next prompt.
    fn edit(&mut self, sql: &str, out: &mut Sink<'_>) -> Result<()>;
}

/// A one-shot run (`-q`, `-f`, `-i`): no interactive session.
struct Batch;

impl Interactive for Batch {
    fn edit(&mut self, _sql: &str, _out: &mut Sink<'_>) -> Result<()> {
        Err(Error::new(
            ErrorKind::Client,
            "The edit command can only be used in interactive mode.",
        ))
    }
}

/// How the results of a run are printed (ADR 0004, Decision 4).
pub(super) struct Printer {
    /// The statement echo of a one-shot run (snow's `VerboseCursor`): on the terminal only,
    /// while the console is on (TABLE and PLAIN, not `--silent`).
    pub verbose_echo: bool,
    /// The interactive session: the `!set echo` echo, and Ctrl-C stops the output.
    pub repl: bool,
    /// The results are printed as snow's `MultipleResults` (two or more statements, or any
    /// interactive input): JSON is a list of lists and CSV results end with an empty line.
    pub multi: bool,
    /// How each request is sent (`--single-transaction` turns autocommit off).
    pub script: ScriptOptions,
    /// Set by Ctrl-C in the interactive session.
    pub interrupt: Option<Arc<AtomicBool>>,
}

/// The format of a result printed on its own.
fn structured(format: OutputFormat) -> bool {
    format.is_json() || format == OutputFormat::Csv
}

impl Printer {
    /// Runs `statements` in order and prints their results; `!` commands run in between.
    pub(super) fn print(
        &self,
        client: &Executor,
        statements: &[Statement],
        out: &mut Sink<'_>,
        interactive: &mut dyn Interactive,
    ) -> Result<()> {
        // `MultipleResults` takes its shape from the format when printing starts.
        let start = out.format;
        let wrap_json = self.multi && start.is_json();
        let wrap_csv = self.multi && start == OutputFormat::Csv;
        if wrap_json {
            write(out, b"[\n")?;
        }
        let mut printed = 0usize;
        for segment in segments(statements) {
            if let [
                Statement {
                    command: Some(command),
                    ..
                },
            ] = segment
            {
                if let Err(err) = run_command(command, client, out, interactive) {
                    let _ = out.flush();
                    return Err(err);
                }
                continue;
            }
            if let [
                statement @ Statement {
                    asynchronous: true, ..
                },
            ] = segment
            {
                self.submit(client, statement, out)?;
                continue;
            }
            let texts: Vec<String> = segment.iter().map(|s| s.text.clone()).collect();
            let mut run = client.run_script(&texts, &self.script)?;
            for statement in segment {
                if self.repl && out.echo && !structured(out.format) {
                    out.raw(&statement.text)?;
                }
                let Some(item) = run.next() else {
                    return Err(Error::new(
                        ErrorKind::Communication,
                        "Snowflake returned fewer results than statements.",
                    ));
                };
                self.echo_statement(&statement.text, out)?;
                let mut stream = match item {
                    Ok(stream) => stream,
                    Err(err) => {
                        // What was printed stays; stdout goes out before the panel.
                        let _ = out.flush();
                        return Err(err);
                    }
                };
                let columns = stream.columns().to_vec();
                let mut rows = Interruptible {
                    rows: &mut stream,
                    flag: self.interrupt.as_deref(),
                    count: 0,
                };
                if wrap_json {
                    if printed > 0 {
                        write(out, b",\n")?;
                    }
                    render_json_multi(&columns, &mut rows, start, out)?;
                } else {
                    let format = if wrap_csv { start } else { out.format };
                    let width = out.width();
                    render_stream(&columns, &mut rows, format, width, out)?;
                    if wrap_csv {
                        write(out, b"\n")?;
                    }
                    let count = rows.count;
                    out.trailer(format, count)?;
                }
                printed += 1;
            }
        }
        if wrap_json {
            write(out, b"\n]\n\n")?;
        }
        Ok(())
    }
}

impl Printer {
    /// The statement echo of a one-shot run (`verbose_echo`): on the console only. A closed
    /// pipe ends it silently.
    fn echo_statement(&self, text: &str, out: &mut Sink<'_>) -> Result<()> {
        if self.verbose_echo && out.console_on() {
            let line = format!("{}\n", sanitize_for_terminal(text));
            match out.echo(line.as_bytes()) {
                Err(e) if e.kind() != io::ErrorKind::BrokenPipe => return Err(write_error(e)),
                _ => {}
            }
        }
        Ok(())
    }

    /// A `;>` statement (`_execute_compiled_statements`): the echo, the submission, then its
    /// query id printed on its own as a one-row collection, wherever the output stands.
    fn submit(&self, client: &Executor, statement: &Statement, out: &mut Sink<'_>) -> Result<()> {
        if self.repl && out.echo && !structured(out.format) {
            out.raw(&statement.text)?;
        }
        self.echo_statement(&statement.text, out)?;
        let session = client.session().ok_or_else(|| {
            Error::new(
                ErrorKind::Client,
                "Asynchronous statements (;>) need a Snowflake session.",
            )
        })?;
        let id = match session.submit_async(&statement.text) {
            Ok(id) => id,
            Err(err) => {
                let _ = out.flush();
                return Err(err);
            }
        };
        log::info!("Async execution id: {id}");
        print_collection(
            vec![vec![("scheduled query ID".to_string(), Field::str(id))]],
            out,
        )
    }
}

/// The rows of a result, cut short by Ctrl-C (an `Aborted` error row).
struct Interruptible<'a> {
    rows: &'a mut crate::sql::RowStream,
    flag: Option<&'a AtomicBool>,
    /// Rows read so far.
    count: usize,
}

impl Iterator for Interruptible<'_> {
    type Item = Result<Vec<crate::sql::result::Value>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.flag.is_some_and(|f| f.load(Ordering::SeqCst)) {
            self.flag = None;
            return Some(Err(Error::new(ErrorKind::Aborted, "Interrupted.")));
        }
        let row = self.rows.next();
        self.count += usize::from(row.is_some());
        row
    }
}

/// Runs one `!` command (`ReplCommand.execute`).
fn run_command(
    command: &ReplCommand,
    client: &Executor,
    out: &mut Sink<'_>,
    interactive: &mut dyn Interactive,
) -> Result<()> {
    let session = || {
        client
            .session()
            .ok_or_else(|| Error::new(ErrorKind::Client, "This command needs a Snowflake session."))
    };
    match command {
        ReplCommand::Set(option, value) => match option {
            SetOption::OutputFile => out.open_spool(value)?,
            SetOption::Quiet => out.quiet = parse_bool("quiet", value)?,
            SetOption::Timing => out.timing = parse_bool("timing", value)?,
            SetOption::TimingInOutputFile => {
                out.timing_in_output_file = parse_bool("timing_in_output_file", value)?;
            }
            SetOption::Echo => out.echo = value == "true",
            SetOption::OutputFormat => out.format = command::parse_format(value).map_err(usage)?,
        },
        ReplCommand::Spool(None) => out.close_spool()?,
        ReplCommand::Spool(Some(path)) => out.open_spool(path)?,
        ReplCommand::Rehash => out.console("Autocomplete is disabled.")?,
        ReplCommand::Edit(sql) => interactive.edit(sql, out)?,
        ReplCommand::QueriesHelp => {
            let rows = [
                ["amount", "integer", "25"],
                ["status", "string", "any"],
                ["warehouse", "string", "any"],
                ["user", "string", "any"],
                [
                    "start_date",
                    "datetime in ISO format (for example YYYY-MM-DDTHH:mm:ss.sss)",
                    "any",
                ],
                [
                    "end_date",
                    "datetime in ISO format (for example YYYY-MM-DDTHH:mm:ss.sss)",
                    "any",
                ],
                ["start", "timestamp in milliseconds (integer)", "any"],
                ["end", "timestamp in milliseconds (integer)", "any"],
                ["type", "string", "any"],
                ["duration", "time in milliseconds", "any"],
                ["session", "No arguments", "any"],
            ];
            let records = rows
                .iter()
                .map(|row| {
                    ["FILTER", "ARGUMENT", "DEFAULT"]
                        .iter()
                        .zip(row)
                        .map(|(k, v)| (k.to_string(), Field::str(*v)))
                        .collect()
                })
                .collect();
            print_collection(records, out)?;
        }
        ReplCommand::Queries(filter) => {
            let session = session()?;
            let path = queries_path(filter, session.session_id().as_deref());
            let reply = session.get_json(&path)?;
            let queries = reply["data"]["queries"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            if !queries.is_empty() {
                let records = queries
                    .iter()
                    .map(|q| {
                        vec![
                            ("QUERY ID".to_string(), json_field(&q["id"])),
                            ("SQL TEXT".to_string(), json_field(&q["sqlText"])),
                            ("STATUS".to_string(), json_field(&q["state"])),
                            ("DURATION_MS".to_string(), json_field(&q["totalDuration"])),
                        ]
                    })
                    .collect();
                print_collection(records, out)?;
            }
        }
        ReplCommand::Result(id) => {
            let session = session()?;
            let rows = session.query_result(id)?.into_rows(session)?;
            print_single(rows, out)?;
        }
        ReplCommand::Abort(id) => {
            let session = session()?;
            // The id is a checked UUID: safe inside the literal (the connector binds it).
            let sql = format!("SELECT SYSTEM$CANCEL_QUERY('{id}')");
            let rows = session.query(&sql)?.into_rows(session)?;
            print_single(rows, out)?;
        }
    }
    Ok(())
}

/// `/monitoring/queries?…` with the parameters of `!queries`, in snow's order.
fn queries_path(filter: &QueriesFilter, session_id: Option<&str>) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or_default();
    let mut params: Vec<(&str, String)> = vec![
        ("_dc", format!("{now}")),
        ("includeDDL", "false".into()),
        ("max", filter.amount.to_string()),
    ];
    let optional = [
        ("user", filter.user.clone()),
        ("wh", filter.warehouse.clone()),
        ("start", filter.start_ms.map(|v| v.to_string())),
        ("end", filter.end_ms.map(|v| v.to_string())),
        ("min_duration", filter.duration.clone()),
        (
            "session_id",
            session_id
                .filter(|_| filter.from_current_session)
                .map(String::from),
        ),
        ("subset", filter.status.clone()),
        ("stmt_type", filter.stmt_type.clone()),
    ];
    params.extend(
        optional
            .into_iter()
            .filter_map(|(k, v)| v.filter(|v| !v.is_empty()).map(|v| (k, v))),
    );
    let query: Vec<String> = params
        .iter()
        .map(|(k, v)| format!("{k}={}", crate::codec::form_encode_plus(v)))
        .collect();
    format!("/monitoring/queries?{}", query.join("&"))
}

fn json_field(value: &serde_json::Value) -> Field {
    match value {
        serde_json::Value::Null => Field::Null,
        serde_json::Value::Bool(b) => Field::Bool(*b),
        serde_json::Value::Number(n) => match n.as_i64() {
            Some(i) => Field::Int(i),
            None => Field::Float(n.as_f64().unwrap_or_default()),
        },
        serde_json::Value::String(s) => Field::str(s.as_str()),
        other => Field::str(other.to_string()),
    }
}

/// `print_result(CollectionResult(...))` in the current format.
fn print_collection(records: Vec<Vec<(String, Field)>>, out: &mut Sink<'_>) -> Result<()> {
    let (format, width, count) = (out.format, out.width(), records.len());
    CommandResult::Collection(records).write(format, width, out)?;
    out.trailer(format, count)?;
    out.flush().map_err(write_error)
}

/// `print_result(QueryResult(cursor))` in the current format.
fn print_single(mut rows: crate::sql::RowStream, out: &mut Sink<'_>) -> Result<()> {
    let columns = rows.columns().to_vec();
    let (format, width) = (out.format, out.width());
    let mut counted = Interruptible {
        rows: &mut rows,
        flag: None,
        count: 0,
    };
    render_stream(&columns, &mut counted, format, width, out)?;
    let count = counted.count;
    out.trailer(format, count)
}

/// The requests of a run: consecutive statements together; an empty statement alone (the
/// server ignores it inside a multi-statement request; alone it fails as in `snow`), a `!`
/// command alone (it runs between requests) and a `;>` statement alone (submitted on its own).
fn segments(statements: &[Statement]) -> Vec<&[Statement]> {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, statement) in statements.iter().enumerate() {
        if statement.empty || statement.command.is_some() || statement.asynchronous {
            if start < i {
                out.push(&statements[start..i]);
            }
            out.push(&statements[i..=i]);
            start = i + 1;
        }
    }
    if start < statements.len() {
        out.push(&statements[start..]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement(text: &str, empty: bool) -> Statement {
        Statement {
            text: text.into(),
            empty,
            put_or_get: false,
            command: None,
            asynchronous: false,
        }
    }

    fn test_sink<'a>(
        stdout: &'a mut dyn Write,
        spool: Option<BufWriter<std::fs::File>>,
        quiet: bool,
    ) -> Sink<'a> {
        let mut sink = Sink::new(
            stdout,
            OutputStart {
                format: OutputFormat::Table,
                quiet,
                spool,
            },
            false,
            crate::env::Env::default(),
            None,
        );
        sink.quiet = quiet;
        sink
    }

    #[test]
    fn empty_statements_get_their_own_request() {
        let list = [
            statement("a;", false),
            statement("b;", false),
            statement(";", true),
            statement("c;", false),
            statement(";", true),
        ];
        let lens: Vec<usize> = segments(&list).iter().map(|s| s.len()).collect();
        assert_eq!(lens, vec![2, 1, 1, 1]);
        assert!(segments(&[]).is_empty());
        let asynchronous = Statement {
            asynchronous: true,
            ..statement("b", false)
        };
        let list = [
            statement("a;", false),
            asynchronous.clone(),
            asynchronous,
            statement("c;", false),
            statement("d;", false),
        ];
        let lens: Vec<usize> = segments(&list).iter().map(|s| s.len()).collect();
        assert_eq!(lens, vec![1, 1, 1, 2]);
    }

    fn parse(items: &[&str]) -> Result<StartupOptions> {
        let raw: Vec<String> = items.iter().map(|s| s.to_string()).collect();
        StartupOptions::parse(&raw)
    }

    #[test]
    fn startup_options_parse_like_snow() {
        assert_eq!(parse(&[]).unwrap(), StartupOptions::default());
        let all = parse(&[
            " OUTPUT_FILE = \"a b.txt\" ",
            "quiet=Yes",
            "output_format= json_ext",
        ])
        .unwrap();
        assert_eq!(all.output_file.as_deref(), Some("a b.txt"));
        assert_eq!(all.quiet, Some(true));
        assert_eq!(all.output_format, Some(OutputFormat::JsonExt));
    }

    #[test]
    fn startup_options_last_value_wins() {
        let options = parse(&[
            "output_file=a",
            "quiet=true",
            "output_format=csv",
            "output_file=b",
            "quiet=0",
            "output_format=plain",
        ])
        .unwrap();
        assert_eq!(options.output_file.as_deref(), Some("b"));
        assert_eq!(options.quiet, Some(false));
        assert_eq!(options.output_format, Some(OutputFormat::Plain));
    }

    #[test]
    fn output_file_values_are_normalized() {
        for (raw, want) in [
            ("output_file=", None),
            ("output_file=   ", None),
            ("output_file=''", None),
            ("output_file=\" \"", None),
            ("output_file=off", Some("off")),
            ("output_file='x'", Some("x")),
            ("output_file=\"x'", Some("\"x'")),
            ("output_file='", Some("'")),
            ("output_file= ' x ' ", Some(" x ")),
            ("output_file=a=b", Some("a=b")),
        ] {
            let got = parse(&[raw]).unwrap().output_file;
            assert_eq!(got.as_deref(), want, "{raw}");
        }
        assert_eq!(
            parse(&["output_file=a", "output_file="])
                .unwrap()
                .output_file,
            None
        );
    }

    #[test]
    fn bad_options_fail_with_snows_messages() {
        let message = |items: &[&str]| {
            let err = parse(items).unwrap_err();
            // A CliArgumentError: a panel without usage lines, exit code 1 (2 when enhanced).
            assert_eq!(
                (
                    err.kind(),
                    err.usage(),
                    err.exit_code(),
                    err.exit_code_with(true)
                ),
                (ErrorKind::Argument, None, 1, 2)
            );
            err.message().to_string()
        };
        assert_eq!(
            message(&[" x "]),
            "Invalid option 'x'. Use -o <option>=<value>."
        );
        assert_eq!(
            message(&["Header =false"]),
            "Unknown option 'Header'. Only output_file, quiet and output_format are supported."
        );
        assert_eq!(
            message(&["quiet=maybe"]),
            "Invalid value for quiet: 'maybe'. Use true or false."
        );
        assert_eq!(
            message(&["quiet="]),
            "Invalid value for quiet: ''. Use true or false."
        );
        assert_eq!(
            message(&["output_format=it's"]),
            "Invalid output format: \"it's\". Must be one of: TABLE, JSON, JSON_EXT, CSV, PLAIN."
        );
        // The first bad entry is the one reported.
        assert_eq!(
            message(&["quiet=maybe", "nope=1"]),
            "Invalid value for quiet: 'maybe'. Use true or false."
        );
    }

    #[test]
    fn output_format_option_conflicts_only_with_an_explicit_format_flag() {
        let with_format = parse(&["output_format=csv"]).unwrap();
        assert!(with_format.check_format_conflict(false).is_ok());
        let err = with_format.check_format_conflict(true).unwrap_err();
        assert_eq!(
            err.message(),
            "--format cannot be combined with -o output_format. Use only one of them."
        );
        assert!(
            StartupOptions::default()
                .check_format_conflict(true)
                .is_ok()
        );
    }

    #[test]
    fn bool_values_use_snows_spellings() {
        for v in ["true", " TRUE ", "yes", "On", "1"] {
            assert!(parse_bool("quiet", v).unwrap(), "{v}");
        }
        for v in ["false", "No", "OFF", "0"] {
            assert!(!parse_bool("quiet", v).unwrap(), "{v}");
        }
        assert!(parse_bool("quiet", "2").is_err());
    }

    // POSIX home and separators; Windows reads USERPROFILE and uses `\`, covered by `config::paths` tests
    #[cfg(unix)]
    #[test]
    fn home_is_expanded_in_spool_paths() {
        let env = crate::env::Env::from_pairs([("HOME", "/home/u/")]);
        assert_eq!(expand_user("~", &env), PathBuf::from("/home/u/"));
        assert_eq!(expand_user("~/a.txt", &env), PathBuf::from("/home/u/a.txt"));
        assert_eq!(expand_user("~x/a", &env), PathBuf::from("~x/a"));
        assert_eq!(expand_user("a/~", &env), PathBuf::from("a/~"));
        // Without `HOME` (or `USERPROFILE` on Windows) the OS answer is used, as for `snow`.
        let none = crate::env::Env::default();
        let expected = std::env::home_dir().map_or_else(|| PathBuf::from("~/a"), |h| h.join("a"));
        assert_eq!(expand_user("~/a", &none), expected);
    }

    fn spool_text(path: &Path, warn: bool) -> (Result<()>, String) {
        let mut console = Vec::new();
        let env = crate::env::Env::default();
        let opened = open_spool(&path.display().to_string(), &env, warn, &mut console);
        (opened.map(drop), String::from_utf8(console).unwrap())
    }

    #[test]
    fn spool_is_created_owner_only_and_appended_to() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.txt");
        let (opened, console) = spool_text(&path, true);
        opened.unwrap();
        assert_eq!(console, "");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "{mode:o}");
        }
        std::fs::write(&path, "old\n").unwrap();
        let mut terminal = Vec::new();
        let mut sink = test_sink(
            &mut terminal,
            Some(
                open_spool(
                    &path.display().to_string(),
                    &crate::env::Env::default(),
                    false,
                    &mut Vec::new(),
                )
                .unwrap(),
            ),
            true,
        );
        sink.write_all(b"new\n").unwrap();
        sink.flush().unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "old\nnew\n");
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_spool_broader_than_owner_only_is_reported() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.txt");
        let shown = path.display();
        for (mode, detail) in [
            (
                0o644,
                "Other users on this machine can read query results written to this file.",
            ),
            (0o622, "Other users on this machine can write to this file."),
            (
                0o666,
                "Other users on this machine can read query results written to this file, and can write to it.",
            ),
        ] {
            std::fs::write(&path, "").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let (opened, console) = spool_text(&path, true);
            opened.unwrap();
            assert_eq!(
                console,
                format!("Spool file '{shown}' is broader than owner-only. {detail}\n")
            );
            assert_eq!(spool_text(&path, false).1, "", "no console, no warning");
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(spool_text(&path, true).1, "");
    }

    // Asserts the POSIX OS error texts (`ENOENT`, `EISDIR`); Windows words them differently
    #[cfg(unix)]
    #[test]
    fn an_unwritable_spool_is_a_client_error() {
        let dir = tempfile::tempdir().unwrap();
        let (opened, _) = spool_text(&dir.path().join("missing/out.txt"), true);
        let err = opened.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Client);
        assert_eq!(
            err.message(),
            format!(
                "Cannot write spool file '{}': No such file or directory",
                dir.path().join("missing/out.txt").display()
            )
        );
        let (opened, _) = spool_text(dir.path(), true);
        assert!(opened.unwrap_err().message().ends_with(": Is a directory"));
    }

    /// A writer that fails like a closed pipe, then counts what it was given.
    struct Closed;
    impl Write for Closed {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }

    #[test]
    fn a_closed_terminal_does_not_stop_the_spool() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.txt");
        let spool = open_spool(
            &path.display().to_string(),
            &crate::env::Env::default(),
            false,
            &mut Vec::new(),
        )
        .unwrap();
        let mut closed = Closed;
        let mut sink = test_sink(&mut closed, Some(spool), false);
        sink.write_all(b"abc").unwrap();
        let err = sink.flush().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "abc");
    }

    #[test]
    fn quiet_without_a_spool_discards_results_but_not_the_echo() {
        let mut terminal = Vec::new();
        {
            let mut sink = test_sink(&mut terminal, None, true);
            sink.echo(b"select 1\n").unwrap();
            sink.write_all(b"result\n").unwrap();
            sink.flush().unwrap();
        }
        assert_eq!(String::from_utf8(terminal).unwrap(), "select 1\n");
    }

    fn parsed(argv: &[&str]) -> SqlArgs {
        #[derive(clap::Parser)]
        struct Wrapper {
            #[command(flatten)]
            args: SqlArgs,
        }
        let argv = std::iter::once("sql").chain(argv.iter().copied());
        clap::Parser::try_parse_from(argv)
            .map(|w: Wrapper| w.args)
            .unwrap()
    }

    #[test]
    fn query_is_the_non_empty_q_text() {
        assert_eq!(query(&parsed(&["-q", "select 1"])), Some("select 1"));
        assert_eq!(query(&parsed(&["-q", ""])), None);
        assert_eq!(query(&parsed(&[])), None);
        assert!(any_source(&parsed(&["-q", "select 1"])));
        assert!(!any_source(&parsed(&["-q", ""])));
    }

    fn echo_printer(verbose_echo: bool) -> Printer {
        Printer {
            verbose_echo,
            repl: false,
            multi: false,
            script: ScriptOptions::default(),
            interrupt: None,
        }
    }

    #[test]
    fn echo_statement_prints_the_sanitized_text_on_the_console_only() {
        let mut terminal = Vec::new();
        {
            let mut sink = test_sink(&mut terminal, None, false);
            echo_printer(true)
                .echo_statement("select 1\u{1b}[31m", &mut sink)
                .unwrap();
            echo_printer(false)
                .echo_statement("select 2", &mut sink)
                .unwrap();
            sink.format = OutputFormat::Json;
            echo_printer(true)
                .echo_statement("select 3", &mut sink)
                .unwrap();
        }
        let text = String::from_utf8(terminal).unwrap();
        assert!(text.starts_with("select 1"), "{text:?}");
        assert!(!text.contains("select 2") && !text.contains("select 3"));
        assert!(!text.contains('\u{1b}'));
    }

    #[test]
    fn python_repr_quotes_like_click() {
        assert_eq!(py_repr("a.sql"), "'a.sql'");
        assert_eq!(py_repr("it's.sql"), "\"it's.sql\"");
        assert_eq!(py_repr("a'\"b\\\n"), "'a\\'\"b\\\\\\n'");
    }
}
