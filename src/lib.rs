//! Library half of the `snow-rs` binary: argument parsing and the entry point.

pub mod auth;
pub mod cli;
mod codec;
pub mod commands;
pub mod completion;
pub mod config;
pub mod connection;
pub mod diag;
pub mod diagnostics;
pub mod env;
pub mod error;
mod fsutil;
pub mod info;
pub mod matrix;
pub mod output;
pub mod project;
pub mod render;
pub mod repl;
pub mod report;
pub mod script;
pub mod secret;
pub mod session;
pub mod sql;
pub mod structure;
pub mod transfer;

use crate::commands::connection::ConnectionArgs;
use crate::commands::sql::{SqlArgs, USAGE_NAME};
use crate::commands::{Context, Prompter, TerminalPrompter};
use crate::config::{ConfigPaths, ConfigSource};
use crate::env::Env;
use crate::error::Result;
use crate::output::format::OutputFormat;
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use std::ffi::OsString;
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;

/// Command line interface of `snow-rs`.
#[derive(Debug, Parser)]
#[command(
    name = "snow-rs",
    disable_version_flag = true,
    about = "Rust port of the Snowflake CLI"
)]
pub struct Cli {
    /// Shows version of the Snowflake CLI
    #[arg(long)]
    pub version: bool,
    /// Prints a JSON catalog of commands, arguments, and options
    #[arg(long)]
    pub structure: bool,
    /// Shows information about the Snowflake CLI
    #[arg(long)]
    pub info: bool,
    #[arg(
        long,
        help = "Skip auto-upgrade for this invocation. Accepted and ignored: this binary has no auto-upgrade."
    )]
    pub no_auto_upgrade: bool,
    /// Specifies Snowflake CLI configuration file that should be used.
    #[arg(long, global = true, value_name = "PATH")]
    pub config_file: Option<PathBuf>,
    #[arg(long, help = "Install completion for the current shell.")]
    pub install_completion: bool,
    #[arg(
        long,
        help = "Show completion for the current shell, to copy it or customize the installation."
    )]
    pub show_completion: bool,
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// The command groups.
// One value per process, parsed once: its size does not matter.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Manages connections to Snowflake.
    Connection(ConnectionArgs),
    /// Executes SQL statements against Snowflake interactively or from a query, file, or
    /// standard input.
    Sql(SqlArgs),
}

/// Parses `args` (including the program name) and runs the CLI on the real process: environment,
/// terminal, stdout and stderr.
///
/// Returns the process exit code. `--help` and `--version` print to stdout
/// and return 0; invalid arguments print to stderr and return 2.
pub fn run<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let stdout = std::io::stdout();
    let width = stdout.is_terminal().then(terminal_size_columns).flatten();
    run_with(
        args,
        Env::from_process(),
        Stdin {
            is_tty: std::io::stdin().is_terminal(),
            reader: &mut std::io::stdin(),
        },
        &mut TerminalPrompter,
        width,
        &mut stdout.lock(),
        &mut std::io::stderr(),
    )
}

/// Width of the terminal from `COLUMNS`, the only source without a platform dependency.
fn terminal_size_columns() -> Option<usize> {
    std::env::var("COLUMNS").ok()?.trim().parse().ok()
}

/// Standard input: whether it is a terminal, and the reader (`snow-rs sql -i` and piped queries).
pub struct Stdin<'a> {
    pub is_tty: bool,
    pub reader: &'a mut dyn Read,
}

/// [`run`] with every process input injected.
pub fn run_with<I, T>(
    args: I,
    env: Env,
    stdin: Stdin<'_>,
    prompter: &mut dyn Prompter,
    terminal_width: Option<usize>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match parse(args) {
        Ok(cli) => cli,
        Err(err) => {
            let code = err.exit_code();
            // Printing can only fail on a closed pipe; nothing useful to do then.
            let _ = err.print();
            return code;
        }
    };
    if let Some(code) = root_option(&cli, &env, stdout, stderr) {
        return code;
    }
    let Some(command) = cli.command else {
        return 0;
    };
    let global = match &command {
        Command::Connection(args) => args.command.global(),
        Command::Sql(args) => &args.global,
    };
    let debug = global.debug;
    // The format of the feedback line until the command resolves it.
    let mut format = global.format.unwrap_or(OutputFormat::Table);
    let enhanced_exit_codes = global.enhanced_exit_codes(&env).unwrap_or(false);
    let mut ctx = Context {
        env,
        config_file: cli.config_file,
        // An invalid value is reported by `dispatch`, with exit code 2.
        enhanced_exit_codes,
        decimal_precision: None,
        stdin_is_tty: stdin.is_tty,
        prompter,
        stdout,
        stderr,
        terminal_width,
    };
    match dispatch(&command, stdin.reader, &mut format, &mut ctx) {
        Ok(()) => 0,
        Err(err) => {
            // Output already written goes out before the panel.
            let _ = ctx.stdout.flush();
            report::report_error(&err, debug, ctx.stderr);
            if report::wants_feedback(&err, format) {
                let _ = ctx.stderr.write_all(report::FEEDBACK.as_bytes());
            }
            err.exit_code_with(ctx.enhanced_exit_codes)
        }
    }
}

/// The root options that print something and exit, in snow's (click's eager) order. `None` when
/// none is given.
fn root_option(
    cli: &Cli,
    env: &Env,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Option<i32> {
    let write = |out: &mut dyn Write, text: &str| {
        // Printing can only fail on a closed pipe; nothing useful to do then.
        let _ = out.write_all(text.as_bytes());
        0
    };
    if cli.version {
        return Some(write(stdout, &info::version_line()));
    }
    if cli.structure {
        let catalog = structure::catalog(&Cli::command());
        return Some(write(stdout, &structure::to_json(&catalog)));
    }
    if cli.info {
        return Some(match info::info_json(env) {
            Ok(json) => write(stdout, &json),
            Err(err) => {
                report::report_error(&err, false, stderr);
                err.exit_code()
            }
        });
    }
    if cli.install_completion {
        return Some(completion::install(
            &Cli::command(),
            env,
            &completion::powershell_profile,
            stdout,
            stderr,
        ));
    }
    if cli.show_completion {
        return Some(completion::show(&Cli::command(), env, stdout, stderr));
    }
    None
}

/// Parses the arguments; for `sql`, also records the order of the source flags (snow names
/// the conflicting flags in that order).
fn parse<I, T>(args: I) -> std::result::Result<Cli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let matches = Cli::command().try_get_matches_from(args)?;
    let mut cli = Cli::from_arg_matches(&matches)?;
    if let (Some(Command::Sql(sql)), Some((USAGE_NAME, sub))) =
        (&mut cli.command, matches.subcommand())
    {
        sql.fill_source_order(sub);
    }
    Ok(cli)
}

fn dispatch(
    command: &Command,
    stdin: &mut dyn Read,
    format: &mut OutputFormat,
    ctx: &mut Context<'_>,
) -> Result<()> {
    let global = match command {
        Command::Connection(args) => args.command.global(),
        Command::Sql(args) => &args.global,
    };
    diag::init(global.verbosity());
    let paths = ConfigPaths::discover(&ctx.env, ctx.config_file.as_deref())?;
    let source = ConfigSource::load(&paths)?;
    ctx.enhanced_exit_codes = global.enhanced_exit_codes(&ctx.env)?;
    ctx.decimal_precision = global.decimal_precision(&source, &ctx.env)?;
    *format = global.output_format(&source, &ctx.env)?;
    match command {
        Command::Connection(args) => {
            let result = args.command.run(&paths, &source, *format, ctx)?;
            result.write(*format, ctx.terminal_width, ctx.stdout)
        }
        Command::Sql(args) => commands::sql::run(args, &paths, &source, format, stdin, ctx),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_args_succeeds() {
        assert_eq!(run(["snow-rs"]), 0);
    }

    #[test]
    fn version_and_help_exit_zero() {
        assert_eq!(run(["snow-rs", "--version"]), 0);
        assert_eq!(run(["snow-rs", "--help"]), 0);
    }

    #[test]
    fn root_options_parse() {
        let cli = Cli::try_parse_from([
            "snow-rs",
            "--no-auto-upgrade",
            "--info",
            "--structure",
            "--show-completion",
            "--install-completion",
            "--version",
        ])
        .unwrap();
        assert!(
            cli.no_auto_upgrade
                && cli.info
                && cli.structure
                && cli.show_completion
                && cli.install_completion
                && cli.version
        );
    }

    #[test]
    fn unknown_flag_exits_two() {
        assert_eq!(run(["snow-rs", "--nope"]), 2);
    }

    #[test]
    fn config_file_is_accepted() {
        let cli = Cli::try_parse_from(["snow-rs", "--config-file", "/x/config.toml"]).unwrap();
        assert_eq!(cli.config_file, Some(PathBuf::from("/x/config.toml")));
    }
}
