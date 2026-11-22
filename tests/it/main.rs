//! The integration tests: one binary, one module per area (see CLAUDE.md).
#![allow(clippy::unwrap_used, clippy::expect_used)] // test crate

mod cli;
mod command_matrix;
mod common;
mod connection;
mod connection_diag;
mod connector_sign_in;
mod global_options;
mod golden;
// The naming check is a bash script that CI runs on Linux.
#[cfg(unix)]
mod naming;
mod put_get;
// The REPL tests drive a pty through rexpect, which is Unix-only.
#[cfg(unix)]
mod repl;
mod sandbox;
mod secrets;
mod sign_in;
// The goldens hold `<root>/files/…` paths; Windows canonical paths (`\\?\C:\…`) and `\` do not match them.
#[cfg(unix)]
mod source_golden;
mod split_golden;
mod sql_async;
mod sql_cli;
mod sql_client;
mod sql_golden;
mod sql_script;
mod sql_secrets;
mod sql_source_cli;
mod sql_stream;
// The goldens hold snow's POSIX path texts (`PosixPath('…/project/nope.txt')`) and read `HOME`; Windows paths and `USERPROFILE` differ.
#[cfg(unix)]
mod template_golden;
mod template_overhead;
