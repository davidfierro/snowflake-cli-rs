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
mod put_get;
mod repl;
mod sandbox;
mod secrets;
mod sign_in;
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
mod template_golden;
mod template_overhead;
