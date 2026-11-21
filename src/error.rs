//! Error type shared by every module, and the process exit code.

use std::fmt;

/// Failure class. The default exit code is 2 for `Usage`, 1 for the rest. With
/// `--enhanced-exit-codes` ([`Error::exit_code_with`]) snow 3.34.0 exits 5 for SQL failures; for
/// the other classes it matches the default, because the commands ported so far only meet
/// connector failures, which snow reports as plain client errors (exit 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Bad command-line arguments (enhanced: 2).
    Usage,
    /// Config, key or other client-side problem (enhanced: 1).
    Client,
    /// An invalid argument value found after parsing, or a `snowflake.yml` that cannot be read: snow's
    /// `CliArgumentError`: an error panel
    /// without `Usage:` lines, exit code 1 (enhanced: 2).
    Argument,
    /// Could not reach Snowflake: DNS, TCP, TLS (enhanced: 1, as snow's connector errors).
    Connection,
    /// Unexpected HTTP status, malformed response, timeout, 401 (enhanced: 1, as above).
    Communication,
    /// Snowflake rejected the statement (HTTP 422), or a script could not be rendered (enhanced: 5).
    Sql,
    /// The private key is encrypted and no passphrase was given, so a command may ask for one.
    /// Exit code 1, as `Client`.
    MissingPassphrase,
    /// The user aborted a prompt (Ctrl-D / EOF). snow prints a bare `Aborted.` and exits 1.
    Aborted,
    /// An exception snow does not expect (a template syntax error, …): snow prints `An
    /// unexpected exception occurred. …` and the message as a warning on stdout, then exits 1
    /// with no panel. The caller prints that text; the report adds nothing but the feedback line.
    Unexpected,
}

/// An error with a user-facing message.
///
/// `message` is printed on stderr. It and every `source` in the chain must be
/// free of secrets: build them from names, paths, codes and server messages,
/// never from a [`crate::secret::Secret`] or a request header/body.
#[derive(Debug, thiserror::Error)]
pub struct Error {
    kind: ErrorKind,
    message: String,
    /// Command path whose `Usage:` lines precede the panel (click's `UsageError`).
    usage: Option<String>,
    /// snow adds its feedback line after the panel (not for a plain click exception).
    feedback: bool,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl Error {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            usage: None,
            feedback: true,
            source: None,
        }
    }

    /// No feedback line after the panel, as for snow's plain `ClickException`s.
    pub fn without_feedback(mut self) -> Self {
        self.feedback = false;
        self
    }

    pub fn has_feedback(&self) -> bool {
        self.feedback
    }

    /// Attaches the underlying cause, shown only under `--debug`.
    pub fn with_source(mut self, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    /// Prints `Usage: snow-rs <command> [OPTIONS]` and the `--help` hint before the panel, as click
    /// does for a usage error.
    pub fn with_usage(mut self, command: impl Into<String>) -> Self {
        self.usage = Some(command.into());
        self
    }

    pub fn usage(&self) -> Option<&str> {
        self.usage.as_deref()
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    /// Exit code without `--enhanced-exit-codes`: 2 for usage, else 1.
    pub fn exit_code(&self) -> i32 {
        self.exit_code_with(false)
    }

    /// Exit code, differentiated by failure class when `enhanced` (`--enhanced-exit-codes`).
    pub fn exit_code_with(&self, enhanced: bool) -> i32 {
        match self.kind {
            ErrorKind::Usage => 2,
            ErrorKind::Sql if enhanced => 5,
            ErrorKind::Argument if enhanced => 2,
            _ => 1,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_default_and_enhanced() {
        for (kind, plain, enhanced) in [
            (ErrorKind::Usage, 2, 2),
            (ErrorKind::Client, 1, 1),
            (ErrorKind::Argument, 1, 2),
            (ErrorKind::Unexpected, 1, 1),
            (ErrorKind::Connection, 1, 1),
            (ErrorKind::Communication, 1, 1),
            (ErrorKind::Sql, 1, 5),
            (ErrorKind::MissingPassphrase, 1, 1),
            (ErrorKind::Aborted, 1, 1),
        ] {
            let err = Error::new(kind, "x");
            assert_eq!(err.exit_code(), plain, "{kind:?}");
            assert_eq!(err.exit_code_with(false), plain, "{kind:?}");
            assert_eq!(err.exit_code_with(true), enhanced, "{kind:?}");
        }
    }
}
