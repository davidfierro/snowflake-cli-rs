//! Config files and connection resolution, compatible with snow 3.34.0 (ADR 0001, Decision 3).

mod paths;
pub(crate) use paths::{expand_user_with, home_dir};
mod resolve;
mod source;
mod variables;
mod writer;

pub use resolve::resolve_connection;
pub use variables::config_variables;
pub use writer::{ConfigValue, ConfigWriter};

use std::path::PathBuf;

/// Where config.toml and connections.toml are read from (Decision 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigPaths {
    pub config_file: PathBuf,
    pub connections_file: PathBuf,
    /// true when config_file came from --config-file (permission problems only warn).
    pub config_file_is_custom: bool,
}

/// Parsed config.toml + connections.toml, after the permission checks.
///
/// The tables hold credentials, so `Debug` prints key and connection names only.
#[derive(Clone)]
pub struct ConfigSource {
    /// `config.toml`; empty when the file does not exist.
    config: toml::Table,
    /// Where `config` was read from; `None` when the file does not exist.
    config_path: Option<PathBuf>,
    /// The connections, in file order: the top-level tables of `connections.toml` when it
    /// exists, else the `[connections]` section of `config.toml`.
    connections: toml::Table,
}

impl std::fmt::Debug for ConfigSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigSource")
            .field("config_keys", &self.config.keys().collect::<Vec<_>>())
            .field("connections", &self.connections.keys().collect::<Vec<_>>())
            .finish()
    }
}
