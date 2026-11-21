//! Loading `config.toml` and `connections.toml`: permission checks and TOML parsing.

use super::{ConfigPaths, ConfigSource};
use crate::env::Env;
use crate::error::{Error, ErrorKind, Result};
use std::path::Path;

impl ConfigSource {
    pub fn load(paths: &ConfigPaths) -> Result<Self> {
        let config = read_toml(&paths.config_file, paths.config_file_is_custom)?;
        let config_path = config.is_some().then(|| paths.config_file.clone());
        let config = config.unwrap_or_default();
        let connections = match read_toml(&paths.connections_file, false)? {
            // connections.toml replaces the whole [connections] section of config.toml.
            Some(connections) => {
                log::debug!(
                    "Reading connections from {}",
                    paths.connections_file.display()
                );
                connections
            }
            None => match config.get("connections") {
                Some(toml::Value::Table(t)) => t.clone(),
                Some(_) => {
                    log::warn!(
                        "Ignoring 'connections' in {}: it is not a table",
                        paths.config_file.display()
                    );
                    toml::Table::new()
                }
                None => toml::Table::new(),
            },
        };
        Ok(Self {
            config,
            config_path,
            connections,
        })
    }

    /// The parsed `config.toml` when `path` is the file this source read, so a caller that needs
    /// the same file does not read and parse it again.
    pub(crate) fn config_read_from(&self, path: &Path) -> Option<&toml::Table> {
        (self.config_path.as_deref() == Some(path)).then_some(&self.config)
    }

    /// `default_connection_name`: env SNOWFLAKE_DEFAULT_CONNECTION_NAME > config.toml > "default".
    pub fn default_connection_name(&self, env: &Env) -> String {
        if let Some(name) = env.get_non_empty("SNOWFLAKE_DEFAULT_CONNECTION_NAME") {
            return name.to_string();
        }
        match self.config.get("default_connection_name") {
            Some(toml::Value::String(name)) => name.clone(),
            _ => "default".to_string(),
        }
    }

    /// Connection names defined in the files, in file order.
    pub fn connection_names(&self) -> Vec<String> {
        self.connections
            .iter()
            .filter(|(_, v)| v.is_table())
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// The raw entry of connection `name` (a table, unless the file is malformed).
    pub(crate) fn connection(&self, name: &str) -> Option<&toml::Value> {
        self.connections.get(name)
    }

    /// A value of the `[cli]` section of config.toml.
    pub(crate) fn cli_value(&self, key: &str) -> Option<&toml::Value> {
        self.config.get("cli").and_then(|cli| cli.get(key))
    }

    /// `[cli] decimal_precision` from config.toml, as the text snow would try to cast to an int.
    pub(crate) fn cli_decimal_precision(&self) -> Option<String> {
        let value = self.config.get("cli")?.get("decimal_precision")?;
        Some(match value {
            toml::Value::String(s) => s.clone(),
            other => other.to_string(),
        })
    }

    /// `[cli] output_format` from config.toml.
    pub(crate) fn cli_output_format(&self) -> Result<Option<&str>> {
        let Some(value) = self
            .config
            .get("cli")
            .and_then(|cli| cli.get("output_format"))
        else {
            return Ok(None);
        };
        value.as_str().map(Some).ok_or_else(|| {
            Error::new(
                ErrorKind::Usage,
                "Invalid value for cli.output_format: it must be a string. Must be one of: TABLE, JSON, CSV, PLAIN.",
            )
        })
    }
}

/// Reads and parses one config file; `Ok(None)` when it does not exist.
fn read_toml(path: &Path, custom: bool) -> Result<Option<toml::Table>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Client,
                format!("Cannot read configuration file {}", path.display()),
            )
            .with_source(e));
        }
    };
    check_permissions(path, custom)?;
    log::debug!("Reading configuration from {}", path.display());
    text.parse::<toml::Table>()
        .map(Some)
        .map_err(|e| corrupted(&text, &e))
}

/// snow's message for a TOML syntax error. toml's `Display` quotes the offending line, which may
/// hold a secret, so only the parser message and the position are kept.
fn corrupted(text: &str, err: &toml::de::Error) -> Error {
    let mut message = format!(
        "Configuration file seems to be corrupted. {}",
        err.message().trim_end()
    );
    if let Some(span) = err.span() {
        let before = &text[..span.start.min(text.len())];
        let line = before.matches('\n').count() + 1;
        let col = before.chars().rev().take_while(|c| *c != '\n').count() + 1;
        message.push_str(&format!(" at line {line} col {col}"));
    }
    Error::new(ErrorKind::Client, message)
}

/// Decision 3.5: default files with any group/other bit are an error; a `--config-file` only
/// warns when group/other readable and fails when group/other writable.
#[cfg(unix)]
fn check_permissions(path: &Path, custom: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = std::fs::metadata(path)
        .map_err(|e| {
            Error::new(
                ErrorKind::Client,
                format!("Cannot read configuration file {}", path.display()),
            )
            .with_source(e)
        })?
        .permissions()
        .mode();
    let chmod = format!("chmod 0600 \"{}\"", path.display());
    if custom && mode & 0o022 == 0 {
        if mode & 0o044 != 0 {
            log::warn!(
                "Bad owner or permissions on {}.\n * To restrict permissions, run `{chmod}`.",
                path.display()
            );
        }
        return Ok(());
    }
    if mode & 0o077 != 0 {
        return Err(Error::new(
            ErrorKind::Client,
            format!(
                "Configuration file {} has too wide permissions. Run the command below exactly as printed.\n{chmod}",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path, _custom: bool) -> Result<()> {
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// A temp SNOWFLAKE_HOME with the given files, each written with mode 0600.
    pub(crate) fn home_with(files: &[(&str, &str)]) -> (TempDir, ConfigPaths) {
        let dir = TempDir::new().unwrap();
        for (name, content) in files {
            write_private(&dir.path().join(name), content);
        }
        let paths = ConfigPaths {
            config_file: dir.path().join("config.toml"),
            connections_file: dir.path().join("connections.toml"),
            config_file_is_custom: false,
        };
        (dir, paths)
    }

    fn write_private(path: &Path, content: &str) {
        std::fs::write(path, content).unwrap();
        set_mode(path, 0o600);
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(not(unix))]
    fn set_mode(_path: &Path, _mode: u32) {}

    #[test]
    fn missing_files_give_an_empty_source() {
        let (_dir, paths) = home_with(&[]);
        let source = ConfigSource::load(&paths).unwrap();
        assert!(source.connection_names().is_empty());
        assert_eq!(source.default_connection_name(&Env::default()), "default");
        assert_eq!(source.cli_output_format().unwrap(), None);
    }

    #[test]
    fn connections_come_from_config_toml_in_file_order() {
        let (_dir, paths) = home_with(&[(
            "config.toml",
            "[connections.zeta]\naccount = \"z\"\n[connections.alpha]\naccount = \"a\"\n",
        )]);
        let source = ConfigSource::load(&paths).unwrap();
        assert_eq!(source.connection_names(), ["zeta", "alpha"]);
    }

    #[test]
    fn connections_toml_replaces_config_toml_connections() {
        let (_dir, paths) = home_with(&[
            (
                "config.toml",
                "default_connection_name = \"b\"\n[connections.a]\naccount = \"from_config\"\n",
            ),
            ("connections.toml", "[b]\naccount = \"from_connections\"\n"),
        ]);
        let source = ConfigSource::load(&paths).unwrap();
        assert_eq!(source.connection_names(), ["b"]);
        assert!(source.connection("a").is_none());
        // config.toml's other settings still apply.
        assert_eq!(source.default_connection_name(&Env::default()), "b");
    }

    #[test]
    fn non_table_entries_are_not_connections() {
        let (_dir, paths) = home_with(&[(
            "config.toml",
            "[connections]\nloose = \"value\"\n[connections.real]\nuser = \"u\"\n",
        )]);
        let source = ConfigSource::load(&paths).unwrap();
        assert_eq!(source.connection_names(), ["real"]);
    }

    #[test]
    fn connections_that_is_not_a_table_is_ignored() {
        let (_dir, paths) = home_with(&[("config.toml", "connections = 5\n")]);
        let source = ConfigSource::load(&paths).unwrap();
        assert!(source.connection_names().is_empty());
    }

    #[test]
    fn default_connection_name_precedence() {
        let (_dir, paths) =
            home_with(&[("config.toml", "default_connection_name = \"from_file\"\n")]);
        let source = ConfigSource::load(&paths).unwrap();
        assert_eq!(source.default_connection_name(&Env::default()), "from_file");
        let env = Env::from_pairs([("SNOWFLAKE_DEFAULT_CONNECTION_NAME", "from_env")]);
        assert_eq!(source.default_connection_name(&env), "from_env");
        let empty = Env::from_pairs([("SNOWFLAKE_DEFAULT_CONNECTION_NAME", "")]);
        assert_eq!(source.default_connection_name(&empty), "from_file");
    }

    #[test]
    fn cli_decimal_precision_is_read_as_text() {
        for (config, expected) in [
            ("", None),
            ("[cli]\n", None),
            ("[cli]\ndecimal_precision = 4\n", Some("4")),
            ("[cli]\ndecimal_precision = \"7\"\n", Some("7")),
            ("[cli]\ndecimal_precision = true\n", Some("true")),
        ] {
            let (_dir, paths) = home_with(&[("config.toml", config)]);
            let source = ConfigSource::load(&paths).unwrap();
            assert_eq!(
                source.cli_decimal_precision().as_deref(),
                expected,
                "{config}"
            );
        }
    }

    #[test]
    fn cli_output_format_is_read_and_type_checked() {
        let (_dir, paths) = home_with(&[("config.toml", "[cli]\noutput_format = \"json\"\n")]);
        let source = ConfigSource::load(&paths).unwrap();
        assert_eq!(source.cli_output_format().unwrap(), Some("json"));

        let (_dir, paths) = home_with(&[("config.toml", "[cli]\noutput_format = 1\n")]);
        let err = ConfigSource::load(&paths)
            .unwrap()
            .cli_output_format()
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Usage);
    }

    #[test]
    fn corrupt_toml_reports_position_but_not_the_line() {
        let (_dir, paths) = home_with(&[(
            "config.toml",
            "[connections.a]\nprivate_key_raw = \"SECRET-MARKER\" = oops\n",
        )]);
        let err = ConfigSource::load(&paths).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Client);
        assert_eq!(err.exit_code(), 1);
        assert!(
            err.message()
                .starts_with("Configuration file seems to be corrupted. "),
            "{}",
            err.message()
        );
        assert!(
            err.message().contains("at line 2 col "),
            "{}",
            err.message()
        );
        assert!(!err.message().contains("SECRET-MARKER"));
    }

    #[test]
    fn corrupt_connections_toml_is_an_error_too() {
        let (_dir, paths) = home_with(&[("connections.toml", "[a\n")]);
        let err = ConfigSource::load(&paths).unwrap_err();
        assert!(err.message().contains("corrupted"));
    }

    #[test]
    fn unreadable_path_is_a_client_error() {
        // A directory where the file should be: exists, but cannot be read as a file.
        let dir = TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("config.toml")).unwrap();
        let paths = ConfigPaths {
            config_file: dir.path().join("config.toml"),
            connections_file: dir.path().join("connections.toml"),
            config_file_is_custom: false,
        };
        let err = ConfigSource::load(&paths).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Client);
        assert!(err.message().starts_with("Cannot read configuration file"));
        assert!(std::error::Error::source(&err).is_some());
    }

    #[cfg(unix)]
    mod permissions {
        use super::*;

        fn load_with_mode(file: &str, mode: u32, custom: bool) -> Result<ConfigSource> {
            let (dir, mut paths) = home_with(&[(file, "[x]\n")]);
            let path: PathBuf = dir.path().join(file);
            set_mode(&path, mode);
            if custom {
                paths.config_file = path;
                paths.config_file_is_custom = true;
            }
            let result = ConfigSource::load(&paths);
            drop(dir);
            result
        }

        #[test]
        fn default_files_with_any_group_or_other_bit_fail() {
            for file in ["config.toml", "connections.toml"] {
                for mode in [0o640, 0o604, 0o620, 0o602, 0o610, 0o601, 0o644] {
                    let err = load_with_mode(file, mode, false).unwrap_err();
                    assert_eq!(err.kind(), ErrorKind::Client, "{file} {mode:o}");
                    assert!(err.message().contains("has too wide permissions"));
                    assert!(err.message().contains("chmod 0600 \""), "{}", err.message());
                }
            }
        }

        #[test]
        fn default_files_with_owner_only_bits_load() {
            for mode in [0o600, 0o400, 0o700] {
                assert!(load_with_mode("config.toml", mode, false).is_ok());
            }
        }

        #[test]
        fn custom_config_file_readable_by_others_only_warns() {
            for mode in [0o644, 0o640, 0o604, 0o600, 0o611] {
                assert!(
                    load_with_mode("custom.toml", mode, true).is_ok(),
                    "{mode:o}"
                );
            }
        }

        #[test]
        fn custom_config_file_writable_by_others_fails() {
            for mode in [0o620, 0o602, 0o666] {
                let err = load_with_mode("custom.toml", mode, true).unwrap_err();
                assert!(err.message().contains("has too wide permissions"));
            }
        }
    }
}
