//! Editing `config.toml` / `connections.toml` the way `snow connection add|remove|set-default`
//! does, but preserving everything the user wrote: comments, key order and formatting.
//!
//! Every write is atomic (a temp file in the same directory, then a rename). New files are
//! created with mode 0600; an existing file keeps its mode.

use super::ConfigPaths;
use crate::error::{Error, ErrorKind, Result};
use std::path::{Path, PathBuf};
use toml_edit::{DocumentMut, Item, Table, Value};

const DEFAULT_CONNECTION_KEY: &str = "default_connection_name";

/// A value `connection add` writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigValue {
    Str(String),
    Int(i64),
    Bool(bool),
}

impl ConfigValue {
    fn to_value(&self) -> Value {
        match self {
            ConfigValue::Str(s) => Value::from(s.as_str()),
            ConfigValue::Int(i) => Value::from(*i),
            ConfigValue::Bool(b) => Value::from(*b),
        }
    }
}

/// Writes connections and the default connection name.
pub struct ConfigWriter<'a> {
    paths: &'a ConfigPaths,
}

impl<'a> ConfigWriter<'a> {
    pub fn new(paths: &'a ConfigPaths) -> Self {
        Self { paths }
    }

    /// The file connections are written to: `connections.toml` if it exists, else `config.toml`.
    pub fn connections_target(&self) -> &Path {
        if self.paths.connections_file.exists() {
            &self.paths.connections_file
        } else {
            &self.paths.config_file
        }
    }

    /// Adds connection `name` with `values` (written in the given order) and returns the file.
    pub fn add_connection(&self, name: &str, values: &[(&str, ConfigValue)]) -> Result<PathBuf> {
        let in_connections_file = self.paths.connections_file.exists();
        let path = self.connections_target().to_path_buf();
        edit(&path, |doc| {
            let had_content = !doc.as_table().is_empty();
            let parent = if in_connections_file {
                doc.as_table_mut()
            } else {
                connections_section(doc)?
            };
            if parent.contains_key(name) {
                return Err(duplicate(name));
            }
            let mut table = Table::new();
            for (key, value) in values {
                table.insert(key, Item::Value(value.to_value()));
            }
            if had_content {
                table.decor_mut().set_prefix("\n");
            }
            parent.insert(name, Item::Table(table));
            Ok(())
        })?;
        Ok(path)
    }

    /// Removes connection `name` and returns the file it was in. With `unset_default`, also
    /// removes `default_connection_name` from `config.toml`: when the connection is in that same
    /// file, both changes go in one atomic write. When it is in `connections.toml` they are two
    /// files, so two writes (the default first, as snow does).
    pub fn remove_connection(&self, name: &str, unset_default: bool) -> Result<PathBuf> {
        let in_connections_file = self.paths.connections_file.exists();
        let path = self.connections_target().to_path_buf();
        if unset_default && in_connections_file {
            self.unset_default_connection()?;
        }
        edit(&path, |doc| {
            let parent = if in_connections_file {
                Some(doc.as_table_mut() as &mut dyn toml_edit::TableLike)
            } else {
                doc.get_mut("connections").and_then(Item::as_table_like_mut)
            };
            let removed = match parent {
                Some(parent) => {
                    keep_header_comment(parent, name);
                    parent.remove(name).is_some()
                }
                None => false,
            };
            if removed {
                if unset_default && !in_connections_file {
                    doc.remove(DEFAULT_CONNECTION_KEY);
                }
                Ok(())
            } else {
                Err(Error::new(
                    ErrorKind::Client,
                    format!("Connection {name} is not configured"),
                ))
            }
        })?;
        Ok(path)
    }

    /// Sets `default_connection_name` in `config.toml`.
    pub fn set_default_connection(&self, name: &str) -> Result<()> {
        edit(&self.paths.config_file, |doc| {
            match doc.get_mut(DEFAULT_CONNECTION_KEY) {
                Some(Item::Value(old)) => {
                    let decor = old.decor().clone();
                    let mut new = Value::from(name);
                    *new.decor_mut() = decor;
                    *old = new;
                }
                _ => {
                    // snow writes the key first, then a blank line.
                    if let Some(table) = doc.iter_mut().next().and_then(|(_, i)| i.as_table_mut()) {
                        let prefix = table
                            .decor()
                            .prefix()
                            .and_then(|p| p.as_str())
                            .unwrap_or_default();
                        if !prefix.starts_with('\n') {
                            let prefix = format!("\n{prefix}");
                            table.decor_mut().set_prefix(prefix);
                        }
                    }
                    doc.insert(DEFAULT_CONNECTION_KEY, Item::Value(Value::from(name)));
                }
            }
            Ok(())
        })
    }

    /// Removes `default_connection_name` from `config.toml`, if present.
    pub fn unset_default_connection(&self) -> Result<()> {
        if !self.paths.config_file.exists() {
            return Ok(());
        }
        edit(&self.paths.config_file, |doc| {
            doc.remove(DEFAULT_CONNECTION_KEY);
            Ok(())
        })
    }
}

/// A comment paragraph above `[name]` that a blank line separates from it is the file's, not
/// the entry's: hand it to the next entry so removing `name` keeps it.
fn keep_header_comment(parent: &mut dyn toml_edit::TableLike, name: &str) {
    let prefix = match parent.get(name).and_then(Item::as_table) {
        Some(table) => table
            .decor()
            .prefix()
            .and_then(|p| p.as_str())
            .unwrap_or_default()
            .to_string(),
        None => return,
    };
    let Some(split) = prefix.rfind("\n\n") else {
        return;
    };
    let kept = &prefix[..split + 2];
    if kept.trim().is_empty() {
        return;
    }
    let next = parent
        .iter_mut()
        .skip_while(|(key, _)| *key != name)
        .nth(1)
        .and_then(|(_, item)| item.as_table_mut());
    if let Some(next) = next {
        let existing = next
            .decor()
            .prefix()
            .and_then(|p| p.as_str())
            .unwrap_or_default();
        let merged = format!("{kept}{}", existing.strip_prefix('\n').unwrap_or(existing));
        next.decor_mut().set_prefix(merged);
    }
}

fn duplicate(name: &str) -> Error {
    Error::new(
        ErrorKind::Usage,
        format!("Connection {name} already exists"),
    )
}

/// The `[connections]` table of `config.toml`, created (implicit) when missing.
fn connections_section(doc: &mut DocumentMut) -> Result<&mut Table> {
    if !doc.contains_key("connections") {
        let mut table = Table::new();
        table.set_implicit(true);
        doc.insert("connections", Item::Table(table));
    }
    doc.get_mut("connections")
        .and_then(Item::as_table_mut)
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Client,
                "Cannot add the connection: 'connections' in the configuration file is not a table",
            )
        })
}

/// Reads `path` (a new config file starts from snow's defaults), applies `change` and writes the
/// result atomically.
fn edit(path: &Path, change: impl FnOnce(&mut DocumentMut) -> Result<()>) -> Result<()> {
    let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => initial_contents(&path),
        Err(e) => return Err(io_error("Cannot read", &path, e)),
    };
    let mut doc: DocumentMut = text.parse().map_err(|e: toml_edit::TomlError| {
        // The parser message quotes the offending line, which may hold a secret: keep the
        // position only.
        let at = e
            .span()
            .map(|s| {
                let before = &text[..s.start.min(text.len())];
                let line = before.matches('\n').count() + 1;
                let col = before.chars().rev().take_while(|c| *c != '\n').count() + 1;
                format!(" at line {line} col {col}")
            })
            .unwrap_or_default();
        Error::new(
            ErrorKind::Client,
            format!("Configuration file seems to be corrupted.{at}"),
        )
    })?;
    change(&mut doc)?;
    write_atomic(&path, &doc.to_string())
}

/// What snow puts in a `config.toml` it creates.
fn initial_contents(path: &Path) -> String {
    let logs = path.parent().unwrap_or(Path::new("")).join("logs");
    let logs = Value::from(logs.display().to_string());
    format!(
        "[cli]\nignore_new_version_warning = false\nair_gapped = false\nauto_upgrade = false\n\
         auto_upgrade_allow_major = false\n\n[cli.logs]\nsave_logs = true\npath = {logs}\n\
         level = \"info\"\n"
    )
}

fn io_error(what: &str, path: &Path, source: std::io::Error) -> Error {
    Error::new(
        ErrorKind::Client,
        format!("{what} configuration file {}", path.display()),
    )
    .with_source(source)
}

/// Atomic replace (see [`crate::fsutil`]). A new file gets 0600, an existing one keeps its
/// permissions.
fn write_atomic(path: &Path, contents: &str) -> Result<()> {
    std::fs::create_dir_all(crate::fsutil::parent_dir(path))
        .map_err(|e| io_error("Cannot create the directory of", path, e))?;
    crate::fsutil::replace_atomic(path, contents.as_bytes(), true)
        .map_err(|e| io_error("Cannot write", path, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn paths(dir: &TempDir) -> ConfigPaths {
        ConfigPaths {
            config_file: dir.path().join("config.toml"),
            connections_file: dir.path().join("connections.toml"),
            config_file_is_custom: false,
        }
    }

    fn s(v: &str) -> ConfigValue {
        ConfigValue::Str(v.into())
    }

    fn read(dir: &TempDir, name: &str) -> String {
        std::fs::read_to_string(dir.path().join(name)).unwrap()
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    const COMMENTED: &str = "# my config\ndefault_connection_name = \"b\" # the default\n\n[cli]\n  # keep me\noutput_format = 'json'\n\n[connections.b]\n# about b\nuser   = \"bob\"  # inline\naccount = \"b1\"\n\n[connections.a]\naccount = \"a1\"\n";

    // Expects the TOML encoding of a POSIX path (a basic string); a Windows path with `\` is
    // written as a literal string, and the test also checks the 0600 mode.
    #[cfg(unix)]
    #[test]
    fn missing_file_and_directory_are_created_with_snow_defaults_and_0600() {
        let dir = TempDir::new().unwrap();
        let p = ConfigPaths {
            config_file: dir.path().join("deep/er/config.toml"),
            connections_file: dir.path().join("deep/er/connections.toml"),
            config_file_is_custom: false,
        };
        let file = ConfigWriter::new(&p)
            .add_connection(
                "dev",
                &[
                    ("account", s("acc")),
                    ("port", ConfigValue::Int(443)),
                    ("client_store_temporary_credential", ConfigValue::Bool(true)),
                ],
            )
            .unwrap();
        assert_eq!(file, p.config_file);
        let text = std::fs::read_to_string(&p.config_file).unwrap();
        let logs = dir.path().join("deep/er/logs");
        assert_eq!(
            text,
            format!(
                "[cli]\nignore_new_version_warning = false\nair_gapped = false\nauto_upgrade = false\nauto_upgrade_allow_major = false\n\n[cli.logs]\nsave_logs = true\npath = \"{}\"\nlevel = \"info\"\n\n[connections.dev]\naccount = \"acc\"\nport = 443\nclient_store_temporary_credential = true\n",
                logs.display()
            )
        );
        #[cfg(unix)]
        assert_eq!(mode(&p.config_file), 0o600);
    }

    #[test]
    fn add_to_config_toml_keeps_everything_else_byte_for_byte() {
        let dir = TempDir::new().unwrap();
        let p = paths(&dir);
        std::fs::write(&p.config_file, COMMENTED).unwrap();
        ConfigWriter::new(&p)
            .add_connection("c", &[("account", s("c1")), ("user", s("carl"))])
            .unwrap();
        assert_eq!(
            read(&dir, "config.toml"),
            format!("{COMMENTED}\n[connections.c]\naccount = \"c1\"\nuser = \"carl\"\n")
        );
    }

    #[test]
    fn add_creates_the_connections_section_when_missing() {
        let dir = TempDir::new().unwrap();
        let p = paths(&dir);
        std::fs::write(&p.config_file, "# only a comment\nx = 1\n").unwrap();
        ConfigWriter::new(&p)
            .add_connection("c", &[("account", s("c1"))])
            .unwrap();
        assert_eq!(
            read(&dir, "config.toml"),
            "# only a comment\nx = 1\n\n[connections.c]\naccount = \"c1\"\n"
        );
    }

    #[test]
    fn connections_toml_is_the_target_when_it_exists() {
        let dir = TempDir::new().unwrap();
        let p = paths(&dir);
        std::fs::write(&p.config_file, COMMENTED).unwrap();
        let existing = "# conns\n[z]  # zed\naccount = \"z\"\n";
        std::fs::write(&p.connections_file, existing).unwrap();
        let writer = ConfigWriter::new(&p);
        assert_eq!(writer.connections_target(), p.connections_file);
        writer.add_connection("c", &[("account", s("c"))]).unwrap();
        assert_eq!(
            read(&dir, "connections.toml"),
            format!("{existing}\n[c]\naccount = \"c\"\n")
        );
        assert_eq!(read(&dir, "config.toml"), COMMENTED);
        writer.remove_connection("c", false).unwrap();
        assert_eq!(read(&dir, "connections.toml"), existing);
    }

    #[test]
    fn duplicate_names_are_rejected() {
        let dir = TempDir::new().unwrap();
        let p = paths(&dir);
        std::fs::write(&p.config_file, COMMENTED).unwrap();
        let err = ConfigWriter::new(&p)
            .add_connection("a", &[("account", s("x"))])
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Usage);
        assert_eq!(err.message(), "Connection a already exists");
        assert_eq!(read(&dir, "config.toml"), COMMENTED);
    }

    #[test]
    fn remove_drops_only_the_entry() {
        let dir = TempDir::new().unwrap();
        let p = paths(&dir);
        std::fs::write(&p.config_file, COMMENTED).unwrap();
        let file = ConfigWriter::new(&p).remove_connection("a", false).unwrap();
        assert_eq!(file, p.config_file);
        let expected = COMMENTED.replace("\n[connections.a]\naccount = \"a1\"\n", "");
        assert_eq!(read(&dir, "config.toml"), expected);
    }

    #[test]
    fn remove_keeps_a_header_comment_separated_by_a_blank_line() {
        let dir = TempDir::new().unwrap();
        let p = paths(&dir);
        std::fs::write(
            &p.config_file,
            "# header\n\n# about a\n[connections.a]\naccount = \"a\"\n\n[connections.b]\naccount = \"b\"\n",
        )
        .unwrap();
        let writer = ConfigWriter::new(&p);
        writer.remove_connection("a", false).unwrap();
        assert_eq!(
            read(&dir, "config.toml"),
            "# header\n\n[connections.b]\naccount = \"b\"\n"
        );
        // The last entry has no successor: its comments go with it.
        writer.remove_connection("b", false).unwrap();
        // A comment that is not separated stays with its entry.
        std::fs::write(
            &p.config_file,
            "# only a\n[connections.a]\naccount = \"a\"\n[connections.b]\n",
        )
        .unwrap();
        writer.remove_connection("a", false).unwrap();
        assert_eq!(read(&dir, "config.toml"), "[connections.b]\n");
    }

    #[test]
    fn remove_unknown_name_or_missing_file_fails() {
        let dir = TempDir::new().unwrap();
        let p = paths(&dir);
        let writer = ConfigWriter::new(&p);
        let err = writer.remove_connection("nope", false).unwrap_err();
        assert_eq!(err.message(), "Connection nope is not configured");
        std::fs::write(&p.config_file, COMMENTED).unwrap();
        assert!(writer.remove_connection("nope", false).is_err());
        std::fs::write(&p.connections_file, "[z]\naccount = \"z\"\n").unwrap();
        assert!(writer.remove_connection("nope", false).is_err());
        assert_eq!(read(&dir, "connections.toml"), "[z]\naccount = \"z\"\n");
    }

    #[test]
    fn set_default_replaces_the_value_and_keeps_the_comment() {
        let dir = TempDir::new().unwrap();
        let p = paths(&dir);
        std::fs::write(&p.config_file, COMMENTED).unwrap();
        ConfigWriter::new(&p).set_default_connection("a").unwrap();
        assert_eq!(
            read(&dir, "config.toml"),
            COMMENTED.replace(
                "default_connection_name = \"b\" # the default",
                "default_connection_name = \"a\" # the default"
            )
        );
    }

    #[test]
    fn set_default_adds_the_key_at_the_top_when_missing() {
        let dir = TempDir::new().unwrap();
        let p = paths(&dir);
        std::fs::write(&p.config_file, "[connections.a]\naccount = \"a\"\n").unwrap();
        ConfigWriter::new(&p).set_default_connection("a").unwrap();
        let text = read(&dir, "config.toml");
        assert!(
            text.starts_with("default_connection_name = \"a\"\n"),
            "{text}"
        );
        assert!(
            text.ends_with("[connections.a]\naccount = \"a\"\n"),
            "{text}"
        );
    }

    #[test]
    fn set_default_without_a_file_creates_one() {
        let dir = TempDir::new().unwrap();
        let p = paths(&dir);
        ConfigWriter::new(&p).set_default_connection("a").unwrap();
        let text = read(&dir, "config.toml");
        assert!(text.starts_with("default_connection_name = \"a\"\n\n[cli]"));
    }

    #[test]
    fn unset_default_removes_the_key_only() {
        let dir = TempDir::new().unwrap();
        let p = paths(&dir);
        std::fs::write(&p.config_file, COMMENTED).unwrap();
        let writer = ConfigWriter::new(&p);
        writer.unset_default_connection().unwrap();
        let after = read(&dir, "config.toml");
        assert!(!after.contains("default_connection_name"));
        assert!(after.contains("[connections.b]\n# about b\nuser   = \"bob\"  # inline"));
        // Nothing to remove is fine.
        writer.unset_default_connection().unwrap();
        assert_eq!(read(&dir, "config.toml"), after);
        // No file: nothing is created.
        std::fs::remove_file(&p.config_file).unwrap();
        writer.unset_default_connection().unwrap();
        assert!(!p.config_file.exists());
    }

    #[cfg(unix)]
    #[test]
    fn existing_file_mode_is_kept_and_no_temp_file_is_left() {
        let dir = TempDir::new().unwrap();
        let p = paths(&dir);
        std::fs::write(&p.config_file, COMMENTED).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p.config_file, std::fs::Permissions::from_mode(0o640))
                .unwrap();
        }
        ConfigWriter::new(&p)
            .add_connection("c", &[("account", s("c"))])
            .unwrap();
        assert_eq!(mode(&p.config_file), 0o640);
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["config.toml"]);
    }

    #[test]
    fn removing_the_default_connection_unsets_the_default_in_one_write() {
        let dir = TempDir::new().unwrap();
        let p = paths(&dir);
        std::fs::write(&p.config_file, COMMENTED).unwrap();
        ConfigWriter::new(&p).remove_connection("b", true).unwrap();
        let text = read(&dir, "config.toml");
        assert!(!text.contains("default_connection_name"), "{text}");
        assert!(!text.contains("[connections.b]"), "{text}");
        assert!(text.contains("[connections.a]"), "{text}");
    }

    #[test]
    fn removing_a_connection_that_is_not_there_keeps_the_default() {
        let dir = TempDir::new().unwrap();
        let p = paths(&dir);
        std::fs::write(&p.config_file, COMMENTED).unwrap();
        assert!(ConfigWriter::new(&p).remove_connection("zz", true).is_err());
        assert_eq!(read(&dir, "config.toml"), COMMENTED);
    }

    #[test]
    fn removing_from_connections_toml_unsets_the_default_in_config_toml() {
        let dir = TempDir::new().unwrap();
        let p = paths(&dir);
        std::fs::write(&p.connections_file, "[a]\naccount = \"a\"\n").unwrap();
        std::fs::write(&p.config_file, "default_connection_name = \"a\"\n").unwrap();
        ConfigWriter::new(&p).remove_connection("a", true).unwrap();
        assert_eq!(read(&dir, "connections.toml"), "");
        assert_eq!(read(&dir, "config.toml"), "");
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_remove_with_unset_default_leaves_the_file_byte_for_byte() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let p = paths(&dir);
        std::fs::write(&p.config_file, COMMENTED).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let result = ConfigWriter::new(&p).remove_connection("b", true);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        if result.is_err() {
            assert_eq!(read(&dir, "config.toml"), COMMENTED);
        }
        // (Running as root, the write succeeds: nothing to assert then.)
    }

    fn tmp_files(dir: &TempDir) -> Vec<String> {
        let mut names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_stale_temp_file_does_not_block_writes() {
        let dir = TempDir::new().unwrap();
        let p = paths(&dir);
        std::fs::write(&p.config_file, COMMENTED).unwrap();
        // What the old writer left behind after a crash, and a guess at any other name.
        let stale = [
            format!(".config.toml.{}.tmp", std::process::id()),
            ".config.toml.1.tmp".to_string(),
        ];
        for name in &stale {
            std::fs::write(dir.path().join(name), "stale").unwrap();
        }
        let writer = ConfigWriter::new(&p);
        writer.add_connection("c", &[("account", s("c"))]).unwrap();
        writer.remove_connection("a", false).unwrap();
        assert!(read(&dir, "config.toml").contains("[connections.c]"));
        let mut expected = stale.to_vec();
        expected.sort();
        assert_eq!(tmp_files(&dir), expected, "stale files are left alone");
        for name in &stale {
            assert_eq!(read(&dir, name), "stale");
        }
    }

    #[test]
    fn a_failed_write_removes_its_temp_file() {
        let dir = TempDir::new().unwrap();
        // Renaming a file over a directory fails after the temp file exists.
        let target = dir.path().join("config.toml");
        std::fs::create_dir(&target).unwrap();
        let err = write_atomic(&target, "x = 1\n").unwrap_err();
        assert!(err.message().starts_with("Cannot write configuration file"));
        assert!(tmp_files(&dir).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_planted_symlink_is_never_followed() {
        let dir = TempDir::new().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "keep").unwrap();
        // Whatever name the writer picks, a link at a known name cannot capture it.
        std::os::unix::fs::symlink(&victim, dir.path().join(".config.toml.1.tmp")).unwrap();
        write_atomic(&dir.path().join("config.toml"), "x = 1\n").unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_write_leaves_the_original_untouched() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let p = paths(&dir);
        std::fs::write(&p.config_file, COMMENTED).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let result = ConfigWriter::new(&p).add_connection("c", &[("account", s("c"))]);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        if let Err(err) = result {
            assert_eq!(err.kind(), ErrorKind::Client);
            assert!(err.message().starts_with("Cannot write configuration file"));
            assert_eq!(read(&dir, "config.toml"), COMMENTED);
        }
        // (Running as root, the write succeeds: nothing to assert then.)
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_config_is_edited_in_place() {
        let dir = TempDir::new().unwrap();
        let real = dir.path().join("real.toml");
        std::fs::write(&real, "[connections.a]\naccount = \"a\"\n").unwrap();
        let link = dir.path().join("config.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let p = ConfigPaths {
            config_file: link.clone(),
            connections_file: dir.path().join("connections.toml"),
            config_file_is_custom: false,
        };
        ConfigWriter::new(&p).remove_connection("a", false).unwrap();
        assert!(link.is_symlink());
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "");
    }

    #[test]
    fn corrupted_file_reports_the_position_not_the_line() {
        let dir = TempDir::new().unwrap();
        let p = paths(&dir);
        std::fs::write(&p.config_file, "[a]\npassword = \"SECRET-MARKER\" = oops\n").unwrap();
        let err = ConfigWriter::new(&p)
            .add_connection("c", &[("account", s("c"))])
            .unwrap_err();
        assert!(
            err.message()
                .starts_with("Configuration file seems to be corrupted. at line 2")
                || err
                    .message()
                    .starts_with("Configuration file seems to be corrupted"),
            "{}",
            err.message()
        );
        assert!(!err.message().contains("SECRET-MARKER"));
    }

    #[test]
    fn connections_that_is_not_a_table_is_an_error() {
        let dir = TempDir::new().unwrap();
        let p = paths(&dir);
        std::fs::write(&p.config_file, "connections = 5\n").unwrap();
        let err = ConfigWriter::new(&p)
            .add_connection("c", &[("account", s("c"))])
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Client);
        assert_eq!(read(&dir, "config.toml"), "connections = 5\n");
    }

    #[test]
    fn unreadable_target_is_a_client_error() {
        let dir = TempDir::new().unwrap();
        let p = ConfigPaths {
            // A directory where the file should be: reading it fails with something other
            // than NotFound.
            config_file: dir.path().to_path_buf(),
            connections_file: dir.path().join("connections.toml"),
            config_file_is_custom: false,
        };
        let err = ConfigWriter::new(&p)
            .add_connection("c", &[("account", s("c"))])
            .unwrap_err();
        assert!(err.message().starts_with("Cannot read configuration file"));
    }

    #[test]
    fn special_names_are_quoted() {
        let dir = TempDir::new().unwrap();
        let p = paths(&dir);
        std::fs::write(&p.config_file, "").unwrap();
        ConfigWriter::new(&p)
            .add_connection("my conn.x", &[("account", s("a\"b"))])
            .unwrap();
        let text = read(&dir, "config.toml");
        let parsed: toml::Table = text.parse().unwrap();
        assert_eq!(
            parsed["connections"]["my conn.x"]["account"].as_str(),
            Some("a\"b")
        );
    }
}
