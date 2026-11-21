//! Connection diagnostics: `--enable-diag`, `--diag-log-path`, `--diag-allowlist-path` and
//! `connection test --print-diag` (snow 3.34.0).
//!
//! `snow connection test --enable-diag` writes `SnowflakeConnectionTestReport.txt` in two
//! parts: the connector's report ([`connector`]), then snow's own per-endpoint section
//! ([`snow`]). `--print-diag` also prints the second part.

pub mod cert;
pub mod connector;
pub mod net;
pub mod snow;
#[cfg(test)]
pub(crate) mod testing;

use crate::cli::ConnectionOptions;
use crate::error::{Error, ErrorKind, Result};
use crate::sql::SqlClient;
use crate::sql::result::Value;
use std::path::{Path, PathBuf};

/// One row of a query: `(column name, text)`.
pub type Row = Vec<(String, Option<String>)>;

/// The SQL the diagnostics need, behind a seam: the allowlist and the network policy.
pub trait Query {
    fn rows(&self, sql: &str) -> std::result::Result<Vec<Row>, String>;
}

fn value_text(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::Text(s) | Value::Json(s) | Value::Decimal(s) => Some(s.clone()),
        Value::Int(i) => Some(i.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        other => Some(format!("{other:?}")),
    }
}

impl Query for SqlClient {
    fn rows(&self, sql: &str) -> std::result::Result<Vec<Row>, String> {
        let result = self.execute(sql).map_err(|e| e.to_string())?;
        Ok(rows_of(result))
    }
}

impl Query for crate::sql::Executor {
    fn rows(&self, sql: &str) -> std::result::Result<Vec<Row>, String> {
        match self {
            crate::sql::Executor::SqlApi(client) => client.rows(sql),
            crate::sql::Executor::Session(session, _) => session
                .query(sql)
                .and_then(|r| r.into_rows(session))
                .and_then(crate::sql::RowStream::into_result)
                .map(rows_of)
                .map_err(|e| e.to_string()),
        }
    }
}

fn rows_of(result: crate::sql::QueryResult) -> Vec<Row> {
    result
        .rows
        .iter()
        .map(|row| {
            result
                .columns
                .iter()
                .zip(row)
                .map(|(c, v)| (c.name.clone(), value_text(v)))
                .collect()
        })
        .collect()
}

/// Python's `repr()` of a list of strings.
pub(crate) fn py_list_repr(items: &[String]) -> String {
    let items: Vec<String> = items
        .iter()
        .map(|s| crate::output::result::py_str_repr(s))
        .collect();
    format!("[{}]", items.join(", "))
}

/// Opens the report file for writing (truncating, or appending), owner-only when it is created,
/// and never through a symlink: the default directory is the shared system temp dir.
pub(crate) fn open_report(path: &Path, append: bool) -> std::io::Result<std::fs::File> {
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(std::io::Error::other(format!(
            "{} is a symbolic link",
            path.display()
        )));
    }
    let mut options = crate::fsutil::private_options();
    options.create(true).write(true);
    if append {
        options.append(true);
    } else {
        options.truncate(true);
    }
    options.open(path)
}

/// `--enable-diag`, `--diag-log-path` and `--diag-allowlist-path`, resolved the way snow's option
/// callbacks do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagOptions {
    pub enabled: bool,
    /// Absolute; created when missing.
    pub log_dir: PathBuf,
    pub allowlist_path: Option<PathBuf>,
}

fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

impl DiagOptions {
    pub fn resolve(options: &ConnectionOptions) -> Result<Self> {
        let log_dir = match &options.diag_log_path {
            Some(path) => absolute(path),
            None => std::env::temp_dir(),
        };
        if options.diag_log_path.is_some() && !log_dir.exists() {
            std::fs::create_dir_all(&log_dir).map_err(|e| {
                Error::new(
                    ErrorKind::Client,
                    format!("Cannot create the directory {}: {e}", log_dir.display()),
                )
            })?;
        }
        let allowlist_path = match &options.diag_allowlist_path {
            Some(path) if !path.is_file() => {
                return Err(Error::new(
                    ErrorKind::Usage,
                    format!(
                        "Invalid value for '--diag-allowlist-path': File '{}' does not exist.",
                        path.display()
                    ),
                ));
            }
            Some(path) => Some(absolute(path)),
            None => None,
        };
        Ok(Self {
            enabled: options.enable_diag,
            log_dir,
            allowlist_path,
        })
    }

    /// Where the report goes, as `connection test` prints it.
    pub fn report_path(&self) -> PathBuf {
        self.log_dir.join(connector::REPORT_FILENAME)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_report_goes_to_the_temporary_directory_by_default() {
        let diag = DiagOptions::resolve(&ConnectionOptions::default()).unwrap();
        assert!(!diag.enabled);
        assert_eq!(diag.log_dir, std::env::temp_dir());
        assert_eq!(
            diag.report_path(),
            std::env::temp_dir().join("SnowflakeConnectionTestReport.txt")
        );
        assert_eq!(diag.allowlist_path, None);
    }

    #[test]
    fn a_given_log_path_is_made_absolute_and_created() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a/b");
        let options = ConnectionOptions {
            enable_diag: true,
            diag_log_path: Some(nested.clone()),
            ..ConnectionOptions::default()
        };
        let diag = DiagOptions::resolve(&options).unwrap();
        assert!(diag.enabled);
        assert_eq!(diag.log_dir, nested);
        assert!(nested.is_dir());

        let relative = ConnectionOptions {
            diag_log_path: Some(PathBuf::from("relative-dir-that-needs-no-creation")),
            ..ConnectionOptions::default()
        };
        // Cargo runs unit tests from the package root, which exists, but the directory below
        // it does not: it is created there, then removed.
        let diag = DiagOptions::resolve(&relative).unwrap();
        assert!(diag.log_dir.is_absolute());
        std::fs::remove_dir(&diag.log_dir).unwrap();
    }

    #[test]
    fn an_uncreatable_log_path_is_a_client_error() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, "x").unwrap();
        let options = ConnectionOptions {
            diag_log_path: Some(file.join("below-a-file")),
            ..ConnectionOptions::default()
        };
        let err = DiagOptions::resolve(&options).unwrap_err();
        assert!(err.to_string().contains("Cannot create the directory"));
    }

    #[test]
    fn the_allowlist_file_must_exist() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("allowlist.json");
        let options = ConnectionOptions {
            diag_allowlist_path: Some(file.clone()),
            ..ConnectionOptions::default()
        };
        let err = DiagOptions::resolve(&options).unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains(&format!(
            "Invalid value for '--diag-allowlist-path': File '{}' does not exist.",
            file.display()
        )));
        std::fs::write(&file, "[]").unwrap();
        assert_eq!(
            DiagOptions::resolve(&options).unwrap().allowlist_path,
            Some(file)
        );
    }

    #[cfg(unix)]
    #[test]
    fn reports_are_owner_only_and_never_written_through_a_symlink() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.txt");
        open_report(&path, false).unwrap().write_all(b"a").unwrap();
        open_report(&path, true).unwrap().write_all(b"b").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "ab");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        open_report(&path, false).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
        let target = dir.path().join("target.txt");
        std::fs::write(&target, "keep").unwrap();
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(
            open_report(&link, false)
                .unwrap_err()
                .to_string()
                .contains("symbolic link")
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
    }

    #[test]
    fn query_values_become_text() {
        assert_eq!(value_text(&Value::Null), None);
        assert_eq!(value_text(&Value::Text("a".into())).as_deref(), Some("a"));
        assert_eq!(value_text(&Value::Int(7)).as_deref(), Some("7"));
        assert_eq!(value_text(&Value::Bool(true)).as_deref(), Some("true"));
        assert_eq!(
            value_text(&Value::Decimal("1.50".into())).as_deref(),
            Some("1.50")
        );
        assert!(value_text(&Value::Float(1.5)).is_some());
    }

    #[test]
    fn lists_print_like_python() {
        assert_eq!(py_list_repr(&[]), "[]");
        assert_eq!(
            py_list_repr(&["a".into(), "it's".into()]),
            "['a', \"it's\"]"
        );
    }
}
