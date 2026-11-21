//! `!source` / `!load`: the directive parser and the loaders of files and URLs, as `snow` 3.34.0
//! does them (`statement_reader.py`: `COMMAND_PATTERN`, `parse_statement`, `ParsedStatement`).
//!
//! The parser is separate from the loading so the interactive session can add its own `!`
//! commands: it returns [`Directive::Repl`] for the commands `snow` registers.

use super::split::{py_strip, split_statements};
use regex::Regex;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

/// Bounds of the `!source` expansion (`SQL_SOURCE_MAX_DEPTH`, `SQL_SOURCE_MAX_INCLUDES`).
pub const MAX_DEPTH: usize = 32;
pub const MAX_INCLUDES: usize = 32;
/// `DEFAULT_SIZE_LIMIT_MB`: the largest file or URL payload read.
pub const SIZE_LIMIT_MB: u64 = 128;
const URL_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REDIRECTS: usize = 10;

/// The commands `snow` registers for the interactive session (`repl_commands.py`).
const REPL_COMMANDS: [&str; 7] = [
    "queries", "result", "abort", "set", "spool", "edit", "rehash",
];

/// What a statement that starts with `!` means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Directive {
    /// `!source`/`!load` of a local path, as written (quotes removed).
    File(String),
    /// `!source`/`!load` of an `https://` URL.
    Url(String),
    /// A registered interactive-session command (its name, lower case).
    Repl(String),
    /// Not usable: the error `snow` reports.
    Invalid(String),
}

fn command_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        // `^!(\w+)\s*["']?(.*?)["']?\s*(?:;|$)`; Python's `$` after `\s*` is the end.
        #[allow(clippy::unwrap_used)] // a constant pattern, checked by the tests
        Regex::new(r#"(?i)^!(\w+)\s*["']?(.*?)["']?\s*(?:;|\z)"#).unwrap()
    })
}

/// The lower-case scheme of `text` when it matches `^(\w+?):\/(\/.*)`.
fn url_scheme(text: &str) -> Option<String> {
    let lower = text.to_lowercase();
    let end = lower
        .char_indices()
        .find(|(_, c)| !(c.is_alphanumeric() || *c == '_'))
        .map_or(lower.len(), |(i, _)| i);
    (end > 0 && lower[end..].starts_with("://")).then(|| lower[..end].to_string())
}

/// `parse_statement` after the templating: `None` for a statement that is plain SQL.
/// `local_only` is `--local-only`.
pub fn parse(statement: &str, local_only: bool) -> Option<Directive> {
    let caps = command_pattern().captures(statement)?;
    let command = py_strip(&caps[1]);
    let args = py_strip(&caps[2]);
    let scheme = url_scheme(args);
    let lower = command.to_lowercase();
    Some(match (lower.as_str(), scheme.as_deref()) {
        ("source" | "load", Some("http")) => Directive::Invalid(format!(
            "Plaintext http:// sources are not allowed: {args}. Use https:// or a local file."
        )),
        ("source" | "load", Some("https")) if local_only => Directive::Invalid(format!(
            "Loading SQL from URLs is disabled (--local-only): {}",
            drop_comments(args)
        )),
        ("source" | "load", Some("https")) => Directive::Url(args.to_string()),
        ("source" | "load", None) => Directive::File(args.to_string()),
        ("source" | "load", Some(_)) => Directive::Invalid(format!("Unknown source: {args}")),
        (name, None) if REPL_COMMANDS.contains(&name) => Directive::Repl(name.to_string()),
        _ => Directive::Invalid(format!("Unknown command: {command}")),
    })
}

/// `drop_comments_from_path_parts`: the first statement of the path part, comments removed.
/// `None` where `snow` raises `StopIteration` (an empty path).
pub fn drop_comments_opt(path_part: &str) -> Option<String> {
    split_statements(path_part, true)
        .into_iter()
        .next()
        .map(|p| p.text)
}

fn drop_comments(path_part: &str) -> String {
    drop_comments_opt(path_part).unwrap_or_default()
}

/// Reads the content of a `!source`/`!load` target. Errors are the messages `snow` reports.
pub trait Sources {
    /// The identity of a local file for the cycle check (`Path.resolve()`).
    fn canonical(&self, path: &str) -> String;
    /// The text of a local file. `path_part` is the argument as written, for the message.
    fn read_file(&self, path: &str, path_part: &str) -> Result<String, String>;
    /// The text of an `https://` URL.
    fn fetch_url(&self, url: &str, path_part: &str) -> Result<String, String>;
}

/// Files from the disk and URLs over HTTPS.
#[derive(Debug, Clone, Default)]
pub struct FsSources {
    /// `~` in a path: the home directory (`os.path.expanduser`).
    pub home: Option<PathBuf>,
}

impl FsSources {
    fn expand(&self, path: &str) -> PathBuf {
        crate::config::expand_user_with(path, self.home.as_deref())
    }
}

impl Sources for FsSources {
    fn canonical(&self, path: &str) -> String {
        resolve(&self.expand(path)).display().to_string()
    }

    fn read_file(&self, path: &str, path_part: &str) -> Result<String, String> {
        let path = self.expand(path);
        let cannot = || format!("Could not read: {path_part}");
        if !path.is_file() {
            return Err(cannot());
        }
        let limit = SIZE_LIMIT_MB * 1024 * 1024;
        let file = std::fs::File::open(&path).map_err(|_| cannot())?;
        let mut bytes = Vec::new();
        file.take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| cannot())?;
        if bytes.len() as u64 > limit {
            return Err(format!(
                "Could not read: {path_part} (exceeds {SIZE_LIMIT_MB} MB limit)"
            ));
        }
        String::from_utf8(bytes).map_err(|_| cannot())
    }

    fn fetch_url(&self, url: &str, path_part: &str) -> Result<String, String> {
        fetch(url, path_part, true)
    }
}

/// `Path.resolve()`: absolute, symlinks resolved when the path exists.
pub fn resolve(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir().unwrap_or_default().join(path)
        };
        let mut out = PathBuf::new();
        for part in absolute.components() {
            match part {
                std::path::Component::ParentDir => {
                    out.pop();
                }
                std::path::Component::CurDir => {}
                other => out.push(other),
            }
        }
        out
    })
}

fn plaintext(url: &str) -> String {
    format!("Plaintext http:// sources are not allowed: {url}. Use https:// or a local file.")
}

/// `ParsedStatement.from_url`: GET with a 10 s timeout; a redirect or final URL that is not
/// `https://` is refused when `https_only`.
pub(crate) fn fetch(url: &str, path_part: &str, https_only: bool) -> Result<String, String> {
    let url = drop_comments(url);
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_connect(Some(URL_TIMEOUT))
        .timeout_recv_response(Some(URL_TIMEOUT))
        .timeout_recv_body(Some(URL_TIMEOUT))
        .user_agent("Python-urllib/3.13")
        .build()
        .into();
    let failed = |reason: String| format!("Could not fetch {path_part}: {reason}");
    let mut current = url;
    for _ in 0..=MAX_REDIRECTS {
        let response = agent
            .get(&current)
            .call()
            .map_err(|e| failed(describe(&e)))?;
        let status = response.status().as_u16();
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            let location = response
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let Some(location) = location else {
                return Err(failed(http_error(status)));
            };
            let next = join_url(&current, &location);
            if https_only && !next.to_lowercase().starts_with("https://") {
                return Err(plaintext(&next));
            }
            current = next;
            continue;
        }
        if !(200..300).contains(&status) {
            return Err(failed(http_error(status)));
        }
        if https_only && !current.to_lowercase().starts_with("https://") {
            return Err(plaintext(&current));
        }
        let limit = SIZE_LIMIT_MB * 1024 * 1024;
        let mut bytes = Vec::new();
        let mut body = response.into_body();
        body.as_reader()
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| failed(describe_io(&e)))?;
        if bytes.len() as u64 > limit {
            return Err(failed(format!("payload exceeds {SIZE_LIMIT_MB} MB limit")));
        }
        return String::from_utf8(bytes).map_err(|_| failed("invalid UTF-8".into()));
    }
    Err(failed(format!(
        "HTTP Error {}: The HTTP server returned a redirect error that would lead to an infinite loop.",
        302
    )))
}

fn http_error(status: u16) -> String {
    let reason = ureq::http::StatusCode::from_u16(status)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("");
    format!("HTTP Error {status}: {reason}")
}

/// Python's text of the same failure: `<urlopen error [Errno 111] Connection refused>`.
fn describe(err: &ureq::Error) -> String {
    match err {
        ureq::Error::Timeout(_) => "timed out".into(),
        ureq::Error::Io(io) => describe_io(io),
        other => format!("<urlopen error {other}>"),
    }
}

fn describe_io(err: &std::io::Error) -> String {
    if err.kind() == std::io::ErrorKind::TimedOut {
        return "timed out".into();
    }
    match err.raw_os_error() {
        Some(code) => {
            let text = err.to_string();
            let text = text.split(" (os error").next().unwrap_or(&text);
            format!("<urlopen error [Errno {code}] {text}>")
        }
        None => format!("<urlopen error {err}>"),
    }
}

/// `urllib.parse.urljoin` for a redirect `Location` (absolute, scheme-relative, absolute path
/// or relative to the directory of `base`).
fn join_url(base: &str, location: &str) -> String {
    if url_scheme(location).is_some() {
        return location.to_string();
    }
    let (scheme, rest) = base.split_once("://").unwrap_or(("https", base));
    if let Some(network) = location.strip_prefix("//") {
        return format!("{scheme}://{network}");
    }
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if location.starts_with('/') {
        return format!("{scheme}://{host}{location}");
    }
    let dir = &path[..path.rfind('/').map_or(0, |i| i + 1)];
    format!("{scheme}://{host}{dir}{location}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::MockServer;

    fn parsed(text: &str) -> Option<Directive> {
        parse(text, false)
    }

    #[test]
    fn plain_sql_and_a_bang_without_a_word_are_not_directives() {
        assert_eq!(parsed("select 1"), None);
        assert_eq!(parsed("! x"), None);
        // The pattern needs the argument to end the statement: a second line is SQL.
        assert_eq!(parsed("!source a.sql\nselect 1"), None);
    }

    #[test]
    fn source_and_load_take_a_path_with_or_without_quotes_and_a_semicolon() {
        for text in [
            "!source a.sql",
            "!SOURCE a.sql;",
            "!load 'a.sql'",
            "!source \"a.sql\" ;",
            "!source   a.sql  \n",
        ] {
            assert_eq!(
                parsed(text),
                Some(Directive::File("a.sql".into())),
                "{text}"
            );
        }
        assert_eq!(
            parsed("!source my dir/a b.sql"),
            Some(Directive::File("my dir/a b.sql".into()))
        );
        assert_eq!(parsed("!source"), Some(Directive::File(String::new())));
    }

    #[test]
    fn urls_are_https_only_and_local_only_disables_them() {
        assert_eq!(
            parsed("!source https://h/a.sql"),
            Some(Directive::Url("https://h/a.sql".into()))
        );
        assert_eq!(
            parsed("!load HTTPS://h/a.sql"),
            Some(Directive::Url("HTTPS://h/a.sql".into()))
        );
        assert_eq!(
            parse("!source https://h/a.sql -- c", true),
            Some(Directive::Invalid(
                "Loading SQL from URLs is disabled (--local-only): https://h/a.sql".into()
            ))
        );
        assert_eq!(
            parsed("!source http://h/a.sql"),
            Some(Directive::Invalid(
                "Plaintext http:// sources are not allowed: http://h/a.sql. Use https:// or a local file.".into()
            ))
        );
        for text in ["!source ftp://h/a", "!source file:///etc/passwd"] {
            let Some(Directive::Invalid(message)) = parsed(text) else {
                panic!("{text}");
            };
            assert!(message.starts_with("Unknown source: "), "{message}");
        }
        // A path with `:/` but not `://` is a file.
        assert_eq!(
            parsed("!source c:/a.sql"),
            Some(Directive::File("c:/a.sql".into()))
        );
    }

    #[test]
    fn registered_session_commands_are_repl_and_others_unknown() {
        for name in REPL_COMMANDS {
            assert_eq!(
                parsed(&format!("!{} x", name.to_uppercase())),
                Some(Directive::Repl(name.into()))
            );
        }
        assert_eq!(
            parsed("!nope x"),
            Some(Directive::Invalid("Unknown command: nope".into()))
        );
        // A URL among the arguments of a session command is not accepted.
        assert_eq!(
            parsed("!set http://x"),
            Some(Directive::Invalid("Unknown command: set".into()))
        );
    }

    #[test]
    fn comments_are_dropped_from_the_path() {
        assert_eq!(drop_comments_opt("a.sql -- note").as_deref(), Some("a.sql"));
        assert_eq!(drop_comments_opt(""), None);
        assert_eq!(drop_comments(""), "");
    }

    #[test]
    fn files_are_read_from_the_disk_with_tilde_and_resolve_to_one_identity() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.sql"), "select 1;").unwrap();
        let sources = FsSources {
            home: Some(dir.path().to_path_buf()),
        };
        assert_eq!(
            sources.read_file("~/a.sql", "~/a.sql").unwrap(),
            "select 1;"
        );
        assert_eq!(
            sources.canonical("~/a.sql"),
            // Canonical root: `x` does not exist, so the path is normalised lexically, and a
            // temp dir behind a symlink (macOS `/var` -> `/private/var`) must match `~` expansion.
            sources.canonical(&format!(
                "{}/x/../a.sql",
                dir.path().canonicalize().unwrap().display()
            ))
        );
        assert_eq!(
            sources
                .read_file("~/missing.sql", "~/missing.sql")
                .unwrap_err(),
            "Could not read: ~/missing.sql"
        );
        assert_eq!(sources.expand("~"), dir.path());
        assert_eq!(sources.expand("~other/x"), PathBuf::from("~other/x"));
        let no_home = FsSources::default();
        assert_eq!(no_home.expand("~/a"), PathBuf::from("~/a"));
        // A directory and invalid UTF-8 are not readable files.
        assert!(sources.read_file("~", "~").is_err());
        std::fs::write(dir.path().join("bin"), [0xff, 0xfe]).unwrap();
        assert_eq!(
            sources.read_file("~/bin", "bin").unwrap_err(),
            "Could not read: bin"
        );
        assert!(sources.fetch_url("https://127.0.0.1:1/", "u").is_err());
    }

    #[test]
    fn resolve_normalizes_a_path_that_does_not_exist() {
        let resolved = resolve(Path::new("/nonexistent-dir/../x/./y.sql"));
        assert_eq!(resolved, PathBuf::from("/x/y.sql"));
        let relative = resolve(Path::new("nonexistent-file.sql"));
        assert!(relative.is_absolute());
    }

    #[test]
    fn urls_are_fetched_and_failures_have_pythons_text() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.path("/ok.sql");
            then.status(200).body("select 1;");
        });
        server.mock(|when, then| {
            when.path("/missing.sql");
            then.status(404);
        });
        server.mock(|when, then| {
            when.path("/bad.sql");
            then.status(200).body(vec![0xff, 0xfe]);
        });
        let url = |p: &str| server.url(p);
        assert_eq!(fetch(&url("/ok.sql"), "u", false).unwrap(), "select 1;");
        assert_eq!(
            fetch(&url("/missing.sql"), "p", false).unwrap_err(),
            "Could not fetch p: HTTP Error 404: Not Found"
        );
        assert_eq!(
            fetch(&url("/bad.sql"), "p", false).unwrap_err(),
            "Could not fetch p: invalid UTF-8"
        );
        // The final URL must be https.
        assert_eq!(
            fetch(&url("/ok.sql"), "p", true).unwrap_err(),
            plaintext(&url("/ok.sql"))
        );
    }

    #[test]
    fn redirects_are_followed_but_never_to_plaintext() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.path("/final.sql");
            then.status(200).body("select 2;");
        });
        server.mock(|when, then| {
            when.path("/hop");
            then.status(302).header("location", "/final.sql");
        });
        server.mock(|when, then| {
            when.path("/loop");
            then.status(302).header("location", "/loop");
        });
        server.mock(|when, then| {
            when.path("/nowhere");
            then.status(302);
        });
        assert_eq!(fetch(&server.url("/hop"), "u", false).unwrap(), "select 2;");
        // With https only, the redirect target (http here) is refused before it is requested.
        assert_eq!(
            fetch(&server.url("/hop"), "u", true).unwrap_err(),
            plaintext(&server.url("/final.sql"))
        );
        assert!(
            fetch(&server.url("/loop"), "u", false)
                .unwrap_err()
                .contains("redirect")
        );
        assert_eq!(
            fetch(&server.url("/nowhere"), "p", false).unwrap_err(),
            "Could not fetch p: HTTP Error 302: Found"
        );
    }

    #[test]
    fn an_unreachable_url_reports_the_os_error() {
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let message = fetch(&format!("https://127.0.0.1:{port}/a.sql"), "u", true).unwrap_err();
        // The errno and its text are the OS's: 111 on Linux, 61 on macOS, 10061 on Windows.
        assert!(
            message.starts_with("Could not fetch u: <urlopen error [Errno "),
            "{message}"
        );
        #[cfg(target_os = "linux")]
        assert_eq!(
            message,
            "Could not fetch u: <urlopen error [Errno 111] Connection refused>"
        );
    }

    #[test]
    fn locations_join_like_urljoin() {
        let base = "https://h/a/b.sql";
        assert_eq!(join_url(base, "https://x/y"), "https://x/y");
        assert_eq!(join_url(base, "//x/y"), "https://x/y");
        assert_eq!(join_url(base, "/y"), "https://h/y");
        assert_eq!(join_url(base, "c.sql"), "https://h/a/c.sql");
        assert_eq!(join_url("https://h", "c.sql"), "https://h/c.sql");
    }

    #[test]
    fn io_errors_are_described() {
        use std::io::{Error, ErrorKind};
        assert_eq!(describe_io(&Error::from(ErrorKind::TimedOut)), "timed out");
        assert_eq!(describe_io(&Error::other("boom")), "<urlopen error boom>");
        assert_eq!(
            describe(&ureq::Error::Timeout(ureq::Timeout::Global)),
            "timed out"
        );
        assert!(describe(&ureq::Error::HostNotFound).starts_with("<urlopen error"));
    }
}
