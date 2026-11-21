//! The `[variables]` of the config files, merged under the `-D` variables of `snow sql`
//! (`get_merged_variables` of `snow` 3.34.0, `config_ng/sources.py`).
//!
//! `snow` asks its config provider for the `variables` section. The default provider has none,
//! so the files only count with `SNOWFLAKE_CLI_CONFIG_V2_ENABLED` on, as in `snow`. Then the
//! alternative provider reads, lowest priority first:
//!
//! 1. the SnowSQL INI files (`$SNOWFLAKE_HOME/config` when that directory exists, else
//!    `/etc/snowsql.cnf`, `/etc/snowflake/snowsql.cnf`, `/usr/local/etc/snowsql.cnf`,
//!    `~/.snowsql.cnf`, `~/.snowsql/config`), merged key by key;
//! 2. the first `config.toml` found (`--config-file`, else `$SNOWFLAKE_HOME/config.toml` when
//!    that directory exists, else `./config.toml`, then `~/.snowflake/config.toml`), whose
//!    `variables` key replaces the whole section of the SnowSQL files.
//!
//! A source that fails (permissions too wide, a parse or interpolation error) contributes
//! nothing, as `snow` logs and skips it. Values are rendered as text, as Python's `str()` of the
//! value `snow` reads.

use super::ConfigSource;
use super::paths::{expand_user, home_dir};
use crate::env::Env;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Variable name to value.
pub type Variables = BTreeMap<String, String>;

/// `get_merged_variables` without the `-D` pairs, which the caller lays over the result.
/// `cwd` is where `./config.toml` is looked for. `loaded` is the already-loaded `ConfigSource`:
/// when the `config.toml` found is the file it read, that table is reused instead of parsing the
/// file again (the permission check still runs).
pub fn config_variables(
    env: &Env,
    config_override: Option<&Path>,
    cwd: &Path,
    loaded: Option<&ConfigSource>,
) -> Variables {
    if !v2_enabled(env) {
        return Variables::new();
    }
    let home = home_dir(env).ok();
    // `os.environ.get(SNOWFLAKE_HOME)` is falsy when empty.
    let snowflake_home = env
        .get_non_empty("SNOWFLAKE_HOME")
        .and_then(|h| expand_user(h, env).ok())
        .filter(|h| h.exists());
    let snowsql_paths: Vec<PathBuf> = match &snowflake_home {
        Some(dir) => vec![dir.join("config")],
        None => {
            let mut paths: Vec<PathBuf> = [
                "/etc/snowsql.cnf",
                "/etc/snowflake/snowsql.cnf",
                "/usr/local/etc/snowsql.cnf",
            ]
            .iter()
            .map(PathBuf::from)
            .collect();
            if let Some(home) = &home {
                paths.push(home.join(".snowsql.cnf"));
                paths.push(home.join(".snowsql").join("config"));
            }
            paths
        }
    };
    let toml_paths: Vec<PathBuf> = match (config_override, &snowflake_home) {
        (Some(path), _) => vec![path.to_path_buf()],
        (None, Some(dir)) => vec![dir.join("config.toml")],
        (None, None) => {
            let mut paths = vec![cwd.join("config.toml")];
            if let Some(home) = &home {
                paths.push(home.join(".snowflake").join("config.toml"));
            }
            paths
        }
    };
    let skip_read_check = skip_permission_check(env);
    let mut section = snowsql_variables(&snowsql_paths, skip_read_check);
    if let Some(replacement) = toml_variables(&toml_paths, skip_read_check, loaded) {
        section = replacement;
    }
    section
}

/// `SNOWFLAKE_CLI_CONFIG_V2_ENABLED` in `1`, `true`, `yes`, `on` (any case).
fn v2_enabled(env: &Env) -> bool {
    env.get("SNOWFLAKE_CLI_CONFIG_V2_ENABLED")
        .is_some_and(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
}

/// `should_skip_permission_warning`: the first of the two variables that is set decides, as
/// `try_cast_to_bool` reads it (anything else is false).
fn skip_permission_check(env: &Env) -> bool {
    for name in [
        "SF_SKIP_TOKEN_FILE_PERMISSIONS_VERIFICATION",
        "SKIP_TOKEN_FILE_PERMISSIONS_VERIFICATION",
    ] {
        if let Some(value) = env.get(name) {
            return matches!(value.to_lowercase().as_str(), "true" | "1");
        }
    }
    false
}

/// `_ensure_strict_file_permissions`: no group/other write bit, and no group/other read bit
/// unless the check is skipped.
#[cfg(unix)]
fn strict_enough(path: &Path, skip_read_check: bool) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = std::fs::metadata(path) else {
        return true;
    };
    let mode = meta.permissions().mode();
    if mode & 0o022 != 0 {
        return false;
    }
    mode & 0o044 == 0 || skip_read_check
}

#[cfg(not(unix))]
fn strict_enough(_path: &Path, _skip_read_check: bool) -> bool {
    true
}

/// The `[variables]` of the SnowSQL files, merged in order; empty when the merged content does
/// not survive `SnowSQLParser.parse` (an interpolation error in a parsed section).
fn snowsql_variables(paths: &[PathBuf], skip_read_check: bool) -> Variables {
    let mut ini = Ini::default();
    for path in paths {
        if !path.exists() {
            continue;
        }
        if !strict_enough(path, skip_read_check) {
            log::warn!("{} skipped: permissions too wide", path.display());
            continue;
        }
        match std::fs::read(path) {
            Ok(bytes) => {
                if let Err(e) = ini.read(&String::from_utf8_lossy(&bytes)) {
                    log::debug!("Failed to read SnowSQL config {}: {e}", path.display());
                }
            }
            Err(e) => log::debug!("Failed to read SnowSQL config {}: {e}", path.display()),
        }
    }
    // `SnowSQLParser.parse` reads every `connections…` section and `variables`; an error in
    // any of them drops the whole source.
    let mut variables = Variables::new();
    for name in ini.section_names() {
        let parsed = name.starts_with("connections") || name == "variables";
        if !parsed {
            continue;
        }
        match ini.items(&name) {
            Ok(items) if name == "variables" => variables = items,
            Ok(_) => {}
            Err(e) => {
                log::warn!("Error from source snowsql_config: {e}");
                return Variables::new();
            }
        }
    }
    variables
}

/// The `variables` key of the first `config.toml` found: `Some` replaces the SnowSQL section
/// (with nothing when it is not a table), `None` leaves it.
fn toml_variables(
    paths: &[PathBuf],
    skip_read_check: bool,
    loaded: Option<&ConfigSource>,
) -> Option<Variables> {
    let path = paths.iter().find(|p| p.exists())?;
    if !strict_enough(path, skip_read_check) {
        log::warn!("Error from source cli_config_toml: permissions too wide");
        return None;
    }
    let parsed;
    let table = match loaded.and_then(|source| source.config_read_from(path)) {
        Some(table) => table,
        None => {
            let text = std::fs::read_to_string(path).ok()?;
            parsed = match text.parse::<toml::Table>() {
                Ok(table) => table,
                Err(_) => {
                    log::warn!("Error from source cli_config_toml: invalid TOML");
                    return None;
                }
            };
            &parsed
        }
    };
    let value = table.get("variables")?;
    Some(match value {
        toml::Value::Table(t) => t.iter().map(|(k, v)| (k.clone(), py_str(v))).collect(),
        _ => Variables::new(),
    })
}

/// Python's `str()` of the value `tomlkit` unwraps.
fn py_str(value: &toml::Value) -> String {
    match value {
        toml::Value::String(s) => s.clone(),
        other => py_repr(other),
    }
}

/// Python's `repr()` of an unwrapped TOML value (strings quoted, as inside a list).
fn py_repr(value: &toml::Value) -> String {
    match value {
        toml::Value::String(s) => crate::script::py_repr(s),
        toml::Value::Integer(i) => i.to_string(),
        toml::Value::Float(f) => py_float(*f),
        toml::Value::Boolean(b) => if *b { "True" } else { "False" }.to_string(),
        toml::Value::Datetime(d) => {
            let text = d.to_string().replacen('T', " ", 1);
            match text.strip_suffix('Z') {
                Some(utc) => format!("{utc}+00:00"),
                None => text,
            }
        }
        toml::Value::Array(items) => {
            let items: Vec<String> = items.iter().map(py_repr).collect();
            format!("[{}]", items.join(", "))
        }
        toml::Value::Table(t) => {
            let items: Vec<String> = t
                .iter()
                .map(|(k, v)| format!("{}: {}", crate::script::py_repr(k), py_repr(v)))
                .collect();
            format!("{{{}}}", items.join(", "))
        }
    }
}

/// Python's `repr()` of a float: the shortest text that reads back, exponent from 1e16 up
/// and below 1e-4.
fn py_float(f: f64) -> String {
    if f.is_nan() {
        return "nan".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf" } else { "-inf" }.into();
    }
    let abs = f.abs();
    if abs != 0.0 && !(1e-4..1e16).contains(&abs) {
        // `{:e}` is the shortest mantissa: `1e20`, `1.5e-7`; Python writes `1e+20`, `1.5e-07`.
        let text = format!("{f:e}");
        let (mantissa, exponent) = text.split_once('e').unwrap_or((&text, "0"));
        let (sign, digits) = match exponent.strip_prefix('-') {
            Some(d) => ('-', d),
            None => ('+', exponent),
        };
        return format!("{mantissa}e{sign}{digits:0>2}");
    }
    let text = f.to_string();
    if text.contains('.') {
        text
    } else {
        format!("{text}.0")
    }
}

/// The subset of Python's `configparser.ConfigParser` (default settings) that `snow` uses:
/// sections, `=`/`:` options with lowercased keys, full-line `#`/`;` comments, indented
/// continuation lines, the `DEFAULT` section and `BasicInterpolation`. Like `read()`, an error
/// keeps what was read before it.
#[derive(Default)]
struct Ini {
    defaults: Vec<(String, String)>,
    sections: Vec<(String, Vec<(String, String)>)>,
}

impl Ini {
    fn section_names(&self) -> Vec<String> {
        self.sections.iter().map(|(n, _)| n.clone()).collect()
    }

    fn options_mut(&mut self, section: &str) -> &mut Vec<(String, String)> {
        if section == "DEFAULT" {
            return &mut self.defaults;
        }
        let i = self
            .sections
            .iter()
            .position(|(n, _)| n == section)
            .unwrap_or_else(|| {
                self.sections.push((section.to_string(), Vec::new()));
                self.sections.len() - 1
            });
        &mut self.sections[i].1
    }

    fn set(&mut self, section: &str, key: String, value: String) {
        let options = self.options_mut(section);
        match options.iter_mut().find(|(k, _)| *k == key) {
            Some(slot) => slot.1 = value,
            None => options.push((key, value)),
        }
    }

    /// `ConfigParser.read` of one file: later files override earlier values. Duplicate
    /// sections or options inside one file are errors (`strict=True`).
    fn read(&mut self, text: &str) -> std::result::Result<(), String> {
        let mut section: Option<String> = None;
        let mut seen_sections: Vec<String> = Vec::new();
        let mut seen_options: Vec<(String, String)> = Vec::new();
        // The option being read: (section, key, indent, value lines).
        let mut current: Option<(String, String, usize, Vec<String>)> = None;
        let mut error = None;
        let flush = |ini: &mut Ini, current: &mut Option<(String, String, usize, Vec<String>)>| {
            if let Some((sec, key, _, mut lines)) = current.take() {
                while lines.last().is_some_and(|l| l.is_empty()) {
                    lines.pop();
                }
                ini.set(&sec, key, lines.join("\n"));
            }
        };
        for (number, raw) in text.lines().enumerate() {
            let line = raw.trim_end_matches('\r');
            let stripped = line.trim();
            let comment = stripped.starts_with('#') || stripped.starts_with(';');
            if stripped.is_empty() || comment {
                // Inside a value, an empty line is kept (`empty_lines_in_values`); a comment
                // line is skipped.
                if stripped.is_empty()
                    && let Some((_, _, _, lines)) = current.as_mut()
                {
                    lines.push(String::new());
                }
                continue;
            }
            let indent = line.len() - line.trim_start().len();
            if let Some((_, _, cur_indent, lines)) = current.as_mut()
                && indent > *cur_indent
            {
                lines.push(stripped.to_string());
                continue;
            }
            flush(self, &mut current);
            if stripped.starts_with('[') && stripped.ends_with(']') {
                let name = stripped[1..stripped.len() - 1].to_string();
                if seen_sections.contains(&name) {
                    error = Some(format!("Section '{name}' already exists"));
                    break;
                }
                seen_sections.push(name.clone());
                if name != "DEFAULT" {
                    self.options_mut(&name);
                }
                section = Some(name);
                continue;
            }
            let Some(sec) = section.clone() else {
                error = Some(format!(
                    "File contains no section headers (line {})",
                    number + 1
                ));
                break;
            };
            let Some(at) = stripped.find(['=', ':']) else {
                // `allow_no_value=False`: reported at the end, the rest is still read.
                error.get_or_insert_with(|| {
                    format!("Source contains parsing errors (line {})", number + 1)
                });
                continue;
            };
            let key = stripped[..at].trim().to_lowercase();
            let value = stripped[at + 1..].trim().to_string();
            if seen_options.contains(&(sec.clone(), key.clone())) {
                error = Some(format!("Option '{key}' in section '{sec}' already exists"));
                break;
            }
            seen_options.push((sec.clone(), key.clone()));
            current = Some((sec, key, indent, vec![value]));
        }
        flush(self, &mut current);
        error.map_or(Ok(()), Err)
    }

    /// `dict(parser[section])`: the section's options, then the defaults it does not override,
    /// each interpolated.
    fn items(&self, section: &str) -> std::result::Result<Variables, String> {
        let own = &self
            .sections
            .iter()
            .find(|(n, _)| n == section)
            .map(|(_, o)| o.clone())
            .unwrap_or_default();
        let lookup = |key: &str| -> Option<&str> {
            own.iter()
                .chain(&self.defaults)
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        };
        let mut out = Variables::new();
        for (key, _) in own.iter().chain(&self.defaults) {
            if out.contains_key(key) {
                continue;
            }
            let raw = lookup(key).unwrap_or_default();
            out.insert(key.clone(), interpolate(raw, &lookup, 1)?);
        }
        Ok(out)
    }
}

/// `BasicInterpolation`: `%%` is `%`, `%(name)s` the (interpolated) option `name`; any other
/// `%` is an error, as is a reference deeper than 10.
fn interpolate<'a>(
    value: &str,
    lookup: &dyn Fn(&str) -> Option<&'a str>,
    depth: usize,
) -> std::result::Result<String, String> {
    if depth > 10 {
        return Err("Interpolation depth exceeded".into());
    }
    let mut out = String::new();
    let mut rest = value;
    while let Some(at) = rest.find('%') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        if let Some(after) = rest.strip_prefix("%%") {
            out.push('%');
            rest = after;
        } else if let Some(after) = rest.strip_prefix("%(") {
            let Some(end) = after.find(")s") else {
                return Err(format!("bad interpolation variable reference {rest:?}"));
            };
            let name = after[..end].to_lowercase();
            let Some(target) = lookup(&name) else {
                return Err(format!("Bad value substitution: option {name:?}"));
            };
            out.push_str(&interpolate(target, lookup, depth + 1)?);
            rest = &after[end + 2..];
        } else {
            return Err(format!(
                "'%' must be followed by '%' or '(', found: {rest:?}"
            ));
        }
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn env(pairs: &[(&str, &str)]) -> Env {
        Env::from_pairs(pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())))
    }

    fn vars(pairs: &[(&str, &str)]) -> Variables {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn nothing_without_the_alternative_config_provider() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("config"), "[variables]\na = 1\n");
        let home = dir.path().display().to_string();
        let off = env(&[("SNOWFLAKE_HOME", &home)]);
        assert!(config_variables(&off, None, dir.path(), None).is_empty());
        let no = env(&[
            ("SNOWFLAKE_HOME", &home),
            ("SNOWFLAKE_CLI_CONFIG_V2_ENABLED", "no"),
        ]);
        assert!(config_variables(&no, None, dir.path(), None).is_empty());
        let on = env(&[
            ("SNOWFLAKE_HOME", &home),
            ("SNOWFLAKE_CLI_CONFIG_V2_ENABLED", "ON"),
        ]);
        assert_eq!(
            config_variables(&on, None, dir.path(), None),
            vars(&[("a", "1")])
        );
    }

    #[test]
    fn snowsql_files_merge_and_config_toml_replaces_the_section() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        write(
            &home.join(".snowsql.cnf"),
            "[variables]\nA = old\nb = keep\n",
        );
        write(&home.join(".snowsql/config"), "[variables]\na = new\n");
        let h = home.display().to_string();
        let e = env(&[("HOME", &h), ("SNOWFLAKE_CLI_CONFIG_V2_ENABLED", "1")]);
        let cwd = dir.path().join("cwd");
        std::fs::create_dir(&cwd).unwrap();
        assert_eq!(
            config_variables(&e, None, &cwd, None),
            vars(&[("a", "new"), ("b", "keep")])
        );
        // The first config.toml found replaces the whole section: ./config.toml first.
        write(
            &home.join(".snowflake/config.toml"),
            "[variables]\nt = 'home'\n",
        );
        assert_eq!(
            config_variables(&e, None, &cwd, None),
            vars(&[("t", "home")])
        );
        write(&cwd.join("config.toml"), "variables = 3\n");
        assert!(config_variables(&e, None, &cwd, None).is_empty());
        // --config-file wins over both.
        let custom = dir.path().join("custom.toml");
        write(&custom, "[variables]\nn = 7\nb = true\nf = 1.5\ns = 'x'\n");
        assert_eq!(
            config_variables(&e, Some(&custom), &cwd, None),
            vars(&[("n", "7"), ("b", "True"), ("f", "1.5"), ("s", "x")])
        );
        // A config.toml without the key leaves the SnowSQL section.
        write(&custom, "[cli]\nx = 1\n");
        assert_eq!(
            config_variables(&e, Some(&custom), &cwd, None),
            vars(&[("a", "new"), ("b", "keep")])
        );
    }

    #[test]
    fn an_existing_snowflake_home_narrows_both_lookups() {
        let dir = tempfile::tempdir().unwrap();
        let sh = dir.path().join("sh");
        write(&sh.join("config"), "[variables]\nv = from_home\n");
        let home = dir.path().join("home");
        write(&home.join(".snowsql/config"), "[variables]\nw = ignored\n");
        let (sh_text, home_text) = (sh.display().to_string(), home.display().to_string());
        let e = env(&[
            ("HOME", &home_text),
            ("SNOWFLAKE_HOME", &sh_text),
            ("SNOWFLAKE_CLI_CONFIG_V2_ENABLED", "true"),
        ]);
        assert_eq!(
            config_variables(&e, None, dir.path(), None),
            vars(&[("v", "from_home")])
        );
        // A SNOWFLAKE_HOME that does not exist is ignored.
        let missing = dir.path().join("nope").display().to_string();
        let e = env(&[
            ("HOME", &home_text),
            ("SNOWFLAKE_HOME", &missing),
            ("SNOWFLAKE_CLI_CONFIG_V2_ENABLED", "true"),
        ]);
        assert_eq!(
            config_variables(&e, None, dir.path(), None),
            vars(&[("w", "ignored")])
        );
    }

    #[cfg(unix)]
    #[test]
    fn files_open_to_others_are_skipped() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        write(&path, "[variables]\na = 1\n");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let home = dir.path().display().to_string();
        let base = [
            ("SNOWFLAKE_HOME", home.as_str()),
            ("SNOWFLAKE_CLI_CONFIG_V2_ENABLED", "1"),
        ];
        assert!(config_variables(&env(&base), None, dir.path(), None).is_empty());
        let mut skip = base.to_vec();
        skip.push(("SF_SKIP_TOKEN_FILE_PERMISSIONS_VERIFICATION", "true"));
        assert_eq!(
            config_variables(&env(&skip), None, dir.path(), None),
            vars(&[("a", "1")])
        );
        // Writable by others is never read; the same for config.toml.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o622)).unwrap();
        assert!(config_variables(&env(&skip), None, dir.path(), None).is_empty());
        let toml = dir.path().join("config.toml");
        write(&toml, "[variables]\nt = 1\n");
        std::fs::set_permissions(&toml, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(config_variables(&env(&base), None, dir.path(), None).is_empty());
        write(&toml, "not toml [");
        assert!(config_variables(&env(&base), None, dir.path(), None).is_empty());
    }

    #[test]
    fn the_loaded_config_source_is_reused_and_not_read_again() {
        use crate::config::ConfigPaths;
        let dir = tempfile::tempdir().unwrap();
        let toml = dir.path().join("config.toml");
        write(&toml, "[variables]\nv = \"loaded\"\n");
        let home = dir.path().display().to_string();
        let e = env(&[
            ("SNOWFLAKE_HOME", home.as_str()),
            ("SNOWFLAKE_CLI_CONFIG_V2_ENABLED", "1"),
        ]);
        let paths = ConfigPaths::discover(&e, None).unwrap();
        assert_eq!(paths.config_file, toml);
        let source = ConfigSource::load(&paths).unwrap();
        // The file changes after the load: a second read would see it.
        write(&toml, "[variables]\nv = \"changed\"\n");
        assert_eq!(
            config_variables(&e, None, dir.path(), Some(&source)),
            vars(&[("v", "loaded")])
        );
        assert_eq!(
            config_variables(&e, None, dir.path(), None),
            vars(&[("v", "changed")])
        );
        // A file the source did not read (another path) is still read.
        let other = dir.path().join("other.toml");
        write(&other, "[variables]\nv = \"other\"\n");
        assert_eq!(
            config_variables(&e, Some(&other), dir.path(), Some(&source)),
            vars(&[("v", "other")])
        );
        // The permission check still applies to the reused file.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&toml, std::fs::Permissions::from_mode(0o666)).unwrap();
            assert!(config_variables(&e, None, dir.path(), Some(&source)).is_empty());
        }
    }

    #[test]
    fn ini_reads_like_configparser() {
        let mut ini = Ini::default();
        let text = "# c\n[DEFAULT]\nd = dv\n[variables]\nKey : v1\nlong = a\n  b\n\n  c\n\n; c\nref = %(key)s-%%-%(d)s\n";
        ini.read(text).unwrap();
        assert_eq!(
            ini.items("variables").unwrap(),
            vars(&[
                ("key", "v1"),
                ("long", "a\nb\n\nc"),
                ("ref", "v1-%-dv"),
                ("d", "dv"),
            ])
        );
        assert_eq!(ini.section_names(), vec!["variables"]);
        // Errors keep what was read before them.
        let mut ini = Ini::default();
        assert!(ini.read("[variables]\na = 1\na = 2\nb = 3").is_err());
        assert_eq!(ini.items("variables").unwrap(), vars(&[("a", "1")]));
        assert!(Ini::default().read("a = 1").is_err());
        assert!(Ini::default().read("[s]\n[s]").is_err());
        let mut ini = Ini::default();
        assert!(ini.read("[s]\nnovalue\nb = 2").is_err());
        assert_eq!(ini.items("s").unwrap(), vars(&[("b", "2")]));
        for bad in ["%", "%(missing)s", "%(open", "%(a)s"] {
            let mut ini = Ini::default();
            ini.read(&format!("[s]\na = {bad}\n")).unwrap();
            assert!(ini.items("s").is_err(), "{bad}");
        }
    }

    #[test]
    fn an_interpolation_error_in_a_connection_drops_the_snowsql_source() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join("config"),
            "[connections.x]\npassword = 50%off\n[variables]\na = 1\n",
        );
        let home = dir.path().display().to_string();
        let e = env(&[
            ("SNOWFLAKE_HOME", &home),
            ("SNOWFLAKE_CLI_CONFIG_V2_ENABLED", "1"),
        ]);
        assert!(config_variables(&e, None, dir.path(), None).is_empty());
        // Other sections are never interpolated.
        write(
            &dir.path().join("config"),
            "[options]\nx = 50%off\n[variables]\na = 1\n",
        );
        assert_eq!(
            config_variables(&e, None, dir.path(), None),
            vars(&[("a", "1")])
        );
    }

    #[test]
    fn toml_values_print_as_python_str() {
        let table: toml::Table = r#"
            i = -3
            f = [1.5, 2.0, 1e20, 1.5e-7, 0.0001, nan, inf, -inf]
            b = false
            d = 1979-05-27T07:32:00Z
            t = { "it's" = 1 }
        "#
        .parse()
        .unwrap();
        let s = |k: &str| py_str(&table[k]);
        assert_eq!(s("i"), "-3");
        assert_eq!(s("f"), "[1.5, 2.0, 1e+20, 1.5e-07, 0.0001, nan, inf, -inf]");
        assert_eq!(s("b"), "False");
        assert_eq!(s("d"), "1979-05-27 07:32:00+00:00");
        assert_eq!(s("t"), "{\"it's\": 1}");
    }
}
