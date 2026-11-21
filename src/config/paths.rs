//! Where `config.toml` and `connections.toml` live (ADR 0001, Decision 3 "Files").

use super::ConfigPaths;
use crate::env::Env;
use crate::error::{Error, ErrorKind, Result};
use std::path::{Path, PathBuf};

impl ConfigPaths {
    pub fn discover(env: &Env, config_file_override: Option<&Path>) -> Result<Self> {
        let dir = config_dir(env)?;
        Ok(Self {
            config_file: config_file_override
                .map(Path::to_path_buf)
                .unwrap_or_else(|| dir.join("config.toml")),
            connections_file: dir.join("connections.toml"),
            config_file_is_custom: config_file_override.is_some(),
        })
    }
}

/// `$SNOWFLAKE_HOME` (default `~/.snowflake`) if it exists, else the platform config dir.
fn config_dir(env: &Env) -> Result<PathBuf> {
    // As snow: `Path(os.environ.get("SNOWFLAKE_HOME", "~/.snowflake/")).expanduser()`; an empty
    // SNOWFLAKE_HOME is Python's `Path("")`, the current directory.
    let snowflake_home = match env.get("SNOWFLAKE_HOME") {
        Some("") => PathBuf::from("."),
        Some(home) => expand_user(home, env)?,
        None => home_dir(env)?.join(".snowflake"),
    };
    if snowflake_home.exists() {
        return Ok(snowflake_home);
    }
    Ok(platform_config_dir(env)?.join("snowflake"))
}

/// platformdirs `user_config_dir` (`appauthor=False`, `roaming=False`), without the app name.
#[cfg(target_os = "macos")]
fn platform_config_dir(env: &Env) -> Result<PathBuf> {
    Ok(home_dir(env)?.join("Library/Application Support"))
}

#[cfg(windows)]
fn platform_config_dir(env: &Env) -> Result<PathBuf> {
    match env.get_non_empty("LOCALAPPDATA") {
        Some(dir) => Ok(PathBuf::from(dir)),
        None => Ok(home_dir(env)?.join("AppData").join("Local")),
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
fn platform_config_dir(env: &Env) -> Result<PathBuf> {
    match env.get("XDG_CONFIG_HOME").map(str::trim) {
        Some(dir) if !dir.is_empty() => Ok(PathBuf::from(dir)),
        _ => Ok(home_dir(env)?.join(".config")),
    }
}

/// The user's home: `HOME` (`USERPROFILE` on Windows) from `env`, else the OS's answer.
pub(crate) fn home_dir(env: &Env) -> Result<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    env.get_non_empty(var)
        .map(PathBuf::from)
        .or_else(std::env::home_dir)
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Client,
                "Cannot determine the home directory. Set SNOWFLAKE_HOME or HOME.",
            )
        })
}

/// The text after a leading `~` when it names the home directory: `~` and `~/…` (`~\\…` on
/// Windows). `~user` is not a home reference.
fn tilde_rest(path: &str) -> Option<&str> {
    path.strip_prefix('~').filter(|rest| {
        rest.is_empty() || rest.starts_with('/') || (cfg!(windows) && rest.starts_with('\\'))
    })
}

/// Python's `os.path.expanduser` with the home given: `~` and `~/…` (`~\\…` on Windows) are
/// relative to `home`, `~user` and paths without a tilde are returned as they are, and so is
/// everything when `home` is `None`. A trailing separator of `home` is dropped.
pub(crate) fn expand_user_with(path: &str, home: Option<&Path>) -> PathBuf {
    match (tilde_rest(path), home) {
        (Some(rest), Some(home)) => {
            let rest = rest.trim_start_matches(|c| c == '/' || (cfg!(windows) && c == '\\'));
            // Rebuilding from components drops a trailing separator of `home`.
            let home: PathBuf = home.components().collect();
            if rest.is_empty() {
                home
            } else {
                home.join(rest)
            }
        }
        _ => PathBuf::from(path),
    }
}

/// [`expand_user_with`] with the home from `env`; an error when a `~` needs a home that is unknown.
pub(crate) fn expand_user(path: &str, env: &Env) -> Result<PathBuf> {
    match tilde_rest(path) {
        Some(_) => Ok(expand_user_with(path, Some(&home_dir(env)?))),
        None => Ok(PathBuf::from(path)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn env_with_home(home: &Path, extra: &[(&str, &str)]) -> Env {
        let mut pairs: Vec<(String, String)> =
            vec![("HOME".into(), home.to_string_lossy().into_owned())];
        if cfg!(windows) {
            pairs.push(("USERPROFILE".into(), home.to_string_lossy().into_owned()));
        }
        pairs.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        Env::from_pairs(pairs)
    }

    #[test]
    fn existing_snowflake_home_is_used() {
        let home = TempDir::new().unwrap();
        let sf = TempDir::new().unwrap();
        let env = env_with_home(
            home.path(),
            &[("SNOWFLAKE_HOME", sf.path().to_str().unwrap())],
        );
        let paths = ConfigPaths::discover(&env, None).unwrap();
        assert_eq!(
            paths,
            ConfigPaths {
                config_file: sf.path().join("config.toml"),
                connections_file: sf.path().join("connections.toml"),
                config_file_is_custom: false,
            }
        );
    }

    #[test]
    fn default_snowflake_home_is_dot_snowflake_when_it_exists() {
        let home = TempDir::new().unwrap();
        std::fs::create_dir(home.path().join(".snowflake")).unwrap();
        let env = env_with_home(home.path(), &[]);
        let paths = ConfigPaths::discover(&env, None).unwrap();
        assert_eq!(
            paths.config_file,
            home.path().join(".snowflake/config.toml")
        );
    }

    #[test]
    fn tilde_in_snowflake_home_is_expanded() {
        let home = TempDir::new().unwrap();
        std::fs::create_dir(home.path().join("sf")).unwrap();
        let env = env_with_home(home.path(), &[("SNOWFLAKE_HOME", "~/sf")]);
        let paths = ConfigPaths::discover(&env, None).unwrap();
        assert_eq!(
            paths.connections_file,
            home.path().join("sf/connections.toml")
        );
    }

    #[test]
    fn empty_snowflake_home_is_the_current_directory() {
        let home = TempDir::new().unwrap();
        let env = env_with_home(home.path(), &[("SNOWFLAKE_HOME", "")]);
        let paths = ConfigPaths::discover(&env, None).unwrap();
        assert_eq!(paths.config_file, Path::new(".").join("config.toml"));
    }

    #[cfg(not(any(target_os = "macos", windows)))]
    #[test]
    fn missing_snowflake_home_falls_back_to_xdg_config_home() {
        let home = TempDir::new().unwrap();
        let xdg = TempDir::new().unwrap();
        let env = env_with_home(
            home.path(),
            &[
                ("SNOWFLAKE_HOME", home.path().join("nope").to_str().unwrap()),
                ("XDG_CONFIG_HOME", xdg.path().to_str().unwrap()),
            ],
        );
        let paths = ConfigPaths::discover(&env, None).unwrap();
        assert_eq!(paths.config_file, xdg.path().join("snowflake/config.toml"));
    }

    #[cfg(not(any(target_os = "macos", windows)))]
    #[test]
    fn missing_snowflake_home_and_blank_xdg_fall_back_to_dot_config() {
        let home = TempDir::new().unwrap();
        let env = env_with_home(home.path(), &[("XDG_CONFIG_HOME", "  ")]);
        let paths = ConfigPaths::discover(&env, None).unwrap();
        assert_eq!(
            paths.config_file,
            home.path().join(".config/snowflake/config.toml")
        );
    }

    #[test]
    fn config_file_override_replaces_only_config_toml() {
        let home = TempDir::new().unwrap();
        let sf = TempDir::new().unwrap();
        let env = env_with_home(
            home.path(),
            &[("SNOWFLAKE_HOME", sf.path().to_str().unwrap())],
        );
        let custom = Path::new("custom/my.toml");
        let paths = ConfigPaths::discover(&env, Some(custom)).unwrap();
        assert_eq!(paths.config_file, custom);
        assert_eq!(paths.connections_file, sf.path().join("connections.toml"));
        assert!(paths.config_file_is_custom);
    }

    #[test]
    fn expand_user_with_covers_every_form() {
        let home = Some(Path::new("/h"));
        assert_eq!(expand_user_with("~", home), Path::new("/h"));
        assert_eq!(expand_user_with("~/x", home), Path::new("/h/x"));
        assert_eq!(expand_user_with("~//x", home), Path::new("/h/x"));
        assert_eq!(expand_user_with("~/", home), Path::new("/h"));
        let slashed = Some(Path::new("/h/"));
        assert_eq!(expand_user_with("~", slashed).to_str(), Some("/h"));
        assert_eq!(expand_user_with("~/x", slashed).to_str(), Some("/h/x"));
        assert_eq!(expand_user_with("~/x", None), Path::new("~/x"));
        assert_eq!(expand_user_with("~", None), Path::new("~"));
        assert_eq!(expand_user_with("~bob/x", home), Path::new("~bob/x"));
        assert_eq!(expand_user_with("a/~", home), Path::new("a/~"));
        assert_eq!(expand_user_with("/abs", home), Path::new("/abs"));
        let backslash = expand_user_with("~\\x", home);
        if cfg!(windows) {
            assert_eq!(backslash, Path::new("/h/x"));
        } else {
            assert_eq!(backslash, Path::new("~\\x"));
        }
    }

    #[test]
    fn expand_user_handles_tilde_forms() {
        let home = TempDir::new().unwrap();
        let env = env_with_home(home.path(), &[]);
        assert_eq!(expand_user("~", &env).unwrap(), home.path());
        assert_eq!(
            expand_user("~/k.p8", &env).unwrap(),
            home.path().join("k.p8")
        );
        assert_eq!(expand_user("~bob/k", &env).unwrap(), Path::new("~bob/k"));
        assert_eq!(expand_user("/abs/k", &env).unwrap(), Path::new("/abs/k"));
    }

    #[test]
    fn home_falls_back_to_the_os_when_env_has_none() {
        // The OS always knows the home of the user running the tests.
        assert!(home_dir(&Env::default()).is_ok());
    }
}
