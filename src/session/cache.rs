//! The temporary credential cache (ADR 0005, Decision 3): ID, MFA and OAuth tokens kept between
//! runs in the connector's Linux file format, so the cache is shared with `snow` there.
//!
//! `credential_cache_v1.json` is `{"tokens": {"<sha256 hex of KEY>": "<token>"}}` in a
//! directory that must be `0700` and owned by the user; the file must be `0600`. A
//! `credential_cache_v1.json.lck` directory serializes access. Anything that fails these checks
//! is ignored with a warning, and nothing is written there.

use crate::env::Env;
use crate::secret::Secret;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const FILE: &str = "credential_cache_v1.json";
const LOCK: &str = "credential_cache_v1.json.lck";
const LOCK_RETRIES: u32 = 5;
const LOCK_FIRST_BACKOFF: Duration = Duration::from_millis(25);
/// A lock directory older than this was left behind by a crashed process. One second matches
/// the Python connector's `FileLock`, which may share this cache directory: a longer window
/// would leave us waiting on locks it already considers stale, a shorter one would break locks
/// it still holds. No heartbeat keeps a lock alive; the critical section is a small file write.
const STALE_LOCK: Duration = Duration::from_secs(1);

/// The kind of a cached token (the connector's `TokenType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    IdToken,
    MfaToken,
    OAuthAccessToken,
    OAuthRefreshToken,
}

impl TokenType {
    fn name(self) -> &'static str {
        match self {
            TokenType::IdToken => "ID_TOKEN",
            TokenType::MfaToken => "MFA_TOKEN",
            TokenType::OAuthAccessToken => "OAUTH_ACCESS_TOKEN",
            TokenType::OAuthRefreshToken => "OAUTH_REFRESH_TOKEN",
        }
    }
}

/// Where a token is filed: `sha256_hex("<FIRST>:<SECOND>:<TYPE>")`, both parts upper-cased.
///
/// The connector uses two orders: `<USER>:<SNOWFLAKE HOST>` for ID and MFA tokens
/// (`C/auth/_auth.py`) and `<IDP HOST>:<USER>` for OAuth tokens (`C/auth/_oauth_base.py`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenKey {
    first: String,
    second: String,
    kind: TokenType,
}

impl TokenKey {
    /// The key of an ID or MFA token.
    pub fn sign_in(user: &str, host: &str, kind: TokenType) -> Self {
        Self {
            first: user.to_string(),
            second: host.to_string(),
            kind,
        }
    }

    /// The key of an OAuth access or refresh token.
    pub fn oauth(idp_host: &str, user: &str, kind: TokenType) -> Self {
        Self {
            first: idp_host.to_string(),
            second: user.to_string(),
            kind,
        }
    }

    /// `None` when a part is empty, as the connector refuses such keys.
    pub fn hash(&self) -> Option<String> {
        if self.first.is_empty() || self.second.is_empty() {
            return None;
        }
        let text = format!(
            "{}:{}:{}",
            self.first.to_uppercase(),
            self.second.to_uppercase(),
            self.kind.name()
        );
        Some(
            Sha256::digest(text.as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        )
    }
}

/// Stores credentials between runs. Every operation is best effort: a cache that cannot be used
/// behaves as an empty one.
pub trait CredentialCache: Send + Sync {
    fn retrieve(&self, key: &TokenKey) -> Option<Secret>;
    fn store(&self, key: &TokenKey, token: &Secret);
    fn remove(&self, key: &TokenKey);
}

/// No caching.
pub struct NoCache;

impl CredentialCache for NoCache {
    fn retrieve(&self, _key: &TokenKey) -> Option<Secret> {
        None
    }
    fn store(&self, _key: &TokenKey, _token: &Secret) {}
    fn remove(&self, _key: &TokenKey) {}
}

/// The connector's file cache.
pub struct FileCache {
    dir: Option<PathBuf>,
}

impl FileCache {
    /// The first usable directory of `$SF_TEMPORARY_CREDENTIAL_CACHE_DIR`,
    /// `$XDG_CACHE_HOME/snowflake`, `$HOME/.cache/snowflake` (on Windows,
    /// `%LOCALAPPDATA%\snowflake`), creating the last segments as the connector does.
    pub fn from_env(env: &Env) -> Self {
        let mut candidates: Vec<(&str, &[&str])> = vec![
            ("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", &[]),
            ("XDG_CACHE_HOME", &["snowflake"]),
            ("HOME", &[".cache", "snowflake"]),
        ];
        if cfg!(windows) {
            candidates.push(("LOCALAPPDATA", &["snowflake"]));
        }
        let dir = candidates
            .into_iter()
            .find_map(|(var, segments)| lookup(env.get(var)?, segments));
        if dir.is_none() {
            log::debug!("No usable directory for the temporary credential cache.");
        }
        Self { dir }
    }

    /// A cache in `dir` (tests).
    pub fn in_dir(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: Some(dir.into()),
        }
    }

    fn with_tokens<T>(
        &self,
        what: &str,
        change: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>) -> (T, bool),
    ) -> Option<T> {
        let dir = self.dir.as_deref()?;
        if let Err(problem) = check_dir(dir) {
            warn(&format!("Failed to {what} token: {problem}"));
            return None;
        }
        let _lock = match DirLock::acquire(&dir.join(LOCK)) {
            Ok(lock) => lock,
            Err(problem) => {
                warn(&format!("Unable to lock the credential cache: {problem}"));
                return None;
            }
        };
        let path = dir.join(FILE);
        let mut cache = match read(&path) {
            Ok(cache) => cache,
            Err(problem) => {
                warn(&format!("Failed to {what} token: {problem}"));
                return None;
            }
        };
        if !cache
            .get("tokens")
            .is_some_and(serde_json::Value::is_object)
        {
            cache.insert(
                "tokens".into(),
                serde_json::Value::Object(Default::default()),
            );
        }
        let tokens = cache.get_mut("tokens").and_then(|t| t.as_object_mut())?;
        let (value, changed) = change(tokens);
        if changed && let Err(problem) = write(&path, &cache) {
            warn(&format!("Failed to {what} token: {problem}"));
            return None;
        }
        Some(value)
    }
}

impl CredentialCache for FileCache {
    fn retrieve(&self, key: &TokenKey) -> Option<Secret> {
        let hash = key.hash()?;
        self.with_tokens("retrieve", |tokens| {
            let token = tokens.get(&hash).and_then(|t| t.as_str()).map(Secret::new);
            (token, false)
        })
        .flatten()
    }

    fn store(&self, key: &TokenKey, token: &Secret) {
        let Some(hash) = key.hash() else { return };
        self.with_tokens("store", |tokens| {
            tokens.insert(hash, token.expose().into());
            ((), true)
        });
    }

    fn remove(&self, key: &TokenKey) {
        let Some(hash) = key.hash() else { return };
        self.with_tokens("remove", |tokens| ((), tokens.remove(&hash).is_some()));
    }
}

/// snow prints the connector's cache warnings; they never name a token.
fn warn(message: &str) {
    log::warn!("{message}");
}

/// `$VAR` itself when there are no segments; otherwise `$VAR/<segments>`, created with the
/// connector's modes (`0755` for the intermediate ones, `0700` for the last), when `$VAR` is an
/// existing directory.
fn lookup(base: &str, segments: &[&str]) -> Option<PathBuf> {
    let mut dir = PathBuf::from(base);
    if let Some((last, middle)) = segments.split_last() {
        if !dir.is_dir() {
            return None;
        }
        for segment in middle {
            dir.push(segment);
            mkdir(&dir, 0o755);
        }
        dir.push(last);
        mkdir(&dir, 0o700);
    }
    match check_dir(&dir) {
        Ok(()) => Some(dir),
        Err(problem) => {
            warn(&format!(
                "Cache directory validation failed for {} due to error '{problem}'. Skipping it in cache directory lookup.",
                dir.display()
            ));
            None
        }
    }
}

fn mkdir(dir: &Path, mode: u32) {
    #[cfg_attr(not(unix), allow(unused_mut))]
    // `mut` is needed only by the unix-only mode call below
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    // An existing directory is fine; anything else shows up in `check_dir`.
    let _ = builder.create(dir);
}

/// A directory, `0700` and owned by the effective user.
fn check_dir(dir: &Path) -> Result<(), String> {
    let meta = std::fs::metadata(dir)
        .map_err(|_| format!("Cache dir {} was not found. Failed to stat.", dir.display()))?;
    if !meta.is_dir() {
        return Err(format!("Cache dir {} is not a directory", dir.display()));
    }
    check_owner_and_mode(&meta, 0o700, || format!("Cache dir {}", dir.display()))
}

#[cfg(unix)]
fn check_owner_and_mode(
    meta: &std::fs::Metadata,
    mode: u32,
    what: impl Fn() -> String,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let actual = meta.mode() & 0o7777;
    if actual != mode {
        return Err(format!(
            "{} has incorrect permissions. {actual:o} != {mode:04o}",
            what()
        ));
    }
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(format!(
            "{} has incorrect owner. {euid} != {}",
            what(),
            meta.uid()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_owner_and_mode(
    _meta: &std::fs::Metadata,
    _mode: u32,
    _what: impl Fn() -> String,
) -> Result<(), String> {
    // Windows has no POSIX modes; the directory sits in the user's own profile.
    Ok(())
}

/// The cache file as JSON; a missing or unreadable-as-JSON file is an empty cache.
fn read(path: &Path) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Default::default()),
        Err(e) => return Err(format!("Failed to read cache file {}: {e}", path.display())),
    };
    let meta = file
        .metadata()
        .map_err(|e| format!("Failed to read cache file {}: {e}", path.display()))?;
    check_owner_and_mode(&meta, 0o600, || format!("Cache file {}", path.display()))?;
    let text = std::io::read_to_string(file).unwrap_or_default();
    match serde_json::from_str(&text) {
        Ok(serde_json::Value::Object(map)) => Ok(map),
        _ => {
            warn(&format!(
                "Failed to decode json read from cache file {}",
                path.display()
            ));
            Ok(Default::default())
        }
    }
}

/// Writes the cache file atomically (temp file, `fsync`, rename), so a crash or a concurrent
/// reader never sees a partial file. The new file is `0600`; an existing one must already be
/// `0600` and ours, or nothing is written.
fn write(path: &Path, cache: &serde_json::Map<String, serde_json::Value>) -> Result<(), String> {
    write_with(path, cache, || Ok(()))
}

/// [`write`], running `before_rename` once the temp file is complete (a test seam).
fn write_with(
    path: &Path,
    cache: &serde_json::Map<String, serde_json::Value>,
    before_rename: impl FnOnce() -> std::io::Result<()>,
) -> Result<(), String> {
    let failed = |e: std::io::Error| format!("Failed to write cache file: {e}");
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            check_owner_and_mode(&meta, 0o600, || format!("Cache file {}", path.display()))?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(failed(e)),
    }
    let text = serde_json::Value::Object(cache.clone()).to_string();
    crate::fsutil::replace_atomic_with(path, text.as_bytes(), false, before_rename).map_err(failed)
}

/// The connector's `FileLock`: a directory created atomically, removed on drop.
struct DirLock {
    path: PathBuf,
}

impl DirLock {
    fn acquire(path: &Path) -> Result<Self, String> {
        let stale = std::fs::metadata(path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| SystemTime::now().duration_since(t).ok())
            .is_some_and(|age| age > STALE_LOCK);
        if stale {
            log::debug!("Removing stale file lock");
            let _ = std::fs::remove_dir(path);
        }
        let mut backoff = LOCK_FIRST_BACKOFF;
        for _ in 0..LOCK_RETRIES {
            backoff *= 2;
            #[cfg_attr(not(unix), allow(unused_mut))]
            // `mut` is needed only by the unix-only mode call below
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(path) {
                Ok(()) => {
                    return Ok(Self {
                        path: path.to_path_buf(),
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    std::thread::sleep(backoff);
                }
                Err(e) => return Err(format!("Failed to acquire lock file: {e}")),
            }
        }
        Err(format!(
            "Failed to acquire file lock, after {LOCK_RETRIES} attempts."
        ))
    }
}

impl Drop for DirLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn private_dir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn keys_hash_like_the_connector() {
        // hashlib.sha256(b"ME:ACCT.SNOWFLAKECOMPUTING.COM:ID_TOKEN").hexdigest()
        let key = TokenKey::sign_in("me", "acct.snowflakecomputing.com", TokenType::IdToken);
        assert_eq!(
            key.hash().unwrap(),
            "416d658730d2ff0552593e23be272621a0848ce232a27dd7548a3eed13007030"
        );
        let oauth = TokenKey::oauth("idp.example", "me", TokenType::OAuthAccessToken);
        assert_ne!(oauth.hash(), key.hash());
        assert_eq!(TokenKey::sign_in("", "h", TokenType::MfaToken).hash(), None);
        assert_eq!(
            TokenKey::oauth("h", "", TokenType::OAuthRefreshToken).hash(),
            None
        );
    }

    #[test]
    fn no_cache_keeps_nothing() {
        let key = TokenKey::sign_in("u", "h", TokenType::MfaToken);
        NoCache.store(&key, &Secret::new("t"));
        NoCache.remove(&key);
        assert!(NoCache.retrieve(&key).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn the_file_cache_round_trips_with_the_connector_permissions() {
        let dir = private_dir();
        let cache = FileCache::in_dir(dir.path());
        let key = TokenKey::sign_in("u", "h", TokenType::MfaToken);
        assert!(cache.retrieve(&key).is_none());
        cache.store(&key, &Secret::new("mfa-token"));
        assert_eq!(cache.retrieve(&key).unwrap().expose(), "mfa-token");
        let file = dir.path().join(FILE);
        assert_eq!(mode(&file), 0o600);
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        assert_eq!(json["tokens"][key.hash().unwrap()], "mfa-token");
        assert!(!dir.path().join(LOCK).exists(), "the lock is released");
        cache.remove(&key);
        assert!(cache.retrieve(&key).is_none());
        // A key with an empty part is never filed.
        let empty = TokenKey::sign_in("", "h", TokenType::MfaToken);
        cache.store(&empty, &Secret::new("x"));
        cache.remove(&empty);
        assert!(cache.retrieve(&empty).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn the_file_cache_keeps_other_entries_and_survives_bad_json() {
        let dir = private_dir();
        let file = dir.path().join(FILE);
        write(
            &file,
            serde_json::json!({"tokens": {"other": "x"}, "extra": 1})
                .as_object()
                .unwrap(),
        )
        .unwrap();
        let cache = FileCache::in_dir(dir.path());
        let key = TokenKey::sign_in("u", "h", TokenType::IdToken);
        cache.store(&key, &Secret::new("id"));
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        assert_eq!(json["tokens"]["other"], "x");
        assert_eq!(json["extra"], 1);
        std::fs::write(&file, "not json").unwrap();
        assert!(cache.retrieve(&key).is_none());
        std::fs::write(&file, r#"{"tokens": []}"#).unwrap();
        assert!(cache.retrieve(&key).is_none());
        cache.store(&key, &Secret::new("again"));
        assert_eq!(cache.retrieve(&key).unwrap().expose(), "again");
    }

    #[cfg(unix)]
    #[test]
    fn wrong_permissions_are_never_read_or_written() {
        use std::os::unix::fs::PermissionsExt;
        let dir = private_dir();
        let cache = FileCache::in_dir(dir.path());
        let key = TokenKey::sign_in("u", "h", TokenType::IdToken);
        cache.store(&key, &Secret::new("id"));
        let file = dir.path().join(FILE);
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(cache.retrieve(&key).is_none(), "a 0644 file is ignored");
        cache.store(&key, &Secret::new("new"));
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(cache.retrieve(&key).unwrap().expose(), "id", "not written");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            cache.retrieve(&key).is_none(),
            "a 0755 directory is ignored"
        );
        cache.store(&key, &Secret::new("new"));
        cache.remove(&key);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(cache.retrieve(&key).unwrap().expose(), "id");
        assert!(
            FileCache::in_dir(dir.path().join("missing"))
                .retrieve(&key)
                .is_none()
        );
        let not_dir = dir.path().join("f");
        std::fs::write(&not_dir, "").unwrap();
        assert!(check_dir(&not_dir).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_held_lock_blocks_and_a_stale_one_is_removed() {
        let dir = private_dir();
        let cache = FileCache::in_dir(dir.path());
        let key = TokenKey::sign_in("u", "h", TokenType::IdToken);
        let lock = dir.path().join(LOCK);
        std::fs::create_dir(&lock).unwrap();
        cache.store(&key, &Secret::new("id"));
        assert!(lock.exists());
        std::fs::remove_dir(&lock).unwrap();
        assert!(
            cache.retrieve(&key).is_none(),
            "the held lock blocked the store"
        );
        std::fs::create_dir(&lock).unwrap();
        let old = SystemTime::now() - Duration::from_secs(10);
        std::fs::File::open(&lock)
            .unwrap()
            .set_modified(old)
            .unwrap();
        cache.store(&key, &Secret::new("id"));
        assert_eq!(cache.retrieve(&key).unwrap().expose(), "id");
    }

    #[cfg(unix)]
    #[test]
    fn an_interrupted_write_leaves_the_previous_cache_intact() {
        let dir = private_dir();
        let cache = FileCache::in_dir(dir.path());
        let key = TokenKey::sign_in("u", "h", TokenType::IdToken);
        cache.store(&key, &Secret::new("old"));
        let file = dir.path().join(FILE);
        let mut next = read(&file).unwrap();
        next.insert("tokens".into(), serde_json::json!({}));
        let err = write_with(&file, &next, || Err(std::io::Error::other("crash"))).unwrap_err();
        assert!(err.contains("crash"), "{err}");
        assert_eq!(cache.retrieve(&key).unwrap().expose(), "old");
        let names: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(names.len(), 1, "no temp file is left behind");
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_writers_all_land_and_the_file_stays_valid() {
        let dir = private_dir();
        let path = dir.path().to_path_buf();
        let file = path.join(FILE);
        let keys: Vec<_> = (0..4)
            .map(|i| TokenKey::sign_in(&format!("u{i}"), "h", TokenType::IdToken))
            .collect();
        // The lock gives up after a few attempts, so each writer retries until stored.
        std::thread::scope(|scope| {
            for (i, key) in keys.iter().enumerate() {
                let (path, file) = (&path, &file);
                scope.spawn(move || {
                    let cache = FileCache::in_dir(path);
                    let token = Secret::new(format!("t{i}"));
                    while cache
                        .retrieve(key)
                        .is_none_or(|t| t.expose() != token.expose())
                    {
                        cache.store(key, &token);
                        if let Ok(text) = std::fs::read_to_string(file) {
                            assert!(serde_json::from_str::<serde_json::Value>(&text).is_ok());
                        }
                    }
                });
            }
        });
        let cache = FileCache::in_dir(&path);
        for (i, key) in keys.iter().enumerate() {
            assert_eq!(cache.retrieve(key).unwrap().expose(), format!("t{i}"));
        }
        assert_eq!(mode(&file), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn a_lock_older_than_a_second_is_taken_over_and_a_fresh_one_waited_on() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("l.lck");
        std::fs::create_dir(&lock).unwrap();
        assert!(
            DirLock::acquire(&lock).is_err(),
            "a fresh lock is waited on"
        );
        let old = SystemTime::now() - STALE_LOCK - Duration::from_secs(1);
        std::fs::File::open(&lock)
            .unwrap()
            .set_modified(old)
            .unwrap();
        let taken = DirLock::acquire(&lock).unwrap();
        drop(taken);
        assert!(!lock.exists());
    }

    #[cfg(unix)]
    #[test]
    fn the_directory_chain_matches_the_connector() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let env = Env::from_pairs([("HOME".to_string(), home.display().to_string())]);
        let cache = FileCache::from_env(&env);
        let dir = home.join(".cache").join("snowflake");
        assert_eq!(cache.dir.as_deref(), Some(dir.as_path()));
        assert_eq!(mode(&home.join(".cache")), 0o755);
        assert_eq!(mode(&dir), 0o700);

        let xdg = root.path().join("xdg");
        std::fs::create_dir(&xdg).unwrap();
        let env = Env::from_pairs([
            ("XDG_CACHE_HOME".to_string(), xdg.display().to_string()),
            ("HOME".to_string(), home.display().to_string()),
        ]);
        assert_eq!(FileCache::from_env(&env).dir, Some(xdg.join("snowflake")));

        // An explicit directory is used as is, and must already be private.
        let explicit = root.path().join("explicit");
        std::fs::create_dir(&explicit).unwrap();
        std::fs::set_permissions(&explicit, std::fs::Permissions::from_mode(0o755)).unwrap();
        let env = Env::from_pairs([
            (
                "SF_TEMPORARY_CREDENTIAL_CACHE_DIR".to_string(),
                explicit.display().to_string(),
            ),
            (
                "XDG_CACHE_HOME".to_string(),
                root.path().join("nope").display().to_string(),
            ),
        ]);
        assert_eq!(FileCache::from_env(&env).dir, None);
        std::fs::set_permissions(&explicit, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(FileCache::from_env(&env).dir, Some(explicit));
    }
}
