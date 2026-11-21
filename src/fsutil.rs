//! Crash-safe local file writes shared by the config writer and the credential cache, and the
//! temp files of downloads.
//!
//! Temp names are `.<32 hex><suffix>` in the target's directory: short whatever the target's
//! name (a name near the 255-byte limit still works), unpredictable, and created exclusively, so
//! a planted file or link is never followed or overwritten.

use std::io::Write;
use std::path::{Path, PathBuf};

/// 122 random bits as hex (a v4 UUID, from the OS random source).
fn random_suffix() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// `OpenOptions` that create files owner-only (`0600` on unix, a no-op elsewhere). The caller
/// chooses read, write, append, truncate or `create_new`; the mode applies only to a file this
/// open creates, so an existing file keeps its permissions.
pub(crate) fn private_options() -> std::fs::OpenOptions {
    let mut options = std::fs::OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

/// A new owner-only file `.<32 hex><suffix>` in `dir`. A name that exists (astronomically
/// unlikely) is retried.
pub(crate) fn create_temp(dir: &Path, suffix: &str) -> std::io::Result<(std::fs::File, PathBuf)> {
    let mut attempts = 0;
    loop {
        let tmp = dir.join(format!(".{}{suffix}", random_suffix()));
        let mut options = private_options();
        options.write(true).create_new(true);
        match options.open(&tmp) {
            Ok(file) => return Ok((file, tmp)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempts < 8 => {
                attempts += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

/// The directory a temp file next to `path` goes in.
pub(crate) fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    }
}

/// Replaces `path` with `contents` atomically: temp file in the same directory, `fsync`, then
/// rename. The new file is `0600`; with `keep_permissions` an existing target's permissions
/// carry over. On failure the temp file is removed and the target is untouched.
pub(crate) fn replace_atomic(
    path: &Path,
    contents: &[u8],
    keep_permissions: bool,
) -> std::io::Result<()> {
    replace_atomic_with(path, contents, keep_permissions, || Ok(()))
}

/// [`replace_atomic`], running `before_rename` once the temp file is written and synced (a seam
/// for tests to simulate a crash at that point).
pub(crate) fn replace_atomic_with(
    path: &Path,
    contents: &[u8],
    keep_permissions: bool,
    before_rename: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<()> {
    let existing = if keep_permissions {
        std::fs::metadata(path).ok().map(|m| m.permissions())
    } else {
        None
    };
    let (mut file, tmp) = create_temp(parent_dir(path), ".tmp")?;
    let result = (|| {
        file.write_all(contents)?;
        file.sync_all()?;
        if let Some(permissions) = existing {
            std::fs::set_permissions(&tmp, permissions)?;
        }
        before_rename()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        // Best effort: the temp file may not exist.
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_names_are_short_unique_and_unpredictable() {
        let dir = tempfile::tempdir().unwrap();
        let (_a, a) = create_temp(dir.path(), ".part").unwrap();
        let (_b, b) = create_temp(dir.path(), ".part").unwrap();
        assert_ne!(a, b);
        let name = a.file_name().unwrap().to_str().unwrap();
        assert_eq!(name.len(), 1 + 32 + ".part".len());
        assert!(name.starts_with('.') && name.ends_with(".part"));
    }

    #[test]
    fn replaces_the_target_and_removes_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("t");
        std::fs::write(&target, "old").unwrap();
        replace_atomic(&target, b"new", false).unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn a_failure_before_the_rename_leaves_the_target_and_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("t");
        std::fs::write(&target, "old").unwrap();
        let err = replace_atomic_with(&target, b"new", false, || {
            Err(std::io::Error::other("crash"))
        })
        .unwrap_err();
        assert_eq!(err.to_string(), "crash");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "old");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn a_missing_directory_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(replace_atomic(&dir.path().join("no/t"), b"x", false).is_err());
    }

    #[test]
    fn a_bare_file_name_uses_the_current_directory() {
        assert_eq!(parent_dir(Path::new("t")), Path::new("."));
        assert_eq!(parent_dir(Path::new("a/t")), Path::new("a"));
    }

    #[cfg(unix)]
    #[test]
    fn permissions_are_0600_for_new_files_and_kept_on_request() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("t");
        replace_atomic(&target, b"x", true).unwrap();
        assert_eq!(mode(&target), 0o600);
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
        replace_atomic(&target, b"y", true).unwrap();
        assert_eq!(mode(&target), 0o640);
        replace_atomic(&target, b"z", false).unwrap();
        assert_eq!(mode(&target), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn a_planted_link_is_never_followed() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "keep").unwrap();
        std::os::unix::fs::symlink(&victim, dir.path().join(".t.tmp")).unwrap();
        replace_atomic(&dir.path().join("t"), b"x", false).unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
    }

    #[cfg(unix)]
    #[test]
    fn private_options_create_0600_and_leave_an_existing_file_alone() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        private_options()
            .write(true)
            .create(true)
            .open(&path)
            .unwrap();
        assert_eq!(mode(&path), 0o600);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        private_options().append(true).open(&path).unwrap();
        assert_eq!(mode(&path), 0o644);
    }

    #[cfg(unix)]
    #[test]
    fn create_new_refuses_an_existing_file_and_a_planted_link() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "keep").unwrap();
        let open = |p: &Path| private_options().write(true).create_new(true).open(p);
        assert!(open(&victim).is_err());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(open(&link).is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
    }
}
