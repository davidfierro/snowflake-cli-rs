use super::*;

#[cfg(unix)]
#[test]
fn the_edit_buffer_is_owner_only_while_the_editor_runs() {
    let dir = tempfile::tempdir().unwrap();
    let record = dir.path().join("mode");
    let editor = format!("stat -c %a >{} --", record.display());
    // The editor receives the buffer path as its last argument.
    let out = edit_in(dir.path(), &editor, "select 1").unwrap();
    assert_eq!(out, "select 1\n");
    assert_eq!(std::fs::read_to_string(&record).unwrap().trim(), "600");
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(leftovers.len(), 1, "the buffer is removed: {leftovers:?}");
}

#[cfg(unix)]
#[test]
fn an_unusable_buffer_directory_fails_the_edit_without_running_the_editor() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("ran");
    let editor = format!("touch {}; true", marker.display());
    let err = edit_in(&dir.path().join("missing"), &editor, "x").unwrap_err();
    assert!(err.to_string().contains("Editing failed"), "{err}");
    assert!(!marker.exists());
}
