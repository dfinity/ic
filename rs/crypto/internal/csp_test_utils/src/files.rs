//! Utilities for file handling to test crypto code.
#![allow(clippy::unwrap_used)]
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir as tempdir_deleted_at_end_of_scope;
use tempfile::TempDir;

/// This creates a temporary directory with the given UNIX permissions.
/// Note:  TempDirs are deleted when they go out of scope.  The deletion
/// may not be immediate.  You will have undefined behaviour if you
/// operate outside the specification.
pub fn mk_temp_dir_with_permissions(mode: u32) -> TempDir {
    let dir = tempdir_deleted_at_end_of_scope().unwrap();
    let metadata =
        fs::metadata(dir.path()).expect("Could not get the permissions of the new test directory.");
    let mut permissions = metadata.permissions();
    permissions.set_mode(mode);
    fs::set_permissions(dir.path(), permissions)
        .expect("Could not set the permissions of the new test directory.");
    dir
}

/// Creates a new, temporary directory, and returns it as `TempDir`. The
/// temporary directory exists as long as the returned `TempDir` does.
pub fn temp_dir() -> TempDir {
    tempfile::Builder::new()
        .prefix("ic_crypto_")
        .tempdir()
        .expect("unable to create temp dir")
}

/// Converts the given temporary directory into a string.
pub fn path_str(temp_dir: &TempDir) -> &str {
    temp_dir
        .path()
        .to_str()
        .expect("path could not be converted to string")
}
