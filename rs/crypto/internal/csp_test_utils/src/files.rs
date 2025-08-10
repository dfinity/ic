//! Utilities for file handling to test crypto code.
use std::fs;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

/// This creates a temporary directory with the given UNIX permissions.
/// Note:  TempDirs are deleted when they go out of scope.  The deletion
/// may not be immediate.  You will have undefined behaviour if you
/// operate outside the specification.
pub fn mk_temp_dir_with_permissions(mode: u32) -> TempDir {
    let temp_dir = tempfile::Builder::new()
        .prefix("ic_crypto_")
        .tempdir()
        .expect("failed to create temporary crypto directory");
    fs::set_permissions(temp_dir.path(), Permissions::from_mode(mode)).unwrap_or_else(|_| {
        panic!(
            "failed to set permissions of crypto directory {}",
            temp_dir.path().display()
        )
    });
    temp_dir
}

/// Creates a temporary directory for storing crypto state for testing.
/// The directory has the required permissions and will be automatically
/// deleted when the returned `TempDir` goes out of scope.
/// Panics if creating the directory or setting the permissions fails.
pub fn temp_dir() -> TempDir {
    mk_temp_dir_with_permissions(0o750)
}

/// Converts the given temporary directory into a string.
pub fn path_str(temp_dir: &TempDir) -> &str {
    temp_dir
        .path()
        .to_str()
        .expect("path could not be converted to string")
}
