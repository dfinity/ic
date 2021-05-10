//! Functions related to spawning processes and executing commands.

use std::convert::AsRef;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::{env, path};

/// Tests whether `file` exists in any of the directories listed in the `PATH`
/// environment variable.
pub fn is_file_on_path(file: impl AsRef<OsStr>) -> bool {
    find_file_on_path(file).is_some()
}

/// Finds the `file` in the directories listed in the `PATH` environment
/// variable.
pub fn find_file_on_path(file: impl AsRef<OsStr>) -> Option<path::PathBuf> {
    find_file(file, env::var_os("PATH")?.as_os_str())
}

fn find_file(
    file: impl AsRef<OsStr>,
    colon_separated_path: impl AsRef<OsStr>,
) -> Option<path::PathBuf> {
    colon_separated_path
        .as_ref()
        .as_bytes()
        .split(|b| *b == b':')
        .find_map(|p| {
            let path = path::PathBuf::from(OsStr::from_bytes(p)).join(file.as_ref());
            if path.exists() {
                Some(path)
            } else {
                None
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::fs;

    #[test]
    fn can_find_sh() {
        let tmp_dir = tempfile::TempDir::new().expect("failed to create a temporary directory");
        fs::write(tmp_dir.path().join("sh"), "command interpreter").unwrap();
        assert_eq!(
            find_file("sh", tmp_dir.path()),
            Some(tmp_dir.path().join("sh"))
        );
    }

    #[test]
    fn can_find_colon_separated() {
        let tmp_dir_1 = tempfile::TempDir::new().expect("failed to create a temporary directory");
        let tmp_dir_2 = tempfile::TempDir::new().expect("failed to create a temporary directory");
        fs::write(tmp_dir_2.path().join("sh"), "command interpreter").unwrap();
        let mut path = OsString::from(tmp_dir_1.path());
        path.push(OsStr::from_bytes(&[b':'][..]));
        path.push(tmp_dir_2.path());
        assert!(find_file("sh", path.as_os_str()).is_some());
    }

    #[test]
    fn can_not_find_nonexistent() {
        let tmp_dir = tempfile::TempDir::new().expect("failed to create a temporary directory");
        assert!(find_file("sh", tmp_dir.path()).is_none());
    }
}
