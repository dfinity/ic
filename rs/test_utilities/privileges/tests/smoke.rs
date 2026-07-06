//! Smoke tests for `run_as_nobody_if_root`.
//!
//! When run as a regular user these exercise the in-process path; when run as
//! root (e.g. on a Bazel remote-execution worker) they exercise the forked,
//! privilege-dropping path.

use ic_test_utilities_privileges::run_as_nobody_if_root;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;

#[test]
fn should_return_success() {
    run_as_nobody_if_root(|| {});
}

#[test]
#[should_panic(expected = "boom: 42")]
fn should_propagate_panic_message() {
    run_as_nobody_if_root(|| panic!("boom: {}", 42));
}

#[test]
fn should_deny_write_to_read_only_file() {
    run_as_nobody_if_root(|| {
        let dir = tempfile::tempdir().expect("failed to create a temp dir");
        let path = dir.path().join("read-only");
        std::fs::write(&path, b"before").expect("failed to create the file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))
            .expect("failed to make the file read-only");

        let err = std::fs::write(&path, b"after").expect_err("write should be denied");

        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    });
}

#[test]
fn should_spawn_many_concurrently() {
    // Regression test for fork-safety: forking from a multi-threaded process
    // must not deadlock the children (e.g. on locks that another thread of the
    // parent held at fork time).
    let handles: Vec<_> = (0..8)
        .map(|i| {
            std::thread::spawn(move || {
                for _ in 0..8 {
                    run_as_nobody_if_root(|| {
                        let dir = tempfile::tempdir().expect("failed to create a temp dir");
                        std::fs::write(dir.path().join("file"), format!("{i}"))
                            .expect("failed to write");
                    });
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().expect("worker thread panicked");
    }
}

mod attribute_form {
    use super::*;

    #[test]
    #[ic_test_utilities_privileges::as_nobody_when_root]
    fn should_return_success() {}

    #[test]
    #[should_panic(expected = "boom: 42")]
    #[ic_test_utilities_privileges::as_nobody_when_root]
    fn should_propagate_panic_message() {
        panic!("boom: {}", 42);
    }

    #[test]
    #[ic_test_utilities_privileges::as_nobody_when_root]
    fn should_deny_write_to_read_only_file() {
        let dir = tempfile::tempdir().expect("failed to create a temp dir");
        let path = dir.path().join("read-only");
        std::fs::write(&path, b"before").expect("failed to create the file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))
            .expect("failed to make the file read-only");

        let err = std::fs::write(&path, b"after").expect_err("write should be denied");

        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    }
}
