//! Smoke tests for `run_with_file_permissions_enforced`.
//!
//! When run as a regular user these exercise the no-op path; when run as root
//! (e.g. on a Bazel remote-execution worker) they additionally exercise the
//! capability-dropping path. Every assertion below is written to hold either
//! way, so nothing is silently skipped on a developer machine.
//!
//! To exercise the privileged path locally:
//!
//! ```text
//! sudo -E env "PATH=$PATH" cargo test -p ic-test-utilities-privileges
//! ```

use ic_test_utilities_privileges::{bypasses_file_permissions, run_with_file_permissions_enforced};
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Barrier};

/// Creates a file with the given permission bits, returning the temp dir
/// holding it (which the caller must keep alive, since dropping it deletes the
/// file) and the path to it.
fn file_with_mode(mode: u32) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("failed to create a temp dir");
    let path = dir.path().join("file");
    std::fs::write(&path, b"before").expect("failed to create the file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
        .expect("failed to restrict the file");
    (dir, path)
}

#[test]
fn should_return_success() {
    run_with_file_permissions_enforced(|| {});
}

#[test]
fn should_return_the_action_result() {
    assert_eq!(run_with_file_permissions_enforced(|| 42), 42);
}

#[test]
#[should_panic(expected = "boom: 42")]
fn should_propagate_panic_message() {
    run_with_file_permissions_enforced(|| panic!("boom: {}", 42));
}

#[test]
fn should_deny_write_to_read_only_file() {
    run_with_file_permissions_enforced(|| {
        let (_dir, path) = file_with_mode(0o400);

        let err = std::fs::write(&path, b"after").expect_err("write should be denied");

        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    });
}

#[test]
fn should_deny_read_of_mode_000_file() {
    run_with_file_permissions_enforced(|| {
        let (_dir, path) = file_with_mode(0o000);

        let err = std::fs::read(&path).expect_err("read should be denied");

        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    });
}

#[test]
fn should_deny_traversal_of_non_searchable_directory() {
    // The only assertion here that fails if `CAP_DAC_OVERRIDE` is dropped but
    // `CAP_DAC_READ_SEARCH` is not: searching a directory needs one of the two.
    run_with_file_permissions_enforced(|| {
        let dir = tempfile::tempdir().expect("failed to create a temp dir");
        let path = dir.path().join("file");
        std::fs::write(&path, b"contents").expect("failed to create the file");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o600))
            .expect("failed to make the directory non-searchable");

        let err = std::fs::read(&path).expect_err("traversal should be denied");

        // Restore before `dir` is dropped so that it can be cleaned up.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("failed to make the directory searchable again");
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    });
}

#[test]
fn should_drop_the_bypass_inside_and_restore_it_afterwards() {
    let before = bypasses_file_permissions();

    run_with_file_permissions_enforced(|| {
        assert!(
            !bypasses_file_permissions(),
            "the DAC bypass should be dropped inside the action"
        );
    });

    assert_eq!(
        bypasses_file_permissions(),
        before,
        "the DAC bypass should be restored after the action"
    );
}

#[test]
fn should_restore_the_bypass_after_a_panic() {
    let before = bypasses_file_permissions();

    let result = std::panic::catch_unwind(|| {
        run_with_file_permissions_enforced(|| panic!("boom"));
    });

    assert!(result.is_err(), "the panic should propagate");
    assert_eq!(
        bypasses_file_permissions(),
        before,
        "the DAC bypass should be restored while unwinding"
    );
}

#[test]
fn should_drop_the_bypass_in_threads_spawned_by_the_action() {
    // Threads inherit the capability sets of the thread that creates them, so a
    // thread spawned inside the action must see the permission bits enforced
    // too. Several call sites rely on this (they hand the filesystem work to a
    // worker thread they spawn).
    run_with_file_permissions_enforced(|| {
        std::thread::spawn(|| {
            assert!(
                !bypasses_file_permissions(),
                "a thread spawned inside the action should inherit the drop"
            );
            let (_dir, path) = file_with_mode(0o400);
            let err = std::fs::write(&path, b"after").expect_err("write should be denied");
            assert_eq!(err.kind(), ErrorKind::PermissionDenied);
        })
        .join()
        .expect("the spawned thread panicked");
    });
}

#[test]
fn should_not_affect_other_threads() {
    // The load-bearing property of the whole design: capabilities are
    // per-thread, so dropping them here must leave a thread that already exists
    // untouched. Were this wrong, the ~500-test crypto binary would produce
    // random `PermissionDenied` failures in tests unrelated to the one that
    // dropped them.
    let before = bypasses_file_permissions();
    // Two rendezvous points: the first is reached while the main thread is
    // inside the action, the second releases it once the observer is done.
    let entered = Arc::new(Barrier::new(2));
    let observed = Arc::new(Barrier::new(2));

    let observer = std::thread::spawn({
        let (entered, observed) = (Arc::clone(&entered), Arc::clone(&observed));
        move || {
            entered.wait();
            let bypasses = bypasses_file_permissions();
            // ... and check it behaves accordingly, not just that the bit is set.
            let (_dir, path) = file_with_mode(0o400);
            let denied = std::fs::write(&path, b"after").is_err();
            observed.wait();
            (bypasses, denied)
        }
    });

    run_with_file_permissions_enforced(|| {
        entered.wait();
        observed.wait();
    });

    let (bypasses, denied) = observer.join().expect("the observer thread panicked");
    assert_eq!(
        bypasses, before,
        "dropping the DAC bypass must not affect a thread that already existed"
    );
    assert_eq!(
        denied, !before,
        "a pre-existing thread should still write a read-only file it owns iff it \
         holds the DAC bypass"
    );
}

#[test]
fn should_be_usable_concurrently_from_many_threads() {
    // Regression test for the fork-based implementation this replaced, which
    // deadlocked when called from a multi-threaded process. It now also covers
    // concurrent drops and restores not interfering with one another.
    let handles: Vec<_> = (0..8)
        .map(|i| {
            std::thread::spawn(move || {
                for _ in 0..8 {
                    run_with_file_permissions_enforced(|| {
                        assert!(!bypasses_file_permissions());
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
    #[ic_test_utilities_privileges::enforce_file_permissions]
    fn should_return_success() {}

    #[test]
    #[should_panic(expected = "boom: 42")]
    #[ic_test_utilities_privileges::enforce_file_permissions]
    fn should_propagate_panic_message() {
        panic!("boom: {}", 42);
    }

    #[test]
    #[ic_test_utilities_privileges::enforce_file_permissions]
    fn should_deny_write_to_read_only_file() {
        let (_dir, path) = file_with_mode(0o400);

        let err = std::fs::write(&path, b"after").expect_err("write should be denied");

        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    }

    #[test]
    #[ic_test_utilities_privileges::enforce_file_permissions]
    fn should_deny_read_of_mode_000_file() {
        let (_dir, path) = file_with_mode(0o000);

        let err = std::fs::read(&path).expect_err("read should be denied");

        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    }

    #[test]
    #[ic_test_utilities_privileges::enforce_file_permissions]
    fn should_support_a_return_type() -> std::io::Result<()> {
        let (_dir, path) = file_with_mode(0o000);
        assert_eq!(
            std::fs::read(&path)
                .expect_err("read should be denied")
                .kind(),
            ErrorKind::PermissionDenied
        );
        Ok(())
    }
}
