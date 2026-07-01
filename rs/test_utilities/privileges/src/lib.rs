//! A test helper for running permission-sensitive assertions as an
//! unprivileged user.
//!
//! Many tests assert that a filesystem operation fails with
//! [`std::io::ErrorKind::PermissionDenied`]. Such assertions only hold for a
//! non-root user: root holds `CAP_DAC_OVERRIDE` and therefore bypasses the
//! `rwx` permission bits. When the test process runs as root (for example under
//! some remote-execution setups) those tests instead observe the operation
//! *succeeding* and fail.
//!
//! [`run_as_nobody_if_root`] runs a closure as the unprivileged `nobody` user
//! when the current process is root, and unchanged (in-process) otherwise.

#[cfg(target_os = "linux")]
mod imp {
    use nix::sys::wait::{WaitStatus, waitpid};
    use nix::unistd::{ForkResult, Gid, Uid, fork, geteuid, setgid, setgroups, setuid};
    use std::io::{PipeWriter, Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::path::PathBuf;

    /// The conventional uid/gid of the unprivileged `nobody`/`nogroup` user.
    /// Using the numeric id directly means no `/etc/passwd` entry is required.
    const NOBODY: u32 = 65534;

    /// The exit code a child uses to signal that `action` panicked. Matches the
    /// exit code the standard test harness uses for a failing test.
    const PANIC_EXIT_CODE: i32 = 101;

    /// Runs `action`, first dropping to the unprivileged `nobody` user if the
    /// current process is running as root.
    ///
    /// When the effective uid is not `0`, `action` simply runs in-process, so
    /// behavior is unchanged for the common (non-root) case. When it is `0`,
    /// `action` runs in a forked child that redirects the temporary directory to
    /// a `nobody`-owned location and then drops its supplementary groups, group,
    /// and user to `nobody` (which also clears `CAP_DAC_OVERRIDE`), so that
    /// filesystem permission bits are enforced.
    ///
    /// The child's outcome is mirrored in the caller: if `action` panics, the
    /// caller panics with the same message (so `#[should_panic]`, including
    /// `expected = "..."`, keeps working); if it returns, the caller returns.
    ///
    /// # Notes
    /// * The *whole* closure runs in the child, so any temporary files it
    ///   creates are owned by `nobody`; restricting their permissions therefore
    ///   denies `nobody` exactly as it would a normal non-root owner. Threads
    ///   spawned by `action` also run as `nobody`.
    /// * Temporary directories must be derived from `TMPDIR`/`TEST_TMPDIR` (as
    ///   `tempfile` and `ic_test_utilities_tmpdir::tmpdir` are); the child points
    ///   both at a world-writable, `nobody`-owned base.
    pub fn run_as_nobody_if_root<F: FnOnce()>(action: F) {
        if geteuid().as_raw() != 0 {
            action();
            return;
        }
        run_forked(action);
    }

    fn run_forked<F: FnOnce()>(action: F) {
        // Pipe used to forward the child's panic message to the parent.
        let (mut reader, writer) = std::io::pipe().expect("failed to create pipe");

        match unsafe { fork() }.expect("fork failed") {
            ForkResult::Child => {
                drop(reader);
                let mut writer = writer;
                let code = run_child(action, &mut writer);
                // Skip destructors / at-exit handlers inherited from the parent.
                std::process::exit(code);
            }
            ForkResult::Parent { child } => {
                drop(writer);
                let mut message = String::new();
                let _ = reader.read_to_string(&mut message);
                let status = waitpid(child, None).expect("waitpid failed");
                let _ = std::fs::remove_dir_all(nobody_tmp_base(child.as_raw()));
                match status {
                    WaitStatus::Exited(_, 0) => {}
                    WaitStatus::Exited(_, code) if code == PANIC_EXIT_CODE => {
                        // Re-raise the child's panic (with its message) so that
                        // `#[should_panic]` matches and the failure is visible.
                        panic!("{message}");
                    }
                    other => panic!("unprivileged child process did not exit cleanly: {other:?}"),
                }
            }
        }
    }

    /// Runs `action` in the forked child as `nobody`, returning the process exit
    /// code: `0` on success, [`PANIC_EXIT_CODE`] on panic.
    fn run_child<F: FnOnce()>(action: F, writer: &mut PipeWriter) -> i32 {
        if let Err(err) = redirect_tmp_and_drop_privileges() {
            let _ = write!(writer, "failed to drop privileges to nobody: {err}");
            return PANIC_EXIT_CODE;
        }
        match catch_unwind(AssertUnwindSafe(action)) {
            Ok(()) => 0,
            Err(payload) => {
                let _ = write!(writer, "{}", panic_message(payload.as_ref()));
                PANIC_EXIT_CODE
            }
        }
    }

    /// A world-writable base directory, created (as root) before privileges are
    /// dropped, in which the `nobody` child owns everything it creates.
    fn nobody_tmp_base(pid: i32) -> PathBuf {
        std::env::temp_dir().join(format!("ic-nobody-{pid}"))
    }

    fn redirect_tmp_and_drop_privileges() -> nix::Result<()> {
        // Point the temp-dir helpers at a base the `nobody` child can own, so
        // that files it creates (and then restricts) deny `nobody` as an owner.
        let base = nobody_tmp_base(std::process::id() as i32);
        std::fs::create_dir_all(&base).map_err(|_| nix::errno::Errno::EACCES)?;
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o777))
            .map_err(|_| nix::errno::Errno::EACCES)?;
        // SAFETY: the child is single-threaded after `fork`, so mutating the
        // environment here cannot race with other threads.
        unsafe {
            std::env::set_var("TMPDIR", &base);
            std::env::set_var("TEST_TMPDIR", &base);
        }

        // Order matters: drop the supplementary groups and gid while we still
        // hold `CAP_SETGID` (i.e. before dropping the uid).
        setgroups(&[])?;
        setgid(Gid::from_raw(NOBODY))?;
        setuid(Uid::from_raw(NOBODY))?;
        Ok(())
    }

    fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
        if let Some(s) = payload.downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else {
            "unprivileged action panicked with a non-string payload".to_string()
        }
    }
}

#[cfg(target_os = "linux")]
pub use imp::run_as_nobody_if_root;

/// On non-Linux platforms, dropping privileges is a no-op: `action` runs directly.
#[cfg(not(target_os = "linux"))]
pub fn run_as_nobody_if_root<F: FnOnce()>(action: F) {
    action();
}
