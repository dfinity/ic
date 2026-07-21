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
//! The [`as_nobody_when_root`] attribute is sugar wrapping a whole test body
//! in [`run_as_nobody_if_root`], avoiding the closure and its indentation.

/// Attribute form of [`run_as_nobody_if_root`]; see its documentation.
pub use ic_test_utilities_privileges_macros::as_nobody_when_root;

#[cfg(target_os = "linux")]
mod imp {
    use nix::libc;
    use nix::sys::wait::{WaitStatus, waitpid};
    use nix::unistd::{ForkResult, Gid, Uid, fork, geteuid, setgid, setgroups, setuid};
    use std::ffi::CString;
    use std::io::{PipeWriter, Read, Write};
    use std::os::unix::fs::{PermissionsExt, chown};
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
    ///   both at a `nobody`-owned base with mode `0700`, prepared by the parent.
    ///   The parent also grants others-execute on the base's ancestor
    ///   directories where missing, so `nobody` can traverse into it even when
    ///   the temp root is not world-traversable (as under some sandboxed
    ///   remote-execution setups); see `TmpDirRedirect::prepare`.
    /// * The parent test process may be multi-threaded, and after `fork` the
    ///   child must not wait on locks that another parent thread held at fork
    ///   time. The temp base and the `putenv(3)` strings are therefore prepared
    ///   in the parent before forking, and the child avoids `std::env::set_var`
    ///   (and with it `std`'s global environment lock), using only direct
    ///   syscalls to drop privileges and `_exit(2)` to terminate.
    pub fn run_as_nobody_if_root<F: FnOnce()>(action: F) {
        if geteuid().as_raw() != 0 {
            action();
            return;
        }
        run_forked(action);
    }

    /// The temp-dir redirection for the child, prepared in the parent (where
    /// allocating and taking locks is safe, since no fork has happened yet).
    struct TmpDirRedirect {
        /// The `nobody`-owned (mode `0700`) base directory for the child's
        /// temporary files, removed by the parent once the child has exited.
        base: PathBuf,
        /// `putenv`-style `NAME=VALUE` strings. After `putenv(3)` the child's
        /// `environ` references them directly, so they must stay allocated for
        /// the child's whole lifetime. This holds because the child `_exit`s
        /// inside `run_forked`, while this struct is still live in its frame.
        env_entries: [CString; 2],
    }

    impl TmpDirRedirect {
        /// Creates the base directory (as root, in the parent) and hands it
        /// over to `nobody` with mode `0700`, so the unprivileged child owns
        /// everything beneath it and no world-writable directory is created.
        fn prepare() -> Self {
            // Distinguishes concurrently prepared bases within one process.
            static SEQ: AtomicUsize = AtomicUsize::new(0);
            let temp_root = std::env::temp_dir();
            let base = temp_root.join(format!(
                "ic-nobody-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            // `create_dir` rather than `create_dir_all`: fail instead of
            // silently adopting a pre-existing directory of unknown ownership.
            std::fs::create_dir(&base).expect("failed to create the nobody temp base");
            chown(&base, Some(NOBODY), Some(NOBODY)).expect("failed to chown the nobody temp base");
            std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700))
                .expect("failed to chmod the nobody temp base");
            // The child creates its temporary files under `base` as `nobody`,
            // which requires *search* (execute) permission on every ancestor
            // directory. Some sandboxed remote-execution setups leave the temp
            // root not world-traversable: Namespace's
            // `namespace_action_isolation=sandboxed` runs the action as uid 0
            // with `TMPDIR` unset, so `std::env::temp_dir()` is a root-owned,
            // non-traversable `/tmp` that `nobody` cannot descend into. As root
            // (in the parent) grant others-execute on each ancestor that lacks
            // it — the minimal relaxation permitting traversal, without exposing
            // directory listings or write access (the base itself stays `0700`
            // `nobody`). The sandbox is ephemeral and per-action, so this has no
            // effect beyond the running test.
            //
            // Confine this to the default temp root (`/tmp`, used precisely
            // because `TMPDIR` is unset). An explicitly-configured `TMPDIR` is
            // left untouched, so running tests as root *outside* the sandbox
            // cannot be steered into world-traversing a sensitive directory
            // (e.g. `TMPDIR=/root/tmp` must not relax `/root`).
            if temp_root == std::path::Path::new("/tmp") {
                grant_ancestor_traversal(&base);
            }
            let entry = |name: &str| {
                CString::new(format!("{name}={}", base.display()))
                    .expect("temp base path contains an interior NUL byte")
            };
            Self {
                env_entries: [entry("TMPDIR"), entry("TEST_TMPDIR")],
                base,
            }
        }

        /// Points `TMPDIR`/`TEST_TMPDIR` at the prepared base; runs in the
        /// forked child.
        ///
        /// Uses `putenv(3)` with the pre-allocated strings instead of
        /// `std::env::set_var`, because the latter takes `std`'s global
        /// environment lock: if another thread of the parent held it at `fork`
        /// time, it would never be released in the child.
        fn apply_in_child(&self) -> nix::Result<()> {
            for entry in &self.env_entries {
                // SAFETY: `entry` points to a valid, NUL-terminated string that
                // stays allocated for the child's whole lifetime (see the
                // `env_entries` field documentation).
                if unsafe { libc::putenv(entry.as_ptr() as *mut libc::c_char) } != 0 {
                    return Err(nix::errno::Errno::last());
                }
            }
            Ok(())
        }
    }

    /// Adds others-execute (search) permission to every ancestor directory of
    /// `dir`, so the unprivileged `nobody` child can traverse the path down to
    /// it. Only the execute bit is added, and only to directories that lack it,
    /// so no directory becomes listable or writable by others. Runs as root in
    /// the parent; see the call site in `TmpDirRedirect::prepare` for why this
    /// is needed under sandboxed remote execution.
    fn grant_ancestor_traversal(dir: &std::path::Path) {
        // `ancestors()` yields `dir` first; skip it (it is already owned by
        // `nobody`) and walk its parent, grandparent, ... up to the root.
        for ancestor in dir.ancestors().skip(1) {
            let Ok(metadata) = std::fs::metadata(ancestor) else {
                // Unreadable ancestor (e.g. we walked above the mount root):
                // nothing to relax here.
                continue;
            };
            let mode = metadata.permissions().mode();
            if mode & 0o001 == 0 {
                std::fs::set_permissions(ancestor, std::fs::Permissions::from_mode(mode | 0o001))
                    .unwrap_or_else(|err| {
                        panic!(
                            "failed to make {} traversable for nobody: {err}",
                            ancestor.display()
                        )
                    });
            }
        }
    }

    fn run_forked<F: FnOnce()>(action: F) {
        // Prepared before forking; see `TmpDirRedirect`.
        let redirect = TmpDirRedirect::prepare();
        // Pipe used to forward the child's panic message to the parent.
        let (mut reader, writer) = std::io::pipe().expect("failed to create pipe");

        match unsafe { fork() }.expect("fork failed") {
            ForkResult::Child => {
                drop(reader);
                let mut writer = writer;
                let code = run_child(action, &redirect, &mut writer);
                // `_exit(2)` rather than `exit(3)`: skip the `atexit(3)`
                // handlers and stdio flushing inherited from the parent, which
                // must not run in the forked child of a (potentially
                // multi-threaded) test process.
                unsafe { libc::_exit(code) }
            }
            ForkResult::Parent { child } => {
                drop(writer);
                let mut message = String::new();
                let _ = reader.read_to_string(&mut message);
                let status = waitpid(child, None).expect("waitpid failed");
                let _ = std::fs::remove_dir_all(&redirect.base);
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
    fn run_child<F: FnOnce()>(
        action: F,
        redirect: &TmpDirRedirect,
        writer: &mut PipeWriter,
    ) -> i32 {
        if let Err(err) = redirect_tmp_and_drop_privileges(redirect) {
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

    fn redirect_tmp_and_drop_privileges(redirect: &TmpDirRedirect) -> nix::Result<()> {
        redirect.apply_in_child()?;

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
