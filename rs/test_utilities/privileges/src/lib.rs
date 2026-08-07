//! A test helper for asserting that filesystem permission bits are enforced.
//!
//! Many tests assert that a filesystem operation fails with
//! [`std::io::ErrorKind::PermissionDenied`]. Such an assertion only holds for a
//! process that does *not* hold `CAP_DAC_OVERRIDE`/`CAP_DAC_READ_SEARCH`: those
//! two capabilities let their holder (in practice, root) bypass the `rwx`
//! permission bits. Under remote-execution setups that run Bazel test actions as
//! uid 0 the operation therefore *succeeds*, and the test fails.
//!
//! [`run_with_file_permissions_enforced`] drops exactly those two capabilities
//! from the effective set of the *calling thread*, runs a closure, and restores
//! them afterwards — including while unwinding from a panic. The
//! [`enforce_file_permissions`] attribute is sugar wrapping a whole test body in
//! it, avoiding the closure and its indentation.
//!
//! # Limitations
//!
//! The helper makes the kernel enforce the permission bits against the calling
//! thread. It is not a sandbox, and three things are deliberately outside what
//! it can express. None is reachable from the current call sites, and each one
//! fails loudly (the guarded assertion expects a denial, so a bypass makes the
//! test fail rather than pass):
//!
//! * `access(2)`/`faccessat(2)` re-raise the effective set from the permitted
//!   set whenever the *real* uid is 0, so they keep reporting access as granted
//!   no matter what this helper does. Assert on a real operation
//!   ([`std::fs::File::open`], [`std::fs::write`], ...) rather than on an
//!   access check.
//! * Only the calling thread and threads it goes on to create are affected;
//!   capabilities are copied at thread creation. Work handed to a thread that
//!   *already* existed — a global runtime, a `OnceLock` thread pool — runs with
//!   the full sets. Create such pools inside the closure, and make sure they
//!   have terminated by the time it returns: the guard restores only the
//!   thread it was created on, so a thread spawned inside that outlives the
//!   closure keeps the reduced sets for the rest of its life. That is harmless
//!   for one that simply exits, but a pool stashed somewhere global would go
//!   on to deny later, unrelated work.
//! * `execve` as uid 0 restores the full capability sets, so a subprocess
//!   spawned inside the closure regains `CAP_DAC_OVERRIDE`.

/// Attribute form of [`run_with_file_permissions_enforced`]; see its documentation.
pub use ic_test_utilities_privileges_macros::enforce_file_permissions;

#[cfg(target_os = "linux")]
mod imp {
    use std::io;
    use std::marker::PhantomData;

    /// Capability bit numbers (see `<linux/capability.h>`); both are < 32 so
    /// they live in the first of the two 32-bit capability words.
    const CAP_DAC_OVERRIDE: u32 = 1;
    const CAP_DAC_READ_SEARCH: u32 = 2;

    /// The capabilities that let their holder bypass the `rwx` permission bits:
    /// `CAP_DAC_OVERRIDE` (read, write, and — for files with at least one
    /// execute bit — execute) and `CAP_DAC_READ_SEARCH` (read, and search on
    /// directories). These two are exactly what the kernel consults in
    /// `generic_permission()`, so dropping both, and only both, is the minimal
    /// change that makes it enforce the permission bits against us.
    ///
    /// `CAP_FOWNER` is deliberately *not* dropped: it is not consulted by that
    /// path, so keeping it weakens no assertion, and tests routinely `chmod`
    /// back the files they made inaccessible in order to clean up.
    const DAC_BYPASS_MASK: u32 = (1 << CAP_DAC_OVERRIDE) | (1 << CAP_DAC_READ_SEARCH);

    /// `_LINUX_CAPABILITY_VERSION_3`: 64-bit capabilities, i.e. two data words.
    /// The version matters — `_LINUX_CAPABILITY_VERSION_1` is still accepted by
    /// modern kernels but silently truncates the capability sets to their lower
    /// 32 bits, permanently discarding everything above `CAP_AUDIT_READ`.
    const CAP_VERSION_3: u32 = 0x2008_0522;

    /// The `libc` crate does not expose the capability get/set structs, so
    /// declare them here to match the kernel's stable `capget(2)`/`capset(2)`
    /// ABI for `_LINUX_CAPABILITY_VERSION_3`: a header plus an array of two
    /// 32-bit data words (covering capabilities 0..64).
    ///
    /// `pid: 0` designates the *calling thread*. Capabilities are a per-thread
    /// property, and `capset` compares a non-zero `pid` against the caller's
    /// thread id, so `0` is also the only value that works from a thread other
    /// than the main one.
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: libc::c_int,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    fn header() -> CapHeader {
        CapHeader {
            version: CAP_VERSION_3,
            pid: 0,
        }
    }

    /// Reads the calling thread's capability sets.
    fn capget() -> io::Result<[CapData; 2]> {
        let mut header = header();
        let mut data = [CapData::default(); 2];
        // SAFETY: `capget` reads `header` and writes exactly the two `CapData`
        // words that `_LINUX_CAPABILITY_VERSION_3` prescribes. Both pointers
        // are derived from live, correctly aligned `#[repr(C)]` locals that
        // outlive the call, and the syscall has no effect beyond writing
        // through them.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_capget,
                &mut header as *mut CapHeader,
                data.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(data)
    }

    /// Sets the calling thread's *effective* capability word for capabilities
    /// 0..32.
    ///
    /// `capset` always writes all three sets at once, so the current ones are
    /// read back first and the permitted and inheritable sets — and the second
    /// data word, for capabilities 32..64 — are handed back verbatim. Leaving
    /// the permitted set alone is what makes restoring infallible: the kernel
    /// only requires `effective ⊆ permitted`, so re-raising a capability that
    /// was effective a moment ago is always accepted.
    fn set_effective_low_word(effective: u32) -> io::Result<()> {
        let mut header = header();
        let mut data = capget()?;
        data[0].effective = effective;
        // SAFETY: `capset` reads `header` and the two `CapData` words; both
        // pointers are derived from live, correctly aligned `#[repr(C)]` locals
        // that outlive the call, and the syscall writes through neither.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_capset,
                &mut header as *mut CapHeader,
                data.as_ptr(),
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Whether the calling thread currently holds a capability that lets it
    /// bypass the file permission bits.
    ///
    /// Outside [`run_with_file_permissions_enforced`] this answers "am I running
    /// privileged", which is `true` on a remote-execution worker running test
    /// actions as uid 0 and `false` for an ordinary user; inside it, it is
    /// `false` either way.
    pub fn bypasses_file_permissions() -> bool {
        let data = capget().unwrap_or_else(|err| panic!("capget failed: {err}"));
        data[0].effective & DAC_BYPASS_MASK != 0
    }

    /// Restores the capabilities that [`drop_dac_bypass`] took away when it goes
    /// out of scope, including while unwinding from a panic in the action —
    /// which is why this is a guard and not a pair of calls around it.
    struct RestoreDacBypass {
        /// The subset of [`DAC_BYPASS_MASK`] that was effective before the drop
        /// and therefore has to be raised again.
        dropped: u32,
        /// Capabilities are per-thread, so the guard has to be dropped on the
        /// thread that created it: moving it elsewhere would raise capabilities
        /// on a thread that never dropped them and leave this one deprivileged.
        /// A `PhantomData` over a raw pointer opts the whole struct out of
        /// `Send`/`Sync` — raw pointers implement neither — so the compiler
        /// enforces that rather than leaving it to a comment. The assertion
        /// below keeps it that way.
        _not_send: PhantomData<*const ()>,
    }

    static_assertions::assert_not_impl_any!(RestoreDacBypass: Send, Sync);

    impl Drop for RestoreDacBypass {
        fn drop(&mut self) {
            let restore = || -> io::Result<()> {
                let effective = capget()?[0].effective;
                set_effective_low_word(effective | self.dropped)
            };
            if let Err(err) = restore() {
                // Unreachable in practice: the permitted set was left untouched
                // and `self.dropped` was effective moments ago, so the kernel
                // has no grounds to refuse. Should it happen anyway, the thread
                // is left permanently deprivileged — and the test harness runs
                // later tests on this same thread when it is not parallel — so
                // failing quietly is not an option. `abort` rather than `panic!`
                // because panicking here while already unwinding would abort
                // anyway, having first destroyed the original failure message.
                eprintln!(
                    "failed to restore CAP_DAC_OVERRIDE/CAP_DAC_READ_SEARCH \
                     (0x{:08x}) after the action, aborting to avoid running \
                     later tests on a deprivileged thread: {err}",
                    self.dropped
                );
                std::process::abort();
            }
        }
    }

    /// Runs `action` with the file permission bits enforced against the caller,
    /// and returns its result.
    ///
    /// `CAP_DAC_OVERRIDE` and `CAP_DAC_READ_SEARCH` are removed from the
    /// effective capability set of the calling thread for the duration of
    /// `action`, so a test asserting [`std::io::ErrorKind::PermissionDenied`]
    /// observes the denial even when the test process runs as root (as under
    /// some remote-execution setups). For an ordinary unprivileged process the
    /// two capabilities are not held in the first place, and this costs a single
    /// `capget(2)`.
    ///
    /// The caller keeps its uid and its ownership of everything it creates, so
    /// `chmod`-based teardown inside `action` keeps working.
    ///
    /// See the crate documentation for what this does *not* cover.
    pub fn run_with_file_permissions_enforced<T>(action: impl FnOnce() -> T) -> T {
        let _guard = drop_dac_bypass();
        action()
    }

    /// Drops the DAC-bypass capabilities from the calling thread, returning the
    /// guard that restores them, or `None` if they were not held anyway.
    fn drop_dac_bypass() -> Option<RestoreDacBypass> {
        let before = capget().unwrap_or_else(|err| panic!("capget failed: {err}"));
        let dropped = before[0].effective & DAC_BYPASS_MASK;
        if dropped == 0 {
            // The ordinary unprivileged case: the permission bits are already
            // enforced against us and no `capset` is issued at all. Note this
            // deliberately keys off the capabilities rather than off
            // `geteuid() == 0`, which is neither necessary (file capabilities)
            // nor sufficient (uid 0 in a user namespace with an empty set).
            return None;
        }
        set_effective_low_word(before[0].effective & !DAC_BYPASS_MASK).unwrap_or_else(|err| {
            // Lowering effective capabilities is unconditionally permitted, so
            // this cannot legitimately fail — and carrying on would run the
            // action privileged, i.e. decide the assertions it guards for the
            // wrong reason.
            panic!(
                "capset failed while dropping CAP_DAC_OVERRIDE/CAP_DAC_READ_SEARCH \
                 (effective 0x{:08x}): {err}",
                before[0].effective
            )
        });
        // Construct the guard *before* the checks below, so that a failing check
        // unwinds through it and restores the capabilities rather than leaving
        // the thread deprivileged.
        let guard = RestoreDacBypass {
            dropped,
            _not_send: PhantomData,
        };
        assert_dac_bypass_cleared(&before);
        assert_permission_bits_enforced();
        Some(guard)
    }

    /// Reads the capability sets back and panics unless the DAC-bypass bits are
    /// really gone and nothing but the effective set changed.
    ///
    /// This is what keeps a mistake here — a wrong bit number, a wrong
    /// capability version, a `capset` that reported success without taking
    /// effect — from quietly reverting every caller to running fully privileged,
    /// where the assertions they exist for would no longer mean anything.
    ///
    /// Both capability words are compared, not just the low one holding the two
    /// bits of interest. That is what catches a `capset` issued with
    /// `_LINUX_CAPABILITY_VERSION_1`, whose single-word ABI modern kernels still
    /// accept while silently zeroing the *upper* word of the permitted and
    /// inheritable sets — discarding `CAP_AUDIT_READ` and everything above it.
    fn assert_dac_bypass_cleared(before: &[CapData; 2]) {
        let after = capget().unwrap_or_else(|err| panic!("capget failed: {err}"));
        assert_eq!(
            after[0].effective & DAC_BYPASS_MASK,
            0,
            "CAP_DAC_OVERRIDE/CAP_DAC_READ_SEARCH are still effective after capset \
             (effective 0x{:08x}, permitted 0x{:08x}); the file permission bits would \
             not be enforced, so the assertions guarded by this helper would be \
             decided for the wrong reason",
            after[0].effective,
            after[0].permitted,
        );
        for (word, (before, after)) in before.iter().zip(after.iter()).enumerate() {
            assert_eq!(
                (after.permitted, after.inheritable),
                (before.permitted, before.inheritable),
                "capset changed more than the effective set in capability word {word} \
                 (permitted 0x{:08x} -> 0x{:08x}, inheritable 0x{:08x} -> 0x{:08x}); \
                 restoring the effective set afterwards may no longer be possible",
                before.permitted,
                after.permitted,
                before.inheritable,
                after.inheritable,
            );
        }
    }

    /// Confirms behaviourally, once per process, that the permission bits are
    /// now enforced: creates a mode `0000` file and checks that reading it is
    /// denied.
    ///
    /// [`assert_dac_bypass_cleared`] proves the capability bits are clear; this
    /// proves the kernel acts on that in the environment the tests really run
    /// in, which is the whole reason this crate exists. It runs only when
    /// capabilities were in fact dropped, and at most once per test binary.
    ///
    /// Note the probe has to be a real read: `access(2)` restores the effective
    /// set from the permitted set whenever the real uid is 0, so it would report
    /// success here regardless and defeat the check.
    fn assert_permission_bits_enforced() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::OnceLock;

        static PROBED: OnceLock<()> = OnceLock::new();
        PROBED.get_or_init(|| {
            let Ok(dir) = tempfile::tempdir() else {
                // A temp directory we cannot create is not evidence of
                // anything, so a failure to *set up* the probe skips it rather
                // than failing the test that happened to run it first.
                return;
            };
            let path = dir.path().join("unreadable");
            let setup = std::fs::write(&path, b"probe").and_then(|()| {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))
            });
            if setup.is_err() {
                return;
            }
            let denied = std::fs::read(&path)
                .err()
                .map(|err| err.kind() == std::io::ErrorKind::PermissionDenied)
                .unwrap_or(false);
            // Make the file removable again before asserting, so a failure here
            // does not also leave `dir` undeletable.
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            assert!(
                denied,
                "reading a mode 0000 file succeeded even though \
                 CAP_DAC_OVERRIDE/CAP_DAC_READ_SEARCH were dropped; the file permission \
                 bits are not being enforced against this process, so the assertions \
                 guarded by this helper are meaningless"
            );
        });
    }
}

#[cfg(target_os = "linux")]
pub use imp::{bypasses_file_permissions, run_with_file_permissions_enforced};

/// On non-Linux platforms there are no capabilities to drop, so `action` runs
/// directly. The affected tests are Linux-only in practice: this crate exists
/// for Linux remote-execution workers that run test actions as uid 0.
#[cfg(not(target_os = "linux"))]
pub fn run_with_file_permissions_enforced<T>(action: impl FnOnce() -> T) -> T {
    action()
}

/// See the Linux implementation; there is no equivalent notion elsewhere.
#[cfg(not(target_os = "linux"))]
pub fn bypasses_file_permissions() -> bool {
    false
}
