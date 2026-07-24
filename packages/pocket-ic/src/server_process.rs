//! Process-lifetime management for the spawned `pocket-ic-server`.
//!
//! Historically [`crate::start_server`] spawned the server, detached it into its own
//! process group (`process_group(0)`) and then discarded the [`Child`] handle, so the
//! server — and the canister-sandbox processes it re-execs — outlived the spawning
//! process. Under a remote-execution worker that only completes once the test action's
//! stdout/stderr pipes reach EOF, the lingering server (and its sandbox children, which
//! inherit those pipes) kept the pipe write-ends open, and the action failed with
//! `WaitDelay expired before I/O complete`.
//!
//! To fix this, every spawned server is transferred to a process-global registry. On
//! unix a `libc::atexit` callback — which runs when the process exits *normally* (for a
//! test binary: once all `#[test]`s have finished and the harness is exiting; not when
//! the process is killed by a signal or aborts, in which case the server falls back to
//! shutting down on its TTL) — kills each server's whole process *group* (so the sandbox
//! children die too and release the inherited pipes) and reaps it. This also closes
//! `SDK-1936` (properly reap the spawned child instead of leaking a zombie).

use std::path::PathBuf;
use std::process::Child;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
#[cfg(unix)]
use std::time::{Duration, Instant};

/// A spawned `pocket-ic-server` candidate, owned exclusively by the [`registry`].
struct ServerProc {
    child: Child,
    /// Path to the server's port file. The server removes the file itself only when it
    /// shuts down gracefully, so it is removed as best-effort cleanup whenever the server
    /// is killed *by us* ([`ServerHandle::kill_and_wait`] or the exit-time reaper): a
    /// stale `reuse: true` port file (named after this process's pid) could otherwise be
    /// trusted by a later process that gets the same pid recycled, handing it a URL
    /// nothing listens on. A server that died for any other reason keeps its file: with
    /// `reuse: true` the file may belong to a different, still-live server, and removing
    /// it could leave a concurrent [`crate::start_server`] call polling for the file
    /// forever.
    #[cfg(unix)]
    port_file_path: PathBuf,
    /// The server's process-group id. The client spawns the server with
    /// `process_group(0)`, so the server is a group *leader* and `pgid == child.id()`.
    /// The launcher/sandbox processes it re-execs inherit this group (they set no
    /// `setpgid`/`setsid`), so signalling the group reaches all of them.
    #[cfg(unix)]
    pgid: libc::pid_t,
}

/// The process-global registry of spawned servers.
struct Registry {
    /// The pid of the process the registry's entries belong to. `fork()`ed children
    /// inherit both the atexit registration and the registry's memory; [`reap_all`]
    /// compares this against `getpid()` so that a forked child exiting normally does not
    /// kill the servers its parent is still using. A forked child that spawns servers of
    /// its own first disowns the inherited entries and adopts the registry — updating
    /// this pid — so its own servers are still reaped at its exit (see [`register`]).
    #[cfg(unix)]
    owner_pid: AtomicI32,
    /// The spawned servers, indexed by the [`ServerHandle`] returned to callers. A slot
    /// becomes `None` once its server has been reaped (by [`ServerHandle::kill_and_wait`],
    /// the opportunistic sweep in [`register`] or the exit-time reaper) or has been
    /// [`ServerHandle::detach`]ed, so no server is signalled or waited on twice. Slots are
    /// never removed, so a [`ServerHandle`]'s index stays valid.
    servers: Mutex<Vec<Option<ServerProc>>>,
}

/// Set by [`reap_all`] before it drains the registry. A server registered after that
/// drain (by a thread that outlives `main`) would never be signalled, so [`register`]
/// kills it immediately when this flag is set.
#[cfg(unix)]
static SHUTTING_DOWN: AtomicBool = AtomicBool::new(false);

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        // Install the exit-time reaper exactly once, when the first server is registered.
        // It runs from `libc::exit()` after the libtest harness returns or calls
        // `std::process::exit` — i.e. once every subtest has finished. This is *not* a
        // signal-handler context, so locking a `Mutex`, sleeping and `waitpid` are all
        // legal here; it only needs to be panic-free (see `reap_all`).
        #[cfg(unix)]
        {
            // SAFETY: `reap_all` is an `extern "C"`, panic-free function and is registered
            // exactly once (guarded by `OnceLock`).
            let rc = unsafe { libc::atexit(reap_all) };
            // A non-zero return means the handler was not registered, which would silently
            // reintroduce the leaked-server problem — fail loudly instead.
            assert_eq!(
                rc, 0,
                "failed to register the pocket-ic-server atexit reaper"
            );
        }
        Registry {
            #[cfg(unix)]
            owner_pid: AtomicI32::new(std::process::id() as libc::pid_t),
            servers: Mutex::new(Vec::new()),
        }
    })
}

fn lock_registry() -> MutexGuard<'static, Vec<Option<ServerProc>>> {
    // A poisoned registry is fine to keep using: the data is a plain list of child
    // handles and recovering it lets us still kill/reap the servers.
    registry().servers.lock().unwrap_or_else(|e| e.into_inner())
}

/// Transfers ownership of a freshly spawned `pocket-ic-server` [`Child`] to the
/// process-global registry and returns a [`ServerHandle`] referring to it.
///
/// The registry keeps the child alive for the remainder of the process (so the server
/// stays up for the whole test run). On unix it is then killed (its process group) and
/// reaped when the process exits normally, on a bounded, best-effort basis, replacing the
/// previous "spawn and leak" behaviour; on other platforms the child is not reaped
/// automatically and shuts down on its TTL.
pub(crate) fn register(child: Child, port_file_path: PathBuf) -> ServerHandle {
    #[cfg(not(unix))]
    let _ = &port_file_path;
    let pid = child.id();
    #[cfg(unix)]
    let pgid = pid as libc::pid_t;
    let idx = {
        let mut servers = lock_registry();
        // A `fork()`ed child inherits the registry, but the inherited entries belong to
        // the parent: their processes are not this process's children to signal or reap.
        // On the first registration after a fork, disown the inherited entries (clearing
        // the slots, so any inherited `ServerHandle`s go inert instead of aliasing new
        // entries) and adopt the registry for this process — the (equally inherited)
        // exit-time reaper then cleans up exactly the servers spawned by this process.
        #[cfg(unix)]
        {
            // SAFETY: getpid cannot fail and has no preconditions.
            let current_pid = unsafe { libc::getpid() };
            if registry().owner_pid.load(Ordering::SeqCst) != current_pid {
                for slot in servers.iter_mut() {
                    // Dropping a `Child` neither signals nor waits, so the parent's
                    // servers are untouched.
                    *slot = None;
                }
                registry().owner_pid.store(current_pid, Ordering::SeqCst);
            }
        }
        // Opportunistically clean up candidates that have already exited (e.g.
        // `reuse: true` candidates that lost the port-file race and exited on their own),
        // so they do not accumulate as zombies for the lifetime of long-lived processes.
        // The slot is cleared so the exit-time reaper never signals a pid/pgid that may
        // have been recycled after the reap.
        #[cfg(unix)]
        for slot in servers.iter_mut() {
            let Some(proc) = slot else { continue };
            // `waitid(WNOWAIT)` checks for termination *without* reaping, so the zombie
            // still pins the pid/pgid and the group signal below cannot hit a recycled
            // pid.
            if !has_terminated(proc.child.id() as libc::pid_t) {
                continue;
            }
            // Terminate any group members that survived the server itself (e.g. a
            // sandbox process orphaned by a server crash), which would otherwise no
            // longer be covered by the exit-time reaper once this slot is cleared.
            // `ESRCH` — the common case of an already-empty group — is harmless.
            unsafe { libc::kill(-proc.pgid, libc::SIGKILL) };
            // Reap the zombie. Its port file is deliberately left alone: unlike servers
            // killed by us, a server that died on its own either already cleaned the
            // file up gracefully or never owned it (see `ServerProc::port_file_path`).
            let _ = try_reap(proc);
            *slot = None;
        }
        #[cfg(not(unix))]
        for slot in servers.iter_mut() {
            if let Some(proc) = slot
                && matches!(proc.child.try_wait(), Ok(Some(_)))
            {
                *slot = None;
            }
        }
        servers.push(Some(ServerProc {
            child,
            #[cfg(unix)]
            port_file_path,
            #[cfg(unix)]
            pgid,
        }));
        servers.len() - 1
    };
    let handle = ServerHandle { idx, pid };
    // The exit-time reaper drains the registry only once: a server registered after that
    // (by a thread still spawning servers while the process exits) would never be
    // signalled and would outlive the process holding the inherited pipes — kill it
    // right away instead. The flag is set before the reaper takes the registry lock, so
    // a registration that misses the drain is guaranteed to observe it.
    #[cfg(unix)]
    if SHUTTING_DOWN.load(Ordering::SeqCst) {
        handle.kill_and_wait();
    }
    handle
}

/// A handle to a `pocket-ic-server` spawned by [`crate::start_server`].
///
/// The server is owned by a process-global registry. On unix it is killed and reaped
/// when the spawning process exits normally (on a bounded, best-effort basis; not when
/// the process is killed by a signal or aborts), so most callers can simply drop this
/// handle (dropping it does not stop the server). Callers that want to terminate the
/// server earlier — e.g. to test crash recovery — can call
/// [`ServerHandle::kill_and_wait`]; callers that want the server to outlive this process
/// can call [`ServerHandle::detach`].
#[derive(Debug)]
pub struct ServerHandle {
    idx: usize,
    pid: u32,
}

impl ServerHandle {
    /// The OS process id of the server process spawned by this [`crate::start_server`]
    /// call, e.g. for sending it custom signals or attaching diagnostics.
    ///
    /// With [`crate::StartServerParams::reuse`] the URL returned alongside this handle
    /// may belong to a server spawned by an earlier call (see
    /// [`ServerHandle::kill_and_wait`]); the pid always refers to the process spawned by
    /// *this* call. Once the server has been killed or has shut down on its own, the pid
    /// is stale: the server may linger briefly as an unreaped zombie, and after reaping
    /// the OS may recycle the pid for an unrelated process — do not send signals to a
    /// stale pid.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Kills the server now — its whole process group on unix, so the canister-sandbox
    /// children are terminated too — and makes a bounded, best-effort attempt to reap it.
    ///
    /// This is a *hard* kill (`SIGKILL` on unix): it does not give the server a chance to
    /// shut down gracefully or checkpoint state. The call blocks until the server is
    /// reaped or a bound of a few seconds expires (reaping typically takes milliseconds),
    /// so on return the process has been signalled (and, on unix, its whole group
    /// `SIGKILL`ed) but in rare cases may not yet be fully reaped; it is then left as a
    /// zombie for `init` to reap once this process exits. Idempotent with respect to the
    /// exit-time reaper: the server is removed from the registry here, so it is not
    /// signalled or waited on again at process exit. On unix the killed server's port
    /// file is removed as well, since the server did not get to clean it up itself.
    ///
    /// Note that with [`crate::StartServerParams::reuse`] this handle refers to the
    /// server candidate spawned by this [`crate::start_server`] call, which may not be
    /// the (shared) server behind the returned URL — killing a server is only meaningful
    /// with `reuse: false`. In particular, killing a `reuse: true` candidate that is
    /// still starting up removes the port file shared with the live server behind the
    /// URL, so later `reuse: true` calls spawn a fresh server instead of reusing it.
    pub fn kill_and_wait(&self) {
        let taken = lock_registry().get_mut(self.idx).and_then(Option::take);
        if let Some(proc) = taken {
            #[cfg(unix)]
            reap_procs(vec![proc], Signal::Kill);
            #[cfg(windows)]
            {
                let mut proc = proc;
                let _ = proc.child.kill();
                let _ = proc.child.wait();
            }
        }
    }

    /// Removes the server from the process-global registry *without* killing it: the
    /// server is no longer terminated when this process exits and keeps running until it
    /// shuts down on its TTL (see [`crate::StartServerParams`]), restoring the detached
    /// behaviour of earlier `pocket-ic` versions. Use this when the server must outlive
    /// the spawning process, e.g. to hand its URL to other processes.
    ///
    /// Idempotent, and a no-op if the server was already killed or reaped. On unix the
    /// detached server's zombie is reaped by `init` once this process exits.
    ///
    /// Note that with [`crate::StartServerParams::reuse`] this handle refers to the
    /// server candidate spawned by this [`crate::start_server`] call, which may not be
    /// the (shared) server behind the returned URL — that server may have been spawned
    /// by an earlier call and remains subject to the exit-time reaper, so detaching is
    /// only meaningful with `reuse: false`.
    pub fn detach(&self) {
        let taken = lock_registry().get_mut(self.idx).and_then(Option::take);
        // Dropping a `Child` neither kills nor reaps the process, which is exactly what
        // detaching means.
        drop(taken);
    }
}

/// How aggressively [`reap_procs`] terminates servers.
#[cfg(unix)]
#[derive(Clone, Copy)]
enum Signal {
    /// Request a graceful shutdown first (`SIGTERM` drives the server's `ctrlc` handler,
    /// which is built with the `termination` feature), escalating to `SIGKILL` if the
    /// server outlives a short grace period.
    TermThenKill,
    /// Immediate, uncatchable `SIGKILL`.
    Kill,
}

/// `libc::atexit` callback: kill and reap every server still registered.
///
/// Must be panic-free — unwinding across an `extern "C"` boundary is undefined
/// behaviour — hence the `catch_unwind`.
#[cfg(unix)]
extern "C" fn reap_all() {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // atexit registrations and the registry's memory are inherited across `fork()`:
        // a forked child exiting normally must not kill the servers its parent is still
        // using. (A forked child that spawned servers of its own has adopted the
        // registry — and disowned the parent's entries — in `register`, so it passes
        // this check and reaps exactly its own servers.)
        // SAFETY: getpid cannot fail and has no preconditions.
        if unsafe { libc::getpid() } != registry().owner_pid.load(Ordering::SeqCst) {
            return;
        }
        // From here on, late registrations kill their server themselves (see `register`).
        SHUTTING_DOWN.store(true, Ordering::SeqCst);
        let taken: Vec<ServerProc> = {
            let mut servers = lock_registry();
            servers.iter_mut().filter_map(Option::take).collect()
        };
        reap_procs(taken, Signal::TermThenKill);
    }));
}

/// Grace period given to each signal before escalating / giving up.
#[cfg(unix)]
const REAP_GRACE: Duration = Duration::from_millis(2_000);

/// Signals each server's process group and makes a bounded, best-effort attempt to reap
/// the direct server children.
///
/// A child's launcher/sandbox descendants are terminated by the process-group signal
/// (their pipe write-ends close on *termination*, not on reaping) and are reaped by init,
/// since this process cannot `waitpid` them (they are not its direct children).
///
/// All groups are signalled up front and then reaped against one shared deadline, so the
/// whole operation is bounded by 2 × [`REAP_GRACE`] no matter how many servers are still
/// running — it can never hang process exit. Children not reaped within the first
/// [`REAP_GRACE`] get their group `SIGKILL`ed and one more [`REAP_GRACE`] window; children
/// *still* not reaped are left for init to reap once we exit — what matters here (closing
/// the inherited pipes) is already done by the kill.
#[cfg(unix)]
fn reap_procs(mut procs: Vec<ServerProc>, signal: Signal) {
    let first = match signal {
        Signal::TermThenKill => libc::SIGTERM,
        Signal::Kill => libc::SIGKILL,
    };
    for proc in &procs {
        // A negative target signals the whole process group (server + launcher +
        // sandboxes). `ESRCH` — e.g. a loser candidate whose group is already empty — is
        // expected and harmless: the reap below still reaps the zombie.
        unsafe { libc::kill(-proc.pgid, first) };
    }
    reap_procs_until(&mut procs, Instant::now() + REAP_GRACE);
    if procs.is_empty() {
        return;
    }
    // Still alive after the grace period: force-kill the groups and try once more.
    for proc in &procs {
        unsafe { libc::kill(-proc.pgid, libc::SIGKILL) };
    }
    reap_procs_until(&mut procs, Instant::now() + REAP_GRACE);
    // Whatever is left was `SIGKILL`ed but not reaped in time (and is left for init), so
    // its port file is stale and still needs to be cleaned up.
    for proc in &procs {
        remove_port_file(proc);
    }
}

/// Polls [`try_reap`] for each child until all are reaped/gone or `deadline` passes,
/// removing the reaped children from `procs`. Already-exited children (zombies) are
/// reaped by the first poll, so the deadline only comes into play for children that are
/// still alive.
///
/// A child that died from a signal (i.e. from the kill that brought us here) did not run
/// the server's graceful-shutdown path, so its port file is removed; a child that exited
/// by itself either already removed the file or never owned it (see
/// [`ServerProc::port_file_path`]).
#[cfg(unix)]
fn reap_procs_until(procs: &mut Vec<ServerProc>, deadline: Instant) {
    loop {
        procs.retain(|proc| match try_reap(proc) {
            ReapOutcome::StillRunning => true,
            ReapOutcome::Reaped { signaled } => {
                if signaled {
                    remove_port_file(proc);
                }
                false
            }
            ReapOutcome::Gone => false,
        });
        if procs.is_empty() || Instant::now() >= deadline {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The result of a [`try_reap`] call.
#[cfg(unix)]
enum ReapOutcome {
    /// The child is still running.
    StillRunning,
    /// The child was reaped; `signaled` says whether it was terminated by a signal
    /// (rather than exiting by itself).
    Reaped { signaled: bool },
    /// The child was already reaped elsewhere (`ECHILD`); its exit status is unknown.
    Gone,
}

/// Reaps a single direct child without blocking, retrying on `EINTR`.
///
/// `EINTR` (interrupted by a signal) is retried rather than treated as terminal, so an
/// interruption cannot cause an early return that leaves the server holding the pipes.
/// The expected terminal error is `ECHILD` (the child was already reaped / is not ours).
#[cfg(unix)]
fn try_reap(proc: &ServerProc) -> ReapOutcome {
    let pid = proc.child.id() as libc::pid_t;
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: reaping our own direct child by pid.
        match unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } {
            r if r == pid => {
                return ReapOutcome::Reaped {
                    signaled: libc::WIFSIGNALED(status),
                };
            }
            -1 if last_errno() == libc::EINTR => continue,
            -1 => return ReapOutcome::Gone,
            // Still running (`0`).
            _ => return ReapOutcome::StillRunning,
        }
    }
}

/// Non-destructively checks whether a direct child has terminated: unlike `waitpid`,
/// `waitid(WNOWAIT)` leaves the child reapable, so its pid/pgid stay reserved. Errors
/// (e.g. `ECHILD`) are reported as "not terminated" — the caller then simply leaves the
/// child to the exit-time reaper, whose `waitpid`/`kill` handle those cases.
#[cfg(unix)]
fn has_terminated(pid: libc::pid_t) -> bool {
    // SAFETY: a zeroed `siginfo_t` is a valid out-parameter; `waitid` only writes to it.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    // With `WNOHANG`, a live child yields success with `si_signo == 0` (the struct is
    // left zeroed), while a terminated child yields `si_signo == SIGCHLD`.
    rc == 0 && info.si_signo == libc::SIGCHLD
}

/// Best-effort removal of a killed server's port file (see [`ServerProc::port_file_path`]).
#[cfg(unix)]
fn remove_port_file(proc: &ServerProc) {
    let _ = std::fs::remove_file(&proc.port_file_path);
}

/// The calling thread's `errno`. Only meaningful immediately after a failed libc call.
#[cfg(unix)]
fn last_errno() -> libc::c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}
