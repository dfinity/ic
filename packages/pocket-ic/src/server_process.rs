//! Process-lifetime management for the spawned `pocket-ic-server`.
//!
//! Historically [`crate::start_server`] spawned the server, detached it into its own
//! process group (`process_group(0)`) and then discarded the [`Child`] handle, so the
//! server — and the canister-sandbox processes it re-execs — outlived the test process.
//! Under a remote-execution worker that only completes once the test action's
//! stdout/stderr pipes reach EOF, the lingering server (and its sandbox children, which
//! inherit those pipes) kept the pipe write-ends open, and the action failed with
//! `WaitDelay expired before I/O complete`.
//!
//! To fix this, every spawned server is transferred to a process-global registry. On
//! unix a `libc::atexit` callback — which runs once all `#[test]`s in the binary have
//! finished and the harness is exiting — kills each server's whole process *group* (so
//! the sandbox children die too and release the inherited pipes) and reaps it. This also
//! closes `SDK-1936` (properly reap the spawned child instead of leaking a zombie).

use std::process::Child;
use std::sync::{Mutex, MutexGuard, OnceLock};
#[cfg(unix)]
use std::time::{Duration, Instant};

/// A spawned `pocket-ic-server` candidate, owned exclusively by the [`registry`].
struct ServerProc {
    child: Child,
    /// The server's process-group id. The client spawns the server with
    /// `process_group(0)`, so the server is a group *leader* and `pgid == child.id()`.
    /// The launcher/sandbox processes it re-execs inherit this group (they set no
    /// `setpgid`/`setsid`), so signalling the group reaches all of them.
    #[cfg(unix)]
    pgid: libc::pid_t,
}

/// The process-global set of spawned servers, indexed by the [`ServerHandle`] returned
/// to callers. A slot becomes `None` once its server has been reaped (by
/// [`ServerHandle::kill_and_wait`] or the exit-time reaper) so no server is signalled or
/// waited on twice. Slots are never removed, so a [`ServerHandle`]'s index stays valid.
fn registry() -> &'static Mutex<Vec<Option<ServerProc>>> {
    static SERVERS: OnceLock<Mutex<Vec<Option<ServerProc>>>> = OnceLock::new();
    SERVERS.get_or_init(|| {
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
        Mutex::new(Vec::new())
    })
}

fn lock_registry() -> MutexGuard<'static, Vec<Option<ServerProc>>> {
    // A poisoned registry is fine to keep using: the data is a plain list of child
    // handles and recovering it lets us still kill/reap the servers.
    registry().lock().unwrap_or_else(|e| e.into_inner())
}

/// Transfers ownership of a freshly spawned `pocket-ic-server` [`Child`] to the
/// process-global registry and returns a [`ServerHandle`] referring to it.
///
/// The registry keeps the child alive for the remainder of the process (so the server
/// stays up for the whole test run). On unix it is then killed (its process group) and
/// reaped at process exit on a bounded, best-effort basis, replacing the previous
/// "spawn and leak" behaviour; on other platforms the child is not reaped automatically
/// and shuts down on its TTL.
pub(crate) fn register(child: Child) -> ServerHandle {
    #[cfg(unix)]
    let pgid = child.id() as libc::pid_t;
    let mut servers = lock_registry();
    servers.push(Some(ServerProc {
        child,
        #[cfg(unix)]
        pgid,
    }));
    ServerHandle {
        idx: servers.len() - 1,
    }
}

/// A handle to a `pocket-ic-server` spawned by [`crate::start_server`].
///
/// The server is owned by a process-global registry. On unix it is killed and reaped
/// when the test process exits (on a bounded, best-effort basis), so most callers can
/// simply drop this handle. Callers that want to terminate the server earlier — e.g. to
/// test crash recovery — can call [`ServerHandle::kill_and_wait`].
pub struct ServerHandle {
    idx: usize,
}

impl ServerHandle {
    /// Kills the server now — its whole process group on unix, so the canister-sandbox
    /// children are terminated too — and makes a bounded, best-effort attempt to reap it.
    ///
    /// This is a *hard* kill (`SIGKILL` on unix): it does not give the server a chance to
    /// shut down gracefully or checkpoint state. The reap is time-bounded, so on return
    /// the process has been signalled (and, on unix, its whole group `SIGKILL`ed) but may
    /// not yet be fully reaped. Idempotent with respect to the exit-time reaper: the
    /// server is removed from the registry here, so it is not signalled or waited on again
    /// at process exit.
    pub fn kill_and_wait(&self) {
        let taken = lock_registry().get_mut(self.idx).and_then(Option::take);
        if let Some(mut proc) = taken {
            #[cfg(unix)]
            reap_one(&mut proc, Signal::Kill);
            #[cfg(windows)]
            {
                let _ = proc.child.kill();
                let _ = proc.child.wait();
            }
        }
    }
}

/// How aggressively [`reap_one`] terminates a server.
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
        let taken: Vec<ServerProc> = {
            let mut servers = lock_registry();
            servers.iter_mut().filter_map(Option::take).collect()
        };
        for mut proc in taken {
            reap_one(&mut proc, Signal::TermThenKill);
        }
    }));
}

/// Grace period given to each signal before escalating / giving up.
#[cfg(unix)]
const REAP_GRACE: Duration = Duration::from_millis(2_000);

/// Signals a server's process group and makes a bounded, best-effort attempt to reap the
/// direct server child.
///
/// The child's launcher/sandbox descendants are terminated by the process-group signal
/// (their pipe write-ends close on *termination*, not on reaping) and are reaped by init,
/// since the test process cannot `waitpid` them (they are not its direct children).
///
/// The whole operation is time-bounded so it can never hang process exit: after the first
/// signal fails to reap the child within [`REAP_GRACE`] the group is `SIGKILL`ed and given
/// one more [`REAP_GRACE`] window. If the child is *still* not reaped it is left for init
/// to reap once we exit — what matters here (closing the inherited pipes) is already done
/// by the kill.
#[cfg(unix)]
fn reap_one(proc: &mut ServerProc, signal: Signal) {
    let pgid = proc.pgid;
    let pid = proc.child.id() as libc::pid_t;

    let first = match signal {
        Signal::TermThenKill => libc::SIGTERM,
        Signal::Kill => libc::SIGKILL,
    };
    // A negative target signals the whole process group (server + launcher + sandboxes).
    // `ESRCH` — e.g. a loser candidate whose group is already empty — is expected and
    // harmless: `reap_until` still reaps the zombie.
    unsafe { libc::kill(-pgid, first) };

    if reap_until(pid, Instant::now() + REAP_GRACE) {
        return;
    }
    // Still alive after the grace period: force-kill the group and try once more.
    unsafe { libc::kill(-pgid, libc::SIGKILL) };
    reap_until(pid, Instant::now() + REAP_GRACE);
}

/// The calling thread's `errno`. Only meaningful immediately after a failed libc call.
#[cfg(unix)]
fn last_errno() -> libc::c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Polls `waitpid(WNOHANG)` for a direct child until it is reaped/gone or `deadline`
/// passes, retrying on `EINTR`. Returns `true` if the child was reaped or is already gone,
/// `false` if the deadline elapsed while it was still alive (so the caller can escalate).
///
/// Bounded by `deadline` so it can never hang process exit; `EINTR` (interrupted by a
/// signal) is retried rather than treated as terminal, so an interruption cannot cause an
/// early return that leaves the server holding the pipes. The expected terminal error is
/// `ECHILD` (the child was already reaped / is not ours).
#[cfg(unix)]
fn reap_until(pid: libc::pid_t, deadline: Instant) -> bool {
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: reaping our own direct child by pid.
        match unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } {
            r if r == pid => return true,
            -1 if last_errno() == libc::EINTR => continue,
            -1 => return true,
            // Still running (`0`): wait unless the deadline has passed.
            _ => {
                if Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}
