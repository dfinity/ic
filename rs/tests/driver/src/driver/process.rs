use nix::{
    errno::Errno,
    sys::{
        signal::{Signal, kill},
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::{Pid, getpid},
};
use slog::{Logger, info, warn};
use std::collections::{HashMap, HashSet};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, BufReader},
    process::{Child, Command as AsyncCommand},
    select,
    sync::watch::{Receiver, channel},
    task::{self, JoinHandle},
    time::timeout,
};

pub trait KillFn: FnOnce() + Send + Sync {}
impl<T: FnOnce() + Send + Sync> KillFn for T {}

use crate::driver::event::TaskId;
pub struct Process {
    child: Child,
    stdout_jh: JoinHandle<()>,
    stderr_jh: JoinHandle<()>,
}

impl Process {
    pub async fn new(task_id: TaskId, cmd: Command, log: Logger) -> (Self, impl FnOnce()) {
        let mut cmd: AsyncCommand = cmd.into();
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // When the `Process` object is dropped, the child is sent a kill
        // signal.
        cmd.kill_on_drop(true);

        let mut child = cmd.spawn().expect("Spawning subprocess should succeed");

        let stdout = child.stdout.take().unwrap();
        let (kill_tx, kill_watch) = channel::<bool>(false);

        let stdout_jh = task::spawn(Self::listen_on_channel(
            kill_watch.clone(),
            task_id.clone(),
            log.clone(),
            ChannelName::StdOut,
            stdout,
        ));
        let stderr = child.stderr.take().unwrap();
        let stderr_jh = task::spawn(Self::listen_on_channel(
            kill_watch,
            task_id,
            log.clone(),
            ChannelName::StdErr,
            stderr,
        ));

        let self_ = Self {
            child,
            stdout_jh,
            stderr_jh,
        };

        let kill_signal = {
            let pid = Pid::from_raw(self_.child.id().unwrap() as i32);
            move || {
                let _ = kill(pid, Signal::SIGKILL);
                let _ = kill_tx.send(true);
            }
        };

        (self_, kill_signal)
    }

    /// Waits for stdout/err to be closed. Then waits for the child process to
    /// exit and returns the corresponding ExitStatus.
    pub async fn block_on_exit(self) -> std::io::Result<ExitStatus> {
        let mut child = self.child;
        // The listeners should not return with an error, so it should be safe
        // to unwrap().
        self.stdout_jh.await.unwrap();
        self.stderr_jh.await.unwrap();
        child.wait().await
    }

    async fn listen_on_channel<R>(
        mut kill_watch: Receiver<bool>,
        task_id: TaskId,
        log: Logger,
        channel_tag: ChannelName,
        src: R,
    ) where
        R: AsyncRead + Unpin,
    {
        let buffered_reader = BufReader::new(src);
        let mut lines = buffered_reader.lines();
        let task_id_str = format!("{task_id}");
        let output_channel_str = format!("{channel_tag:?}");
        loop {
            select! {
                line_res = lines.next_line() => {
                    match line_res {
                        Ok(Some(line)) => {
                            info!(log, "{}", line; "task_id" => &task_id_str, "output_channel" => &output_channel_str)
                        }
                        Ok(None) => break,
                        Err(e) => eprintln!("listen_on_channel(): {e:?}"),
                    }
                }
                _ = kill_watch.changed() => {
                    info!(log, "({}|{:?}): Kill received. Draining remaining output ...", task_id, channel_tag);
                    // Drain any remaining buffered lines before returning.
                    // Use a short timeout to avoid blocking on grandchild
                    // processes that keep the pipe open after the child is killed.
                    let drain_timeout = Duration::from_secs(1);
                    match timeout(drain_timeout, async {
                        loop {
                            match lines.next_line().await {
                                Ok(Some(line)) => {
                                    info!(log, "{}", line; "task_id" => &task_id_str, "output_channel" => &output_channel_str);
                                }
                                Ok(None) => break,
                                Err(e) => {
                                    info!(log, "({}|{:?}): Error during drain: {e:?}", task_id, channel_tag);
                                    break;
                                }
                            }
                        }
                    }).await {
                        Ok(()) => info!(log, "({}|{:?}): Drain complete.", task_id, channel_tag),
                        Err(_) => info!(log, "({}|{:?}): Drain timed out.", task_id, channel_tag),
                    }
                    return;
                }
            }
        }
        info!(log, "({}|{:?}): Channel has closed.", task_id, channel_tag);
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum ChannelName {
    StdOut,
    StdErr,
}

/// Marks the current process as a "child subreaper" (Linux `PR_SET_CHILD_SUBREAPER`).
///
/// Once set, any descendant process that becomes orphaned (e.g. daemons that
/// double-fork to detach from their parent) is reparented to this process
/// instead of to PID 1 / the spawning `process-wrapper`. This lets us reliably
/// enumerate and reap all transitive descendants at teardown via
/// [`kill_all_descendants`].
///
/// The subreaper attribute is per-process and is NOT inherited across `fork`,
/// so this must be called on the long-lived parent process that outlives both
/// setup and teardown. Best-effort: failures are logged and otherwise ignored.
pub fn enable_child_subreaper(logger: &Logger) {
    // SAFETY: `prctl` with `PR_SET_CHILD_SUBREAPER` only sets a per-process
    // attribute and does not touch process memory; the extra arguments are
    // ignored for this option. It returns 0 on success and -1 on error.
    let rc = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
    if rc == 0 {
        info!(logger, "Enabled child-subreaper for the current process.");
    } else {
        let err = std::io::Error::last_os_error();
        warn!(logger, "Failed to enable child-subreaper: {err}");
    }
}

/// Spawns a detached background thread that continuously reaps orphaned,
/// double-forked daemons that have been reparented to this process.
///
/// # Why this is needed
///
/// Local-backend daemons (`libvirtd`'s QEMU processes and `dnsmasq`)
/// daemonize by double-forking. With [`enable_child_subreaper`] in effect, the
/// orphaned grandchild is reparented to *this* process rather than to the
/// daemon that launched it. That has two consequences if nobody reaps the
/// resulting zombies promptly:
///
///   1. Zombie (`<defunct>`) processes accumulate under us for the lifetime of
///      the test run.
///   2. When the local backend later asks libvirt to destroy a domain, libvirt
///      `SIGKILL`s the QEMU process and then polls `kill(pid, 0)` waiting for it
///      to disappear. Because QEMU is now *our* child (not libvirt's), only we
///      can reap it; until we do, libvirt keeps seeing the zombie as alive and
///      eventually fails with `Device or resource busy`, stalling teardown for
///      ~2 minutes.
///
/// Reaping these zombies promptly fixes both problems: the process table stays
/// clean, and libvirt's `kill(pid, 0)` sees `ESRCH` immediately so domain
/// destruction returns without stalling.
///
/// # Why it does not interfere with the Tokio runtime
///
/// Tokio reaps the task subprocesses it spawns itself (by their specific PID,
/// driven by `SIGCHLD`); a blanket `waitpid(-1, ...)` here would race with that
/// and could steal a child's exit status. To avoid this, the reaper only reaps
/// zombie children whose `comm` differs from our own. Every task subprocess
/// re-`exec`s this same binary and therefore shares our `comm`, so Tokio's
/// children are never touched; only the foreign daemons are reaped.
pub fn spawn_descendant_reaper(logger: &Logger) {
    let my_pid = getpid().as_raw();
    let my_comm = match read_comm(my_pid) {
        Some(c) if !c.is_empty() => c,
        _ => {
            warn!(
                logger,
                "Could not read own comm; not starting the descendant reaper."
            );
            return;
        }
    };

    let builder = std::thread::Builder::new().name("descendant-reaper".to_string());
    if let Err(e) = builder.spawn(move || {
        loop {
            reap_foreign_zombie_children(my_pid, &my_comm);
            std::thread::sleep(Duration::from_millis(200));
        }
    }) {
        warn!(logger, "Failed to start the descendant reaper thread: {e}");
        return;
    }
    info!(
        logger,
        "Started background reaper for orphaned descendant daemons."
    );
}

/// Reaps every zombie child of `my_pid` whose `comm` differs from `my_comm`.
///
/// Children sharing our `comm` are Tokio-managed task subprocesses and are left
/// for Tokio to reap (see [`spawn_descendant_reaper`]).
fn reap_foreign_zombie_children(my_pid: i32, my_comm: &str) {
    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return,
    };
    for entry in proc_dir.flatten() {
        let pid: i32 = match entry.file_name().to_str().and_then(|n| n.parse().ok()) {
            Some(p) => p,
            None => continue,
        };
        // Skip anything that is not a zombie ('Z') direct child of ours: only
        // such processes are ours to reap, and reaping them won't block.
        if !matches!(read_state_and_ppid(pid), Some(('Z', ppid)) if ppid == my_pid) {
            continue;
        }
        // Only reap foreign daemons; leave our own (Tokio-managed) task
        // subprocesses for Tokio to reap so their exit status is preserved.
        if read_comm(pid).as_deref() == Some(my_comm) {
            continue;
        }
        let _ = waitpid(Pid::from_raw(pid), Some(WaitPidFlag::WNOHANG));
    }
}

/// SIGKILLs and reaps every transitive descendant of the current process.
///
/// Relies on the current process being a child subreaper (see
/// [`enable_child_subreaper`]) so that orphaned, double-forked daemons
/// (e.g. `libvirtd`, `dnsmasq`, QEMU) have been reparented here and are thus
/// reachable by walking the process tree.
///
/// The function repeatedly:
///   1. builds a `pid -> ppid` map by scanning `/proc/<pid>/stat`,
///   2. computes the transitive set of descendants of `getpid()`,
///   3. sends `SIGKILL` to each, and
///   4. reaps any exited children via `waitpid(-1, WNOHANG)`.
///
/// It loops (with a short sleep) until no descendants remain or a deadline is
/// reached, so that processes which themselves spawn children during teardown
/// are also caught. Best-effort: all errors are logged and ignored.
pub fn kill_all_descendants(logger: &Logger) {
    let my_pid = getpid();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut total_killed: HashSet<i32> = HashSet::new();

    loop {
        let descendants = collect_descendants(my_pid.as_raw());
        if descendants.is_empty() {
            break;
        }

        for pid in &descendants {
            total_killed.insert(*pid);
            if let Err(e) = kill(Pid::from_raw(*pid), Signal::SIGKILL) {
                // ESRCH simply means the process already exited.
                if e != Errno::ESRCH {
                    warn!(logger, "Failed to SIGKILL descendant pid {pid}: {e:?}");
                }
            }
        }

        // Reap any zombies that have been reparented to us so they do not
        // linger and so that subsequent scans see an accurate tree.
        reap_exited_children();

        if Instant::now() >= deadline {
            warn!(
                logger,
                "kill_all_descendants reached its deadline with descendants still present."
            );
            break;
        }

        std::thread::sleep(Duration::from_millis(100));
    }

    // Final drain of any remaining zombies.
    reap_exited_children();

    if !total_killed.is_empty() {
        info!(
            logger,
            "kill_all_descendants killed {} descendant process(es).",
            total_killed.len()
        );
    }
}

/// Builds a `pid -> ppid` map by scanning `/proc/<pid>/stat`, then returns the
/// transitive set of descendants of `root_pid` via a breadth-first traversal.
fn collect_descendants(root_pid: i32) -> Vec<i32> {
    let mut children_by_parent: HashMap<i32, Vec<i32>> = HashMap::new();

    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };

    for entry in proc_dir.flatten() {
        let file_name = entry.file_name();
        let name = match file_name.to_str() {
            Some(n) => n,
            None => continue,
        };
        // Only numeric entries correspond to processes.
        let pid: i32 = match name.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        if let Some(ppid) = read_ppid(pid) {
            children_by_parent.entry(ppid).or_default().push(pid);
        }
    }

    let mut descendants = Vec::new();
    let mut queue = vec![root_pid];
    let mut seen: HashSet<i32> = HashSet::new();
    while let Some(parent) = queue.pop() {
        if let Some(children) = children_by_parent.get(&parent) {
            for &child in children {
                if seen.insert(child) {
                    descendants.push(child);
                    queue.push(child);
                }
            }
        }
    }
    descendants
}

/// Reads the parent PID (field 4) from `/proc/<pid>/stat`.
fn read_ppid(pid: i32) -> Option<i32> {
    read_state_and_ppid(pid).map(|(_state, ppid)| ppid)
}

/// Reads the process state (field 3) and parent PID (field 4) from
/// `/proc/<pid>/stat`.
///
/// The `comm` field (field 2) is wrapped in parentheses and may itself contain
/// spaces or parentheses, so we parse the fields after the LAST `)` to locate
/// the state and ppid reliably.
fn read_state_and_ppid(pid: i32) -> Option<(char, i32)> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = content.rsplit_once(')')?.1;
    // after_comm starts with " <state> <ppid> ..."
    let mut fields = after_comm.split_whitespace();
    let state = fields.next()?.chars().next()?;
    let ppid = fields.next()?.parse().ok()?;
    Some((state, ppid))
}

/// Reads the (possibly truncated, 15-char) `comm` of `pid` from
/// `/proc/<pid>/comm`, trimming the trailing newline. Remains readable while a
/// process is a zombie.
fn read_comm(pid: i32) -> Option<String> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    Some(content.trim_end().to_string())
}

/// Reaps any direct children that have already exited, without blocking.
///
/// Only direct children are reaped: `waitpid(-1, ...)` waits on immediate
/// children of the calling process, not arbitrary descendants.
fn reap_exited_children() {
    loop {
        match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
            // No more children have exited yet (still running).
            Ok(WaitStatus::StillAlive) => break,
            // A child was reaped; keep draining.
            Ok(_) => continue,
            // No children at all, or interrupted; nothing more to do.
            Err(_) => break,
        }
    }
}
