use ic_logger::{ReplicaLogger, debug, info, warn};
use nix::{
    errno::Errno,
    sys::signal::{self, Signal},
    unistd::Pid,
};
use std::{
    collections::HashMap,
    ffi::OsString,
    fmt::Debug,
    io::Result,
    os::unix::process::CommandExt,
    path::PathBuf,
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};

use crate::error::OrchestratorResult;

/// How long [`SingleProcessRunner::stop`] waits for the process to exit after
/// sending `SIGTERM`, before escalating to `SIGKILL`.
const STOP_GRACE_PERIOD: Duration = if !cfg!(test) {
    Duration::from_secs(30)
} else {
    // In tests, we want to fail fast.
    Duration::from_secs(1)
};

/// How long [`SingleProcessRunner::stop`] waits for the process to exit after
/// sending `SIGKILL`, before giving up and returning an error.
const KILL_TIMEOUT: Duration = Duration::from_secs(10);

/// The `Pid` of the running process (if any), shared between a
/// [`SingleProcessRunner`] and the thread waiting for the process to exit.
/// The condition variable is notified when the process exits and the `Pid` is
/// cleared.
#[derive(Default)]
struct PidState {
    pid: Mutex<Option<Pid>>,
    exited: Condvar,
}

type PIDCell = Arc<PidState>;

/// Captures a process that should be run by a [`ProcessRunner`]
pub(crate) trait Process {
    /// Name of the type of process
    ///
    /// Used for logging and metrics
    const NAME: &'static str;

    /// Version type of the process
    ///
    /// Different processes might be using different versioning schemes.
    /// We only impose that we can check that versions are equal and have
    /// a debug representation
    type Version: Debug;
    /// Static configuration of the process, such as the path to the binary
    /// and static arguments.
    type Config;
    /// Dynamic arguments of the process, such as the subnet ID for the replica
    /// (which could change across the orchestrator's lifetime).
    type Args;

    /// Build a new instance of the process with the given configuration and
    /// arguments.
    fn build(config: &Self::Config, args: Self::Args) -> OrchestratorResult<Self>
    where
        Self: Sized;

    /// Return the version of the [`Process`]
    fn get_version(&self) -> &Self::Version;

    /// Return the path to the binary of the [`Process`]
    fn get_binary(&self) -> PathBuf;

    /// Return the arguments passed to the [`Process`]
    fn get_args(&self) -> Vec<OsString>;

    /// Return the env vars passed to the [`Process`]
    fn get_env(&self) -> HashMap<OsString, OsString>;
}

/// Trait for running a single versioned [`Process`]
pub(crate) trait ProcessRunner<P: Process>: Send {
    /// Start the given process.
    ///
    /// If a process is already running, it is first stopped as in [`Self::stop`], and the given
    /// process is started once it has exited.
    fn start(&mut self, process: P) -> Result<()>;

    /// Stop the currently running process and wait until it has exited.
    /// If this returns `Ok`, the process is no longer running.
    fn stop(&mut self) -> Result<()>;

    /// Returns true only if the process is running.
    fn is_running(&self) -> bool;

    /// Returns the `Pid` of the currently running process; or `None` if no
    /// process is running.
    fn get_pid(&self) -> Option<Pid>;
}

/// A [`SingleProcessRunner`] manages running a single versioned [`Process`]
pub(crate) struct SingleProcessRunner<P: Process> {
    process: Option<P>,
    pid_cell: PIDCell,
    log: ReplicaLogger,
    join_handle: Option<std::thread::JoinHandle<()>>,
}

impl<P: Process> SingleProcessRunner<P> {
    pub(crate) fn new(logger: ReplicaLogger) -> Self {
        Self {
            process: None,
            pid_cell: Default::default(),
            log: logger,
            join_handle: None,
        }
    }

    /// Sets the pid for the running process.
    ///
    /// # Panics
    ///
    /// If the pid is already set, this function will panic.
    fn set_pid(&self, pid: Pid) {
        let mut pid_lock = self.pid_cell.pid.lock().unwrap();
        if pid_lock.replace(pid).is_some() {
            panic!("Process is still running!");
        }
    }

    /// Sends `signal` to the currently running process group. If no process
    /// is running, a log message is printed. If the process group no longer
    /// exists, this is not an error.
    ///
    /// It is critical that we signal and terminate the whole
    /// process group of which the [`Process`] is the leader. The
    /// process may spawn other sub-processes under the same process
    /// group. For correctness -- the processes may access state file
    /// paths and handles -- it is important we signal the sub-processes
    /// too.
    ///
    /// We guarantee that the [`Process`] is its own process group leader
    /// (so its PID equals its PGID, which is what the negation below
    /// relies on) by setting its process group at spawn time via
    /// `Command::process_group(0)` -- see `start`. We therefore do not
    /// rely on the managed binary calling `setpgid` itself.
    ///
    /// We still depend on init to handle reaping of adopted children,
    /// as the orchestrator has no way of adopting or even knowing the
    /// processes in question, cf. https://linux.die.net/man/2/waitpid.
    fn signal_group(&self, signal: Signal) -> Result<()> {
        let pid = self.pid_cell.pid.lock().unwrap();
        if let Some(pid) = *pid {
            let mut gpid = pid;
            // We want to signal the whole process group.
            if gpid > Pid::from_raw(0) {
                let t_gpid = gpid.as_raw();
                let t_gpid = -t_gpid;
                gpid = Pid::from_raw(t_gpid);
            }
            return match signal::kill(gpid, signal) {
                // The process group no longer exists: its leader has been reaped, and the thread
                // waiting on it is about to clear the pid.
                Ok(()) | Err(Errno::ESRCH) => Ok(()),
                Err(err) => Err(std::io::Error::other(format!(
                    "Failed to send {signal} to {} process with gpid {gpid}: {err}",
                    P::NAME
                ))),
            };
        }
        info!(self.log, "no {} process running", P::NAME);
        Ok(())
    }

    /// Waits up to `timeout` for the currently running process to exit.
    /// Returns true if no process is running anymore.
    fn wait_for_exit(&self, timeout: Duration) -> bool {
        let pid = self.pid_cell.pid.lock().unwrap();
        let (pid, _) = self
            .pid_cell
            .exited
            .wait_timeout_while(pid, timeout, |pid| pid.is_some())
            .unwrap();
        pid.is_none()
    }
}

impl<P: Process + Send> ProcessRunner<P> for SingleProcessRunner<P> {
    fn start(&mut self, process: P) -> Result<()> {
        // If there is a currently running process, stop it and wait for it to exit before starting
        // the new one.
        self.stop()?;

        info!(
            self.log,
            "Starting {} (version {:?}) with command: {:?} {:?}",
            P::NAME,
            process.get_version(),
            process.get_binary(),
            process.get_args()
        );
        let child = std::process::Command::new(process.get_binary())
            .args(process.get_args())
            .envs(process.get_env())
            // Put the child into a new process group of which it is the leader (PGID == PID). Any
            // sub-processes it spawns inherit this group, which lets `signal_group()` reliably
            // signal the whole group by negating the PID. We establish the group here, in the
            // orchestrator, rather than relying on each managed binary to call `setpgid` itself.
            // This is equivalent to `setpgid(0, 0)` run in the forked child before `exec`, while it
            // is still in the orchestrator's SELinux domain -- which is permitted to set its own
            // process group.
            .process_group(0)
            .spawn()?;
        debug!(self.log, "Process started. Pid: {}", child.id());
        self.set_pid(Pid::from_raw(child.id() as i32));

        self.join_handle = Some(std::thread::spawn(wait_on_exit(
            P::NAME,
            self.log.clone(),
            child,
            self.pid_cell.clone(),
        )));

        self.process = Some(process);
        Ok(())
    }

    /// Sends `SIGTERM` to the process group and waits for the process to exit.
    /// If it does not exit within the grace period, escalates to `SIGKILL`.
    /// Returns an error if the process still has not exited after that.
    ///
    /// Note that this blocks the calling thread for up to the grace period plus
    /// the kill timeout.
    fn stop(&mut self) -> Result<()> {
        if self.get_pid().is_none() {
            return Ok(());
        }

        self.signal_group(Signal::SIGTERM)?;
        if !self.wait_for_exit(STOP_GRACE_PERIOD) {
            warn!(
                self.log,
                "{} process did not exit within {:?} after SIGTERM, sending SIGKILL",
                P::NAME,
                STOP_GRACE_PERIOD
            );
            self.signal_group(Signal::SIGKILL)?;
            if !self.wait_for_exit(KILL_TIMEOUT) {
                return Err(std::io::Error::other(format!(
                    "{} process did not exit within {:?} after SIGKILL",
                    P::NAME,
                    KILL_TIMEOUT
                )));
            }
        }

        if let Some(join_handle) = self.join_handle.take()
            && join_handle.join().is_err()
        {
            warn!(self.log, "Thread waiting on {} process panicked", P::NAME);
        }
        self.process = None;
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.get_pid().is_some()
    }

    fn get_pid(&self) -> Option<Pid> {
        *self.pid_cell.pid.lock().unwrap()
    }
}

/// Wait for the child process to return, log the exit status and send.
fn wait_on_exit(
    name: &'static str,
    log: ReplicaLogger,
    mut process: std::process::Child,
    pid_cell: PIDCell,
) -> impl FnOnce() {
    move || {
        let exit_status = process.wait();
        if let Err(e) = &exit_status {
            warn!(log, "wait() for {} returned error: {:?}", name, e);
        } else {
            info!(log, "{} exited. Exit Status: {:?}", name, exit_status);
        }
        let _pid = pid_cell.pid.lock().unwrap().take();
        pid_cell.exited.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_logger::no_op_logger;
    use std::time::Instant;
    use tempfile::tempdir;

    /// A [`Process`] running the given shell script.
    struct ShellProcess {
        script: String,
    }

    impl Process for ShellProcess {
        const NAME: &'static str = "shell";
        type Version = ();
        type Config = ();
        type Args = String;

        fn build(_config: &Self::Config, script: Self::Args) -> OrchestratorResult<Self> {
            Ok(Self { script })
        }
        fn get_version(&self) -> &Self::Version {
            &()
        }
        fn get_binary(&self) -> PathBuf {
            PathBuf::from("/bin/sh")
        }
        fn get_args(&self) -> Vec<OsString> {
            vec!["-c".into(), self.script.clone().into()]
        }
        fn get_env(&self) -> HashMap<OsString, OsString> {
            HashMap::new()
        }
    }

    fn shell(script: &str) -> ShellProcess {
        ShellProcess::build(&(), script.to_string()).unwrap()
    }

    const LONG_RUNNING: &str = "sleep 60";

    #[test]
    fn stop_waits_for_exit() {
        let mut runner = SingleProcessRunner::new(no_op_logger());
        runner.start(shell(LONG_RUNNING)).unwrap();
        assert!(runner.is_running());
        assert!(runner.get_pid().is_some());

        assert!(!runner.wait_for_exit(Duration::from_secs(1)));
        assert!(runner.is_running());

        runner.stop().unwrap();
        assert!(!runner.is_running());
        assert_eq!(runner.get_pid(), None);
    }

    #[test]
    fn stop_when_not_running_is_noop() {
        let mut runner = SingleProcessRunner::new(no_op_logger());
        assert!(!runner.is_running());

        runner.stop().unwrap();
        assert!(!runner.is_running());

        // The process exits on its own.
        runner.start(shell("true")).unwrap();
        assert!(runner.wait_for_exit(Duration::from_secs(10)));
        assert!(!runner.is_running());

        runner.stop().unwrap();
        assert!(!runner.is_running());
    }

    #[test]
    fn start_while_running_restarts_process() {
        let mut runner = SingleProcessRunner::new(no_op_logger());
        runner.start(shell(LONG_RUNNING)).unwrap();
        let old_pid = runner.get_pid().unwrap();

        runner.start(shell(LONG_RUNNING)).unwrap();

        let new_pid = runner.get_pid().expect("a new process should be running");
        assert_ne!(old_pid, new_pid);
        runner.stop().unwrap();
    }

    #[test]
    fn stop_escalates_to_sigkill() {
        let dir = tempdir().unwrap();
        let ready = dir.path().join("ready");
        let mut runner = SingleProcessRunner::new(no_op_logger());
        // Ignore SIGTERM, then signal that the trap is installed.
        runner
            .start(shell(&format!(
                "trap '' TERM; touch {}; {LONG_RUNNING}",
                ready.display()
            )))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() {
            assert!(Instant::now() < deadline, "process did not become ready");
            std::thread::sleep(Duration::from_millis(10));
        }

        let start = Instant::now();
        runner.stop().unwrap();

        assert!(start.elapsed() >= STOP_GRACE_PERIOD);
        assert!(!runner.is_running());
    }
}
