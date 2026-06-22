use ic_logger::{ReplicaLogger, debug, info, warn};
use nix::{
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
    sync::{Arc, Mutex},
};

use crate::error::OrchestratorResult;

type PIDCell = Arc<Mutex<Option<Pid>>>;

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
    type Version: Eq + Debug;
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
    fn start(&mut self, process: P) -> Result<()>;

    /// Stop the currently running process.
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
        let mut pid_lock = self.pid_cell.lock().unwrap();
        if pid_lock.replace(pid).is_some() {
            panic!("Process is still running!");
        }
    }

    /// Kills the currently running process group. If no process is
    /// running, a log message is printed.
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
    fn kill(&mut self) -> Result<()> {
        let pid = self.pid_cell.lock().unwrap();
        if let Some(pid) = *pid {
            let mut gpid = pid;
            // We want to signal the whole process group.
            if gpid > Pid::from_raw(0) {
                let t_gpid = gpid.as_raw();
                let t_gpid = -t_gpid;
                gpid = Pid::from_raw(t_gpid);
            }
            return signal::kill(gpid, Signal::SIGTERM).map_err(|err| {
                std::io::Error::other(format!(
                    "Failed to kill {} process with gpid {gpid}: {err}",
                    P::NAME
                ))
            });
        }
        info!(self.log, "no {} process running", P::NAME);
        Ok(())
    }
}

impl<P: Process + Send> ProcessRunner<P> for SingleProcessRunner<P> {
    fn start(&mut self, process: P) -> Result<()> {
        // Do nothing if we're already running a process with the requested version
        if let Some(current_version) = self.process.as_ref().map(|p| p.get_version())
            && self.get_pid().is_some()
            && process.get_version() == current_version
        {
            debug!(
                self.log,
                "{} process already running with correct version",
                P::NAME
            );
            return Ok(());
        }

        debug!(
            self.log,
            "{} process not running: command is {:?} {:?} {:?}",
            P::NAME,
            process.get_binary(),
            process.get_version(),
            process.get_args()
        );

        // If there is a currently running process, kill it. Instead of starting the new
        // command (`msg`) immediately, wait for the current process to exit
        // which will cause it to be restarted.
        if self.get_pid().is_some() {
            self.kill()?;
        } else {
            info!(
                self.log,
                "Starting {} with command: {:?} {:?} {:?}",
                P::NAME,
                process.get_binary(),
                process.get_version(),
                process.get_args()
            );
            let child = std::process::Command::new(process.get_binary())
                .args(process.get_args())
                .envs(process.get_env())
                // Put the child into a new process group of which it is the
                // leader (PGID == PID). Any sub-processes it spawns inherit this
                // group, which lets `kill()` reliably signal the whole group by
                // negating the PID. We establish the group here, in the
                // orchestrator, rather than relying on each managed binary to
                // call `setpgid` itself. This is equivalent to `setpgid(0, 0)`
                // run in the forked child before `exec`, while it is still in
                // the orchestrator's SELinux domain -- which is permitted to set
                // its own process group.
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
        }

        self.process = Some(process);
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.kill()
    }

    fn is_running(&self) -> bool {
        self.get_pid().is_some()
    }

    fn get_pid(&self) -> Option<Pid> {
        *self.pid_cell.lock().unwrap()
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
        let _pid = pid_cell.lock().unwrap().take();
    }
}
