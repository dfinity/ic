use ic_logger::{ReplicaLogger, debug, info, warn};
use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};
use std::{
    collections::HashMap,
    fmt::Debug,
    io::Result,
    sync::{Arc, Mutex},
};

type PIDCell = Arc<Mutex<Option<Pid>>>;

/// Captures a process that should be run by the [`ProcessManager`]
pub(crate) trait Process {
    /// Name of the type of process
    ///
    /// Used only for logging purposes
    const NAME: &'static str;

    /// Version type of the process
    ///
    /// Different processes might be using different versioning schemes.
    /// We only impose that we can check that versions are equal and have
    /// a debug representation
    type Version: Eq + Debug;

    /// Return the version of the [`Process`]
    fn get_version(&self) -> &Self::Version;

    /// Return the path to the binary of the [`Process`]
    fn get_binary(&self) -> &str;

    /// Return the arguments passed to the [`Process`]
    fn get_args(&self) -> &[String];

    /// Return the env vars passed to the [`Process`]
    fn get_env(&self) -> HashMap<String, String>;
}

/// A [`ProcessManager`] manages running a single versioned [`Process`]
pub(crate) struct ProcessManager<P: Process> {
    process: Option<P>,
    pid_cell: PIDCell,
    log: ReplicaLogger,
    join_handle: Option<std::thread::JoinHandle<()>>,
}

impl<P: Process> ProcessManager<P> {
    pub(crate) fn new(logger: ReplicaLogger) -> Self {
        Self {
            process: None,
            pid_cell: Default::default(),
            log: logger,
            join_handle: None,
        }
    }

    /// Returns true only if the process is running.
    pub fn is_running(&self) -> bool {
        self.get_pid().is_some()
    }

    /// Returns the `Pid` if the currently running process; or `None` if no
    /// process is running.
    pub fn get_pid(&self) -> Option<Pid> {
        *self.pid_cell.lock().unwrap()
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
    /// process group of which the [`Process`] should be the
    /// leader. The process may spawn other
    /// sub-processes under the same process group. For correctness
    /// -- the processes may access state file paths and
    /// handles -- it is important we signal the sub-processes
    /// processes too. This is possible because we shall
    /// restrict setgpid() in production -- by default disabled
    /// by SELinux type enforcement.
    ///
    /// We still depend on init to handle reaping of adopted children,
    /// as the orchestrator has no way of adopting or even knowing the
    /// processes in question, cf. https://linux.die.net/man/2/waitpid.
    pub(crate) fn stop(&mut self) -> Result<()> {
        self.kill()
    }

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

    pub(crate) fn start(&mut self, process: P) -> Result<()> {
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
