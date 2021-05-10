use ic_types::ReplicaVersion;
use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};
use slog::{debug, info, warn};
use std::sync::Mutex;
use std::{io::Result, sync::Arc};

type PIDCell = Arc<Mutex<Option<Pid>>>;

#[derive(Clone, Debug)]
pub(crate) struct ReplicaCommand {
    pub(crate) replica_binary: String,
    pub(crate) replica_version: ReplicaVersion,
    pub(crate) args: Vec<String>,
}

/// Runs and monitors a Replica process and accepts requests to stop the current
/// Replica process and run a new Replica binary
pub(crate) struct ReplicaProcess {
    pub(crate) command: Option<ReplicaCommand>,
    pub(crate) pid_cell: PIDCell,
    pub(crate) log: slog::Logger,
    pub(crate) join_handle: Option<std::thread::JoinHandle<()>>,
    pub(crate) stopping: bool,
}

impl ReplicaProcess {
    pub(crate) fn new(logger: slog::Logger) -> Self {
        Self {
            command: None,
            pid_cell: Default::default(),
            log: logger.clone(),
            join_handle: None,
            stopping: false,
        }
    }

    /// Returns the `Pid` if the currently running replica; or `None` if no
    /// replica is running.
    fn get_pid(&self) -> Option<Pid> {
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

    /// Kills the currently running replica process group. If no replica is
    /// running, a log message is printed.
    ///
    /// It is critical that we signal and terminate the whole
    /// process group of which the replica should be the
    /// leader. The Replica spawns multiple other sandboxed
    /// processes under the same process group. For correctness
    /// -- the processes may access state file paths and
    /// handles -- it is important we signal the sandbox
    /// processes too. This is possible because we shall
    /// restrict setgpid() in production -- by default disabled
    /// by SELinux type enforcement.
    ///
    /// We still depend on init to handle reaping of adopted children,
    /// as the nodemanager has no way of adopting or even knowing the
    /// processes in question, cf. https://linux.die.net/man/2/waitpid.
    ///
    /// WARNING: We treat the sandbox processes as ACTIVELY
    /// MALICIOUS. That is we can not depend on any signal
    /// handling. Furthermore, this approach works because we send an
    /// unmaskable Signal (SIGKILL). If we start sending SIGTERM at
    /// **ANY** point we need to handle waiting for the whole process
    /// group, and that includes the grandchildren. This would work
    /// differently on OS X and linux. N.B. in OS X our only path
    /// would be via kqueue and on linux we can not depend on child
    /// subreaper via prctl(2) (PR_SET_CHILD_SUBREAPER), as we are
    /// dealing with malicious processes and secondly this feature is
    /// thread specific, i.e. the thread not the process does the
    /// subreaping.
    pub(crate) fn stop(&mut self) -> Result<()> {
        self.stopping = true;
        self.kill()
    }

    pub(crate) fn kill(&mut self) -> Result<()> {
        let pid = self.pid_cell.lock().unwrap();
        if let Some(pid) = *pid {
            let mut gpid = pid;
            // We want to signal the whole process group.
            if gpid > Pid::from_raw(0) {
                let t_gpid = gpid.as_raw();
                let t_gpid = -t_gpid;
                gpid = Pid::from_raw(t_gpid);
            }
            return signal::kill(gpid, Signal::SIGKILL)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", e)));
        }
        info!(
            self.log,
            "🚀 Unable to terminate replica process - it's probably already down."
        );
        Ok(())
    }

    pub(crate) fn start(
        &mut self,
        replica_binary: String,
        replica_version: ReplicaVersion,
        args: Vec<String>,
    ) -> Result<()> {
        // Do nothing if we're already running a Replica with the requested version
        let current_version = self.command.as_ref().map(|x| x.replica_version.clone());
        if self.get_pid().is_some() && Some(replica_version.clone()) == current_version {
            debug!(
                self.log,
                "Replica process already running with correct version"
            );
            return Ok(());
        }

        self.command = Some(ReplicaCommand {
            replica_binary: replica_binary.clone(),
            replica_version: replica_version.clone(),
            args: args.clone(),
        });

        debug!(
            self.log,
            "Replica process not running: command is {:?} {:?} {:?}",
            &replica_binary,
            &replica_version,
            &args
        );

        // If there is a currently running process, kill it. Instead of starting the new
        // command (`msg`) immediately, wait for the current process to exit
        // which will cause it to be restarted.
        //
        // It is critical that we signal and terminate the whole
        // process group of which the replica should be the
        // leader. The Replica spawns multiple other sandboxed
        // processes under the same process group. For correctness
        // -- the processes may access state file paths and
        // handles -- it is important we signal the sandbox
        // processes too. This is possible because we shall
        // restrict setgpid() in production -- by default disabled
        // by SELinux type enforcement.
        if self.get_pid().is_some() {
            self.kill()?;
        } else {
            info!(
                self.log,
                "🚀 Sarting process manager for replica with command: {:?} {:?} {:?}",
                &replica_binary,
                &replica_version,
                &args
            );
            let child = std::process::Command::new(replica_binary)
                .args(&args)
                .spawn()?;
            debug!(self.log, "🚀 Process started. Pid: {}", child.id());
            self.set_pid(Pid::from_raw(child.id() as i32));

            self.join_handle = Some(std::thread::spawn(wait_on_exit(
                self.log.clone(),
                child,
                self.pid_cell.clone(),
            )));
        }
        Ok(())
    }

    pub(crate) fn spawn_wait_and_restart(replica_process: Arc<Mutex<ReplicaProcess>>) {
        tokio::task::spawn_blocking(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            let join_handle = replica_process.lock().unwrap().join_handle.take();
            if let Some(join_handle) = join_handle {
                join_handle.join().expect("join failed");
            };
            let mut replica_process_guard = replica_process.lock().unwrap();
            if replica_process_guard.stopping {
                break;
            }
            if let Some(command) = replica_process_guard.command.clone() {
                let e = replica_process_guard.start(
                    command.replica_binary.clone(),
                    command.replica_version.clone(),
                    command.args,
                );
                warn!(replica_process_guard.log, "Replica exited, {:?}", e);
            }
        });
    }
}

/// Wait for the child process to return, log the exit status and send
/// `ReplicaExited`-message to `exit_recipient`.
fn wait_on_exit(
    log: slog::Logger,
    mut process: std::process::Child,
    pid_cell: PIDCell,
) -> impl FnOnce() {
    move || {
        let exit_status = process.wait();
        if let Err(e) = &exit_status {
            warn!(log, "wait() for replica returned error: {:?}", e);
        } else {
            info!(log, "Replica exited. Exit Status: {:?}", exit_status);
        }
        let _pid = pid_cell.lock().unwrap().take();
    }
}
