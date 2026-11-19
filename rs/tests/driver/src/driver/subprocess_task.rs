//! A child task is a function that is executed in a child process. Thus,
//! `execute()` is called in the child process only, while `spawn()` is called
//! in the parent process.

use crate::driver::{
    constants::{KILLED_TASK_EXIT_TIMEOUT, LOG_CLOSE_TIMEOUT},
    context::GroupContext,
    dsl::SubprocessFn,
    event::TaskId,
    logger::new_discard_logger,
    process::{KillFn, Process},
    process_tree,
    subprocess_ipc::{LogReceiver, ReportOrFailure, log_panic_event},
    task::{Task, TaskHandle},
    task_scheduler::TaskResult,
};
use nix::unistd::Pid;
use slog::{Logger, debug, error, info, warn};
use std::{
    panic::catch_unwind,
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{runtime::Handle as RtHandle, task::JoinHandle, time::timeout};

use super::task::TaskResultCallback;

pub struct SubprocessTask {
    task_id: TaskId,
    rt: RtHandle,
    // To execute the function within an `catch_unwind`, it must be FnOnce.
    // Thus, `f` needs to be moved out of the object when executed.
    f: Arc<Mutex<Option<Box<dyn SubprocessFn>>>>,
    spawned: AtomicBool,
    group_ctx: GroupContext,
    quiet: bool,
}

impl SubprocessTask {
    pub fn new<F: SubprocessFn>(
        task_id: TaskId,
        rt: RtHandle,
        f: F,
        group_ctx: GroupContext,
        quiet: bool,
    ) -> Self {
        Self {
            task_id,
            rt,
            f: shared_mutex(Some(Box::new(f))),
            spawned: Default::default(),
            group_ctx,
            quiet,
        }
    }
}

impl Task for SubprocessTask {
    fn spawn(&self, notify: TaskResultCallback) -> Box<dyn crate::driver::task::TaskHandle> {
        if self.spawned.swap(true, Ordering::Relaxed) {
            panic!("Respawned already spawned task '{}'", self.task_id);
        }

        // select a random socket id used for this child process
        use rand::Rng;
        let sock_id: u64 = rand::thread_rng().r#gen();
        let sock_path = GroupContext::log_socket_path(sock_id);

        let mut child_cmd = Command::new(self.group_ctx.exec_path.clone());
        child_cmd
            .arg("--working-dir") // TODO: rename as --group-dir
            .arg(self.group_ctx.group_dir().as_os_str())
            .arg("--group-base-name")
            .arg(self.group_ctx.group_base_name.clone());

        if self.group_ctx.enable_metrics {
            child_cmd.arg("--enable-metrics");
        }

        if !self.group_ctx.logs_enabled {
            child_cmd.arg("--no-logs");
        }

        if self.group_ctx.stream_ic_node_logs {
            child_cmd.arg("--stream-ic-node-logs");
        }

        if self.group_ctx.stream_console_logs {
            child_cmd.arg("--stream-console-logs");
        }

        for pattern in &self.group_ctx.exclude_logs {
            child_cmd.arg("--exclude-logs").arg(pattern.as_str());
        }

        child_cmd
            .arg("spawn-child")
            .arg(self.task_id.name())
            .arg(sock_id.to_string());

        info!(self.group_ctx.log(), "Spawning {:?} ...", child_cmd);

        // When this subtask is `quiet`, have the receiver discard logs.
        // NOTE: We discard on the receiver rather than the sender, so that no
        // information is lost. Eventually, we may want to split the logfile
        // and stdout, and will leave this to the receiver.
        let log = if !self.quiet {
            self.group_ctx.logger()
        } else {
            new_discard_logger()
        };
        let log_rcvr = self
            .rt
            .block_on(LogReceiver::new(sock_path, log.clone()))
            .expect("Could not start LogReceiver");
        let (proc, kill) =
            self.rt
                .block_on(Process::new(self.task_id.clone(), child_cmd, log.clone()));
        let pid = proc.pid();

        let task_state = shared_mutex(TaskState::Running(Box::new(kill)));
        let jh = self.rt.spawn({
            let task_id = self.task_id.clone();
            let task_state = task_state.clone();
            async move {
                let log_jh = tokio::task::spawn(async move { log_rcvr.receive_all().await });
                let exit_code = proc.block_on_exit().await;

                info!(
                    log,
                    "Task '{task_id}' finished with exit code: {exit_code:?}"
                );
                // TODO:
                // if cancellation request: task state is set to cancelled
                // we still have to wait for jh_res -> leads to report or failure
                // if cancelled, ignore child report
                //

                // A misbehaving child might have not connected to the parent at all. In such a
                // case, this join would block forever.
                let mut child_report = None;
                match timeout(LOG_CLOSE_TIMEOUT, log_jh).await {
                    Ok(jh_res) => match jh_res.unwrap() {
                        Ok(Some(ReportOrFailure::Report(msg))) => {
                            child_report = Some(TaskResult::Report(task_id.clone(), msg));
                        }
                        Ok(Some(ReportOrFailure::Failure(msg))) => {
                            child_report = Some(TaskResult::Failure(task_id.clone(), msg));
                        }
                        Ok(_) => {}
                        Err(e) => {
                            error!(log, "[Driver Error] Reading logs failed: {e:?}");
                        }
                    },
                    Err(e) => {
                        error!(
                            log,
                            "Timeout occurred when waiting for log channel to close: {e:?}"
                        );
                    }
                }

                let mut task_state = task_state.lock().unwrap();
                *task_state = match &*task_state {
                    TaskState::Running(_) => {
                        if let Some(child_report) = child_report {
                            notify(child_report);
                        } else {
                            match exit_code {
                                // exit_code.code() should be Some, unless an external signal will fail the subprocess.
                                // In that case, we should fail the parent process.
                                Ok(exit_code) => match exit_code.code() {
                                    Some(0) => notify(TaskResult::Report(
                                        task_id.clone(),
                                        "Exited with code 0.".to_owned(),
                                    )),
                                    Some(code) => notify(TaskResult::Failure(
                                        task_id.clone(),
                                        format!("Task {task_id} failed with exit code: {code:?}."),
                                    )),
                                    None => notify(TaskResult::Failure(
                                        task_id.clone(),
                                        "The process was signaled externally (no exit code available)"
                                            .to_owned(),
                                    )),
                                },
                                Err(e) => {
                                    notify(TaskResult::Failure(
                                        task_id,
                                        format!("System API failure: {e:?}"),
                                    ));
                                }
                            }
                        }
                        TaskState::Finished
                    },
                    TaskState::Cancelled => TaskState::Cancelled,
                    TaskState::Finished => TaskState::Finished,
                };
            }
        });

        Box::new(ChildTaskHandle {
            task_id: self.task_id.clone(),
            pid,
            log: self.group_ctx.logger(),
            task_state,
            jh: shared_mutex(Some(jh)),
            rt: self.rt.clone(),
            exit_timeout: KILLED_TASK_EXIT_TIMEOUT,
        })
    }

    fn execute(&self) -> Result<(), String> {
        let f = self
            .f
            .lock()
            .unwrap()
            .take()
            .expect("Task was already executed!");
        let res = panic_to_result(catch_unwind(f));
        if let Err(s) = &res {
            log_panic_event(&self.group_ctx.logger(), s);
        }
        res
    }

    fn task_id(&self) -> TaskId {
        self.task_id.clone()
    }
}

pub struct ChildTaskHandle {
    task_id: TaskId,
    /// The pid of the subprocess that runs the task.
    pid: Pid,
    log: Logger,
    task_state: Arc<Mutex<TaskState>>,
    jh: Arc<Mutex<Option<JoinHandle<()>>>>,
    rt: RtHandle,
    /// How long to wait for the subprocess to finish after killing it.
    exit_timeout: Duration,
}

impl ChildTaskHandle {
    /// Kills the subprocess of the task and its descendants, if it's still
    /// running, and waits at most `exit_timeout` for it to finish.
    /// `failure_reason` is the reason the task is killed for when it failed,
    /// e.g. because it timed out.
    fn finish(&self, requested_state: TaskState, failure_reason: Option<&str>) {
        // When the task failed, describe what its processes are doing before
        // killing them, to show where it got stuck. Reading `/proc` and killing
        // the processes can take a while, so both are done without holding the
        // lock, which the task needs to report that it exited. Once the state is
        // no longer `Running`, the task doesn't report anything.
        let is_running = self.task_state.lock().unwrap().is_running();
        let failure = match failure_reason {
            Some(reason) if is_running => Some((reason, process_tree::describe_tree(self.pid))),
            _ => None,
        };
        let kill = {
            let mut task_state = self.task_state.lock().unwrap();
            if !task_state.is_running() {
                debug!(self.log, "Task '{}' already terminated!", self.task_id);
                return;
            }
            match std::mem::replace(&mut *task_state, requested_state) {
                TaskState::Running(kill) => kill,
                _ => unreachable!(),
            }
        };
        if let Some((reason, processes)) = failure {
            warn!(
                self.log,
                "Killing task '{}' (pid {}) because it failed: {reason}. \
                 What its processes were doing in the kernel:\n{processes}",
                self.task_id,
                self.pid,
            );
        }
        let killed_descendants = kill();
        let jh = self
            .jh
            .lock()
            .unwrap()
            .take()
            .expect("JoinHandle already taken!");
        // Bound the wait, so that a subprocess that survives `SIGKILL` doesn't
        // block the driver, and with it the remaining tasks and the report,
        // until Bazel kills the test.
        match self
            .rt
            .block_on(async { timeout(self.exit_timeout, jh).await })
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => error!(self.log, "ChildTask JoinHandle returned error: {e:?}"),
            Err(_) => {
                let pids = std::iter::once(self.pid)
                    .chain(killed_descendants.into_iter().map(|(pid, _)| pid))
                    .collect();
                error!(
                    self.log,
                    "Task '{}' (pid {}) did not finish within {}s of being killed with SIGKILL. \
                     A process only survives SIGKILL while one of its threads waits \
                     uninterruptibly in the kernel, e.g. for I/O that doesn't complete. \
                     Continuing without waiting for it. \
                     What its processes are doing in the kernel:\n{}",
                    self.task_id,
                    self.pid,
                    self.exit_timeout.as_secs(),
                    process_tree::describe(pids),
                );
            }
        }
    }
}

impl TaskHandle for ChildTaskHandle {
    fn cancel(&self) {
        self.finish(TaskState::Cancelled, None);
    }

    fn cancel_after_failure(&self, reason: &str) {
        self.finish(TaskState::Cancelled, Some(reason));
    }
}

pub enum TaskState {
    Running(Box<dyn KillFn>),
    Cancelled,
    Finished,
}

impl TaskState {
    fn is_running(&self) -> bool {
        if let Self::Running(_) = self {
            return true;
        }
        false
    }
}

fn panic_to_result(panic_res: std::thread::Result<()>) -> Result<(), String> {
    if let Err(panic_res) = panic_res {
        if let Some(s) = panic_res.downcast_ref::<String>() {
            Err(s.to_string())
        } else if let Some(s) = panic_res.downcast_ref::<&str>() {
            Err(s.to_string())
        } else {
            Err(format!("{panic_res:?}"))
        }
    } else {
        Ok(())
    }
}

fn shared_mutex<T>(v: T) -> Arc<Mutex<T>> {
    Arc::new(Mutex::new(v))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// A handle of a running task whose subprocess, `sleep`, survives being
    /// killed, like a process that waits uninterruptibly in the kernel.
    fn handle_of_unkillable_task(rt: &tokio::runtime::Runtime, sleep_pid: Pid) -> ChildTaskHandle {
        ChildTaskHandle {
            task_id: TaskId::Test("unkillable".to_string()),
            pid: sleep_pid,
            log: new_discard_logger(),
            task_state: shared_mutex(TaskState::Running(Box::new(Vec::new))),
            jh: shared_mutex(Some(rt.spawn(std::future::pending()))),
            rt: rt.handle().clone(),
            exit_timeout: Duration::from_millis(100),
        }
    }

    #[test]
    fn cancel_gives_up_on_a_subprocess_that_does_not_exit() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut sleep = Command::new("sleep").arg("1000").spawn().unwrap();
        let handle = handle_of_unkillable_task(&rt, Pid::from_raw(sleep.id() as i32));

        let start = Instant::now();
        handle.cancel_after_failure("Timeout after 1s");

        assert!(start.elapsed() < Duration::from_secs(30));
        assert!(matches!(
            *handle.task_state.lock().unwrap(),
            TaskState::Cancelled
        ));
        // Cancelling again is a no-op.
        handle.cancel();
        sleep.kill().unwrap();
        sleep.wait().unwrap();
    }
}
