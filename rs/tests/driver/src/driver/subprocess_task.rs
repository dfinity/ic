//! A child task is a function that is executed in a child process. Thus,
//! `execute()` is called in the child process only, while `spawn()` is called
//! in the parent process.

use crate::driver::{
    constants::LOG_CLOSE_TIMEOUT,
    context::GroupContext,
    dsl::SubprocessFn,
    event::TaskId,
    process::{KillFn, Process},
    subprocess_ipc::{log_panic_event, LogReceiver, ReportOrFailure},
    task::{Task, TaskHandle},
    task_scheduler::TaskResult,
};
use slog::{debug, error, info, Logger};
use std::{
    panic::catch_unwind,
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
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
}

impl SubprocessTask {
    pub fn new<F: SubprocessFn>(
        task_id: TaskId,
        rt: RtHandle,
        f: F,
        group_ctx: GroupContext,
    ) -> Self {
        Self {
            task_id,
            rt,
            f: shared_mutex(Some(Box::new(f))),
            spawned: Default::default(),
            group_ctx,
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
        let sock_id: u64 = rand::thread_rng().gen();
        let sock_path = GroupContext::log_socket_path(sock_id);

        let mut child_cmd = Command::new(self.group_ctx.exec_path.clone());
        child_cmd
            .arg("--working-dir") // TODO: rename as --group-dir
            .arg(self.group_ctx.group_dir().as_os_str())
            .arg("--group-base-name")
            .arg(self.group_ctx.group_base_name.clone())
            .arg("spawn-child")
            .arg(self.task_id.name())
            .arg(sock_id.to_string());

        info!(self.group_ctx.log(), "Spawning {:?} ...", child_cmd);

        let log = self.group_ctx.logger();
        let log_rcvr = self
            .rt
            .block_on(LogReceiver::new(sock_path, log.clone()))
            .expect("Could not start LogReceiver");
        let (proc, kill) =
            self.rt
                .block_on(Process::new(self.task_id.clone(), child_cmd, log.clone()));

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
                                        format!("Task {} failed with exit code: {:?}.", task_id, code),
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
                                        format!("System API failure: {:?}", e),
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
            log: self.group_ctx.logger(),
            task_state,
            jh: shared_mutex(Some(jh)),
            rt: self.rt.clone(),
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
    log: Logger,
    task_state: Arc<Mutex<TaskState>>,
    jh: Arc<Mutex<Option<JoinHandle<()>>>>,
    rt: RtHandle,
}

impl ChildTaskHandle {
    fn finish(&self, requested_state: TaskState) {
        {
            let mut task_state = self.task_state.lock().unwrap();

            if task_state.is_running() {
                if let TaskState::Running(kill) =
                    std::mem::replace(&mut *task_state, requested_state)
                {
                    (kill)()
                } else {
                    unreachable!();
                }
            } else {
                debug!(self.log, "Task '{}' already terminated!", self.task_id);
                return;
            };
        }
        {
            let jh = self
                .jh
                .lock()
                .unwrap()
                .take()
                .expect("JoinHandle already taken!");
            if let Err(e) = self.rt.block_on(jh) {
                error!(self.log, "ChildTask JoinHandle returned error: {e:?}");
            }
        }
    }
}

impl TaskHandle for ChildTaskHandle {
    fn cancel(&self) {
        self.finish(TaskState::Cancelled);
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
            Err(format!("{:?}", panic_res))
        }
    } else {
        Ok(())
    }
}

fn shared_mutex<T>(v: T) -> Arc<Mutex<T>> {
    Arc::new(Mutex::new(v))
}
