//! A child task is a function that is executed in a child process. Thus,
//! `execute()` is called in the child process only, while `spawn()` is called
//! in the parent process.

use std::{
    panic::catch_unwind,
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use slog::{crit, error, info, Logger};
use tokio::{runtime::Handle as RtHandle, task::JoinHandle};

use super::{
    context::GroupContext,
    dsl::ChildFn,
    event::EventSubscriberFactory,
    event::{Event, TaskId},
    process::{KillFn, Process},
    task::{Task, TaskHandle},
};

pub struct ChildTask {
    task_id: TaskId,
    rt: RtHandle,
    // To execute the function within an `catch_unwind`, it must be FnOnce.
    // Thus, `f` needs to be moved out of the object when executed.
    f: Arc<Mutex<Option<Box<dyn ChildFn>>>>,
    spawned: AtomicBool,
    group_ctx: GroupContext,
    sub_fact: Arc<dyn EventSubscriberFactory>,
}

impl ChildTask {
    pub fn new<F: ChildFn>(
        task_id: TaskId,
        rt: RtHandle,
        f: F,
        group_ctx: GroupContext,
        sub_fact: Arc<dyn EventSubscriberFactory>,
    ) -> Self {
        Self {
            task_id,
            rt,
            f: shared_mutex(Some(Box::new(f))),
            spawned: Default::default(),
            group_ctx,
            sub_fact,
        }
    }
}

impl Task for ChildTask {
    fn spawn(&self) -> Box<dyn super::task::TaskHandle> {
        if self.spawned.swap(true, Ordering::Relaxed) {
            panic!("Respawned already spawned task '{}'", self.task_id);
        }

        let mut child_cmd = Command::new(self.group_ctx.exec_path.clone());
        child_cmd
            .arg("--working-dir") // TODO: rename as --group-dir
            .arg(self.group_ctx.group_dir().as_os_str())
            .arg("spawn-child")
            .arg(self.task_id.clone())
            .arg("ABC")
            .arg("XYZ");

        let mut sub = self.sub_fact.create_subscriber();
        (sub)(Event::task_spawned(self.task_id.clone()));

        let (proc, kill) = self.rt.block_on(Process::new(
            self.task_id.clone(),
            child_cmd,
            self.sub_fact.clone(),
        ));

        let task_state = shared_mutex(TaskState::Running(Box::new(kill)));
        let jh = self.rt.spawn({
            let log = self.group_ctx.logger();
            let task_id = self.task_id.clone();
            let task_state = task_state.clone();
            async move {
                let exit_code = proc.block_on_exit().await;
                info!(
                    log,
                    "Task '{task_id}' finished with exit code: {exit_code:?}"
                );

                let mut task_state = task_state.lock().unwrap();
                let event = match &*task_state {
                    TaskState::Running(_) => {
                        if exit_code.is_err() {
                            Event::task_failed(
                                task_id,
                                "Task '{task_id}' failed with exit code: {exit_code:?}."
                                    .to_string(),
                            )
                        } else {
                            Event::task_stopped(task_id)
                        }
                    }
                    // If either a stop or a failure was requested by the
                    // scheduler, we ignore the exit code. I.e., the request
                    // overrides the result from the process.
                    TaskState::StopRequested => Event::task_stopped(task_id),
                    TaskState::FailRequested => Event::task_failed(
                        task_id,
                        "Task '{task_id}' failed with exit code: {exit_code:?}.".to_string(),
                    ),
                    TaskState::Finished => {
                        crit!(log, "Task '{task_id}' already finished!");
                        unreachable!()
                    }
                };
                (sub)(event);
                *task_state = TaskState::Finished;
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
        panic_to_result(catch_unwind(move || (f)()))
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
                error!(self.log, "Task '{}' already failed!", self.task_id);
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
    fn fail(&self) {
        self.finish(TaskState::FailRequested);
    }

    fn stop(&self) {
        self.finish(TaskState::StopRequested);
    }
}

pub enum TaskState {
    Running(Box<dyn KillFn>),
    StopRequested,
    FailRequested,
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
