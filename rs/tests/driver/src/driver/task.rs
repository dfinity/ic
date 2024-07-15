//! A [Task] is an object that can be either spawned or executed.
//!
//! Spawning a task immediately returns control to the caller, while executing a
//! task consumes the thread until the task finishes. A task that is being
//! executed, has been executed, or was spawned cannot be execute again or be
//! re-spawned. A spawned task can be cancelled.

use std::sync::atomic::{AtomicBool, Ordering};

use slog::{info, Logger};
use tokio::{runtime::Handle as RtHandle, task::JoinHandle};

use crate::driver::event::TaskId;

use super::task_scheduler::TaskResult;

pub trait TaskIdT: Clone + PartialEq + Eq + Send + Sync + std::fmt::Debug {}
impl<T: Clone + PartialEq + Eq + Send + Sync + std::fmt::Debug> TaskIdT for T {}

pub type TaskResultCallback = Box<dyn FnOnce(TaskResult) + Send>;

pub trait Task: Send + Sync {
    /// Spawn a task. Control is returned to the user immediately.
    ///
    /// Calling this method more than once consistutes a hard failure.
    fn spawn(&self, notify: TaskResultCallback) -> Box<dyn TaskHandle>;

    /// Execute the task, consuming the current thread.
    /// execute() is only ever called on SubprocessTasks, so only that task type should reimplement this.
    fn execute(&self) -> Result<(), String> {
        Ok(())
    }

    fn task_id(&self) -> TaskId;
}

impl std::fmt::Debug for dyn Task {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Task< task_id={} >", self.task_id())
    }
}

pub trait TaskHandle: Send {
    /// Fail a running task. If the task has already finished, this call has no
    /// effect on the task.
    fn cancel(&self);
}

/// An EmptyTask is a virtual task that, after being spawned, does nothing and
/// just waits to be either stopped or failed.
pub struct EmptyTask {
    spawned: AtomicBool,
    task_id: TaskId,
}

pub struct SkipTestTask {
    spawned: AtomicBool,
    task_id: TaskId,
}

impl SkipTestTask {
    pub fn new(task_id: TaskId) -> Self {
        Self {
            spawned: Default::default(),
            task_id,
        }
    }
}

pub struct SkipTestTaskHandle;

impl TaskHandle for SkipTestTaskHandle {
    fn cancel(&self) {}
}

impl Task for SkipTestTask {
    fn spawn(&self, notify: TaskResultCallback) -> Box<dyn TaskHandle> {
        if self.spawned.fetch_or(true, Ordering::Relaxed) {
            panic!("Cannot respawn already spawned task.");
        }
        notify(TaskResult::Report(
            self.task_id.clone(),
            "Task skipped.".to_owned(),
        ));
        Box::new(SkipTestTaskHandle) as Box<dyn TaskHandle>
    }

    fn execute(&self) -> Result<(), String> {
        Ok(())
    }

    fn task_id(&self) -> TaskId {
        self.task_id.clone()
    }
}

impl EmptyTask {
    pub fn new(task_id: TaskId) -> Self {
        Self {
            spawned: Default::default(),
            task_id,
        }
    }
}

impl Task for EmptyTask {
    fn spawn(&self, _notify: TaskResultCallback) -> Box<dyn TaskHandle> {
        if self.spawned.fetch_or(true, Ordering::Relaxed) {
            panic!("Cannot respawn already spawned task.");
        }
        Box::new(EmptyTaskHandle {}) as Box<dyn TaskHandle>
    }

    fn task_id(&self) -> TaskId {
        self.task_id.clone()
    }
}

pub struct EmptyTaskHandle {}

impl TaskHandle for EmptyTaskHandle {
    fn cancel(&self) {}
}

pub struct DebugKeepaliveTask {
    spawned: AtomicBool,
    task_id: TaskId,
    logger: Logger,
    rt: RtHandle,
}

impl DebugKeepaliveTask {
    pub fn new(task_id: TaskId, logger: Logger, rt: RtHandle) -> Self {
        Self {
            spawned: Default::default(),
            task_id,
            logger,
            rt,
        }
    }
}

impl Task for DebugKeepaliveTask {
    fn spawn(&self, _notify: TaskResultCallback) -> Box<dyn TaskHandle> {
        if self.spawned.fetch_or(true, Ordering::Relaxed) {
            panic!("Cannot respawn already spawned task.");
        }
        let logger = self.logger.clone();
        let join_handle = self.rt.spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let mut mins = 1;
            loop {
                info!(
                    logger,
                    "Keeping alive system under test due to `ict -k` flag. Ctrl-c to stop."
                );
                tokio::time::sleep(std::time::Duration::from_secs(60 * mins)).await;
                if mins < 5 {
                    mins += 1;
                }
            }
        });

        Box::new(DebugKeepaliveTaskHandle {
            join_handle,
            stopped: Default::default(),
        }) as Box<dyn TaskHandle>
    }

    fn task_id(&self) -> TaskId {
        self.task_id.clone()
    }
}

pub struct DebugKeepaliveTaskHandle {
    join_handle: JoinHandle<()>,
    stopped: AtomicBool,
}

impl TaskHandle for DebugKeepaliveTaskHandle {
    fn cancel(&self) {
        if self.stopped.fetch_or(true, Ordering::Relaxed) {
            return;
        }
        self.join_handle.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::*;

    #[test]
    fn uninterrupted_empty_task_sends_no_events() {
        let expected_task_id = TaskId::Test("test-id".to_string());
        #[allow(clippy::disallowed_methods)]
        let (evt_send, evt_rcv) = unbounded();

        let t = EmptyTask::new(expected_task_id);
        let _th = t.spawn(Box::new(move |res| {
            evt_send.send(res).expect("Failed to send.")
        }));
        // Should have the same result for an any timeout.
        std::thread::sleep(std::time::Duration::from_millis(10));
        let res = evt_rcv.try_recv();
        assert!(matches!(res, Err(TryRecvError::Disconnected)));
    }
}
