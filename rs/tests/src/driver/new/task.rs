//! A [Task] is an object that can be either spawned or executed.
//!
//! Spawning a task immediately returns control to the caller, while executing a
//! task consumes the thread until the task finishes. A task that is being
//! executed, has been executed, or was spawned cannot be execute again or be
//! re-spawned. A spawned task can be cancelled.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use slog::{info, Logger};
use tokio::{runtime::Handle as RtHandle, task::JoinHandle};

use super::event::{BroadcastingEventSubscriberFactory, Event, TaskId};

pub trait TaskIdT: Clone + PartialEq + Eq + Send + Sync + std::fmt::Debug {}
impl<T: Clone + PartialEq + Eq + Send + Sync + std::fmt::Debug> TaskIdT for T {}

pub trait Task: Send + Sync {
    /// Spawn a task. Control is returned to the user immediately.
    ///
    /// Calling this method more than once consistutes a hard failure.
    fn spawn(&self) -> Box<dyn TaskHandle>;

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

pub trait TaskHandle: Send + Sync {
    /// Fail a running task. If the task has already finished, this call has no
    /// effect on the task.
    fn fail(&self);

    /// Stop a running task. If the task has already finished, this call has no
    /// effect on the task.
    fn stop(&self);
}

/// An EmptyTask is a virtual task that, after being spawned, does nothing and
/// just waits to be either stopped or failed.
pub struct EmptyTask {
    spawned: AtomicBool,
    task_id: TaskId,
    sub_fact: Arc<dyn BroadcastingEventSubscriberFactory>,
}

pub struct SkipTestTask {
    spawned: AtomicBool,
    task_id: TaskId,
    sub_fact: Arc<dyn BroadcastingEventSubscriberFactory>,
}

impl SkipTestTask {
    pub fn new(sub_fact: Arc<dyn BroadcastingEventSubscriberFactory>, task_id: TaskId) -> Self {
        Self {
            spawned: Default::default(),
            task_id,
            sub_fact,
        }
    }
}

pub struct SkipTestTaskHandle;

impl TaskHandle for SkipTestTaskHandle {
    fn fail(&self) {}

    fn stop(&self) {}
}

impl Task for SkipTestTask {
    fn spawn(&self) -> Box<dyn TaskHandle> {
        if self.spawned.fetch_or(true, Ordering::Relaxed) {
            panic!("Cannot respawn already spawned task.");
        }

        let mut sub = self.sub_fact.create_broadcasting_subscriber();
        (sub)(Event::task_spawned(self.task_id.clone()));
        (sub)(Event::task_skipped(self.task_id.clone()));
        (sub)(Event::task_stopped(self.task_id.clone()));

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
    pub fn new(sub_fact: Arc<dyn BroadcastingEventSubscriberFactory>, task_id: TaskId) -> Self {
        Self {
            spawned: Default::default(),
            task_id,
            sub_fact,
        }
    }
}

impl Task for EmptyTask {
    fn spawn(&self) -> Box<dyn TaskHandle> {
        if self.spawned.fetch_or(true, Ordering::Relaxed) {
            panic!("Cannot respawn already spawned task.");
        }

        let mut sub = self.sub_fact.create_broadcasting_subscriber();
        (sub)(Event::task_spawned(self.task_id.clone()));

        Box::new(EmptyTaskHandle {
            task_id: self.task_id.clone(),
            stopped: Default::default(),
            sub_fact: self.sub_fact.clone(),
        }) as Box<dyn TaskHandle>
    }

    fn task_id(&self) -> TaskId {
        self.task_id.clone()
    }
}

pub struct EmptyTaskHandle {
    task_id: TaskId,
    stopped: AtomicBool,
    sub_fact: Arc<dyn BroadcastingEventSubscriberFactory>,
}

impl TaskHandle for EmptyTaskHandle {
    fn fail(&self) {
        if self.stopped.fetch_or(true, Ordering::Relaxed) {
            return;
        }
        let mut sub = self.sub_fact.create_broadcasting_subscriber();
        (sub)(Event::task_failed(
            self.task_id.clone(),
            "Empty Task failed.".to_string(),
        ));
    }

    fn stop(&self) {
        if self.stopped.fetch_or(true, Ordering::Relaxed) {
            return;
        }
        let mut sub = self.sub_fact.create_broadcasting_subscriber();
        (sub)(Event::task_stopped(self.task_id.clone()));
    }
}

pub struct DebugKeepaliveTask {
    spawned: AtomicBool,
    task_id: TaskId,
    sub_fact: Arc<dyn BroadcastingEventSubscriberFactory>,
    logger: Logger,
    rt: RtHandle,
}

impl DebugKeepaliveTask {
    pub fn new(
        sub_fact: Arc<dyn BroadcastingEventSubscriberFactory>,
        task_id: TaskId,
        logger: Logger,
        rt: RtHandle,
    ) -> Self {
        Self {
            spawned: Default::default(),
            task_id,
            sub_fact,
            logger,
            rt,
        }
    }
}

impl Task for DebugKeepaliveTask {
    fn spawn(&self) -> Box<dyn TaskHandle> {
        if self.spawned.fetch_or(true, Ordering::Relaxed) {
            panic!("Cannot respawn already spawned task.");
        }
        let mut sub = self.sub_fact.create_broadcasting_subscriber();
        (sub)(Event::task_spawned(self.task_id.clone()));

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
            task_id: self.task_id.clone(),
            stopped: Default::default(),
            sub_fact: self.sub_fact.clone(),
        }) as Box<dyn TaskHandle>
    }

    fn task_id(&self) -> TaskId {
        self.task_id.clone()
    }
}

pub struct DebugKeepaliveTaskHandle {
    join_handle: JoinHandle<()>,
    task_id: TaskId,
    stopped: AtomicBool,
    sub_fact: Arc<dyn BroadcastingEventSubscriberFactory>,
}

impl TaskHandle for DebugKeepaliveTaskHandle {
    fn fail(&self) {
        if self.stopped.fetch_or(true, Ordering::Relaxed) {
            return;
        }
        self.join_handle.abort();
        let mut sub = self.sub_fact.create_broadcasting_subscriber();
        (sub)(Event::task_failed(
            self.task_id.clone(),
            "Keepalive Task failed.".to_string(),
        ));
    }

    fn stop(&self) {
        if self.stopped.fetch_or(true, Ordering::Relaxed) {
            return;
        }
        self.join_handle.abort();
        let mut sub = self.sub_fact.create_broadcasting_subscriber();
        (sub)(Event::task_stopped(self.task_id.clone()));
    }
}

#[cfg(test)]
mod tests {
    use crate::driver::new::event::{test_utils::create_subfact, EventPayload};

    use super::*;
    use crossbeam_channel::TryRecvError;

    #[test]
    fn uninterrupted_empty_task_sends_no_events() {
        let expected_task_id = TaskId::Test("test-id".to_string());
        let (evt_send, evt_rcv) = create_subfact();

        let t = EmptyTask::new(evt_send, expected_task_id);
        let _th = t.spawn();
        let _spawn_evt = evt_rcv.recv().unwrap();
        // Should have the same result for an any timeout.
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(matches!(evt_rcv.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn spawned_empty_task_can_be_stopped() {
        let expected_task_id = TaskId::Test("test-id".to_string());
        let (evt_send, evt_rcv) = create_subfact();

        let t = EmptyTask::new(evt_send, expected_task_id.clone());
        let th = t.spawn();
        th.stop();
        let _spawn_evt = evt_rcv.recv().unwrap();
        let evt = evt_rcv.recv().unwrap();

        assert!(matches!(evt.what,
            EventPayload::TaskStopped { task_id, .. } if task_id == expected_task_id
        ));
    }

    #[test]
    fn spawned_empty_task_can_be_failed() {
        let expected_task_id = TaskId::Test("test-id".to_string());
        let (evt_send, evt_rcv) = create_subfact();

        let t = EmptyTask::new(evt_send, expected_task_id.clone());
        let th = t.spawn();
        th.fail();
        let _spawn_evt = evt_rcv.recv().unwrap();
        let evt = evt_rcv.recv().unwrap();

        assert!(matches!(evt.what,
            EventPayload::TaskFailed { task_id, .. } if task_id == expected_task_id
        ));
    }
}
