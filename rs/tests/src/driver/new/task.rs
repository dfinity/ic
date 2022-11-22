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

use super::event::{Event, EventSubscriberFactory, TaskId};

pub trait TaskIdT: Clone + PartialEq + Eq + Send + Sync + std::fmt::Debug {}
impl<T: Clone + PartialEq + Eq + Send + Sync + std::fmt::Debug> TaskIdT for T {}

pub trait Task: Send + Sync {
    /// Spawn a task. Control is returned to the user immediately.
    ///
    /// Calling this method more than once consistutes a hard failure.
    fn spawn(&self) -> Box<dyn TaskHandle>;

    /// Execute the task, consuming the current thread.
    fn execute(&self) -> Result<(), String>;
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
    sub_fact: Arc<dyn EventSubscriberFactory>,
}

impl EmptyTask {
    pub fn new(sub_fact: Arc<dyn EventSubscriberFactory>, task_id: TaskId) -> Self {
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
            panic!("Respawn already spawned task.");
        }

        let mut sub = self.sub_fact.create_subscriber();
        (sub)(Event::task_spawned(self.task_id.clone()));

        Box::new(EmptyTaskHandle {
            task_id: self.task_id.clone(),
            stopped: Default::default(),
            sub_fact: self.sub_fact.clone(),
        }) as Box<dyn TaskHandle>
    }

    fn execute(&self) -> Result<(), String> {
        Ok(())
    }
}

pub struct EmptyTaskHandle {
    task_id: TaskId,
    stopped: AtomicBool,
    sub_fact: Arc<dyn EventSubscriberFactory>,
}

impl TaskHandle for EmptyTaskHandle {
    fn fail(&self) {
        if self.stopped.fetch_or(true, Ordering::Relaxed) {
            return;
        }
        let mut sub = self.sub_fact.create_subscriber();
        (sub)(Event::task_failed(
            self.task_id.clone(),
            "Empty Task failed.".to_string(),
        ));
    }

    fn stop(&self) {
        if self.stopped.fetch_or(true, Ordering::Relaxed) {
            return;
        }
        let mut sub = self.sub_fact.create_subscriber();
        (sub)(Event::task_stopped(self.task_id.clone()));
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum OldTaskState {
    Skipped,
    Scheduled,
    Running { pid: u32 },
    Passed,
    Failed { failure_message: String },
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum OldTask {
    Setup(OldTaskState),
    Test { name: String, state: OldTaskState },
}

impl OldTask {
    pub fn name(&self) -> String {
        match self {
            Self::Setup(_) => String::from("::setup"),
            Self::Test { name, state: _ } => name.clone(),
        }
    }

    pub fn state(&self) -> OldTaskState {
        (match self {
            Self::Setup(state) => state,
            Self::Test { name: _, state } => state,
        })
        .clone()
    }

    fn finalize(&self, final_state: OldTaskState) -> Self {
        // use move semantics (self)
        match final_state {
            OldTaskState::Passed => {}
            OldTaskState::Failed { failure_message: _ } => {}
            _ => {
                panic!(
                    "state {:?} cannot be the state of a finalized task",
                    final_state
                )
            }
        }

        match self {
            Self::Setup(_) => Self::Setup(final_state),
            Self::Test { name, state: _ } => Self::Test {
                name: name.clone(),
                state: final_state,
            },
        }
    }

    pub fn mk_passed(&self) -> Self {
        println!("Task {:?} succeeded", self.name());
        self.finalize(OldTaskState::Passed)
    }

    pub fn mk_failed(&self, failure_message: String) -> Self {
        println!(
            "Task {:?} failed with message: {:?}",
            self.name(),
            failure_message
        );
        self.finalize(OldTaskState::Failed { failure_message })
    }
}

#[cfg(test)]
mod tests {
    use crate::driver::new::event::{test_utils::create_subfact, EventPayload};

    use super::*;
    use crossbeam_channel::TryRecvError;

    #[test]
    fn uninterrupted_empty_task_sends_no_events() {
        let expected_task_id = "test-id".to_string();
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
        let expected_task_id = "test-id".to_string();
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
        let expected_task_id = "test-id".to_string();
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
