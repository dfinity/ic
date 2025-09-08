//! A task that fails after a specified duration.
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::{runtime::Handle as RtHandle, task::JoinHandle};

use crate::driver::{
    event::TaskId,
    task::{Task, TaskHandle},
};

use super::{task::TaskResultCallback, task_scheduler::TaskResult};

pub struct TimeoutTask {
    spawned: AtomicBool,
    rt: RtHandle,
    duration: Duration,
    task_id: TaskId,
}

impl TimeoutTask {
    pub fn new(rt: RtHandle, duration: Duration, task_id: TaskId) -> Self {
        Self {
            spawned: Default::default(),
            rt,
            duration,
            task_id,
        }
    }
}

impl Task for TimeoutTask {
    fn spawn(&self, notify: TaskResultCallback) -> Box<dyn crate::driver::task::TaskHandle> {
        if self.spawned.fetch_or(true, Ordering::Relaxed) {
            panic!("respawned already spawned task `{}`", self.task_id);
        }
        let stopped = Arc::new(AtomicBool::default());
        let jh = self.rt.spawn({
            let duration = self.duration;
            let task_id = self.task_id.clone();
            async move {
                tokio::time::sleep(duration).await;
                // xxx: ignore send errors
                if !stopped.fetch_or(true, Ordering::Relaxed) {
                    notify(TaskResult::Failure(
                        task_id,
                        format!("Timeout after {}s", duration.as_secs()),
                    ));
                }
            }
        });

        let th = TimeoutTaskHandle { jh };

        Box::new(th)
    }

    fn task_id(&self) -> TaskId {
        self.task_id.clone()
    }
}

pub struct TimeoutTaskHandle {
    jh: JoinHandle<()>,
}

impl TaskHandle for TimeoutTaskHandle {
    fn cancel(&self) {
        self.jh.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::unbounded;
    use tokio::runtime::Runtime;

    #[test]
    fn timeout_task_times_out() {
        let rt = create_rt();
        let d = ms(1);
        let expected_task_id = TaskId::Test("test-id".to_string());
        #[allow(clippy::disallowed_methods)]
        let (evt_send, evt_rcv) = unbounded();

        let t = TimeoutTask::new(rt.handle().clone(), d, expected_task_id.clone());
        let _th = t.spawn(Box::new(move |res| {
            evt_send.send(res).expect("Failed to send.")
        }));
        std::thread::sleep(d * 20);
        let evt = evt_rcv.recv().unwrap();
        assert!(matches!(evt, TaskResult::Failure(task_id, _msg) if task_id == expected_task_id));
    }

    #[test]
    #[should_panic]
    fn spawning_timeout_task_twice_should_panic() {
        let rt = create_rt();
        let d = ms(2000);
        let expected_task_id = TaskId::Test("test-id".to_string());
        #[allow(clippy::disallowed_methods)]
        let (evt_send, _evt_rcv) = unbounded();
        let evt_send2 = evt_send.clone();

        let t = TimeoutTask::new(rt.handle().clone(), d, expected_task_id);
        t.spawn(Box::new(move |res| {
            evt_send.send(res).expect("Failed to send.")
        }));
        t.spawn(Box::new(move |res| {
            evt_send2.send(res).expect("Failed to send.")
        }));
    }

    fn create_rt() -> Runtime {
        Runtime::new().unwrap()
    }

    fn ms(ms: u64) -> Duration {
        Duration::from_millis(ms)
    }
}
