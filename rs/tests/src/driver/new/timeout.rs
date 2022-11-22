//! A task that fails after a specified duration.
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use tokio::{runtime::Handle as RtHandle, task::JoinHandle};

use super::{
    event::{Event, EventSubscriberFactory, TaskId},
    task::{Task, TaskHandle},
};

pub struct TimeoutTask {
    spawned: AtomicBool,
    rt: RtHandle,
    duration: Duration,
    sub_fact: Arc<dyn EventSubscriberFactory>,
    task_id: TaskId,
}

impl TimeoutTask {
    pub fn new(
        rt: RtHandle,
        duration: Duration,
        sub_fact: Arc<dyn EventSubscriberFactory>,
        task_id: TaskId,
    ) -> Self {
        Self {
            spawned: Default::default(),
            rt,
            duration,
            sub_fact,
            task_id,
        }
    }
}

impl Task for TimeoutTask {
    fn spawn(&self) -> Box<dyn super::task::TaskHandle> {
        if self.spawned.fetch_or(true, Ordering::Relaxed) {
            panic!("respawned already spawned task `{}`", self.task_id);
        }
        let mut sub = self.sub_fact.create_subscriber();
        (sub)(Event::task_spawned(self.task_id.clone()));
        let stopped = Arc::new(AtomicBool::default());
        let jh = self.rt.spawn({
            let duration = self.duration;
            let task_id = self.task_id.clone();
            let stopped = stopped.clone();
            async move {
                let _ = tokio::time::sleep(duration);
                // xxx: ignore send errors
                if !stopped.fetch_or(true, Ordering::Relaxed) {
                    (sub)(Event::task_failed(
                        task_id,
                        format!("Timeout after {}s", duration.as_secs()),
                    ));
                }
            }
        });

        let th = TimeoutTaskHandle {
            jh,
            finished: stopped,
            sub_fact: self.sub_fact.clone(),
            task_id: self.task_id.clone(),
        };

        Box::new(th)
    }

    fn execute(&self) -> Result<(), String> {
        std::thread::sleep(self.duration);
        Ok(())
    }
}

pub struct TimeoutTaskHandle {
    /// This boolean prevents and outside stop/fail signal from being propagated
    /// when the task finished.
    finished: Arc<AtomicBool>,
    sub_fact: Arc<dyn EventSubscriberFactory>,
    task_id: TaskId,
    jh: JoinHandle<()>,
}

impl TaskHandle for TimeoutTaskHandle {
    fn fail(&self) {
        self.jh.abort();
        let mut sub = self.sub_fact.create_subscriber();
        if !self.finished.fetch_or(true, Ordering::Relaxed) {
            (sub)(Event::task_failed(
                self.task_id.clone(),
                "Timeout failed.".to_string(),
            ));
        }
    }

    fn stop(&self) {
        self.jh.abort();
        let mut sub = self.sub_fact.create_subscriber();
        if !self.finished.fetch_or(true, Ordering::Relaxed) {
            (sub)(Event::task_stopped(self.task_id.clone()));
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::driver::new::event::{test_utils::create_subfact, EventPayload};

    use super::*;
    use tokio::runtime::Runtime;

    #[test]
    fn timeout_task_times_out() {
        let rt = create_rt();
        let d = ms(1);
        let expected_task_id = "test-id".to_string();
        let (evt_send, evt_rcv) = create_subfact();

        let t = TimeoutTask::new(rt.handle().clone(), d, evt_send, expected_task_id.clone());
        let _th = t.spawn();
        std::thread::sleep(d * 20);

        let _spawned_event = evt_rcv.recv().unwrap();
        let evt = evt_rcv.recv().unwrap();

        assert!(matches!(evt.what,
            EventPayload::TaskFailed { task_id, .. } if task_id == expected_task_id
        ));
    }

    #[test]
    fn timeout_task_can_be_stopped() {
        let rt = create_rt();
        let d = ms(2000);
        let expected_task_id = "test-id".to_string();
        let (evt_send, evt_rcv) = create_subfact();

        let t = TimeoutTask::new(rt.handle().clone(), d, evt_send, expected_task_id.clone());
        let th = t.spawn();
        th.stop();
        let _spawned_event = evt_rcv.recv().unwrap();
        let evt = evt_rcv.recv().unwrap();

        assert!(matches!(evt.what,
            EventPayload::TaskStopped { task_id } if task_id == expected_task_id
        ));
    }

    #[test]
    fn timeout_task_can_be_failed() {
        let rt = create_rt();
        let d = ms(2000);
        let expected_task_id = "test-id".to_string();
        let (evt_send, evt_rcv) = create_subfact();

        let t = TimeoutTask::new(rt.handle().clone(), d, evt_send, expected_task_id.clone());
        let th = t.spawn();
        th.fail();
        let _spawned_event = evt_rcv.recv().unwrap();
        let evt = evt_rcv.recv().unwrap();

        assert!(matches!(evt.what,
            EventPayload::TaskFailed { task_id, .. } if task_id == expected_task_id
        ));
    }

    #[test]
    #[should_panic]
    fn spawning_timeout_task_twice_should_panic() {
        let rt = create_rt();
        let d = ms(2000);
        let expected_task_id = "test-id".to_string();
        let (evt_send, _evt_rcv) = create_subfact();

        let t = TimeoutTask::new(rt.handle().clone(), d, evt_send, expected_task_id);
        t.spawn();
        t.spawn();
    }

    fn create_rt() -> Runtime {
        Runtime::new().unwrap()
    }

    fn ms(ms: u64) -> Duration {
        Duration::from_millis(ms)
    }
}
