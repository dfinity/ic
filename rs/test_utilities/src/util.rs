use ic_interfaces::time_source::{TimeNotMonotoneError, TimeSource};
use ic_types::time::{Time, UNIX_EPOCH};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, RwLock};

// A mock object that wraps a queue
#[derive(Default)]
pub struct FakeQueue<T> {
    pub queue: Mutex<VecDeque<T>>,
}

impl<T> FakeQueue<T> {
    pub fn new() -> FakeQueue<T> {
        FakeQueue {
            queue: Mutex::new(VecDeque::new()),
        }
    }

    pub fn enqueue(&self, elem: T) {
        let mut q = self.queue.lock().unwrap();
        q.push_back(elem)
    }

    pub fn dequeue(&self) -> Option<T> {
        let mut q = self.queue.lock().unwrap();
        q.pop_front()
    }

    pub fn dump(&self) -> VecDeque<T> {
        self.replace(VecDeque::new())
    }

    pub fn replace(&self, new_value: VecDeque<T>) -> VecDeque<T> {
        let mut q = self.queue.lock().unwrap();
        std::mem::replace(&mut *q, new_value)
    }
}

pub fn mock_time() -> Time {
    UNIX_EPOCH
}

/// A pure implementation of [TimeSource] that requires manual
/// fast forward to advance time.
pub struct FastForwardTimeSource(RwLock<TickTimeData>);

struct TickTimeData {
    current_time: Time,
}

impl FastForwardTimeSource {
    pub fn new() -> Arc<FastForwardTimeSource> {
        Arc::new(FastForwardTimeSource(RwLock::new(TickTimeData {
            current_time: UNIX_EPOCH,
        })))
    }

    /// Set the time to a new value, only when the given time is greater than
    /// or equal to the current time. Return error otherwise.
    pub fn set_time(&self, time: Time) -> Result<(), TimeNotMonotoneError> {
        let data = &mut self.0.write().unwrap();
        if time >= data.current_time {
            data.current_time = time;
            Ok(())
        } else {
            Err(TimeNotMonotoneError)
        }
    }

    /// Reset the time to start value.
    pub fn reset(&self) {
        self.0.write().unwrap().current_time = UNIX_EPOCH;
    }
}

impl TimeSource for FastForwardTimeSource {
    fn get_relative_time(&self) -> Time {
        self.0.read().unwrap().current_time
    }
}

/// Execute the provided closure on a separate thread, but with a timeout.
/// Return true if the action completed successfully and false otherwise.
pub fn with_timeout<T>(timeout: std::time::Duration, action: T) -> bool
where
    T: FnOnce() + std::marker::Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        action();
        tx.send(()).unwrap();
    });
    rx.recv_timeout(timeout).is_ok()
}
