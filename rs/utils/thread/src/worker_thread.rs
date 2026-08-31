//! A background thread that runs workloads off the critical path.
//!
//! Backpressure: we use a bounded channel and block the caller when it is
//! full, so workloads are never dropped. A capacity above zero means that the
//! caller does not block if the worker thread has not been scheduled (e.g.
//! under heavy load); with the trade-off that the queued workloads (and
//! whatever they capture) are held on to until the worker gets to them.
//!
//! The struct is `Send + Sync` and shuts down cleanly on `Drop`: dropping the
//! sender closes the channel, the worker completes the in-progress workload and
//! any queued ones, its `recv()` returns `Err`, and the `JoinOnDrop` handle joins
//! the thread.

use crate::JoinOnDrop;
use crossbeam_channel::{Sender, TrySendError, bounded};
use prometheus::Histogram;

/// A workload to be executed by the worker thread.
pub type Workload = Box<dyn FnOnce() + Send>;

enum Job {
    Workload(Workload),
    /// Test-only barrier: the worker acknowledges it once it has completed all
    /// jobs enqueued before it.
    Flush(Sender<()>),
}

/// A worker thread that executes workloads in the background.
pub struct WorkerThread {
    sender: Sender<Job>,
    blocked_duration: Histogram,
    _handle: JoinOnDrop<()>,
}

impl WorkerThread {
    /// Spawns a worker thread, with a channel of the given capacity.
    /// `blocked_duration` records how long each `enqueue()` call had to block (zero
    /// if it did not).
    pub fn new(name: &str, capacity: usize, blocked_duration: Histogram) -> Self {
        let (sender, receiver) = bounded::<Job>(capacity);

        let handle = JoinOnDrop::new(
            std::thread::Builder::new()
                .name(name.to_string())
                .spawn(move || {
                    while let Ok(job) = receiver.recv() {
                        match job {
                            Job::Workload(workload) => {
                                workload();
                            }
                            Job::Flush(ack) => {
                                // All jobs enqueued earlier have been completed. Ignore send errors, the sender
                                // may have given up waiting.
                                let _ = ack.send(());
                            }
                        }
                    }
                })
                .expect("failed to spawn worker thread"),
        );
        Self {
            sender,
            blocked_duration,
            _handle: handle,
        }
    }

    /// Enqueues a workload, blocking if the channel is full (i.e. until the worker
    /// thread has caught up).
    pub fn enqueue(&self, workload: Workload) {
        match self.sender.try_send(Job::Workload(workload)) {
            Ok(()) => {
                self.blocked_duration.observe(0.0);
            }

            Err(TrySendError::Full(job)) => {
                let _timer = self.blocked_duration.start_timer();
                self.sender
                    .send(job)
                    .expect("worker thread has exited unexpectedly");
            }

            Err(TrySendError::Disconnected(_)) => {
                // Don't allow the worker thread to exit silently (e.g. by panicking).
                panic!("worker thread has exited unexpectedly");
            }
        }
    }

    /// Test-only: blocks until the worker thread has completed all current and/or
    /// enqueued workloads.
    #[doc(hidden)]
    pub fn flush_channel(&self) {
        // Capacity of 1, so the worker thread never blocks on acknowledging.
        let (ack, ack_receiver) = bounded::<()>(1);
        self.sender
            .send(Job::Flush(ack))
            .expect("worker thread has exited unexpectedly");
        // Jobs are executed in order, so the acknowledgement means that all workloads
        // enqueued before the barrier have been completed.
        ack_receiver
            .recv()
            .expect("worker thread has exited unexpectedly");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    fn blocked_duration_histogram() -> Histogram {
        let registry = ic_metrics::MetricsRegistry::new();
        registry.histogram(
            "test_blocked_duration",
            "Time spent blocked enqueuing workloads.",
            vec![0.0, 1.0],
        )
    }

    /// Every enqueued workload is executed, however many of them there are and
    /// whatever the channel capacity.
    #[test]
    fn all_workloads_are_executed() {
        const N: u64 = 1_000;

        for capacity in [0, 1, 10] {
            let completed = Arc::new(AtomicU64::new(0));
            let blocked_duration = blocked_duration_histogram();

            let worker_thread = WorkerThread::new(
                "test_worker_thread_execute_all",
                capacity,
                blocked_duration.clone(),
            );

            for _ in 0..N {
                let completed = Arc::clone(&completed);
                worker_thread.enqueue(Box::new(move || {
                    completed.fetch_add(1, Ordering::Relaxed);
                }));
            }
            worker_thread.flush_channel();

            assert_eq!(N, completed.load(Ordering::Relaxed));
            assert_eq!(N, blocked_duration.get_sample_count());
        }
    }

    /// Enqueuing blocks (and records the time spent blocked) while the worker
    /// thread is busy and the channel is full.
    #[test]
    fn enqueue_blocks_while_channel_is_full() {
        const WORKLOAD_DURATION: Duration = Duration::from_millis(100);

        let blocked_duration = blocked_duration_histogram();
        let worker_thread =
            WorkerThread::new("test_worker_thread_block", 0, blocked_duration.clone());

        // With a zero capacity channel, this workload is picked up immediately.
        worker_thread.enqueue(Box::new(|| std::thread::sleep(WORKLOAD_DURATION)));

        // And this one can only be enqueued once the above has completed.
        let since = Instant::now();
        worker_thread.enqueue(Box::new(|| {}));
        assert!(since.elapsed() >= WORKLOAD_DURATION / 2);
        assert!(blocked_duration.get_sample_sum() > 0.0);
    }

    /// Flushing waits for the in-progress workload to complete.
    #[test]
    fn flush_waits_for_workload_completion() {
        let completed = Arc::new(AtomicBool::new(false));
        let worker_thread =
            WorkerThread::new("test_worker_thread_flush", 1, blocked_duration_histogram());

        let workload_completed = Arc::clone(&completed);
        worker_thread.enqueue(Box::new(move || {
            std::thread::sleep(Duration::from_millis(100));
            workload_completed.store(true, Ordering::Relaxed);
        }));
        worker_thread.flush_channel();

        assert!(completed.load(Ordering::Relaxed));
    }

    #[test]
    fn flush_is_a_no_op_when_idle() {
        let worker_thread = WorkerThread::new(
            "test_worker_thread_flush_idle",
            1,
            blocked_duration_histogram(),
        );
        // Should return promptly even with nothing in the queue.
        worker_thread.flush_channel();
    }
}
