//! A background thread that runs workloads off the critical path.
//!
//! Backpressure: we use a synchronous, zero-capacity channel, with the worker
//! thread blocking on `recv()` when not processing a workload. If a new
//! workload arrives while the worker is busy, the new workload is dropped and a
//! "skipped" counter is bumped.
//!
//! The struct is `Send + Sync` and shuts down cleanly on `Drop`: dropping the
//! sender closes the channel, the worker completes any in-progress workload,
//! its `recv()` returns `Err`, and the `JoinOnDrop` handle joins the thread.

use crate::JoinOnDrop;
use crossbeam_channel::{Sender, TrySendError, bounded};
use prometheus::IntCounter;

/// A workload to be executed by the worker thread.
pub type Workload = Box<dyn FnOnce() + Send>;

enum Job {
    Workload(Workload),
    /// Test-only barrier: enqueued with `send()`, will only unblock when the worker
    /// thread is idle (having completed any in-progress job).
    Flush(),
}

/// A worker thread that executes workloads in the background.
pub struct WorkerThread {
    sender: Sender<Job>,
    skipped: IntCounter,
    _handle: JoinOnDrop<()>,
}

impl WorkerThread {
    pub fn new(name: &str, skipped: IntCounter) -> Self {
        // Synchronous channel: worker blocks on `recv()`, sender, using `try_send()`
        // doesn't block when enqueuing jobs.
        let (sender, receiver) = bounded::<Job>(0);

        let handle = JoinOnDrop::new(
            std::thread::Builder::new()
                .name(name.to_string())
                .spawn(move || {
                    while let Ok(job) = receiver.recv() {
                        match job {
                            Job::Workload(workload) => {
                                workload();
                            }
                            Job::Flush() => {
                                // No need to do anything: sender already knows the worker is idle.
                            }
                        }
                    }
                })
                .expect("failed to spawn worker thread"),
        );
        Self {
            sender,
            skipped,
            _handle: handle,
        }
    }

    /// Enqueues a workload. If the worker is busy and the channel is full, drops
    /// the workload and increments the `skipped` counter rather than blocking the
    /// caller.
    pub fn enqueue(&self, workload: Workload) {
        match self.sender.try_send(Job::Workload(workload)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.skipped.inc();
            }
            Err(TrySendError::Disconnected(_)) => {
                // Don't allow the worker thread to exit silently (e.g. by panicking).
                panic!("worker thread has exited unexpectedly");
            }
        }
    }

    /// Test-only: blocks until the worker thread has completed any previous
    /// workload.
    #[doc(hidden)]
    pub fn flush_channel(&self) {
        // Blocking send waits for the worker thread to complete any in-progress job.
        self.sender
            .send(Job::Flush())
            .expect("worker thread has exited unexpectedly");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn skipped_counter() -> IntCounter {
        let registry = ic_metrics::MetricsRegistry::new();
        registry.int_counter("test_skipped", "Skipped workloads.")
    }

    #[test]
    fn enqueue_does_not_block_caller_under_load() {
        // Spam the worker with many workloads and ensure that the caller is
        // never blocked: with a synchronous channel, the surplus must be
        // dropped via the `skipped` counter rather than queued. We only
        // assert that the loop completes promptly and that `skipped + processed`
        // accounts for all the workloads we attempted.
        const N: u64 = 1_000;

        let completed = Arc::new(AtomicU64::new(0));
        let skipped = skipped_counter();

        let worker_thread = WorkerThread::new("test_worker_thread_skip", skipped.clone());
        // Wait for the worker thread to become responsive.
        worker_thread.flush_channel();

        for _ in 0..N {
            let completed = Arc::clone(&completed);
            worker_thread.enqueue(Box::new(move || {
                completed.fetch_add(1, Ordering::Relaxed);
            }));
        }
        worker_thread.flush_channel();

        // Completed vs skipped counts are non-deterministic (scheduling dependent), but
        // they should both be non-zero and must sum to the number of attempts.
        let completed = completed.load(Ordering::Relaxed);
        assert!(completed > 0);
        assert!(skipped.get() > 0);
        assert_eq!(completed + skipped.get(), N);
    }

    #[test]
    fn flush_is_a_no_op_when_idle() {
        let worker_thread = WorkerThread::new("test_worker_thread_flush_idle", skipped_counter());
        // Should return promptly even with nothing in the queue.
        worker_thread.flush_channel();
    }
}
