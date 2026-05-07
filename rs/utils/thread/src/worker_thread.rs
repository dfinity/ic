//! A background thread that runs workloads off the critical path.
//!
//! Backpressure: the worker has a single-slot channel plus the job currently
//! being processed (so at most two workloads pinned in memory at any time). If
//! a new workload arrives while both slots are full, the new workload is
//! dropped and a "skipped" counter is bumped.
//!
//! The struct is `Send + Sync` and shuts down cleanly on `Drop`: dropping the
//! sender closes the channel, the worker drains any enqueued workloads, its
//! `recv()` returns `Err`, and the `JoinOnDrop` handle joins the thread.

use crate::JoinOnDrop;
use crossbeam_channel::{Sender, TrySendError, bounded};
use prometheus::IntCounter;

/// A workload to be executed by the worker thread.
type Workload = Box<dyn FnOnce() + Send>;

enum Job {
    Workload(Workload),
    /// Test-only barrier: notify when the worker has drained all preceding
    /// jobs; only used in tests.
    Flush(Sender<()>),
}

/// A worker thread that executes workloads in the background.
pub struct WorkerThread {
    sender: Sender<Job>,
    skipped: IntCounter,
    _handle: JoinOnDrop<()>,
}

impl WorkerThread {
    pub fn new(name: &str, skipped: IntCounter) -> Self {
        // At most one queued job; combined with the in-flight job that's the
        // most state we'll keep alive.
        let (sender, receiver) = bounded::<Job>(1);

        let handle = JoinOnDrop::new(
            std::thread::Builder::new()
                .name(name.to_string())
                .spawn(move || {
                    while let Ok(job) = receiver.recv() {
                        match job {
                            Job::Workload(workload) => {
                                workload();
                            }
                            Job::Flush(notify) => {
                                // Best-effort notify; ignore if the receiver is
                                // already gone (e.g. test was aborted).
                                let _ = notify.send(());
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
                // The worker thread exited; should only happen during shutdown.
            }
        }
    }

    /// Test-only: blocks until all previously-enqueued workloads have been
    /// processed.
    #[doc(hidden)]
    pub fn flush_channel(&self) {
        let (notify_send, notify_recv) = bounded(1);
        // Use a blocking send: this waits for the in-flight + queued job (if
        // any) to drain, then enqueues the flush marker.
        if self.sender.send(Job::Flush(notify_send)).is_err() {
            // Worker is gone; nothing to flush.
            return;
        }
        notify_recv
            .recv()
            .expect("worker thread exited while flushing");
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
        // never blocked: with a single-slot channel, the surplus must be
        // dropped via the `skipped` counter rather than queued. We only
        // assert that the loop completes promptly and that `skipped + processed`
        // accounts for all the workloads we attempted.
        const N: u64 = 1_000;

        let completed = Arc::new(AtomicU64::new(0));
        let skipped = skipped_counter();

        let worker_thread = WorkerThread::new("test_worker_thread_skip", skipped.clone());
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
