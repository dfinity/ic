use crate::JoinOnDrop;
use crossbeam_channel::{Sender, bounded, unbounded};
use std::time::Duration;

/// An object to be deallocated in the background.
type Deallocation = Box<dyn std::any::Any + Send + 'static>;

/// A helper struct that notifies when it's deallocated.
struct NotifyWhenDeallocated {
    channel: Sender<()>,
}

impl Drop for NotifyWhenDeallocated {
    fn drop(&mut self) {
        self.channel
            .send(())
            .expect("Failed to notify deallocation");
    }
}

// We will not use the deallocation thread when the number of pending
// deallocation objects goes above the threshold.
const DEALLOCATION_BACKLOG_THRESHOLD: usize = 500;

/// A thread that deallocates complex objects in the background. It spreads the
/// cost of deallocation over a longer period of time, to avoid long pauses.
pub struct DeallocatorThread {
    deallocation_sender: DeallocationSender,
    _deallocation_handle: JoinOnDrop<()>,
}

impl DeallocatorThread {
    pub fn new(name: &str, sleep_between_drops: Duration) -> Self {
        #[allow(clippy::disallowed_methods)]
        let (sender, receiver) = unbounded();
        let deallocation_sender = DeallocationSender { sender };
        let _deallocation_handle = JoinOnDrop::new(
            std::thread::Builder::new()
                .name(name.to_string())
                .spawn({
                    move || {
                        while let Ok(object) = receiver.recv() {
                            std::mem::drop(object);
                            // Sleep, to spread out the load on the memory allocator.
                            std::thread::sleep(sleep_between_drops);
                        }
                    }
                })
                .expect("failed to spawn background deallocation thread"),
        );

        Self {
            deallocation_sender,
            _deallocation_handle,
        }
    }

    /// Returns a reference to the sender to the deallocation thread.
    pub fn sender(&self) -> &DeallocationSender {
        &self.deallocation_sender
    }

    /// Sends an object to be deallocated in the background, iff the backlog is
    /// under the threshold; else, drops the object directly.
    pub fn send(&self, obj: Deallocation) {
        self.deallocation_sender.send(obj);
    }

    /// Wait until deallocation queue is empty.
    ///
    /// Used in tests to wait for all deallocations to complete.
    #[doc(hidden)]
    pub fn flush_deallocation_channel(&self) {
        let (send, recv) = bounded(1);
        self.deallocation_sender
            .sender
            .send(Box::new(NotifyWhenDeallocated { channel: send }))
            .expect("failed to send object to deallocation thread");
        recv.recv()
            .expect("Failed to receive deallocation notification");
    }
}

/// A cheaply cloneable sender to a `DeallocatorThread`.
#[derive(Clone)]
pub struct DeallocationSender {
    sender: Sender<Deallocation>,
}

impl DeallocationSender {
    /// Sends an object to be deallocated in the background, iff the backlog is
    /// under the threshold; else, drops the object directly.
    pub fn send(&self, obj: Deallocation) {
        if self.sender.len() < DEALLOCATION_BACKLOG_THRESHOLD {
            self.sender
                .send(obj)
                .expect("failed to send object to deallocation thread");
        } else {
            std::mem::drop(obj);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    /// A struct that increments one of two counters on drop, depending on whether
    /// it's dropped on the same thread or not. And can wait on an optional barrier
    /// before proceeding with the drop.
    struct IncrementOnDrop {
        dropped_on_same_thread: Arc<AtomicUsize>,
        dropped_on_other_thread: Arc<AtomicUsize>,
        thread_id: std::thread::ThreadId,
        barrier: Option<Arc<std::sync::Barrier>>,
    }

    impl Drop for IncrementOnDrop {
        fn drop(&mut self) {
            if std::thread::current().id() != self.thread_id {
                // Drop by `DeallocatorThread`.
                if let Some(barrier) = &self.barrier {
                    barrier.wait();
                }

                self.dropped_on_other_thread.fetch_add(1, Ordering::Relaxed);
            } else {
                // Synchronous drop.
                self.dropped_on_same_thread.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Deallocate `N` objects via `DeallocatorThread::send()`.
    #[test]
    fn test_deallocator_thread() {
        const N: usize = 100;

        let deallocator =
            DeallocatorThread::new("test_deallocator_thread", Duration::from_millis(0));

        let dropped_on_same_thread = Arc::new(AtomicUsize::new(0));
        let dropped_on_other_thread = Arc::new(AtomicUsize::new(0));

        for _ in 0..N {
            let deallocation = Box::new(IncrementOnDrop {
                dropped_on_same_thread: dropped_on_same_thread.clone(),
                dropped_on_other_thread: dropped_on_other_thread.clone(),
                thread_id: std::thread::current().id(),
                barrier: None,
            });
            deallocator.send(deallocation);
        }
        deallocator.flush_deallocation_channel();

        // All objects were dropped.
        assert_eq!(
            N,
            dropped_on_same_thread.load(Ordering::Relaxed)
                + dropped_on_other_thread.load(Ordering::Relaxed)
        );
    }

    /// Deallocate `N` objects via `DeallocationSender::send()`.
    #[test]
    fn test_deallocation_sender() {
        const N: usize = 100;

        let deallocator =
            DeallocatorThread::new("test_deallocation_sender", Duration::from_millis(0));
        let sender = deallocator.sender();

        let dropped_on_same_thread = Arc::new(AtomicUsize::new(0));
        let dropped_on_other_thread = Arc::new(AtomicUsize::new(0));

        for _ in 0..N {
            let deallocation = Box::new(IncrementOnDrop {
                dropped_on_same_thread: dropped_on_same_thread.clone(),
                dropped_on_other_thread: dropped_on_other_thread.clone(),
                thread_id: std::thread::current().id(),
                barrier: None,
            });
            sender.send(deallocation);
        }
        deallocator.flush_deallocation_channel();

        // All objects were dropped.
        assert_eq!(
            N,
            dropped_on_same_thread.load(Ordering::Relaxed)
                + dropped_on_other_thread.load(Ordering::Relaxed)
        );
    }

    /// Test synchronous deallocation beyond `DEALLOCATION_BACKLOG_THRESHOLD`:
    /// enqueue `2 * DEALLOCATION_BACKLOG_THRESHOLD` objects for deallocation,
    /// blocking the first half on the deallocation thread until the second half
    /// have been dropped synchronously.
    #[test]
    fn test_synchronous_deallocation() {
        let deallocator =
            DeallocatorThread::new("test_synchronous_deallocation", Duration::from_millis(0));

        let dropped_on_same_thread = Arc::new(AtomicUsize::new(0));
        let dropped_on_other_thread = Arc::new(AtomicUsize::new(0));

        // We only have 2 threads, unblock the `DeallocatorThread` one drop at a time.
        let barrier = Arc::new(std::sync::Barrier::new(2));

        for _ in 0..2 * DEALLOCATION_BACKLOG_THRESHOLD {
            let deallocation = Box::new(IncrementOnDrop {
                dropped_on_same_thread: dropped_on_same_thread.clone(),
                dropped_on_other_thread: dropped_on_other_thread.clone(),
                thread_id: std::thread::current().id(),
                barrier: Some(barrier.clone()),
            });
            deallocator.send(deallocation);
        }

        // There are `DEALLOCATION_BACKLOG_THRESHOLD` objects enqueued in
        // `DeallocatorThread`'s channel. Plus, potentially, one object that has already
        // been picked up. Meaning that either `DEALLOCATION_BACKLOG_THRESHOLD` or
        // `DEALLOCATION_BACKLOG_THRESHOLD - 1` objects have been dropped synchronously.
        let deallocated_synchronously = dropped_on_same_thread.load(Ordering::Relaxed);
        assert!(
            deallocated_synchronously == DEALLOCATION_BACKLOG_THRESHOLD
                || deallocated_synchronously == DEALLOCATION_BACKLOG_THRESHOLD - 1
        );

        // Unblock dropping the first half.
        let to_be_deallocated_asynchronously =
            2 * DEALLOCATION_BACKLOG_THRESHOLD - deallocated_synchronously;
        for _ in 0..to_be_deallocated_asynchronously {
            barrier.wait();
        }
        deallocator.flush_deallocation_channel();

        assert_eq!(
            (deallocated_synchronously, to_be_deallocated_asynchronously),
            (
                dropped_on_same_thread.load(Ordering::Relaxed),
                dropped_on_other_thread.load(Ordering::Relaxed)
            )
        );
    }

    /// Deallocate `N` objects (with `N <= DEALLOCATION_BACKLOG_THRESHOLD`) with a
    /// non-zero `sleep_between_drops` to make it likely that they won't all be
    /// dropped before flushing. Then flush and check the elapsed time and that all
    /// objects were dropped by the `DeallocatorThread`.
    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_flush_deallocation_channel() {
        const N: usize = 100;
        assert!(N <= DEALLOCATION_BACKLOG_THRESHOLD);

        let sleep_between_drops = Duration::from_millis(100) / N as u32;
        let deallocator =
            DeallocatorThread::new("test_flush_deallocation_channel", sleep_between_drops);

        let dropped_on_same_thread = Arc::new(AtomicUsize::new(0));
        let dropped_on_other_thread = Arc::new(AtomicUsize::new(0));

        let start = Instant::now();
        for _ in 0..N {
            let deallocation = Box::new(IncrementOnDrop {
                dropped_on_same_thread: dropped_on_same_thread.clone(),
                dropped_on_other_thread: dropped_on_other_thread.clone(),
                thread_id: std::thread::current().id(),
                barrier: None,
            });
            deallocator.send(deallocation);
        }
        deallocator.flush_deallocation_channel();

        // We have slept at least `DEALLOCATION_BACKLOG_THRESHOLD` times.
        assert!(start.elapsed() > sleep_between_drops * N as u32);

        // All objects were dropped by the `DeallocatorThread`.
        assert_eq!(
            (0, N),
            (
                dropped_on_same_thread.load(Ordering::Relaxed),
                dropped_on_other_thread.load(Ordering::Relaxed)
            )
        );
    }
}
