//! The accessed page limit of the Wasm heap as seen by host functions.
//!
//! Plain Wasm loads and stores are limited by the deterministic memory
//! tracker, which refuses to map the first page beyond the limit. Host
//! functions must not fault on such a page, so every heap range they touch is
//! checked here first, through [`Heap`](ic_interfaces::execution_environment::Heap).

use std::ops::Range;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use ic_config::embedders::MemoryPageLimit;
use ic_interfaces::execution_environment::{HeapAccessCheck, HypervisorError, HypervisorResult};
use ic_sys::PAGE_SIZE;
use ic_types::NumOsPages;
use memory_tracker::{DeterministicMemoryTracker, signal_mutex::SignalMutex};

/// Checks host accesses to the Wasm heap against the accessed page limit of
/// the heap memory tracker.
pub struct TrackerHeapAccess {
    /// The heap memory tracker, `None` before the trackers are installed.
    tracker: Option<Arc<SignalMutex<DeterministicMemoryTracker>>>,
    /// Shared with the tracker: set once any access was refused because of
    /// the limit, by the tracker or by this check.
    page_limit_exceeded: Arc<AtomicBool>,
    /// The configured limits, for the error message.
    limits: MemoryPageLimit,
}

impl TrackerHeapAccess {
    /// A check that lets every access pass. Used until the heap memory
    /// tracker exists.
    pub fn inactive(limits: MemoryPageLimit) -> Self {
        Self {
            tracker: None,
            page_limit_exceeded: Arc::new(AtomicBool::new(false)),
            limits,
        }
    }

    /// A check against the specified heap memory tracker.
    pub fn new(
        tracker: Arc<SignalMutex<DeterministicMemoryTracker>>,
        limits: MemoryPageLimit,
    ) -> Self {
        let page_limit_exceeded = tracker.lock().page_limit_exceeded_flag().clone();
        Self {
            tracker: Some(tracker),
            page_limit_exceeded,
            limits,
        }
    }

    /// Returns true if any heap access was refused because of the limit
    /// during this execution. Does not lock the tracker.
    pub fn page_limit_exceeded(&self) -> bool {
        self.page_limit_exceeded.load(Ordering::Relaxed)
    }

    /// The error reported when the limit is exceeded.
    pub fn limit_exceeded_error(&self) -> HypervisorError {
        const KIB: u64 = 1024;
        let kib = |pages: NumOsPages| pages.get() * (PAGE_SIZE as u64 / KIB);
        HypervisorError::MemoryAccessLimitExceeded(format!(
            "Exceeded the limit for the number of accessed pages in the Wasm \
            heap in a single message execution: limit {} KB for regular \
            messages, {} KB for upgrade messages and {} KB for queries.",
            kib(self.limits.message),
            kib(self.limits.upgrade),
            kib(self.limits.query),
        ))
    }
}

impl HeapAccessCheck for TrackerHeapAccess {
    fn check(&self, range: Range<usize>) -> HypervisorResult<()> {
        if range.is_empty() {
            return Ok(());
        }
        let Some(tracker) = &self.tracker else {
            return Ok(());
        };
        // Host functions run on the Wasm thread while no signal is being
        // handled, so the lock is uncontended. Only the bitmap is consulted
        // under the lock; no heap memory is touched.
        let fits = tracker
            .lock()
            .check_range_fits(range.start as u64..range.end as u64);
        if fits {
            Ok(())
        } else {
            self.page_limit_exceeded.store(true, Ordering::Relaxed);
            Err(self.limit_exceeded_error())
        }
    }
}
