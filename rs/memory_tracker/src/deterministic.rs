//! The deterministic memory tracker handles a missing OS page signal
//! by mapping the Wasm page surrounding the faulting OS page into
//! the program's address space. The data for these pages is sourced
//! from the `PageMap`.
//!
//! The missing page signal is currently delivered via a signal handler
//! (`SIGSEGV` or `SIGBUS`), but in the future, it may be delivered
//! through `userfaultfd`.
//!
//! ## Assumptions
//!
//! 1. The majority of memory accesses are reads.
//! 2. Memory accesses are typically clustered.
//! 3. Signals may be delivered in a non-deterministic order, but the
//!    final result remains deterministic.
//!
//! ## Access Type Handling
//!
//! The tracker's behavior adapts based on platform capabilities:
//!
//! 1. If `AccessKind` is available, it is used to optimize the handling
//!    of write accesses.
//! 2. If `AccessKind` is not available, the tracker heuristically assumes
//!    the first access to a page is a read and any subsequent access
//!    is a write.
//!
//! ## Operating Modes
//!
//! The tracker works in two modes:
//!
//! 1. Ignoring dirty pages: Tracks accessed pages without recording
//!    modifications (queries).
//! 2. Tracking dirty pages: Tracks both accessed and modified (dirty) pages (updates).
//!
//! ## Deterministic Results
//!
//! The result of memory tracking is always deterministic:
//!
//! 1. Ignoring dirty pages: Returns a deterministic count of accessed pages.
//! 2. Tracking dirty pages: Returns a deterministic list of accessed
//!    and dirty pages.
//!
//! Additionally, the tracker provides a digest of the accessed and dirty
//! pages, which can be used to verify that the same pages were accessed
//! across different replicas.

use std::ops::{BitXor, Range};

use bit_vec::BitVec;
use ic_replicated_state::{NumWasmPages, canister_state::WASM_PAGE_SIZE_IN_BYTES};
use ic_sys::PageIndex;
use ic_types::{NumBytes, NumOsPages};
use nix::sys::mman::{ProtFlags, mprotect};

use crate::{
    AccessKind, DirtyPageTracking, SigsegvMemoryTracker, map_unaccessed_pages, print_enomem_help,
    range_size_in_bytes,
};

mod conversions;
use conversions::{
    FromNumBytes, FromNumOsPages, FromNumWasmPages, FromPageIndex, FromWasmPageIndex, WasmPageIndex,
};

/// Memory limits for the deterministic memory tracker.
#[derive(Clone)]
pub struct MemoryLimits {
    pub max_memory_size: NumBytes,
    pub max_accessed_pages: NumOsPages,
    pub max_dirty_pages: NumOsPages,
}

/// Specifies the kind of handler for missing pages.
#[derive(Clone, Copy)]
pub enum MissingPageHandlerKind {
    /// The legacy `old` handler, which does not prefetch pages or use
    /// `AccessKind` information.
    Old,
    /// The `new` handler, which leverages `AccessKind` and prefetching
    /// for improved performance.
    New,
    /// A handler that provides deterministic prefetching behavior
    /// and works on all platforms.
    Deterministic,
}

/// Metrics may vary due to non-deterministic signal delivery.
#[derive(Default)]
struct NonDeterministicMetrics {
    /// The number of memory area misses.
    memory_miss: u64,
    /// The number of memory area hits.
    memory_hit: u64,
    /// The number of times pages were mapped ignoring dirty pages.
    map_ignoring: u64,
    /// The number of times pages were mapped as read-only.
    map_read: u64,
    /// The number of times pages were mapped as read-write.
    map_read_write: u64,
    /// The number of times write-protection was applied.
    protect_write: u64,
    /// The number of times unaccessed pages were mapped.
    map_unaccessed_pages: u64,
    /// The number of times `mprotect` was called.
    mprotect: u64,
}

/// A digest of Wasm page indexes, which can be used to check for
/// deterministic memory access across different replicas.
pub struct WasmPageIndexDigest {
    pub digest: u64,
}

impl WasmPageIndexDigest {
    /// Creates a new `WasmPageIndexDigest` for tracking memory accesses.
    pub fn new(seed: u64) -> Self {
        WasmPageIndexDigest { digest: seed }
    }

    /// Returns an accumulated digest.
    pub fn get(&self) -> u64 {
        self.digest
    }

    /// Adds a Wasm page index to the digest using a fast non-cryptographic
    /// hash function based on FxHash.
    /// The order of operations is not important.
    #[inline]
    pub fn hash(&mut self, wasm_page_index: WasmPageIndex) {
        let value = wasm_page_index.get();
        const K: u64 = 0x517cc1b727220a95;
        let digest = value.rotate_left(5).bitxor(value).wrapping_mul(K);
        self.digest ^= digest;
    }
}

/// Deterministic memory tracker state.
pub struct DeterministicState {
    /// Bitmap of accessed Wasm pages.
    accessed_wasm_pages_bitmap: BitVec,
    /// A list of accessed Wasm pages.
    /// The order of Wasm pages is non-deterministic, so this list must
    /// be sorted before use.
    ///
    /// WARNING: If the accessed page limit is reached, the list may be
    /// incomplete and should not be used.
    accessed_wasm_pages_list: Vec<WasmPageIndex>,
    /// Number of accessed Wasm pages.
    accessed_wasm_pages_count: NumWasmPages,
    /// A digest of accessed Wasm pages, which can be used to check for
    /// deterministic memory access across different replicas.
    accessed_wasm_pages_digest: WasmPageIndexDigest,

    /// Bitmap of dirty Wasm pages (used only when tracking dirty pages).
    dirty_wasm_pages_bitmap: BitVec,
    /// A list of dirty Wasm pages (used only when tracking dirty pages).
    /// The order of Wasm pages is non-deterministic, so this list must
    /// be sorted before use.
    ///
    /// WARNING: If the accessed page limit is reached, the list may be
    /// incomplete and should not be used.
    dirty_wasm_pages_list: Vec<WasmPageIndex>,
    /// Number of dirty Wasm pages.
    dirty_wasm_pages_count: NumWasmPages,
    /// A digest of dirty Wasm pages, which can be used to check for
    /// deterministic memory writes across different replicas.
    dirty_wasm_pages_digest: WasmPageIndexDigest,

    /// Non-deterministic metrics.
    non_deterministic_metrics: NonDeterministicMetrics,
}

/// Prints the digest when dropped (for debugging purposes).
impl Drop for DeterministicState {
    fn drop(&mut self) {
        println!(
            "XXX accessed_wasm_pages_digest:{} dirty_wasm_pages_digest:{}",
            self.accessed_wasm_pages_digest.get(),
            self.dirty_wasm_pages_digest.get()
        );
    }
}

impl DeterministicState {
    /// Creates a new `DeterministicState` for tracking memory accesses
    /// over the specified number of OS pages.
    pub(crate) fn new(num_os_pages: NumOsPages, memory_limits: MemoryLimits) -> DeterministicState {
        let MemoryLimits {
            max_memory_size,
            max_accessed_pages,
            max_dirty_pages,
        } = memory_limits;

        let num_bytes = NumBytes::from_num_os_pages(num_os_pages);
        assert!(
            num_bytes <= max_memory_size,
            "Error checking the number of pages {num_os_pages} <= memory size {max_memory_size}"
        );
        assert_eq!(
            num_bytes.get() % WASM_PAGE_SIZE_IN_BYTES as u64,
            0,
            "Error asserting the number of pages {num_os_pages} is a multiple of Wasm page size"
        );

        let max_wasm_pages = NumWasmPages::from_num_bytes(max_memory_size);
        assert!(max_wasm_pages.get() > 0);
        let max_accessed_wasm_pages = NumWasmPages::from_num_os_pages(max_accessed_pages);
        let max_dirty_wasm_pages = NumWasmPages::from_num_os_pages(max_dirty_pages);

        DeterministicState {
            accessed_wasm_pages_bitmap: BitVec::from_elem(max_wasm_pages.get(), false),
            accessed_wasm_pages_list: Vec::with_capacity(max_accessed_wasm_pages.get()),
            accessed_wasm_pages_count: NumWasmPages::new(0),
            accessed_wasm_pages_digest: WasmPageIndexDigest::new(0),
            dirty_wasm_pages_bitmap: BitVec::from_elem(max_wasm_pages.get(), false),
            dirty_wasm_pages_list: Vec::with_capacity(max_dirty_wasm_pages.get()),
            dirty_wasm_pages_count: NumWasmPages::new(0),
            dirty_wasm_pages_digest: WasmPageIndexDigest::new(0),
            non_deterministic_metrics: NonDeterministicMetrics::default(),
        }
    }

    /// Marks specified Wasm page as accessed.
    fn mark_wasm_page_accessed(&mut self, wasm_page_idx: WasmPageIndex) {
        self.accessed_wasm_pages_count = self.accessed_wasm_pages_count.increment();
        self.accessed_wasm_pages_bitmap
            .set(wasm_page_idx.get() as usize, true);
        self.accessed_wasm_pages_digest.hash(wasm_page_idx);

        // Avoid growing the list beyond the limits set in capacity.
        if self.accessed_wasm_pages_list.len() < self.accessed_wasm_pages_list.capacity() {
            self.accessed_wasm_pages_list.push(wasm_page_idx);
        }
    }

    /// Returns true if specified Wasm page is marked as accessed.
    fn is_wasm_page_accessed(&self, wasm_page_idx: WasmPageIndex) -> bool {
        self.accessed_wasm_pages_bitmap
            .get(wasm_page_idx.get() as usize)
            .unwrap_or(false)
    }

    /// Marks specified Wasm page as dirty.
    fn mark_wasm_page_dirty(&mut self, wasm_page_idx: WasmPageIndex) {
        self.dirty_wasm_pages_count = self.dirty_wasm_pages_count.increment();
        self.dirty_wasm_pages_bitmap
            .set(wasm_page_idx.get() as usize, true);
        self.dirty_wasm_pages_digest.hash(wasm_page_idx);

        // Avoid growing the list beyond the limits set in capacity.
        if self.dirty_wasm_pages_list.len() < self.dirty_wasm_pages_list.capacity() {
            self.dirty_wasm_pages_list.push(wasm_page_idx);
        }
    }

    /// Tries to write-protect an accessed Wasm page. Returns true if successful.
    fn try_write_protect_wasm_page(
        &mut self,
        tracker: &SigsegvMemoryTracker,
        wasm_page_idx: WasmPageIndex,
    ) -> bool {
        if !self.is_wasm_page_accessed(wasm_page_idx) {
            return false;
        }

        let page_range = Range::from_wasm_page_idx(wasm_page_idx);
        let page_start_addr = tracker.page_start_addr_from(page_range.start);

        // SAFETY: We just checked that the Wasm page was accessed (mapped), so it must be valid.
        unsafe {
            mprotect(
                page_start_addr,
                range_size_in_bytes(&page_range),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            )
            .map_err(print_enomem_help)
            .unwrap()
        };
        self.non_deterministic_metrics.mprotect += 1;
        true
    }

    /// Handles missing Wasm page by mapping it into the process address space
    /// with specified protection flags.
    fn map_wasm_page_as(
        &mut self,
        tracker: &SigsegvMemoryTracker,
        wasm_page_idx: WasmPageIndex,
        prot: ProtFlags,
    ) {
        let page_range = Range::from_wasm_page_idx(wasm_page_idx);
        let mapped_range =
            map_unaccessed_pages(tracker, prot, page_range.clone(), page_range.clone());
        debug_assert_eq!(page_range, mapped_range);
        self.non_deterministic_metrics.map_unaccessed_pages += 1;
    }
}

/// A missing OS page handler that provides deterministic prefetching behavior
/// and works on all platforms.
pub fn handle_missing_os_page(
    tracker: &SigsegvMemoryTracker,
    access_kind: Option<AccessKind>,
    faulting_address: *mut libc::c_void,
) -> bool {
    // SAFETY: The caller must ensure that the tracker has a deterministic state.
    let state = &mut *tracker.deterministic_state.as_ref().unwrap().borrow_mut();
    if !tracker.memory_area.contains(faulting_address) {
        state.non_deterministic_metrics.memory_miss += 1;
        // This memory tracker is not responsible for handling this address.
        return false;
    };
    state.non_deterministic_metrics.memory_hit += 1;

    let faulting_os_page_idx = tracker.page_index_from(faulting_address);
    let faulting_wasm_page_idx = WasmPageIndex::from_os_page_idx(faulting_os_page_idx);

    const READ: ProtFlags = ProtFlags::PROT_READ;
    const WRITE: ProtFlags = ProtFlags::PROT_WRITE;

    match (access_kind, tracker.dirty_page_tracking) {
        (_, DirtyPageTracking::Ignore) => {
            state.map_wasm_page_as(tracker, faulting_wasm_page_idx, READ | WRITE);
            state.non_deterministic_metrics.map_ignoring += 1;
            // When ignoring dirty pages, we only report accessed pages.
            state.mark_wasm_page_accessed(faulting_wasm_page_idx);
        }
        (Some(AccessKind::Read), DirtyPageTracking::Track) => {
            state.map_wasm_page_as(tracker, faulting_wasm_page_idx, READ);
            state.non_deterministic_metrics.map_read += 1;
            state.mark_wasm_page_accessed(faulting_wasm_page_idx);
        }
        (Some(AccessKind::Write), DirtyPageTracking::Track) => {
            if state.try_write_protect_wasm_page(tracker, faulting_wasm_page_idx) {
                state.non_deterministic_metrics.protect_write += 1;
                state.mark_wasm_page_dirty(faulting_wasm_page_idx);
            } else {
                state.map_wasm_page_as(tracker, faulting_wasm_page_idx, READ | WRITE);
                state.non_deterministic_metrics.map_read_write += 1;
                state.mark_wasm_page_accessed(faulting_wasm_page_idx);
                state.mark_wasm_page_dirty(faulting_wasm_page_idx);
            }
        }
        (None, DirtyPageTracking::Track) => {
            if state.try_write_protect_wasm_page(tracker, faulting_wasm_page_idx) {
                state.non_deterministic_metrics.protect_write += 1;
                state.mark_wasm_page_dirty(faulting_wasm_page_idx);
            } else {
                state.map_wasm_page_as(tracker, faulting_wasm_page_idx, READ);
                state.non_deterministic_metrics.map_read += 1;
                state.mark_wasm_page_accessed(faulting_wasm_page_idx);
            }
        }
    }
    true
}

/// Returns a deterministic number of accessed OS pages.
pub fn num_accessed_os_pages(tracker: &SigsegvMemoryTracker) -> NumOsPages {
    // SAFETY: The caller must ensure that the tracker has a deterministic state.
    let state = &mut *tracker.deterministic_state.as_ref().unwrap().borrow_mut();
    NumOsPages::from_num_wasm_pages(state.accessed_wasm_pages_count)
}

/// Returns a deterministic list of dirty OS pages.
pub fn take_dirty_os_pages(tracker: &SigsegvMemoryTracker) -> Vec<PageIndex> {
    // SAFETY: The caller must ensure that the tracker has a deterministic state.
    let state = &mut *tracker.deterministic_state.as_ref().unwrap().borrow_mut();

    state.dirty_wasm_pages_list.sort_unstable();
    let res = state
        .dirty_wasm_pages_list
        .iter()
        .flat_map(|wasm_page_idx| {
            let start_os_page_idx = PageIndex::from_wasm_page_idx(*wasm_page_idx);
            let end_wasm_page_idx = WasmPageIndex::new(wasm_page_idx.get() + 1);
            let end_os_page_idx = PageIndex::from_wasm_page_idx(end_wasm_page_idx);

            start_os_page_idx.get()..end_os_page_idx.get()
        })
        .map(PageIndex::new)
        .collect();
    // Unlike std::mem::take, this keeps the original vector capacity.
    state.dirty_wasm_pages_list.clear();
    res
}
