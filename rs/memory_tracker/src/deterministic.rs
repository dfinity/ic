//! The deterministic memory tracker handles a missing page signal
//! by mapping the chunk of pages surrounding the faulting page into
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
use ic_sys::{OS_PAGES_IN_CHUNK, PAGE_SIZE, PageIndex};
use ic_types::{NumBytes, NumOsPages};
use nix::sys::mman::{ProtFlags, mprotect};
use phantom_newtype::Id;

use crate::{
    AccessKind, DirtyPageTracking, SigsegvMemoryTracker, map_unaccessed_pages, print_enomem_help,
    range_size_in_bytes,
};

pub struct ChunkIndexTag;
/// Zero-based index of a page chunk. The chunk size is defined by
/// `OS_PAGES_IN_CHUNK`.
pub type ChunkIndex = Id<ChunkIndexTag, u64>;

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

/// Fast non-cryptographic hash function based on FxHash.
/// This is used to compute a digest of accessed and dirty chunks.
/// The order of operations is not important.
#[inline]
fn hash(value: u64) -> u64 {
    const K: u64 = 0x517cc1b727220a95;
    value.rotate_left(5).bitxor(value).wrapping_mul(K)
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
    /// The number of times write-protection was applied to a chunk.
    protect_write: u64,
    /// The number of times unaccessed pages were mapped.
    map_unaccessed_pages: u64,
    /// The number of times `mprotect` was called.
    mprotect: u64,
}

/// Deterministic memory tracker state.
pub struct DeterministicState {
    /// Bitmap of accessed chunks.
    accessed_chunks_bitmap: BitVec,
    /// A list of accessed chunks.
    /// The order of chunks is non-deterministic, so this list must be
    /// sorted before use.
    ///
    /// WARNING: If the accessed page limit is reached, the list may be
    /// incomplete and should not be used.
    accessed_chunks_list: Vec<ChunkIndex>,
    /// Number of accessed chunks.
    accessed_chunks_count: u64,
    /// A digest of accessed chunks, which can be used to check for
    /// deterministic memory access across different replicas.
    accessed_chunks_digest: u64,

    /// Bitmap of dirty chunks (used only when tracking dirty pages).
    dirty_chunks_bitmap: BitVec,
    /// A list of dirty chunks (used only when tracking dirty pages).
    /// The order of chunks is non-deterministic, so this list must be
    /// sorted before use.
    ///
    /// WARNING: If the accessed page limit is reached, the list may be
    /// incomplete and should not be used.
    dirty_chunks_list: Vec<ChunkIndex>,
    /// Number of dirty chunks.
    dirty_chunks_count: u64,
    /// A digest of dirty chunks, which can be used to check for
    /// deterministic memory writes across different replicas.
    dirty_chunks_digest: u64,

    /// Non-deterministic metrics.
    non_deterministic_metrics: NonDeterministicMetrics,
}

impl DeterministicState {
    /// Creates a new `DeterministicState` for tracking memory accesses
    /// over the specified number of OS pages.
    pub(crate) fn new(num_pages: NumOsPages, memory_limits: MemoryLimits) -> DeterministicState {
        let MemoryLimits {
            max_memory_size,
            max_accessed_pages,
            max_dirty_pages,
        } = memory_limits;
        let num_chunks = num_pages.get() / OS_PAGES_IN_CHUNK;
        assert_eq!(
            num_chunks * OS_PAGES_IN_CHUNK,
            num_pages.get(),
            "Number of pages {num_pages} must be a multiple of chunk size {OS_PAGES_IN_CHUNK}"
        );

        let max_memory_chunks =
            max_memory_size.get() as usize / PAGE_SIZE / OS_PAGES_IN_CHUNK as usize;
        let max_accessed_chunks = (max_accessed_pages.get() / OS_PAGES_IN_CHUNK) as usize;
        let max_dirty_chunks = (max_dirty_pages.get() / OS_PAGES_IN_CHUNK) as usize;
        DeterministicState {
            accessed_chunks_bitmap: BitVec::from_elem(max_memory_chunks, false),
            accessed_chunks_list: Vec::with_capacity(max_accessed_chunks),
            accessed_chunks_count: 0,
            accessed_chunks_digest: 0,
            dirty_chunks_bitmap: BitVec::from_elem(max_memory_chunks, false),
            dirty_chunks_list: Vec::with_capacity(max_dirty_chunks),
            dirty_chunks_count: 0,
            dirty_chunks_digest: 0,
            non_deterministic_metrics: NonDeterministicMetrics::default(),
        }
    }

    /// Marks specified chunk as accessed.
    fn mark_accessed_chunk(&mut self, chunk_idx: ChunkIndex) {
        self.accessed_chunks_count += 1;
        self.accessed_chunks_bitmap
            .set(chunk_idx.get() as usize, true);
        self.accessed_chunks_digest ^= hash(chunk_idx.get());

        debug_assert!(self.accessed_chunks_list.len() <= self.accessed_chunks_list.capacity());
        if self.accessed_chunks_list.len() <= self.accessed_chunks_list.capacity() {
            self.accessed_chunks_list.push(chunk_idx);
        }
    }

    /// Returns true if specified chunk is marked as accessed.
    fn is_chunk_accessed(&self, chunk_idx: ChunkIndex) -> bool {
        self.accessed_chunks_bitmap
            .get(chunk_idx.get() as usize)
            .unwrap_or(false)
    }

    /// Marks specified chunk as dirty.
    fn mark_dirty_chunk(&mut self, chunk_idx: ChunkIndex) {
        self.dirty_chunks_count += 1;
        self.dirty_chunks_bitmap.set(chunk_idx.get() as usize, true);
        self.dirty_chunks_digest ^= hash(chunk_idx.get());

        debug_assert!(self.dirty_chunks_list.len() <= self.dirty_chunks_list.capacity());
        if self.dirty_chunks_list.len() <= self.dirty_chunks_list.capacity() {
            self.dirty_chunks_list.push(chunk_idx);
        }
    }

    /// Tries to write-protect an accessed chunk. Returns true if successful.
    fn try_write_protect_chunk(
        &mut self,
        tracker: &SigsegvMemoryTracker,
        chunk_idx: ChunkIndex,
    ) -> bool {
        if !self.is_chunk_accessed(chunk_idx) {
            return false;
        }

        let page_range = range_from(chunk_idx);
        let page_start_addr = tracker.page_start_addr_from(page_range.start);

        // SAFETY: We just checked that the chunk was accessed (mapped), so it must be valid.
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

    /// Handles missing chunk of pages by mapping it into the process address space
    /// with specified protection flags.
    fn map_chunk_as(
        &mut self,
        tracker: &SigsegvMemoryTracker,
        chunk_idx: ChunkIndex,
        prot: ProtFlags,
    ) {
        let page_range = range_from(chunk_idx);
        let mapped_range =
            map_unaccessed_pages(tracker, prot, page_range.clone(), page_range.clone());
        debug_assert_eq!(page_range, mapped_range);
        self.non_deterministic_metrics.map_unaccessed_pages += 1;
    }
}

/// A missing page handler that provides deterministic prefetching behavior
/// and works on all platforms.
pub fn handle_missing_page(
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

    let faulting_page_idx = tracker.page_index_from(faulting_address);
    let faulting_chunk_idx = chunk_idx_from(faulting_page_idx);

    const READ: ProtFlags = ProtFlags::PROT_READ;
    const WRITE: ProtFlags = ProtFlags::PROT_WRITE;

    match (access_kind, tracker.dirty_page_tracking) {
        (_, DirtyPageTracking::Ignore) => {
            state.map_chunk_as(tracker, faulting_chunk_idx, READ | WRITE);
            state.non_deterministic_metrics.map_ignoring += 1;
            // When ignoring dirty pages, we only report accessed pages.
            state.mark_accessed_chunk(faulting_chunk_idx);
        }
        (Some(AccessKind::Read), DirtyPageTracking::Track) => {
            state.map_chunk_as(tracker, faulting_chunk_idx, READ);
            state.non_deterministic_metrics.map_read += 1;
            state.mark_accessed_chunk(faulting_chunk_idx);
        }
        (Some(AccessKind::Write), DirtyPageTracking::Track) => {
            if state.try_write_protect_chunk(tracker, faulting_chunk_idx) {
                state.non_deterministic_metrics.protect_write += 1;
                state.mark_dirty_chunk(faulting_chunk_idx);
            } else {
                state.map_chunk_as(tracker, faulting_chunk_idx, READ | WRITE);
                state.non_deterministic_metrics.map_read_write += 1;
                state.mark_accessed_chunk(faulting_chunk_idx);
                state.mark_dirty_chunk(faulting_chunk_idx);
            }
        }
        (None, DirtyPageTracking::Track) => {
            if state.try_write_protect_chunk(tracker, faulting_chunk_idx) {
                state.non_deterministic_metrics.protect_write += 1;
                state.mark_dirty_chunk(faulting_chunk_idx);
            } else {
                state.map_chunk_as(tracker, faulting_chunk_idx, READ);
                state.non_deterministic_metrics.map_read += 1;
                state.mark_accessed_chunk(faulting_chunk_idx);
            }
        }
    }
    true
}

/// Returns a deterministic number of accessed pages.
pub fn num_accessed_pages(tracker: &SigsegvMemoryTracker) -> usize {
    // SAFETY: The caller must ensure that the tracker has a deterministic state.
    let state = &mut *tracker.deterministic_state.as_ref().unwrap().borrow_mut();
    (state.accessed_chunks_count * OS_PAGES_IN_CHUNK) as usize
}

/// Returns a deterministic
pub fn take_dirty_pages(tracker: &SigsegvMemoryTracker) -> Vec<PageIndex> {
    // SAFETY: The caller must ensure that the tracker has a deterministic state.
    let state = &mut *tracker.deterministic_state.as_ref().unwrap().borrow_mut();
    debug_assert!(state.dirty_chunks_list.len() <= state.dirty_chunks_list.capacity());
    state.dirty_chunks_list.sort_unstable();
    let chunks = std::mem::take(&mut state.dirty_chunks_list);
    chunks
        .into_iter()
        .flat_map(|chunk_idx| {
            let start = chunk_idx.get() * OS_PAGES_IN_CHUNK;
            let end = (chunk_idx.get() + 1) * OS_PAGES_IN_CHUNK;
            start..end
        })
        .map(PageIndex::new)
        .collect()
}

/// Returns a range of pages that make up the chunk containing the given page.
fn chunk_idx_from(page: PageIndex) -> ChunkIndex {
    ChunkIndex::new(page.get() / OS_PAGES_IN_CHUNK)
}

/// Returns a range of pages that make up the chunk containing the given page.
fn range_from(chunk_idx: ChunkIndex) -> Range<PageIndex> {
    let start = chunk_idx.get() * OS_PAGES_IN_CHUNK;
    PageIndex::new(start)..PageIndex::new(start + OS_PAGES_IN_CHUNK)
}

#[cfg(test)]
mod tests {
    use ic_sys::{OS_PAGES_IN_CHUNK, PageIndex};

    use crate::deterministic::{chunk_idx_from, range_from};

    #[test]
    fn range_from_chunk_idx_from_page_index_works() {
        for i in 0..OS_PAGES_IN_CHUNK {
            let chunk_idx = chunk_idx_from(PageIndex::new(i));
            assert_eq!(
                range_from(chunk_idx),
                PageIndex::new(0)..PageIndex::new(OS_PAGES_IN_CHUNK)
            );
        }
        let chunk_idx = chunk_idx_from(PageIndex::new(OS_PAGES_IN_CHUNK));
        assert_eq!(
            range_from(chunk_idx),
            PageIndex::new(OS_PAGES_IN_CHUNK)..PageIndex::new(OS_PAGES_IN_CHUNK * 2)
        );
    }
}
