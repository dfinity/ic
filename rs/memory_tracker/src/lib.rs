use bit_vec::BitVec;
use ic_logger::ReplicaLogger;
use ic_replicated_state::{
    PageIndex, PageMap,
    page_map::{FileDescriptor, MemoryInstructions},
};
use ic_sys::{PAGE_SIZE, PageBytes};
use ic_types::{NumBytes, NumOsPages};
use nix::{
    errno::Errno,
    sys::mman::{MapFlags, ProtFlags, mmap, mprotect},
};
use std::{
    cell::Cell,
    ops::Range,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    time::Duration,
};

mod prefetching;
#[cfg(test)]
mod tests;

pub use prefetching::PrefetchingMemoryTracker;
/// Only used for benchmarks.
pub use prefetching::basic_signal_handler;

/// Memory limits for the deterministic memory tracker.
#[derive(Clone, Copy, Default)]
pub struct MemoryLimits {
    pub max_memory_size: NumBytes,
    pub max_accessed_pages: NumOsPages,
    pub max_dirty_pages: NumOsPages,
}

/// Specifies whether the currently running message execution needs to know
/// which pages were dirtied or not. Dirty page tracking comes with a large
/// performance overhead.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum DirtyPageTracking {
    Ignore,
    Track,
}

/// Specifies whether the memory access that caused the signal was a read access
/// or a write access.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum AccessKind {
    Read,
    Write,
}

#[derive(Default)]
pub struct MemoryTrackerMetrics {
    read_before_write_count: AtomicUsize,
    direct_write_count: AtomicUsize,
    sigsegv_count: AtomicUsize,
    mmap_count: AtomicUsize,
    mprotect_count: AtomicUsize,
    copy_page_count: AtomicUsize,
    sigsegv_handler_duration_nanos: AtomicU64,
}

impl MemoryTrackerMetrics {
    pub fn read_before_write_count(&self) -> usize {
        self.read_before_write_count.load(Ordering::Relaxed)
    }

    pub fn direct_write_count(&self) -> usize {
        self.direct_write_count.load(Ordering::Relaxed)
    }

    pub fn sigsegv_count(&self) -> usize {
        self.sigsegv_count.load(Ordering::Relaxed)
    }

    pub fn mmap_count(&self) -> usize {
        self.mmap_count.load(Ordering::Relaxed)
    }

    pub fn mprotect_count(&self) -> usize {
        self.mprotect_count.load(Ordering::Relaxed)
    }

    pub fn copy_page_count(&self) -> usize {
        self.copy_page_count.load(Ordering::Relaxed)
    }

    pub fn sigsegv_handler_duration(&self) -> Duration {
        Duration::from_nanos(self.sigsegv_handler_duration_nanos.load(Ordering::Relaxed))
    }

    pub fn add_sigsegv_handler_duration(&self, elapsed: Duration) {
        let elapsed_nanos = elapsed.as_nanos() as u64;
        self.sigsegv_handler_duration_nanos
            .fetch_add(elapsed_nanos, Ordering::Relaxed);
    }
}

/// Represents a memory area: address + size. Address must be page-aligned and
/// size must be a multiple of PAGE_SIZE.
#[derive(Clone)]
pub struct MemoryArea {
    // Start address of the tracked memory area.
    start: usize,
    // Size of the tracked memory area in bytes.
    size: Cell<NumBytes>,
}

impl MemoryArea {
    fn new(start: *const libc::c_void, size: NumBytes) -> Self {
        let start = start as usize;
        assert!(start.is_multiple_of(PAGE_SIZE), "address is page-aligned");
        assert!(
            size.get().is_multiple_of(PAGE_SIZE as u64),
            "size is a multiple of page size"
        );
        let size = Cell::new(size);
        MemoryArea { start, size }
    }

    fn page_start_addr_from(&self, page_index: PageIndex) -> *mut libc::c_void {
        let page_start_addr = self.start + page_index.get() as usize * PAGE_SIZE;
        page_start_addr as *mut libc::c_void
    }

    fn page_index_from(&self, addr: *mut libc::c_void) -> PageIndex {
        let page_start_mask = !(PAGE_SIZE - 1);
        let page_start_addr = (addr as usize) & page_start_mask;

        let page_index = (page_start_addr - self.start) / PAGE_SIZE;
        PageIndex::new(page_index as u64)
    }

    pub fn start(&self) -> usize {
        self.start
    }

    pub fn size(&self) -> NumBytes {
        self.size.get()
    }

    #[inline]
    pub fn contains(&self, address: *const libc::c_void) -> bool {
        let a = address as usize;
        (self.start <= a) && (a < self.start + self.size.get().get() as usize)
    }
}

/// Bitmap tracking which pages on the memory were accessed during an execution.
struct PageBitmap {
    pages: BitVec,
    marked_count: NumOsPages,
}

impl PageBitmap {
    fn new(num_pages: NumOsPages) -> Self {
        Self {
            pages: BitVec::from_elem(num_pages.get() as usize, false),
            marked_count: 0.into(),
        }
    }

    fn grow(&mut self, delta_pages: NumOsPages) {
        self.pages.grow(delta_pages.get() as usize, false);
    }

    fn marked_count(&self) -> NumOsPages {
        self.marked_count
    }

    /// Indicates if the given page was accessed.
    pub fn is_marked(&self, page_idx: PageIndex) -> bool {
        self.pages.get(page_idx.get() as usize).unwrap_or(false)
    }

    fn mark(&mut self, page_idx: PageIndex) {
        self.pages.set(page_idx.get() as usize, true);
        self.marked_count.inc_assign();
    }

    fn mark_range(&mut self, range: &Range<PageIndex>) {
        let range = range.start.get()..range.end.get();
        for i in range {
            self.mark(PageIndex::new(i));
        }
    }

    /// Returns the largest range around the faulting page such that all pages there have
    /// not been marked yet.
    fn restrict_range_to_unmarked(
        &self,
        faulting_page: PageIndex,
        range: Range<PageIndex>,
    ) -> Range<PageIndex> {
        debug_assert!(
            range.contains(&faulting_page),
            "Error checking page:{faulting_page} ∈ range:{range:?}"
        );
        let range = range_intersection(&range, &self.page_range());

        let old_start = range.start.get();
        let mut start = faulting_page.get();
        while start > old_start {
            if self.pages.get(start as usize - 1).unwrap_or(true) {
                break;
            }
            start -= 1;
        }
        let old_end = range.end.get();
        let mut end = faulting_page.get();
        while end < old_end {
            if self.pages.get(end as usize).unwrap_or(true) {
                break;
            }
            end += 1;
        }

        PageIndex::new(start)..PageIndex::new(end)
    }

    /// Returns the largest range around the faulting page such that
    /// all pages there have been already marked.
    fn restrict_range_to_marked(
        &self,
        faulting_page: PageIndex,
        range: Range<PageIndex>,
    ) -> Range<PageIndex> {
        debug_assert!(
            range.contains(&faulting_page),
            "Error checking page:{faulting_page} ∈ range:{range:?}"
        );
        let range = range_intersection(&range, &self.page_range());

        let old_start = range.start.get();
        let mut start = faulting_page.get();
        while start > old_start {
            match self.pages.get(start as usize - 1) {
                None | Some(false) => break,
                Some(true) => {}
            }
            start -= 1;
        }
        let old_end = range.end.get();
        let mut end = faulting_page.get();
        while end < old_end {
            match self.pages.get(end as usize) {
                None | Some(false) => break,
                Some(true) => {}
            }
            end += 1;
        }
        PageIndex::new(start)..PageIndex::new(end)
    }

    /// Returns the range of pages that are predicted to be marked in the future
    /// based on the marked pages before the start of the given range or after the end.
    fn restrict_range_to_predicted(
        &self,
        faulting_page: PageIndex,
        range: Range<PageIndex>,
    ) -> Range<PageIndex> {
        debug_assert!(
            range.contains(&faulting_page),
            "Error checking page:{faulting_page} ∈ range:{range:?}"
        );
        let range = range_intersection(&range, &self.page_range());
        if range.is_empty() {
            return range;
        }

        let page = faulting_page.get();
        let start = range.start.get();
        let end = range.end.get();

        let mut bwd_predicted_count = 0;
        while page - bwd_predicted_count > start {
            if !self
                .pages
                .get((page + bwd_predicted_count + 1) as usize)
                .unwrap_or(false)
            {
                break;
            }
            bwd_predicted_count += 1;
        }

        let mut fwd_predicted_count = 1;
        while fwd_predicted_count < page && page + fwd_predicted_count < end {
            if !self
                .pages
                .get((page - fwd_predicted_count) as usize)
                .unwrap_or(false)
            {
                break;
            }
            fwd_predicted_count += 1;
        }

        PageIndex::new(page - bwd_predicted_count)..PageIndex::new(page + fwd_predicted_count)
    }

    fn page_range(&self) -> Range<PageIndex> {
        PageIndex::new(0)..PageIndex::new(self.pages.len() as u64)
    }
}

/// Memory tracker interface.
pub trait MemoryTracker {
    /// Creates a new memory tracker.
    fn new(
        start: *mut libc::c_void,
        size: NumBytes,
        log: ReplicaLogger,
        dirty_page_tracking: DirtyPageTracking,
        page_map: PageMap,
        memory_limits: MemoryLimits,
    ) -> nix::Result<Self>
    where
        Self: Sized;

    /// Handles missing page signal (SIGSEGV or SIGBUS).
    fn handle_sigsegv(
        &self,
        access_kind: Option<AccessKind>,
        fault_address: *mut libc::c_void,
    ) -> bool;

    /// Returns the memory area covered by the tracker.
    fn memory_area(&self) -> &MemoryArea;

    /// Expands the tracked memory area.
    fn expand(&self, delta: NumBytes);

    /// Returns a number of accessed pages.
    fn num_accessed_pages(&self) -> usize;

    /// Returns a list of accessed page indexes.
    fn take_accessed_pages(&self) -> Vec<PageIndex>;

    /// Returns a list of dirty page indexes.
    fn take_dirty_pages(&self) -> Vec<PageIndex>;

    /// Returns a list of speculatively dirty page indexes.
    fn take_speculatively_dirty_pages(&self) -> Vec<PageIndex>;

    /// Returns None if a speculatively dirty page was not modified.
    fn validate_speculatively_dirty_page(&self, page_idx: PageIndex) -> Option<PageIndex>;

    /// Returns `true` if a specified page was marked as accessed.
    fn is_accessed(&self, page_idx: PageIndex) -> bool;

    /// Returns a reference to the specified page map OS page content.
    fn get_page(&self, page_idx: PageIndex) -> &PageBytes;

    /// Return the associated metrics.
    fn metrics(&self) -> &MemoryTrackerMetrics;
}

/// Dynamic dispatch is used to minimize code changes.
/// Remove this dispatch mechanism once we have fully switched to
/// the deterministic memory tracker.
pub type SigsegvMemoryTracker = Box<dyn MemoryTracker + Send>;

pub fn new(
    start: *mut libc::c_void,
    size: NumBytes,
    log: ReplicaLogger,
    dirty_page_tracking: DirtyPageTracking,
    page_map: PageMap,
    memory_limits: MemoryLimits,
) -> nix::Result<SigsegvMemoryTracker> {
    Ok(Box::new(PrefetchingMemoryTracker::new(
        start,
        size,
        log,
        dirty_page_tracking,
        page_map,
        memory_limits,
    )?))
}

/// Prints a help message on ENOMEM error.
fn print_enomem_help(errno: Errno) -> Errno {
    if let Errno::ENOMEM = errno {
        eprintln!(
            "This failure is likely caused by the `vm.max_map_count` limit.\n\
             Try increasing the limit: `sudo sysctl -w vm.max_map_count=2097152`."
        );
    }
    errno
}

/// Returns the access kind (read or write) and the faulting address based on
/// the provided `siginfo` and `ucontext` pointers.
///
/// # Safety
///
/// Both `siginfo_ptr` and `ucontext_ptr` must be valid, non-null pointers to
/// `libc::siginfo_t` and (on supported platforms) `libc::ucontext_t`.
pub unsafe fn signal_access_kind_and_address(
    siginfo_ptr: *const libc::siginfo_t,
    ucontext_ptr: *const libc::c_void,
) -> (Option<AccessKind>, *mut libc::c_void) {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    let access_kind = {
        let ucontext_ptr = ucontext_ptr as *const libc::ucontext_t;
        let error_register = libc::REG_ERR as usize;
        let error_code = unsafe { (*ucontext_ptr).uc_mcontext.gregs[error_register] };
        // The second least-significant bit distinguishes between read and write
        // accesses. See https://git.io/JEQn3.
        if error_code & 0x2 == 0 {
            Some(AccessKind::Read)
        } else {
            Some(AccessKind::Write)
        }
    };
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    let access_kind: Option<AccessKind> = {
        // Prevent a warning about unused parameter.
        let _use_ucontext_ptr = ucontext_ptr;
        None
    };

    let (_si_signo, _si_errno, _si_code, si_addr) = unsafe {
        let s = *siginfo_ptr;
        (s.si_signo, s.si_errno, s.si_code, s.si_addr())
    };
    (access_kind, si_addr)
}

/// Sets up page mapping for a given range. This function takes two ranges, `min_prefetch_range`
/// and `max_prefetch_range` and returns the range that was initialized.
/// Preconditions:
///    * The pages in `max_prefetch_range` have not been dirtied before.
///    * `min_prefetch_range` ⊆ `max_prefetch_range`
///
/// Guarantees:
///    * `min_prefetch_range` ⊆ result ⊆ `max_prefetch_range`
///    * Any data read from the tracker's memory within the result range will be equal
///      to the pages according to the PageMap.
fn map_unaccessed_pages(
    page_map: &PageMap,
    memory_area: &MemoryArea,
    metrics: &MemoryTrackerMetrics,
    page_protection_flags: ProtFlags,
    min_prefetch_range: Range<PageIndex>,
    max_prefetch_range: Range<PageIndex>,
) -> Range<PageIndex> {
    debug_assert!(
        min_prefetch_range.start >= max_prefetch_range.start
            && min_prefetch_range.end <= max_prefetch_range.end,
        "Error checking min_prefetch_range:{min_prefetch_range:?} ⊆ max_prefetch_range:{max_prefetch_range:?}"
    );

    let instructions = page_map.get_memory_instructions(min_prefetch_range, max_prefetch_range);

    let range = instructions.range.clone();

    apply_memory_instructions(memory_area, page_protection_flags, instructions, metrics);

    range
}

/// Apply the given MemoryInstructions to a range and mprotect the entire range
/// Precondition: The protection level of the entire `prefetch_range` is PROT_NONE
fn apply_memory_instructions(
    memory_area: &MemoryArea,
    page_protection_flags: ProtFlags,
    memory_instructions: MemoryInstructions,
    metrics: &MemoryTrackerMetrics,
) {
    let MemoryInstructions {
        range: prefetch_range,
        instructions,
    } = memory_instructions;
    // We want to do as few mprotect calls as possible. However, to do any copies, we need to make the range read/write.
    // As long as we only have mmap instructions, we mmap them with protection flag PROT_NONE, such that the entire range
    // remains uniformly PROT_NONE. Before the first time we copy, we mark the entire range read/write and maintain that
    // for any later mmap calls.
    let mut current_prot_flags = ProtFlags::PROT_NONE;
    for (range, mmap_or_data) in instructions {
        debug_assert!(
            range.start.get() >= prefetch_range.start.get()
                && range.end.get() <= prefetch_range.end.get()
        );
        match mmap_or_data {
            ic_replicated_state::page_map::MemoryMapOrData::MemoryMap(
                FileDescriptor { fd },
                offset,
            ) => {
                metrics.mmap_count.fetch_add(1, Ordering::Relaxed);
                unsafe {
                    mmap(
                        memory_area.page_start_addr_from(range.start),
                        range_size_in_bytes(&range),
                        current_prot_flags,
                        MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
                        fd,
                        offset as i64,
                    )
                    .map_err(print_enomem_help)
                    .unwrap()
                };
            }
            ic_replicated_state::page_map::MemoryMapOrData::Data(data) => {
                metrics.copy_page_count.fetch_add(
                    (range.end.get() - range.start.get()) as usize,
                    Ordering::Relaxed,
                );

                if current_prot_flags != ProtFlags::PROT_READ | ProtFlags::PROT_WRITE {
                    current_prot_flags = ProtFlags::PROT_READ | ProtFlags::PROT_WRITE;
                    unsafe {
                        mprotect(
                            memory_area.page_start_addr_from(prefetch_range.start),
                            range_size_in_bytes(&prefetch_range),
                            current_prot_flags,
                        )
                        .map_err(print_enomem_help)
                        .unwrap()
                    };
                    metrics.mprotect_count.fetch_add(1, Ordering::Relaxed);
                }
                unsafe {
                    debug_assert_eq!(data.len(), range_size_in_bytes(&range));
                    std::ptr::copy_nonoverlapping(
                        data.as_ptr() as *const libc::c_void,
                        memory_area.page_start_addr_from(range.start),
                        range_size_in_bytes(&range),
                    )
                }
            }
        }
    }

    // There are two situations where the whole range already has the correct protections level
    // 1. `page_protection_flags` is PROT_NONE, and we only did mmap calls with PROT_NONE
    // 2. `page_protection_flags` is read/write, and we already made the whole range read/write
    //    just before the first copy
    if page_protection_flags != current_prot_flags {
        unsafe {
            mprotect(
                memory_area.page_start_addr_from(prefetch_range.start),
                range_size_in_bytes(&prefetch_range),
                page_protection_flags,
            )
            .map_err(print_enomem_help)
            .unwrap()
        };
        metrics.mprotect_count.fetch_add(1, Ordering::Relaxed);
    }
}

fn range_intersection(range1: &Range<PageIndex>, range2: &Range<PageIndex>) -> Range<PageIndex> {
    range1.start.max(range2.start)..range1.end.min(range2.end)
}

fn range_size_in_bytes(range: &Range<PageIndex>) -> usize {
    (range.end.get() - range.start.get()) as usize * PAGE_SIZE
}
