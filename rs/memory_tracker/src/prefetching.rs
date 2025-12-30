//! This is the currently used prefetching signal handler. Its functionality
//! was moved into this module from the root `lib.rs` to facilitate
//! switching to the deterministic memory tracker.
use ic_logger::{ReplicaLogger, debug};
use ic_replicated_state::{PageIndex, PageMap};
use ic_sys::{PAGE_SIZE, PageBytes};
use ic_types::{NumBytes, NumOsPages};
use nix::sys::mman::{ProtFlags, mprotect};
use std::{cell::RefCell, ops::Range, sync::atomic::Ordering};

use crate::{
    AccessKind, DirtyPageTracking, MemoryArea, MemoryLimits, MemoryTracker, MemoryTrackerMetrics,
    PageBitmap, apply_memory_instructions, map_unaccessed_pages, print_enomem_help,
    range_size_in_bytes,
};

#[cfg(test)]
mod tests;

/// The upper bound on the number of pages that are memory mapped from the
/// checkpoint file per signal handler call. Higher value gives higher
/// throughput in memory intensive workloads, but may regress performance
/// in other workloads because it increases work per signal handler call.
const MAX_PAGES_TO_MAP: usize = 128;

/// The prefetching signal handler requires `AccessKind` which currently
/// available only on Linux without WSL.
pub fn prefetching_signal_handler_available() -> bool {
    cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") && !*ic_sys::IS_WSL
}

pub struct PrefetchingMemoryTracker {
    memory_area: MemoryArea,
    accessed_bitmap: RefCell<PageBitmap>,
    accessed_pages: RefCell<Vec<PageIndex>>,
    dirty_bitmap: RefCell<PageBitmap>,
    dirty_pages: RefCell<Vec<PageIndex>>,
    speculatively_dirty_pages: RefCell<Vec<PageIndex>>,
    dirty_page_tracking: DirtyPageTracking,
    page_map: PageMap,
    use_prefetching_signal_handler: bool,
    #[cfg(feature = "sigsegv_handler_checksum")]
    checksum: RefCell<checksum::SigsegChecksum>,
    pub metrics: MemoryTrackerMetrics,
}

impl MemoryTracker for PrefetchingMemoryTracker {
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn new(
        start: *mut libc::c_void,
        size: NumBytes,
        log: ReplicaLogger,
        dirty_page_tracking: DirtyPageTracking,
        page_map: PageMap,
        _memory_limits: MemoryLimits,
    ) -> nix::Result<Self>
    where
        Self: Sized,
    {
        assert_eq!(ic_sys::sysconf_page_size(), PAGE_SIZE);
        let num_pages = NumOsPages::new(size.get() / PAGE_SIZE as u64);
        debug!(
            log,
            "PrefetchingMemoryTracker::new: start={:?}, size={}, num_pages={}",
            start,
            size,
            num_pages
        );

        let memory_area = MemoryArea::new(start, size);
        let accessed_bitmap = RefCell::new(PageBitmap::new(num_pages));
        let accessed_pages = RefCell::new(Vec::new());
        let dirty_bitmap = RefCell::new(PageBitmap::new(num_pages));
        let dirty_pages = RefCell::new(Vec::new());
        let speculatively_dirty_pages = RefCell::new(Vec::new());
        let use_prefetching_signal_handler = prefetching_signal_handler_available();
        let tracker = PrefetchingMemoryTracker {
            memory_area,
            accessed_bitmap,
            accessed_pages,
            dirty_bitmap,
            dirty_pages,
            speculatively_dirty_pages,
            dirty_page_tracking,
            page_map,
            use_prefetching_signal_handler,
            #[cfg(feature = "sigsegv_handler_checksum")]
            checksum: RefCell::new(checksum::SigsegChecksum::default()),
            metrics: MemoryTrackerMetrics::default(),
        };

        // Map the memory and make the range inaccessible to track it with SIGSEGV.
        if tracker.use_prefetching_signal_handler {
            let mut instructions = tracker.page_map.get_base_memory_instructions();

            // Restrict to tracked range before applying
            instructions.restrict_to_range(&tracker.accessed_bitmap.borrow().page_range());

            apply_memory_instructions(
                tracker.memory_area(),
                ProtFlags::PROT_NONE,
                instructions,
                &tracker.metrics,
            );
        } else {
            unsafe { mprotect(start, size.get() as usize, ProtFlags::PROT_NONE)? }
            tracker
                .metrics
                .mprotect_count
                .fetch_add(1, Ordering::Relaxed);
        }

        Ok(tracker)
    }

    fn handle_sigsegv(
        &self,
        access_kind: Option<AccessKind>,
        fault_address: *mut libc::c_void,
    ) -> bool {
        self.metrics.sigsegv_count.fetch_add(1, Ordering::Relaxed);
        if self.use_prefetching_signal_handler {
            prefetching_signal_handler(self, access_kind.unwrap(), fault_address)
        } else {
            basic_signal_handler(self, &self.page_map, fault_address)
        }
    }

    fn memory_area(&self) -> &MemoryArea {
        &self.memory_area
    }

    fn expand(&self, delta: NumBytes) {
        let old_size = self.memory_area.size.get();
        self.memory_area.size.set(old_size + delta);
        let delta_pages = NumOsPages::new(delta.get() / PAGE_SIZE as u64);
        debug_assert_eq!(
            delta_pages.get() * PAGE_SIZE as u64,
            delta.get(),
            "Expand delta {delta} must be page-size aligned (page size: {PAGE_SIZE})"
        );
        self.accessed_bitmap.borrow_mut().grow(delta_pages);
        self.dirty_bitmap.borrow_mut().grow(delta_pages);
    }

    fn num_accessed_pages(&self) -> usize {
        self.accessed_bitmap.borrow().marked_count().get() as usize
    }

    fn take_accessed_pages(&self) -> Vec<PageIndex> {
        self.accessed_pages.take()
    }

    fn take_dirty_pages(&self) -> Vec<PageIndex> {
        self.dirty_pages.take()
    }

    fn take_speculatively_dirty_pages(&self) -> Vec<PageIndex> {
        self.speculatively_dirty_pages.take()
    }

    fn validate_speculatively_dirty_page(&self, page_idx: PageIndex) -> Option<PageIndex> {
        let maybe_dirty_page = self.memory_area.page_start_addr_from(page_idx);
        let original_page = self.page_map.get_page(page_idx).as_ptr() as *const libc::c_void;
        match unsafe { libc::memcmp(maybe_dirty_page, original_page, PAGE_SIZE) } {
            0 => None,
            _ => Some(page_idx),
        }
    }

    fn is_accessed(&self, page_idx: PageIndex) -> bool {
        self.accessed_bitmap.borrow().is_marked(page_idx)
    }

    fn get_page(&self, page_idx: PageIndex) -> &PageBytes {
        self.page_map.get_page(page_idx)
    }

    fn metrics(&self) -> &MemoryTrackerMetrics {
        &self.metrics
    }
}

impl PrefetchingMemoryTracker {
    fn add_accessed_pages(&self, prefetched_range: &Range<PageIndex>) {
        let range = prefetched_range.start.get() as usize..prefetched_range.end.get() as usize;
        let mut accessed_pages = self.accessed_pages.borrow_mut();
        for i in range {
            let page_index = PageIndex::new(i as u64);
            accessed_pages.push(page_index);
        }
    }

    fn add_dirty_pages(&self, dirty_page: PageIndex, prefetched_range: Range<PageIndex>) {
        let range = prefetched_range.start.get() as usize..prefetched_range.end.get() as usize;
        let mut dirty_pages = self.dirty_pages.borrow_mut();
        let mut speculatively_dirty_pages = self.speculatively_dirty_pages.borrow_mut();
        for i in range {
            let page_index = PageIndex::new(i as u64);
            if page_index == dirty_page {
                dirty_pages.push(page_index);
            } else {
                speculatively_dirty_pages.push(page_index);
            }
        }
    }
}

/// This is the basic (unoptimized) signal handler. We keep it for use on MacOS
/// where the prefetching signal handler doesn't work because the [`AccessKind`] is not
/// available.
pub fn basic_signal_handler(
    tracker: &PrefetchingMemoryTracker,
    page_map: &PageMap,
    fault_address: *mut libc::c_void,
) -> bool {
    // We need to handle page faults in units of pages(!). So, round faulting
    // address down to page boundary
    let fault_address_page_boundary = fault_address as usize & !(PAGE_SIZE - 1);

    let page_idx = PageIndex::new(
        ((fault_address_page_boundary - tracker.memory_area.start) / PAGE_SIZE) as u64,
    );

    // Ensure `fault_address` falls within tracked memory area
    if !tracker.memory_area.contains(fault_address) {
        return false;
    };

    #[cfg(feature = "sigsegv_handler_checksum")]
    tracker.checksum.borrow_mut().record_access(
        tracker.memory_area.start,
        fault_address,
        AccessKind::Read, // We don't have the access kind, so default to read.
    );

    #[allow(clippy::branches_sharing_code)]
    if tracker.accessed_bitmap.borrow().is_marked(page_idx) {
        // This page has already been accessed, hence this fault must be for writing.
        // Upgrade its protection to read+write.
        unsafe {
            nix::sys::mman::mprotect(
                fault_address_page_boundary as *mut libc::c_void,
                PAGE_SIZE,
                nix::sys::mman::ProtFlags::PROT_READ | nix::sys::mman::ProtFlags::PROT_WRITE,
            )
            .map_err(print_enomem_help)
            .unwrap()
        };
        tracker.dirty_pages.borrow_mut().push(page_idx);
    } else {
        // This page has not been accessed yet.
        // The fault could be for reading or writing.
        // Load the contents of the page and enable just reading.
        // If the fault was for writing, then another fault will occur right away.
        // Temporarily allow writes to the page, to populate contents with the right
        // data
        unsafe {
            nix::sys::mman::mprotect(
                fault_address_page_boundary as *mut libc::c_void,
                PAGE_SIZE,
                nix::sys::mman::ProtFlags::PROT_READ | nix::sys::mman::ProtFlags::PROT_WRITE,
            )
            .map_err(print_enomem_help)
            .unwrap()
        };
        // Page contents initialization is optional. For example, if the memory tracker
        // is set up for a memory area mmap-ed to a file, the contents of each
        // page will be initialized by the kernel from that file.

        let page = page_map.get_page(page_idx);
        unsafe {
            std::ptr::copy_nonoverlapping(
                page.as_ptr(),
                fault_address_page_boundary as *mut u8,
                PAGE_SIZE,
            )
        };
        // Now reduce the access privileges to read-only
        unsafe {
            nix::sys::mman::mprotect(
                fault_address_page_boundary as *mut libc::c_void,
                PAGE_SIZE,
                nix::sys::mman::ProtFlags::PROT_READ,
            )
            .map_err(print_enomem_help)
            .unwrap()
        };
        tracker.accessed_bitmap.borrow_mut().mark(page_idx);
        tracker.accessed_pages.borrow_mut().push(page_idx);
    };
    true
}

/// This is the prefetching signal handler.
///
/// Differences to the basic signal handler:
/// 1. It can set up mapping for multiple pages in one go (prefetching).
/// 2. It uses the checkpoint file in `PageMap` for copy-on-write mapping.
/// 3. It uses the new access kind bit to optimize the case when the first
///    access to a page is a write access. This saves two `mprotect` calls
///    and expensive TLB flushing.
/// 4. It uses the new dirty-page-tracking bit to optimize for messages that
///    do not care about dirty pages. Currently these are replicated queries.
///    Update calls and non-replicated queries need dirty page tracking.
///
/// To describe the invariants, let's take some page and denote
/// - as `accessed` the corresponding bit in `tracker.accessed_bitmap`.
/// - as `prot_flags` the corresponding protection flags of the mapping.
/// - as `ignore_dirty` the dirty page tracking mode of `tracker`.
/// - as `dirty` the indication that the page is in `tracker.dirty_bitmap`.
///
/// Then the following must hold before and after the signal handler runs:
/// A. `prot_flags=NONE <=> !accessed`,
/// B. `ignore_dirty and accessed => prot_flags=READ_WRITE`,
/// C. `!ignore_dirty and prot_flags=READ_WRITE <=> dirty`,
/// D. `!ignore_dirty and prot_flags=READ => !dirty`,
/// E. `!ignore_dirty and !dirty => prot_flags=READ`,
/// F. `dirty` => `accessed`,
/// G. `dirty => the page is in either `tracker.dirty_pages` or in
///     `tracker.speculatively_dirty_pages`.
///
/// Invariant A ensures that we don't attempt to map the same page twice.
/// Invariant B boosts performance of messages that don't track dirty pages.
/// Invariants C - G ensure correct tracking of dirty pages. A speculatively
/// dirty page needs to be validated after the execution by comparing its
/// contents to the original page.
///
/// To understand how a faulting page `P` is handled we need to consider where
/// its backing memory is coming from in `PageMap`. There are three cases:
/// 1. The corresponding memory is not in `PageMap` meaning that the canister
///    has never written to it.
/// 2. The corresponding memory is in the checkpoint file meaning that the
///    canister has not written to it since the last checkpoint.
/// 3. The corresponding memory is in `PageDelta`.
///
/// In the first two cases the underlying memory has already been mmap'ed at
/// in the constructor of the memory tracker. So handler tries to mprotect `P`
/// and a few of its subsequent pages that have the same backing memory.
/// This optimization is referred to as prefetching in the code. Prefetching
/// is done both for read and write access. In the latter case the prefetched
/// pages are marked as speculatively dirty.
///
/// The third case is handled similar to the basic implementation with one
/// important optimization: if the faulting access is a write access and the
/// page has not been accessed yet, then it is mapped as `READ_WRITE` right away
/// without going through `READ_WRITE` => copy content => `READ` => `READ_WRITE`
/// like the basic signal handler does.
pub fn prefetching_signal_handler(
    tracker: &PrefetchingMemoryTracker,
    access_kind: AccessKind,
    fault_address: *mut libc::c_void,
) -> bool {
    if !tracker.memory_area.contains(fault_address) {
        // This memory tracker is not responsible for handling this address.
        return false;
    };

    #[cfg(feature = "sigsegv_handler_checksum")]
    tracker.checksum.borrow_mut().record_access(
        tracker.memory_area.start,
        fault_address,
        access_kind,
    );

    let faulting_page = tracker.memory_area.page_index_from(fault_address);
    let mut accessed_bitmap = tracker.accessed_bitmap.borrow_mut();

    match (access_kind, tracker.dirty_page_tracking) {
        (_, DirtyPageTracking::Ignore) => {
            // We don't care about dirty pages here, so we can set up the page mapping for
            // for multiple pages as read/write right away.
            let prefetch_range =
                range_from_count(faulting_page, NumOsPages::new(MAX_PAGES_TO_MAP as u64));
            let max_prefetch_range =
                accessed_bitmap.restrict_range_to_unmarked(faulting_page, prefetch_range);
            let min_prefetch_range = accessed_bitmap
                .restrict_range_to_predicted(faulting_page, max_prefetch_range.clone());
            let prefetch_range = map_unaccessed_pages(
                &tracker.page_map,
                &tracker.memory_area,
                &tracker.metrics,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                min_prefetch_range,
                max_prefetch_range,
            );
            accessed_bitmap.mark_range(&prefetch_range);
            tracker.add_accessed_pages(&prefetch_range);
        }
        (AccessKind::Read, DirtyPageTracking::Track) => {
            // Set up the page mapping as read-only in order to get a signal on subsequent
            // write accesses to track dirty pages. We can do this for multiple pages.
            let prefetch_range =
                range_from_count(faulting_page, NumOsPages::new(MAX_PAGES_TO_MAP as u64));
            let max_prefetch_range =
                accessed_bitmap.restrict_range_to_unmarked(faulting_page, prefetch_range);
            let min_prefetch_range = accessed_bitmap
                .restrict_range_to_predicted(faulting_page, max_prefetch_range.clone());
            let prefetch_range = map_unaccessed_pages(
                &tracker.page_map,
                &tracker.memory_area,
                &tracker.metrics,
                ProtFlags::PROT_READ,
                min_prefetch_range,
                max_prefetch_range,
            );
            accessed_bitmap.mark_range(&prefetch_range);
            tracker.add_accessed_pages(&prefetch_range);
        }
        (AccessKind::Write, DirtyPageTracking::Track) => {
            let mut dirty_bitmap = tracker.dirty_bitmap.borrow_mut();
            assert!(!dirty_bitmap.is_marked(faulting_page));
            let prefetch_range =
                range_from_count(faulting_page, NumOsPages::new(MAX_PAGES_TO_MAP as u64));
            // Ensure that we don't overwrite an already dirty page.
            let prefetch_range =
                dirty_bitmap.restrict_range_to_unmarked(faulting_page, prefetch_range);
            if accessed_bitmap.is_marked(faulting_page) {
                tracker
                    .metrics
                    .read_before_write_count
                    .fetch_add(1, Ordering::Relaxed);
                // Ensure that all pages in the range have already been accessed because we are
                // going to simply `mprotect` the range.
                let prefetch_range =
                    accessed_bitmap.restrict_range_to_marked(faulting_page, prefetch_range);
                // Amortize the prefetch work based on the previously written pages.
                let prefetch_range =
                    dirty_bitmap.restrict_range_to_predicted(faulting_page, prefetch_range);
                let page_start_addr = tracker
                    .memory_area
                    .page_start_addr_from(prefetch_range.start);
                unsafe {
                    mprotect(
                        page_start_addr,
                        range_size_in_bytes(&prefetch_range),
                        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                    )
                    .map_err(print_enomem_help)
                    .unwrap()
                };
                tracker
                    .metrics
                    .mprotect_count
                    .fetch_add(1, Ordering::Relaxed);
                dirty_bitmap.mark_range(&prefetch_range);
                tracker.add_dirty_pages(faulting_page, prefetch_range);
            } else {
                tracker
                    .metrics
                    .direct_write_count
                    .fetch_add(1, Ordering::Relaxed);
                // The first access to the page is a write access. This is a good case because
                // it allows us to set up read/write mapping right away.
                // Ensure that all pages in the range have not been accessed yet because we are
                // going to set up a new mapping. Note that this implies that all pages in the
                // range have not been written to.
                let prefetch_range =
                    accessed_bitmap.restrict_range_to_unmarked(faulting_page, prefetch_range);
                // Amortize the prefetch work based on the previously written pages.
                let prefetch_range =
                    dirty_bitmap.restrict_range_to_predicted(faulting_page, prefetch_range);
                let prefetch_range = map_unaccessed_pages(
                    &tracker.page_map,
                    &tracker.memory_area,
                    &tracker.metrics,
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                    prefetch_range.clone(),
                    prefetch_range,
                );
                accessed_bitmap.mark_range(&prefetch_range);
                tracker.add_accessed_pages(&prefetch_range);
                dirty_bitmap.mark_range(&prefetch_range);
                tracker.add_dirty_pages(faulting_page, prefetch_range);
            }
        }
    }
    true
}

fn range_from_count(page: PageIndex, count: NumOsPages) -> Range<PageIndex> {
    PageIndex::new(page.get().saturating_sub(count.get()))..PageIndex::new(page.get() + count.get())
}

#[cfg(feature = "sigsegv_handler_checksum")]
mod checksum {
    use std::io::Write;

    use crate::AccessKind;

    #[derive(Default)]
    pub(super) struct SigsegChecksum {
        value: usize,
        index: usize,
    }

    impl SigsegChecksum {
        pub(super) fn record_access(
            &mut self,
            base_addr: usize,
            access_addr: *const libc::c_void,
            access_kind: AccessKind,
        ) {
            self.index += 1;
            self.value += self
                .index
                .wrapping_mul(access_addr as usize - base_addr)
                .wrapping_mul(match access_kind {
                    AccessKind::Read => 1,
                    AccessKind::Write => 1 << 32,
                });
        }
    }

    impl Drop for SigsegChecksum {
        fn drop(&mut self) {
            let output_file = std::env::var("CHECKSUM_FILE").unwrap();
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(output_file)
                .unwrap();
            writeln!(
                file,
                "Memory tracker completed with checksum {}",
                self.value
            )
            .unwrap();
        }
    }
}
