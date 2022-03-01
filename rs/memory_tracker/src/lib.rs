use bit_vec::BitVec;
use ic_logger::{debug, ReplicaLogger};
use ic_replicated_state::{
    page_map::{FileDescriptor, MemoryRegion},
    PageIndex, PageMap,
};
use ic_sys::{PageBytes, PAGE_SIZE};
use nix::sys::mman::{mmap, mprotect, MapFlags, ProtFlags};
use std::{
    cell::{Cell, RefCell},
    ops::Range,
};

// The upper bound on the number of pages that are memory mapped from the
// checkpoint file per signal handler call. Higher value gives higher
// throughput in memory intensive workloads, but may regress performance
// in other workloads because it increases work per signal handler call.
const MAX_PAGES_TO_MAP: usize = 128;
// The upper bound on the number of pages copied from PageMap. In contrast
// to `MAX_PAGES_TO_MAP`, this value also affects memory usage. Setting it
// too high may increase memory usage.
const MAX_PAGES_TO_COPY: usize = 64;

// The new signal handler requires `AccessKind` which currently available only
// on Linux without WSL.
fn new_signal_handler_available() -> bool {
    cfg!(target_os = "linux") && !*ic_sys::IS_WSL
}

// Represents a memory area: address + size. Address must be page-aligned and
// size must be a multiple of PAGE_SIZE.
#[derive(Clone)]
pub struct MemoryArea {
    // base address of the tracked memory area
    addr: usize,
    // size of the tracked memory area
    size: Cell<usize>,
}

impl MemoryArea {
    pub fn new(addr: *const libc::c_void, size: usize) -> Self {
        let addr = addr as usize;
        assert!(addr % PAGE_SIZE == 0, "address is page-aligned");
        assert!(size % PAGE_SIZE == 0, "size is a multiple of page size");
        let size = Cell::new(size);
        MemoryArea { addr, size }
    }

    #[inline]
    pub fn is_within(&self, a: *const libc::c_void) -> bool {
        (self.addr <= a as usize) && ((a as usize) < self.addr + (self.size.get()))
    }

    #[inline]
    pub fn addr(&self) -> usize {
        self.addr as usize
    }

    #[inline]
    pub fn size(&self) -> usize {
        self.size.get()
    }
}

/// Specifies whether the currently running message execution needs to know
/// which pages were dirtied or not. Dirty page tracking comes with a large
/// performance overhead.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DirtyPageTracking {
    Ignore,
    Track,
}

/// Specifies whether the memory access that caused the signal was a read access
/// or a write access.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AccessKind {
    Read,
    Write,
}

struct PageBitmap {
    pages: BitVec,
    marked_count: usize,
}

impl PageBitmap {
    fn new(num_pages: usize) -> Self {
        Self {
            pages: BitVec::from_elem(num_pages, false),
            marked_count: 0,
        }
    }

    fn grow(&mut self, delta: usize) {
        self.pages.grow(delta, false);
    }

    fn marked_count(&self) -> usize {
        self.marked_count
    }

    fn is_marked(&self, page: PageIndex) -> bool {
        self.pages.get(page.get() as usize).unwrap_or(false)
    }

    fn mark(&mut self, page: PageIndex) {
        self.pages.set(page.get() as usize, true);
        self.marked_count += 1;
    }

    fn mark_range(&mut self, range: &Range<PageIndex>) {
        let range = Range {
            start: range.start.get() as usize,
            end: range.end.get() as usize,
        };
        for i in range {
            self.mark(PageIndex::new(i as u64));
        }
    }

    // Returns the largest prefix of the given range such that all pages there have
    // not been marked yet.
    fn restrict_range_to_unmarked(&self, range: Range<PageIndex>) -> Range<PageIndex> {
        let range = range_intersection(&range, &self.page_range());

        let start = range.start.get() as usize;
        let old_end = range.end.get() as usize;
        let mut end = start;
        while end < old_end {
            if self.pages.get(end).unwrap_or(true) {
                break;
            }
            end += 1;
        }
        Range {
            start: PageIndex::new(start as u64),
            end: PageIndex::new(end as u64),
        }
    }

    // Returns the largest prefix of the given range such that all pages there have
    // been already marked.
    fn restrict_range_to_marked(&self, range: Range<PageIndex>) -> Range<PageIndex> {
        let range = range_intersection(&range, &self.page_range());

        let start = range.start.get() as usize;
        let old_end = range.end.get() as usize;
        let mut end = start;
        while end < old_end {
            match self.pages.get(end) {
                None | Some(false) => break,
                Some(true) => {}
            }
            end += 1;
        }
        Range {
            start: PageIndex::new(start as u64),
            end: PageIndex::new(end as u64),
        }
    }

    // Returns the range of pages that are predicted to be marked in the future
    // based on the marked pages before the start of the given range.
    fn restrict_range_to_predicted(&self, range: Range<PageIndex>) -> Range<PageIndex> {
        let range = range_intersection(&range, &self.page_range());

        let start = range.start.get() as usize;
        let old_end = range.end.get() as usize;

        let mut predicted_count = 1;
        while predicted_count < start && start + predicted_count < old_end {
            if !self.pages.get(start - predicted_count).unwrap_or(false) {
                break;
            }
            predicted_count += 1;
        }

        Range {
            start: PageIndex::new(start as u64),
            end: PageIndex::new((start + predicted_count) as u64),
        }
    }

    fn page_range(&self) -> Range<PageIndex> {
        Range {
            start: PageIndex::new(0),
            end: PageIndex::new(self.pages.len() as u64),
        }
    }
}

pub struct SigsegvMemoryTracker {
    memory_area: MemoryArea,
    accessed_bitmap: RefCell<PageBitmap>,
    dirty_bitmap: RefCell<PageBitmap>,
    dirty_pages: RefCell<Vec<PageIndex>>,
    speculatively_dirty_pages: RefCell<Vec<PageIndex>>,
    dirty_page_tracking: DirtyPageTracking,
    page_map: PageMap,
    use_new_signal_handler: bool,
    #[cfg(feature = "sigsegv_handler_checksum")]
    checksum: RefCell<checksum::SigsegChecksum>,
}

impl SigsegvMemoryTracker {
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn new(
        addr: *mut libc::c_void,
        size: usize,
        log: ReplicaLogger,
        dirty_page_tracking: DirtyPageTracking,
        page_map: PageMap,
    ) -> nix::Result<Self> {
        assert_eq!(ic_sys::sysconf_page_size(), PAGE_SIZE);
        let num_pages = size / PAGE_SIZE;
        debug!(
            log,
            "SigsegvMemoryTracker::new: addr={:?}, size={}, num_pages={}", addr, size, num_pages
        );

        let memory_area = MemoryArea::new(addr, size);
        let accessed_bitmap = RefCell::new(PageBitmap::new(num_pages));
        let dirty_bitmap = RefCell::new(PageBitmap::new(num_pages));
        let dirty_pages = RefCell::new(Vec::new());
        let speculatively_dirty_pages = RefCell::new(Vec::new());
        let use_new_signal_handler = new_signal_handler_available();
        let tracker = SigsegvMemoryTracker {
            memory_area,
            accessed_bitmap,
            dirty_bitmap,
            dirty_pages,
            speculatively_dirty_pages,
            dirty_page_tracking,
            page_map,
            use_new_signal_handler,
            #[cfg(feature = "sigsegv_handler_checksum")]
            checksum: RefCell::new(checksum::SigsegChecksum::default()),
        };

        // Map the memory and make the range inaccessible to track it with SIGSEGV.
        if tracker.use_new_signal_handler {
            match tracker.page_map.get_checkpoint_memory_region() {
                MemoryRegion::BackedByFile(page_map_range, FileDescriptor { fd }) => {
                    // Pages outside `mmap_range` will be automatically initialized to zeros
                    // because of the mapping set up by `MmapMemoryCreator`. This is exactly
                    // what we need for Wasm `memory.grow()`.
                    let mmap_range = range_intersection(&tracker.page_range(), &page_map_range);
                    // The checkpoint page range must be a subset of the Wasm memory page range.
                    assert_eq!(mmap_range, page_map_range);
                    let start_addr = tracker.page_start_addr_from(mmap_range.start);
                    let start_offset_in_file = mmap_range.start.get() as usize * PAGE_SIZE;
                    let actual_addr = unsafe {
                        mmap(
                            start_addr,
                            range_size_in_bytes(&mmap_range),
                            ProtFlags::PROT_NONE,
                            MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
                            fd,
                            start_offset_in_file as i64,
                        )?
                    };
                    assert_eq!(actual_addr, start_addr, "mmap ignored MAP_FIXED");
                }
                MemoryRegion::BackedByPage(_) | MemoryRegion::Zeros(_) => {
                    unsafe { mprotect(addr, size, ProtFlags::PROT_NONE)? };
                }
            }
        } else {
            unsafe { mprotect(addr, size, ProtFlags::PROT_NONE)? }
        }

        Ok(tracker)
    }

    pub fn handle_sigsegv(
        &self,
        access_kind: Option<AccessKind>,
        fault_address: *mut libc::c_void,
    ) -> bool {
        if self.use_new_signal_handler {
            sigsegv_fault_handler_new(self, &self.page_map, access_kind.unwrap(), fault_address)
        } else {
            sigsegv_fault_handler_old(self, &self.page_map, fault_address)
        }
    }

    pub fn area(&self) -> &MemoryArea {
        &self.memory_area
    }

    pub fn expand(&self, delta: usize) {
        let old_size = self.area().size.get();
        self.area().size.set(old_size + delta);
        self.accessed_bitmap.borrow_mut().grow(delta);
        self.dirty_bitmap.borrow_mut().grow(delta);
    }

    pub fn take_dirty_pages(&self) -> Vec<PageIndex> {
        self.dirty_pages.take()
    }

    pub fn take_speculatively_dirty_pages(&self) -> Vec<PageIndex> {
        self.speculatively_dirty_pages.take()
    }

    pub fn validate_speculatively_dirty_page(&self, page_index: PageIndex) -> Option<PageIndex> {
        let maybe_dirty_page = self.page_start_addr_from(page_index);
        let original_page = self.page_map.get_page(page_index).as_ptr() as *const libc::c_void;
        match unsafe { libc::memcmp(maybe_dirty_page, original_page, PAGE_SIZE) } {
            0 => None,
            _ => Some(page_index),
        }
    }

    pub fn num_accessed_pages(&self) -> usize {
        self.accessed_bitmap.borrow().marked_count()
    }

    fn page_index_from(&self, addr: *mut libc::c_void) -> PageIndex {
        let page_start_mask = !(PAGE_SIZE as usize - 1);
        let page_start_addr = (addr as usize) & page_start_mask;

        let page_index = (page_start_addr - self.memory_area.addr()) / PAGE_SIZE;
        PageIndex::new(page_index as u64)
    }

    fn page_start_addr_from(&self, page_index: PageIndex) -> *mut libc::c_void {
        let page_start_addr = self.memory_area.addr() + page_index.get() as usize * PAGE_SIZE;
        page_start_addr as *mut libc::c_void
    }

    fn page_range(&self) -> Range<PageIndex> {
        self.accessed_bitmap.borrow().page_range()
    }

    fn add_dirty_pages(&self, dirty_page: PageIndex, prefetched_range: Range<PageIndex>) {
        let range = Range {
            start: prefetched_range.start.get() as usize,
            end: prefetched_range.end.get() as usize,
        };
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

/// This is the old (unoptimized) signal handler. We keep it for two reasons:
/// 1) It is needed for `CowMemoryManager`.
/// 2) If we discover a bug in the new signal handler, we can quickly revert to
///    the old implementation.
/// It is not possible to use a logger from within the signal handler. Hence,
/// for debugging, we use an ordinary `eprintln!` hidden behind a feature gate.
/// To enable:
/// ic-execution-environment = { ..., features = [ "sigsegv_handler_debug" ] }
pub fn sigsegv_fault_handler_old(
    tracker: &SigsegvMemoryTracker,
    page_map: &PageMap,
    fault_address: *mut libc::c_void,
) -> bool {
    // We need to handle page faults in units of pages(!). So, round faulting
    // address down to page boundary
    let fault_address_page_boundary = fault_address as usize & !(PAGE_SIZE as usize - 1);

    let page_num = (fault_address_page_boundary - tracker.memory_area.addr()) / PAGE_SIZE;

    #[cfg(feature = "sigsegv_handler_debug")]
    eprintln!(
        "> Thread: {:?} sigsegv_fault_handler: base_addr = 0x{:x}, page_size = 0x{:x}, fault_address = 0x{:x}, fault_address_page_boundary = 0x{:x}, page = {}",
        std::thread::current().id(),
        tracker.memory_area.addr() as u64,
        PAGE_SIZE,
        fault_address as u64,
        fault_address_page_boundary,
        page_num
    );

    // Ensure `fault_address` falls within tracked memory area
    if !tracker.memory_area.is_within(fault_address) {
        #[cfg(feature = "sigsegv_handler_debug")]
        eprintln!(
            "fault address {:?} outside of tracked memory area",
            fault_address
        );
        return false;
    };

    #[cfg(feature = "sigsegv_handler_checksum")]
    tracker.checksum.borrow_mut().record_access(
        tracker.memory_area.addr(),
        fault_address,
        AccessKind::Read, // We don't have the access kind, so default to read.
    );

    #[allow(clippy::branches_sharing_code)]
    if tracker
        .accessed_bitmap
        .borrow()
        .is_marked(PageIndex::new(page_num as u64))
    {
        // This page has already been accessed, hence this fault must be for writing.
        // Upgrade its protection to read+write.
        #[cfg(feature = "sigsegv_handler_debug")]
        eprintln!(
            "> sigsegv_fault_handler: page({}) is already faulted: mprotect(addr=0x{:x}, len=0x{:x}, prot=PROT_READ|PROT_WRITE)",
            page_num,
            fault_address_page_boundary, PAGE_SIZE
        );
        unsafe {
            nix::sys::mman::mprotect(
                fault_address_page_boundary as *mut libc::c_void,
                PAGE_SIZE,
                nix::sys::mman::ProtFlags::PROT_READ | nix::sys::mman::ProtFlags::PROT_WRITE,
            )
            .unwrap()
        };
        tracker
            .dirty_pages
            .borrow_mut()
            .push(PageIndex::new(page_num as u64));
    } else {
        // This page has not been accessed yet.
        // The fault could be for reading or writing.
        // Load the contents of the page and enable just reading.
        // If the fault was for writing, then another fault will occur right away.
        #[cfg(feature = "sigsegv_handler_debug")]
        eprintln!(
            "> sigsegv_fault_handler: page({}) has not been faulted: mprotect(addr=0x{:x}, len=0x{:x}, prot=PROT_READ)",
            page_num,
            fault_address_page_boundary,
            PAGE_SIZE
        );
        // Temporarily allow writes to the page, to populate contents with the right
        // data
        unsafe {
            nix::sys::mman::mprotect(
                fault_address_page_boundary as *mut libc::c_void,
                PAGE_SIZE,
                nix::sys::mman::ProtFlags::PROT_READ | nix::sys::mman::ProtFlags::PROT_WRITE,
            )
            .unwrap()
        };
        // Page contents initialization is optional. For example, if the memory tracker
        // is set up for a memory area mmap-ed to a file, the contents of each
        // page will be initialized by the kernel from that file.

        let page = page_map.get_page(PageIndex::new(page_num as u64));
        #[cfg(feature = "sigsegv_handler_debug")]
        eprintln!(
            "> sigsegv_fault_handler: setting page({}) contents to {}",
            page_num,
            show_bytes_compact(page)
        );
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
            .unwrap()
        };
        tracker
            .accessed_bitmap
            .borrow_mut()
            .mark(PageIndex::new(page_num as u64));
    };
    true
}

/// This is the new (optimized) signal handler.
///
/// Differences to the old signal handler:
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
/// The third case is handled similar to the old implementation with one
/// important optimization: if the faulting access is a write access and the
/// page has not been accessed yet, then it is mapped as `READ_WRITE` right away
/// without going through `READ_WRITE` => copy content => `READ` => `READ_WRITE`
/// like the old signal handler does.
pub fn sigsegv_fault_handler_new(
    tracker: &SigsegvMemoryTracker,
    page_map: &PageMap,
    access_kind: AccessKind,
    fault_address: *mut libc::c_void,
) -> bool {
    if !tracker.memory_area.is_within(fault_address) {
        // This memory tracker is not responsible for handling this address.
        return false;
    };

    #[cfg(feature = "sigsegv_handler_checksum")]
    tracker.checksum.borrow_mut().record_access(
        tracker.memory_area.addr(),
        fault_address,
        access_kind,
    );

    let faulting_page = tracker.page_index_from(fault_address);
    let mut accessed_bitmap = tracker.accessed_bitmap.borrow_mut();

    match (access_kind, tracker.dirty_page_tracking) {
        (_, DirtyPageTracking::Ignore) => {
            // We don't care about dirty pages here, so we can set up the page mapping for
            // for multiple pages as read/write right away.
            let prefetch_range = range_from_count(faulting_page, MAX_PAGES_TO_MAP);
            let max_prefetch_range = accessed_bitmap.restrict_range_to_unmarked(prefetch_range);
            let min_prefetch_range =
                accessed_bitmap.restrict_range_to_predicted(max_prefetch_range.clone());
            let prefetch_range = map_unaccessed_pages(
                tracker,
                page_map,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                faulting_page,
                min_prefetch_range,
                max_prefetch_range,
            );
            accessed_bitmap.mark_range(&prefetch_range);
        }
        (AccessKind::Read, DirtyPageTracking::Track) => {
            // Set up the page mapping as read-only in order to get a signal on subsequent
            // write accesses to track dirty pages. We can do this for multiple pages.
            let prefetch_range = range_from_count(faulting_page, MAX_PAGES_TO_MAP);
            let max_prefetch_range = accessed_bitmap.restrict_range_to_unmarked(prefetch_range);
            let min_prefetch_range =
                accessed_bitmap.restrict_range_to_predicted(max_prefetch_range.clone());
            let prefetch_range = map_unaccessed_pages(
                tracker,
                page_map,
                ProtFlags::PROT_READ,
                faulting_page,
                min_prefetch_range,
                max_prefetch_range,
            );
            accessed_bitmap.mark_range(&prefetch_range);
        }
        (AccessKind::Write, DirtyPageTracking::Track) => {
            let mut dirty_bitmap = tracker.dirty_bitmap.borrow_mut();
            assert!(!dirty_bitmap.is_marked(faulting_page));
            let prefetch_range = range_from_count(faulting_page, MAX_PAGES_TO_MAP);
            // Ensure that we don't overwrite an already dirty page.
            let prefetch_range = dirty_bitmap.restrict_range_to_unmarked(prefetch_range);
            if accessed_bitmap.is_marked(faulting_page) {
                // Ensure that all pages in the range have already been accessed because we are
                // going to simply `mprotect` the range.
                let prefetch_range = accessed_bitmap.restrict_range_to_marked(prefetch_range);
                // Amortize the prefetch work based on the previously written pages.
                let prefetch_range = dirty_bitmap.restrict_range_to_predicted(prefetch_range);
                let page_start_addr = tracker.page_start_addr_from(faulting_page);
                unsafe {
                    mprotect(
                        page_start_addr,
                        range_size_in_bytes(&prefetch_range),
                        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                    )
                    .unwrap()
                };
                dirty_bitmap.mark_range(&prefetch_range);
                tracker.add_dirty_pages(faulting_page, prefetch_range);
            } else {
                // The first access to the page is a write access. This is a good case because
                // it allows us to set up read/write mapping right away.
                // Ensure that all pages in the range have not been accessed yet because we are
                // going to set up a new mapping. Note that this implies that all pages in the
                // range have not been written to.
                let prefetch_range = accessed_bitmap.restrict_range_to_unmarked(prefetch_range);
                // Amortize the prefetch work based on the previously written pages.
                let prefetch_range = dirty_bitmap.restrict_range_to_predicted(prefetch_range);
                let prefetch_range = map_unaccessed_pages(
                    tracker,
                    page_map,
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                    faulting_page,
                    prefetch_range.clone(),
                    prefetch_range,
                );
                accessed_bitmap.mark_range(&prefetch_range);
                dirty_bitmap.mark_range(&prefetch_range);
                tracker.add_dirty_pages(faulting_page, prefetch_range);
            }
        }
    }
    true
}

// Sets up page mapping for the given `faulting_page` and its subsequent pages
// using the backing memory from the given `page_map`. The range of mapped pages
// depends on the type of the backing memory. If it is cheap to map then the
// largest range specified by `max_prefetch_range` is used. If it involves
// copying then the smallest range specified by `min_prefetch_range` is used.
// The function is allowed to map less pages than specified by the ranges.
fn map_unaccessed_pages(
    tracker: &SigsegvMemoryTracker,
    page_map: &PageMap,
    page_protection_flags: ProtFlags,
    faulting_page: PageIndex,
    min_prefetch_range: Range<PageIndex>,
    max_prefetch_range: Range<PageIndex>,
) -> Range<PageIndex> {
    assert!(min_prefetch_range.contains(&faulting_page));
    assert!(max_prefetch_range.contains(&faulting_page));

    let memory_region = page_map.get_memory_region(faulting_page);
    match memory_region {
        MemoryRegion::Zeros(page_map_range) | MemoryRegion::BackedByFile(page_map_range, _) => {
            assert!(page_map_range.contains(&faulting_page));
            let mprotect_range = range_intersection(&max_prefetch_range, &page_map_range);
            let start_addr = tracker.page_start_addr_from(mprotect_range.start);
            unsafe {
                mprotect(
                    start_addr,
                    range_size_in_bytes(&mprotect_range),
                    page_protection_flags,
                )
                .unwrap()
            };
            mprotect_range
        }

        MemoryRegion::BackedByPage(contents) => {
            let prefetch_range = range_intersection(
                &range_from_count(faulting_page, MAX_PAGES_TO_COPY),
                &min_prefetch_range,
            );

            // Get the largest contiguous memory region backed by pages.
            let mut pages: [Option<&PageBytes>; MAX_PAGES_TO_COPY] = [None; MAX_PAGES_TO_COPY];
            pages[0] = Some(contents);
            let mut count = 1;
            while count < range_count(&prefetch_range) {
                match page_map.get_memory_region(PageIndex::new(faulting_page.get() + count as u64))
                {
                    MemoryRegion::Zeros(_) | MemoryRegion::BackedByFile(_, _) => {
                        break;
                    }
                    MemoryRegion::BackedByPage(contents) => {
                        pages[count] = Some(contents);
                    }
                }
                count += 1;
            }

            let mprotect_range = range_from_count(faulting_page, count);
            let page_start_addr = tracker.page_start_addr_from(mprotect_range.start);

            // Make the page writable because we are going to copy bytes.
            unsafe {
                mprotect(
                    page_start_addr,
                    range_size_in_bytes(&mprotect_range),
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                )
                .unwrap()
            };

            // Copy the contents of the pages.
            for (index, page) in pages.iter().enumerate() {
                if let Some(contents) = *page {
                    assert!(index < count);
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            contents.as_ptr(),
                            (page_start_addr as *mut u8).add(index * PAGE_SIZE),
                            PAGE_SIZE,
                        )
                    };
                }
            }

            if !page_protection_flags.contains(ProtFlags::PROT_WRITE) {
                // Make the page read-only to intercept the future write accesses.
                // TODO(EXC-447): This `mprotect` call is the main performance bottleneck
                // for messages that need to track dirty pages. It causes expensive TLB flushes
                // because it reduces the protection flags from Read/Write to Read.
                // There are two ways to eliminate this call:
                // 1) Implement an mmap allocator for `PageDelta` pages so that we can mmap it.
                // 2) Track all accessed pages and after execution filter dirty pages by
                //    comparing the page contents.
                unsafe {
                    mprotect(
                        page_start_addr,
                        range_size_in_bytes(&mprotect_range),
                        ProtFlags::PROT_READ,
                    )
                    .unwrap()
                };
            }
            mprotect_range
        }
    }
}

fn range_intersection(range1: &Range<PageIndex>, range2: &Range<PageIndex>) -> Range<PageIndex> {
    Range {
        start: std::cmp::max(range1.start, range2.start),
        end: std::cmp::min(range1.end, range2.end),
    }
}

fn range_size_in_bytes(range: &Range<PageIndex>) -> usize {
    (range.end.get() - range.start.get()) as usize * PAGE_SIZE
}

fn range_from_count(page: PageIndex, count: usize) -> Range<PageIndex> {
    Range {
        start: page,
        end: PageIndex::new(page.get() + count as u64),
    }
}

fn range_count(range: &Range<PageIndex>) -> usize {
    (range.end.get() - range.start.get()) as usize
}

#[allow(dead_code)]
#[cfg(feature = "sigsegv_handler_debug")]
pub(crate) fn show_bytes_compact(bytes: &PageBytes) -> String {
    let mut result = String::new();
    let mut count = 1;
    let mut current = None;
    result += "[";
    for &b in bytes.iter() {
        match current {
            Some(x) if x == b => {
                count += 1;
            }
            Some(x) => {
                result += &format!("{}x{:x} ", count, x);
                count = 1;
            }
            None => (),
        }
        current = Some(b);
    }
    if let Some(x) = current {
        result += &format!("{}x{:x}", count, x)
    }
    result += "]";
    result
}

#[cfg(test)]
mod tests;

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
            self.value += self.index
                * (access_addr as usize - base_addr)
                * match access_kind {
                    AccessKind::Read => 1,
                    AccessKind::Write => 1 << 32,
                };
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
