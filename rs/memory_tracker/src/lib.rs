use bit_vec::BitVec;
use ic_logger::{debug, ReplicaLogger};
use ic_replicated_state::{
    page_map::{FileDescriptor, MemoryRegion},
    PageIndex, PageMap,
};
use ic_sys::PAGE_SIZE;
use nix::sys::mman::{mmap, mprotect, MapFlags, ProtFlags};
use std::{
    cell::{Cell, RefCell},
    ops::Range,
};

// A flag for easy switching between the new and the old signal handlers.
const ENABLE_NEW_SIGNAL_HANDLER: bool = false;
const MAX_PREFETCH_PAGES: usize = 32;

// Represents a memory area: address + size. Address must be page-aligned and
// size must be a multiple of PAGE_SIZE.
#[derive(Clone)]
pub struct MemoryArea {
    // base address of the tracked memory area
    addr: *const libc::c_void,
    // size of the tracked memory area
    size: Cell<usize>,
}

impl MemoryArea {
    pub fn new(addr: *const libc::c_void, size: usize) -> Self {
        assert!(addr as usize % *PAGE_SIZE == 0, "address is page-aligned");
        assert!(size % *PAGE_SIZE == 0, "size is a multiple of page size");
        let size = Cell::new(size);
        MemoryArea { addr, size }
    }

    #[inline]
    pub fn is_within(&self, a: *const libc::c_void) -> bool {
        (self.addr <= a) && (a < unsafe { self.addr.add(self.size.get()) })
    }

    #[inline]
    pub fn addr(&self) -> *const libc::c_void {
        self.addr
    }

    #[inline]
    pub fn size(&self) -> usize {
        self.size.get()
    }

    #[inline]
    pub fn page_addr(&self, page_num: usize) -> *const libc::c_void {
        assert!(
            page_num < self.size.get() / *PAGE_SIZE,
            "page({}) is not within memory area addr={:?}, size={}",
            page_num,
            self.addr,
            self.size.get()
        );
        unsafe { self.addr.add(page_num * *PAGE_SIZE) }
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

type PageNum = usize;

struct AccessedPages {
    pages: BitVec,
    count: usize,
}

impl AccessedPages {
    fn new(num_pages: usize) -> Self {
        Self {
            pages: BitVec::from_elem(num_pages, false),
            count: 0,
        }
    }

    fn grow(&mut self, delta: usize) {
        self.pages.grow(delta, false);
    }

    fn count(&self) -> usize {
        self.count
    }

    fn get(&self, index: usize) -> Option<bool> {
        self.pages.get(index)
    }

    fn set(&mut self, index: usize) {
        self.pages.set(index, true);
        self.count += 1;
    }
}

pub struct SigsegvMemoryTracker {
    memory_area: MemoryArea,
    accessed_pages: RefCell<AccessedPages>,
    dirty_pages: RefCell<Vec<*const libc::c_void>>,
    dirty_page_tracking: DirtyPageTracking,
}

impl SigsegvMemoryTracker {
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn new(
        addr: *mut libc::c_void,
        size: usize,
        log: ReplicaLogger,
        dirty_page_tracking: DirtyPageTracking,
    ) -> nix::Result<Self> {
        let num_pages = size / *PAGE_SIZE;
        debug!(
            log,
            "SigsegvMemoryTracker::new: addr={:?}, size={}, num_pages={}", addr, size, num_pages
        );

        let memory_area = MemoryArea::new(addr, size);

        // make memory inaccessible so we can track it with SIGSEGV
        unsafe { mprotect(addr, size, ProtFlags::PROT_NONE)? };

        let accessed_pages = RefCell::new(AccessedPages::new(num_pages));
        let dirty_pages = RefCell::new(Vec::new());
        Ok(SigsegvMemoryTracker {
            memory_area,
            accessed_pages,
            dirty_pages,
            dirty_page_tracking,
        })
    }

    pub fn handle_sigsegv<'b, F>(
        &self,
        page_map: Option<&PageMap>,
        access_kind: AccessKind,
        page_init: F,
        fault_address: *mut libc::c_void,
    ) -> bool
    where
        F: Fn(PageNum) -> Option<&'b [u8]>,
    {
        match page_map {
            Some(page_map) => {
                if ENABLE_NEW_SIGNAL_HANDLER {
                    sigsegv_fault_handler_mmap(self, page_map, access_kind, fault_address)
                } else {
                    sigsegv_fault_handler_mprotect(self, &page_init, fault_address)
                }
            }
            None => sigsegv_fault_handler_mprotect(self, &page_init, fault_address),
        }
    }

    pub fn area(&self) -> &MemoryArea {
        &self.memory_area
    }

    pub fn expand(&self, delta: usize) {
        let old_size = self.area().size.get();
        self.area().size.set(old_size + delta);
        self.accessed_pages.borrow_mut().grow(delta);
    }

    pub fn dirty_pages(&self) -> Vec<*const libc::c_void> {
        self.dirty_pages.borrow().clone()
    }

    pub fn num_accessed_pages(&self) -> usize {
        self.accessed_pages.borrow().count()
    }

    pub fn num_dirty_pages(&self) -> usize {
        self.dirty_pages.borrow().len()
    }

    fn page_index_from(&self, addr: *mut libc::c_void) -> PageIndex {
        let page_start_mask = !(*PAGE_SIZE as usize - 1);
        let page_start_addr = (addr as usize) & page_start_mask;

        let page_index = (page_start_addr - self.memory_area.addr() as usize) / *PAGE_SIZE;
        PageIndex::new(page_index as u64)
    }

    fn page_start_addr_from(&self, page_index: PageIndex) -> *mut libc::c_void {
        let page_start_addr =
            self.memory_area.addr() as usize + page_index.get() as usize * *PAGE_SIZE;
        page_start_addr as *mut libc::c_void
    }

    fn has_already_accessed(&self, page_index: PageIndex) -> bool {
        let accessed_pages = self.accessed_pages.borrow();
        accessed_pages
            .get(page_index.get() as usize)
            .unwrap_or(false)
    }

    fn mark_range_as_accessed(&self, range: &Range<PageIndex>) {
        let mut accessed_pages = self.accessed_pages.borrow_mut();
        let range = Range {
            start: range.start.get() as usize,
            end: range.end.get() as usize,
        };
        for i in range {
            accessed_pages.set(i);
        }
    }

    // Returns the largest prefix of the given range such that all pages there have
    // not been accessed yet.
    fn restrict_range_to_unaccessed_pages(&self, range: Range<PageIndex>) -> Range<PageIndex> {
        let range = range_intersection(&range, &self.page_range());
        let accessed_pages = self.accessed_pages.borrow();

        let start = range.start.get() as usize;
        let old_end = range.end.get() as usize;
        let mut end = start;
        while end < old_end {
            match accessed_pages.get(end) {
                None | Some(true) => break,
                Some(false) => {}
            }
            end += 1;
        }
        Range {
            start: PageIndex::new(start as u64),
            end: PageIndex::new(end as u64),
        }
    }

    fn page_range(&self) -> Range<PageIndex> {
        Range {
            start: PageIndex::new(0),
            end: PageIndex::new(self.memory_area.size() as u64 + 1),
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
pub fn sigsegv_fault_handler_mprotect<'a>(
    tracker: &SigsegvMemoryTracker,
    page_init: &dyn Fn(PageNum) -> Option<&'a [u8]>,
    fault_address: *mut libc::c_void,
) -> bool {
    // We need to handle page faults in units of pages(!). So, round faulting
    // address down to page boundary
    let fault_address_page_boundary = fault_address as usize & !(*PAGE_SIZE as usize - 1);

    let page_num = (fault_address_page_boundary - tracker.memory_area.addr() as usize) / *PAGE_SIZE;

    #[cfg(feature = "sigsegv_handler_debug")]
    eprintln!(
        "> Thread: {:?} sigsegv_fault_handler: base_addr = 0x{:x}, page_size = 0x{:x}, fault_address = 0x{:x}, fault_address_page_boundary = 0x{:x}, page = {}",
        std::thread::current().id(),
        tracker.memory_area.addr() as u64,
        *PAGE_SIZE,
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

    if tracker
        .accessed_pages
        .borrow()
        .get(page_num)
        .expect("page_num not found in accessed_pages")
    {
        // This page has already been accessed, hence this fault must be for writing.
        // Upgrade its protection to read+write.
        #[cfg(feature = "sigsegv_handler_debug")]
        eprintln!(
            "> sigsegv_fault_handler: page({}) is already faulted: mprotect(addr=0x{:x}, len=0x{:x}, prot=PROT_READ|PROT_WRITE)",
            page_num,
            fault_address_page_boundary, *PAGE_SIZE
        );
        unsafe {
            nix::sys::mman::mprotect(
                fault_address_page_boundary as *mut libc::c_void,
                *PAGE_SIZE,
                nix::sys::mman::ProtFlags::PROT_READ | nix::sys::mman::ProtFlags::PROT_WRITE,
            )
            .unwrap()
        };
        tracker
            .dirty_pages
            .borrow_mut()
            .push(fault_address_page_boundary as *const libc::c_void);
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
            *PAGE_SIZE
        );
        // Temporarily allow writes to the page, to populate contents with the right
        // data
        unsafe {
            nix::sys::mman::mprotect(
                fault_address_page_boundary as *mut libc::c_void,
                *PAGE_SIZE,
                nix::sys::mman::ProtFlags::PROT_READ | nix::sys::mman::ProtFlags::PROT_WRITE,
            )
            .unwrap()
        };
        // Page contents initialization is optional. For example, if the memory tracker
        // is set up for a memory area mmap-ed to a file, the contents of each
        // page will be initialized by the kernel from that file.
        if let Some(page) = page_init(page_num) {
            #[cfg(feature = "sigsegv_handler_debug")]
            eprintln!(
                "> sigsegv_fault_handler: setting page({}) contents to {}",
                page_num,
                show_bytes_compact(&page)
            );
            unsafe {
                std::ptr::copy_nonoverlapping(
                    page.as_ptr(),
                    fault_address_page_boundary as *mut u8,
                    *PAGE_SIZE,
                )
            };
        }
        // Now reduce the access privileges to read-only
        unsafe {
            nix::sys::mman::mprotect(
                fault_address_page_boundary as *mut libc::c_void,
                *PAGE_SIZE,
                nix::sys::mman::ProtFlags::PROT_READ,
            )
            .unwrap()
        };
        tracker.accessed_pages.borrow_mut().set(page_num);
    }
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
/// - as `accessed` the corresponding bit in `tracker.accessed_pages`.
/// - as `prot_flags` the corresponding protection flags of the mapping.
/// - as `ignore_dirty` the dirty page tracking mode of `tracker`.
/// - as `dirty` the indication that the page is in `tracker.dirty_pages`.
///
/// Then the following must hold before and after the signal handler runs:
/// A. `prot_flags=NONE <=> !accessed`,
/// B. `ignore_dirty and accessed => prot_flags=READ_WRITE`,
/// C. `!ignore_dirty and prot_flags=READ_WRITE <=> dirty`,
/// D. `!ignore_dirty and prot_flags=READ => !dirty`,
/// E. `!ignore_dirty and !dirty => prot_flags=READ`.
///
/// Invariant A ensures that we don't attempt to map the same page twice.
/// Invariant B boosts performance of messages that don't track dirty pages.
/// Invariants C, D, E ensure correct tracking of dirty pages.
///
/// To understand how a faulting page `P` is handled we need to consider where
/// its backing memory is coming from in `PageMap`. There are three cases:
/// 1. The corresponding memory is not in `PageMap` meaning that the canister
///    has never written to it.
/// 2. The corresponding memory is in the checkpoint file meaning that the
///    canister has not written to it since the last checkpoint.
/// 3. The corresponding memory is in `PageDelta`.
///
/// In the first two cases the handler tries to mmap `P` and a few of its
/// subsequent pages that have the same backing memory type with one syscall.
/// This optimization is referred to as prefetching in the code. Prefetching
/// is disabled if we are tracking dirty pages and the faulting access was a
/// write access.
///
/// The third case is handled similar to the old implementation with one
/// important optimization: if the faulting access is a write access and the
/// page has not been accessed yet, then it is mapped as `READ_WRITE` right away
/// without going through `READ_WRITE` => copy content => `READ` => `READ_WRITE`
/// like the old signal handler does.
pub fn sigsegv_fault_handler_mmap(
    tracker: &SigsegvMemoryTracker,
    page_map: &PageMap,
    access_kind: AccessKind,
    fault_address: *mut libc::c_void,
) -> bool {
    if !tracker.memory_area.is_within(fault_address) {
        // This memory tracker is not responsible for handling this address.
        return false;
    };

    let page_index = tracker.page_index_from(fault_address);

    match (access_kind, tracker.dirty_page_tracking) {
        (_, DirtyPageTracking::Ignore) => {
            // We don't care about dirty pages here, so we can set up the page mapping for
            // for multiple pages as read/write right away.
            let prefetch_range = range_from_count(page_index, MAX_PREFETCH_PAGES);
            let prefetch_range = tracker.restrict_range_to_unaccessed_pages(prefetch_range);
            mmap_unaccessed_pages(
                tracker,
                page_map,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                page_index,
                prefetch_range,
            );
        }
        (AccessKind::Read, DirtyPageTracking::Track) => {
            // Set up the page mapping as read-only in order to get a signal on subsequent
            // write accesses to track dirty pages. We can do this for multiple pages.
            let prefetch_range = range_from_count(page_index, MAX_PREFETCH_PAGES);
            let prefetch_range = tracker.restrict_range_to_unaccessed_pages(prefetch_range);
            mmap_unaccessed_pages(
                tracker,
                page_map,
                ProtFlags::PROT_READ,
                page_index,
                prefetch_range,
            );
        }
        (AccessKind::Write, DirtyPageTracking::Track) => {
            if tracker.has_already_accessed(page_index) {
                // We already have the read-only mapping set up for the page,
                // so we just need to allow writing.
                let page_start_addr = tracker.page_start_addr_from(page_index);
                unsafe {
                    nix::sys::mman::mprotect(
                        page_start_addr,
                        *PAGE_SIZE,
                        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                    )
                    .unwrap()
                };
            } else {
                // The first access to the page is a write access. This is a good case because
                // it allows us to set up read/write mapping right away.
                // Pass a single-page range instead of `prefetch_range` to disable prefetching,
                // because we need to intercept write accesses to other pages.
                let single_page_range = range_from_count(page_index, 1);
                mmap_unaccessed_pages(
                    tracker,
                    page_map,
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                    page_index,
                    single_page_range,
                );
            }
            tracker
                .dirty_pages
                .borrow_mut()
                .push(tracker.page_start_addr_from(page_index) as *const libc::c_void);
        }
    }
    true
}

// Sets up page mapping for the given `faulting_page` and its subsequent pages
// in `prefetch_range` using the backing memory from the given `page_map`.
fn mmap_unaccessed_pages(
    tracker: &SigsegvMemoryTracker,
    page_map: &PageMap,
    page_protection_flags: ProtFlags,
    faulting_page: PageIndex,
    prefetch_range: Range<PageIndex>,
) {
    assert!(prefetch_range.contains(&faulting_page));

    let memory_region = page_map.get_memory_region(faulting_page);
    match memory_region {
        MemoryRegion::Zeros(page_map_range) => {
            assert!(page_map_range.contains(&faulting_page));
            let mmap_range = range_intersection(&prefetch_range, &page_map_range);
            let start_addr = tracker.page_start_addr_from(mmap_range.start);
            let actual_addr = unsafe {
                mmap(
                    start_addr,
                    range_size_in_bytes(&mmap_range),
                    page_protection_flags,
                    MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
                    /* fd = */ -1,
                    /* offset = */ 0,
                )
                .unwrap()
            };
            assert_eq!(start_addr, actual_addr);
            tracker.mark_range_as_accessed(&mmap_range)
        }

        MemoryRegion::BackedByFile(page_map_range, FileDescriptor { fd }) => {
            assert!(page_map_range.contains(&faulting_page));
            let mmap_range = range_intersection(&prefetch_range, &page_map_range);
            let start_addr = tracker.page_start_addr_from(mmap_range.start);
            let start_offset_in_file = mmap_range.start.get() as usize * *PAGE_SIZE;
            let actual_addr = unsafe {
                mmap(
                    start_addr,
                    range_size_in_bytes(&mmap_range),
                    page_protection_flags,
                    MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
                    fd,
                    start_offset_in_file as i64,
                )
                .unwrap()
            };
            assert_eq!(start_addr, actual_addr);
            tracker.mark_range_as_accessed(&mmap_range);
        }

        MemoryRegion::BackedByPage(contents) => {
            // TODO(EXC-447): Implement prefetching of pages to improve performance here.
            let page_start_addr = tracker.page_start_addr_from(faulting_page);
            // Make the page writable because we are going to copy bytes.
            unsafe {
                nix::sys::mman::mprotect(
                    page_start_addr,
                    *PAGE_SIZE,
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                )
                .unwrap()
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    contents.as_ptr(),
                    page_start_addr as *mut u8,
                    *PAGE_SIZE,
                )
            };
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
                    nix::sys::mman::mprotect(page_start_addr, *PAGE_SIZE, ProtFlags::PROT_READ)
                        .unwrap()
                };
            }
            tracker.mark_range_as_accessed(&range_from_count(faulting_page, 1));
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
    (range.end.get() - range.start.get()) as usize * *PAGE_SIZE
}

fn range_from_count(page: PageIndex, count: usize) -> Range<PageIndex> {
    Range {
        start: page,
        end: PageIndex::new(page.get() + count as u64),
    }
}

#[allow(dead_code)]
#[cfg(feature = "sigsegv_handler_debug")]
pub(crate) fn show_bytes_compact(bytes: &[u8]) -> String {
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
