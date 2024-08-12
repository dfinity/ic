use crate::page_map::{
    FileDescriptor, FileOffset, PageAllocatorFileDescriptor, TestPageAllocatorFileDescriptorImpl,
};

use super::page_allocator_registry::PageAllocatorRegistry;
use super::{
    MmapPageSerialization, Page, PageAllocatorSerialization, PageDeltaSerialization,
    PageValidation, ALLOCATED_PAGES,
};
use cvt::{cvt, cvt_r};
use ic_sys::{page_bytes_from_ptr, PageBytes, PageIndex, PAGE_SIZE};
use ic_utils::deterministic_operations::deterministic_copy_from_slice;
use libc::{c_void, close};
use nix::sys::mman::{madvise, mmap, munmap, MapFlags, MmapAdvise, ProtFlags};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::os::raw::c_int;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(target_os = "linux")]
use ic_sys::HUGE_PAGE_SIZE;
#[cfg(target_os = "linux")]
use ic_types::NumOsPages;
/// The minimum number of huge pages where the actual huge page optimization
/// will kick in. This corresponds to 64 MiB of memory (because the huge page size is 2 MiB)
#[cfg(target_os = "linux")]
const MIN_NUM_HUGE_PAGES_FOR_OPTIMIZATION: NumOsPages = NumOsPages::new(32);

const MIN_PAGES_TO_FREE: usize = 10000;
// The start address of a page.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct PagePtr(*mut u8);

// SAFETY: All shared pages are immutable.
unsafe impl Sync for PagePtr {}
unsafe impl Send for PagePtr {}

/// A memory-mapped page of size 4KiB starting at the address specified by the
/// `ptr` field. It is mostly immutable after creation with the only exception
/// of `Buffer` modifying privately owned pages. The immutability is important
/// for `Send` and `Sync`.
///
/// The only way to create such a page is via `MmapBasedPageAllocator`, which
/// actually owns the backing store of the page. That's why all operations that
/// access the page contents requires a reference to the page allocator.
///
/// It is exported publicly for benchmarking.
#[derive(Clone, Debug)]
pub struct PageInner {
    ptr: PagePtr,
    offset: FileOffset,
    // The page allocator is needed only in the destructor of the page in order
    // to enqueue the page for freeing. This field is empty if the page allocator
    // does not own the backing file.
    page_allocator: Option<Arc<PageAllocatorInner>>,
    validation: PageValidation,
}

impl Drop for PageInner {
    fn drop(&mut self) {
        if let Some(page_allocator) = self.page_allocator.as_ref() {
            page_allocator.add_dropped_page(self.ptr);
        }
    }
}

impl PageInner {
    pub fn contents(&self) -> &PageBytes {
        // SAFETY: The provided reference to the page allocator is a witness that the
        // underlying memory is still valid.
        unsafe {
            assert!(self.is_valid());
            page_bytes_from_ptr(self, self.ptr.0)
        }
    }

    fn copy_from_slice(&mut self, offset: usize, slice: &[u8]) {
        assert!(offset + slice.len() <= PAGE_SIZE);
        // SAFETY: The provided reference to the page allocator is a witness that the
        // underlying memory is still valid. The mutable reference to self shows that
        // the page is privately owned.
        unsafe {
            if self.validation.non_zero_word_value != 0 {
                // The branch optimizes for the common case when the page is
                // initialized immediately after allocation.
                assert!(self.is_valid());
            }
            // Manually copy page one byte at a time. Compiler is able to optimize this
            // better than std::ptr::copy_nonoverlapping().
            deterministic_copy_from_slice(
                std::slice::from_raw_parts_mut(self.ptr.0.add(offset), slice.len()),
                slice,
            );
            // Update the validation information if it wasn't initialized yet or
            // became invalid.
            if self.validation.non_zero_word_value == 0 || !self.is_valid() {
                self.validation = self.compute_validation();
            }
        };
    }
    // See the comments of `PageValidation`.
    #[inline]
    unsafe fn is_valid(&self) -> bool {
        let ptr = self.ptr.0 as *const u16;
        *ptr.add(self.validation.non_zero_word_index as usize)
            == self.validation.non_zero_word_value
    }

    // See the comments of `PageValidation`.
    unsafe fn compute_validation(&self) -> PageValidation {
        // Search for the first non-zero 8-byte word.
        let mut ptr = self.ptr.0 as *const u64;
        let end = self.ptr.0.add(PAGE_SIZE) as *const u64;
        while ptr != end && *ptr == 0 {
            ptr = ptr.add(1);
        }
        if ptr == end {
            // The page contains only zeros.
            return PageValidation::default();
        }
        // We found the non-zero 8-byte word. Now find the non-zero two-byte
        // word within it. The `while` loop below is guaranteed to stop after
        // at most four steps.
        let mut ptr = ptr as *const u16;
        while *ptr == 0 {
            ptr = ptr.add(1);
        }
        PageValidation {
            non_zero_word_index: ptr.offset_from(self.ptr.0 as *const u16) as u16,
            non_zero_word_value: *ptr,
        }
    }
}

/// A page allocator that uses a memory-mapped file as a backing store of pages.
///
/// On Linux the page allocator uses `memfd_create` to create the file in memory.
/// Since MacOS does not support `memfd_create`, the page allocator falls back
/// to a temporary file.
///
/// The design of the allocator is based on the idea of a region or a zone
/// allocator (https://en.wikipedia.org/wiki/Region-based_memory_management):
/// - allocate pages by growing the file and memory-mapping a new chunk.
/// - the physical memory of a dropped page is freed using `madvise` when
///   there is sufficient number of dropped pages.
/// - all virtual memory is freed at once the page allocator itself is dropped.
///
/// This approach works well with the checkpoints and allows us to avoid all
/// the complexity and inefficiency of maintaining a thread-safe free-list.
///
/// It is exported publicly for benchmarking.
#[derive(Debug)]
pub struct PageAllocatorInner {
    // These two optional members cannot both be None at the same time.
    // The core allocator is None when there is no file descriptor created,
    // while the fd_factory can be None when the file descriptor is already created.
    core_allocator: Mutex<Option<MmapBasedPageAllocatorCore>>,
    fd_factory: Option<Arc<dyn PageAllocatorFileDescriptor>>,
}

impl PageAllocatorInner {
    // See the comments of the corresponding method in `PageAllocator`.
    pub fn allocate(
        page_allocator: &Arc<Self>,
        pages: &[(PageIndex, &PageBytes)],
    ) -> Vec<(PageIndex, Page)> {
        let mut guard = page_allocator.core_allocator.lock().unwrap();
        let allocator_creator = || {
            MmapBasedPageAllocatorCore::new(Arc::clone(page_allocator.fd_factory.as_ref().unwrap()))
        };
        let core = guard.get_or_insert_with(allocator_creator);
        // It would also be correct to increment the counters after all the
        // allocations, but doing it before gives better performance because
        // the core allocator can memory-map larger chunks.
        ALLOCATED_PAGES.inc_by(pages.len());
        core.allocated_pages += pages.len();
        pages
            .iter()
            .map(|(page_index, contents)| {
                let mut page = core.allocate_page(page_allocator);
                // Lint suggestion leads to non-compiling a bug. Rustc 1.65
                #[allow(clippy::explicit_auto_deref)]
                page.copy_from_slice(0, *contents);
                (*page_index, Page(Arc::new(page)))
            })
            .collect()
    }

    // This is the same functionality as `allocate`, but it uses rayon to parallelize
    // the copying of pages. This is useful when the number of pages is large.
    pub fn allocate_fastpath(
        page_allocator: &Arc<Self>,
        pages: &[(PageIndex, &PageBytes)],
    ) -> Vec<(PageIndex, Page)> {
        let mut guard = page_allocator.core_allocator.lock().unwrap();
        let allocator_creator = || {
            MmapBasedPageAllocatorCore::new(Arc::clone(page_allocator.fd_factory.as_ref().unwrap()))
        };
        let core = guard.get_or_insert_with(allocator_creator);
        // It would also be correct to increment the counters after all the
        // allocations, but doing it before gives better performance because
        // the core allocator can memory-map larger chunks.
        ALLOCATED_PAGES.inc_by(pages.len());
        core.allocated_pages += pages.len();

        // Collect page addresses to avoid locking and copying for every page.
        // This enables parallel copying of pages.
        let mut allocated_pages_vec: Vec<_> = pages
            .iter()
            .map(|(_, _)| core.allocate_page(page_allocator))
            .collect();

        // Copy the contents of the pages in parallel using rayon parallel iterators.
        // NB: the number of threads used are the same as the ones allocated when starting
        // the sandbox, controlled by the embedders_config.num_rayon_page_allocator_threads.
        allocated_pages_vec
            .par_iter_mut()
            .zip(pages.par_iter())
            .for_each(|(allocated_page, delta_page)| {
                allocated_page.copy_from_slice(0, delta_page.1);
            });

        allocated_pages_vec
            .into_iter()
            .zip(pages)
            .map(|(allocated_page, delta_page)| (delta_page.0, Page(Arc::new(allocated_page))))
            .collect()
    }

    // See the comments of the corresponding method in `PageAllocator`.
    pub fn serialize(&self) -> PageAllocatorSerialization {
        let mut guard = self.core_allocator.lock().unwrap();
        let allocator_creator =
            || MmapBasedPageAllocatorCore::new(Arc::clone(self.fd_factory.as_ref().unwrap()));
        let core = guard.get_or_insert_with(allocator_creator);

        PageAllocatorSerialization {
            id: core.id,
            fd: FileDescriptor {
                fd: core.file_descriptor,
            },
        }
    }

    // If the page allocator with the given id has already been deserialized and
    // exists in the given `PageAllocatorRegistry`, then the function returns a
    // reference to that page allocator.
    // Otherwise, the function creates a new page allocator and registers it in the
    // given `PageAllocatorRegistry`.
    pub fn deserialize(
        serialized_page_allocator: PageAllocatorSerialization,
        registry: &PageAllocatorRegistry,
    ) -> Arc<Self> {
        let PageAllocatorSerialization { id, fd } = serialized_page_allocator;
        registry.lookup_or_insert_with(&id, || {
            Arc::new(Self::open(id, fd, BackingFileOwner::AnotherAllocator))
        })
    }

    // See the comments of the corresponding method in `PageAllocator`.
    pub fn serialize_page_delta<'a, I>(&'a self, page_delta: I) -> PageDeltaSerialization
    where
        I: IntoIterator<Item = (PageIndex, &'a Page)>,
    {
        let pages: Vec<_> = page_delta
            .into_iter()
            .map(|(page_index, page)| MmapPageSerialization {
                page_index,
                file_offset: page.0.offset,
                validation: page.0.validation,
            })
            .collect();
        let mut guard = self.core_allocator.lock().unwrap();
        let allocator_creator =
            || MmapBasedPageAllocatorCore::new(Arc::clone(self.fd_factory.as_ref().unwrap()));
        let core = guard.get_or_insert_with(allocator_creator);

        PageDeltaSerialization {
            file_len: core.file_len,
            pages,
        }
    }

    // See the comments of the corresponding method in `PageAllocator`.
    pub fn deserialize_page_delta(
        page_allocator: &Arc<PageAllocatorInner>,
        page_delta: PageDeltaSerialization,
    ) -> Vec<(PageIndex, Page)> {
        let mut guard = page_allocator.core_allocator.lock().unwrap();
        let core = guard.as_mut().unwrap();
        core.grow_for_deserialization(page_delta.file_len);
        core.deserialized_pages += page_delta.pages.len();
        // Deserialized pages are considered as allocated for the purposes of the metric.
        ALLOCATED_PAGES.inc_by(page_delta.pages.len());
        // File offsets of all pages are smaller than `file_len`, which means
        // that the precondition of `deserialize_page()` is fulfilled after
        // the call to `grow_for_deserialization(file_len)`.
        page_delta
            .pages
            .into_iter()
            .map(|ser| {
                let page = core.deserialize_page(&ser, page_allocator);
                (ser.page_index, Page(Arc::new(page)))
            })
            .collect()
    }
}

#[allow(clippy::new_without_default)]
impl PageAllocatorInner {
    /// One always needs to instantiate a PageAllocatorInner with a file descriptor factory
    /// which will serve as a backing file for the MmapBasedPageAllocator
    pub fn new(fd_factory: Arc<dyn PageAllocatorFileDescriptor>) -> Self {
        Self {
            core_allocator: Mutex::new(None),
            fd_factory: Some(fd_factory),
        }
    }

    pub fn new_for_testing() -> Self {
        Self {
            core_allocator: Mutex::new(None),
            fd_factory: Some(Arc::new(TestPageAllocatorFileDescriptorImpl::new())),
        }
    }

    fn open(
        id: PageAllocatorId,
        file_descriptor: FileDescriptor,
        backing_file_owner: BackingFileOwner,
    ) -> Self {
        Self {
            core_allocator: Mutex::new(Some(MmapBasedPageAllocatorCore::open(
                id,
                file_descriptor,
                backing_file_owner,
            ))),
            // We don't need a factory here because the file descriptor already exists
            fd_factory: None,
        }
    }

    // Adds the given page to the list of dropped pages that will be freed on the
    // next allocation.
    // Precondition: the page allocator must be the owner of the backing file.
    fn add_dropped_page(&self, page_ptr: PagePtr) {
        let dropped_pages = {
            let mut guard = self.core_allocator.lock().unwrap();
            let core = guard.as_mut().unwrap();
            assert_eq!(core.backing_file_owner, BackingFileOwner::CurrentAllocator);
            core.dropped_pages.push(page_ptr);
            if core.dropped_pages.len() > MIN_PAGES_TO_FREE {
                Some(std::mem::take(&mut core.dropped_pages))
            } else {
                None
            }
        };

        if let Some(dropped_pages) = dropped_pages {
            free_pages(dropped_pages);
        }
    }
}

/// A memory-mapped chunk that consists of multiple 4KiB pages.
#[derive(Debug)]
struct Chunk {
    ptr: *mut u8,
    size: usize,
    offset: FileOffset,
}

/// SAFETY: Shared pages are immutable .
unsafe impl Send for Chunk {}

/// A bump pointer allocation area in the recently memory-mapped `Chunk`.
/// Allocation is done by bumping the `start` pointer until it reaches the
/// `end` pointer.
#[derive(Debug)]
struct AllocationArea {
    start: *mut u8,
    end: *mut u8,
    offset: FileOffset,
}

/// SAFETY: Shared pages are immutable.
unsafe impl Send for AllocationArea {}

impl Default for AllocationArea {
    fn default() -> Self {
        Self {
            start: std::ptr::null_mut(),
            end: std::ptr::null_mut(),
            offset: 0,
        }
    }
}

impl AllocationArea {
    fn is_empty(&self) -> bool {
        self.start == self.end
    }

    // SAFETY: The caller must ensure that `self.start` and `self.end`
    // are backed a valid mutable memory.
    unsafe fn allocate_page(
        &mut self,
        page_allocator: Option<&Arc<PageAllocatorInner>>,
    ) -> PageInner {
        assert!(!self.is_empty());
        let ptr = PagePtr(self.start);
        let offset = self.offset;
        self.start = self.start.add(PAGE_SIZE);
        self.offset += PAGE_SIZE as FileOffset;
        PageInner {
            ptr,
            offset,
            page_allocator: page_allocator.cloned(),
            validation: PageValidation::default(),
        }
    }
}

/// The unique identifier of a page allocator. It is used to ensure the 1:1
/// correspondence of page allocators in the replica and sandbox processes.
/// If there was a 1:n correspondence, then that would cause data corruption
/// due to multiple page allocators in the sandbox process sharing the same
/// backing file.
/// See `PageAllocatorRegistry`.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageAllocatorId(usize);

impl Default for PageAllocatorId {
    fn default() -> Self {
        // Each active canister creates a few page allocators per a checkpoint
        // interval, so overflowing a 64-bit counter is practically impossible.
        static MONOTONICALLY_INCREASING_COUNTER: AtomicUsize = AtomicUsize::new(0);
        let id = MONOTONICALLY_INCREASING_COUNTER.fetch_add(1, Ordering::SeqCst);
        Self(id)
    }
}

// Indicates whether the backing file is owned by the current allocator or
// another allocator. The owner is responsible for freeing the physical memory
// of dropped pages by punching holes in the backing file.
#[derive(Debug, PartialEq)]
enum BackingFileOwner {
    CurrentAllocator,
    AnotherAllocator,
}

/// The actual allocator implementation. It starts with an empty file, an
/// empty set of memory-mapped `Chunk`s, and an empty allocation area.
/// Allocation has two paths: slow and fast.
///
/// The slow path is taken when the bump-pointer allocation area is empty. In
/// that case the file grows by N pages. Those new pages are memory-mapped into
/// a new `Chunk`. The allocation area is set to the whole extent of the new
/// `Chunk`. The number of new pages N is not constant. It grows proportionally
/// to the number of already allocated pages to ensure that the number of
/// expensive `mmap` operations remains low - O(log(allocated_pages)).
///
/// The fast path simply increments the `start` pointer in the allocation area.
/// It is expected that almost all pages take the fast path.
#[derive(Debug)]
struct MmapBasedPageAllocatorCore {
    // The unique id of the page allocator.
    id: PageAllocatorId,
    // The bump-pointer allocation area.
    allocation_area: AllocationArea,
    // The number of already allocated pages.
    allocated_pages: usize,
    // The number of deserialized pages.
    deserialized_pages: usize,
    // The descriptor of the backing file.
    file_descriptor: RawFd,
    // The length of the backing file.
    file_len: FileOffset,
    // The memory-mapped chunks. We need to remember them so that we can unmap them on drop.
    chunks: Vec<Chunk>,
    // Pages that are not longer used.
    dropped_pages: Vec<PagePtr>,
    // The owner of the backing file.
    backing_file_owner: BackingFileOwner,
}

impl Drop for MmapBasedPageAllocatorCore {
    fn drop(&mut self) {
        for chunk in self.chunks.iter() {
            let ptr = chunk.ptr as *mut c_void;
            // SAFETY: The chunk was created using `mmap`, so `munmap` should work.
            unsafe { munmap(ptr, chunk.size) }.unwrap_or_else(|err| {
                panic!(
                    "MmapPageAllocator failed to munmap {} bytes at address {:?} for memory file #{}: {}",
                    chunk.size, chunk.ptr, self.file_descriptor, err
                )
            });
        }
        // SAFETY: the file descriptor is valid. We need `cvt_r` to handle `EINTR`.
        cvt_r(|| unsafe { close(self.file_descriptor) }).unwrap_or_else(|err| {
            panic!(
                "MmapPageAllocator failed to close the memory file #{}: {}",
                self.file_descriptor, err
            )
        });
        ALLOCATED_PAGES.dec_by(self.allocated_pages);
        // Deserialized pages are considered as allocated for the purposes of the metric.
        ALLOCATED_PAGES.dec_by(self.deserialized_pages);
    }
}

impl MmapBasedPageAllocatorCore {
    fn new(fd_factory: Arc<dyn PageAllocatorFileDescriptor>) -> Self {
        // We get the file descriptor passed from the factory instantiated by the state manager.
        let fd = fd_factory.get_fd();

        Self::open(
            PageAllocatorId::default(),
            FileDescriptor { fd },
            BackingFileOwner::CurrentAllocator,
        )
    }

    fn open(
        id: PageAllocatorId,
        file_descriptor: FileDescriptor,
        backing_file_owner: BackingFileOwner,
    ) -> Self {
        let mut page_allocator = Self {
            id,
            allocation_area: Default::default(),
            allocated_pages: 0,
            deserialized_pages: 0,
            file_descriptor: file_descriptor.fd,
            file_len: 0,
            chunks: vec![],
            dropped_pages: vec![],
            backing_file_owner,
        };
        // SAFETY: The file descriptor is valid.
        let file_len = unsafe { get_file_length(file_descriptor.fd) };
        // Depending on how this page allocator is used, the existing pages in
        // the file may be deserialized later on. We need to prepare for that
        // potential deserialization.
        page_allocator.grow_for_deserialization(file_len);
        page_allocator
    }

    fn allocate_page(&mut self, page_allocator: &Arc<PageAllocatorInner>) -> PageInner {
        if self.allocation_area.is_empty() {
            // Slow path of allocation.
            self.allocation_area = self.new_allocation_area();
            assert!(!self.allocation_area.is_empty());
        }
        let page_allocator = match self.backing_file_owner {
            BackingFileOwner::CurrentAllocator => Some(page_allocator),
            BackingFileOwner::AnotherAllocator => None,
        };
        // Fast path of allocation.
        // SAFETY: the allocation area is backed by the most recently
        // allocated `Chunk`. We also know that it is not empty.
        unsafe { self.allocation_area.allocate_page(page_allocator) }
    }

    // Returns the number of pages that should be memory-mapped in the slow path of
    // allocation to reduce the number of `mmap` calls.
    fn get_amortized_chunk_size_in_pages(&self) -> usize {
        const MIN_CHUNK_SIZE_IN_PAGES: usize = 4;
        // Grow the chunk size proportionally to the already allocated pages.
        // The proportion is 1 to 1.
        self.allocated_pages.max(MIN_CHUNK_SIZE_IN_PAGES)
    }

    // The implementation of the slow path of allocation.
    fn new_allocation_area(&mut self) -> AllocationArea {
        let mmap_pages = self.get_amortized_chunk_size_in_pages();
        let mmap_size = mmap_pages * PAGE_SIZE;
        let mmap_file_offset = self.file_len;

        // SAFETY: The file descriptor is valid.
        let file_len = unsafe { get_file_length(self.file_descriptor) };

        // Allocation is the only operation that modifies the file size.
        // Ensure that the file size did not change since the last allocation.
        assert_eq!(file_len, self.file_len);

        self.file_len += mmap_size as i64;
        // SAFETY: The file descriptor is valid.  We need `cvt_r` to handle `EINTR`.
        cvt_r(|| unsafe { truncate_file(self.file_descriptor, self.file_len) }).unwrap_or_else(
            |err| {
                panic!(
                    "MmapPageAllocator failed to grow the memory file #{} to {} bytes: {}",
                    self.file_descriptor, self.file_len, err
                )
            },
        );

        // SAFETY: The parameters are valid.
        let mmap_ptr = unsafe {
            mmap(
                std::ptr::null_mut(),
                mmap_size,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED,
                self.file_descriptor,
                mmap_file_offset,
            )
        }
        .unwrap_or_else(|err| {
            panic!(
                "MmapPageAllocator failed to mmap {} bytes to memory file #{} \
                 at offset {} while allocating a new memory block: {}",
                mmap_size, self.file_descriptor, mmap_file_offset, err,
            )
        }) as *mut u8;

        // Do madvise transparent huge page performance optimization only on Linux.
        #[cfg(target_os = "linux")]
        {
            // Huge pages are 2MiB on x86_64. We only use huge pages for
            // memory allocations that are at least MIN_NUM_HUGE_PAGES_FOR_OPTIMIZATION huge pages (i.e., 64 MiB).
            if mmap_size >= MIN_NUM_HUGE_PAGES_FOR_OPTIMIZATION.get() as usize * HUGE_PAGE_SIZE {
                unsafe {
                    madvise(
                        mmap_ptr as *mut c_void,
                        mmap_size,
                        MmapAdvise::MADV_HUGEPAGE,
                    )
                }.unwrap_or_else(|err| {
                    // We don't need to panic, madvise failing is not a problem, 
                    // it will only mean that we are not using huge pages.
                    println!(
                    "MmapPageAllocator failed to madvise {} bytes at address {:?} for memory file #{}: {}",
                    mmap_size, mmap_ptr, self.file_descriptor, err
                    )
                });
            }
        }

        self.chunks.push(Chunk {
            ptr: mmap_ptr,
            size: mmap_size,
            offset: mmap_file_offset,
        });

        let start = mmap_ptr;
        // SAFETY: We memory-mapped exactly `mmap_size` bytes, so `end` points one byte
        // after the last byte of the chunk.
        let end = unsafe { mmap_ptr.add(mmap_size) };
        AllocationArea {
            start,
            end,
            offset: mmap_file_offset,
        }
    }

    // Ensures that that last chunk of the file up to the given length is
    // memory-mapped to allow deserialization of pages.
    fn grow_for_deserialization(&mut self, file_len: FileOffset) {
        if file_len == self.file_len {
            return;
        }
        if file_len < self.file_len {
            // This may happen if another thread already called `grow_for_deserialization`
            // while this thread was waiting for the lock. In that case the actual file
            // length is the same or is larger than the saved file length.
            let actual_file_len = unsafe { get_file_length(self.file_descriptor) };
            assert!(
                actual_file_len >= self.file_len,
                "The page allocator file was truncated: actual file_len = {}, new file_len = {}, old file_len = {}",
                actual_file_len,
                file_len,
                self.file_len
            );
            return;
        }
        let mmap_size = (file_len - self.file_len) as usize;
        let mmap_file_offset = self.file_len;
        self.file_len = file_len;

        // The mapping is read/write because freeing of pages uses `madvise()` with
        // `MADV_REMOVE`, which requires writable mapping.
        // SAFETY: The parameters are valid.
        let mmap_ptr = unsafe {
            mmap(
                std::ptr::null_mut(),
                mmap_size,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED,
                self.file_descriptor,
                mmap_file_offset,
            )
        }
        .unwrap_or_else(|err| {
            panic!(
                "MmapPageAllocator failed to mmap {} bytes to memory file #{} \
                         at offset {} for deserialization: {}",
                mmap_size, self.file_descriptor, mmap_file_offset, err,
            )
        }) as *mut u8;

        self.chunks.push(Chunk {
            ptr: mmap_ptr,
            size: mmap_size,
            offset: mmap_file_offset,
        });
    }

    // Returns a page that starts at the given file offset.
    // Precondition: the chunk containing the file offset must be already
    // memory-mapped in `grow_for_deserialization()`.
    fn deserialize_page(
        &self,
        serialized_page: &MmapPageSerialization,
        page_allocator: &Arc<PageAllocatorInner>,
    ) -> PageInner {
        let page_allocator = match self.backing_file_owner {
            BackingFileOwner::CurrentAllocator => Some(page_allocator),
            BackingFileOwner::AnotherAllocator => None,
        };
        let file_offset = serialized_page.file_offset;
        // Find the memory-mapped chunk that contains the given file offset.
        // For a file of length N bytes, there will be O(lg(N)) chunks because
        // allocation ensures that the chunk size increases exponentially.
        // New pages are likely to be in the last chunk, that's why we iterate
        // the chunks in the reverse order. The expected run-time is O(1).
        for chunk in self.chunks.iter().rev() {
            if chunk.offset <= file_offset && file_offset < chunk.offset + chunk.size as FileOffset
            {
                // If the start of the page is in the chunk, then the entire page must be in the
                // chunk.
                assert!(
                    file_offset + PAGE_SIZE as FileOffset
                        <= chunk.offset + chunk.size as FileOffset
                );
                // SAFETY: The chunk is memory-mapped, so the address range from `chunk.ptr` to
                // `chunk.ptr + chunk.size` is valid. The page is fully contained in that
                // address range.
                let page_start = unsafe { chunk.ptr.add((file_offset - chunk.offset) as usize) };
                return PageInner {
                    ptr: PagePtr(page_start),
                    offset: file_offset,
                    page_allocator: page_allocator.cloned(),
                    validation: serialized_page.validation,
                };
            }
        }
        // Unreachable based on the precondition.
        unreachable!(
            "Couldn't deserialize a page at offset {}. Current file length {}.",
            file_offset, self.file_len
        );
    }
}

// Free the memory of given range and punch a hole in the backing file.
// Preconditions:
// - the range is mapped as shared and writable.
// - the range is not empty.
unsafe fn madvise_remove(start_ptr: *mut u8, end_ptr: *mut u8) {
    let ptr = start_ptr as *mut c_void;
    let size = end_ptr.offset_from(start_ptr);
    assert!(size > 0);
    // MacOS does not support punching holes in the file with `MADV_REMOVE`.
    // On MacOS we use the closest option: `MADV_DONTNEED`.
    #[cfg(target_os = "linux")]
    let advise = MmapAdvise::MADV_REMOVE;
    #[cfg(not(target_os = "linux"))]
    let advise = MmapAdvise::MADV_DONTNEED;
    // SAFETY: the range is mapped as shared and writable by precondition.
    madvise(ptr, size as usize, advise).unwrap_or_else(|err| {
        panic!(
            "Failed to madvise a page range {:?}..{:?}:
        {}",
            start_ptr, end_ptr, err
        )
    });
}

// Frees the memory used by the given pages.
// Precondition:
// - each page is mapped as shared and writable.
fn free_pages(mut pages: Vec<PagePtr>) {
    if pages.is_empty() {
        return;
    }

    // Sort the pages to find contiguous page ranges.
    pages.sort_unstable();

    // The start and end of the current contiguous page range.
    let mut start_ptr = pages[0].0;
    // SAFETY: the page is valid.
    let mut end_ptr = unsafe { start_ptr.add(PAGE_SIZE) };

    for page_ptr in pages.into_iter() {
        if page_ptr.0 == end_ptr {
            // Extend the current page range.
            // SAFETY: the page is valid.
            end_ptr = unsafe { end_ptr.add(PAGE_SIZE) };
        } else {
            // Free the current page range and a start a new one.
            // SAFETY: the range consists of pages that mapped as shared and writable.
            unsafe { madvise_remove(start_ptr, end_ptr) }
            start_ptr = page_ptr.0;
            // SAFETY: the page is valid.
            end_ptr = unsafe { start_ptr.add(PAGE_SIZE) };
        }
    }

    // Free the last page range.
    // SAFETY: the range consists of pages that mapped as shared and writable.
    unsafe { madvise_remove(start_ptr, end_ptr) }
}

// A platform-specific function to truncate a file.
// On Linux it uses `ftruncate64()`.
// On MacOS it uses `ftruncate()` that accepts 64-bit offset.
#[cfg(target_os = "linux")]
unsafe fn truncate_file(fd: RawFd, offset: FileOffset) -> c_int {
    libc::ftruncate64(fd, offset)
}
#[cfg(not(target_os = "linux"))]
unsafe fn truncate_file(fd: RawFd, offset: FileOffset) -> c_int {
    libc::ftruncate(fd, offset)
}

// A platform-specific function to get the length of a file.
// On Linux it uses `fstat64()`.
// On MacOS it uses `fstat()` that returns 64-bit `st_size`.
#[cfg(target_os = "linux")]
unsafe fn get_file_length(fd: RawFd) -> FileOffset {
    let mut stat = std::mem::MaybeUninit::<libc::stat64>::uninit();
    cvt(libc::fstat64(fd, stat.as_mut_ptr())).unwrap_or_else(|err| {
        panic!(
            "MmapPageAllocator failed to get the length of the file #{}: {}",
            fd, err
        )
    });
    stat.assume_init().st_size
}
#[cfg(not(target_os = "linux"))]
unsafe fn get_file_length(fd: RawFd) -> FileOffset {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    cvt(libc::fstat(fd, stat.as_mut_ptr())).unwrap_or_else(|err| {
        panic!(
            "MmapPageAllocator failed get the length of the file #{}: {}",
            fd, err
        )
    });
    stat.assume_init().st_size
}

#[cfg(test)]
mod tests;
