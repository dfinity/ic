use crate::page_map::{FileDescriptor, FileOffset};

use super::{
    Page, PageAllocatorInner, PageAllocatorSerialization, PageDeltaSerialization, PageInner,
    ALLOCATED_PAGES,
};
use cvt::cvt_r;
use ic_sys::{page_bytes_from_ptr, PageBytes, PageIndex, PAGE_SIZE};
use libc::{c_void, close, ftruncate64};
use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
use nix::sys::mman::{mmap, munmap, MapFlags, ProtFlags};
use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};

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
pub struct MmapBasedPage {
    ptr: *mut u8,
    offset: FileOffset,
}

// SAFETY: All shared pages are immutable.
unsafe impl Sync for MmapBasedPage {}
unsafe impl Send for MmapBasedPage {}

impl PageInner for MmapBasedPage {
    type PageAllocatorInner = MmapBasedPageAllocator;

    fn contents<'a>(&'a self, _page_allocator: &'a Self::PageAllocatorInner) -> &'a PageBytes {
        // SAFETY: The provided reference to the page allocator is a witness that the
        // underlying memory is still valid.
        unsafe { page_bytes_from_ptr(self, self.ptr) }
    }

    fn copy_from_slice<'a>(
        &'a mut self,
        offset: usize,
        slice: &[u8],
        _page_allocator: &'a Self::PageAllocatorInner,
    ) {
        assert!(offset + slice.len() <= PAGE_SIZE);
        // SAFETY: The provided reference to the page allocator is a witness that the
        // underlying memory is still valid. The mutable reference to self shows that
        // the page is privately owned.
        unsafe { std::ptr::copy_nonoverlapping(slice.as_ptr(), self.ptr.add(offset), slice.len()) };
    }
}

/// A page allocator that uses a memory-mapped file as a backing store of pages.
/// In the initial version the file is created in-memory using `memfd_create`,
/// so it works only on Linux. Future versions will use an actual file.
///
/// The design of the allocator is based on the idea of a region or a zone
/// allocator (https://en.wikipedia.org/wiki/Region-based_memory_management):
/// - allocate pages by growing the file and memory-mapping a new chunk.
/// - dropping page is a no-op and does not free the underlying memory.
/// - all memory is freed at once when the page allocator itself is dropped.
/// This approach works well with the checkpoints and allows us to avoid all
/// the complexity and inefficiency of maintaing a thread-safe free-list.
///
/// It is exported publicly for benchmarking.
#[derive(Debug)]
pub struct MmapBasedPageAllocator(Mutex<MmapBasedPageAllocatorCore>);

impl Default for MmapBasedPageAllocator {
    fn default() -> MmapBasedPageAllocator {
        MmapBasedPageAllocator::new()
    }
}

impl PageAllocatorInner for MmapBasedPageAllocator {
    type PageInner = MmapBasedPage;

    // See the comments of the corresponding method in `PageAllocator`.
    fn allocate(
        &self,
        pages: &[(PageIndex, &PageBytes)],
    ) -> Vec<(PageIndex, Page<Self::PageInner>)> {
        let mut core = self.0.lock().unwrap();
        // It would also be correct to increment the counters after all the
        // allocations, but doing it before gives better performance because
        // the core allocator can memory-map larger chunks.
        ALLOCATED_PAGES.inc_by(pages.len());
        core.allocated_pages += pages.len();
        pages
            .iter()
            .map(|(page_index, contents)| {
                let mut page = core.allocate_page();
                page.copy_from_slice(0, *contents, self);
                (*page_index, Page(Arc::new(page)))
            })
            .collect()
    }

    // See the comments of the corresponding method in `PageAllocator`.
    fn serialize(&self) -> PageAllocatorSerialization {
        let core = self.0.lock().unwrap();
        PageAllocatorSerialization::Mmap(FileDescriptor {
            fd: core.file_descriptor,
        })
    }

    // See the comments of the corresponding method in `PageAllocator`.
    fn deserialize(serialized_page_allocator: PageAllocatorSerialization) -> Self {
        match serialized_page_allocator {
            PageAllocatorSerialization::Mmap(file_descriptor) => Self::open(file_descriptor),
            PageAllocatorSerialization::Heap | PageAllocatorSerialization::Empty => {
                // This is really unreachable. See `serialize()`.
                unreachable!("Unexpected serialization of MmapBasedPageAllocator");
            }
        }
    }

    // See the comments of the corresponding method in `PageAllocator`.
    fn serialize_page_delta<'a, I>(&'a self, page_delta: I) -> PageDeltaSerialization
    where
        I: IntoIterator<Item = (PageIndex, &'a Page<Self::PageInner>)>,
    {
        let pages: Vec<(PageIndex, FileOffset)> = page_delta
            .into_iter()
            .map(|(page_index, page)| (page_index, page.0.offset))
            .collect();
        let core = self.0.lock().unwrap();
        PageDeltaSerialization::Mmap {
            file_len: core.file_len,
            pages,
        }
    }

    // See the comments of the corresponding method in `PageAllocator`.
    fn deserialize_page_delta(
        &self,
        page_delta: PageDeltaSerialization,
    ) -> Vec<(PageIndex, Page<Self::PageInner>)> {
        match page_delta {
            PageDeltaSerialization::Mmap { file_len, pages } => {
                let mut core = self.0.lock().unwrap();
                core.grow_for_deserialization(file_len);
                // File offsets of all pages are smaller than `file_len`, which means
                // that the precondition of `deserialize_page()` is fulfilled after
                // the call to `grow_for_deserialization(file_len)`.
                pages
                    .into_iter()
                    .map(|(page_index, file_offset)| {
                        let page = core.deserialize_page(file_offset);
                        (page_index, Page(Arc::new(page)))
                    })
                    .collect()
            }
            PageDeltaSerialization::Empty | PageDeltaSerialization::Heap(_) => {
                // This is really unreachable. See `serialize_page_delta()`.
                unreachable!("Unexpected serialization of page-delta in MmapBasedPageAllocator");
            }
        }
    }
}

impl MmapBasedPageAllocator {
    fn new() -> Self {
        Self(Mutex::new(MmapBasedPageAllocatorCore::new()))
    }

    fn open(file_descriptor: FileDescriptor) -> Self {
        Self(Mutex::new(MmapBasedPageAllocatorCore::open(
            file_descriptor,
        )))
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
    unsafe fn allocate_page(&mut self) -> MmapBasedPage {
        assert!(!self.is_empty());
        let ptr = self.start;
        let offset = self.offset;
        self.start = self.start.add(PAGE_SIZE);
        self.offset += PAGE_SIZE as FileOffset;
        MmapBasedPage { ptr, offset }
    }
}

/// The actual allocator implementation. It starts with an empty file, an
/// emty set of memory-mapped `Chunk`s, and an empty allocation area.
/// Allocation has two paths: slow and fast.
///
/// The slow path is taken when the bump-pointer allocation area is empty. In
/// that case the file grows by N pages. Those new pages are memory-mapped into
/// a new `Chunk`. The allocation area is set to the whole extent of the new
/// `Chunk`. The number of new pages N is not constant. It grows proportionaly
/// to the number of already allocated pages to ensure that the number of
/// expensive `mmap` operations remains low - O(log(allocated_pages)).
///
/// The fast path simply increments the `start` pointer in the allocation area.
/// It is expected that almost all pages take the fast path.
#[derive(Debug)]
struct MmapBasedPageAllocatorCore {
    // The bump-pointer allocation area.
    allocation_area: AllocationArea,
    // The number of already allocated pages.
    allocated_pages: usize,
    // The descriptor of the backing file.
    file_descriptor: RawFd,
    // The length of the backing file.
    file_len: FileOffset,
    // The memory-mapped chunks. We need to remember them so that we can unmap them on drop.
    chunks: Vec<Chunk>,
}

impl Drop for MmapBasedPageAllocatorCore {
    fn drop(&mut self) {
        for chunk in self.chunks.iter() {
            let ptr = chunk.ptr as *mut c_void;
            // SAFETY: The chunk was created using `mmap`, so `munmap` should work.
            unsafe { munmap(ptr, chunk.size) }.unwrap_or_else(|_| {
                panic!(
                    "MmapPageAllocator failed to munmap {} bytes at address {:?} for memory file #{}",
                    chunk.size, chunk.ptr, self.file_descriptor
                )
            });
        }
        // SAFETY: the file descriptor is valid. We need `cvt_r` to handle `EINTR`.
        cvt_r(|| unsafe { close(self.file_descriptor) }).unwrap_or_else(|_| {
            panic!(
                "MmapPageAllocator failed to close the memory file #{}",
                self.file_descriptor
            )
        });
        ALLOCATED_PAGES.dec_by(self.allocated_pages);
    }
}

impl MmapBasedPageAllocatorCore {
    fn new() -> Self {
        let fd = memfd_create(&CString::default(), MemFdCreateFlag::empty())
            .expect("MmapPageAllocatorCore failed to create a memory file");
        Self::open(FileDescriptor { fd })
    }

    fn open(file_descriptor: FileDescriptor) -> Self {
        Self {
            allocation_area: Default::default(),
            allocated_pages: 0,
            file_descriptor: file_descriptor.fd,
            file_len: 0,
            chunks: vec![],
        }
    }

    fn allocate_page(&mut self) -> MmapBasedPage {
        if self.allocation_area.is_empty() {
            // Slow path of allocation.
            self.allocation_area = self.new_allocation_area();
            assert!(!self.allocation_area.is_empty());
        }
        // Fast path of allocation.
        // SAFETY: the allocation area is backed by the most recently
        // allocated `Chunk`. We also know that it is not empty.
        unsafe { self.allocation_area.allocate_page() }
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

        self.file_len += mmap_size as i64;
        // SAFETY: The file descriptor is valid.  We need `cvt_r` to handle `EINTR`.
        cvt_r(|| unsafe { ftruncate64(self.file_descriptor, self.file_len) }).unwrap_or_else(
            |_| {
                panic!(
                    "MmapPageAllocator failed to grow the memory file #{} to {} bytes",
                    self.file_descriptor, self.file_len
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
        .unwrap_or_else(|_| {
            panic!(
                "MmapPageAllocator failed to mmap {} bytes to memory file #{} \
                 at offset {} while allocating a new memory block",
                mmap_size, self.file_descriptor, mmap_file_offset,
            )
        }) as *mut u8;
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
        if file_len <= self.file_len {
            return;
        }

        let mmap_size = (file_len - self.file_len) as usize;
        let mmap_file_offset = self.file_len;
        self.file_len = file_len;

        // The mapping is read-only because all pages are already initialized in the
        // file and are immutable.
        // SAFETY: The parameters are valid.
        let mmap_ptr = unsafe {
            mmap(
                std::ptr::null_mut(),
                mmap_size,
                ProtFlags::PROT_READ,
                MapFlags::MAP_SHARED,
                self.file_descriptor,
                mmap_file_offset,
            )
        }
        .unwrap_or_else(|_| {
            panic!(
                "MmapPageAllocator failed to mmap {} bytes to memory file #{} \
                         at offset {} for deserialization",
                mmap_size, self.file_descriptor, mmap_file_offset,
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
    fn deserialize_page(&self, file_offset: FileOffset) -> MmapBasedPage {
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
                return MmapBasedPage {
                    ptr: page_start,
                    offset: file_offset,
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
