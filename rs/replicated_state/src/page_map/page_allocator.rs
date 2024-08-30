use ic_sys::{PageBytes, PageIndex};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Debug,
    sync::atomic::{AtomicUsize, Ordering},
    sync::Arc,
};
mod page_bytes;

mod page_allocator_registry;

pub mod mmap;

use mmap::{PageAllocatorId, PageAllocatorInner, PageInner};

pub use self::page_allocator_registry::PageAllocatorRegistry;
use super::{FileDescriptor, FileOffset, PageAllocatorFileDescriptor};
use ic_sys::PAGE_SIZE;

static ALLOCATED_PAGES: PageCounter = PageCounter::new();

/// Any allocation that is larger than this threshold will be copied in parallel
/// instead of the sequential code for smaller allocations.
const MIN_MEMORY_ALLOCATION_FOR_PARALLEL_COPY: usize = 64 * 1024 * 1024;

/// A clonable wrapper around a 4KiB memory page implementation.
/// It is mostly immutable after creation with the only exception of `Buffer`
/// modifying privately owned pages. The only way to create a page is via a
/// `PageAllocator`.
///
/// Exported publicly for benchmarking.
#[derive(Debug)]
pub struct Page(Arc<PageInner>);

impl Page {
    /// Returns the contents of the page. The length of the slice is
    /// always equal to the page size.
    ///
    /// Use `page.contents().as_ptr()` to get a pointer to the
    /// beginning of the page.
    ///
    /// The given `page_allocator` must be the same as the one used for
    /// allocating this page. It serves as a witness that the content of the
    /// page is still valid.
    pub(super) fn contents(&self) -> &PageBytes {
        self.0.contents()
    }
}

/// We have to implement `Clone` manually because `#[derive(Clone)]` is confused
/// by the generic parameter even though it is wrapped in `Arc`.
impl Clone for Page {
    fn clone(&self) -> Page {
        Page(Arc::clone(&self.0))
    }
}

/// A clonable wrapper around a page allocator implementation.
/// The actual implementation is wrapped in an optional for two reasons:
/// 1) Cheap initialization: most PageMaps will not have dirty pages, so we can
///    safe a lot of redundant work by postponing the initialization of the
///    allocator until the actual allocation.
/// 2) PageMaps corresponding to checkpoints must have an empty page allocator
///    to prevent memory leaks. That's because such PageMaps may be kept in
///    memory for thousands of rounds by the state manager.
pub struct PageAllocator(Arc<PageAllocatorInner>);

/// We have to implement `Clone` manually because `#[derive(Clone)]` is confused
/// by the generic parameter even though it is wrapped in `Arc`.
impl Clone for PageAllocator {
    fn clone(&self) -> PageAllocator {
        PageAllocator(Arc::clone(&self.0))
    }
}

#[allow(clippy::new_without_default)]
impl PageAllocator {
    pub fn new(fd_factory: Arc<dyn PageAllocatorFileDescriptor>) -> Self {
        Self(Arc::new(PageAllocatorInner::new(fd_factory)))
    }

    pub fn new_for_testing() -> Self {
        Self(Arc::new(PageAllocatorInner::new_for_testing()))
    }

    /// Allocates multiple pages with the given contents.
    ///
    /// The provided page count must match exactly the number of items in the
    /// iterator. Knowing the page count beforehand allows the page allocator
    /// to optimize allocation.
    pub fn allocate(&self, pages: &[(PageIndex, &PageBytes)]) -> Vec<(PageIndex, Page)> {
        // If the pages that need to be allocated and copied are more than MIN_MEMORY_ALLOCATION_FOR_PARALLEL_COPY,
        // then we can call the fastpath allocator, which does parallel copying.
        if pages.len() * PAGE_SIZE >= MIN_MEMORY_ALLOCATION_FOR_PARALLEL_COPY {
            return PageAllocatorInner::allocate_fastpath(&self.0, pages);
        }
        PageAllocatorInner::allocate(&self.0, pages)
    }

    /// Returns a serialization-friendly representation of the page allocator.
    pub fn serialize(&self) -> PageAllocatorSerialization {
        self.0.serialize()
    }

    // If the page allocator with the given id has already been deserialized and
    // exists in the given `PageAllocatorRegistry`, then the function returns a
    // reference to that page allocator.
    // Otherwise, the function creates a new page allocator and registers it in the
    // given `PageAllocatorRegistry`.
    pub fn deserialize(
        page_allocator: PageAllocatorSerialization,
        registry: &PageAllocatorRegistry,
    ) -> Self {
        Self(PageAllocatorInner::deserialize(page_allocator, registry))
    }

    /// Returns a serialization-friendly representation of the given page-delta.
    /// The generic parameters simplify the usage with `PageDelta::iter()`.
    pub fn serialize_page_delta<'a, I>(&'a self, page_delta: I) -> PageDeltaSerialization
    where
        I: IntoIterator<Item = (PageIndex, &'a Page)>,
    {
        self.0.serialize_page_delta(page_delta)
    }

    /// Creates a page-delta from the given serialization-friendly
    /// representation.
    pub fn deserialize_page_delta(
        &self,
        page_delta: PageDeltaSerialization,
    ) -> Vec<(PageIndex, Page)> {
        PageAllocatorInner::deserialize_page_delta(&self.0, page_delta)
    }
}

struct PageCounter(AtomicUsize);

impl PageCounter {
    const fn new() -> Self {
        Self(AtomicUsize::new(0))
    }

    fn inc_by(&self, count: usize) {
        self.0.fetch_add(count, Ordering::Relaxed);
    }

    fn dec_by(&self, count: usize) {
        self.0.fetch_sub(count, Ordering::Relaxed);
    }

    fn get(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}

/// Returns the total number of tracked pages allocated at the moment.
pub fn allocated_pages_count() -> usize {
    ALLOCATED_PAGES.get()
}

/// Serialization-friendly representation of `PageAllocator`.
///
/// It contains sufficient information to reconstruct the page allocator
/// in another process ensuring that there are no two page allocators
/// with the same id.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PageAllocatorSerialization {
    pub id: PageAllocatorId,
    pub fd: FileDescriptor,
}

/// Serialization-friendly representation of an indexed page.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PageSerialization {
    pub index: PageIndex,
    #[serde(with = "page_bytes")]
    pub bytes: PageBytes,
}

/// Information for validating page contents.
///
/// If the page contains only zeros, then both fields are zeros.  Otherwise,
/// the fields specify any non-zero two-byte word within the page by the
/// word's index and value.
///
/// The mmap-based page allocator frees physical memory by punching holes in the
/// backing file. A subsequent access to an already a freed page (both in the
/// sandbox and the replica processes) does not cause a segmentation fault.
/// Instead, the page silently becomes a zero page. That is dangerous and may
/// cause silent data corruption.  That's why we use this validation to catch
/// use-after-free bugs.
///
/// This validation is also useful for checking that the page transfer between
/// the sandbox and the replica processes works properly.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq)]
pub struct PageValidation {
    // The index of a non-zero two-byte word in the page.
    // It is zero if no such word exists.
    pub non_zero_word_index: u16,
    // The value of a non-zero two-byte word specified by the index above.
    // It is zero if no such word exists.
    pub non_zero_word_value: u16,
}

/// Serialization-friendly representation of an mmap-based page.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MmapPageSerialization {
    pub page_index: PageIndex,
    pub file_offset: FileOffset,
    pub validation: PageValidation,
}

/// Serialization-friendly representation of `PageDelta`.
///
/// It contains sufficient information to reconstruct the page-delta
/// in another process. Note that he pages are backed by the file owned by the page allocator.
/// Each page is represented by its offset in the file. The length of the file is
/// sent along to simplify deserialization. It is guaranteed that the file
/// offsets of all pages are smaller than the length of the file.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PageDeltaSerialization {
    file_len: FileOffset,
    pages: Vec<MmapPageSerialization>,
}

impl PageDeltaSerialization {
    pub fn is_empty(&self) -> bool {
        let Self { file_len, pages } = self;
        *file_len == 0 && pages.is_empty()
    }
}

#[cfg(test)]
mod tests;
