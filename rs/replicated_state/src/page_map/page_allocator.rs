use ic_sys::{PageBytes, PageIndex};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Debug,
    sync::atomic::{AtomicUsize, Ordering},
    sync::Arc,
};
mod page_bytes;

// Exported publicly for benchmarking.
pub use heap::{HeapBasedPage, HeapBasedPageAllocator};

mod heap;
// MmapBasedPageAllocator currenly uses memfd_create that is
// available only on linux.
#[cfg(target_os = "linux")]
pub mod mmap;

#[cfg(target_os = "linux")]
mod default_implementation {
    pub use super::mmap::{MmapBasedPage, MmapBasedPageAllocator};
    // Exported publicly for benchmarking.
    // TODO(EXC-883): Re-enable with sandboxing after fixing crashes.
    pub type DefaultPageImpl = MmapBasedPage;
    pub type DefaultPageAllocatorImpl = MmapBasedPageAllocator;
}
#[cfg(not(target_os = "linux"))]
mod default_implementation {
    use super::{HeapBasedPage, HeapBasedPageAllocator};
    // Exported publicly for benchmarking.
    pub type DefaultPageImpl = HeapBasedPage;
    pub type DefaultPageAllocatorImpl = HeapBasedPageAllocator;
}
pub use default_implementation::*;

use super::{FileDescriptor, FileOffset};

static ALLOCATED_PAGES: PageCounter = PageCounter::new();

/// A clonable wrapper around a 4KiB memory page implementation.
/// It is mostly immutable after creation with the only exception of `Buffer`
/// modifying privately owned pages. The only way to create a page is via a
/// `PageAllocator`.
/// It is parameterized by the implementation type with the default value to
/// enable easy switching between heap-based and mmap-based implementations.
///
/// Exported publicly for benchmarking.
#[derive(Debug)]
pub struct Page<P: PageInner = DefaultPageImpl>(Arc<P>);

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
///
/// It is parameterized by the implementation type with the default value to
/// enable easy switching between heap-based and mmap-based implementations.
pub(super) struct PageAllocator<A: PageAllocatorInner = DefaultPageAllocatorImpl>(Arc<A>);

/// We have to implement `Clone` manually because `#[derive(Clone)]` is confused
/// by the generic parameter even though it is wrapped in `Arc`.
impl Clone for PageAllocator {
    fn clone(&self) -> PageAllocator {
        PageAllocator(Arc::clone(&self.0))
    }
}

impl<A: PageAllocatorInner> Default for PageAllocator<A> {
    fn default() -> PageAllocator<A> {
        PageAllocator(Arc::new(A::default()))
    }
}

impl<A: PageAllocatorInner> PageAllocator<A> {
    /// Allocates multiple pages with the given contents.
    ///
    /// The provided page count must match exactly the number of items in the
    /// iterator. Knowing the page count beforehand allows the page allocator
    /// to optimize allocation.
    ///
    /// The caller must ensure that the page allocator is initialized and
    /// provide the corresponding witness.
    pub(super) fn allocate(
        &self,
        pages: &[(PageIndex, &PageBytes)],
    ) -> Vec<(PageIndex, Page<A::PageInner>)> {
        A::allocate(&self.0, pages)
    }

    /// Returns a serialization-friendly representation of the page allocator.
    pub(super) fn serialize(&self) -> PageAllocatorSerialization {
        self.0.serialize()
    }

    /// Creates a page allocator from the given serialization-friendly
    /// representation.
    pub(super) fn deserialize(page_allocator: PageAllocatorSerialization) -> Self {
        Self(Arc::new(A::deserialize(page_allocator)))
    }

    /// Returns a serialization-friendly representation of the given page-delta.
    /// The generic parameters simplify the usage with `PageDelta::iter()`.
    pub(super) fn serialize_page_delta<'a, I>(&'a self, page_delta: I) -> PageDeltaSerialization
    where
        I: IntoIterator<Item = (PageIndex, &'a Page<A::PageInner>)>,
    {
        self.0.serialize_page_delta(page_delta)
    }

    /// Creates a page-delta from the given serialization-friendly
    /// representation.
    pub(super) fn deserialize_page_delta(
        &self,
        page_delta: PageDeltaSerialization,
    ) -> Vec<(PageIndex, Page<A::PageInner>)> {
        A::deserialize_page_delta(&self.0, page_delta)
    }
}

/// Exported publicly for benchmarking.
pub trait PageInner: Debug {
    type PageAllocatorInner;

    fn contents(&self) -> &PageBytes;

    fn copy_from_slice(&mut self, offset: usize, slice: &[u8]);
}

/// Exported publicly for benchmarking.
pub trait PageAllocatorInner: Debug + Default {
    type PageInner: PageInner;

    /// See the comments of the corresponding method in `PageAllocator`.
    fn allocate(
        page_allocator: &Arc<Self>,
        pages: &[(PageIndex, &PageBytes)],
    ) -> Vec<(PageIndex, Page<Self::PageInner>)>;

    /// See the comments of the corresponding method in `PageAllocator`.
    fn deserialize(serialized_page_allocator: PageAllocatorSerialization) -> Self;

    /// See the comments of the corresponding method in `PageAllocator`.
    fn serialize(&self) -> PageAllocatorSerialization;

    /// See the comments of the corresponding method in `PageAllocator`.
    fn serialize_page_delta<'a, I>(&'a self, page_delta: I) -> PageDeltaSerialization
    where
        I: IntoIterator<Item = (PageIndex, &'a Page<Self::PageInner>)>;

    /// See the comments of the corresponding method in `PageAllocator`.
    fn deserialize_page_delta(
        page_allocator: &Arc<Self>,
        page_delta: PageDeltaSerialization,
    ) -> Vec<(PageIndex, Page<Self::PageInner>)>;
}

struct PageCounter(AtomicUsize);

impl PageCounter {
    const fn new() -> Self {
        Self(AtomicUsize::new(0))
    }

    fn inc(&self) {
        self.inc_by(1);
    }

    fn inc_by(&self, count: usize) {
        self.0.fetch_add(count, Ordering::Relaxed);
    }

    fn dec(&self) {
        self.dec_by(1);
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
/// in another process. There are three possible cases:
/// - `Empty`: the page allocator doesn't exist and no pages were allocated.
/// - `Heap`: the page allocator is `HeapBasedPageAllocator`.
/// - `Mmap`: the page allocator is `MmapBasedPageAllocator` backed by a file
///   with the given file descriptor.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum PageAllocatorSerialization {
    Heap,
    Mmap(FileDescriptor),
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
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default)]
pub struct PageValidation {
    // The index of a non-zero two-byte word in the page.
    // It is zero if no such word exists.
    pub non_zero_word_index: u16,
    // The value of a non-zero two-byte word specified by the index above.
    // It is zero if no such word exists.
    pub non_zero_word_value: u16,
}

/// Serialization-friendly representation of an mmap-based page.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MmapPageSerialization {
    pub page_index: PageIndex,
    pub file_offset: FileOffset,
    pub validation: PageValidation,
}

/// Serialization-friendly representation of `PageDelta`.
///
/// It contains sufficient information to reconstruct the page-delta
/// in another process. Note that pages are created using a page allocator,
/// so the three cases here correspond to the three cases in `PageAllocator`:
/// - `Heap`: the pages are allocated on the Rust heap and can be sent to
///   another process only by copying the bytes.
/// - `Mmap`: the pages are backed by the file owned by the page allocator. Each
///   page is represented by its offset in the file. The length of the file is
///   sent along to simplify deserialization. It is guaranteed that the file
///   offsets of all pages are smaller than the length of the file.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum PageDeltaSerialization {
    Heap(Vec<PageSerialization>),
    Mmap {
        file_len: FileOffset,
        pages: Vec<MmapPageSerialization>,
    },
}

impl PageDeltaSerialization {
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Heap(pages) => pages.is_empty(),
            Self::Mmap { file_len, pages } => *file_len == 0 && pages.is_empty(),
        }
    }
}

#[cfg(test)]
mod tests;
