use ic_sys::{PageBytes, PageIndex};
use std::{
    fmt::Debug,
    sync::atomic::{AtomicUsize, Ordering},
    sync::Arc,
};
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
    pub(super) fn contents<'a>(&'a self, page_allocator: &'a PageAllocator) -> &'a PageBytes {
        (self.0).contents(page_allocator.inner_ref())
    }

    /// Copies bytes from the given slice to the chunk that starts at
    /// the given offset. This is used by `Buffer` on privately owned
    /// pages, so the mutation is safe.
    ///
    /// The given `page_allocator` must be the same as the one used for
    /// allocating this page. It serves as a witness that the contents of the
    /// page is still valid.
    pub(super) fn copy_from_slice(
        &mut self,
        offset: usize,
        slice: &[u8],
        page_allocator: &PageAllocator,
    ) {
        Arc::get_mut(&mut self.0).unwrap().copy_from_slice(
            offset,
            slice,
            page_allocator.inner_ref(),
        );
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
pub(super) struct PageAllocator<A: PageAllocatorInner = DefaultPageAllocatorImpl>(Option<Arc<A>>);

/// We have to implement `Clone` manually because `#[derive(Clone)]` is confused
/// by the generic parameter even though it is wrapped in `Arc`.
impl Clone for PageAllocator {
    fn clone(&self) -> PageAllocator {
        PageAllocator(self.0.as_ref().map(|inner| Arc::clone(inner)))
    }
}

impl Default for PageAllocator {
    fn default() -> PageAllocator {
        PageAllocator(None)
    }
}

impl<A: PageAllocatorInner> PageAllocator<A> {
    /// Allocates multiple pages with the given contents.
    ///
    /// The provided page count must match exactly the number of items in the
    /// iterator. Knowing the page count beforehand allows the page allocator
    /// to optimize allocation.
    pub(super) fn allocate(
        &mut self,
        pages: &[(PageIndex, &PageBytes)],
    ) -> Vec<(PageIndex, Page<A::PageInner>)> {
        let initialized = self.ensure_initialized();
        self.allocate_initialized(initialized, pages)
    }

    /// This function is exposed to the parent module because of
    /// `PageMap::copy_page()` which cannot use `allocate()` function
    /// due to a borrow conflict of the page allocator:
    /// - it borrows the page allocator to get the contents of a page.
    /// - `allocate()` requires a mutable borrow of the page allocator.
    /// This is solved by splitting `allocate()` into two functions:
    /// `ensure_initialized()` and `allocate_initialized()`. The latter
    /// doesn't require a mutable borrow.
    pub(super) fn ensure_initialized(&mut self) -> InitializationWitness {
        self.0.get_or_insert(Arc::new(A::default()));
        InitializationWitness(())
    }

    /// This function is exposed because of `PageMap::copy_page()`. See the
    /// comment above.
    pub(super) fn allocate_initialized(
        &self,
        _initialized: InitializationWitness,
        pages: &[(PageIndex, &PageBytes)],
    ) -> Vec<(PageIndex, Page<A::PageInner>)> {
        self.inner_ref().allocate(pages)
    }

    /// Returns a reference to the actual implementation assuming that it is
    /// initialized. It doesn't require the initialization witness because
    /// `Page` uses it to perform runtime check of validity of the page
    /// allocator.
    fn inner_ref(&self) -> &A {
        self.0.as_ref().unwrap().as_ref()
    }
}

/// A helper to ensure that the caller of `allocate_initialized()` does not
/// forget to call `ensure_initialized()`.
pub(super) struct InitializationWitness(());

/// Exported publicly for benchmarking.
pub trait PageInner: Debug {
    type PageAllocatorInner;

    fn contents<'a>(&'a self, _page_allocator: &'a Self::PageAllocatorInner) -> &'a PageBytes;

    fn copy_from_slice<'a>(
        &'a mut self,
        offset: usize,
        slice: &[u8],
        _page_allocator: &'a Self::PageAllocatorInner,
    );
}

/// Exported publicly for benchmarking.
pub trait PageAllocatorInner: Debug + Default {
    type PageInner: PageInner;
    fn allocate(
        &self,
        pages: &[(PageIndex, &PageBytes)],
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

#[cfg(test)]
mod tests;
