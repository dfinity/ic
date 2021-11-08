use self::heap::{HeapBasedPage, HeapBasedPageAllocator};
use ic_sys::PageBytes;
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    sync::Arc,
};

mod heap;

static ALLOCATED_PAGES: PageCounter = PageCounter::new();

type PageImpl = HeapBasedPage;
type PageAllocatorImpl = HeapBasedPageAllocator;

/// A clonable wrapper around a 4KiB memory page.
/// It is mostly immutable after creation with the only exception
/// of `Buffer` modifying privately owned pages.
/// The only way to create a page is via a `PageAllocator`.
#[derive(Clone, Debug)]
pub(super) struct Page(Arc<PageImpl>);

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
    pub(super) fn contents<'a>(&'a self, _page_allocator: &'a PageAllocator) -> &'a PageBytes {
        (self.0).contents()
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
        _page_allocator: &PageAllocator,
    ) {
        Arc::get_mut(&mut self.0)
            .unwrap()
            .copy_from_slice(offset, slice);
    }
}

/// A clonable wrapper around a page allocator.
#[derive(Clone)]
pub(super) struct PageAllocator(Arc<PageAllocatorImpl>);

impl PageAllocator {
    /// Allocates multiple pages with the given contents.
    pub(super) fn allocate(&self, pages: &[&PageBytes]) -> Vec<Page> {
        // TODO(EXC-537): Fuse the mapping into allocation.
        self.0.allocate(pages).into_iter().map(Page).collect()
    }
}

impl Default for PageAllocator {
    fn default() -> PageAllocator {
        PageAllocator(Arc::new(PageAllocatorImpl {}))
    }
}

struct PageCounter(AtomicUsize);

impl PageCounter {
    const fn new() -> Self {
        Self(AtomicUsize::new(0))
    }

    fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    fn dec(&self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }

    fn get(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}

/// Returns the total number of tracked pages allocated at the moment.
pub fn allocated_pages_count() -> usize {
    ALLOCATED_PAGES.get()
}
