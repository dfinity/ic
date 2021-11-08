use super::{Page, PageAllocatorInner, PageInner, ALLOCATED_PAGES};
use ic_sys::{PageBytes, PageIndex};
use std::sync::Arc;

// A memory page allocated on the Rust heap.
#[derive(Debug)]
pub struct HeapBasedPage(PageBytes);

impl HeapBasedPage {
    fn new(contents: &PageBytes) -> Self {
        ALLOCATED_PAGES.inc();
        Self(*contents)
    }
}

impl Drop for HeapBasedPage {
    fn drop(&mut self) {
        ALLOCATED_PAGES.dec();
    }
}

impl PageInner for HeapBasedPage {
    type PageAllocatorInner = HeapBasedPageAllocator;

    fn contents<'a>(&'a self, _page_allocator: &'a Self::PageAllocatorInner) -> &'a PageBytes {
        &self.0
    }

    fn copy_from_slice<'a>(
        &'a mut self,
        offset: usize,
        slice: &[u8],
        _page_allocator: &'a Self::PageAllocatorInner,
    ) {
        (self.0[offset..offset + slice.len()]).copy_from_slice(slice);
    }
}

// A trivial allocator that delegates to the default
// Rust heap allocator.
#[derive(Debug, Default)]
pub struct HeapBasedPageAllocator {}

impl PageAllocatorInner for HeapBasedPageAllocator {
    type PageInner = HeapBasedPage;
    fn allocate(
        &self,
        pages: &[(PageIndex, &PageBytes)],
    ) -> Vec<(PageIndex, Page<Self::PageInner>)> {
        pages
            .iter()
            .map(|(page_index, contents)| {
                (*page_index, Page(Arc::new(HeapBasedPage::new(*contents))))
            })
            .collect()
    }
}
