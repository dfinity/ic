use super::ALLOCATED_PAGES;
use ic_sys::PageBytes;
use std::sync::Arc;

// A memory page allocated on the Rust heap.
#[derive(Debug)]
pub struct HeapBasedPage(PageBytes);

impl HeapBasedPage {
    fn new(contents: &PageBytes) -> Self {
        ALLOCATED_PAGES.inc();
        Self(*contents)
    }

    pub fn contents(&self) -> &PageBytes {
        &self.0
    }

    pub fn copy_from_slice(&mut self, offset: usize, slice: &[u8]) {
        (self.0[offset..offset + slice.len()]).copy_from_slice(slice);
    }
}

impl Drop for HeapBasedPage {
    fn drop(&mut self) {
        ALLOCATED_PAGES.dec();
    }
}

// A trivial allocator that delegates to the default
// Rust heap allocator.
pub struct HeapBasedPageAllocator {}

impl HeapBasedPageAllocator {
    pub fn allocate(&self, pages: &[&PageBytes]) -> Vec<Arc<HeapBasedPage>> {
        pages
            .iter()
            .map(|contents| Arc::new(HeapBasedPage::new(*contents)))
            .collect()
    }
}
