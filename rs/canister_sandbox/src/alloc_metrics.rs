use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

pub(crate) static CURRENT: AtomicUsize = AtomicUsize::new(0);

pub struct MetricsAlloc {}

unsafe impl GlobalAlloc for MetricsAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let result = System.alloc(layout);
        if !result.is_null() {
            CURRENT.fetch_add(layout.size(), Relaxed);
        }
        result
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        CURRENT.fetch_sub(layout.size(), Relaxed);
    }
}
