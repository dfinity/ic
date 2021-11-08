use std::sync::Arc;
use std::time::Duration;

use criterion::{black_box, BenchmarkId, Criterion};
use criterion_time::ProcessTime;
use ic_replicated_state::{
    page_map::{DefaultPageAllocatorImpl, HeapBasedPageAllocator, PageAllocatorInner},
    PageIndex,
};
use ic_sys::{PageBytes, PAGE_SIZE};

fn bench_allocator(c: &mut Criterion<ProcessTime>) {
    let page = &[1u8; PAGE_SIZE];
    let mut group = c.benchmark_group("Allocate");
    for n in [1usize, 10, 100, 1_000].iter().cloned() {
        let pages: Vec<(PageIndex, &PageBytes)> = (0..n)
            .into_iter()
            .map(|i| (PageIndex::new(i as u64), page))
            .collect();
        group.bench_function(BenchmarkId::new("HeapBasedPageAllocator", n), |b| {
            b.iter(|| {
                let allocator = Arc::new(HeapBasedPageAllocator::default());
                let pages = allocator.allocate(&pages[..]);
                black_box(pages);
            })
        });
        // We don't use mmap-based allocator directly because it is only available on
        // Linux for now. To avoid platform specific code here, we compare the
        // heap-based allocator with the default allocator, which can be either
        // the mmap-based allocator or the heap-based allocator.
        group.bench_function(BenchmarkId::new("DefaultPageAllocatorImpl", n), |b| {
            b.iter(|| {
                let allocator = Arc::new(DefaultPageAllocatorImpl::default());
                let pages = allocator.allocate(&pages[..]);
                black_box(pages);
            })
        });
    }
    group.finish();
}

fn main() {
    let mut c = Criterion::default()
        .with_measurement(ProcessTime::UserTime)
        .sample_size(10)
        .measurement_time(Duration::from_secs(20))
        .configure_from_args();
    bench_allocator(&mut c);
    c.final_summary();
}
