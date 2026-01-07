use std::cell::Cell;
use std::sync::Arc;

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use ic_replicated_state::PageIndex;
use ic_replicated_state::page_map::PageAllocator;
use ic_sys::{PAGE_SIZE, PageBytes};

// The number of threads doing allocation in parallel
// to simulate parallel execution of canisters.
const NUM_THREADS: u32 = 6;

// The number of `allocate()` calls per allocator to
// simulate the number of executed canisters on each thread.
const NUM_ALLOCATIONS: usize = 1;

fn bench_allocator(c: &mut Criterion) {
    let page = &[1u8; PAGE_SIZE];
    let mut group = c.benchmark_group("Allocate");
    for page_delta_mib in [2, 8, 32, 128, 512, 2048].iter().cloned() {
        let num_pages = page_delta_mib * 1024 * 1024 / PAGE_SIZE;
        let pages: Vec<(PageIndex, &PageBytes)> = (0..num_pages)
            .map(|i| (PageIndex::new(i as u64), page))
            .collect();
        let mut thread_pool = Cell::new(scoped_threadpool::Pool::new(NUM_THREADS));
        group.bench_function(
            format!(
                "allocation:{NUM_ALLOCATIONS}/page_delta:{page_delta_mib}MiB/pages:{}K",
                num_pages / 1024
            ),
            |b| {
                b.iter(|| {
                    thread_pool.get_mut().scoped(|scope| {
                        for _ in 0..NUM_THREADS {
                            scope.execute(|| {
                                let allocator = Arc::new(PageAllocator::new_for_testing());
                                // Allocate multiple times to simulate multiple executions.
                                for _ in 0..NUM_ALLOCATIONS {
                                    let pages = PageAllocator::allocate(&allocator, &pages[..]);
                                    black_box(pages);
                                }
                            });
                        }
                    });
                })
            },
        );
    }
    group.finish();
}

criterion_group! {
    name = benchmarks;
    config = Criterion::default().sample_size(10);
    targets = bench_allocator
}
criterion_main!(benchmarks);
