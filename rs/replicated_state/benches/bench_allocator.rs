use std::cell::Cell;
use std::sync::Arc;
use std::time::Duration;

use criterion::{black_box, BenchmarkId, Criterion};
use criterion_time::ProcessTime;
use ic_replicated_state::page_map::PageAllocator;
use ic_replicated_state::PageIndex;
use ic_sys::{PageBytes, PAGE_SIZE};

// The number of threads doing allocation in parallel
// to simulate parallel execution of canisters.
const NUM_THREADS: u32 = 4;

// The number of `allocate()` calls per allocator to
// simulate the number of rounds between checkpoints.
const NUM_ALLOCATIONS: usize = 100;

fn bench_allocator(c: &mut Criterion<ProcessTime>) {
    let page = &[1u8; PAGE_SIZE];
    let mut group = c.benchmark_group("Allocate");
    for n in [1usize, 10, 100, 1_000].iter().cloned() {
        let pages: Vec<(PageIndex, &PageBytes)> =
            (0..n).map(|i| (PageIndex::new(i as u64), page)).collect();
        let mut thread_pool = Cell::new(scoped_threadpool::Pool::new(NUM_THREADS));
        group.bench_function(BenchmarkId::new("MmapBasedPageAllocator", n), |b| {
            b.iter(|| {
                thread_pool.get_mut().scoped(|scope| {
                    for _ in 0..NUM_THREADS {
                        scope.execute(|| {
                            let allocator = Arc::new(PageAllocator::new_for_testing());
                            // Allocate multiple times to simulate multiple rounds per checkpoint.
                            for _ in 0..NUM_ALLOCATIONS {
                                let pages = PageAllocator::allocate(&allocator, &pages[..]);
                                black_box(pages);
                            }
                        });
                    }
                });
            })
        });
    }
    group.finish();
}

fn main() {
    let mut c = Criterion::default()
        .with_measurement(ProcessTime::UserTime)
        .sample_size(10)
        .measurement_time(Duration::from_secs(40))
        .configure_from_args();
    bench_allocator(&mut c);
    c.final_summary();
}
