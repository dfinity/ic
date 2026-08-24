use criterion::{Criterion, black_box, criterion_group, criterion_main};
use ic_types::{NumBytes, NumOsPages};
use memory_tracker::{
    AccessKind, DeterministicMemoryTracker, DirtyPageTracking, MemoryLimits,
    signal_mutex::SignalMutex,
};

use libc::{self, c_void};
use nix::sys::mman::{MapFlags, ProtFlags, mmap_anonymous};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use ic_logger::replica_logger::no_op_logger;
use ic_replicated_state::PageMap;
use ic_replicated_state::canister_state::WASM_PAGE_SIZE_IN_BYTES;
use ic_sys::PAGE_SIZE;

struct BenchData {
    ptr: *mut c_void,
    tracker: DeterministicMemoryTracker,
}

/// The tracker maps memory in units of Wasm pages, so the tracked region must
/// span a whole Wasm page.
fn tracked_region() -> *mut c_void {
    unsafe {
        mmap_anonymous(
            None,
            NonZeroUsize::new(WASM_PAGE_SIZE_IN_BYTES).expect("mmap length must be non-zero"),
            ProtFlags::PROT_NONE,
            MapFlags::MAP_PRIVATE,
        )
        .unwrap()
    }
    .as_ptr()
}

/// Creates a tracker over `ptr`, which resets the whole region to `PROT_NONE`.
fn new_tracker(ptr: *mut c_void) -> DeterministicMemoryTracker {
    DeterministicMemoryTracker::new(
        ptr,
        NumBytes::new(WASM_PAGE_SIZE_IN_BYTES as u64),
        no_op_logger(),
        DirtyPageTracking::Track,
        PageMap::new_for_testing(),
        MemoryLimits {
            max_memory_size: NumBytes::new(WASM_PAGE_SIZE_IN_BYTES as u64),
            max_dirty_pages: NumOsPages::new((WASM_PAGE_SIZE_IN_BYTES / PAGE_SIZE) as u64),
        },
        /* page_overhead */ 0,
        Arc::new(SignalMutex::new(|_| {})),
    )
    .unwrap()
}

/// Test the first execution of the sigsegv handler for a memory address.
///
/// This is when a page is lazily mapped readonly.
fn criterion_fault_handler_sim_read(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("fault_handler");

    let ptr = tracked_region();

    group.bench_function("fault handler sim read", |bench| {
        bench.iter_with_setup(
            // Setup input data for measurement
            || BenchData {
                ptr,
                tracker: new_tracker(ptr),
            },
            // Do the actual measurement
            |data| {
                black_box(&data.tracker).handle_sigsegv(Some(AccessKind::Read), black_box(data.ptr))
            },
        )
    });
}

/// Test the second execution of the sigsegv handler for a memory address.
///
/// This is when a page previously mapped readonly is remapped as writeable.
fn criterion_fault_handler_sim_write(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("fault_handler");

    let ptr = tracked_region();

    group.bench_function("fault handler sim write", |bench| {
        bench.iter_with_setup(
            // Setup input data for measurement
            || {
                let data = BenchData {
                    ptr,
                    tracker: new_tracker(ptr),
                };

                data.tracker
                    .handle_sigsegv(Some(AccessKind::Read), data.ptr);

                data
            },
            // Do the actual measurement
            |data| {
                black_box(&data.tracker)
                    .handle_sigsegv(Some(AccessKind::Write), black_box(data.ptr))
            },
        )
    });
}

fn criterion_only_once() -> Criterion {
    // Maybe we need to disable warm-up?
    Criterion::default()
        .warm_up_time(Duration::from_millis(50))
        .sample_size(10)
}

criterion_group! {
    name = first_trap;
    config = criterion_only_once();
    targets = criterion_fault_handler_sim_read
}

criterion_group! {
    name = second_trap;
    config = criterion_only_once();
    targets = criterion_fault_handler_sim_write
}

criterion_main!(first_trap, second_trap);
