use criterion::{black_box, criterion_group, criterion_main, Criterion};
use memory_tracker::*;

use libc::{self, c_void};
use nix::sys::mman::{mmap, MapFlags, ProtFlags};
use std::ptr;
use std::time::Duration;

use lazy_static::lazy_static;

use ic_logger::replica_logger::no_op_logger;
use ic_sys::PAGE_SIZE;

lazy_static! {
    static ref ZEROED_PAGE: Vec<u8> = vec![0; *PAGE_SIZE];
}

struct BenchData {
    ptr: *mut c_void,
    tracker: SigsegvMemoryTracker,
}

/// Test the first execution of the sigsegv handler for a memory address.
///
/// This is when a page is lazily mapped readonly.
fn criterion_fault_handler_sim_read(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("fault_handler");

    let ptr: *mut c_void = unsafe {
        mmap(
            ptr::null_mut(),
            *PAGE_SIZE,
            ProtFlags::PROT_NONE,
            MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE,
            0,
            0,
        )
        .unwrap()
    };

    group.bench_function("fault handler sim read", |bench| {
        bench.iter_with_setup(
            // Setup input data for measurement
            || BenchData {
                ptr,
                tracker: SigsegvMemoryTracker::new(ptr, *PAGE_SIZE, no_op_logger()).unwrap(),
            },
            // Do the actual measurement
            |data| {
                sigsegv_fault_handler(
                    black_box(&data.tracker),
                    &(|_| Some(&ZEROED_PAGE)),
                    black_box(data.ptr),
                )
            },
        )
    });
}

/// Test the second execution of the sigsegv handler for a memory address.
///
/// This is when a page previously mapped readonly is remapped as writeable.
fn criterion_fault_handler_sim_write(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("fault_handler");

    let ptr: *mut c_void = unsafe {
        mmap(
            ptr::null_mut(),
            *PAGE_SIZE,
            ProtFlags::PROT_NONE,
            MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE,
            0,
            0,
        )
        .unwrap()
    };

    group.bench_function("fault handler sim write", |bench| {
        bench.iter_with_setup(
            // Setup input data for measurement
            || {
                let data = BenchData {
                    ptr,
                    tracker: SigsegvMemoryTracker::new(ptr, *PAGE_SIZE, no_op_logger()).unwrap(),
                };

                sigsegv_fault_handler(&data.tracker, &(|_| Some(&ZEROED_PAGE)), data.ptr);

                data
            },
            // Do the actual measurement
            |data| {
                sigsegv_fault_handler(
                    black_box(&data.tracker),
                    &(|_| Some(&ZEROED_PAGE)),
                    black_box(data.ptr),
                )
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
