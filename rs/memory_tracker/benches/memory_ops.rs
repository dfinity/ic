use std::{fs::File, os::unix::fs::FileExt};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use memmap2::MmapOptions;
use rayon::prelude::*;

const DATA: &str = "rs/memory_tracker/benches/test-data/64KiB.txt";
const OPS: [usize; 1] = [100];
const THREADS: [usize; 4] = [1, 2, 4, 8];
const PAGE_SIZE: usize = 4096;
const WASM_PAGE_SIZE: usize = 64 * 1024;

fn mmap(file: &File) {
    // Calls `mmap` with `PROT_READ` and `MAP_PRIVATE`.
    let _mm = unsafe { MmapOptions::new().map_copy_read_only(file).unwrap() };
}

fn mmap_mprotect(file: &File) {
    // Calls `mmap` with `PROT_READ` and `MAP_PRIVATE`.
    let mm = unsafe { MmapOptions::new().map_copy_read_only(file).unwrap() };
    // Calls `mprotect` with `PROT_READ | PROT_WRITE`.
    let _mm = mm.make_mut().unwrap();
}

fn mmap_mprotect_read(file: &File) {
    // Calls `mmap` with `PROT_READ` and `MAP_PRIVATE`.
    let mm = unsafe { MmapOptions::new().map_copy_read_only(file).unwrap() };
    // Calls `mprotect` with `PROT_READ | PROT_WRITE`.
    let mm = mm.make_mut().unwrap();
    // Reads 64 KiB.
    for i in 0..64 / 4 {
        let _b = std::hint::black_box(mm[PAGE_SIZE * i]);
    }
}

fn mmap_mprotect_write(file: &File) {
    // Calls `mmap` with `PROT_READ` and `MAP_PRIVATE`.
    let mm = unsafe { MmapOptions::new().map_copy_read_only(file).unwrap() };
    // Calls `mprotect` with `PROT_READ | PROT_WRITE`.
    let mut mm = mm.make_mut().unwrap();
    // Makes 64 KiB copies on write.
    for i in 0..64 / 4 {
        mm[PAGE_SIZE * i] = 42;
    }
}

fn mmap_mprotect_read_write(file: &File) {
    // Calls `mmap` with `PROT_READ` and `MAP_PRIVATE`.
    let mm = unsafe { MmapOptions::new().map_copy_read_only(file).unwrap() };
    // Calls `mprotect` with `PROT_READ | PROT_WRITE`.
    let mut mm = mm.make_mut().unwrap();
    // Reads then makes 64 KiB copies on write.
    for i in 0..64 / 4 {
        mm[PAGE_SIZE * i] = mm[1 + PAGE_SIZE * i];
    }
}

fn mmap_read_write(file: &File) {
    // Calls `mmap` with `PROT_READ | PROT_WRITE` and `MAP_PRIVATE`.
    let mut mm = unsafe { MmapOptions::new().map_copy(file).unwrap() };
    // Reads then makes 64 KiB copies on write.
    for i in 0..64 / 4 {
        mm[PAGE_SIZE * i] = mm[1 + PAGE_SIZE * i];
    }
}

fn file_read_write(file: &File) {
    let mut buf = [0u8; WASM_PAGE_SIZE];
    file.read_exact_at(&mut buf, 0).unwrap();
    for i in 0..64 / 4 {
        buf[PAGE_SIZE * i] = buf[1 + PAGE_SIZE * i];
    }
}

fn bench(c: &mut Criterion, group_name: &str, routine: fn(&File)) {
    let mut group = c.benchmark_group(group_name);

    let file = File::open(DATA).unwrap();

    for ops in OPS {
        let input = vec![&file; ops];

        group.throughput(Throughput::Elements(ops as u64));

        group.bench_with_input(format!("iter/ops:{ops}"), &input, |b, i| {
            b.iter(|| {
                i.iter().for_each(|f| {
                    routine(f);
                })
            })
        });

        for threads in THREADS {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();

            group.bench_with_input(
                format!("par_iter/threads:{threads}/ops:{ops}"),
                &input,
                |b, i| {
                    b.iter(|| {
                        pool.install(|| {
                            i.par_iter().for_each(|f| {
                                routine(f);
                            })
                        })
                    })
                },
            );
        }
    }

    group.finish();
}

fn mmap_bench(c: &mut Criterion) {
    bench(c, "mmap", mmap);
}

fn mmap_mprotect_bench(c: &mut Criterion) {
    bench(c, "mmap_mprotect", mmap_mprotect);
}

fn mmap_mprotect_read_bench(c: &mut Criterion) {
    bench(c, "mmap_mprotect_read", mmap_mprotect_read);
}

fn mmap_mprotect_write_bench(c: &mut Criterion) {
    bench(c, "mmap_mprotect_write", mmap_mprotect_write);
}

fn mmap_mprotect_read_write_bench(c: &mut Criterion) {
    bench(c, "mmap_mprotect_read_write", mmap_mprotect_read_write);
}

fn mmap_read_write_bench(c: &mut Criterion) {
    bench(c, "mmap_read_write", mmap_read_write);
}

fn file_read_write_bench(c: &mut Criterion) {
    bench(c, "file_read_write", file_read_write);
}

criterion_group!(
    benches,
    mmap_bench,
    mmap_mprotect_bench,
    mmap_mprotect_read_bench,
    mmap_mprotect_write_bench,
    mmap_mprotect_read_write_bench,
    mmap_read_write_bench,
    file_read_write_bench,
);
criterion_main!(benches);
