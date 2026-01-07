use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use nix::sys::mman::{MapFlags, ProtFlags, mmap, munmap};

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;
const GIB: usize = 1024 * MIB;
const TIB: usize = 1024 * GIB;

const OS_PAGE_SIZE: usize = 4 * KIB;
const WASM_PAGE_SIZE: usize = 64 * KIB;
const MAX_ACCESSED_SIZE: usize = 2 * GIB;

#[repr(usize)]
#[derive(Copy, Clone)]
enum PageSize {
    Os = OS_PAGE_SIZE,
    Wasm = WASM_PAGE_SIZE,
}

/// Number of executions (per round per thread).
const NUM_EXECUTIONS: u64 = 100;

const MEMORY_SIZE: &[(&str, usize)] = &[
    ("1GiB", GIB),
    ("2GiB", 2 * GIB),
    ("4GiB", 4 * GIB),
    ("6GiB", 6 * GIB),
    ("8GiB", 8 * GIB),
    ("16GiB", 16 * GIB),
    ("512GiB", 512 * GIB),
    ("768GiB", 768 * GIB),
    ("1TiB", TIB),
    ("2TiB", 2 * TIB),
];

fn bitvec_from_elem_false(memory_size: usize, page_size: PageSize) {
    let num_bits = memory_size / page_size as usize;
    for _ in 0..NUM_EXECUTIONS {
        let _bit_vec = black_box(bit_vec::BitVec::from_elem(black_box(num_bits), false));
    }
}

fn bitvec_from_elem_true(memory_size: usize, page_size: PageSize) {
    let num_bits = memory_size / page_size as usize;
    for _ in 0..NUM_EXECUTIONS {
        let _bit_vec = black_box(bit_vec::BitVec::from_elem(black_box(num_bits), true));
    }
}

fn bitvec_with_capacity(memory_size: usize, page_size: PageSize) {
    let num_bits = memory_size / page_size as usize;
    for _ in 0..NUM_EXECUTIONS {
        let mut bit_vec = black_box(bit_vec::BitVec::with_capacity(black_box(num_bits)));
        bit_vec.push(true);
        let _bit_vec = black_box(bit_vec);
    }
}

fn vec_from_elem_0(memory_size: usize, page_size: PageSize) {
    let num_bits = memory_size / page_size as usize;
    let num_blocks = num_bits / u32::BITS as usize;
    for _ in 0..NUM_EXECUTIONS {
        let _vec = black_box(std::vec::from_elem(0_u32, black_box(num_blocks)));
    }
}

fn vec_from_mmap(memory_size: usize, page_size: PageSize) {
    let num_bits = memory_size / page_size as usize;
    let num_blocks = num_bits / u32::BITS as usize;
    let size = num_blocks * size_of::<u32>();
    for _ in 0..NUM_EXECUTIONS {
        let addr = unsafe {
            mmap(
                std::ptr::null_mut(),
                size,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_ANON,
                -1,
                0,
            )
            .unwrap()
        };
        let vec = black_box(unsafe { Vec::from_raw_parts(addr as *mut u32, 0, num_blocks) });
        let _manually_drop = std::mem::ManuallyDrop::new(vec);
        unsafe { munmap(addr, size).unwrap() }
    }
}

fn from_elem_bench(c: &mut Criterion) {
    bench(c, "bitvec_from_elem_false", bitvec_from_elem_false);
    bench(c, "bitvec_from_elem_true", bitvec_from_elem_true);
    bench(c, "bitvec_with_capacity", bitvec_with_capacity);
    bench(c, "vec_from_elem_0", vec_from_elem_0);
    bench(c, "vec_from_mmap", vec_from_mmap);
}

fn bitvec_grow_false(memory_size: usize, page_size: PageSize) {
    let num_bits = memory_size / page_size as usize;
    for _ in 0..NUM_EXECUTIONS {
        let mut bit_vec = bit_vec::BitVec::new();
        bit_vec.grow(black_box(num_bits), false);
        let _bit_vec = black_box(bit_vec);
    }
}

fn bitvec_grow_true(memory_size: usize, page_size: PageSize) {
    let num_bits = memory_size / page_size as usize;
    for _ in 0..NUM_EXECUTIONS {
        let mut bit_vec = bit_vec::BitVec::new();
        bit_vec.grow(black_box(num_bits), true);
        let _bit_vec = black_box(bit_vec);
    }
}

fn bitvec_reserve(memory_size: usize, page_size: PageSize) {
    let num_bits = memory_size / page_size as usize;
    for _ in 0..NUM_EXECUTIONS {
        let mut bit_vec = bit_vec::BitVec::new();
        bit_vec.reserve(black_box(num_bits));
        bit_vec.push(true);
        let _bit_vec = black_box(bit_vec);
    }
}

fn resize_bench(c: &mut Criterion) {
    bench(c, "bitvec_grow_false", bitvec_grow_false);
    bench(c, "bitvec_grow_true", bitvec_grow_true);
    bench(c, "bitvec_reserve", bitvec_reserve);
}

fn bitvec_worst_case_old(memory_size: usize, page_size: PageSize) {
    let max_bits = memory_size / page_size as usize;
    let max_accessed_pages = (MAX_ACCESSED_SIZE / page_size as usize).min(max_bits);
    for _ in 0..NUM_EXECUTIONS {
        let mut bit_vec = bit_vec::BitVec::from_elem(1, false);
        let mut accessed_list = Vec::new();
        let mut dirty_list = Vec::new();
        // Growing the BitVec to the max size.
        while bit_vec.len() < max_bits {
            let old_len = bit_vec.len();
            let diff = old_len.min(max_bits - old_len);
            bit_vec.grow(diff, false);
        }
        // Accessing and dirtying pages.
        for i in 0..max_accessed_pages {
            bit_vec.set(black_box(i), !bit_vec.get(i).unwrap_or(false));
            accessed_list.push(black_box(i));
            dirty_list.push(black_box(i));
        }
        let _bit_vec = black_box(bit_vec);
    }
}

fn bitvec_worst_case_new(memory_size: usize, page_size: PageSize) {
    let max_bits = memory_size / page_size as usize;
    let max_accessed_pages = (MAX_ACCESSED_SIZE / page_size as usize).min(max_bits);
    for _ in 0..NUM_EXECUTIONS {
        let mut bit_vec = bit_vec::BitVec::from_elem(max_bits, false);
        let mut accessed_list = Vec::with_capacity(max_accessed_pages);
        let mut dirty_list = Vec::with_capacity(max_accessed_pages);
        // Accessing and dirtying pages.
        for i in 0..max_accessed_pages {
            bit_vec.set(black_box(i), !bit_vec.get(i).unwrap_or(false));
            accessed_list.push(black_box(i));
            dirty_list.push(black_box(i));
        }
        let _bit_vec = black_box(bit_vec);
    }
}

fn bitvec_worst_case(memory_size: usize, page_size: PageSize) {
    match page_size {
        PageSize::Os => bitvec_worst_case_old(memory_size, page_size),
        PageSize::Wasm => bitvec_worst_case_new(memory_size, page_size),
    }
}

fn realistic_bench(c: &mut Criterion) {
    bench(c, "bitvec_worst_case", bitvec_worst_case);
}

fn bench(c: &mut Criterion, group_name: &str, routine: fn(usize, PageSize)) {
    let mut group = c.benchmark_group(group_name);

    for (size_str, memory_size) in MEMORY_SIZE {
        group.throughput(Throughput::Elements(NUM_EXECUTIONS));

        for page_size in [PageSize::Os, PageSize::Wasm] {
            let num_bits = memory_size / page_size as usize;
            group.bench_function(
                format!(
                    "memory_size:{size_str}/page_size:{}KiB/bits:{}Ki/executions:{NUM_EXECUTIONS}",
                    page_size as usize / KIB,
                    num_bits as f64 / 1024.0
                ),
                |b| {
                    b.iter(|| {
                        routine(*memory_size, page_size);
                    })
                },
            );
        }
    }

    group.finish();
}

criterion_group!(benches, from_elem_bench, resize_bench, realistic_bench);
criterion_main!(benches);
