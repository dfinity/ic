use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};

const PAGE_SIZE: usize = 4096;
const MIB: usize = 1024 * 1024;
const GIB: usize = 1024 * 1024 * 1024;
const TIB: usize = 1024 * 1024 * 1024 * 1024;
const OPS: u64 = 1;
const NUM_BITS: &[(&str, usize)] = &[
    ("64MiB", 64 * MIB / PAGE_SIZE),
    ("512MiB", 512 * MIB / PAGE_SIZE),
    ("1GiB", GIB / PAGE_SIZE),
    ("2GiB", 2 * GIB / PAGE_SIZE),
    ("4GiB", 4 * GIB / PAGE_SIZE),
    ("8GiB", 8 * GIB / PAGE_SIZE),
    ("64GiB", 64 * GIB / PAGE_SIZE),
    ("256GiB", 256 * GIB / PAGE_SIZE),
    ("512GiB", 512 * GIB / PAGE_SIZE),
    ("768GiB", 768 * GIB / PAGE_SIZE),
    ("1008GiB", 1008 * GIB / PAGE_SIZE),
    ("1TiB", TIB / PAGE_SIZE),
    ("2TiB", 2 * TIB / PAGE_SIZE),
];

fn bitvec_from_elem_false(num_bits: usize) {
    for _ in 0..OPS {
        let _bit_vec = black_box(bit_vec::BitVec::from_elem(black_box(num_bits), false));
    }
}

fn bitvec_from_elem_true(num_bits: usize) {
    for _ in 0..OPS {
        let _bit_vec = black_box(bit_vec::BitVec::from_elem(black_box(num_bits), true));
    }
}

fn bitvec_with_capacity(num_bits: usize) {
    for _ in 0..OPS {
        let mut bit_vec = black_box(bit_vec::BitVec::with_capacity(black_box(num_bits)));
        bit_vec.push(true);
        let _bit_vec = black_box(bit_vec);
    }
}

fn vec_from_elem_0(num_bits: usize) {
    let num_blocks = num_bits / u32::BITS as usize;
    for _ in 0..OPS {
        let _vec = black_box(std::vec::from_elem(0_u32, black_box(num_blocks)));
    }
}

fn from_elem_bench(c: &mut Criterion) {
    bench(c, "bitvec_from_elem_false", bitvec_from_elem_false);
    bench(c, "bitvec_from_elem_true", bitvec_from_elem_true);
    bench(c, "bitvec_with_capacity", bitvec_with_capacity);
    bench(c, "vec_from_elem_0", vec_from_elem_0);
}

fn bitvec_grow_false(num_bits: usize) {
    for _ in 0..OPS {
        let mut bit_vec = bit_vec::BitVec::new();
        bit_vec.grow(black_box(num_bits), false);
        let _bit_vec = black_box(bit_vec);
    }
}

fn bitvec_grow_true(num_bits: usize) {
    for _ in 0..OPS {
        let mut bit_vec = bit_vec::BitVec::new();
        bit_vec.grow(black_box(num_bits), true);
        let _bit_vec = black_box(bit_vec);
    }
}

fn bitvec_reserve(num_bits: usize) {
    for _ in 0..OPS {
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

fn bench(c: &mut Criterion, group_name: &str, routine: fn(usize)) {
    let mut group = c.benchmark_group(group_name);

    for (id, num_bits) in NUM_BITS {
        group.throughput(Throughput::Elements(OPS));

        group.bench_function(format!("bits:{id}/ops:{OPS}"), |b| {
            b.iter(|| {
                routine(*num_bits);
            })
        });
    }

    group.finish();
}

criterion_group!(benches, from_elem_bench, resize_bench);
criterion_main!(benches);
