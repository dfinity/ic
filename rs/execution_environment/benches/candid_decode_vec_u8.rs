//! Benchmarks Candid decoding of a `Vec<u8>` (`vec nat8`) payload.
//!
//! The measured throughput is used to calibrate the number of instructions
//! charged per byte of a subnet message (management canister request)
//! payload, see `SUBNET_MESSAGE_INSTRUCTIONS_PER_PAYLOAD_BYTE` in
//! `rs/execution_environment/src/execution_environment.rs`: the constant is
//! chosen so that 2B instructions correspond to 1 second of decoding time.
//!
//! Run with:
//! ```
//! bazel run //rs/execution_environment:candid_decode_vec_u8_bench
//! ```

use candid::{Decode, Encode};
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;

fn candid_decode_vec_u8(c: &mut Criterion) {
    let mut group = c.benchmark_group("candid_decode_vec_u8");
    for size in [KIB, 64 * KIB, MIB, 2 * MIB, 10 * MIB] {
        let bytes: Vec<u8> = (0..size).map(|i| i as u8).collect();
        let encoded = Encode!(&bytes).unwrap();
        group.throughput(Throughput::Bytes(encoded.len() as u64));
        group.bench_function(format!("{size}"), |b| {
            b.iter_batched(
                || encoded.clone(),
                |encoded| black_box(Decode!(&encoded, Vec<u8>).unwrap()),
                BatchSize::LargeInput,
            )
        });
    }
    group.finish();
}

criterion_group!(benchmarks, candid_decode_vec_u8);
criterion_main!(benchmarks);
