use criterion::measurement::Measurement;
use criterion::BatchSize::SmallInput;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion, Throughput};
use ic_crypto_sha256::Sha256;
use rand::prelude::*;
use std::convert::TryFrom;
use std::time::Duration;

const KIBIBYTE: u128 = 1024; // 2 ^ 10
const MEBIBYTE: u128 = 1_048_576; // 2 ^ 20

criterion_main!(benches);
criterion_group!(benches, bench_hash);

fn bench_hash(criterion: &mut Criterion) {
    let group = &mut criterion.benchmark_group("crypto_hash");

    group.sample_size(20);
    bench_sha256(group, "sha256_32_B", 32);
    bench_sha256(group, "sha256_1_KiB", KIBIBYTE);
    bench_sha256(group, "sha256_1_MiB", MEBIBYTE);
    bench_sha256_chunked(group, "sha256_1_MiB_in_1_KiB_chunks", MEBIBYTE, KIBIBYTE);
    bench_sha256_chunked(
        group,
        "sha256_1_MiB_in_16_KiB_chunks",
        MEBIBYTE,
        16 * KIBIBYTE,
    );

    group.sample_size(10);
    group.measurement_time(Duration::from_secs(7));
    bench_sha256(group, "sha256_10_MiB", 10 * MEBIBYTE);
    bench_sha256_chunked(
        group,
        "sha256_10_MiB_in_1_KiB_chunks",
        10 * MEBIBYTE,
        KIBIBYTE,
    );
    bench_sha256_chunked(
        group,
        "sha256_10_MiB_in_16_KiB_chunks",
        10 * MEBIBYTE,
        16 * KIBIBYTE,
    );
    bench_sha256_chunked(
        group,
        "sha256_100_MiB_in_16_KiB_chunks",
        100 * MEBIBYTE,
        16 * KIBIBYTE,
    );
}

fn bench_sha256<M: Measurement>(group: &mut BenchmarkGroup<'_, M>, name: &str, size: u128) {
    let rng = &mut thread_rng();
    group.throughput(Throughput::Bytes(as_u64(size)));
    group.bench_function(name, |bench| {
        bench.iter_batched_ref(
            || random_bytes(size, rng),
            |bytes| {
                Sha256::hash(bytes);
            },
            SmallInput,
        );
    });
}

fn bench_sha256_chunked<M: Measurement>(
    group: &mut BenchmarkGroup<'_, M>,
    name: &str,
    size: u128,
    chunk_size: u128,
) {
    let rng = &mut thread_rng();
    group.throughput(Throughput::Bytes(as_u64(size)));
    group.bench_function(name, |bench| {
        bench.iter_batched_ref(
            || random_bytes_chunked(size, chunk_size, rng),
            |chunks| {
                let mut sha256 = Sha256::new();
                for chunk in chunks {
                    sha256.write(chunk)
                }
                sha256.finish();
            },
            SmallInput,
        );
    });
}

fn random_bytes_chunked<R: Rng>(n: u128, chunk_size: u128, rng: &mut R) -> Vec<Vec<u8>> {
    assert_eq!(n % chunk_size, 0, "partial chunks currently not supported");
    let mut chunks: Vec<Vec<u8>> = vec![];
    for _ in 0..(n / chunk_size) {
        let chunk: Vec<u8> = random_bytes(chunk_size, rng);
        chunks.push(chunk);
    }
    chunks
}

fn random_bytes<R: Rng>(n: u128, rng: &mut R) -> Vec<u8> {
    (0..n).map(|_| rng.gen::<u8>()).collect()
}

fn as_u64(u128: u128) -> u64 {
    u64::try_from(u128).expect("failed to convert u128 to u64")
}
