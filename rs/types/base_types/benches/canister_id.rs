//! Microbenchmarks for `CanisterId::eq()` and `CanisterId::cmp()`.
//!
//! These exercise the two comparison paths that matter in practice:
//!
//!  * "u64" canister IDs (those produced by `CanisterId::from_u64()`, i.e. the
//!    vast majority of canister IDs on a subnet), and
//!  * "opaque"/long principal-based IDs, which fall back to comparing the
//!    underlying `PrincipalId`.
//!
//! Run with:
//! ```
//! bazel run //rs/types/base_types:canister_id_bench
//! ```
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use ic_base_types::{CanisterId, PrincipalId};
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::hint::black_box;

/// A `CanisterId` backed by a full-length (29 byte) principal, i.e. one that
/// does NOT take the fast `u64` path.
fn long_canister_id(seed: u8) -> CanisterId {
    let mut bytes = [seed; PrincipalId::MAX_LENGTH_IN_BYTES];
    // Make it a self-authenticating principal (0x02 suffix, 29 bytes) so it is
    // definitely not recognized as a `u64` canister ID.
    bytes[PrincipalId::MAX_LENGTH_IN_BYTES - 1] = 0x02;
    let principal = PrincipalId::new(PrincipalId::MAX_LENGTH_IN_BYTES, bytes);
    CanisterId::unchecked_from_principal(principal)
}

fn bench_eq(c: &mut Criterion) {
    let mut group = c.benchmark_group("CanisterId::eq");

    // Two distinct `u64` canister IDs (fast path, differ in the low bits).
    let a = CanisterId::from_u64(0x0123_4567_89ab_cdef);
    let b = CanisterId::from_u64(0x0123_4567_89ab_cdee);
    group.bench_function("u64_ne", |bench| {
        bench.iter(|| black_box(black_box(&a) == black_box(&b)))
    });

    // Two equal `u64` canister IDs (fast path, worst case: must compare all
    // bytes / the full u64 before returning `true`).
    let a = CanisterId::from_u64(0x0123_4567_89ab_cdef);
    let b = CanisterId::from_u64(0x0123_4567_89ab_cdef);
    group.bench_function("u64_eq", |bench| {
        bench.iter(|| black_box(black_box(&a) == black_box(&b)))
    });

    // Two distinct long (29 byte) principal-based canister IDs (slow path).
    let a = long_canister_id(0x11);
    let b = long_canister_id(0x22);
    group.bench_function("long_ne", |bench| {
        bench.iter(|| black_box(black_box(&a) == black_box(&b)))
    });

    // Two equal long principal-based canister IDs (slow path, worst case).
    let a = long_canister_id(0x11);
    let b = long_canister_id(0x11);
    group.bench_function("long_eq", |bench| {
        bench.iter(|| black_box(black_box(&a) == black_box(&b)))
    });

    group.finish();
}

fn bench_cmp(c: &mut Criterion) {
    let mut group = c.benchmark_group("CanisterId::cmp");

    let a = CanisterId::from_u64(0x0123_4567_89ab_cdef);
    let b = CanisterId::from_u64(0x0123_4567_89ab_cdee);
    group.bench_function("u64", |bench| {
        bench.iter(|| black_box(black_box(&a).cmp(black_box(&b))))
    });

    let a = long_canister_id(0x11);
    let b = long_canister_id(0x22);
    group.bench_function("long", |bench| {
        bench.iter(|| black_box(black_box(&a).cmp(black_box(&b))))
    });

    group.finish();
}

/// A more realistic workload: sorting / deduplicating a collection of canister
/// IDs, which stresses `cmp` (and, for the map lookup, `eq`) many times.
fn bench_collections(c: &mut Criterion) {
    const N: usize = 1024;

    let mut group = c.benchmark_group("CanisterId::collections");

    // A shuffled-ish set of `u64` canister IDs.
    let ids: Vec<CanisterId> = (0..N as u64)
        .map(|i| CanisterId::from_u64(i.wrapping_mul(2_654_435_761)))
        .collect();

    group.bench_with_input(BenchmarkId::new("sort_u64", N), &ids, |bench, ids| {
        bench.iter_batched(
            || ids.clone(),
            |mut ids| {
                ids.sort_unstable();
                black_box(&ids);
            },
            BatchSize::SmallInput,
        )
    });

    // Binary search (pure `cmp`) over a sorted vector.
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    let needle = sorted[N / 3];
    group.bench_function("binary_search_u64", |bench| {
        bench.iter(|| black_box(sorted.binary_search(black_box(&needle))))
    });

    // Linear scan comparing every element for equality against a needle that is
    // absent (worst case for `eq`: every comparison runs to completion).
    let absent = CanisterId::from_u64(u64::MAX);
    group.bench_function("linear_find_u64", |bench| {
        bench.iter(|| black_box(black_box(&ids).contains(&absent)))
    });

    group.finish();
}

/// Hashes a single value with the standard-library (SipHash) hasher and returns
/// the finished hash, mirroring what `HashMap`/`HashSet` do per key.
fn hash_one<T: Hash>(v: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    v.hash(&mut hasher);
    hasher.finish()
}

fn bench_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("CanisterId::hash");

    // Hashing a single `u64` canister ID (fast path: 8 bytes fed to the hasher).
    let a = CanisterId::from_u64(0x0123_4567_89ab_cdef);
    group.bench_function("hash_u64", |bench| {
        bench.iter(|| black_box(hash_one(black_box(&a))))
    });

    // Hashing a single long/opaque canister ID (fall back to hashing the full
    // principal).
    let a = long_canister_id(0x11);
    group.bench_function("hash_long", |bench| {
        bench.iter(|| black_box(hash_one(black_box(&a))))
    });

    // Realistic workload: `HashMap<CanisterId, _>` lookups, which hash the key
    // and then use `eq` to resolve the bucket.
    const N: usize = 1024;
    let map: HashMap<CanisterId, u64> = (0..N as u64)
        .map(|i| (CanisterId::from_u64(i.wrapping_mul(2_654_435_761)), i))
        .collect();

    let present = CanisterId::from_u64(500_u64.wrapping_mul(2_654_435_761));
    group.bench_function("hashmap_get_hit", |bench| {
        bench.iter(|| black_box(map.get(black_box(&present))))
    });

    let absent = CanisterId::from_u64(u64::MAX);
    group.bench_function("hashmap_get_miss", |bench| {
        bench.iter(|| black_box(map.get(black_box(&absent))))
    });

    group.finish();
}

criterion_group!(benches, bench_eq, bench_cmp, bench_collections, bench_hash);
criterion_main!(benches);
