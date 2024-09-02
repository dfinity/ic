// To run the benchmarks:
// bazel run //rs/execution_environment:management_canister_bench -- canister_snapshot
use crate::utils::env;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkGroup, Criterion};
use ic_management_canister_types::LoadCanisterSnapshotArgs;
use ic_state_machine_tests::{StateMachine, TakeCanisterSnapshotArgs};
use ic_types::{CanisterId, Cycles, SnapshotId};
use ic_universal_canister::{wasm, UNIVERSAL_CANISTER_WASM};

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

fn env_and_canister(canister_size: u64) -> (StateMachine, CanisterId) {
    let env = env();
    let canister_id = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.into(),
            vec![],
            None,
            Cycles::new(u128::MAX / 2),
        )
        .unwrap();

    env.execute_ingress(
        canister_id,
        "update",
        wasm()
            .memory_size_is_at_least(canister_size)
            .reply_data(&[42])
            .build(),
    )
    .expect("Error increasing the canister memory size");

    // Skip a few rounds to avoid `CanisterHeapDeltaRateLimited`.
    for _ in 0..100 {
        env.tick();
    }

    (env, canister_id)
}

fn env_and_canister_snapshot(canister_size: u64) -> (StateMachine, CanisterId, SnapshotId) {
    let (env, canister_id) = env_and_canister(canister_size);
    let snapshot_id = env
        .take_canister_snapshot(TakeCanisterSnapshotArgs::new(canister_id, None))
        .expect("Error taking canister snapshot")
        .snapshot_id();
    // Skip a few rounds to avoid `CanisterHeapDeltaRateLimited`.
    for _ in 0..100 {
        env.tick();
    }
    (env, canister_id, snapshot_id)
}

fn take_canister_snapshot_bench<M: criterion::measurement::Measurement>(
    group: &mut BenchmarkGroup<M>,
    bench_name: &str,
    canister_size: u64,
) {
    group.bench_function(bench_name, |b| {
        b.iter_batched(
            || env_and_canister(canister_size),
            |(env, canister_id)| {
                env.take_canister_snapshot(TakeCanisterSnapshotArgs::new(canister_id, None))
                    .expect("Error taking canister snapshot");
            },
            BatchSize::SmallInput,
        );
    });
}

fn load_canister_snapshot_bench<M: criterion::measurement::Measurement>(
    group: &mut BenchmarkGroup<M>,
    bench_name: &str,
    canister_size: u64,
) {
    group.bench_function(bench_name, |b| {
        b.iter_batched(
            || env_and_canister_snapshot(canister_size),
            |(env, canister_id, snapshot_id)| {
                env.load_canister_snapshot(LoadCanisterSnapshotArgs::new(
                    canister_id,
                    snapshot_id,
                    None,
                ))
                .expect("Error taking canister snapshot");
            },
            BatchSize::SmallInput,
        );
    });
}

pub fn benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("take_canister_snapshot");
    take_canister_snapshot_bench(&mut group, "10 MiB", 10 * MIB);
    take_canister_snapshot_bench(&mut group, "100 MiB", 100 * MIB);
    take_canister_snapshot_bench(&mut group, "1 GiB", GIB);
    take_canister_snapshot_bench(&mut group, "2 GiB", 2 * GIB);
    group.finish();

    let mut group = c.benchmark_group("load_canister_snapshot");
    load_canister_snapshot_bench(&mut group, "10 MiB", 10 * MIB);
    load_canister_snapshot_bench(&mut group, "100 MiB", 100 * MIB);
    load_canister_snapshot_bench(&mut group, "1 GiB", GIB);
    load_canister_snapshot_bench(&mut group, "2 GiB", 2 * GIB);
    group.finish();
}

criterion_group!(benchmarks, benchmark);
criterion_main!(benchmarks);
