// To run the benchmarks:
// bazel run //rs/execution_environment:management_canister_bench -- canister_snapshot
use crate::utils::env;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkGroup, Criterion};
use ic_management_canister_types::{CanisterSettingsArgsBuilder, LoadCanisterSnapshotArgs};
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
    env.update_settings(
        &canister_id,
        CanisterSettingsArgsBuilder::new()
            .with_wasm_memory_limit(4 * GIB)
            .build(),
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

fn baseline_bench<M: criterion::measurement::Measurement>(
    group: &mut BenchmarkGroup<M>,
    bench_name: &str,
    canister_size: u64,
) {
    group.bench_function(bench_name, |b| {
        b.iter_batched(
            || env_and_canister(canister_size),
            |(_env, _canister_id)| {
                // Do nothing.
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function(format!("{bench_name}+checkpoint"), |b| {
        b.iter_batched(
            || env_and_canister(canister_size),
            |(env, _canister_id)| {
                // Just do the checkpoint.
                env.set_checkpoints_enabled(true);
                env.tick();
            },
            BatchSize::SmallInput,
        );
    });
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
    group.bench_function(format!("{bench_name}+checkpoint"), |b| {
        b.iter_batched(
            || env_and_canister(canister_size),
            |(env, canister_id)| {
                env.take_canister_snapshot(TakeCanisterSnapshotArgs::new(canister_id, None))
                    .expect("Error taking canister snapshot");
                env.set_checkpoints_enabled(true);
                env.tick();
            },
            BatchSize::SmallInput,
        );
    });
}

fn replace_canister_snapshot_bench<M: criterion::measurement::Measurement>(
    group: &mut BenchmarkGroup<M>,
    bench_name: &str,
    canister_size: u64,
) {
    group.bench_function(bench_name, |b| {
        b.iter_batched(
            || env_and_canister_snapshot(canister_size),
            |(env, canister_id, snapshot_id)| {
                env.take_canister_snapshot(TakeCanisterSnapshotArgs::new(
                    canister_id,
                    Some(snapshot_id),
                ))
                .expect("Error replacing canister snapshot");
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function(format!("{bench_name}+checkpoint"), |b| {
        b.iter_batched(
            || env_and_canister_snapshot(canister_size),
            |(env, canister_id, snapshot_id)| {
                env.take_canister_snapshot(TakeCanisterSnapshotArgs::new(
                    canister_id,
                    Some(snapshot_id),
                ))
                .expect("Error replacing canister snapshot");
                env.set_checkpoints_enabled(true);
                env.tick();
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
                .expect("Error loading canister snapshot");
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function(format!("{bench_name}+checkpoint"), |b| {
        b.iter_batched(
            || env_and_canister_snapshot(canister_size),
            |(env, canister_id, snapshot_id)| {
                env.load_canister_snapshot(LoadCanisterSnapshotArgs::new(
                    canister_id,
                    snapshot_id,
                    None,
                ))
                .expect("Error loading canister snapshot");
                env.set_checkpoints_enabled(true);
                env.tick();
            },
            BatchSize::SmallInput,
        );
    });
}

pub fn benchmark(c: &mut Criterion) {
    let sizes = [
        ("10 MiB", 10 * MIB),
        ("100 MiB", 100 * MIB),
        ("1000 MiB", 1000 * MIB),
        ("2000 MiB", 2000 * MIB),
        ("3000 MiB", 3000 * MIB),
        ("4000 MiB", 4000 * MIB),
    ];
    let mut group = c.benchmark_group("canister_snapshot_baseline");
    for (name, size) in sizes {
        baseline_bench(&mut group, name, size);
    }
    group.finish();

    let mut group = c.benchmark_group("take_canister_snapshot");
    for (name, size) in sizes {
        take_canister_snapshot_bench(&mut group, name, size);
    }
    group.finish();

    let mut group = c.benchmark_group("replace_canister_snapshot");
    for (name, size) in sizes {
        replace_canister_snapshot_bench(&mut group, name, size);
    }
    group.finish();

    let mut group = c.benchmark_group("load_canister_snapshot");
    for (name, size) in sizes {
        load_canister_snapshot_bench(&mut group, name, size);
    }
    group.finish();
}

criterion_group!(benchmarks, benchmark);
criterion_main!(benchmarks);
