// To run the benchmarks:
// bazel run //rs/execution_environment:management_canister_bench -- canister_snapshot
use crate::utils::env;
use criterion::{BatchSize, BenchmarkGroup, Criterion, criterion_group, criterion_main};
use ic_management_canister_types_private::{
    CanisterSettingsArgsBuilder, CanisterSnapshotDataKind, CanisterSnapshotDataOffset,
    LoadCanisterSnapshotArgs, ReadCanisterSnapshotDataArgs, ReadCanisterSnapshotMetadataArgs,
    TakeCanisterSnapshotArgs, UploadCanisterSnapshotDataArgs, UploadCanisterSnapshotMetadataArgs,
};
use ic_state_machine_tests::StateMachine;
use ic_types::{CanisterId, Cycles, SnapshotId};
use ic_universal_canister::{UNIVERSAL_CANISTER_WASM, wasm};
use rand::Rng;

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

fn env_and_canister(canister_size: u64) -> (StateMachine, CanisterId) {
    let env = env();
    let canister_id = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
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
    (env, canister_id)
}

fn env_and_canister_snapshot(canister_size: u64) -> (StateMachine, CanisterId, SnapshotId) {
    let (env, canister_id) = env_and_canister(canister_size);
    let snapshot_id = env
        .take_canister_snapshot(TakeCanisterSnapshotArgs::new(canister_id, None, None, None))
        .expect("Error taking canister snapshot")
        .snapshot_id();
    (env, canister_id, snapshot_id)
}

fn env_and_writeable_canister_snapshot(
    canister_size: u64,
) -> (StateMachine, CanisterId, SnapshotId) {
    let (env, canister_id, snapshot_id) = env_and_canister_snapshot(canister_size);
    let args = ReadCanisterSnapshotMetadataArgs::new(canister_id, snapshot_id);
    let md = env.read_canister_snapshot_metadata(&args).unwrap();
    let module = env.get_snapshot_module(&args).unwrap();
    let main_memory = env.get_snapshot_heap(&args).unwrap();
    let stable_memory = env.get_snapshot_stable_memory(&args).unwrap();
    let snapshot_id = env
        .upload_canister_snapshot_metadata(&UploadCanisterSnapshotMetadataArgs::new(
            canister_id,
            None,
            md.wasm_module_size,
            md.globals,
            md.wasm_memory_size,
            md.stable_memory_size,
            md.certified_data,
            md.global_timer,
            md.on_low_wasm_memory_hook_status,
        ))
        .expect("Error taking canister snapshot")
        .snapshot_id;
    env.upload_snapshot_module(canister_id, snapshot_id, module, None, None)
        .unwrap();
    env.upload_snapshot_heap(canister_id, snapshot_id, main_memory, None, None)
        .unwrap();
    env.upload_snapshot_stable_memory(canister_id, snapshot_id, stable_memory, None, None)
        .unwrap();
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
            |(env, _canister_id)| {
                // Do nothing.
                // Return env so that it is dropped outside rather than inside the benchmarked code.
                env
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function(format!("{bench_name}+checkpoint"), |b| {
        b.iter_batched(
            || env_and_canister(canister_size),
            |(env, _canister_id)| {
                // Just do the checkpoint.
                env.checkpointed_tick();
                env
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
                env.take_canister_snapshot(TakeCanisterSnapshotArgs::new(
                    canister_id,
                    None,
                    None,
                    None,
                ))
                .expect("Error taking canister snapshot");
                env
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function(format!("{bench_name}+checkpoint"), |b| {
        b.iter_batched(
            || env_and_canister(canister_size),
            |(env, canister_id)| {
                env.take_canister_snapshot(TakeCanisterSnapshotArgs::new(
                    canister_id,
                    None,
                    None,
                    None,
                ))
                .expect("Error taking canister snapshot");
                env.checkpointed_tick();
                env
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
                    None,
                    None,
                ))
                .expect("Error replacing canister snapshot");
                env
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
                    None,
                    None,
                ))
                .expect("Error replacing canister snapshot");
                env.checkpointed_tick();
                env
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
                env
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
                env.checkpointed_tick();
                env
            },
            BatchSize::SmallInput,
        );
    });
}

fn read_canister_snapshot_metadata_bench<M: criterion::measurement::Measurement>(
    group: &mut BenchmarkGroup<M>,
    bench_name: &str,
    canister_size: u64,
) {
    group.bench_function(bench_name, |b| {
        b.iter_batched(
            || env_and_canister_snapshot(canister_size),
            |(env, canister_id, snapshot_id)| {
                let args = ReadCanisterSnapshotMetadataArgs::new(canister_id, snapshot_id);
                let _ = env
                    .read_canister_snapshot_metadata(&args)
                    .expect("Error reading snapshot metadata");
                env
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function(format!("{bench_name}+checkpoint"), |b| {
        b.iter_batched(
            || env_and_canister_snapshot(canister_size),
            |(env, canister_id, snapshot_id)| {
                let args = ReadCanisterSnapshotMetadataArgs::new(canister_id, snapshot_id);
                let _ = env
                    .read_canister_snapshot_metadata(&args)
                    .expect("Error reading snapshot metadata");
                env.checkpointed_tick();
                env
            },
            BatchSize::SmallInput,
        );
    });
}

fn read_canister_snapshot_data_bench<M: criterion::measurement::Measurement>(
    group: &mut BenchmarkGroup<M>,
    bench_name: &str,
    canister_size: u64,
) {
    group.bench_function(bench_name, |b| {
        b.iter_batched(
            || env_and_canister_snapshot(canister_size),
            |(env, canister_id, snapshot_id)| {
                let mut rng = rand::thread_rng();
                let offset = rng.gen_range(0..canister_size - 1);
                let args = ReadCanisterSnapshotDataArgs::new(
                    canister_id,
                    snapshot_id,
                    CanisterSnapshotDataKind::WasmMemory { offset, size: 1 },
                );
                let _ = env
                    .read_canister_snapshot_data(&args)
                    .expect("Error reading snapshot data");
                env
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function(format!("{bench_name}+checkpoint"), |b| {
        b.iter_batched(
            || env_and_canister_snapshot(canister_size),
            |(env, canister_id, snapshot_id)| {
                let mut rng = rand::thread_rng();
                let offset = rng.gen_range(0..canister_size - 1);
                let args = ReadCanisterSnapshotDataArgs::new(
                    canister_id,
                    snapshot_id,
                    CanisterSnapshotDataKind::WasmMemory { offset, size: 1 },
                );
                let _ = env
                    .read_canister_snapshot_data(&args)
                    .expect("Error reading snapshot data");
                env.checkpointed_tick();
                env
            },
            BatchSize::SmallInput,
        );
    });
}

fn write_canister_snapshot_data_bench<M: criterion::measurement::Measurement>(
    group: &mut BenchmarkGroup<M>,
    bench_name: &str,
    canister_size: u64,
) {
    group.bench_function(bench_name, |b| {
        b.iter_batched(
            || env_and_writeable_canister_snapshot(canister_size),
            |(env, canister_id, snapshot_id)| {
                let mut rng = rand::thread_rng();
                let offset = rng.gen_range(0..canister_size - 1);
                let args = UploadCanisterSnapshotDataArgs::new(
                    canister_id,
                    snapshot_id,
                    CanisterSnapshotDataOffset::WasmMemory { offset },
                    vec![42],
                );
                env.upload_canister_snapshot_data(&args)
                    .expect("Error writing snapshot data");
                env
            },
            BatchSize::SmallInput,
        );
    });
    group.bench_function(format!("{bench_name}+checkpoint"), |b| {
        b.iter_batched(
            || env_and_writeable_canister_snapshot(canister_size),
            |(env, canister_id, snapshot_id)| {
                let mut rng = rand::thread_rng();
                let offset = rng.gen_range(0..canister_size - 1);
                let args = UploadCanisterSnapshotDataArgs::new(
                    canister_id,
                    snapshot_id,
                    CanisterSnapshotDataOffset::WasmMemory { offset },
                    vec![42],
                );
                env.upload_canister_snapshot_data(&args)
                    .expect("Error writing snapshot data");
                env.checkpointed_tick();
                env
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

    let mut group = c.benchmark_group("read_canister_snapshot_metadata");
    for (name, size) in sizes {
        read_canister_snapshot_metadata_bench(&mut group, name, size);
    }
    group.finish();

    let mut group = c.benchmark_group("read_canister_snapshot_data");
    for (name, size) in sizes {
        read_canister_snapshot_data_bench(&mut group, name, size);
    }
    group.finish();

    let mut group = c.benchmark_group("write_canister_snapshot_data_bench");
    for (name, size) in sizes {
        write_canister_snapshot_data_bench(&mut group, name, size);
    }
    group.finish();
}

criterion_group!(benchmarks, benchmark);
criterion_main!(benchmarks);
