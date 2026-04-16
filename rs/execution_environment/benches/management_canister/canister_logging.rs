use std::time::Duration;

use criterion::{BatchSize, BenchmarkGroup, Criterion, criterion_group, criterion_main};
use ic_base_types::{CanisterId, PrincipalId};
use ic_management_canister_types_private::{
    CanisterInstallMode, CanisterSettingsArgsBuilder, LogVisibilityV2,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::system_state::log_memory_store::LogMemoryStore;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder};
use ic_test_utilities_execution_environment::{wat_canister, wat_fn};
use ic_types_cycles::Cycles;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;

/// Creates a StateMachine with a canister whose log buffer is filled to capacity.
fn setup_canister_with_full_log(
    log_memory_limit: u64,
    log_message_size: usize,
) -> (StateMachine, CanisterId) {
    let log_message = vec![b'a'; log_message_size];
    let record_size = LogMemoryStore::estimate_record_size(log_message_size) as u64;
    let records_to_fill = (log_memory_limit / record_size + 1) as u32;

    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .with_checkpoints_enabled(false)
        .build();
    let settings = CanisterSettingsArgsBuilder::new()
        .with_controllers(vec![PrincipalId::new_anonymous()])
        .with_log_memory_limit(log_memory_limit)
        .with_log_visibility(LogVisibilityV2::Public)
        .build();
    let canister_id =
        env.create_canister_with_cycles(None, Cycles::new(u128::MAX / 2), Some(settings));
    env.install_wasm_in_mode(
        canister_id,
        CanisterInstallMode::Install,
        wat_canister()
            .update(
                "fill_logs",
                wat_fn().repeat(records_to_fill, wat_fn().debug_print(&log_message)),
            )
            .build_wasm(),
        vec![],
    )
    .unwrap();
    let _ = env.execute_ingress(canister_id, "fill_logs", vec![]);
    (env, canister_id)
}

fn run_bench_resize_canister_log<M: criterion::measurement::Measurement>(
    group: &mut BenchmarkGroup<M>,
    bench_name: &str,
    initial_log_memory_limit: u64,
    new_log_memory_limit: u64,
) {
    group.bench_function(bench_name, |b| {
        b.iter_batched(
            || setup_canister_with_full_log(initial_log_memory_limit, 0),
            |(env, canister_id)| {
                let result = env.update_settings(
                    &canister_id,
                    CanisterSettingsArgsBuilder::new()
                        .with_log_memory_limit(new_log_memory_limit)
                        .build(),
                );
                assert!(result.is_ok());
            },
            BatchSize::LargeInput,
        );
    });
}

pub fn canister_logging_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("resize_canister_log");
    group.sample_size(60);
    group.warm_up_time(Duration::from_secs(1));

    // Baseline: update_settings with the same log_memory_limit (no-op resize).
    // Measures pure update_settings overhead without log migration work.
    group.bench_function("baseline:2MiB/same_limit", |b| {
        b.iter_batched(
            || setup_canister_with_full_log(2 * MIB, 0),
            |(env, canister_id)| {
                let result = env.update_settings(
                    &canister_id,
                    CanisterSettingsArgsBuilder::new()
                        .with_log_memory_limit(2 * MIB)
                        .build(),
                );
                assert!(result.is_ok());
            },
            BatchSize::LargeInput,
        );
    });

    // Varying sizes to verify linear scaling of resize cost.
    run_bench_resize_canister_log(
        &mut group,
        "from:256KiB/to:-1/msg:0B",
        256 * KIB,
        256 * KIB - 1,
    );
    run_bench_resize_canister_log(&mut group, "from:1MiB/to:-1/msg:0B", MIB, MIB - 1);
    run_bench_resize_canister_log(&mut group, "from:2MiB/to:-1/msg:0B", 2 * MIB, 2 * MIB - 1);
    // Resize up to confirm symmetric cost.
    run_bench_resize_canister_log(
        &mut group,
        "from:2MiB-1/to:2MiB/msg:0B",
        2 * MIB - 1,
        2 * MIB,
    );
}

criterion_group!(benchmarks, canister_logging_benchmark);
criterion_main!(benchmarks);
