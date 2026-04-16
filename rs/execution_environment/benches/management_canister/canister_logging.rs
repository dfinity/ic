use std::time::Duration;

use criterion::{BatchSize, BenchmarkGroup, Criterion, criterion_group, criterion_main};
use ic_base_types::{CanisterId, PrincipalId};
use ic_config::execution_environment::{Config as ExecutionConfig, LOG_MEMORY_STORE_FEATURE};
use ic_config::flag_status::FlagStatus;
use ic_config::subnet_config::SubnetConfig;
use ic_management_canister_types_private::{
    CanisterIdRecord, CanisterInstallMode, CanisterSettingsArgsBuilder, FetchCanisterLogsRequest,
    LogVisibilityV2, Payload,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::system_state::log_memory_store::LogMemoryStore;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, StateMachineConfig};
use ic_test_utilities_execution_environment::{wat_canister, wat_fn};
use ic_types_cycles::Cycles;
use ic_universal_canister::{UNIVERSAL_CANISTER_WASM, call_args, wasm};

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

/// Creates a StateMachine with two canisters:
/// - `caller`: universal canister that will call fetch_canister_logs
/// - `target`: canister with log buffer filled to capacity
///
/// Returns (env, caller, target).
fn setup_fetch_bench(
    log_memory_limit: u64,
    log_message_size: usize,
) -> (StateMachine, CanisterId, CanisterId) {
    let log_message = vec![b'a'; log_message_size];
    let record_size = LogMemoryStore::estimate_record_size(log_message_size) as u64;
    let records_to_fill = (log_memory_limit / record_size + 1) as u32;

    let subnet_type = SubnetType::Application;
    let config = StateMachineConfig::new(
        SubnetConfig::new(subnet_type),
        ExecutionConfig {
            replicated_inter_canister_log_fetch: FlagStatus::Enabled,
            log_memory_store_feature: LOG_MEMORY_STORE_FEATURE,
            ..Default::default()
        },
    );
    let env = StateMachineBuilder::new()
        .with_config(Some(config))
        .with_subnet_type(subnet_type)
        .with_checkpoints_enabled(false)
        .build();

    // Create the caller (universal canister).
    let caller = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            Cycles::new(u128::MAX / 2),
        )
        .unwrap();

    // Create the target canister controlled by the caller.
    let settings = CanisterSettingsArgsBuilder::new()
        .with_controllers(vec![caller.get()])
        .with_log_memory_limit(log_memory_limit)
        .with_log_visibility(LogVisibilityV2::Controllers)
        .build();
    let target = env.create_canister_with_cycles(None, Cycles::new(u128::MAX / 2), Some(settings));
    env.install_wasm_in_mode(
        target,
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
    let _ = env.execute_ingress(target, "fill_logs", vec![]);

    (env, caller, target)
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

fn run_bench_fetch_canister_log<M: criterion::measurement::Measurement>(
    group: &mut BenchmarkGroup<M>,
    bench_name: &str,
    log_memory_limit: u64,
    log_message_size: usize,
) {
    group.bench_function(bench_name, |b| {
        b.iter_batched(
            || setup_fetch_bench(log_memory_limit, log_message_size),
            |(env, caller, target)| {
                let result = env.execute_ingress(
                    caller,
                    "update",
                    wasm()
                        .call_with_cycles(
                            CanisterId::ic_00(),
                            "fetch_canister_logs",
                            call_args().other_side(FetchCanisterLogsRequest::new(target).encode()),
                            Cycles::new(5_000_000_000),
                        )
                        .build(),
                );
                assert!(result.is_ok());
            },
            BatchSize::LargeInput,
        );
    });
}

pub fn canister_logging_benchmark(c: &mut Criterion) {
    {
        let mut group = c.benchmark_group("resize_canister_log");
        group.sample_size(60);
        group.warm_up_time(Duration::from_secs(1));

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

    {
        let mut group = c.benchmark_group("fetch_canister_log");
        group.sample_size(60);
        group.warm_up_time(Duration::from_secs(1));

        // Baseline: inter-canister call to canister_status (same call overhead,
        // no log reading). Subtract this from fetch results to isolate fetch cost.
        group.bench_function("baseline", |b| {
            b.iter_batched(
                || setup_fetch_bench(128 * KIB, 0),
                |(env, caller, target)| {
                    let result = env.execute_ingress(
                        caller,
                        "update",
                        wasm()
                            .call_with_cycles(
                                CanisterId::ic_00(),
                                "canister_status",
                                call_args().other_side(CanisterIdRecord::from(target).encode()),
                                Cycles::new(0),
                            )
                            .build(),
                    );
                    assert!(result.is_ok());
                },
                BatchSize::LargeInput,
            );
        });

        // Worst case: 0-byte messages maximize records per buffer.
        run_bench_fetch_canister_log(&mut group, "fetch:128KiB/msg:0B", 128 * KIB, 0);
        run_bench_fetch_canister_log(&mut group, "fetch:1MiB/msg:0B", MIB, 0);
        run_bench_fetch_canister_log(&mut group, "fetch:2MiB/msg:0B", 2 * MIB, 0);
        // Realistic: 100-byte messages.
        run_bench_fetch_canister_log(&mut group, "fetch:128KiB/msg:100B", 128 * KIB, 100);
        run_bench_fetch_canister_log(&mut group, "fetch:1MiB/msg:100B", MIB, 100);
        run_bench_fetch_canister_log(&mut group, "fetch:2MiB/msg:100B", 2 * MIB, 100);
    }
}

criterion_group!(benchmarks, canister_logging_benchmark);
criterion_main!(benchmarks);
