use criterion::{BatchSize, BenchmarkGroup, Criterion, criterion_group, criterion_main};
use ic_base_types::PrincipalId;
use ic_management_canister_types_private::{
    CanisterInstallMode, CanisterSettingsArgsBuilder, LogVisibilityV2,
};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::StateMachineBuilder;
use ic_test_utilities_execution_environment::{wat_canister, wat_fn};
use ic_types::Cycles;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const MAX_LOG_MESSAGE_LEN: u64 = 32 * KIB;

fn run_bench_resize_canister_log<M: criterion::measurement::Measurement>(
    group: &mut BenchmarkGroup<M>,
    bench_name: &str,
    params: (u64, u64, u64, u64),
) {
    let (canisters_number, initial_log_memory_limit, new_log_memory_limit, log_message_size) =
        params;

    group.bench_function(bench_name, |b| {
        b.iter_batched(
            // Test setup.
            || {
                let subnet_type = SubnetType::Application;
                let env = StateMachineBuilder::new()
                    .with_subnet_type(subnet_type)
                    .with_checkpoints_enabled(false)
                    .build();
                let initial_cycles = Cycles::new(u128::MAX / 2);
                let settings = CanisterSettingsArgsBuilder::new()
                    .with_controllers(vec![PrincipalId::new_anonymous()])
                    // Set initial log memory limit
                    .with_log_memory_limit(initial_log_memory_limit)
                    .with_log_visibility(LogVisibilityV2::Public)
                    .build();
                let log_message_size = log_message_size.min(MAX_LOG_MESSAGE_LEN);
                let log_message = vec![b'a'; log_message_size as usize];
                let canister_ids: Vec<_> = (0..canisters_number)
                    // Create all canisters.
                    .map(|_| {
                        env.create_canister_with_cycles(
                            None,
                            initial_cycles,
                            Some(settings.clone()),
                        )
                    })
                    // Install wasm in all canisters.
                    .inspect(|&canister_id| {
                        env.install_wasm_in_mode(
                            canister_id,
                            CanisterInstallMode::Install,
                            wat_canister()
                                .update("debug_print", wat_fn().debug_print(&log_message))
                                .build_wasm(),
                            vec![],
                        )
                        .unwrap();
                    })
                    // Prepopulate logs.
                    .inspect(|&canister_id| {
                        // Make sure there are more logs written than the limit.
                        let mut logs_written = 0;
                        while logs_written <= initial_log_memory_limit {
                            let _ = env.execute_ingress(canister_id, "debug_print", vec![]);
                            logs_written += log_message_size;
                        }
                    })
                    .collect();

                (env, canister_ids)
            },
            // Test measurement.
            |(env, canister_ids)| {
                for canister_id in canister_ids {
                    let result = env.update_settings(
                        &canister_id,
                        CanisterSettingsArgsBuilder::new()
                            .with_log_memory_limit(new_log_memory_limit)
                            .build(),
                    );
                    assert!(result.is_ok());
                }
            },
            BatchSize::SmallInput,
        );
    });
}

pub fn canister_logging_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("resize_canister_log");

    run_bench_resize_canister_log(
        &mut group,
        "canisters:1/from:2MiB/to:-1",
        (1, 2 * MIB, 2 * MIB - 1, 0),
    );
    run_bench_resize_canister_log(
        &mut group,
        "canisters:1/from:-1/to:2MiB",
        (1, 2 * MIB - 1, 2 * MIB, 0),
    );
}

criterion_group!(benchmarks, canister_logging_benchmark);
criterion_main!(benchmarks);
