//!
//! Benchmark Wasm instructions using `execute_update()`.
//!
//! This benchmark runs nightly in CI, and the results are available in Grafana.
//! See: `schedule-rust-bench.yml`
//!
//! To run a specific benchmark:
//!
//! ```shell
//! bazel run //rs/execution_environment:wasm_instructions_bench -- --sample-size 10 i32.div
//! ```

use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use execution_environment_bench::common;
use ic_error_types::ErrorCode;
use ic_execution_environment::{
    ExecuteMessageResult, ExecutionEnvironment, ExecutionResponse, RoundLimits,
    as_num_instructions, as_round_instructions,
};
use ic_limits::SMALL_APP_SUBNET_MAX_SIZE;
use ic_types::{
    batch::CanisterCyclesCostSchedule,
    ingress::{IngressState, IngressStatus},
    messages::CanisterMessageOrTask,
};
mod basic;
mod helper;
mod simd;

pub fn wasm_instructions_bench(c: &mut Criterion) {
    // List of benchmarks to run.
    let mut benchmarks = vec![];
    benchmarks.extend(basic::benchmarks());
    benchmarks.extend(simd::benchmarks());

    ////////////////////////////////////////////////////////////////////
    // Benchmark function.
    common::run_benchmarks(
        c,
        "execution_environment:wasm_instructions",
        &benchmarks,
        |_id: &str,
         exec_env: &ExecutionEnvironment,
         _expected_iterations,
         common::BenchmarkArgs {
             canister_state,
             ingress,
             time,
             network_topology,
             execution_parameters,
             subnet_available_memory,
             subnet_memory_reservation,
             subnet_available_callbacks,
             ..
         }| {
            let mut round_limits = RoundLimits::new(
                as_round_instructions(execution_parameters.instruction_limits.message()),
                subnet_available_memory,
                subnet_available_callbacks,
                0,
                subnet_memory_reservation,
            );
            let instructions_before = round_limits.instructions();
            let res = exec_env.execute_canister_input(
                canister_state,
                execution_parameters.instruction_limits.clone(),
                execution_parameters.instruction_limits.message(),
                CanisterMessageOrTask::Message(ingress),
                None,
                time,
                network_topology,
                &mut round_limits,
                SMALL_APP_SUBNET_MAX_SIZE,
                CanisterCyclesCostSchedule::Normal,
            );
            // We do not validate the number of executed instructions.
            let _executed_instructions =
                as_num_instructions(instructions_before - round_limits.instructions());
            let response = match res {
                ExecuteMessageResult::Finished { response, .. } => response,
                ExecuteMessageResult::Paused { .. } => panic!("Unexpected paused execution"),
            };
            let ExecutionResponse::Ingress((_, status)) = response else {
                panic!("Expected ingress result");
            };
            let IngressStatus::Known { state, .. } = status else {
                panic!("Unexpected ingress status");
            };
            if let IngressState::Failed(err) = state {
                assert_eq!(err.code(), ErrorCode::CanisterDidNotReply)
            }
        },
    );
}

criterion_group! {
    name = benchmarks;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(1))
        .sample_size(10);
    targets = wasm_instructions_bench
}
criterion_main!(benchmarks);
