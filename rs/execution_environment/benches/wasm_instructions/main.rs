//!
//! Benchmark Wasm instructions using `execute_update()`.
//!
//! To run a specific benchmark:
//!
//!     bazel run //rs/execution_environment:wasm_instructions_bench -- --sample-size 10 i32.div
//!

use criterion::{criterion_group, criterion_main, Criterion};
use execution_environment_bench::common;
use ic_error_types::ErrorCode;
use ic_execution_environment::{
    as_num_instructions, as_round_instructions, ExecuteMessageResult, ExecutionEnvironment,
    ExecutionResponse, RoundLimits,
};
use ic_limits::SMALL_APP_SUBNET_MAX_SIZE;
use ic_types::{
    ingress::{IngressState, IngressStatus},
    messages::CanisterMessageOrTask,
};
mod basic;
mod helper;
mod simd;

use crate::common::Wasm64;

pub fn wasm_instructions_bench(c: &mut Criterion) {
    const WASM64_ENABLED: Wasm64 = Wasm64::Enabled;

    // List of benchmarks to run.
    let mut benchmarks = vec![];
    benchmarks.extend(basic::benchmarks(WASM64_ENABLED));
    benchmarks.extend(simd::benchmarks(WASM64_ENABLED));

    ////////////////////////////////////////////////////////////////////
    // Benchmark function.
    common::run_benchmarks(
        c,
        "wasm_instructions",
        &benchmarks,
        |exec_env: &ExecutionEnvironment,
         _expected_iterations,
         common::BenchmarkArgs {
             canister_state,
             ingress,
             time,
             network_topology,
             execution_parameters,
             subnet_available_memory,
             ..
         }| {
            let mut round_limits = RoundLimits {
                instructions: as_round_instructions(
                    execution_parameters.instruction_limits.message(),
                ),
                subnet_available_memory,
                compute_allocation_used: 0,
            };
            let instructions_before = round_limits.instructions;
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
            );
            // We do not validate the number of executed instructions.
            let _executed_instructions =
                as_num_instructions(instructions_before - round_limits.instructions);
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
        WASM64_ENABLED,
    );
}

criterion_group!(benchmarks, wasm_instructions_bench);
criterion_main!(benchmarks);
