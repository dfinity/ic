///
/// Benchmark System API performance in `execute_query()`
///
use criterion::{criterion_group, criterion_main, Criterion};
use execution_environment_bench::{common, wat::*};
use ic_execution_environment::{
    as_num_instructions, as_round_instructions,
    execution::nonreplicated_query::execute_non_replicated_query, ExecutionEnvironment,
    NonReplicatedQueryKind, RoundLimits,
};
use ic_interfaces::execution_environment::ExecutionMode;
use ic_types::methods::WasmMethod;
use ic_types::PrincipalId;

use crate::common::Wasm64;

pub fn execute_query_bench(c: &mut Criterion) {
    // List of benchmarks: benchmark id (name), WAT, expected instructions.
    let benchmarks: Vec<common::Benchmark> = vec![
        common::Benchmark(
            "wasm32/ic0_data_certificate_size()".into(),
            Module::QueryTest.from_ic0(
                "data_certificate_size",
                NoParams,
                Result::I32,
                Wasm64::Disabled,
            ),
            517000006,
        ),
        common::Benchmark(
            "wasm64/ic0_data_certificate_size()".into(),
            Module::QueryTest.from_ic0(
                "data_certificate_size",
                NoParams,
                Result::I64,
                Wasm64::Enabled,
            ),
            517000006,
        ),
        common::Benchmark(
            "wasm32/ic0_data_certificate_copy()/1B".into(),
            Module::QueryTest.from_ic0(
                "data_certificate_copy",
                Params3(0, 0, 1),
                Result::No,
                Wasm64::Disabled,
            ),
            520000006,
        ),
        common::Benchmark(
            "wasm64/ic0_data_certificate_copy()/1B".into(),
            Module::QueryTest.from_ic0(
                "data_certificate_copy",
                Params3(0_i64, 0_i64, 1_i64),
                Result::No,
                Wasm64::Enabled,
            ),
            520000006,
        ),
        common::Benchmark(
            "wasm32/ic0_data_certificate_copy()/64B".into(),
            Module::QueryTest.from_ic0(
                "data_certificate_copy",
                Params3(0, 0, 64),
                Result::No,
                Wasm64::Disabled,
            ),
            583000006,
        ),
        common::Benchmark(
            "wasm64/ic0_data_certificate_copy()/64B".into(),
            Module::QueryTest.from_ic0(
                "data_certificate_copy",
                Params3(0_i64, 0_i64, 64_i64),
                Result::No,
                Wasm64::Enabled,
            ),
            583000006,
        ),
    ];
    let sender = PrincipalId::new_node_test_id(common::REMOTE_CANISTER_ID);
    common::run_benchmarks(
        c,
        "query",
        &benchmarks,
        |id: &str,
         exec_env: &ExecutionEnvironment,
         expected_instructions,
         common::BenchmarkArgs {
             canister_state,
             time,
             mut execution_parameters,
             subnet_available_memory,
             subnet_available_callbacks,
             network_topology,
             ..
         }| {
            execution_parameters.execution_mode = ExecutionMode::NonReplicated;
            let mut round_limits = RoundLimits {
                instructions: as_round_instructions(
                    execution_parameters.instruction_limits.message(),
                ),
                subnet_available_memory,
                subnet_available_callbacks,
                compute_allocation_used: 0,
            };
            let instructions_before = round_limits.instructions;
            let result = execute_non_replicated_query(
                NonReplicatedQueryKind::Pure { caller: sender },
                WasmMethod::Query("test".to_string()),
                &[],
                canister_state,
                Some(vec![0; 256]),
                time,
                execution_parameters,
                &network_topology,
                exec_env.hypervisor_for_testing(),
                &mut round_limits,
                exec_env.state_changes_error(),
            )
            .2;
            let executed_instructions =
                as_num_instructions(instructions_before - round_limits.instructions);
            assert_eq!(result, Ok(None), "Error executing a query method");
            assert_eq!(
                expected_instructions,
                executed_instructions.get(),
                "update the reference number of instructions for '{id}' to {}",
                executed_instructions.get()
            );
        },
    );
}

criterion_group!(benchmarks, execute_query_bench);
criterion_main!(benchmarks);
