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
    let wasm64_disabled = Wasm64::Disabled;
    // List of benchmarks: benchmark id (name), WAT, expected instructions.
    let benchmarks: Vec<common::Benchmark> = vec![
        common::Benchmark(
            "ic0_data_certificate_size()".into(),
            Module::QueryTest.from_ic0(
                "data_certificate_size",
                NoParams,
                Result::I32,
                wasm64_disabled,
            ),
            517000006,
        ),
        common::Benchmark(
            "ic0_data_certificate_copy()/1B".into(),
            Module::QueryTest.from_ic0(
                "data_certificate_copy",
                Params3(0, 0, 1),
                Result::No,
                wasm64_disabled,
            ),
            520000006,
        ),
        common::Benchmark(
            "ic0_data_certificate_copy()/64B".into(),
            Module::QueryTest.from_ic0(
                "data_certificate_copy",
                Params3(0, 0, 64),
                Result::No,
                wasm64_disabled,
            ),
            583000006,
        ),
    ];
    let sender = PrincipalId::new_node_test_id(common::REMOTE_CANISTER_ID);
    common::run_benchmarks(
        c,
        "query",
        &benchmarks,
        |exec_env: &ExecutionEnvironment,
         expected_instructions,
         common::BenchmarkArgs {
             canister_state,
             time,
             mut execution_parameters,
             subnet_available_memory,
             network_topology,
             ..
         }| {
            execution_parameters.execution_mode = ExecutionMode::NonReplicated;
            let mut round_limits = RoundLimits {
                instructions: as_round_instructions(
                    execution_parameters.instruction_limits.message(),
                ),
                subnet_available_memory,
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
                "Error comparing number of actual and expected instructions"
            );
        },
        wasm64_disabled,
    );
}

criterion_group!(benchmarks, execute_query_bench);
criterion_main!(benchmarks);
