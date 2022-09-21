///
/// Benchmark System API performance in `execute_query()`
///
mod common;
mod common_wat;

use common_wat::*;
use criterion::{criterion_group, criterion_main, Criterion};
use ic_execution_environment::{
    as_num_instructions, as_round_instructions,
    execution::nonreplicated_query::execute_non_replicated_query, ExecutionEnvironment,
    NonReplicatedQueryKind, RoundLimits,
};
use ic_interfaces::execution_environment::ExecutionMode;
use ic_types::PrincipalId;

use lazy_static::lazy_static;

lazy_static! {
    /// List of benchmarks: benchmark id (name), WAT, expected instructions.
    pub static ref BENCHMARKS: Vec<common::Benchmark> = vec![
        common::Benchmark(
            "ic0_data_certificate_size()",
            Module::QueryTest.from_ic0("data_certificate_size", NoParams, Result::I32),
            11_000_004,
        ),
        common::Benchmark(
            "ic0_data_certificate_copy()/1B",
            Module::QueryTest.from_ic0("data_certificate_copy", Params3(0, 0, 1), Result::No),
            13_000_004,
        ),
        common::Benchmark(
            "ic0_data_certificate_copy()/64B",
            Module::QueryTest.from_ic0("data_certificate_copy", Params3(0, 0, 64), Result::No),
            13_000_004,
        ),
    ];
}

pub fn bench_execute_query(c: &mut Criterion) {
    let sender = PrincipalId::new_node_test_id(common::REMOTE_CANISTER_ID);
    common::run_benchmarks(
        c,
        "query",
        &BENCHMARKS,
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
            let (_, _, result) = execute_non_replicated_query(
                NonReplicatedQueryKind::Pure { caller: sender },
                "test",
                &[],
                canister_state,
                Some(vec![0; 256]),
                time,
                execution_parameters,
                &network_topology,
                exec_env.hypervisor_for_testing(),
                &mut round_limits,
            );
            let executed_instructions =
                as_num_instructions(instructions_before - round_limits.instructions);
            assert_eq!(result, Ok(None), "Error executing a query method");
            assert_eq!(
                expected_instructions,
                executed_instructions.get(),
                "Error comparing number of actual and expected instructions"
            );
        },
    );
}

criterion_group!(benchmarks, bench_execute_query);
criterion_main!(benchmarks);
