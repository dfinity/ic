///
/// Benchmark System API performance in `execute_query()`
///
mod common;
mod common_wat;

use common_wat::*;
use criterion::{criterion_group, criterion_main, Criterion};
use ic_execution_environment::QueryExecutionType;
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
        "inspect",
        &BENCHMARKS,
        |hypervisor,
         expected_instructions,
         common::BenchmarkArgs {
             canister_state,
             time,
             execution_parameters,
             network_topology,
             ..
         }| {
            let (_state, instructions_left, result) = hypervisor.execute_query(
                QueryExecutionType::Replicated,
                "test",
                &Vec::new(),
                sender,
                canister_state,
                Some(vec![0; 256]),
                time,
                execution_parameters,
                &network_topology,
            );
            assert_eq!(result, Ok(None), "Error executing a query method");
            assert_eq!(
                expected_instructions,
                common::MAX_NUM_INSTRUCTIONS.get() - instructions_left.get(),
                "Error comparing number of actual and expected instructions"
            );
        },
    );
}

criterion_group!(benchmarks, bench_execute_query);
criterion_main!(benchmarks);
