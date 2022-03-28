///
/// Benchmark System API performance in `execute_inspect_message()`
///
mod common;
mod common_wat;

use common_wat::*;
use criterion::{criterion_group, criterion_main, Criterion};
use ic_types::PrincipalId;

use lazy_static::lazy_static;

lazy_static! {
    /// List of benchmarks: benchmark id (name), WAT, expected instructions.
    pub static ref BENCHMARKS: Vec<common::Benchmark> = vec![
        common::Benchmark(
            "ic0_msg_method_name_size()",
            Module::InspectMessage.from_ic0("msg_method_name_size", NoParams, Result::I32),
            11_000_005,
        ),
        common::Benchmark(
            "ic0_msg_method_name_copy()/1B",
            Module::InspectMessage.from_ic0("msg_method_name_copy", Params3(0, 0, 1), Result::No),
            34_000_005,
        ),
        common::Benchmark(
            "ic0_msg_method_name_copy()/30B",
            Module::InspectMessage.from_ic0("msg_method_name_copy", Params3(0, 0, 20), Result::No),
            53_000_005,
        ),
        common::Benchmark(
            "ic0_accept_message()*",
            Module::InspectMessage.from_sections(("", "")), // inspect_message accepts by default
            1,
        ),
    ];
}

pub fn bench_execute_inspect_message(c: &mut Criterion) {
    let sender = PrincipalId::new_node_test_id(common::REMOTE_CANISTER_ID);
    let method_name = "very_long_method_name".to_string();
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
             ..
         }| {
            let (instructions_left, result) = hypervisor.execute_inspect_message(
                canister_state,
                sender,
                method_name.clone(),
                Vec::new(),
                time,
                execution_parameters,
            );
            assert_eq!(result, Ok(()), "Error executing inspect message method");
            assert_eq!(
                expected_instructions,
                common::MAX_NUM_INSTRUCTIONS.get() - instructions_left.get(),
                "Error comparing number of actual and expected instructions"
            );
        },
    );
}

criterion_group!(benchmarks, bench_execute_inspect_message);
criterion_main!(benchmarks);
