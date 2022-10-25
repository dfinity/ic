///
/// Benchmark System API performance in `execute_inspect_message()`
///
use criterion::{criterion_group, criterion_main, Criterion};
use execution_environment_bench::common;
use execution_environment_bench::common_wat::*;
use ic_execution_environment::execution::inspect_message;

use ic_execution_environment::ExecutionEnvironment;
use ic_logger::replica_logger::no_op_logger;
use ic_test_utilities::types::ids::user_test_id;
use ic_test_utilities::types::messages::SignedIngressBuilder;
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
    common::run_benchmarks(
        c,
        "inspect",
        &BENCHMARKS,
        |exec_env: &ExecutionEnvironment,
         expected_instructions,
         common::BenchmarkArgs {
             canister_state,
             time,
             execution_parameters,
             subnet_available_memory,
             network_topology,
             ..
         }| {
            let ingress = SignedIngressBuilder::new()
                .canister_id(canister_state.canister_id())
                .sender(user_test_id(common::REMOTE_CANISTER_ID))
                .method_name("very_long_method_name".to_string())
                .build()
                .into();

            let hypervisor = exec_env.hypervisor_for_testing();
            let (instructions_left, result) = inspect_message::execute_inspect_message(
                time,
                canister_state,
                &ingress,
                hypervisor.subnet_type(),
                execution_parameters,
                subnet_available_memory,
                hypervisor,
                &network_topology,
                &no_op_logger(),
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
