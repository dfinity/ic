///
/// Benchmark System API performance in `execute_inspect_message()`
///
use criterion::{criterion_group, criterion_main, Criterion};
use execution_environment_bench::{common, wat::*};
use ic_execution_environment::execution::inspect_message;

use ic_execution_environment::{ExecutionEnvironment, IngressFilterMetrics};
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_test_utilities_types::ids::user_test_id;
use ic_test_utilities_types::messages::SignedIngressBuilder;

use crate::common::Wasm64;

pub fn execute_inspect_message_bench(c: &mut Criterion) {
    // List of benchmarks: benchmark id (name), WAT, expected instructions.
    let benchmarks: Vec<common::Benchmark> = vec![
        common::Benchmark(
            "wasm32/ic0_msg_method_name_size()".into(),
            Module::InspectMessage.from_ic0(
                "msg_method_name_size",
                NoParams,
                Result::I32,
                Wasm64::Disabled,
            ),
            517000511,
        ),
        common::Benchmark(
            "wasm64/ic0_msg_method_name_size()".into(),
            Module::InspectMessage.from_ic0(
                "msg_method_name_size",
                NoParams,
                Result::I64,
                Wasm64::Enabled,
            ),
            517000511,
        ),
        common::Benchmark(
            "wasm32/ic0_msg_method_name_copy()/1B".into(),
            Module::InspectMessage.from_ic0(
                "msg_method_name_copy",
                Params3(0, 0, 1),
                Result::No,
                Wasm64::Disabled,
            ),
            520000511,
        ),
        common::Benchmark(
            "wasm64/ic0_msg_method_name_copy()/1B".into(),
            Module::InspectMessage.from_ic0(
                "msg_method_name_copy",
                Params3(0_i64, 0_i64, 1_i64),
                Result::No,
                Wasm64::Enabled,
            ),
            520000511,
        ),
        common::Benchmark(
            "wasm32/ic0_msg_method_name_copy()/20B".into(),
            Module::InspectMessage.from_ic0(
                "msg_method_name_copy",
                Params3(0, 0, 20),
                Result::No,
                Wasm64::Disabled,
            ),
            539000511,
        ),
        common::Benchmark(
            "wasm64/ic0_msg_method_name_copy()/20B".into(),
            Module::InspectMessage.from_ic0(
                "msg_method_name_copy",
                Params3(0_i64, 0_i64, 20_i64),
                Result::No,
                Wasm64::Enabled,
            ),
            539000511,
        ),
        common::Benchmark(
            "wasm32/ic0_accept_message()*".into(),
            Module::InspectMessage.from_sections(("", ""), Wasm64::Disabled), // inspect_message accepts by default
            506,
        ),
        common::Benchmark(
            "wasm64/ic0_accept_message()*".into(),
            Module::InspectMessage.from_sections(("", ""), Wasm64::Enabled), // inspect_message accepts by default
            506,
        ),
    ];
    common::run_benchmarks(
        c,
        "inspect",
        &benchmarks,
        |id: &str,
         exec_env: &ExecutionEnvironment,
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
                execution_parameters,
                subnet_available_memory,
                hypervisor,
                &network_topology,
                &no_op_logger(),
                exec_env.state_changes_error(),
                &IngressFilterMetrics::new(&MetricsRegistry::new()),
            );
            assert_eq!(result, Ok(()), "Error executing inspect message method");
            assert_eq!(
                expected_instructions,
                common::MAX_NUM_INSTRUCTIONS.get() - instructions_left.get(),
                "update the reference number of instructions for '{id}' to {}",
                common::MAX_NUM_INSTRUCTIONS.get() - instructions_left.get()
            );
        },
    );
}

criterion_group!(benchmarks, execute_inspect_message_bench);
criterion_main!(benchmarks);
