///
/// Benchmark System API performance in `execute_update()`.
///
use criterion::{criterion_group, criterion_main, Criterion};
use execution_environment_bench::{common, wat::*};
use ic_constants::SMALL_APP_SUBNET_MAX_SIZE;
use ic_error_types::ErrorCode;
use ic_execution_environment::{
    as_num_instructions, as_round_instructions, ExecuteMessageResult, ExecutionEnvironment,
    ExecutionResponse, RoundLimits,
};
use ic_interfaces::execution_environment::ExecutionComplexity;
use ic_types::{
    ingress::{IngressState, IngressStatus},
    messages::CanisterMessageOrTask,
};

pub fn execute_update_bench(c: &mut Criterion) {
    // List of benchmarks: benchmark id (name), WAT, expected instructions.
    let benchmarks: Vec<common::Benchmark> = vec![
        common::Benchmark(
            "baseline/empty test*",
            Module::Test.from_sections(("", "(drop (i32.const 0))")),
            2,
        ),
        common::Benchmark(
            "baseline/empty loop",
            Module::Test.from_sections(("", Module::render_loop(LoopIterations::Mi, ""))),
            9_000_004,
        ),
        common::Benchmark(
            "baseline/adds",
            Module::Test.from_sections((
                "",
                Module::render_loop(
                    LoopIterations::Mi,
                    "(set_local $s (i32.add (get_local $s) (i32.load (i32.const 0))))",
                ),
            )),
            14_000_004,
        ),
        common::Benchmark(
            "ic0_msg_caller_size()",
            Module::Test.from_ic0("msg_caller_size", NoParams, Result::I32),
            11_000_004,
        ),
        common::Benchmark(
            "ic0_msg_caller_copy()/1B",
            Module::Test.from_ic0("msg_caller_copy", Params3(0, 0, 1), Result::No),
            13_000_004,
        ),
        common::Benchmark(
            "ic0_msg_caller_copy()/10B",
            Module::Test.from_ic0("msg_caller_copy", Params3(0, 0, 10), Result::No), // 10B max
            13_000_004,
        ),
        common::Benchmark(
            "ic0_msg_arg_data_size()",
            Module::Test.from_ic0("msg_arg_data_size", NoParams, Result::I32),
            11_000_004,
        ),
        common::Benchmark(
            "ic0_msg_arg_data_copy()/1B",
            Module::Test.from_ic0("msg_arg_data_copy", Params3(0, 0, 1), Result::No),
            34_000_004,
        ),
        common::Benchmark(
            "ic0_msg_arg_data_copy()/8K",
            Module::Test.from_ic0("msg_arg_data_copy", Params3(0, 0, 8192), Result::No),
            8_225_000_004,
        ),
        common::Benchmark(
            "ic0_msg_reply()*",
            // We can reply just once
            Module::Test.from_sections(Module::sections(
                LoopIterations::One,
                "msg_reply",
                NoParams,
                Result::No,
            )),
            1,
        ),
        common::Benchmark(
            "ic0_msg_reply_data_append()/1B",
            Module::Test.from_ic0("msg_reply_data_append", Params2(0, 1), Result::No), // 2MiB max
            33_000_004,
        ),
        common::Benchmark(
            "ic0_msg_reply_data_append()/2B",
            Module::Test.from_ic0("msg_reply_data_append", Params2(0, 2), Result::No), // 2MiB max
            34_000_004,
        ),
        common::Benchmark(
            "ic0_msg_reject()*",
            // We can reject just once
            Module::Test.from_sections(Module::sections(
                LoopIterations::One,
                "msg_reject",
                Params2(0, 0),
                Result::No,
            )),
            23,
        ),
        common::Benchmark(
            "ic0_canister_self_size()",
            Module::Test.from_ic0("canister_self_size", NoParams, Result::I32),
            11_000_004,
        ),
        common::Benchmark(
            "ic0_canister_self_copy()/1B",
            Module::Test.from_ic0("canister_self_copy", Params3(0, 0, 1), Result::No),
            13_000_004,
        ),
        common::Benchmark(
            "ic0_canister_self_copy()/10B",
            Module::Test.from_ic0("canister_self_copy", Params3(0, 0, 10), Result::No), // 10B max
            13_000_004,
        ),
        common::Benchmark(
            "ic0_debug_print()/1B",
            Module::Test.from_ic0("debug_print", Params2(0, 1), Result::No),
            113_000_004,
        ),
        common::Benchmark(
            "ic0_debug_print()/64B",
            Module::Test.from_ic0("debug_print", Params2(0, 64), Result::No),
            176_000_004,
        ),
        common::Benchmark(
            "ic0_call_new()",
            Module::CallNewLoop.from_sections(("", "")), // call_new in a loop is rendered by default
            18_000_004,
        ),
        common::Benchmark(
            "call_new+ic0_call_data_append()/1B",
            Module::CallNewLoop.from_ic0("call_data_append", Params2(0, 1), Result::No), // 2MiB max
            42_000_004,
        ),
        common::Benchmark(
            "call_new+ic0_call_data_append()/8K",
            Module::CallNewLoop.from_ic0("call_data_append", Params2(0, 8192), Result::No), // 2MiB max
            8_233_000_004,
        ),
        common::Benchmark(
            "call_new+ic0_call_on_cleanup()",
            Module::CallNewLoop.from_ic0("call_on_cleanup", Params2(33, 0), Result::No),
            21_000_004,
        ),
        common::Benchmark(
            "call_new+ic0_call_cycles_add()",
            Module::CallNewLoop.from_ic0("call_cycles_add", Param1(100_i64), Result::No),
            20_000_004,
        ),
        common::Benchmark(
            "call_new+ic0_call_cycles_add128()",
            Module::CallNewLoop.from_ic0("call_cycles_add128", Params2(0_i64, 100_i64), Result::No),
            21_000_004,
        ),
        common::Benchmark(
            "call_new+ic0_call_perform()",
            Module::CallNewLoop.from_ic0("call_perform", NoParams, Result::I32),
            20_000_004,
        ),
        common::Benchmark(
            "ic0_stable_size()",
            Module::Test.from_ic0("stable_size", NoParams, Result::I32),
            11_000_004,
        ),
        common::Benchmark(
            "ic0_stable_grow()",
            Module::Test.from_ic0("stable_grow", Param1(1), Result::I32),
            12_000_004,
        ),
        common::Benchmark(
            "ic0_stable_read()/1B",
            Module::StableTest.from_ic0("stable_read", Params3(0, 0, 1), Result::No),
            34_000_007,
        ),
        common::Benchmark(
            "ic0_stable_read()/8K",
            Module::StableTest.from_ic0("stable_read", Params3(0, 0, 8192), Result::No),
            8_225_000_007,
        ),
        common::Benchmark(
            "ic0_stable_write()/1B",
            Module::StableTest.from_ic0("stable_write", Params3(0, 0, 1), Result::No),
            34_000_007,
        ),
        common::Benchmark(
            "ic0_stable_write()/8K",
            Module::StableTest.from_ic0("stable_write", Params3(0, 0, 8192), Result::No),
            8_225_000_007,
        ),
        common::Benchmark(
            "ic0_stable64_size()",
            Module::Test.from_ic0("stable64_size", NoParams, Result::I64),
            11_000_004,
        ),
        common::Benchmark(
            "ic0_stable64_grow()",
            Module::Test.from_ic0("stable64_grow", Param1(1_i64), Result::I64),
            12_000_004,
        ),
        common::Benchmark(
            "ic0_stable64_read()/1B",
            Module::StableTest.from_ic0("stable64_read", Params3(0_i64, 0_i64, 1_i64), Result::No),
            34_000_007,
        ),
        common::Benchmark(
            "ic0_stable64_read()/8K",
            Module::StableTest.from_ic0(
                "stable64_read",
                Params3(0_i64, 0_i64, 8192_i64),
                Result::No,
            ),
            8_225_000_007,
        ),
        common::Benchmark(
            "ic0_stable64_write()/1B",
            Module::StableTest.from_ic0("stable64_write", Params3(0_i64, 0_i64, 1_i64), Result::No),
            34_000_007,
        ),
        common::Benchmark(
            "ic0_stable64_write()/8K",
            Module::StableTest.from_ic0(
                "stable64_write",
                Params3(0_i64, 0_i64, 8192_i64),
                Result::No,
            ),
            8_225_000_007,
        ),
        common::Benchmark(
            "ic0_time()",
            Module::Test.from_ic0("time", NoParams, Result::I64),
            11_000_004,
        ),
        common::Benchmark(
            "ic0_global_timer_set()",
            Module::Test.from_ic0("global_timer_set", Param1(0_i64), Result::I64),
            12_000_004,
        ),
        common::Benchmark(
            "ic0_performance_counter()",
            Module::Test.from_ic0("performance_counter", Param1(0), Result::I64),
            212_000_004,
        ),
        common::Benchmark(
            "ic0_canister_cycle_balance()",
            Module::Test.from_ic0("canister_cycle_balance", NoParams, Result::I64),
            11_000_004,
        ),
        common::Benchmark(
            "ic0_canister_cycle_balance128()",
            Module::Test.from_ic0("canister_cycle_balance128", Param1(0), Result::No),
            11_000_004,
        ),
        common::Benchmark(
            "ic0_msg_cycles_available()",
            Module::Test.from_ic0("msg_cycles_available", NoParams, Result::I64),
            11_000_004,
        ),
        common::Benchmark(
            "ic0_msg_cycles_available128()",
            Module::Test.from_ic0("msg_cycles_available128", Param1(0), Result::No),
            11_000_004,
        ),
        common::Benchmark(
            "ic0_msg_cycles_accept()",
            Module::Test.from_ic0("msg_cycles_accept", Param1(1_i64), Result::I64),
            12_000_004,
        ),
        common::Benchmark(
            "ic0_msg_cycles_accept128()",
            Module::Test.from_ic0(
                "msg_cycles_accept128",
                Params3(1_i64, 2_i64, 3_i32),
                Result::No,
            ),
            13_000_004,
        ),
        common::Benchmark(
            "ic0_data_certificate_present()",
            Module::Test.from_ic0("data_certificate_present", NoParams, Result::I32),
            11_000_004,
        ),
        common::Benchmark(
            "ic0_certified_data_set()/1B",
            Module::Test.from_ic0("certified_data_set", Params2(0, 1), Result::No),
            12_000_004,
        ),
        common::Benchmark(
            "ic0_certified_data_set()/32B",
            Module::Test.from_ic0("certified_data_set", Params2(0, 32), Result::No), // 32B max
            12_000_004,
        ),
        common::Benchmark(
            "ic0_canister_status()",
            Module::Test.from_ic0("canister_status", NoParams, Result::I32),
            11_000_004,
        ),
        common::Benchmark(
            "ic0_mint_cycles()",
            Module::Test.from_ic0("mint_cycles", Param1(1_i64), Result::I64),
            12_000_004,
        ),
        common::Benchmark(
            "ic0_is_controller()",
            Module::Test.from_ic0("is_controller", Params2(0, 29), Result::I32),
            905_000_004,
        ),
    ];
    common::run_benchmarks(
        c,
        "update",
        &benchmarks,
        |exec_env: &ExecutionEnvironment,
         expected_instructions,
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
                execution_complexity: ExecutionComplexity::MAX,
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
            let executed_instructions =
                as_num_instructions(instructions_before - round_limits.instructions);
            let response = match res {
                ExecuteMessageResult::Finished { response, .. } => response,
                ExecuteMessageResult::Paused { .. } => panic!("Unexpected paused execution"),
            };
            match response {
                ExecutionResponse::Ingress((_, status)) => match status {
                    IngressStatus::Known { state, .. } => {
                        if let IngressState::Failed(err) = state {
                            assert_eq!(err.code(), ErrorCode::CanisterDidNotReply)
                        }
                    }
                    _ => panic!("Unexpected ingress status"),
                },
                _ => panic!("Expected ingress result"),
            }
            assert_eq!(
                expected_instructions,
                executed_instructions.get(),
                "Error comparing number of actual and expected instructions"
            );
        },
    );
}

criterion_group!(benchmarks, execute_update_bench);
criterion_main!(benchmarks);
