///
/// Benchmark System API performance in `execute_update()`.
///
use criterion::{criterion_group, criterion_main, Criterion};
use execution_environment_bench::{common, wat::*};
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

use crate::common::Wasm64;

pub fn execute_update_bench(c: &mut Criterion) {
    // List of benchmarks: benchmark id (name), WAT, expected instructions.
    let benchmarks: Vec<common::Benchmark> = vec![
        common::Benchmark(
            "baseline/empty test*".into(),
            Module::Test.from_sections(("", "(drop (i32.const 0))")),
            3,
        ),
        common::Benchmark(
            "baseline/empty loop".into(),
            Module::Test.from_sections(("", Module::render_loop(LoopIterations::Mi, ""))),
            11000006,
        ),
        common::Benchmark(
            "baseline/adds".into(),
            Module::Test.from_sections((
                "",
                Module::render_loop(
                    LoopIterations::Mi,
                    "(local.set $s (i32.add (local.get $s) (i32.load (i32.const 0))))",
                ),
            )),
            16000006,
        ),
        common::Benchmark(
            "ic0_msg_caller_size()".into(),
            Module::Test.from_ic0("msg_caller_size", NoParams, Result::I32),
            517000006,
        ),
        common::Benchmark(
            "ic0_msg_caller_copy()/1B".into(),
            Module::Test.from_ic0("msg_caller_copy", Params3(0, 0, 1), Result::No),
            520000006,
        ),
        common::Benchmark(
            "ic0_msg_caller_copy()/10B".into(),
            Module::Test.from_ic0("msg_caller_copy", Params3(0, 0, 10), Result::No), // 10B max
            529001006,
        ),
        common::Benchmark(
            "ic0_msg_arg_data_size()".into(),
            Module::Test.from_ic0("msg_arg_data_size", NoParams, Result::I32),
            517000006,
        ),
        common::Benchmark(
            "ic0_msg_arg_data_copy()/1B".into(),
            Module::Test.from_ic0("msg_arg_data_copy", Params3(0, 0, 1), Result::No),
            520000006,
        ),
        common::Benchmark(
            "ic0_msg_arg_data_copy()/1K".into(),
            Module::Test.from_ic0("msg_arg_data_copy", Params3(0, 0, 1024), Result::No),
            1543000006,
        ),
        common::Benchmark(
            "ic0_msg_reply()*".into(),
            // We can reply just once
            Module::Test.from_sections(Module::sections(
                LoopIterations::One,
                "msg_reply",
                NoParams,
                Result::No,
            )),
            506,
        ),
        common::Benchmark(
            "ic0_msg_reply_data_append()/1B".into(),
            Module::Test.from_ic0("msg_reply_data_append", Params2(0, 1), Result::No), // 2MiB max
            568000006,
        ),
        common::Benchmark(
            "ic0_msg_reply_data_append()/2B".into(),
            Module::Test.from_ic0("msg_reply_data_append", Params2(0, 2), Result::No), // 2MiB max
            618000006,
        ),
        common::Benchmark(
            "ic0_msg_reject()*".into(),
            // We can reject just once
            Module::Test.from_sections(Module::sections(
                LoopIterations::One,
                "msg_reject",
                Params2(0, 0),
                Result::No,
            )),
            508,
        ),
        common::Benchmark(
            "ic0_canister_self_size()".into(),
            Module::Test.from_ic0("canister_self_size", NoParams, Result::I32),
            517000006,
        ),
        common::Benchmark(
            "ic0_canister_self_copy()/1B".into(),
            Module::Test.from_ic0("canister_self_copy", Params3(0, 0, 1), Result::No),
            520000006,
        ),
        common::Benchmark(
            "ic0_canister_self_copy()/10B".into(),
            Module::Test.from_ic0("canister_self_copy", Params3(0, 0, 10), Result::No), // 10B max
            529001006,
        ),
        common::Benchmark(
            "ic0_debug_print()/1B".into(),
            Module::Test.from_ic0("debug_print", Params2(0, 1), Result::No),
            170000006,
        ),
        common::Benchmark(
            "ic0_debug_print()/1K".into(),
            Module::Test.from_ic0("debug_print", Params2(0, 1024), Result::No),
            47366018006,
        ),
        common::Benchmark(
            "ic0_call_new()".into(),
            Module::CallNewLoop.from_sections(("", "")), // call_new in a loop is rendered by default
            1552000006,
        ),
        common::Benchmark(
            "call_new+ic0_call_data_append()/1B".into(),
            Module::CallNewLoop.from_ic0("call_data_append", Params2(0, 1), Result::No), // 2MiB max
            2109000006,
        ),
        common::Benchmark(
            "call_new+ic0_call_data_append()/1K".into(),
            Module::CallNewLoop.from_ic0("call_data_append", Params2(0, 1024), Result::No),
            53259000006,
        ),
        common::Benchmark(
            "call_new+ic0_call_on_cleanup()".into(),
            Module::CallNewLoop.from_ic0("call_on_cleanup", Params2(33, 0), Result::No),
            2059000006,
        ),
        common::Benchmark(
            "call_new+ic0_call_cycles_add()".into(),
            Module::CallNewLoop.from_ic0("call_cycles_add", Param1(100_i64), Result::No),
            2058000006,
        ),
        common::Benchmark(
            "call_new+ic0_call_cycles_add128()".into(),
            Module::CallNewLoop.from_ic0("call_cycles_add128", Params2(0_i64, 100_i64), Result::No),
            2059000006,
        ),
        common::Benchmark(
            "call_new+ic0_call_perform()".into(),
            Module::CallNewLoop.from_ic0("call_perform", NoParams, Result::I32),
            6558000006,
        ),
        common::Benchmark(
            "ic0_stable_size()".into(),
            Module::Test.from_ic0("stable_size", NoParams, Result::I32),
            17000006,
        ),
        common::Benchmark(
            "ic0_stable_grow()".into(),
            Module::Test.from_ic0("stable_grow", Param1(0), Result::I32),
            118000006,
        ),
        common::Benchmark(
            "ic0_stable_read()/1B".into(),
            Module::StableTest.from_ic0("stable_read", Params3(0, 0, 1), Result::No),
            40000113,
        ),
        common::Benchmark(
            "ic0_stable_read()/1K".into(),
            Module::StableTest.from_ic0("stable_read", Params3(0, 0, 1024), Result::No),
            1063000113,
        ),
        common::Benchmark(
            "ic0_stable_write()/1B".into(),
            Module::StableTest.from_ic0("stable_write", Params3(0, 0, 1), Result::No),
            40001113,
        ),
        common::Benchmark(
            "ic0_stable_write()/1K".into(),
            Module::StableTest.from_ic0("stable_write", Params3(0, 0, 1024), Result::No),
            1063001113,
        ),
        common::Benchmark(
            "ic0_stable64_size()".into(),
            Module::Test.from_ic0("stable64_size", NoParams, Result::I64),
            17000006,
        ),
        common::Benchmark(
            "ic0_stable64_grow()".into(),
            Module::Test.from_ic0("stable64_grow", Param1(0_i64), Result::I64),
            118000006,
        ),
        common::Benchmark(
            "ic0_stable64_read()/1B".into(),
            Module::StableTest.from_ic0("stable64_read", Params3(0_i64, 0_i64, 1_i64), Result::No),
            40000113,
        ),
        common::Benchmark(
            "ic0_stable64_read()/1K".into(),
            Module::StableTest.from_ic0(
                "stable64_read",
                Params3(0_i64, 0_i64, 1024_i64),
                Result::No,
            ),
            1063000113,
        ),
        common::Benchmark(
            "ic0_stable64_write()/1B".into(),
            Module::StableTest.from_ic0("stable64_write", Params3(0_i64, 0_i64, 1_i64), Result::No),
            40001113,
        ),
        common::Benchmark(
            "ic0_stable64_write()/1K".into(),
            Module::StableTest.from_ic0(
                "stable64_write",
                Params3(0_i64, 0_i64, 1024_i64),
                Result::No,
            ),
            1063001113,
        ),
        common::Benchmark(
            "ic0_time()".into(),
            Module::Test.from_ic0("time", NoParams, Result::I64),
            517000006,
        ),
        common::Benchmark(
            "ic0_global_timer_set()".into(),
            Module::Test.from_ic0("global_timer_set", Param1(0_i64), Result::I64),
            518000006,
        ),
        common::Benchmark(
            "ic0_performance_counter()".into(),
            Module::Test.from_ic0("performance_counter", Param1(0), Result::I64),
            218000006,
        ),
        common::Benchmark(
            "ic0_canister_cycle_balance()".into(),
            Module::Test.from_ic0("canister_cycle_balance", NoParams, Result::I64),
            517000006,
        ),
        common::Benchmark(
            "ic0_canister_cycle_balance128()".into(),
            Module::Test.from_ic0("canister_cycle_balance128", Param1(0), Result::No),
            517001006,
        ),
        common::Benchmark(
            "ic0_msg_cycles_available()".into(),
            Module::Test.from_ic0("msg_cycles_available", NoParams, Result::I64),
            517000006,
        ),
        common::Benchmark(
            "ic0_msg_cycles_available128()".into(),
            Module::Test.from_ic0("msg_cycles_available128", Param1(0), Result::No),
            517000006,
        ),
        common::Benchmark(
            "ic0_msg_cycles_accept()".into(),
            Module::Test.from_ic0("msg_cycles_accept", Param1(1_i64), Result::I64),
            518000006,
        ),
        common::Benchmark(
            "ic0_msg_cycles_accept128()".into(),
            Module::Test.from_ic0(
                "msg_cycles_accept128",
                Params3(1_i64, 2_i64, 3_i32),
                Result::No,
            ),
            519000006,
        ),
        common::Benchmark(
            "ic0_data_certificate_present()".into(),
            Module::Test.from_ic0("data_certificate_present", NoParams, Result::I32),
            517000006,
        ),
        common::Benchmark(
            "ic0_certified_data_set()/1B".into(),
            Module::Test.from_ic0("certified_data_set", Params2(0, 1), Result::No),
            519000006,
        ),
        common::Benchmark(
            "ic0_certified_data_set()/32B".into(),
            Module::Test.from_ic0("certified_data_set", Params2(0, 32), Result::No), // 32B max
            550000006,
        ),
        common::Benchmark(
            "ic0_canister_status()".into(),
            Module::Test.from_ic0("canister_status", NoParams, Result::I32),
            517000006,
        ),
        common::Benchmark(
            "ic0_mint_cycles()".into(),
            Module::Test.from_ic0("mint_cycles", Param1(1_i64), Result::I64),
            18000006,
        ),
        common::Benchmark(
            "ic0_is_controller()".into(),
            Module::Test.from_ic0("is_controller", Params2(0, 29), Result::I32),
            1048000006,
        ),
        common::Benchmark(
            "ic0_in_replicated_execution()".into(),
            Module::Test.from_ic0("in_replicated_execution", NoParams, Result::I32),
            517000006,
        ),
        common::Benchmark(
            "ic0_cycles_burn128()".into(),
            Module::Test.from_ic0("cycles_burn128", Params3(1_i64, 2_i64, 3_i32), Result::No),
            19000006,
        ),
        common::Benchmark(
            "ic0_call_with_best_effort_response()".into(),
            Module::CallNewLoop.from_ic0(
                "call_with_best_effort_response",
                Param1(1_i32),
                Result::No,
            ),
            2058000006,
        ),
        common::Benchmark(
            "ic0_msg_deadline()".into(),
            Module::Test.from_ic0("msg_deadline", NoParams, Result::I64),
            517000006,
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
            let ExecutionResponse::Ingress((_, status)) = response else {
                panic!("Expected ingress result");
            };
            let IngressStatus::Known { state, .. } = status else {
                panic!("Unexpected ingress status");
            };
            if let IngressState::Failed(err) = state {
                assert_eq!(err.code(), ErrorCode::CanisterDidNotReply)
            }
            assert_eq!(
                expected_instructions,
                executed_instructions.get(),
                "Error comparing number of actual and expected instructions"
            );
        },
        Wasm64::Disabled,
    );
}

criterion_group!(benchmarks, execute_update_bench);
criterion_main!(benchmarks);
