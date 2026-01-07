//! Benchmark System API performance in `execute_update()`.
//!
//! This benchmark runs nightly in CI, and the results are available in Grafana.
//! See: `schedule-rust-bench.yml`
//!
//! To run the benchmark locally:
//!
//! ```shell
//! bazel run //rs/execution_environment:execute_update_bench
//! ```

use candid::{CandidType, Deserialize};
use criterion::{Criterion, criterion_group, criterion_main};
use execution_environment_bench::{common, wat::*};
use ic_error_types::ErrorCode;
use ic_execution_environment::{
    ExecuteMessageResult, ExecutionEnvironment, ExecutionResponse, RoundLimits,
    as_num_instructions, as_round_instructions,
};
use ic_limits::SMALL_APP_SUBNET_MAX_SIZE;
use ic_types::{
    batch::CanisterCyclesCostSchedule,
    ingress::{IngressState, IngressStatus},
    messages::CanisterMessageOrTask,
};

use crate::common::Wasm64;

#[derive(CandidType, Deserialize)]
struct CostHttpRequestV2Params {
    request_bytes: u64,
    http_roundtrip_time_ms: u64,
    raw_response_bytes: u64,
    transformed_response_bytes: u64,
    transform_instructions: u64,
}

const COST_HTTP_REQUEST_V2_PARAMS: CostHttpRequestV2Params = CostHttpRequestV2Params {
    request_bytes: 1_000,
    http_roundtrip_time_ms: 2_000,
    raw_response_bytes: 3_000,
    transformed_response_bytes: 2_000,
    transform_instructions: 1_000_000,
};

pub fn execute_update_bench(c: &mut Criterion) {
    // List of benchmarks: benchmark id (name), WAT, expected instructions.
    // We have one benchmark for Wasm32 and one for Wasm64.
    let benchmarks: Vec<common::Benchmark> = vec![
        common::Benchmark(
            "wasm32/baseline/empty test*".into(),
            Module::Test.from_sections(("", "", "(drop (i32.const 0))"), Wasm64::Disabled),
            3,
        ),
        common::Benchmark(
            "wasm64/baseline/empty test*".into(),
            Module::Test.from_sections(("", "", "(drop (i32.const 0))"), Wasm64::Enabled),
            3,
        ),
        common::Benchmark(
            "wasm32/baseline/empty loop".into(),
            Module::Test.from_sections(
                (
                    "",
                    "",
                    Module::render_loop(LoopIterations::Mi, "", Wasm64::Disabled),
                ),
                Wasm64::Disabled,
            ),
            11000006,
        ),
        common::Benchmark(
            "wasm64/baseline/empty loop".into(),
            Module::Test.from_sections(
                (
                    "",
                    "",
                    Module::render_loop(LoopIterations::Mi, "", Wasm64::Enabled),
                ),
                Wasm64::Enabled,
            ),
            11000006,
        ),
        common::Benchmark(
            "wasm32/baseline/adds".into(),
            Module::Test.from_sections(
                (
                    "",
                    "",
                    Module::render_loop(
                        LoopIterations::Mi,
                        "(local.set $s (i32.add (local.get $s) (i32.load (i32.const 0))))",
                        Wasm64::Disabled,
                    ),
                ),
                Wasm64::Disabled,
            ),
            16000006,
        ),
        common::Benchmark(
            "wasm64/baseline/adds".into(),
            Module::Test.from_sections(
                (
                    "",
                    "",
                    Module::render_loop(
                        LoopIterations::Mi,
                        "(local.set $s (i64.add (local.get $s) (i64.load (i64.const 0))))",
                        Wasm64::Enabled,
                    ),
                ),
                Wasm64::Enabled,
            ),
            // Number of instructions is different in Wasm64 mode because charging is different, i.e., instructions have different weights.
            17000006,
        ),
        common::Benchmark(
            "wasm32/ic0_msg_caller_size()".into(),
            Module::Test.from_ic0("msg_caller_size", NoParams, Result::I32, Wasm64::Disabled),
            517000006,
        ),
        common::Benchmark(
            "wasm64/ic0_msg_caller_size()".into(),
            Module::Test.from_ic0("msg_caller_size", NoParams, Result::I64, Wasm64::Enabled),
            517000006,
        ),
        common::Benchmark(
            "wasm32/ic0_msg_caller_copy()/1B".into(),
            Module::Test.from_ic0(
                "msg_caller_copy",
                Params3(0_i32, 0_i32, 1_i32),
                Result::No,
                Wasm64::Disabled,
            ),
            520000006,
        ),
        common::Benchmark(
            "wasm64/ic0_msg_caller_copy()/1B".into(),
            Module::Test.from_ic0(
                "msg_caller_copy",
                Params3(0_i64, 0_i64, 1_i64),
                Result::No,
                Wasm64::Enabled,
            ),
            520000006,
        ),
        common::Benchmark(
            "wasm32/ic0_msg_caller_copy()/10B".into(),
            Module::Test.from_ic0(
                "msg_caller_copy",
                Params3(0, 0, 10),
                Result::No,
                Wasm64::Disabled,
            ), // 10B max
            529001006,
        ),
        common::Benchmark(
            "wasm364/ic0_msg_caller_copy()/10B".into(),
            Module::Test.from_ic0(
                "msg_caller_copy",
                Params3(0_i64, 0_i64, 1_i64),
                Result::No,
                Wasm64::Enabled,
            ), // 10B max
            520000006,
        ),
        common::Benchmark(
            "wasm32/ic0_msg_arg_data_size()".into(),
            Module::Test.from_ic0("msg_arg_data_size", NoParams, Result::I32, Wasm64::Disabled),
            517000006,
        ),
        common::Benchmark(
            "wasm64/ic0_msg_arg_data_size()".into(),
            Module::Test.from_ic0("msg_arg_data_size", NoParams, Result::I64, Wasm64::Enabled),
            517000006,
        ),
        common::Benchmark(
            "wasm32/ic0_msg_arg_data_copy()/1B".into(),
            Module::Test.from_ic0(
                "msg_arg_data_copy",
                Params3(0, 0, 1),
                Result::No,
                Wasm64::Disabled,
            ),
            520000006,
        ),
        common::Benchmark(
            "wasm64/ic0_msg_arg_data_copy()/1B".into(),
            Module::Test.from_ic0(
                "msg_arg_data_copy",
                Params3(0_i64, 0_i64, 1_i64),
                Result::No,
                Wasm64::Enabled,
            ),
            520000006,
        ),
        common::Benchmark(
            "wasm32/ic0_msg_arg_data_copy()/1K".into(),
            Module::Test.from_ic0(
                "msg_arg_data_copy",
                Params3(0, 0, 1024),
                Result::No,
                Wasm64::Disabled,
            ),
            1_543_000_006,
        ),
        common::Benchmark(
            "wasm64/ic0_msg_arg_data_copy()/1K".into(),
            Module::Test.from_ic0(
                "msg_arg_data_copy",
                Params3(0_i64, 0_i64, 1024_i64),
                Result::No,
                Wasm64::Enabled,
            ),
            1_543_000_006,
        ),
        common::Benchmark(
            "wasm32/ic0_msg_reply()*".into(),
            // We can reply just once
            Module::Test.from_sections(
                Module::sections(
                    LoopIterations::One,
                    "msg_reply",
                    NoParams,
                    Result::No,
                    "",
                    Wasm64::Disabled,
                ),
                Wasm64::Disabled,
            ),
            506,
        ),
        common::Benchmark(
            "wasm64/ic0_msg_reply()*".into(),
            // We can reply just once
            Module::Test.from_sections(
                Module::sections(
                    LoopIterations::One,
                    "msg_reply",
                    NoParams,
                    Result::No,
                    "",
                    Wasm64::Enabled,
                ),
                Wasm64::Enabled,
            ),
            506,
        ),
        common::Benchmark(
            "wasm32/ic0_msg_reply_data_append()/1B".into(),
            Module::Test.from_ic0(
                "msg_reply_data_append",
                Params2(0, 1),
                Result::No,
                Wasm64::Disabled,
            ), // 2MiB max
            568000006,
        ),
        common::Benchmark(
            "wasm64/ic0_msg_reply_data_append()/1B".into(),
            Module::Test.from_ic0(
                "msg_reply_data_append",
                Params2(0_i64, 1_i64),
                Result::No,
                Wasm64::Enabled,
            ), // 2MiB max
            568000006,
        ),
        common::Benchmark(
            "wasm32/ic0_msg_reply_data_append()/2B".into(),
            Module::Test.from_ic0(
                "msg_reply_data_append",
                Params2(0, 2),
                Result::No,
                Wasm64::Disabled,
            ), // 2MiB max
            618000006,
        ),
        common::Benchmark(
            "wasm64/ic0_msg_reply_data_append()/2B".into(),
            Module::Test.from_ic0(
                "msg_reply_data_append",
                Params2(0_i64, 2_i64),
                Result::No,
                Wasm64::Enabled,
            ), // 2MiB max
            618000006,
        ),
        common::Benchmark(
            "wasm32/ic0_msg_reject()*".into(),
            // We can reject just once
            Module::Test.from_sections(
                Module::sections(
                    LoopIterations::One,
                    "msg_reject",
                    Params2(0, 0),
                    Result::No,
                    "",
                    Wasm64::Disabled,
                ),
                Wasm64::Disabled,
            ),
            508,
        ),
        common::Benchmark(
            "wasm64/ic0_msg_reject()*".into(),
            // We can reject just once
            Module::Test.from_sections(
                Module::sections(
                    LoopIterations::One,
                    "msg_reject",
                    Params2(0_i64, 0_i64),
                    Result::No,
                    "",
                    Wasm64::Enabled,
                ),
                Wasm64::Enabled,
            ),
            508,
        ),
        common::Benchmark(
            "wasm32/ic0_canister_self_size()".into(),
            Module::Test.from_ic0(
                "canister_self_size",
                NoParams,
                Result::I32,
                Wasm64::Disabled,
            ),
            517000006,
        ),
        common::Benchmark(
            "wasm64/ic0_canister_self_size()".into(),
            Module::Test.from_ic0("canister_self_size", NoParams, Result::I64, Wasm64::Enabled),
            517000006,
        ),
        common::Benchmark(
            "wasm32/ic0_canister_self_copy()/1B".into(),
            Module::Test.from_ic0(
                "canister_self_copy",
                Params3(0, 0, 1),
                Result::No,
                Wasm64::Disabled,
            ),
            520000006,
        ),
        common::Benchmark(
            "wasm64/ic0_canister_self_copy()/1B".into(),
            Module::Test.from_ic0(
                "canister_self_copy",
                Params3(0_i64, 0_i64, 1_i64),
                Result::No,
                Wasm64::Enabled,
            ),
            520000006,
        ),
        common::Benchmark(
            "wasm32/ic0_canister_self_copy()/10B".into(),
            Module::Test.from_ic0(
                "canister_self_copy",
                Params3(0, 0, 10),
                Result::No,
                Wasm64::Disabled,
            ), // 10B max
            529001006,
        ),
        common::Benchmark(
            "wasm64/ic0_canister_self_copy()/10B".into(),
            Module::Test.from_ic0(
                "canister_self_copy",
                Params3(0_i64, 0_i64, 10_i64),
                Result::No,
                Wasm64::Enabled,
            ), // 10B max
            529004006,
        ),
        common::Benchmark(
            "wasm32/ic0_debug_print()/1B".into(),
            Module::Test.from_ic0("debug_print", Params2(0, 1), Result::No, Wasm64::Disabled),
            170000006,
        ),
        common::Benchmark(
            "wasm64/ic0_debug_print()/1B".into(),
            Module::Test.from_ic0(
                "debug_print",
                Params2(0_i64, 1_i64),
                Result::No,
                Wasm64::Enabled,
            ),
            170000006,
        ),
        common::Benchmark(
            "wasm32/ic0_debug_print()/1K".into(),
            Module::Test.from_ic0(
                "debug_print",
                Params2(0, 1024),
                Result::No,
                Wasm64::Disabled,
            ),
            47366018006,
        ),
        common::Benchmark(
            "wasm64/ic0_debug_print()/1K".into(),
            Module::Test.from_ic0(
                "debug_print",
                Params2(0_i64, 1024_i64),
                Result::No,
                Wasm64::Enabled,
            ),
            47366018006,
        ),
        common::Benchmark(
            "wasm32/ic0_call_new()".into(),
            Module::CallNewLoop.from_sections(("", "", ""), Wasm64::Disabled), // call_new in a loop is rendered by default
            1552000006,
        ),
        common::Benchmark(
            "wasm64/ic0_call_new()".into(),
            Module::CallNewLoop.from_sections(("", "", ""), Wasm64::Enabled), // call_new in a loop is rendered by default
            1552000006,
        ),
        common::Benchmark(
            "wasm32/call_new+ic0_call_cycles_add()".into(),
            Module::CallNewLoop.from_ic0(
                "call_cycles_add",
                Param1(100_i64),
                Result::No,
                Wasm64::Disabled,
            ),
            2058000006,
        ),
        common::Benchmark(
            "wasm32/call_new+ic0_call_data_append()/1B".into(),
            Module::CallNewLoop.from_ic0(
                "call_data_append",
                Params2(0, 1),
                Result::No,
                Wasm64::Disabled,
            ), // 2MiB max
            2109000006,
        ),
        common::Benchmark(
            "wasm64/call_new+ic0_call_data_append()/1B".into(),
            Module::CallNewLoop.from_ic0(
                "call_data_append",
                Params2(0_i64, 1_i64),
                Result::No,
                Wasm64::Enabled,
            ), // 2MiB max
            2109000006,
        ),
        common::Benchmark(
            "wasm32/call_new+ic0_call_data_append()/1K".into(),
            Module::CallNewLoop.from_ic0(
                "call_data_append",
                Params2(0, 1024),
                Result::No,
                Wasm64::Disabled,
            ),
            53259000006,
        ),
        common::Benchmark(
            "wasm64/call_new+ic0_call_data_append()/1K".into(),
            Module::CallNewLoop.from_ic0(
                "call_data_append",
                Params2(0_i64, 1024_i64),
                Result::No,
                Wasm64::Enabled,
            ),
            53259000006,
        ),
        common::Benchmark(
            "wasm32/call_new+ic0_call_on_cleanup()".into(),
            Module::CallNewLoop.from_ic0(
                "call_on_cleanup",
                Params2(33, 0),
                Result::No,
                Wasm64::Disabled,
            ),
            2059000006,
        ),
        common::Benchmark(
            "wasm64/call_new+ic0_call_on_cleanup()".into(),
            Module::CallNewLoop.from_ic0(
                "call_on_cleanup",
                Params2(33_i64, 0_i64),
                Result::No,
                Wasm64::Enabled,
            ),
            2059000006,
        ),
        common::Benchmark(
            "wasm32/call_new+ic0_call_cycles_add128()".into(),
            Module::CallNewLoop.from_ic0(
                "call_cycles_add128",
                Params2(0_i64, 100_i64),
                Result::No,
                Wasm64::Disabled,
            ),
            2059000006,
        ),
        common::Benchmark(
            "wasm64/call_new+ic0_call_cycles_add128()".into(),
            Module::CallNewLoop.from_ic0(
                "call_cycles_add128",
                Params2(0_i64, 100_i64),
                Result::No,
                Wasm64::Enabled,
            ),
            2059000006,
        ),
        common::Benchmark(
            "wasm32/call_new+ic0_call_perform()".into(),
            Module::CallNewLoop.from_ic0("call_perform", NoParams, Result::I32, Wasm64::Disabled),
            6558000006,
        ),
        common::Benchmark(
            "wasm64/call_new+ic0_call_perform()".into(),
            Module::CallNewLoop.from_ic0("call_perform", NoParams, Result::I32, Wasm64::Enabled),
            6558000006,
        ),
        common::Benchmark(
            "wasm32/ic0_stable64_size()".into(),
            Module::Test.from_ic0("stable64_size", NoParams, Result::I64, Wasm64::Disabled),
            17000006,
        ),
        common::Benchmark(
            "wasm64/ic0_stable64_size()".into(),
            Module::Test.from_ic0("stable64_size", NoParams, Result::I64, Wasm64::Enabled),
            17000006,
        ),
        common::Benchmark(
            "wasm32/call_new+ic0_call_with_best_effort_response()".into(),
            Module::CallNewLoop.from_ic0(
                "call_with_best_effort_response",
                Param1(1_i32),
                Result::No,
                Wasm64::Disabled,
            ),
            2058000006,
        ),
        common::Benchmark(
            "wasm64/call_new+ic0_call_with_best_effort_response()".into(),
            Module::CallNewLoop.from_ic0(
                "call_with_best_effort_response",
                Param1(1_i32),
                Result::No,
                Wasm64::Enabled,
            ),
            2058000006,
        ),
        common::Benchmark(
            "wasm32/ic0_stable_size()".into(),
            Module::Test.from_ic0("stable_size", NoParams, Result::I32, Wasm64::Disabled),
            17000006,
        ),
        common::Benchmark(
            "wasm32/ic0_stable_grow()".into(),
            Module::Test.from_ic0("stable_grow", Param1(0), Result::I32, Wasm64::Disabled),
            118000006,
        ),
        common::Benchmark(
            "wasm32/ic0_stable64_grow()".into(),
            Module::Test.from_ic0(
                "stable64_grow",
                Param1(0_i64),
                Result::I64,
                Wasm64::Disabled,
            ),
            118000006,
        ),
        common::Benchmark(
            "wasm64/ic0_stable64_grow()".into(),
            Module::Test.from_ic0("stable64_grow", Param1(0_i64), Result::I64, Wasm64::Enabled),
            118000006,
        ),
        common::Benchmark(
            "wasm32/ic0_stable_read()/1B".into(),
            Module::StableTest.from_ic0(
                "stable_read",
                Params3(0, 0, 1),
                Result::No,
                Wasm64::Disabled,
            ),
            40000113,
        ),
        common::Benchmark(
            "wasm32/ic0_stable64_read()/1B".into(),
            Module::StableTest.from_ic0(
                "stable64_read",
                Params3(0_i64, 0_i64, 1_i64),
                Result::No,
                Wasm64::Disabled,
            ),
            40000113,
        ),
        common::Benchmark(
            "wasm64/ic0_stable64_read()/1B".into(),
            Module::StableTest.from_ic0(
                "stable64_read",
                Params3(0_i64, 0_i64, 1_i64),
                Result::No,
                Wasm64::Enabled,
            ),
            40000113,
        ),
        common::Benchmark(
            "wasm32/ic0_stable_read()/1K".into(),
            Module::StableTest.from_ic0(
                "stable_read",
                Params3(0, 0, 1024),
                Result::No,
                Wasm64::Disabled,
            ),
            1063000113,
        ),
        common::Benchmark(
            "wasm32/ic0_stable64_read()/1K".into(),
            Module::StableTest.from_ic0(
                "stable64_read",
                Params3(0_i64, 0_i64, 1024_i64),
                Result::No,
                Wasm64::Disabled,
            ),
            1063000113,
        ),
        common::Benchmark(
            "wasm64/ic0_stable64_read()/1K".into(),
            Module::StableTest.from_ic0(
                "stable64_read",
                Params3(0_i64, 0_i64, 1024_i64),
                Result::No,
                Wasm64::Enabled,
            ),
            1063000113,
        ),
        common::Benchmark(
            "wasm32/ic0_stable_write()/1B".into(),
            Module::StableTest.from_ic0(
                "stable_write",
                Params3(0, 0, 1),
                Result::No,
                Wasm64::Disabled,
            ),
            40001113,
        ),
        common::Benchmark(
            "wasm32/ic0_stable64_write()/1B".into(),
            Module::StableTest.from_ic0(
                "stable64_write",
                Params3(0_i64, 0_i64, 1_i64),
                Result::No,
                Wasm64::Disabled,
            ),
            40001113,
        ),
        common::Benchmark(
            "wasm64/ic0_stable64_write()/1B".into(),
            Module::StableTest.from_ic0(
                "stable64_write",
                Params3(0_i64, 0_i64, 1_i64),
                Result::No,
                Wasm64::Enabled,
            ),
            40001113,
        ),
        common::Benchmark(
            "wasm32/ic0_stable_write()/1K".into(),
            Module::StableTest.from_ic0(
                "stable_write",
                Params3(0, 0, 1024),
                Result::No,
                Wasm64::Disabled,
            ),
            1063001113,
        ),
        common::Benchmark(
            "wasm32/ic0_stable64_write()/1K".into(),
            Module::StableTest.from_ic0(
                "stable64_write",
                Params3(0_i64, 0_i64, 1024_i64),
                Result::No,
                Wasm64::Disabled,
            ),
            1063001113,
        ),
        common::Benchmark(
            "wasm64/ic0_stable64_write()/1K".into(),
            Module::StableTest.from_ic0(
                "stable64_write",
                Params3(0_i64, 0_i64, 1024_i64),
                Result::No,
                Wasm64::Enabled,
            ),
            1063001113,
        ),
        common::Benchmark(
            "wasm32/ic0_time()".into(),
            Module::Test.from_ic0("time", NoParams, Result::I64, Wasm64::Disabled),
            517000006,
        ),
        common::Benchmark(
            "wasm64/ic0_time()".into(),
            Module::Test.from_ic0("time", NoParams, Result::I64, Wasm64::Enabled),
            517000006,
        ),
        common::Benchmark(
            "wasm32/ic0_global_timer_set()".into(),
            Module::Test.from_ic0(
                "global_timer_set",
                Param1(0_i64),
                Result::I64,
                Wasm64::Disabled,
            ),
            518000006,
        ),
        common::Benchmark(
            "wasm64/ic0_global_timer_set()".into(),
            Module::Test.from_ic0(
                "global_timer_set",
                Param1(0_i64),
                Result::I64,
                Wasm64::Enabled,
            ),
            518000006,
        ),
        common::Benchmark(
            "wasm32/ic0_performance_counter()".into(),
            Module::Test.from_ic0(
                "performance_counter",
                Param1(0),
                Result::I64,
                Wasm64::Disabled,
            ),
            218000006,
        ),
        common::Benchmark(
            "wasm64/ic0_performance_counter()".into(),
            Module::Test.from_ic0(
                "performance_counter",
                Param1(0),
                Result::I64,
                Wasm64::Enabled,
            ),
            218000006,
        ),
        common::Benchmark(
            "wasm32/ic0_canister_cycle_balance()".into(),
            Module::Test.from_ic0(
                "canister_cycle_balance",
                NoParams,
                Result::I64,
                Wasm64::Disabled,
            ),
            517000006,
        ),
        common::Benchmark(
            "wasm32/ic0_canister_cycle_balance128()".into(),
            Module::Test.from_ic0(
                "canister_cycle_balance128",
                Param1(0),
                Result::No,
                Wasm64::Disabled,
            ),
            517001006,
        ),
        common::Benchmark(
            "wasm64/ic0_canister_cycle_balance128()".into(),
            Module::Test.from_ic0(
                "canister_cycle_balance128",
                Param1(0_i64),
                Result::No,
                Wasm64::Enabled,
            ),
            517004006,
        ),
        common::Benchmark(
            "wasm32/ic0_msg_cycles_available()".into(),
            Module::Test.from_ic0(
                "msg_cycles_available",
                NoParams,
                Result::I64,
                Wasm64::Disabled,
            ),
            517000006,
        ),
        common::Benchmark(
            "wasm32/ic0_msg_cycles_available128()".into(),
            Module::Test.from_ic0(
                "msg_cycles_available128",
                Param1(0),
                Result::No,
                Wasm64::Disabled,
            ),
            517000006,
        ),
        common::Benchmark(
            "wasm64/ic0_msg_cycles_available128()".into(),
            Module::Test.from_ic0(
                "msg_cycles_available128",
                Param1(0_i64),
                Result::No,
                Wasm64::Enabled,
            ),
            517000006,
        ),
        common::Benchmark(
            "wasm32/ic0_msg_cycles_accept()".into(),
            Module::Test.from_ic0(
                "msg_cycles_accept",
                Param1(1_i64),
                Result::I64,
                Wasm64::Disabled,
            ),
            518000006,
        ),
        common::Benchmark(
            "wasm32/ic0_msg_cycles_accept128()".into(),
            Module::Test.from_ic0(
                "msg_cycles_accept128",
                Params3(1_i64, 2_i64, 3_i32),
                Result::No,
                Wasm64::Disabled,
            ),
            519000006,
        ),
        common::Benchmark(
            "wasm64/ic0_msg_cycles_accept128()".into(),
            Module::Test.from_ic0(
                "msg_cycles_accept128",
                Params3(1_i64, 2_i64, 3_i64),
                Result::No,
                Wasm64::Enabled,
            ),
            519000006,
        ),
        common::Benchmark(
            "wasm32/ic0_data_certificate_present()".into(),
            Module::Test.from_ic0(
                "data_certificate_present",
                NoParams,
                Result::I32,
                Wasm64::Disabled,
            ),
            517000006,
        ),
        common::Benchmark(
            "wasm64/ic0_data_certificate_present()".into(),
            Module::Test.from_ic0(
                "data_certificate_present",
                NoParams,
                Result::I32,
                Wasm64::Enabled,
            ),
            517000006,
        ),
        common::Benchmark(
            "wasm32/ic0_certified_data_set()/1B".into(),
            Module::Test.from_ic0(
                "certified_data_set",
                Params2(0, 1),
                Result::No,
                Wasm64::Disabled,
            ),
            519000006,
        ),
        common::Benchmark(
            "wasm64/ic0_certified_data_set()/1B".into(),
            Module::Test.from_ic0(
                "certified_data_set",
                Params2(0_i64, 1_i64),
                Result::No,
                Wasm64::Enabled,
            ),
            519000006,
        ),
        common::Benchmark(
            "wasm32/ic0_certified_data_set()/32B".into(),
            Module::Test.from_ic0(
                "certified_data_set",
                Params2(0, 32),
                Result::No,
                Wasm64::Disabled,
            ), // 32B max
            550000006,
        ),
        common::Benchmark(
            "wasm64/ic0_certified_data_set()/32B".into(),
            Module::Test.from_ic0(
                "certified_data_set",
                Params2(0_i64, 32_i64),
                Result::No,
                Wasm64::Enabled,
            ), // 32B max
            550000006,
        ),
        common::Benchmark(
            "wasm32/ic0_canister_status()".into(),
            Module::Test.from_ic0("canister_status", NoParams, Result::I32, Wasm64::Disabled),
            517000006,
        ),
        common::Benchmark(
            "wasm64/ic0_canister_status()".into(),
            Module::Test.from_ic0("canister_status", NoParams, Result::I32, Wasm64::Enabled),
            517000006,
        ),
        common::Benchmark(
            "wasm32/ic0_mint_cycles128()".into(),
            Module::Test.from_ic0(
                "mint_cycles128",
                Params3(1_i64, 2_i64, 3_i32),
                Result::No,
                Wasm64::Disabled,
            ),
            19001006,
        ),
        common::Benchmark(
            "wasm64/ic0_mint_cycles128()".into(),
            Module::Test.from_ic0(
                "mint_cycles128",
                Params3(1_i64, 2_i64, 3_i64),
                Result::No,
                Wasm64::Enabled,
            ),
            19004006,
        ),
        common::Benchmark(
            "wasm32/ic0_is_controller()".into(),
            Module::Test.from_ic0(
                "is_controller",
                Params2(0, 29),
                Result::I32,
                Wasm64::Disabled,
            ),
            1048000006,
        ),
        common::Benchmark(
            "wasm64/ic0_is_controller()".into(),
            Module::Test.from_ic0(
                "is_controller",
                Params2(0_i64, 29_i64),
                Result::I32,
                Wasm64::Enabled,
            ),
            1048000006,
        ),
        common::Benchmark(
            "wasm32/ic0_in_replicated_execution()".into(),
            Module::Test.from_ic0(
                "in_replicated_execution",
                NoParams,
                Result::I32,
                Wasm64::Disabled,
            ),
            517000006,
        ),
        common::Benchmark(
            "wasm64/ic0_in_replicated_execution()".into(),
            Module::Test.from_ic0(
                "in_replicated_execution",
                NoParams,
                Result::I32,
                Wasm64::Enabled,
            ),
            517000006,
        ),
        common::Benchmark(
            "wasm32/ic0_cycles_burn128()".into(),
            Module::Test.from_ic0(
                "cycles_burn128",
                Params3(1_i64, 2_i64, 3_i32),
                Result::No,
                Wasm64::Disabled,
            ),
            519000006,
        ),
        common::Benchmark(
            "wasm64/ic0_cycles_burn128()".into(),
            Module::Test.from_ic0(
                "cycles_burn128",
                Params3(1_i64, 2_i64, 3_i64),
                Result::No,
                Wasm64::Enabled,
            ),
            519000006,
        ),
        common::Benchmark(
            "wasm32/ic0_msg_deadline()".into(),
            Module::Test.from_ic0("msg_deadline", NoParams, Result::I64, Wasm64::Disabled),
            517000006,
        ),
        common::Benchmark(
            "wasm64/ic0_msg_deadline()".into(),
            Module::Test.from_ic0("msg_deadline", NoParams, Result::I64, Wasm64::Enabled),
            517000006,
        ),
        common::Benchmark(
            "wasm32/ic0_cost_call()".into(),
            Module::Test.from_ic0(
                "cost_call",
                Params3(1_i64, 2_i64, 3_i32),
                Result::No,
                Wasm64::Disabled,
            ),
            519001006,
        ),
        common::Benchmark(
            "wasm64/ic0_cost_call()".into(),
            Module::Test.from_ic0(
                "cost_call",
                Params3(1_i64, 2_i64, 3_i64),
                Result::No,
                Wasm64::Enabled,
            ),
            519004006,
        ),
        common::Benchmark(
            "wasm32/ic0_cost_create_canister()".into(),
            Module::Test.from_ic0(
                "cost_create_canister",
                Param1(1_i32),
                Result::No,
                Wasm64::Disabled,
            ),
            517001006,
        ),
        common::Benchmark(
            "wasm64/ic0_cost_create_canister()".into(),
            Module::Test.from_ic0(
                "cost_create_canister",
                Param1(1_i64),
                Result::No,
                Wasm64::Enabled,
            ),
            517004006,
        ),
        common::Benchmark(
            "wasm32/ic0_cost_http_request()".into(),
            Module::Test.from_ic0(
                "cost_http_request",
                Params3(1_i64, 2_i64, 3_i32),
                Result::No,
                Wasm64::Disabled,
            ),
            519001006,
        ),
        common::Benchmark(
            "wasm64/ic0_cost_http_request()".into(),
            Module::Test.from_ic0(
                "cost_http_request",
                Params3(1_i64, 2_i64, 3_i64),
                Result::No,
                Wasm64::Enabled,
            ),
            519004006,
        ),
        {
            let serialized_params = candid::encode_one(COST_HTTP_REQUEST_V2_PARAMS).unwrap();

            common::Benchmark(
                "wasm32/ic0_cost_http_request_v2()".into(),
                Module::Test.from_ic0_with_data(
                    "cost_http_request_v2",
                    Params3(
                        0_i32,
                        serialized_params.len() as i32,
                        serialized_params.len() as i32,
                    ),
                    Result::No,
                    DataSections {
                        use_64_bit: false,
                        sections: vec![(0_u32, serialized_params)],
                    },
                    Wasm64::Disabled,
                ),
                10019001006,
            )
        },
        {
            let serialized_params = candid::encode_one(COST_HTTP_REQUEST_V2_PARAMS).unwrap();

            common::Benchmark(
                "wasm64/ic0_cost_http_request_v2()".into(),
                Module::Test.from_ic0_with_data(
                    "cost_http_request_v2",
                    Params3(
                        0_i64,
                        serialized_params.len() as i64,
                        serialized_params.len() as i64,
                    ),
                    Result::No,
                    DataSections {
                        use_64_bit: true,
                        sections: vec![(0_u32, serialized_params)],
                    },
                    Wasm64::Enabled,
                ),
                10019004006,
            )
        },
        common::Benchmark(
            "wasm32/ic0_cost_sign_with_ecdsa()".into(),
            Module::Test.from_ic0(
                "cost_sign_with_ecdsa",
                Params4(1_i32, 2_i32, 3_i32, 3_i32),
                Result::I32,
                Wasm64::Disabled,
            ),
            523000006,
        ),
        common::Benchmark(
            "wasm64/ic0_cost_sign_with_ecdsa()".into(),
            Module::Test.from_ic0(
                "cost_sign_with_ecdsa",
                Params4(1_i64, 2_i64, 3_i32, 3_i64),
                Result::I32,
                Wasm64::Enabled,
            ),
            523000006,
        ),
        common::Benchmark(
            "wasm32/ic0_cost_sign_with_schnorr()".into(),
            Module::Test.from_ic0(
                "cost_sign_with_schnorr",
                Params4(1_i32, 2_i32, 3_i32, 3_i32),
                Result::I32,
                Wasm64::Disabled,
            ),
            523000006,
        ),
        common::Benchmark(
            "wasm64/ic0_cost_sign_with_schnorr()".into(),
            Module::Test.from_ic0(
                "cost_sign_with_schnorr",
                Params4(1_i64, 2_i64, 3_i32, 3_i64),
                Result::I32,
                Wasm64::Enabled,
            ),
            523000006,
        ),
        common::Benchmark(
            "wasm32/ic0_cost_vetkd_derive_key()".into(),
            Module::Test.from_ic0(
                "cost_vetkd_derive_key",
                Params4(1_i32, 2_i32, 3_i32, 3_i32),
                Result::I32,
                Wasm64::Disabled,
            ),
            523000006,
        ),
        common::Benchmark(
            "wasm64/ic0_cost_vetkd_derive_key()".into(),
            Module::Test.from_ic0(
                "cost_vetkd_derive_key",
                Params4(1_i64, 2_i64, 3_i32, 3_i64),
                Result::I32,
                Wasm64::Enabled,
            ),
            523000006,
        ),
    ];

    common::run_benchmarks(
        c,
        "execution_environment:update",
        &benchmarks,
        |id: &str,
         exec_env: &ExecutionEnvironment,
         expected_instructions,
         common::BenchmarkArgs {
             canister_state,
             ingress,
             time,
             network_topology,
             execution_parameters,
             subnet_available_memory,
             subnet_memory_reservation,
             subnet_available_callbacks,
             ..
         }| {
            let mut round_limits = RoundLimits::new(
                as_round_instructions(execution_parameters.instruction_limits.message()),
                subnet_available_memory,
                subnet_available_callbacks,
                0,
                subnet_memory_reservation,
            );
            let instructions_before = round_limits.instructions();
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
                CanisterCyclesCostSchedule::Normal,
            );
            let executed_instructions =
                as_num_instructions(instructions_before - round_limits.instructions());
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
                "update the reference number of instructions for '{id}' to {}",
                executed_instructions.get()
            );
        },
    );
}

criterion_group! {
    name = benchmarks;
    config = Criterion::default().sample_size(10);
    targets = execute_update_bench
}
criterion_main!(benchmarks);
