///
/// Benchmark System API performance in `execute_update()`.
///
mod common;
mod common_wat;

use common_wat::*;
use criterion::{criterion_group, criterion_main, Criterion};
use ic_replicated_state::CallContextAction;
use ic_test_utilities::types::ids::canister_test_id;
use ic_types::Cycles;
use lazy_static::lazy_static;

lazy_static! {
    /// List of benchmarks: benchmark id (name), WAT, expected instructions.
    pub static ref BENCHMARKS: Vec<common::Benchmark> = vec![
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
            3,
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
            "ic0_controller_size()",
            Module::Test.from_ic0("controller_size", NoParams, Result::I32),
            11_000_004,
        ),
        common::Benchmark(
            "ic0_controller_copy()/1B",
            Module::Test.from_ic0("controller_copy", Params3(0, 0, 1), Result::No),
            13_000_004,
        ),
        common::Benchmark(
            "ic0_controller_copy()/10B",
            Module::Test.from_ic0("controller_copy", Params3(0, 0, 10), Result::No), // 10B max
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
            "ic0_call_simple()",
            // Manually implementing imports and body as this is the only API call with 10 params
            Module::Test.from_sections((
                format!(
                    r#"
                (import "ic0" "call_simple"
                    (func $ic0_call_simple
                    (param $callee_src i32)         (param $callee_size i32)
                    (param $name_src i32)           (param $name_size i32)
                    (param $reply_fun i32)          (param $reply_env i32)
                    (param $reject_fun i32)         (param $reject_env i32)
                    (param $message_src i32)        (param $message_size i32)
                    (result i32)
                ))
                (data (i32.const 0)     "{CALLEE}")
                (data (i32.const 100)   "remote_method_name")
                (data (i32.const 200)   "100B message")
                "#,
                    CALLEE = canister_test_id(common::REMOTE_CANISTER_ID)
                ),
                Module::render_loop(
                    LoopIterations::Mi,
                    format!(
                        r#"
                            (drop (call $ic0_call_simple
                                (i32.const 0)   (i32.const {CALLEE_SIZE})
                                (i32.const 100) (i32.const 18)
                                (i32.const 11)  (i32.const 0)   ;; non-existent function
                                (i32.const 22)  (i32.const 0)   ;; non-existent function
                                (i32.const 200) (i32.const 100) ;; 100B message body
                            ))
                    "#,
                        CALLEE_SIZE = canister_test_id(common::REMOTE_CANISTER_ID)
                            .get_ref()
                            .as_slice()
                            .len()
                    ),
                ),
            )),
            121_000_004,
        ),
        common::Benchmark(
            "ic0_call_new()",
            Module::CallNewLoop.from_sections(("", "")), // call_new in a loop is rendered by default
            18_000_004,
        ),
        common::Benchmark(
            "call_new+ic0_call_data_append()/1B",
            Module::CallNewLoop.from_ic0("call_data_append", Params2(0, 1), Result::No), // 2MiB max
            22_000_004,
        ),
        common::Benchmark(
            "call_new+ic0_call_data_append()/8K",
            Module::CallNewLoop.from_ic0("call_data_append", Params2(0, 8192), Result::No), // 2MiB max
            8_213_000_004,
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
            "ic0_canister_cycle_balance()",
            Module::Test.from_ic0("canister_cycle_balance", NoParams, Result::I64),
            11_000_004,
        ),
        common::Benchmark(
            "ic0_canister_cycles_balance128()",
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
    ];
}

pub fn bench_execute_update(c: &mut Criterion) {
    common::run_benchmarks(
        c,
        "update",
        &BENCHMARKS,
        |hypervisor,
         expected_instructions,
         common::BenchmarkArgs(
            cloned_canister_state,
            cloned_ingress,
            _cloned_reject,
            cloned_time,
            cloned_network_topology,
            cloned_execution_parameters,
            _cloned_call_origin,
            _cloned_callback,
        )| {
            let (_state, instructions, action, _bytes) = hypervisor.execute_update(
                cloned_canister_state,
                cloned_ingress,
                cloned_time,
                cloned_network_topology,
                cloned_execution_parameters,
            );
            match action {
                CallContextAction::NoResponse { .. }
                | CallContextAction::NotYetResponded { .. }
                | CallContextAction::Reply { .. }
                | CallContextAction::Reject { .. } => {}
                CallContextAction::Fail { .. } | CallContextAction::AlreadyResponded { .. } => {
                    assert_eq!(
                        action,
                        CallContextAction::NoResponse {
                            refund: Cycles::new(0),
                        },
                        "Error executing an update method"
                    )
                }
            }
            assert_eq!(
                expected_instructions,
                common::MAX_NUM_INSTRUCTIONS.get() - instructions.get(),
                "Error comparing number of actual and expected instructions"
            );
        },
    );
}

criterion_group!(benchmarks, bench_execute_update);
criterion_main!(benchmarks);
