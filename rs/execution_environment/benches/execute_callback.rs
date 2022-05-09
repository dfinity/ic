///
/// Benchmark System API performance in `execute_callback()`
///
mod common;
mod common_wat;

use common_wat::*;
use criterion::{criterion_group, criterion_main, Criterion};
use ic_types::Cycles;

use ic_replicated_state::CallContextAction;
use lazy_static::lazy_static;

lazy_static! {
    /// List of benchmarks: benchmark id (name), WAT, expected instructions.
    pub static ref BENCHMARKS: Vec<common::Benchmark> = vec![
        common::Benchmark(
            "ic0_msg_reject_code()",
            Module::Callback.from_ic0("msg_reject_code", NoParams, Result::I32),
            11_000_004,
        ),
        common::Benchmark(
            "ic0_msg_reject_msg_size()",
            Module::Callback.from_ic0("msg_reject_msg_size", NoParams, Result::I32),
            11_000_004,
        ),
        common::Benchmark(
            "ic0_msg_reject_msg_copy()/1B",
            Module::Callback.from_ic0("msg_reject_msg_copy", Params3(0, 0, 1), Result::No),
            34_000_004,
        ),
        common::Benchmark(
            "ic0_msg_reject_msg_copy()/10B",
            Module::Callback.from_ic0("msg_reject_msg_copy", Params3(0, 0, 10), Result::No), // 10B max
            43_000_004,
        ),
        common::Benchmark(
            "ic0_msg_cycles_refunded()",
            Module::Callback.from_ic0("msg_cycles_refunded", NoParams, Result::I64),
            11_000_004,
        ),
        common::Benchmark(
            "ic0_msg_cycles_refunded128()",
            Module::Callback.from_ic0("msg_cycles_refunded128", Param1(0), Result::No),
            11_000_004,
        ),
    ];
}

pub fn bench_execute_callback(c: &mut Criterion) {
    common::run_benchmarks(
        c,
        "callback",
        &BENCHMARKS,
        |hypervisor,
         expected_instructions,
         common::BenchmarkArgs {
             canister_state,
             reject,
             time,
             network_topology,
             execution_parameters,
             call_origin,
             callback,
             ..
         }| {
            let (_state, instructions, action, _bytes) = hypervisor.execute_callback(
                canister_state,
                &call_origin,
                callback,
                reject,
                Cycles::new(0),
                time,
                network_topology,
                execution_parameters,
            );
            match action {
                CallContextAction::NoResponse { refund: _ } => (),
                _ => panic!("Unexpected callback result: {:?}", action),
            }

            assert_eq!(
                expected_instructions,
                common::MAX_NUM_INSTRUCTIONS.get() - instructions.get(),
                "Error comparing number of actual and expected instructions"
            );
        },
    );
}

criterion_group!(benchmarks, bench_execute_callback);
criterion_main!(benchmarks);
