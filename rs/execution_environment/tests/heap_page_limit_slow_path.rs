//! End-to-end cost of the slow path of the accessed heap page limit check:
//! a canister that sits at the limit and issues many tiny bulk memory
//! operations and stable memory copies inside already accessed pages pays a
//! host call for each (the Wasm fast path bound `(len >> 16) + 2` pages per
//! heap range never fits into a zero budget).
//!
//! Prints `STAT` lines like `cost_report.rs`: the instructions and the wall
//! time of each method with the default (inert) limit and with a limit of
//! one Wasm page. The instruction counts must be identical, since the
//! injected check functions are not metered.

use ic_config::embedders::MemoryPageLimit;
use ic_sys::PAGE_SIZE;
use ic_test_utilities_execution_environment::{ExecutionTest, ExecutionTestBuilder};
use ic_test_utilities_metrics::fetch_int_counter_vec;
use ic_types::{CanisterId, NumOsPages, ingress::WasmResult};
use std::collections::BTreeMap;
use std::time::Instant;

const WASM_PAGE: usize = 64 * 1024;
const WALL_TIME_SAMPLES: usize = 50;

fn stat(name: &str, value: impl std::fmt::Display) {
    println!("STAT {name} = {value}");
}

/// A loop running `body` `n` times with the counter in local `$i` (i32).
fn loop_wat(n: usize, body: &str) -> String {
    format!(
        r#"
            (local.set $i (i32.const 0))
            (loop $l
                {body}
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br_if $l (i32.lt_u (local.get $i) (i32.const {n})))
            )
        "#
    )
}

/// Every method touches heap page 0 only.
fn wat() -> String {
    let by_8_in_page_0 = "(i32.and (i32.shl (local.get $i) (i32.const 3)) (i32.const 65535))";
    let methods = [
        (
            "fill_8b_x10000",
            loop_wat(
                10_000,
                &format!("(memory.fill {by_8_in_page_0} (i32.const 7) (i32.const 8))"),
            ),
        ),
        (
            "copy_8b_x10000",
            loop_wat(
                10_000,
                &format!("(memory.copy {by_8_in_page_0} (i32.const 32768) (i32.const 8))"),
            ),
        ),
        (
            "stable_write_8b_x10000",
            loop_wat(
                10_000,
                "(call $stable64_write (i64.const 0) (i64.const 0) (i64.const 8))",
            ),
        ),
        (
            "stable_read_8b_x10000",
            loop_wat(
                10_000,
                "(call $stable64_read (i64.const 0) (i64.const 0) (i64.const 8))",
            ),
        ),
        (
            "msg_arg_copy_8b_x10000",
            loop_wat(
                10_000,
                &format!("(call $msg_arg_data_copy {by_8_in_page_0} (i32.const 0) (i32.const 8))"),
            ),
        ),
    ];
    let funcs: String = methods
        .iter()
        .map(|(name, body)| {
            format!(
                r#"
            (func (export "canister_update {name}") (local $i i32)
                {body}
                (call $msg_reply)
            )"#
            )
        })
        .collect();
    format!(
        r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_arg_data_copy" (func $msg_arg_data_copy (param i32 i32 i32)))
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
            (import "ic0" "stable64_read" (func $stable64_read (param i64 i64 i64)))
            (import "ic0" "stable64_write" (func $stable64_write (param i64 i64 i64)))
            (func (export "canister_init") (drop (call $stable64_grow (i64.const 1))))
            {funcs}
            (memory (export "memory") 1)
        )
    "#
    )
}

const METHODS: [&str; 5] = [
    "fill_8b_x10000",
    "copy_8b_x10000",
    "stable_write_8b_x10000",
    "stable_read_8b_x10000",
    "msg_arg_copy_8b_x10000",
];

/// Runs the update method once and returns the executed instructions and
/// the cycles charged for the execution.
fn update_cost(test: &mut ExecutionTest, canister_id: CanisterId, method: &str) -> (u64, u128) {
    let instructions_before = test.canister_executed_instructions(canister_id).get();
    let cycles_before = test.canister_execution_cost(canister_id).nominal().get();
    let result = test.ingress(canister_id, method, vec![1; 8]).unwrap();
    assert!(
        matches!(result, WasmResult::Reply(_)),
        "{method}: {result:?}"
    );
    (
        test.canister_executed_instructions(canister_id).get() - instructions_before,
        test.canister_execution_cost(canister_id).nominal().get() - cycles_before,
    )
}

/// Wall time statistics in microseconds: (min, median).
fn wall_time_us(mut run: impl FnMut()) -> (u128, u128) {
    run();
    let mut samples: Vec<u128> = (0..WALL_TIME_SAMPLES)
        .map(|_| {
            let start = Instant::now();
            run();
            start.elapsed().as_micros()
        })
        .collect();
    samples.sort_unstable();
    (samples[0], samples[samples.len() / 2])
}

/// Number of slow path host calls (`__.check_heap_bulk_access`) of update
/// calls so far.
fn slow_path_calls(test: &ExecutionTest) -> u64 {
    fetch_int_counter_vec(
        test.metrics_registry(),
        "sandboxed_execution_wasm_bulk_check_slow_path_calls_total",
    )
    .get(&BTreeMap::from([(
        "api_type".to_string(),
        "update".to_string(),
    )]))
    .copied()
    .unwrap_or(0)
}

fn measure(test: &mut ExecutionTest, config: &str) -> Vec<u64> {
    let canister_id = test.canister_from_wat(wat()).unwrap();
    METHODS
        .iter()
        .map(|method| {
            let slow_path_calls_before = slow_path_calls(test);
            let (instructions, cycles) = update_cost(test, canister_id, method);
            stat(&format!("slow_path/{config}/{method}/instr"), instructions);
            stat(&format!("slow_path/{config}/{method}/cycles"), cycles);
            stat(
                &format!("slow_path/{config}/{method}/slow_path_calls"),
                slow_path_calls(test) - slow_path_calls_before,
            );
            let (min, median) = wall_time_us(|| {
                update_cost(test, canister_id, method);
            });
            stat(&format!("slow_path/{config}/{method}/wall_us/min"), min);
            stat(
                &format!("slow_path/{config}/{method}/wall_us/median"),
                median,
            );
            instructions
        })
        .collect()
}

#[test]
fn heap_page_limit_slow_path_cost() {
    let mut default = ExecutionTestBuilder::new().build();
    let default_instructions = measure(&mut default, "default_limit");

    let one_page = NumOsPages::new((WASM_PAGE / PAGE_SIZE) as u64);
    let mut limited = ExecutionTestBuilder::new()
        .with_wasm_memory_accessed_page_limit(MemoryPageLimit {
            message: one_page,
            upgrade: one_page,
            query: one_page,
        })
        .build();
    let limited_instructions = measure(&mut limited, "one_page_limit");

    assert_eq!(
        default_instructions, limited_instructions,
        "the page limit check must not change the instructions charged"
    );
}
