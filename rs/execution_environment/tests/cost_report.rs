//! Cost report: prints the cost of installing and running canisters as `STAT`
//! lines, so that two versions of the replica can be compared mechanically.
//!
//! Every measurement is printed as one line
//!
//! ```text
//! STAT <group>/<subject>/<metric> = <value>
//! ```
//!
//! The tests only assert that the executions succeed; the values differ
//! between versions by design. Run with
//!
//! ```sh
//! bazel test --cache_test_results=no --test_output=all \
//!   --test_arg=--nocapture --test_arg=--test-threads=1 <target> | grep '^STAT'
//! ```
//!
//! and join the `STAT` lines of the two runs by name.

use ic_config::embedders::{
    Config as EmbeddersConfig, DEFAULT_CREATE_EXECUTION_STATE_BASE_COST, WASM_MAX_SIZE,
};
use ic_embedders::{
    WasmtimeEmbedder,
    wasm_utils::{compile, decoding::decode_wasm, validate_and_instrument_for_testing},
};
use ic_management_canister_types_private::{CanisterInstallMode, InstallCodeArgs};
use ic_test_utilities_execution_environment::{
    ExecutionTest, ExecutionTestBuilder, check_ingress_status, wasm_compilation_cost,
};
use ic_test_utilities_logger::with_test_replica_logger;
use ic_types::{CanisterId, ingress::WasmResult};
use ic_types_cycles::Cycles;
use ic_universal_canister::{UNIVERSAL_CANISTER_WASM, wasm};
use std::sync::Arc;
use std::time::Instant;

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;
const WASM_PAGE: usize = 64 * KIB;

/// Number of timed executions per method for the wall time statistics.
const WALL_TIME_SAMPLES: usize = 50;

/// Number of heap pages of the heap heavy module (~69 MiB).
const HEAP_HEAVY_PAGES: usize = 1100;

fn stat(name: &str, value: impl std::fmt::Display) {
    println!("STAT {name} = {value}");
}

////////////////////////////////////////////////////////////////////////
// Subjects

/// A canister with a few instructions in one update method and a 1-page
/// heap, in Wasm32 or Wasm64 mode (the module of
/// `check_install_code_in_wasm64_mode_is_charged_correctly`).
fn tiny_wat(wasm64: bool) -> String {
    let (a, memory) = if wasm64 {
        ("i64", "i64 1")
    } else {
        ("i32", "1")
    };
    format!(
        r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (func (export "canister_update test")
                (i64.store ({a}.const 0) (i64.const 1))
                (drop (i64.load ({a}.const 0)))
                (call $msg_reply)
            )
            (memory {memory})
        )
    "#
    )
}

/// A canister that imports the stable memory API and uses bulk memory
/// operations: this triggers the injected stable memory bodies and the
/// bulk memory helpers, so it measures the instrumentation overhead for a
/// typical compiled canister that uses `memcpy`/`memset` and stable memory.
fn stable_wat(wasm64: bool) -> String {
    let (a, memory) = if wasm64 {
        ("i64", "i64 1")
    } else {
        ("i32", "1")
    };
    let (s, read, write) = if wasm64 {
        ("i64", "stable64_read", "stable64_write")
    } else {
        ("i32", "stable_read", "stable_write")
    };
    format!(
        r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "stable64_grow" (func $stable_grow (param i64) (result i64)))
            (import "ic0" "{read}" (func $stable_read (param {s} {s} {s})))
            (import "ic0" "{write}" (func $stable_write (param {s} {s} {s})))
            (func (export "canister_init") (drop (call $stable_grow (i64.const 1))))
            (func (export "canister_update test")
                (memory.fill ({a}.const 0) (i32.const 1) ({a}.const 64))
                (memory.copy ({a}.const 64) ({a}.const 0) ({a}.const 64))
                (call $stable_write ({s}.const 0) ({s}.const 0) ({s}.const 128))
                (call $stable_read ({s}.const 128) ({s}.const 0) ({s}.const 128))
                (call $msg_reply)
            )
            (memory {memory})
        )
    "#
    )
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

/// A canister with one update method per kind of heap access, each doing
/// many operations, plus a query method. `wasm64` selects the address type.
fn heap_heavy_wat(wasm64: bool) -> String {
    let (a, memory) = if wasm64 {
        ("i64", format!("i64 {HEAP_HEAVY_PAGES}"))
    } else {
        ("i32", format!("{HEAP_HEAVY_PAGES}"))
    };
    // `$i` as an address of the module's address type.
    let i = if wasm64 {
        "(i64.extend_i32_u (local.get $i))"
    } else {
        "(local.get $i)"
    };
    let page = format!("({a}.mul {i} ({a}.const {WASM_PAGE}))");
    let next_page = format!("({a}.mul ({a}.add {i} ({a}.const 1)) ({a}.const {WASM_PAGE}))");
    let by_8 = format!("({a}.shl {i} ({a}.const 3))");
    let by_8_in_page_0 = format!("({a}.and ({a}.shl {i} ({a}.const 3)) ({a}.const 65535))");
    let whole_heap = 1000 * WASM_PAGE;

    let methods = [
        ("trivial", String::new()),
        (
            "store_sparse_1000_pages",
            loop_wat(1000, &format!("(i64.store {page} (i64.const 1))")),
        ),
        (
            "store_dense_1mb",
            loop_wat(MIB / 8, &format!("(i64.store {by_8} (i64.const 1))")),
        ),
        (
            "load_dense_1mb",
            loop_wat(MIB / 8, &format!("(drop (i64.load {by_8}))")),
        ),
        (
            "fill_8b_x10000",
            loop_wat(
                10_000,
                &format!("(memory.fill {by_8_in_page_0} (i32.const 7) ({a}.const 8))"),
            ),
        ),
        (
            "copy_8b_x10000",
            loop_wat(
                10_000,
                &format!("(memory.copy {by_8_in_page_0} ({a}.const 32768) ({a}.const 8))"),
            ),
        ),
        (
            "copy_64k_x1000",
            loop_wat(
                1000,
                &format!("(memory.copy {next_page} ({a}.const 0) ({a}.const {WASM_PAGE}))"),
            ),
        ),
        (
            "fill_64mb",
            format!("(memory.fill ({a}.const 0) (i32.const 1) ({a}.const {whole_heap}))"),
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
            "stable_write_1mb",
            format!("(call $stable64_write (i64.const 0) (i64.const 0) (i64.const {MIB}))"),
        ),
        (
            "stable_read_1mb",
            format!("(call $stable64_read (i64.const 0) (i64.const 0) (i64.const {MIB}))"),
        ),
        (
            "msg_arg_copy_8b_x10000",
            loop_wat(
                10_000,
                &format!("(call $msg_arg_data_copy {by_8_in_page_0} ({a}.const 0) ({a}.const 8))"),
            ),
        ),
    ];
    let funcs: String = methods
        .iter()
        .map(|(name, body)| {
            format!(
                r#"
            (func $f_{name} (export "canister_update {name}") (local $i i32)
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
            (import "ic0" "msg_arg_data_copy" (func $msg_arg_data_copy (param {a} {a} {a})))
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
            (import "ic0" "stable64_read" (func $stable64_read (param i64 i64 i64)))
            (import "ic0" "stable64_write" (func $stable64_write (param i64 i64 i64)))
            (func (export "canister_init") (drop (call $stable64_grow (i64.const 32))))
            {funcs}
            (export "canister_query query_load_dense_1mb" (func $f_load_dense_1mb))
            (export "canister_query query_trivial" (func $f_trivial))
            (memory (export "memory") {memory})
        )
    "#
    )
}

/// The methods of the heap heavy module, with the ingress payload each needs.
fn heap_heavy_methods() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("trivial", vec![]),
        ("store_sparse_1000_pages", vec![]),
        ("store_dense_1mb", vec![]),
        ("load_dense_1mb", vec![]),
        ("fill_8b_x10000", vec![]),
        ("copy_8b_x10000", vec![]),
        ("copy_64k_x1000", vec![]),
        ("fill_64mb", vec![]),
        ("stable_write_8b_x10000", vec![]),
        ("stable_read_8b_x10000", vec![]),
        ("stable_write_1mb", vec![]),
        ("stable_read_1mb", vec![]),
        ("msg_arg_copy_8b_x10000", vec![1; 8]),
    ]
}

fn image_classification_canister_wasm() -> Vec<u8> {
    let path = std::env::var("IMAGE_CLASSIFICATION_CANISTER_WASM_PATH")
        .expect("Please ensure that this Bazel test target correctly specifies env and data.");
    std::fs::read(path).expect("Failed to read WASM file")
}

/// All module subjects: name and (possibly gzipped) Wasm binary.
fn subjects() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("tiny32", wat::parse_str(tiny_wat(false)).unwrap()),
        ("tiny64", wat::parse_str(tiny_wat(true)).unwrap()),
        ("stable32", wat::parse_str(stable_wat(false)).unwrap()),
        ("stable64", wat::parse_str(stable_wat(true)).unwrap()),
        (
            "heap_heavy32",
            wat::parse_str(heap_heavy_wat(false)).unwrap(),
        ),
        (
            "heap_heavy64",
            wat::parse_str(heap_heavy_wat(true)).unwrap(),
        ),
        ("universal", UNIVERSAL_CANISTER_WASM.to_vec()),
        ("image_classification", image_classification_canister_wasm()),
    ]
}

////////////////////////////////////////////////////////////////////////
// Helpers

/// Installs `wasm` into a fresh canister, running all slices of the
/// install, and returns the canister id.
fn install(test: &mut ExecutionTest, wasm: Vec<u8>) -> CanisterId {
    let canister_id = test.create_canister(Cycles::new(1_000_000_000_000_000));
    let message_id = test.dts_install_code(InstallCodeArgs::new(
        CanisterInstallMode::Install,
        canister_id,
        wasm,
        vec![],
    ));
    test.execute_message(canister_id);
    check_ingress_status(test.ingress_status(&message_id)).unwrap();
    canister_id
}

fn instructions(test: &ExecutionTest, canister_id: CanisterId) -> u64 {
    test.canister_executed_instructions(canister_id).get()
}

/// Cycles charged to the canister for execution so far (nominal).
fn execution_cycles(test: &ExecutionTest, canister_id: CanisterId) -> u128 {
    test.canister_execution_cost(canister_id).nominal().get()
}

fn balance(test: &ExecutionTest, canister_id: CanisterId) -> u128 {
    test.canister_state(canister_id)
        .system_state
        .balance()
        .get()
}

/// The cost of one update call: executed instructions, cycles charged for
/// the execution, and the decrease of the canister balance (execution plus
/// the ingress induction fee).
struct UpdateCost {
    instructions: u64,
    execution_cycles: u128,
    balance_delta: u128,
}

/// Runs the update method once and returns its cost.
fn update_cost(
    test: &mut ExecutionTest,
    canister_id: CanisterId,
    method: &str,
    payload: &[u8],
) -> UpdateCost {
    let instructions_before = instructions(test, canister_id);
    let cycles_before = execution_cycles(test, canister_id);
    let balance_before = balance(test, canister_id);
    let result = test.ingress(canister_id, method, payload.to_vec()).unwrap();
    assert!(
        matches!(result, WasmResult::Reply(_)),
        "{method}: {result:?}"
    );
    UpdateCost {
        instructions: instructions(test, canister_id) - instructions_before,
        execution_cycles: execution_cycles(test, canister_id) - cycles_before,
        balance_delta: balance_before - balance(test, canister_id),
    }
}

/// Wall time statistics in microseconds: (min, median).
fn wall_time_us(mut run: impl FnMut()) -> (u128, u128) {
    // Warm up: compilation cache, sandbox process, page maps.
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

/// Reports the instructions and wall time of the update `method` under
/// the stat name `<subject>/<label>`.
fn report_update(
    test: &mut ExecutionTest,
    canister_id: CanisterId,
    subject: &str,
    label: &str,
    method: &str,
    payload: &[u8],
) {
    let cost = update_cost(test, canister_id, method, payload);
    stat(
        &format!("update_instr/{subject}/{label}"),
        cost.instructions,
    );
    stat(
        &format!("update_cycles/{subject}/{label}/execution"),
        cost.execution_cycles,
    );
    stat(
        &format!("update_cycles/{subject}/{label}/balance_delta"),
        cost.balance_delta,
    );
    let (min, median) = wall_time_us(|| {
        update_cost(test, canister_id, method, payload);
    });
    stat(&format!("update_wall_us/{subject}/{label}/min"), min);
    stat(&format!("update_wall_us/{subject}/{label}/median"), median);
}

/// Reports the wall time of the non-replicated query `method` under the
/// stat name `<subject>/<label>`.
fn report_query(
    test: &mut ExecutionTest,
    canister_id: CanisterId,
    subject: &str,
    label: &str,
    method: &str,
    payload: &[u8],
) {
    let (min, median) = wall_time_us(|| {
        let result = test
            .non_replicated_query(canister_id, method, payload.to_vec())
            .unwrap();
        assert!(
            matches!(result, WasmResult::Reply(_)),
            "{method}: {result:?}"
        );
    });
    stat(&format!("query_wall_us/{subject}/{label}/min"), min);
    stat(&format!("query_wall_us/{subject}/{label}/median"), median);
}

////////////////////////////////////////////////////////////////////////
// Tests

/// Size of the original, instrumented and compiled module and the
/// compilation cost derived from the instrumented instruction count.
#[test]
fn cost_report_module_size() {
    let config = EmbeddersConfig::default();
    let cost_per_instruction = config.cost_to_compile_wasm_instruction.get();
    let embedder = with_test_replica_logger(|log| WasmtimeEmbedder::new(config, log));
    for (subject, bytes) in subjects() {
        let wasm = decode_wasm(WASM_MAX_SIZE, Arc::new(bytes)).unwrap();
        stat(
            &format!("module/{subject}/wasm_bytes"),
            wasm.as_slice().len(),
        );
        let (_, instrumented) = validate_and_instrument_for_testing(&embedder, &wasm).unwrap();
        stat(
            &format!("module/{subject}/instrumented_bytes"),
            instrumented.binary.as_slice().len(),
        );
        let (_, result) = compile(&embedder, &wasm);
        let (_, serialized) = result.unwrap();
        stat(
            &format!("module/{subject}/serialized_module_bytes"),
            serialized.bytes.as_slice().len(),
        );
        let compilation_cost = serialized.compilation_cost.get();
        stat(
            &format!("module/{subject}/compilation_cost"),
            compilation_cost,
        );
        stat(
            &format!("module/{subject}/instrumented_instruction_count"),
            compilation_cost / cost_per_instruction,
        );
    }
}

/// Instructions and cycles charged for installing each subject.
#[test]
fn cost_report_install() {
    for (subject, bytes) in subjects() {
        let compilation_cost = wasm_compilation_cost(&bytes).get();
        let mut test = ExecutionTestBuilder::new()
            .with_query_caching_disabled()
            .build();
        let canister_id = install(&mut test, bytes);
        let instructions = instructions(&test, canister_id);
        stat(&format!("install/{subject}/instructions"), instructions);
        stat(
            &format!("install/{subject}/cycles"),
            test.canister_execution_cost(canister_id).nominal().get(),
        );
        // Sanity check: the install is charged the base cost plus the
        // compilation cost (plus the instructions of `canister_init`, if any).
        stat(
            &format!("install/{subject}/instructions_minus_base_and_compilation"),
            instructions as i128
                - DEFAULT_CREATE_EXECUTION_STATE_BASE_COST.get() as i128
                - compilation_cost as i128,
        );
    }
}

/// Instructions and wall time of update calls doing many heap accesses of
/// one kind each (loads/stores, bulk memory operations, stable memory
/// copies, host function copies).
#[test]
fn cost_report_update_heap_heavy() {
    for (subject, wasm64) in [("heap_heavy32", false), ("heap_heavy64", true)] {
        let mut test = ExecutionTestBuilder::new()
            .with_query_caching_disabled()
            .build();
        let canister_id = install(&mut test, wat::parse_str(heap_heavy_wat(wasm64)).unwrap());
        for (method, payload) in heap_heavy_methods() {
            report_update(&mut test, canister_id, subject, method, method, &payload);
        }
        for method in ["query_trivial", "query_load_dense_1mb"] {
            report_query(&mut test, canister_id, subject, method, method, &[]);
        }
    }
}

/// Instructions and wall time of typical update calls on the tiny module
/// and on the universal canister (a real Rust canister).
#[test]
fn cost_report_update_typical() {
    let mut test = ExecutionTestBuilder::new()
        .with_query_caching_disabled()
        .build();
    let tiny = install(&mut test, wat::parse_str(tiny_wat(false)).unwrap());
    report_update(&mut test, tiny, "tiny32", "test", "test", &[]);

    let stable = install(&mut test, wat::parse_str(stable_wat(false)).unwrap());
    report_update(&mut test, stable, "stable32", "test", "test", &[]);

    let uc = install(&mut test, UNIVERSAL_CANISTER_WASM.to_vec());
    let payloads: Vec<(&str, Vec<u8>)> = vec![
        ("reply", wasm().reply().build()),
        (
            "stable_write_read_1mb",
            wasm()
                .stable64_grow(16)
                .stable64_write(0, &vec![7; MIB])
                .stable64_read(0, MIB as u64)
                .reply()
                .build(),
        ),
        (
            "msg_arg_data_copy_1mb",
            wasm()
                .push_bytes(&vec![7; MIB])
                .msg_arg_data_copy(0, MIB as u32)
                .reply()
                .build(),
        ),
    ];
    for (name, payload) in payloads {
        report_update(&mut test, uc, "universal", name, "update", &payload);
    }
    report_query(
        &mut test,
        uc,
        "universal",
        "reply",
        "query",
        &wasm().reply().build(),
    );
}
