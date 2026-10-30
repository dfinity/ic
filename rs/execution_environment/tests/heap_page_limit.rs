//! End-to-end tests of the limit on the number of Wasm heap pages a single
//! execution may access (`wasm_memory_accessed_page_limit`), through the
//! execution environment and the real canister sandbox:
//!
//! * which of the three limit values (message, upgrade, query) applies to
//!   which kind of execution, including install and upgrade hooks;
//! * data segments do not count against the limit;
//! * accessed pages accumulate across DTS slices and are forgotten when a
//!   paused execution is aborted;
//! * reply, reject and cleanup callbacks each get their own budget;
//! * queries, composite queries, and the limit error in the query cache;
//! * a stable memory read into the heap that crosses both the stable and the
//!   heap limit reports the stable one;
//! * the failure is deterministic across two independent executions;
//! * a failing message is charged for the pages it did touch, and an aborted
//!   execution is charged once;
//! * the globals persisted for a canister have the layout of before the
//!   limit existed.
//!
//! The limits are given in Wasm pages (64 KiB); the canisters touch pages by
//! writing one byte into each, so "touch n" accesses exactly n pages.

use ic_config::embedders::MemoryPageLimit;
use ic_error_types::{ErrorCode, UserError};
use ic_replicated_state::canister_state::{NextExecution, WASM_PAGE_SIZE_IN_BYTES};
use ic_sys::PAGE_SIZE;
use ic_test_utilities_execution_environment::{
    ExecutionTest, ExecutionTestBuilder, check_ingress_status,
};
use ic_test_utilities_metrics::fetch_int_counter;
use ic_types::{CanisterId, NumOsPages, ingress::IngressState, ingress::WasmResult};
use ic_types_cycles::Cycles;
use ic_universal_canister::{call_args, wasm};

const OS_PAGES_PER_WASM_PAGE: u64 = (WASM_PAGE_SIZE_IN_BYTES / PAGE_SIZE) as u64;

fn wasm_pages(n: u64) -> NumOsPages {
    NumOsPages::new(n * OS_PAGES_PER_WASM_PAGE)
}

/// A heap page limit in Wasm pages per kind of execution.
fn limits(message: u64, upgrade: u64, query: u64) -> MemoryPageLimit {
    MemoryPageLimit {
        message: wasm_pages(message),
        upgrade: wasm_pages(upgrade),
        query: wasm_pages(query),
    }
}

fn builder(limits: MemoryPageLimit) -> ExecutionTestBuilder {
    ExecutionTestBuilder::new().with_wasm_memory_accessed_page_limit(limits)
}

fn assert_limit_error(err: &UserError, memory: &str) {
    assert_eq!(
        err.code(),
        ErrorCode::CanisterMemoryAccessLimitExceeded,
        "{err}"
    );
    assert!(
        err.description()
            .contains(&format!("accessed pages in the {memory}")),
        "unexpected error: {err}"
    );
}

////////////////////////////////////////////////////////////////////////
// Canisters

/// Wasm text of a function `$touch` that writes one byte into each of the
/// first `n` Wasm pages, so that it accesses exactly `n` pages.
const TOUCH_FN: &str = r#"
    (func $touch (param $n i32) (local $i i32)
        (block $done
            (br_if $done (i32.eqz (local.get $n)))
            (loop $l
                (i32.store8 (i32.mul (local.get $i) (i32.const 65536)) (i32.const 1))
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br_if $l (i32.lt_u (local.get $i) (local.get $n))))))
"#;

/// A canister whose `touch` update and `touch_query` query access as many
/// pages as the first payload byte says (the payload is copied into page 0,
/// which is one of the touched pages).
fn pages_wat() -> String {
    format!(
        r#"
        (module
            (import "ic0" "msg_arg_data_copy" (func $arg_copy (param i32 i32 i32)))
            (import "ic0" "msg_reply" (func $msg_reply))
            {TOUCH_FN}
            (func $arg_pages (result i32)
                (call $arg_copy (i32.const 256) (i32.const 0) (i32.const 1))
                (i32.load8_u (i32.const 256)))
            (func (export "canister_update touch")
                (call $touch (call $arg_pages))
                (call $msg_reply))
            (func (export "canister_query touch_query")
                (call $touch (call $arg_pages))
                (call $msg_reply))
            (memory (export "memory") 128)
        )"#
    )
}

/// A canister whose install and upgrade hooks touch the given numbers of
/// pages. `version` replies with a byte from a data segment, which tells
/// which module is installed after an upgrade; `extra` is appended to the
/// module (e.g. another data segment).
fn hooks_wat(init: u64, pre_upgrade: u64, post_upgrade: u64, version: u8, extra: &str) -> String {
    format!(
        r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append" (func $reply_append (param i32 i32)))
            (import "ic0" "msg_arg_data_copy" (func $arg_copy (param i32 i32 i32)))
            {TOUCH_FN}
            (func (export "canister_init") (call $touch (i32.const {init})))
            (func (export "canister_pre_upgrade") (call $touch (i32.const {pre_upgrade})))
            (func (export "canister_post_upgrade") (call $touch (i32.const {post_upgrade})))
            (func (export "canister_update version")
                (call $reply_append (i32.const 512) (i32.const 1))
                (call $msg_reply))
            ;; Replies with the byte at the address given by the first
            ;; four payload bytes (little endian).
            (func (export "canister_query byte_at")
                (call $arg_copy (i32.const 256) (i32.const 0) (i32.const 4))
                (call $reply_append (i32.load (i32.const 256)) (i32.const 1))
                (call $msg_reply))
            (memory (export "memory") 16)
            (data (i32.const 512) "\{version:02x}")
            {extra}
        )"#
    )
}

/// A canister that calls another canister's `touch` method and touches pages
/// in its update, its reply callback and its cleanup callback. The payload is
/// `[k, n, r, c, id_len, id...]`: pages to touch in the update (`k`), by the
/// callee (`n`), in the reply callback (`r`) and in the cleanup callback
/// (`c`), then the callee's canister id. The reply callback replies "ok",
/// the reject callback replies with the reject code, and the cleanup
/// callback writes a marker that `marker` returns.
fn caller_wat() -> String {
    format!(
        r#"
        (module
            (import "ic0" "msg_arg_data_copy" (func $arg_copy (param i32 i32 i32)))
            (import "ic0" "msg_arg_data_size" (func $arg_size (result i32)))
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append" (func $reply_append (param i32 i32)))
            (import "ic0" "msg_reject_code" (func $reject_code (result i32)))
            (import "ic0" "call_new"
                (func $call_new (param i32 i32 i32 i32 i32 i32 i32 i32)))
            (import "ic0" "call_data_append" (func $call_data_append (param i32 i32)))
            (import "ic0" "call_on_cleanup" (func $call_on_cleanup (param i32 i32)))
            (import "ic0" "call_perform" (func $call_perform (result i32)))
            {TOUCH_FN}
            (func (export "canister_update call")
                (call $arg_copy (i32.const 256) (i32.const 0) (call $arg_size))
                (call $touch (i32.load8_u (i32.const 256)))
                (call $call_new
                    (i32.const 261) (i32.load8_u (i32.const 260))
                    (i32.const 64) (i32.const 5)
                    (i32.const 0) (i32.load8_u (i32.const 258))
                    (i32.const 1) (i32.const 0))
                (call $call_data_append (i32.const 257) (i32.const 1))
                (call $call_on_cleanup (i32.const 2) (i32.load8_u (i32.const 259)))
                (drop (call $call_perform)))
            (func $on_reply (param $pages i32)
                (call $touch (local.get $pages))
                (call $reply_append (i32.const 80) (i32.const 2))
                (call $msg_reply))
            (func $on_reject (param $env i32)
                (i32.store8 (i32.const 32) (call $reject_code))
                (call $reply_append (i32.const 32) (i32.const 1))
                (call $msg_reply))
            (func $on_cleanup (param $pages i32)
                (call $touch (local.get $pages))
                (i32.store8 (i32.const 48) (i32.const 119)))
            (func (export "canister_query marker")
                (call $reply_append (i32.const 48) (i32.const 1))
                (call $msg_reply))
            (memory (export "memory") 16)
            (data (i32.const 64) "touch")
            (data (i32.const 80) "ok")
            (table 3 3 funcref)
            (elem (i32.const 0) $on_reply $on_reject $on_cleanup)
        )"#
    )
}

/// A canister whose `read` update copies as many pages as the first payload
/// byte says from stable memory into the heap, starting at address 0.
fn stable_read_wat() -> String {
    r#"
        (module
            (import "ic0" "msg_arg_data_copy" (func $arg_copy (param i32 i32 i32)))
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "stable64_grow" (func $stable_grow (param i64) (result i64)))
            (import "ic0" "stable64_read" (func $stable_read (param i64 i64 i64)))
            (func (export "canister_init") (drop (call $stable_grow (i64.const 64))))
            (func (export "canister_update read")
                (call $arg_copy (i32.const 256) (i32.const 0) (i32.const 1))
                (call $stable_read
                    (i64.const 0)
                    (i64.const 0)
                    (i64.mul (i64.extend_i32_u (i32.load8_u (i32.const 256))) (i64.const 65536)))
                (call $msg_reply))
            (memory (export "memory") 64)
        )"#
    .to_string()
}

fn touch(
    test: &mut ExecutionTest,
    canister_id: CanisterId,
    pages: u8,
) -> Result<WasmResult, UserError> {
    test.ingress(canister_id, "touch", vec![pages])
}

fn touch_query(
    test: &mut ExecutionTest,
    canister_id: CanisterId,
    pages: u8,
) -> Result<WasmResult, UserError> {
    test.non_replicated_query(canister_id, "touch_query", vec![pages])
}

fn balance(test: &ExecutionTest, canister_id: CanisterId) -> Cycles {
    test.canister_state(canister_id).system_state.balance()
}

////////////////////////////////////////////////////////////////////////
// Per API type, install and upgrade hooks

#[test]
fn limit_value_depends_on_the_kind_of_execution() {
    let mut test = builder(limits(3, 5, 2)).build();
    let canister_id = test.canister_from_wat(pages_wat()).unwrap();

    // Updates use the message limit.
    touch(&mut test, canister_id, 3).unwrap();
    assert_limit_error(&touch(&mut test, canister_id, 4).unwrap_err(), "Wasm heap");

    // Queries use the query limit, whether they run replicated (as an
    // ingress message) or not.
    touch_query(&mut test, canister_id, 2).unwrap();
    assert_limit_error(
        &touch_query(&mut test, canister_id, 3).unwrap_err(),
        "Wasm heap",
    );
    test.ingress(canister_id, "touch_query", vec![2]).unwrap();
    assert_limit_error(
        &test
            .ingress(canister_id, "touch_query", vec![3])
            .unwrap_err(),
        "Wasm heap",
    );

    // The failures leave the canister working and the next message has a
    // full budget again.
    touch(&mut test, canister_id, 3).unwrap();
}

#[test]
fn install_and_upgrade_hooks_use_the_upgrade_limit() {
    let mut test = builder(limits(1, 5, 1)).build();
    let wasm =
        |init, pre, post, version| wat::parse_str(hooks_wat(init, pre, post, version, "")).unwrap();

    // `canister_init` touching more than the upgrade limit fails the install.
    let err = test.canister_from_binary(wasm(6, 1, 1, 1)).unwrap_err();
    assert_limit_error(&err, "Wasm heap");

    // Exactly the upgrade limit is fine, and the message limit (1 page) is
    // not what applies here.
    let canister_id = test.canister_from_binary(wasm(5, 1, 1, 1)).unwrap();
    assert_eq!(
        test.ingress(canister_id, "version", vec![]).unwrap(),
        WasmResult::Reply(vec![1])
    );

    // A `post_upgrade` over the limit fails the upgrade and keeps the old
    // module and state.
    let err = test
        .upgrade_canister(canister_id, wasm(1, 1, 6, 2))
        .unwrap_err();
    assert_limit_error(&err, "Wasm heap");
    assert_eq!(
        test.ingress(canister_id, "version", vec![]).unwrap(),
        WasmResult::Reply(vec![1])
    );

    // The same for `pre_upgrade` of the old module: install a module whose
    // pre-upgrade hook is over the limit, then try to upgrade away from it.
    let canister_id = test.canister_from_binary(wasm(1, 6, 1, 3)).unwrap();
    let err = test
        .upgrade_canister(canister_id, wasm(1, 1, 1, 4))
        .unwrap_err();
    assert_limit_error(&err, "Wasm heap");
    assert_eq!(
        test.ingress(canister_id, "version", vec![]).unwrap(),
        WasmResult::Reply(vec![3])
    );

    // Hooks at the limit succeed.
    let canister_id = test.canister_from_binary(wasm(5, 5, 1, 5)).unwrap();
    test.upgrade_canister(canister_id, wasm(1, 1, 5, 6))
        .unwrap();
    assert_eq!(
        test.ingress(canister_id, "version", vec![]).unwrap(),
        WasmResult::Reply(vec![6])
    );
}

/// Data segments are written into the heap when the module is installed,
/// outside of any execution, so they do not count against the limit of the
/// `canister_init` execution.
#[test]
fn data_segments_do_not_count_against_the_limit() {
    let mut test = builder(limits(1, 1, 2)).build();
    // `canister_init` touches page 0 (the whole upgrade limit); the data
    // segment puts a byte into page 7.
    let wat = hooks_wat(1, 0, 0, 1, r#"(data (i32.const 458752) "\07")"#);
    let canister_id = test.canister_from_wat(wat).unwrap();

    // The byte is there (the query touches pages 0 and 7, within its limit).
    let result = test
        .non_replicated_query(canister_id, "byte_at", 458752_u32.to_le_bytes().to_vec())
        .unwrap();
    assert_eq!(result, WasmResult::Reply(vec![7]));
}

////////////////////////////////////////////////////////////////////////
// Deterministic time slicing

/// A DTS setup in which touching one page costs more than a slice, so a
/// message touching several pages spans several slices.
fn dts_test(limit_pages: u64) -> ExecutionTest {
    // Writing into a new Wasm page costs 16 OS pages of accessed and of
    // dirty page overhead; a slice allows roughly one page. (A single page
    // fault must fit into a slice, otherwise the execution fails with a
    // slice overrun.)
    let page_overhead = ic_config::subnet_config::SchedulerConfig::application_subnet()
        .page_overhead
        .get();
    builder(limits(limit_pages, limit_pages, limit_pages))
        .with_manual_execution()
        .with_slice_instruction_limit(2 * OS_PAGES_PER_WASM_PAGE * page_overhead + 10_000)
        .with_instruction_limit(100_000_000)
        .build()
}

#[test]
fn accessed_pages_accumulate_across_slices() {
    const LIMIT: u64 = 6;
    let mut test = dts_test(LIMIT);
    let canister_id = test.canister_from_wat(pages_wat()).unwrap();

    // Touching the limit's worth of pages spans several slices and succeeds.
    let (message_id, _) = test.ingress_raw(canister_id, "touch", vec![LIMIT as u8]);
    test.execute_slice(canister_id);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::ContinueLong,
        "the message must not finish in one slice for this test to be meaningful"
    );
    test.execute_message(canister_id);
    check_ingress_status(test.ingress_status(&message_id)).unwrap();

    // One page more fails in a later slice with the limit error (not with
    // the instruction limit), because the pages of earlier slices count.
    let (message_id, _) = test.ingress_raw(canister_id, "touch", vec![LIMIT as u8 + 1]);
    test.execute_slice(canister_id);
    assert_eq!(test.ingress_state(&message_id), IngressState::Processing);
    test.execute_message(canister_id);
    let err = check_ingress_status(test.ingress_status(&message_id)).unwrap_err();
    assert_limit_error(&err, "Wasm heap");
}

#[test]
fn aborted_execution_starts_with_a_fresh_budget() {
    const LIMIT: u64 = 6;
    let mut test = dts_test(LIMIT);
    let canister_id = test.canister_from_wat(pages_wat()).unwrap();

    // Pause a message that touches exactly the limit after its first slice,
    // abort it, and let it run again from the start. If the pages of the
    // aborted slice were still counted, the re-execution would exceed the
    // limit.
    let (message_id, _) = test.ingress_raw(canister_id, "touch", vec![LIMIT as u8]);
    test.execute_slice(canister_id);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::ContinueLong
    );
    test.abort_all_paused_executions();
    assert_eq!(
        fetch_int_counter(test.metrics_registry(), "executions_aborted"),
        Some(1)
    );
    test.execute_message(canister_id);
    check_ingress_status(test.ingress_status(&message_id)).unwrap();
}

////////////////////////////////////////////////////////////////////////
// Callbacks

/// Runs the caller's `call` with the given numbers of pages touched in the
/// update, by the callee, in the reply callback and in the cleanup callback.
fn call(
    test: &mut ExecutionTest,
    caller: CanisterId,
    callee: CanisterId,
    update: u8,
    callee_pages: u8,
    reply: u8,
    cleanup: u8,
) -> Result<WasmResult, UserError> {
    let id = callee.get();
    let mut payload = vec![
        update,
        callee_pages,
        reply,
        cleanup,
        id.as_slice().len() as u8,
    ];
    payload.extend_from_slice(id.as_slice());
    test.ingress(caller, "call", payload)
}

fn marker(test: &mut ExecutionTest, caller: CanisterId) -> u8 {
    match test.non_replicated_query(caller, "marker", vec![]).unwrap() {
        WasmResult::Reply(bytes) => bytes[0],
        other => panic!("unexpected result {other:?}"),
    }
}

#[test]
fn each_callback_has_its_own_budget() {
    const LIMIT: u64 = 4;
    let mut test = builder(limits(LIMIT, LIMIT, LIMIT)).build();
    let callee = test.canister_from_wat(pages_wat()).unwrap();
    let caller = test.canister_from_wat(caller_wat()).unwrap();
    let l = LIMIT as u8;

    // The update, the callee and the reply callback each touch exactly the
    // limit: three separate executions, three separate budgets.
    assert_eq!(
        call(&mut test, caller, callee, l, l, l, 1).unwrap(),
        WasmResult::Reply(b"ok".to_vec())
    );
    assert_eq!(marker(&mut test, caller), 0);

    // The callee exceeds the limit: its execution fails and the caller's
    // reject callback sees reject code 5 (`CanisterError`).
    assert_eq!(
        call(&mut test, caller, callee, 1, l + 1, 1, 1).unwrap(),
        WasmResult::Reply(vec![5])
    );

    // The reply callback exceeds the limit: the message fails with the limit
    // error, and the cleanup callback runs with a budget of its own (it
    // touches the limit's worth of pages) and leaves its marker.
    let err = call(&mut test, caller, callee, 1, 1, l + 1, l).unwrap_err();
    assert_limit_error(&err, "Wasm heap");
    assert_eq!(marker(&mut test, caller), 119);
}

////////////////////////////////////////////////////////////////////////
// Queries

#[test]
fn limit_error_of_a_query_is_cached_like_any_result() {
    const LIMIT: u64 = 2;
    let mut test = builder(limits(8, 8, LIMIT)).build();
    let canister_id = test.canister_from_wat(pages_wat()).unwrap();
    let hits = |test: &ExecutionTest| {
        fetch_int_counter(test.metrics_registry(), "execution_query_cache_hits_total").unwrap_or(0)
    };

    // The limit error is deterministic for a given state, so the query
    // cache serves it like any other result: the second identical query is
    // a cache hit and reports the same error.
    for _ in 0..2 {
        assert_limit_error(
            &touch_query(&mut test, canister_id, LIMIT as u8 + 1).unwrap_err(),
            "Wasm heap",
        );
    }
    assert_eq!(hits(&test), 1);

    // Same for a successful query at the limit.
    touch_query(&mut test, canister_id, LIMIT as u8).unwrap();
    touch_query(&mut test, canister_id, LIMIT as u8).unwrap();
    assert_eq!(hits(&test), 2);
}

#[test]
fn composite_query_callee_is_subject_to_the_query_limit() {
    // Wide enough for the universal canister's own heap use in the caller,
    // too narrow for the callee's 100 pages.
    const LIMIT: u64 = 64;
    let mut test = builder(limits(LIMIT, LIMIT, LIMIT)).build();
    let callee = test.canister_from_wat(pages_wat()).unwrap();
    let caller = test.universal_canister().unwrap();

    let composite_query = |pages: u8| {
        wasm()
            .call_simple(
                callee,
                "touch_query",
                call_args()
                    .other_side(vec![pages])
                    .on_reply(wasm().reply_data(b"ok"))
                    .on_reject(wasm().reject_message().reply_data_append().reply()),
            )
            .build()
    };

    assert_eq!(
        test.non_replicated_query(caller, "composite_query", composite_query(LIMIT as u8))
            .unwrap(),
        WasmResult::Reply(b"ok".to_vec())
    );
    let WasmResult::Reply(reject_message) = test
        .non_replicated_query(caller, "composite_query", composite_query(100))
        .unwrap()
    else {
        panic!("expected a reply with the reject message");
    };
    let reject_message = String::from_utf8(reject_message).unwrap();
    assert!(
        reject_message.contains("accessed pages in the Wasm heap"),
        "{reject_message}"
    );
}

////////////////////////////////////////////////////////////////////////
// Stable memory copies

#[test]
fn stable_read_into_the_heap_reports_the_limit_it_hits() {
    // Heap limit smaller than the copy: the heap limit is reported.
    let mut test = builder(limits(4, 4, 4))
        .with_stable_memory_access_limit(limits(32, 32, 32))
        .build();
    let canister_id = test.canister_from_wat(stable_read_wat()).unwrap();
    test.ingress(canister_id, "read", vec![4]).unwrap();
    assert_limit_error(
        &test.ingress(canister_id, "read", vec![5]).unwrap_err(),
        "Wasm heap",
    );

    // Stable limit smaller than the copy: the stable limit is reported.
    let mut test = builder(limits(32, 32, 32))
        .with_stable_memory_access_limit(limits(4, 4, 4))
        .build();
    let canister_id = test.canister_from_wat(stable_read_wat()).unwrap();
    test.ingress(canister_id, "read", vec![4]).unwrap();
    assert_limit_error(
        &test.ingress(canister_id, "read", vec![5]).unwrap_err(),
        "stable memory",
    );

    // Both exceeded: the stable memory pages are counted first, so that
    // limit is reported.
    let mut test = builder(limits(4, 4, 4))
        .with_stable_memory_access_limit(limits(4, 4, 4))
        .build();
    let canister_id = test.canister_from_wat(stable_read_wat()).unwrap();
    assert_limit_error(
        &test.ingress(canister_id, "read", vec![5]).unwrap_err(),
        "stable memory",
    );
}

////////////////////////////////////////////////////////////////////////
// Determinism and charging

/// Runs `touch pages` in a fresh test and returns what another replica must
/// agree on: the result, the instructions, the cycles and the dirty pages.
fn touch_outcome(pages: u8) -> (Result<WasmResult, String>, u64, Cycles, Vec<u64>) {
    const LIMIT: u64 = 8;
    let mut test = builder(limits(LIMIT, LIMIT, LIMIT)).build();
    let canister_id = test.canister_from_wat(pages_wat()).unwrap();
    let instructions_before = test.canister_executed_instructions(canister_id);
    let balance_before = balance(&test, canister_id);
    let result = touch(&mut test, canister_id, pages).map_err(|err| err.to_string());
    let dirty_pages = test
        .execution_state(canister_id)
        .wasm_memory
        .page_map
        .get_page_delta_indices()
        .into_iter()
        .map(|index| index.get())
        .collect();
    (
        result,
        (test.canister_executed_instructions(canister_id) - instructions_before).get(),
        balance_before - balance(&test, canister_id),
        dirty_pages,
    )
}

#[test]
fn outcome_at_and_over_the_limit_is_deterministic() {
    for pages in [8, 9] {
        let first = touch_outcome(pages);
        let second = touch_outcome(pages);
        assert_eq!(first, second, "touching {pages} pages");
    }
    assert!(touch_outcome(8).0.is_ok());
    assert!(touch_outcome(9).0.is_err());
}

#[test]
fn failed_message_is_charged_for_the_pages_it_touched() {
    const LIMIT: u64 = 8;
    let mut test = builder(limits(LIMIT, LIMIT, LIMIT)).build();
    let canister_id = test.canister_from_wat(pages_wat()).unwrap();

    let charge = |test: &mut ExecutionTest, pages: u8| {
        let before = balance(test, canister_id);
        let result = touch(test, canister_id, pages);
        (result, before - balance(test, canister_id))
    };
    let (ok, charge_at_limit) = charge(&mut test, LIMIT as u8);
    ok.unwrap();
    let (err, charge_over_limit) = charge(&mut test, LIMIT as u8 + 1);
    assert_limit_error(&err.unwrap_err(), "Wasm heap");

    // The failing message faulted in the same pages as the successful one;
    // it differs by a few instructions (one more loop iteration, no reply)
    // and the refused page is not charged, so the two charges agree to
    // within one page's overhead.
    let one_page = Cycles::new(
        (OS_PAGES_PER_WASM_PAGE
            * ic_config::subnet_config::SchedulerConfig::application_subnet()
                .page_overhead
                .get()) as u128,
    );
    let difference =
        charge_over_limit.max(charge_at_limit) - charge_over_limit.min(charge_at_limit);
    assert!(
        difference < one_page,
        "{charge_at_limit} at the limit, {charge_over_limit} over it"
    );
    // Far more than a message touching a single page costs.
    let (ok, charge_one_page) = charge(&mut test, 1);
    ok.unwrap();
    assert!(
        charge_over_limit > charge_one_page + one_page,
        "{charge_over_limit} over the limit, {charge_one_page} for one page"
    );
}

#[test]
fn aborted_execution_is_charged_once() {
    const LIMIT: u64 = 6;
    let pages = LIMIT as u8;

    let mut test = dts_test(LIMIT);
    let canister_id = test.canister_from_wat(pages_wat()).unwrap();
    let before = balance(&test, canister_id);
    let (message_id, _) = test.ingress_raw(canister_id, "touch", vec![pages]);
    test.execute_message(canister_id);
    check_ingress_status(test.ingress_status(&message_id)).unwrap();
    let charge_without_abort = before - balance(&test, canister_id);

    let mut test = dts_test(LIMIT);
    let canister_id = test.canister_from_wat(pages_wat()).unwrap();
    let before = balance(&test, canister_id);
    let (message_id, _) = test.ingress_raw(canister_id, "touch", vec![pages]);
    test.execute_slice(canister_id);
    test.abort_all_paused_executions();
    test.execute_message(canister_id);
    check_ingress_status(test.ingress_status(&message_id)).unwrap();
    let charge_with_abort = before - balance(&test, canister_id);

    assert_eq!(charge_with_abort, charge_without_abort);
}

////////////////////////////////////////////////////////////////////////
// Persisted globals

/// The heap page budget is kept in an exported Wasm global, but it must not
/// be persisted with the canister: the persisted globals are the module's own
/// globals plus the instruction counter, as before the limit existed, so
/// states written by earlier replica versions stay loadable.
#[test]
fn persisted_globals_have_the_layout_of_before_the_limit() {
    // Two exported globals and one internal global, which is not persisted.
    let wat = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (global $a (export "a") (mut i32) (i32.const 1))
            (global $b (export "b") (mut i64) (i64.const 2))
            (global $c (mut i32) (i32.const 3))
            (func (export "canister_update bump")
                (global.set $a (i32.add (global.get $a) (i32.const 1)))
                (global.set $c (i32.add (global.get $c) (i32.const 1)))
                (i32.store8 (i32.const 0) (i32.const 1))
                (call $msg_reply))
            (memory (export "memory") 1)
        )"#;
    let mut test = builder(limits(4, 4, 4)).build();
    let canister_id = test.canister_from_wat(wat).unwrap();
    test.ingress(canister_id, "bump", vec![]).unwrap();

    // The three module globals (the instrumentation exports the internal
    // one too, so that it is persisted) plus the instruction counter. The
    // heap page budget is not among them.
    let persisted = test.execution_state(canister_id).exported_globals.clone();
    assert_eq!(persisted.len(), 4, "{persisted:?}");

    // A state with exactly these globals (what a replica without the budget
    // global persisted) instantiates and runs.
    test.canister_state_mut(canister_id)
        .execution_state
        .as_mut()
        .unwrap()
        .exported_globals = persisted.clone();
    test.ingress(canister_id, "bump", vec![]).unwrap();
    assert_eq!(
        test.execution_state(canister_id).exported_globals.len(),
        persisted.len()
    );
}
