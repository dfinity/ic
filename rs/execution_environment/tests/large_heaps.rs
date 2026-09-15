//! End-to-end tests of Wasm64 heaps larger than the per-message access limit.
//!
//! These tests actually fault and dirty multi-GiB heaps, so they need on the
//! order of 18 GiB of RAM and might take minutes. They live in a dedicated Bazel
//! target so they do not inflate the regular execution-environment suite.

use ic_config::embedders::{Config as EmbeddersConfig, MemoryPageLimit};
use ic_error_types::{ErrorCode, UserError};
use ic_management_canister_types_private::CanisterSettingsArgsBuilder;
use ic_replicated_state::canister_state::WASM_PAGE_SIZE_IN_BYTES;
use ic_sys::PAGE_SIZE;
use ic_test_utilities_execution_environment::{ExecutionTest, ExecutionTestBuilder};
use ic_test_utilities_metrics::{HistogramStats, fetch_histogram_vec_stats, metric_vec};
use ic_types::ingress::WasmResult;
use ic_types::{CanisterId, MAX_WASM64_MEMORY_IN_BYTES};
use ic_types_cycles::Cycles;

/// Cycles balance large enough to allocate an 18 GiB heap and pay for the
/// instruction cost of touching it.
const LARGE_HEAP_CYCLES: Cycles = Cycles::new(100_000_000_000_000_000);

/// The per-message heap access limit in bytes, taken from the default embedders
/// config so the tests stay coupled to the production value.
fn per_message_heap_access_limit_bytes() -> u64 {
    EmbeddersConfig::default()
        .wasm_memory_accessed_page_limit
        .message
        .get()
        * PAGE_SIZE as u64
}

fn expected_heap_access_error(canister_id: CanisterId, limit: &MemoryPageLimit) -> String {
    format!(
        "Error from Canister {canister_id}: Canister exceeded memory access \
        limits: Exceeded the limit for the number of accessed pages in the heap \
        in a single execution: limit {} KB for regular messages, {} KB for \
        upgrade messages and {} KB for queries.",
        limit.message.get() * (PAGE_SIZE as u64 / 1024),
        limit.upgrade.get() * (PAGE_SIZE as u64 / 1024),
        limit.query.get() * (PAGE_SIZE as u64 / 1024),
    )
}

fn wasm64_touch_heap_wat() -> String {
    let heap_pages = MAX_WASM64_MEMORY_IN_BYTES / WASM_PAGE_SIZE_IN_BYTES as u64;
    format!(
        r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_arg_data_copy"
                (func $msg_arg_data_copy (param i64 i64 i64)))
            ;; Exported so it persists across messages.
            (global $next (export "next") (mut i64) (i64.const 0))
            (memory (export "memory") i64 {heap_pages})

            ;; Payload: little-endian i64 byte count. Writes 1 byte per Wasm
            ;; page over that many bytes, starting at $next.
            (func (export "canister_update touch")
                (local $addr i64) (local $end i64)
                ;; Copy the amount into the range we are about to touch, so
                ;; decoding the payload does not fault an extra page.
                (call $msg_arg_data_copy (global.get $next) (i64.const 0) (i64.const 8))
                (local.set $addr (global.get $next))
                (local.set $end (i64.add (local.get $addr) (i64.load (local.get $addr))))
                (loop $loop
                    (i32.store8 (local.get $addr) (i32.const 1))
                    (local.set $addr (i64.add (local.get $addr) (i64.const {wasm_page_size})))
                    (br_if $loop (i64.lt_u (local.get $addr) (local.get $end)))
                )
                (global.set $next (local.get $addr))
                (call $msg_reply)
            )
        )
        "#,
        wasm_page_size = WASM_PAGE_SIZE_IN_BYTES,
    )
}

fn install_wasm64_large_heap() -> (ExecutionTest, CanisterId) {
    let mut test = ExecutionTestBuilder::new()
        // Newly created canisters otherwise inherit the 3 GiB default
        // `wasm_memory_limit`, which would reject an 18 GiB heap.
        .with_default_wasm_memory_limit(0)
        .with_initial_canister_cycles(LARGE_HEAP_CYCLES.get())
        .with_precompiled_universal_canister(false)
        .build();

    let canister_id = test
        .create_canister_with_settings(
            LARGE_HEAP_CYCLES,
            CanisterSettingsArgsBuilder::new()
                .with_wasm_memory_limit(0)
                .with_freezing_threshold(1)
                .build(),
        )
        .unwrap();
    test.install_canister(
        canister_id,
        wat::parse_str(wasm64_touch_heap_wat()).unwrap(),
    )
    .unwrap();
    (test, canister_id)
}

fn touch(
    test: &mut ExecutionTest,
    canister_id: CanisterId,
    amount: u64,
) -> Result<WasmResult, UserError> {
    test.ingress(canister_id, "touch", amount.to_le_bytes().to_vec())
}

fn wasm_pages(bytes: u64) -> u64 {
    bytes / WASM_PAGE_SIZE_IN_BYTES as u64
}

/// Asserts `sandboxed_execution_{accessed,dirty}_wasm_pages` for update/wasm.
fn assert_update_touched_wasm_pages(test: &ExecutionTest, messages: u64, pages: u64) {
    let expected = metric_vec(&[(
        &[("api_type", "update"), ("memory_type", "wasm")],
        HistogramStats {
            count: messages,
            sum: pages as f64,
        },
    )]);
    for metric in [
        "sandboxed_execution_accessed_wasm_pages",
        "sandboxed_execution_dirty_wasm_pages",
    ] {
        assert_eq!(
            fetch_histogram_vec_stats(test.metrics_registry(), metric),
            expected,
            "{metric}"
        );
    }
}

/// Touching past the 6 GiB per-message limit in a single update must fail,
/// even though the canister's heap is 18 GiB.
#[test]
fn touching_past_per_message_heap_access_limit_fails() {
    let per_message = per_message_heap_access_limit_bytes();
    // The pending-trap check runs at the next loop header, so the amount has
    // to extend two Wasm pages past the limit: the first extra page trips
    // the counter, the second iteration notices the pending trap.
    let amount = per_message + 2 * WASM_PAGE_SIZE_IN_BYTES as u64;

    let (mut test, canister_id) = install_wasm64_large_heap();

    let result = touch(&mut test, canister_id, amount).unwrap_err();
    result.assert_contains(
        ErrorCode::CanisterMemoryAccessLimitExceeded,
        &expected_heap_access_error(
            canister_id,
            &EmbeddersConfig::default().wasm_memory_accessed_page_limit,
        ),
    );
    // The trap is raised at the loop header after the first extra page is
    // stored, so that page is counted and the second extra store never runs.
    assert_update_touched_wasm_pages(&test, 1, wasm_pages(per_message) + 1);
}

/// The 18 GiB Wasm64 heap can be filled at 6 GiB per message, across three
/// messages. Each message sits exactly on the per-message access limit.
#[test]
fn touching_full_wasm64_heap_over_three_messages_succeeds() {
    let heap_bytes = MAX_WASM64_MEMORY_IN_BYTES;
    let per_message = per_message_heap_access_limit_bytes();
    assert_eq!(
        heap_bytes,
        3 * per_message,
        "this test assumes the Wasm64 heap is exactly three per-message access limits"
    );

    let (mut test, canister_id) = install_wasm64_large_heap();

    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size.get() as u64,
        heap_bytes / WASM_PAGE_SIZE_IN_BYTES as u64
    );

    for i in 0..3 {
        let result = touch(&mut test, canister_id, per_message);
        assert_eq!(
            result,
            Ok(WasmResult::Reply(vec![])),
            "touch #{i} should succeed at exactly the per-message access limit"
        );
    }
    assert_update_touched_wasm_pages(&test, 3, wasm_pages(heap_bytes));
}
