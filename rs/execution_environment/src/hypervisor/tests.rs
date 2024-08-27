use crate::hypervisor::tests::WasmResult::Reply;
use assert_matches::assert_matches;
use candid::{Decode, Encode};
use ic_base_types::{NumSeconds, PrincipalId};
use ic_config::flag_status::FlagStatus;
use ic_config::subnet_config::SchedulerConfig;
use ic_cycles_account_manager::ResourceSaturation;
use ic_embedders::wasm_utils::instrumentation::instruction_to_cost;
use ic_error_types::{ErrorCode, RejectCode};
use ic_interfaces::execution_environment::{HypervisorError, SubnetAvailableMemory};
use ic_management_canister_types::{
    CanisterChange, CanisterHttpResponsePayload, CanisterUpgradeOptions,
};
use ic_nns_constants::CYCLES_MINTING_CANISTER_ID;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::{NextExecution, WASM_PAGE_SIZE_IN_BYTES};
use ic_replicated_state::testing::CanisterQueuesTesting;
use ic_replicated_state::testing::SystemStateTesting;
use ic_replicated_state::{
    canister_state::execution_state::CustomSectionType, ExportedFunctions, Global, PageIndex,
};
use ic_replicated_state::{CanisterStatus, NumWasmPages, PageMap};
use ic_sys::PAGE_SIZE;
use ic_system_api::MAX_CALL_TIMEOUT_SECONDS;
use ic_test_utilities::assert_utils::assert_balance_equals;
use ic_test_utilities_execution_environment::{
    assert_empty_reply, check_ingress_status, get_reply, wasm_compilation_cost,
    wat_compilation_cost, ExecutionTest, ExecutionTestBuilder,
};
use ic_test_utilities_metrics::fetch_int_counter;
use ic_test_utilities_metrics::{fetch_histogram_vec_stats, metric_vec, HistogramStats};
use ic_types::messages::{CanisterMessage, NO_DEADLINE};
use ic_types::time::CoarseTime;
use ic_types::Time;
use ic_types::{
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::CanisterTask,
    messages::MAX_INTER_CANISTER_PAYLOAD_IN_BYTES,
    methods::WasmMethod,
    CanisterId, ComputeAllocation, Cycles, NumBytes, NumInstructions, MAX_STABLE_MEMORY_IN_BYTES,
};
use ic_universal_canister::{call_args, wasm, UNIVERSAL_CANISTER_WASM};
#[cfg(not(all(target_arch = "aarch64", target_vendor = "apple")))]
use proptest::prelude::*;
#[cfg(not(all(target_arch = "aarch64", target_vendor = "apple")))]
use proptest::test_runner::{TestRng, TestRunner};
use std::collections::BTreeSet;
use std::mem::size_of;
use std::time::Duration;

const MAX_NUM_INSTRUCTIONS: NumInstructions = NumInstructions::new(1_000_000_000);
const BALANCE_EPSILON: Cycles = Cycles::new(10_000_000);

#[test]
fn ic0_canister_status_works() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "canister_status"
                (func $canister_status (result i32))
            )
            (func (export "canister_update test")
                (if (i32.ne (call $canister_status) (i32.const 1))
                    (then unreachable)
                )
            )
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![0, 1, 2, 3]);
    assert_empty_reply(result);
}

#[test]
fn ic0_msg_arg_data_size_works() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "msg_arg_data_size"
                (func $msg_arg_data_size (result i32))
            )
            (func (export "canister_update test")
                (if (i32.ne (call $msg_arg_data_size) (i32.const 4))
                    (then (unreachable))
                )
            )
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![0, 1, 2, 3]);
    assert_empty_reply(result);
}

#[test]
fn ic0_stable_grow_works() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable_size" (func $stable_size (result i32)))
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))

            (func (export "canister_update test")
                ;; Grow the memory by 1 page and verify that the return value
                ;; is the previous number of pages, which should be 0.
                (if (i32.ne (call $stable_grow (i32.const 1)) (i32.const 0))
                    (then (unreachable))
                )

                ;; Grow the memory by 5 more pages and verify that the return value
                ;; is the previous number of pages, which should be 1.
                (if (i32.ne (call $stable_grow (i32.const 5)) (i32.const 1))
                    (then (unreachable))
                )

                ;; Stable memory size now should be 6
                (if (i32.ne (call $stable_size) (i32.const 6))
                    (then (unreachable))
                )
            )
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
}

#[test]
fn ic0_stable_grow_returns_neg_one_when_exceeding_memory_limit() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable_size" (func $stable_size (result i32)))
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))

            (func (export "canister_update test")
                ;; Grow the memory by 1000 pages and verify that the return value
                ;; is -1 because the grow should fail.
                (if (i32.ne (call $stable_grow (i32.const 1000)) (i32.const -1))
                    (then (unreachable))
                )
            )
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    test.canister_update_allocations_settings(canister_id, None, Some(30 * 1024 * 1024))
        .unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
}

#[test]
fn ic0_stable64_size_works() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable64_size" (func $stable_size (result i64)))
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))

            (func (export "canister_update test")
                ;; Grow the memory by 6 pages and verify that the return value
                ;; is the previous number of pages, which should be 0.
                (if (i32.ne (call $stable_grow (i32.const 6)) (i32.const 0))
                    (then (unreachable))
                )

                ;; Stable memory size now should be 6
                (if (i64.ne (call $stable_size) (i64.const 6))
                    (then (unreachable))
                )
            )
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
}

#[test]
#[cfg(not(all(target_arch = "aarch64", target_vendor = "apple")))]
fn ic0_stable_write_increases_heap_delta() {
    let mut test = ExecutionTestBuilder::new().build();
    fn wat(bytes: usize) -> String {
        format!(
            r#"(module
                (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
                (import "ic0" "stable_write"
                    (func $stable_write (param $offset i32) (param $src i32) (param $size i32))
                )
                (func (export "canister_update test")
                    (drop (call $stable_grow (i32.const 1)))
                    (call $stable_write (i32.const 0) (i32.const 0) (i32.const {}))
                )
                (memory 1)
            )"#,
            bytes
        )
    }
    let canister_id = test.canister_from_wat(wat(4097)).unwrap();
    assert_eq!(NumBytes::from(0), test.state().metadata.heap_delta_estimate);
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
    // We wrote more than 1 page but less than 2 pages so we expect 2 pages in
    // heap delta.
    assert_eq!(
        NumBytes::from(8192),
        test.state().metadata.heap_delta_estimate
    );
    let canister_id = test.canister_from_wat(wat(8192)).unwrap();
    let heap_delta_estimate_before = test.state().metadata.heap_delta_estimate;
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
    // We wrote exactly 2 pages so we expect 2 pages in heap delta.
    assert_eq!(
        heap_delta_estimate_before + NumBytes::from(8192),
        test.state().metadata.heap_delta_estimate
    );
}

#[test]
#[cfg(not(all(target_arch = "aarch64", target_vendor = "apple")))]
fn ic0_stable64_write_increases_heap_delta() {
    let mut test = ExecutionTestBuilder::new().build();
    fn wat(bytes: usize) -> String {
        format!(
            r#"(module
                (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
                (import "ic0" "stable64_write"
                    (func $stable64_write (param $offset i64) (param $src i64) (param $size i64))
                )
                (func (export "canister_update test")
                    (drop (call $stable64_grow (i64.const 1)))
                    (call $stable64_write (i64.const 0) (i64.const 0) (i64.const {}))
                )
                (memory 1)
            )"#,
            bytes
        )
    }
    let canister_id = test.canister_from_wat(wat(4097)).unwrap();
    assert_eq!(NumBytes::from(0), test.state().metadata.heap_delta_estimate);
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
    // We wrote more than 1 page but less than 2 pages so we expect 2 pages in
    // heap delta.
    assert_eq!(
        NumBytes::from(8192),
        test.state().metadata.heap_delta_estimate
    );
    let canister_id = test.canister_from_wat(wat(8192)).unwrap();
    let heap_delta_estimate_before = test.state().metadata.heap_delta_estimate;
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
    // We wrote exactly 2 pages so we expect 2 pages in heap delta.
    assert_eq!(
        heap_delta_estimate_before + NumBytes::from(8192),
        test.state().metadata.heap_delta_estimate
    );
}

#[test]
fn ic0_stable64_grow_does_not_change_heap_delta() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable64_size" (func $stable64_size (result i64)))
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
            (func (export "canister_update test")
                (if (i64.ne (call $stable64_grow (i64.const 1)) (i64.const 0))
                    (then (unreachable))
                )
                (if (i64.ne (call $stable64_size) (i64.const 1))
                    (then (unreachable))
                )
            )
            (memory 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
    assert_eq!(NumBytes::from(0), test.state().metadata.heap_delta_estimate);
}

#[test]
fn ic0_grow_handles_overflow() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))

            (func (export "canister_update test")
                ;; Grow the memory by 10 pages.
                (drop (call $stable_grow (i32.const 10)))
                ;; Grow the memory up to 64 * 1024 + 1 pages.
                ;; This should fail since it's bigger than the maximum number of memory
                ;; pages that can be used with the 32-bit API and return -1.
                (if (i32.ne (call $stable_grow (i32.const 65527)) (i32.const -1))
                    (then (unreachable))
                )
            )
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
}

#[test]
fn ic0_grow_can_reach_max_number_of_pages() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(3_000_000_000_000)
        .build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))

            (func (export "canister_update test")
                ;; Grow the memory by 10 pages.
                (drop (call $stable_grow (i32.const 10)))
                ;; Grow the memory up to 64 * 1024 pages which is the maximum allowed.
                ;; The result should be the previous number of pages (10).
                (if (i32.ne (call $stable_grow (i32.const 65526)) (i32.const 10))
                    (then (unreachable))
                )
            )
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
}

#[test]
fn ic0_stable64_grow_works() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable64_size" (func $stable64_size (result i64)))
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))

            (func (export "canister_update test")
                ;; Grow the memory by 1 page and verify that the return value
                ;; is the previous number of pages, which should be 0.
                (if (i64.ne (call $stable64_grow (i64.const 1)) (i64.const 0))
                    (then (unreachable))
                )

                ;; Grow the memory by 5 more pages and verify that the return value
                ;; is the previous number of pages, which should be 1.
                (if (i64.ne (call $stable64_grow (i64.const 5)) (i64.const 1))
                    (then (unreachable))
                )

                ;; Grow the memory by 2^64-1 more pages. This should fail.
                (if (i64.ne (call $stable64_grow (i64.const 18446744073709551615)) (i64.const -1))
                    (then (unreachable))
                )

                ;; Stable memory size now should be 6.
                (if (i64.ne (call $stable64_size) (i64.const 6))
                    (then (unreachable))
                )
            )
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
}

#[test]
fn ic0_stable64_grow_beyond_max_pages_returns_neg_one() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = format!(
        r#"
        (module
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))

            (func (export "canister_update test")
                ;; Grow the memory by the maximum number of pages + 1. This should fail.
                (if (i64.ne (call $stable64_grow (i64.const {})) (i64.const -1))
                    (then (unreachable))
                )
            )
        )"#,
        (MAX_STABLE_MEMORY_IN_BYTES / WASM_PAGE_SIZE_IN_BYTES as u64) + 1
    );
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
}

#[test]
fn ic0_stable_grow_by_0_traps_if_memory_exceeds_4gb() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(3_000_000_000_000)
        .build();
    let wat = r#"
        (module
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))

            (func (export "canister_update test")
                ;; Grow the memory to 4GiB.
                (if (i64.ne (call $stable64_grow (i64.const 65536)) (i64.const 0))
                    (then (unreachable))
                )
                ;; Grow the memory by 0 pages using 32-bit API. This should succeed.
                (if (i32.ne (call $stable_grow (i32.const 0)) (i32.const 65536))
                    (then (unreachable))
                )
                ;; Grow the memory by 1 page. This should succeed.
                (if (i64.ne (call $stable64_grow (i64.const 1)) (i64.const 65536))
                    (then (unreachable))
                )
                ;; Grow the memory by 0 pages using 32-bit API. This should trap.
                (drop (call $stable_grow (i32.const 0)))
            )
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err
        .description()
        .contains("32 bit stable memory api used on a memory larger than 4GB"));
}

#[test]
fn ic0_stable_size_traps_if_memory_exceeds_4gb() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(3_000_000_000_000)
        .build();
    let wat = r#"
        (module
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
            (import "ic0" "stable_size" (func $stable_size (result i32)))

            (func (export "canister_update test")
                ;; Grow the memory to 4GiB + 1 page.
                (if (i64.ne (call $stable64_grow (i64.const 65537)) (i64.const 0))
                    (then (unreachable))
                )

                ;; This should trap because stable memory is too big for 32-bit API.
                (drop (call $stable_size))
            )
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err
        .description()
        .contains("32 bit stable memory api used on a memory larger than 4GB"));
}

#[test]
fn ic0_stable_grow_traps_if_stable_memory_exceeds_4gb() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(3_000_000_000_000)
        .build();
    let wat = r#"
        (module
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))

            (func (export "canister_update test")
                ;; Grow the memory to 4GiB.
                (if (i64.ne (call $stable64_grow (i64.const 65536)) (i64.const 0))
                    (then (unreachable))
                )
                ;; Grow the memory by 0 pages using 32-bit API. This should succeed.
                (if (i32.ne (call $stable_grow (i32.const 0)) (i32.const 65536))
                    (then (unreachable))
                )
                ;; Grow the memory by 1 page. This should succeed.
                (if (i64.ne (call $stable64_grow (i64.const 1)) (i64.const 65536))
                    (then (unreachable))
                )
                ;; Grow the memory by 100 pages using 32-bit API. This should trap.
                (drop (call $stable_grow (i32.const 100)))
            )
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err
        .description()
        .contains("32 bit stable memory api used on a memory larger than 4GB"));
}

#[test]
fn ic0_stable_read_and_write_work() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
            (import "ic0" "stable_read"
                (func $stable_read (param $dst i32) (param $offset i32) (param $size i32))
            )
            (import "ic0" "stable_write"
                (func $stable_write (param $offset i32) (param $src i32) (param $size i32))
            )
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32))
            )
            (func $swap
                ;; Swap the first 8 bytes from "abcdefgh" to "efghabcd"
                ;; (and vice-versa in a repeated call) using stable memory

                ;; Grow stable memory by 1 page.
                (drop (call $stable_grow (i32.const 1)))

                ;; stable_memory[0..4] = heap[0..4]
                (call $stable_write (i32.const 0) (i32.const 0) (i32.const 4))

                ;; stable_memory[60000..60004] = heap[4..8]
                (call $stable_write (i32.const 60000) (i32.const 4) (i32.const 4))

                ;; heap[0..4] = stable_memory[60000..60004]
                (call $stable_read (i32.const 0) (i32.const 60000) (i32.const 4))

                ;; heap[4..8] = stable_memory[0..4]
                (call $stable_read (i32.const 4) (i32.const 0) (i32.const 4))
            )
            (func $test
                (call $swap)
                (call $read)
            )
            (func $read
                ;; Return the first 8 bytes of the heap.
                (call $msg_reply_data_append
                    (i32.const 0)     ;; heap offset = 0
                    (i32.const 8))    ;; length = 8
                (call $msg_reply)     ;; call reply
            )
            (memory 1)
            (start $swap)
            (export "canister_query read" (func $read))
            (export "canister_update test" (func $test))
            (data (i32.const 0) "abcdefgh")  ;; Initial contents of the heap.
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "read", vec![]).unwrap();
    assert_eq!(WasmResult::Reply(b"efghabcd".to_vec()), result); // swapped in `start`
    let result = test.ingress(canister_id, "test", vec![]).unwrap();
    assert_eq!(WasmResult::Reply(b"abcdefgh".to_vec()), result); // swapped again in `test`
}

#[test]
fn ic0_stable_read_traps_if_out_of_bounds() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
            (import "ic0" "stable_read"
                (func $stable_read (param $dst i32) (param $offset i32) (param $size i32)))
            (func (export "canister_update test")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable_grow (i32.const 1)))
                ;; Reading from stable memory just after the page should trap.
                (call $stable_read (i32.const 0) (i32.const 65536) (i32.const 1))
            )
            (memory 2 2)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err.description().contains("stable memory out of bounds"));
}

#[test]
fn ic0_stable_read_handles_overflows() {
    let mut test = ExecutionTestBuilder::new()
        .with_deterministic_time_slicing_disabled()
        .build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
            (import "ic0" "stable_read"
                (func $stable_read (param $dst i32) (param $offset i32) (param $size i32)))
            (func (export "canister_update test")
                ;; Grow the memory by 1 page.
                (drop (call $stable_grow (i32.const 1)))
                ;; Ensure reading from stable memory with overflow doesn't panic.
                (call $stable_read (i32.const 0) (i32.const 1) (i32.const 4294967295))
            )
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err.description().contains("stable memory out of bounds"));
}

#[test]
fn ic0_stable_write_traps_if_out_of_bounds() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
            (import "ic0" "stable_write"
                (func $stable_write (param $offset i32) (param $src i32) (param $size i32))
            )
            (func (export "canister_update test")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable_grow (i32.const 1)))
                ;; Writing to stable memory just after the page should trap.
                (call $stable_write (i32.const 65536) (i32.const 0) (i32.const 1))
            )
            (memory 2 2)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err.description().contains("stable memory out of bounds"));
}

#[test]
fn ic0_stable_write_handles_overflows() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
            (import "ic0" "stable_write"
                (func $stable_write (param $offset i32) (param $src i32) (param $size i32)))
            (func (export "canister_update test")
                ;; Grow the memory by 1 page.
                (drop (call $stable_grow (i32.const 1)))
                ;; Ensure writing to stable memory with overflow doesn't panic.
                (call $stable_write (i32.const 4294967295) (i32.const 0) (i32.const 10))
            )
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err.description().contains("stable memory out of bounds"));
}

#[test]
fn ic0_stable_read_traps_if_heap_is_out_of_bounds() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
            (import "ic0" "stable_read"
                (func $stable_read (param $dst i32) (param $offset i32) (param $size i32))
            )
            (func (export "canister_update test")
                ;; Grow the stable memory by 2 pages (128kb).
                (drop (call $stable_grow (i32.const 2)))
                ;; An attempt to copy a page and a byte to the heap should fail.
                (call $stable_read (i32.const 0) (i32.const 0) (i32.const 65537))
            )
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err.description().contains("heap out of bounds"));
}

#[test]
fn ic0_stable_write_traps_if_heap_is_out_of_bounds() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
            (import "ic0" "stable_write"
                (func $stable_write (param $offset i32) (param $src i32) (param $size i32))
            )
            (func (export "canister_update test")
                ;; Grow the stable memory by 2 pages (128kb).
                (drop (call $stable_grow (i32.const 2)))
                ;; An attempt to copy a page and a byte from the heap should fail.
                (call $stable_write (i32.const 0) (i32.const 0) (i32.const 65537))
            )
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err.description().contains("heap out of bounds"));
}

#[test]
fn ic0_stable_write_works_at_max_size() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(3_000_000_000_000)
        .build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
            (import "ic0" "stable_write"
                (func $stable_write (param $offset i32) (param $src i32) (param $size i32))
            )
            (func (export "canister_update test")
                ;; Grow stable memory to maximum size.
                (drop (call $stable_grow (i32.const 65536)))
                ;; Write to stable memory from position 10 till the end (including).
                (call $stable_write (i32.const 4294967286) (i32.const 0) (i32.const 10))
            )
            (memory 65536)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
}

#[test]
fn ic0_stable_read_does_not_trap_if_in_bounds() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
            (import "ic0" "stable_read"
                (func $stable_read (param $dst i32) (param $offset i32) (param $size i32))
            )
            (func (export "canister_update test")
                ;; Grow stable memory by 1 page (64kb).
                (drop (call $stable_grow (i32.const 1)))
                ;; Reading from stable memory at end of page should not fail.
                (call $stable_read (i32.const 0) (i32.const 0) (i32.const 65536))
            )
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
}

#[test]
fn ic0_stable_read_works_at_max_size() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(3_000_000_000_000)
        .build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
            (import "ic0" "stable_read"
                (func $stable_read (param $dst i32) (param $offset i32) (param $size i32))
            )
            (func (export "canister_update test")
                ;; Grow stable memory to maximum size.
                (drop (call $stable_grow (i32.const 65536)))
                ;; Read from position at index 10 till the end of stable memory (including).
                (call $stable_read (i32.const 0) (i32.const 4294967286) (i32.const 10))
            )
            (memory 65536)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
}

#[test]
fn ic0_stable64_read_traps_if_out_of_bounds() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
            (import "ic0" "stable64_read"
                (func $stable64_read (param $dst i64) (param $offset i64) (param $size i64))
            )
            (func (export "canister_update test")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable64_grow (i64.const 1)))
                ;; Reading from stable memory just after the page should trap.
                (call $stable64_read (i64.const 0) (i64.const 65536) (i64.const 1))
            )
            (memory 2 2)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err.description().contains("stable memory out of bounds"));
}

#[test]
fn ic0_stable64_read_handles_overflows() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
            (import "ic0" "stable64_read"
                (func $stable64_read (param $dst i64) (param $offset i64) (param $size i64))
            )
            (func (export "canister_update test")
                ;; Grow the memory by 1 page.
                (drop (call $stable64_grow (i64.const 1)))
                ;; Ensure reading from stable memory with overflow doesn't panic.
                (call $stable64_read (i64.const 0) (i64.const 18446744073709551615) (i64.const 10))
            )
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err.description().contains("stable memory out of bounds"));
}

#[test]
fn ic0_stable64_write_traps_if_out_of_bounds() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
            (import "ic0" "stable64_write"
                (func $stable64_write (param $offset i64) (param $src i64) (param $size i64))
            )
            (func (export "canister_update test")
                ;; Grow stable memory by 1 page (64kb)
                (drop (call $stable64_grow (i64.const 1)))
                ;; Writing to stable memory just after the page should trap.
                (call $stable64_write (i64.const 65536) (i64.const 0) (i64.const 1))
            )
            (memory 2 2)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err.description().contains("stable memory out of bounds"));
}

#[test]
fn ic0_stable64_write_handles_overflows() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
            (import "ic0" "stable64_write"
                (func $stable64_write (param $offset i64) (param $src i64) (param $size i64))
            )
            (func (export "canister_update test")
                ;; Grow the memory by 1 page.
                (drop (call $stable64_grow (i64.const 1)))
                ;; Ensure writing to stable memory with overflow doesn't panic.
                (call $stable64_write (i64.const 18446744073709551615) (i64.const 0) (i64.const 10))
            )
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err.description().contains("stable memory out of bounds"));
}

#[test]
fn ic0_stable64_read_traps_if_heap_is_out_of_bounds() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
            (import "ic0" "stable64_read"
                (func $stable64_read (param $dst i64) (param $offset i64) (param $size i64))
            )
            (func (export "canister_update test")
                ;; Grow the stable memory by 2 pages (128kb).
                (drop (call $stable64_grow (i64.const 2)))
                ;; An attempt to copy a page and a byte to the heap should fail.
                (call $stable64_read (i64.const 0) (i64.const 0) (i64.const 65537))
            )
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err.description().contains("heap out of bounds"));
}

#[test]
fn ic0_stable64_write_traps_if_heap_is_out_of_bounds() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
            (import "ic0" "stable64_write"
                (func $stable64_write (param $offset i64) (param $src i64) (param $size i64))
            )
            (func (export "canister_update test")
                ;; Grow the stable memory by 2 pages (128kb).
                (drop (call $stable64_grow (i64.const 2)))
                ;; An attempt to copy a page and a byte from the heap should fail.
                (call $stable64_write (i64.const 0) (i64.const 0) (i64.const 65537))
            )
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert!(err.description().contains("heap out of bounds"));
}

#[test]
fn ic0_stable64_read_does_not_trap_if_in_bounds() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
            (import "ic0" "stable64_read"
                (func $stable64_read (param $dst i64) (param $offset i64) (param $size i64))
            )
            (func (export "canister_update test")
                ;; Grow stable memory by 1 page (64kb).
                (drop (call $stable64_grow (i64.const 1)))
                ;; Reading from stable memory at end of page should succeed.
                (call $stable64_read (i64.const 0) (i64.const 0) (i64.const 65536))
            )
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
}

#[test]
fn time_with_5_nanoseconds() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "time" (func $time (result i64)))
            (import "ic0" "msg_reply" (func $msg_reply))
            (func (export "canister_update test")
                (if (i64.ne (call $time) (i64.const 5))
                    (then (unreachable))
                )
                (call $msg_reply)
            )
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    test.advance_time(Duration::new(0, 5));
    let result = test.ingress(canister_id, "test", vec![]).unwrap();
    assert_eq!(result, WasmResult::Reply(vec![]));
}

#[test]
fn ic0_time_with_5_seconds() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "time" (func $time (result i64)))
            (import "ic0" "msg_reply" (func $msg_reply))
            (func (export "canister_update test")
                (if (i64.ne (call $time) (i64.const 5000000000))
                    (then (unreachable))
                )
                (call $msg_reply)
            )
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    test.advance_time(Duration::new(5, 0));
    let result = test.ingress(canister_id, "test", vec![]).unwrap();
    assert_eq!(result, WasmResult::Reply(vec![]));
}

#[test]
fn ic0_global_timer_set_returns_previous_value() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "global_timer_set"
                (func $global_timer_set (param i64) (result i64))
            )
            (import "ic0" "msg_reply" (func $msg_reply))
            (func (export "canister_update test")
                ;; Initially the timer should not be set, i.e. be zero
                (if (i64.ne
                        (call $global_timer_set (i64.const 1))
                        (i64.const 0)
                    )
                    (then (unreachable))
                )
                ;; Expect the timer is set to 1 now
                (if (i64.ne
                        (call $global_timer_set (i64.const 0))
                        (i64.const 1)
                    )
                    (then (unreachable))
                )
                (call $msg_reply)
            )
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    test.advance_time(Duration::new(5, 0));
    let result = test.ingress(canister_id, "test", vec![]).unwrap();
    assert_eq!(result, WasmResult::Reply(vec![]));
}

#[test]
fn ic0_canister_version_returns_correct_value() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    let ctr = wasm().canister_version().reply_int64().build();

    let result = test.ingress(canister_id, "query", ctr.clone()).unwrap();
    let expected_ctr: u64 = 1;
    assert_eq!(
        result,
        WasmResult::Reply(expected_ctr.to_le_bytes().to_vec())
    );

    let result = test.ingress(canister_id, "update", ctr.clone()).unwrap();
    // Update increases the `canister_version` only AFTER the execution,
    // so the result is plus 0, as no update has been finished yet.
    let expected_ctr: u64 = 1;
    assert_eq!(
        result,
        WasmResult::Reply(expected_ctr.to_le_bytes().to_vec())
    );

    test.upgrade_canister(canister_id, vec![]).unwrap_err();
    test.upgrade_canister(canister_id, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();
    let result = test.ingress(canister_id, "update", ctr.clone()).unwrap();
    // Plus 1 for the previous ingress message.
    let expected_ctr: u64 = 2 + 1;
    assert_eq!(
        result,
        WasmResult::Reply(expected_ctr.to_le_bytes().to_vec())
    );

    test.uninstall_code(canister_id).unwrap();
    test.install_canister(canister_id, vec![]).unwrap_err();
    test.install_canister(canister_id, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();
    let result = test.ingress(canister_id, "update", ctr.clone()).unwrap();
    // Plus 2 for the previous ingress messages.
    let expected_ctr: u64 = 4 + 2;
    assert_eq!(
        result,
        WasmResult::Reply(expected_ctr.to_le_bytes().to_vec())
    );

    test.uninstall_code(canister_id).unwrap();
    let memory_allocation = NumBytes::from(1024 * 1024 * 1024);
    test.install_canister_with_allocation(
        canister_id,
        UNIVERSAL_CANISTER_WASM.to_vec(),
        None,
        Some(memory_allocation.get()),
    )
    .unwrap();
    let result = test.ingress(canister_id, "update", ctr.clone()).unwrap();
    // Plus 3 for the previous ingress messages.
    let expected_ctr: u64 = 6 + 3;
    assert_eq!(
        result,
        WasmResult::Reply(expected_ctr.to_le_bytes().to_vec())
    );

    test.reinstall_canister(canister_id, vec![]).unwrap_err();
    test.reinstall_canister(canister_id, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();
    let result = test.ingress(canister_id, "update", ctr.clone()).unwrap();
    // Plus 4 for the previous ingress messages.
    let expected_ctr: u64 = 7 + 4;
    assert_eq!(
        result,
        WasmResult::Reply(expected_ctr.to_le_bytes().to_vec())
    );

    test.update_freezing_threshold(canister_id, NumSeconds::from(1))
        .unwrap();
    let result = test.ingress(canister_id, "update", ctr.clone()).unwrap();
    // Plus 5 for the previous ingress messages.
    let expected_ctr: u64 = 8 + 5;
    assert_eq!(
        result,
        WasmResult::Reply(expected_ctr.to_le_bytes().to_vec())
    );

    test.canister_update_allocations_settings(canister_id, None, None)
        .unwrap();
    let result = test.ingress(canister_id, "update", ctr.clone()).unwrap();
    // Plus 6 for the previous ingress messages.
    let expected_ctr: u64 = 9 + 6;
    assert_eq!(
        result,
        WasmResult::Reply(expected_ctr.to_le_bytes().to_vec())
    );

    test.canister_update_allocations_settings(canister_id, Some(1000), None)
        .unwrap_err();
    let result = test.ingress(canister_id, "update", ctr.clone()).unwrap();
    // Plus 7 for the previous ingress messages.
    let expected_ctr: u64 = 9 + 7;
    assert_eq!(
        result,
        WasmResult::Reply(expected_ctr.to_le_bytes().to_vec())
    );

    // This internally transitioning to stopping and then stopped,
    // i.e. it adds 2 to canister version.
    test.stop_canister(canister_id);
    test.process_stopping_canisters();
    test.ingress(canister_id, "update", ctr.clone())
        .expect_err("The update should fail on the stopped canister.");
    test.start_canister(canister_id)
        .expect("The start canister should not fail.");
    let result = test.ingress(canister_id, "update", ctr.clone()).unwrap();
    // Plus 8 for the previous (successful) ingress messages.
    let expected_ctr: u64 = 12 + 8;
    assert_eq!(
        result,
        WasmResult::Reply(expected_ctr.to_le_bytes().to_vec())
    );

    test.set_controller(canister_id, canister_id.into())
        .unwrap();
    let result = test.ingress(canister_id, "update", ctr.clone()).unwrap();
    // Plus 9 for the previous ingress messages.
    let expected_ctr: u64 = 13 + 9;
    assert_eq!(
        result,
        WasmResult::Reply(expected_ctr.to_le_bytes().to_vec())
    );

    test.uninstall_code(canister_id)
        .expect_err("Uninstall code should fail as the controller has changed.");
    let result = test.ingress(canister_id, "update", ctr).unwrap();
    // Plus 10 for the previous ingress messages.
    let expected_ctr: u64 = 13 + 10;
    assert_eq!(
        result,
        WasmResult::Reply(expected_ctr.to_le_bytes().to_vec())
    );
}

#[test]
fn ic0_canister_version_does_not_change_on_trap_or_queries() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    let trap = wasm().trap().build();
    let ctr = wasm().canister_version().reply_int64().build();

    for _ in 0..3 {
        let result = test.ingress(canister_id, "update", trap.clone());
        assert!(result.is_err());

        let result = test
            .non_replicated_query(canister_id, "query", ctr.clone())
            .unwrap();
        // Neither the trap nor the query should change the version.
        let expected_ctr: u64 = 1;
        assert_eq!(
            result,
            WasmResult::Reply(expected_ctr.to_le_bytes().to_vec())
        );
    }
}

#[test]
fn ic0_global_timer_deactivated() {
    use ic_types::CanisterTimer;

    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();

    let set_timer = wasm().api_global_timer_set(1).reply_int64().build();
    let unset_timer = wasm().api_global_timer_set(0).reply_int64().build();

    assert_eq!(
        test.canister_state(canister_id).system_state.global_timer,
        CanisterTimer::Inactive
    );
    test.ingress(canister_id, "update", set_timer.clone())
        .unwrap();
    assert_eq!(
        test.canister_state(canister_id).system_state.global_timer,
        CanisterTimer::from_nanos_since_unix_epoch(Some(1))
    );
    test.ingress(canister_id, "update", unset_timer).unwrap();
    assert_eq!(
        test.canister_state(canister_id).system_state.global_timer,
        CanisterTimer::Inactive
    );
    test.ingress(canister_id, "update", set_timer.clone())
        .unwrap();
    assert_eq!(
        test.canister_state(canister_id).system_state.global_timer,
        CanisterTimer::from_nanos_since_unix_epoch(Some(1))
    );

    test.upgrade_canister(canister_id, vec![]).unwrap_err();
    assert_eq!(
        test.canister_state(canister_id).system_state.global_timer,
        CanisterTimer::from_nanos_since_unix_epoch(Some(1))
    );

    test.upgrade_canister(canister_id, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();
    assert_eq!(
        test.canister_state(canister_id).system_state.global_timer,
        CanisterTimer::Inactive
    );
    test.ingress(canister_id, "update", set_timer.clone())
        .unwrap();
    assert_eq!(
        test.canister_state(canister_id).system_state.global_timer,
        CanisterTimer::from_nanos_since_unix_epoch(Some(1))
    );

    test.uninstall_code(canister_id).unwrap();
    assert_eq!(
        test.canister_state(canister_id).system_state.global_timer,
        CanisterTimer::Inactive
    );

    test.install_canister(canister_id, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();
    assert_eq!(
        test.canister_state(canister_id).system_state.global_timer,
        CanisterTimer::Inactive
    );
    test.ingress(canister_id, "update", set_timer.clone())
        .unwrap();
    assert_eq!(
        test.canister_state(canister_id).system_state.global_timer,
        CanisterTimer::from_nanos_since_unix_epoch(Some(1))
    );

    test.reinstall_canister(canister_id, vec![]).unwrap_err();
    assert_eq!(
        test.canister_state(canister_id).system_state.global_timer,
        CanisterTimer::from_nanos_since_unix_epoch(Some(1))
    );

    test.reinstall_canister(canister_id, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();
    assert_eq!(
        test.canister_state(canister_id).system_state.global_timer,
        CanisterTimer::Inactive
    );
    test.ingress(canister_id, "update", set_timer).unwrap();
    assert_eq!(
        test.canister_state(canister_id).system_state.global_timer,
        CanisterTimer::from_nanos_since_unix_epoch(Some(1))
    );

    test.canister_update_allocations_settings(canister_id, None, None)
        .unwrap();
    assert_eq!(
        test.canister_state(canister_id).system_state.global_timer,
        CanisterTimer::from_nanos_since_unix_epoch(Some(1))
    );

    test.canister_update_allocations_settings(canister_id, Some(1000), None)
        .unwrap_err();
    assert_eq!(
        test.canister_state(canister_id).system_state.global_timer,
        CanisterTimer::from_nanos_since_unix_epoch(Some(1))
    );

    test.stop_canister(canister_id);
    assert_eq!(
        test.canister_state(canister_id).system_state.global_timer,
        CanisterTimer::from_nanos_since_unix_epoch(Some(1))
    );

    test.start_canister(canister_id).unwrap();
    assert_eq!(
        test.canister_state(canister_id).system_state.global_timer,
        CanisterTimer::from_nanos_since_unix_epoch(Some(1))
    );

    test.set_controller(canister_id, canister_id.into())
        .unwrap();
    assert_eq!(
        test.canister_state(canister_id).system_state.global_timer,
        CanisterTimer::from_nanos_since_unix_epoch(Some(1))
    );

    test.uninstall_code(canister_id).unwrap_err();
    assert_eq!(
        test.canister_state(canister_id).system_state.global_timer,
        CanisterTimer::from_nanos_since_unix_epoch(Some(1))
    );
}

#[test]
fn ic0_msg_arg_data_size_is_not_available_in_reject_callback() {
    let mut test = ExecutionTestBuilder::new().build();
    let caller_id = test.universal_canister().unwrap();
    let callee_id = test.universal_canister().unwrap();
    let callee = wasm().message_payload().reject().build();
    let caller = wasm()
        .inter_update(
            callee_id,
            call_args()
                .other_side(callee)
                .on_reject(wasm().msg_arg_data_size().int_to_blob().append_and_reply()),
        )
        .build();
    let err = test.ingress(caller_id, "update", caller).unwrap_err();
    assert_eq!(ErrorCode::CanisterContractViolation, err.code());
    assert!(
        err.description().contains(
            "\"ic0_msg_arg_data_size\" cannot be executed in replicated reject callback mode"
        ),
        "Unexpected error message: {}",
        err.description()
    );
}

#[test]
fn ic0_msg_reply_works() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32) (param i32))
            )
            (func (export "canister_update test")
                (call $msg_reply_data_append (i32.const 0) (i32.const 4))
                (call $msg_reply_data_append (i32.const 4) (i32.const 4))
                (call $msg_reply)
            )
            (memory 1 1)
            (data (i32.const 0) "abcdefgh")
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]).unwrap();
    assert_eq!(WasmResult::Reply(b"abcdefgh".to_vec()), result);
}

#[test]
fn ic0_msg_reply_data_append_has_no_effect_without_ic0_msg_reply() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32) (param i32))
            )
            (func (export "canister_update test")
                (call $msg_reply_data_append (i32.const 0) (i32.const 8))
            )
            (memory 1 1)
            (data (i32.const 0) "abcdefgh")
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
}

#[test]
fn ic0_msg_caller_size_and_copy_work_in_update_calls() {
    let mut test = ExecutionTestBuilder::new().build();
    let caller_id = test.universal_canister().unwrap();
    let callee_id = test.universal_canister().unwrap();
    let callee = wasm().caller().append_and_reply().build();
    let caller = wasm()
        .inter_update(callee_id, call_args().other_side(callee))
        .build();
    let result = test.ingress(caller_id, "update", caller).unwrap();
    assert_eq!(
        result,
        WasmResult::Reply(caller_id.get().as_slice().to_vec())
    );
}

#[test]
fn ic0_msg_caller_size_and_copy_work_in_query_calls() {
    let mut test = ExecutionTestBuilder::new().build();
    let caller_id = test.universal_canister().unwrap();
    let callee_id = test.universal_canister().unwrap();
    let callee = wasm().caller().append_and_reply().build();
    let caller = wasm()
        .inter_query(callee_id, call_args().other_side(callee))
        .build();
    let result = test.ingress(caller_id, "update", caller).unwrap();
    assert_eq!(
        result,
        WasmResult::Reply(caller_id.get().as_slice().to_vec())
    );
}

#[test]
fn ic0_msg_arg_data_copy_is_not_available_in_reject_callback() {
    let mut test = ExecutionTestBuilder::new().build();
    let caller_id = test.universal_canister().unwrap();
    let callee_id = test.universal_canister().unwrap();
    let callee = wasm().message_payload().reject().build();
    let caller = wasm()
        .inter_update(
            callee_id,
            call_args()
                .other_side(callee)
                .on_reject(wasm().msg_arg_data_copy(0, 1).append_and_reply()),
        )
        .build();
    let err = test.ingress(caller_id, "update", caller).unwrap_err();
    assert_eq!(ErrorCode::CanisterContractViolation, err.code());
    assert!(
        err.description().contains(
            "\"ic0_msg_arg_data_copy\" cannot be executed in replicated reject callback mode"
        ),
        "Unexpected error message: {}",
        err.description()
    );
}

#[test]
fn ic0_msg_arg_data_copy_works() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32))
            )
            (import "ic0" "msg_arg_data_copy"
                (func $msg_arg_data_copy (param i32 i32 i32))
            )
            (func (export "canister_update test")
                    (call $msg_arg_data_copy
                        (i32.const 4)     ;; heap dst = 4
                        (i32.const 0)     ;; payload offset = 0
                        (i32.const 4))    ;; length = 4
                    (call $msg_reply_data_append
                        (i32.const 0)     ;; heap offset = 0
                        (i32.const 8))    ;; length = 8
                    (call $msg_reply)
            )
            (memory 1 1)
            (data (i32.const 0) "xxxxabcd")
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let payload = vec![121, 121, 121, 121];
    let result = test.ingress(canister_id, "test", payload).unwrap();
    assert_eq!(WasmResult::Reply(b"xxxxyyyy".to_vec()), result);
}

#[test]
fn ic0_msg_reject_works() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "msg_reject"
                (func $ic0_msg_reject (param i32) (param i32))
            )
            (func (export "canister_update test")
                (call $ic0_msg_reject (i32.const 0) (i32.const 6))
            )
            (memory 1 1)
            (data (i32.const 0) "panic!")
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]).unwrap();
    assert_eq!(WasmResult::Reject("panic!".to_string()), result);
}

#[test]
fn wasm64_active_data_segments() {
    let mut test = ExecutionTestBuilder::new().with_wasm64().build();
    let wat = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (func (export "canister_update test")
                (if (i64.ne
                         (i64.load8_u (i64.const 0))
                         (i64.const 112) ;; p
                    )
                    (then (unreachable))
                )
                (if (i64.ne
                         (i64.load8_u (i64.const 1))
                         (i64.const 0)
                    )
                    (then (unreachable))
                )
                (if (i64.ne
                         (i64.load8_u (i64.const 2))
                         (i64.const 97) ;; a
                    )
                    (then (unreachable))
                )
                (call $msg_reply)
            )
            (memory i64 1 1)
            (data (i64.const 0) "p")
            (data (i64.const 2) "a")
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]).unwrap();
    assert_eq!(WasmResult::Reply(vec![]), result);
}

#[test]
fn ic0_msg_caller_size_works_in_reply_callback() {
    let mut test = ExecutionTestBuilder::new().build();
    let caller_id = test.universal_canister().unwrap();
    let callee_id = test.universal_canister().unwrap();
    let callee = wasm().message_payload().reply().build();
    let caller = wasm()
        .inter_update(
            callee_id,
            call_args()
                .other_side(callee)
                .on_reply(wasm().msg_caller_size().int_to_blob().append_and_reply()),
        )
        .build();
    let result = test.ingress(caller_id, "update", caller).unwrap();
    assert_eq!(
        WasmResult::Reply(
            (test.user_id().get().to_vec().len() as u32)
                .to_le_bytes()
                .to_vec()
        ),
        result
    );
}

#[test]
fn ic0_msg_caller_copy_works_in_reply_callback() {
    let mut test = ExecutionTestBuilder::new().build();
    let caller_id = test.universal_canister().unwrap();
    let callee_id = test.universal_canister().unwrap();
    let callee = wasm().message_payload().reply().build();
    let caller = wasm()
        .inter_update(
            callee_id,
            call_args().other_side(callee).on_reply(
                wasm()
                    .msg_caller_copy(0, test.user_id().get().to_vec().len() as u32)
                    .append_and_reply(),
            ),
        )
        .build();
    let result = test.ingress(caller_id, "update", caller).unwrap();
    assert_eq!(WasmResult::Reply(test.user_id().get().to_vec()), result);
}

#[test]
fn ic0_msg_caller_size_works_in_reject_callback() {
    let mut test = ExecutionTestBuilder::new().build();
    let caller_id = test.universal_canister().unwrap();
    let callee_id = test.universal_canister().unwrap();
    let callee = wasm().message_payload().reject().build();
    let caller = wasm()
        .inter_update(
            callee_id,
            call_args()
                .other_side(callee)
                .on_reject(wasm().msg_caller_size().int_to_blob().append_and_reply()),
        )
        .build();
    let result = test.ingress(caller_id, "update", caller).unwrap();
    assert_eq!(
        WasmResult::Reply(
            (test.user_id().get().to_vec().len() as u32)
                .to_le_bytes()
                .to_vec()
        ),
        result
    );
}

#[test]
fn ic0_msg_caller_copy_works_in_reject_callback() {
    let mut test = ExecutionTestBuilder::new().build();
    let caller_id = test.universal_canister().unwrap();
    let callee_id = test.universal_canister().unwrap();
    let callee = wasm().message_payload().reject().build();
    let caller = wasm()
        .inter_update(
            callee_id,
            call_args().other_side(callee).on_reject(
                wasm()
                    .msg_caller_copy(0, test.user_id().get().to_vec().len() as u32)
                    .append_and_reply(),
            ),
        )
        .build();
    let result = test.ingress(caller_id, "update", caller).unwrap();
    assert_eq!(WasmResult::Reply(test.user_id().get().to_vec()), result);
}

#[test]
fn ic0_msg_caller_size_works_in_cleanup_callback() {
    let mut test = ExecutionTestBuilder::new().build();
    let caller_id = test.universal_canister().unwrap();
    let callee_id = test.universal_canister().unwrap();
    let callee = wasm().message_payload().reply().build();
    let caller = wasm()
        .inter_update(
            callee_id,
            call_args()
                .other_side(callee)
                .on_reply(wasm().trap())
                .on_cleanup(
                    wasm()
                        .msg_caller_size()
                        .int_to_blob()
                        .set_global_data_from_stack(),
                ),
        )
        .build();

    // Trigger the cleanup so the data is stored on the heap.
    let _ = test.ingress(caller_id, "update", caller).unwrap_err();

    // Check the data on the heap matches what we expect.
    let result = test
        .ingress(
            caller_id,
            "update",
            wasm().get_global_data().append_and_reply().build(),
        )
        .unwrap();
    assert_eq!(
        WasmResult::Reply(
            (test.user_id().get().to_vec().len() as u32)
                .to_le_bytes()
                .to_vec()
        ),
        result
    );
}

#[test]
fn ic0_msg_caller_copy_works_in_cleanup_callback() {
    let mut test = ExecutionTestBuilder::new().build();
    let caller_id = test.universal_canister().unwrap();
    let callee_id = test.universal_canister().unwrap();
    let callee = wasm().message_payload().reply().build();
    let caller = wasm()
        .inter_update(
            callee_id,
            call_args()
                .other_side(callee)
                .on_reply(wasm().trap())
                .on_cleanup(
                    wasm()
                        .msg_caller_copy(0, test.user_id().get().to_vec().len() as u32)
                        .set_global_data_from_stack(),
                ),
        )
        .build();

    // Trigger the cleanup so the data is stored on the heap.
    let _ = test.ingress(caller_id, "update", caller).unwrap_err();

    // Check the data on the heap matches what we expect.
    let result = test
        .ingress(
            caller_id,
            "update",
            wasm().get_global_data().append_and_reply().build(),
        )
        .unwrap();
    assert_eq!(WasmResult::Reply(test.user_id().get().to_vec()), result);
}

#[test]
fn ic0_msg_caller_size_works_in_heartbeat() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    let set_heartbeat = wasm()
        .set_heartbeat(
            wasm()
                .msg_caller_size()
                .int_to_blob()
                .set_global_data_from_stack()
                .build(),
        )
        .reply()
        .build();

    let _ = test.ingress(canister_id, "update", set_heartbeat).unwrap();
    test.canister_task(canister_id, CanisterTask::Heartbeat);
    let result = test
        .ingress(
            canister_id,
            "update",
            wasm().get_global_data().append_and_reply().build(),
        )
        .unwrap();
    assert_eq!(
        WasmResult::Reply(
            (ic_management_canister_types::IC_00.get().to_vec().len() as u32)
                .to_le_bytes()
                .to_vec()
        ),
        result
    );
}

#[test]
fn ic0_msg_caller_copy_works_in_heartbeat() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    let set_heartbeat = wasm()
        .set_heartbeat(
            wasm()
                .msg_caller_copy(
                    0,
                    ic_management_canister_types::IC_00.get().to_vec().len() as u32,
                )
                .set_global_data_from_stack()
                .build(),
        )
        .reply()
        .build();

    let _ = test.ingress(canister_id, "update", set_heartbeat).unwrap();
    test.canister_task(canister_id, CanisterTask::Heartbeat);
    let result = test
        .ingress(
            canister_id,
            "update",
            wasm().get_global_data().append_and_reply().build(),
        )
        .unwrap();
    assert_eq!(
        WasmResult::Reply(ic_management_canister_types::IC_00.get().to_vec()),
        result
    );
}

#[test]
fn ic0_msg_caller_size_works_in_global_timer() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    let set_timer = wasm()
        .set_global_timer_method(
            wasm()
                .msg_caller_size()
                .int_to_blob()
                .set_global_data_from_stack()
                .build(),
        )
        .reply()
        .build();

    let _ = test.ingress(canister_id, "update", set_timer).unwrap();
    test.canister_task(canister_id, CanisterTask::GlobalTimer);
    let result = test
        .ingress(
            canister_id,
            "update",
            wasm().get_global_data().append_and_reply().build(),
        )
        .unwrap();
    assert_eq!(
        WasmResult::Reply(
            (ic_management_canister_types::IC_00.get().to_vec().len() as u32)
                .to_le_bytes()
                .to_vec()
        ),
        result
    );
}

#[test]
fn ic0_msg_caller_copy_works_in_global_timer() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    let set_timer = wasm()
        .set_global_timer_method(
            wasm()
                .msg_caller_copy(
                    0,
                    ic_management_canister_types::IC_00.get().to_vec().len() as u32,
                )
                .set_global_data_from_stack()
                .build(),
        )
        .reply()
        .build();

    let _ = test.ingress(canister_id, "update", set_timer).unwrap();
    test.canister_task(canister_id, CanisterTask::GlobalTimer);
    let result = test
        .ingress(
            canister_id,
            "update",
            wasm().get_global_data().append_and_reply().build(),
        )
        .unwrap();
    assert_eq!(
        WasmResult::Reply(ic_management_canister_types::IC_00.get().to_vec()),
        result
    );
}

#[test]
fn ic0_msg_reject_fails_if_called_twice() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "msg_reject"
                (func $ic0_msg_reject (param i32) (param i32))
            )
            (func (export "canister_update test")
                (call $ic0_msg_reject (i32.const 0) (i32.const 6))
                (call $ic0_msg_reject (i32.const 0) (i32.const 6))
            )
            (memory 1 1)
            (data (i32.const 0) "panic!")
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterContractViolation, err.code());
    assert!(err
        .description()
        .contains("ic0.msg_reject: the call is already replied"));
}

#[test]
fn some_ic0_calls_fail_if_called_with_huge_size() {
    fn test(syscall: &str) {
        let mut test = ExecutionTestBuilder::new()
            // 3T Cycles should be more than enough for a single ingress call.
            .with_initial_canister_cycles(3_000_000_000_000)
            .build();
        let wat = format!(
            r#"
        (module
            (import "ic0" "{syscall}"
                (func $ic0_{syscall} (param i32) (param i32))
            )
            (func (export "canister_update test")
                (call $ic0_{syscall} (i32.const 0) (i32.const {SIZE}))
            )
            (memory 1 1)
        )"#,
            SIZE = u32::MAX
        );
        let canister_id = test.canister_from_wat(wat).unwrap();

        let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
        // It must be neither a contract violation nor timeout.
        assert_eq!(ErrorCode::CanisterInstructionLimitExceeded, err.code());
    }
    for syscall in ["msg_reject", "call_data_append", "msg_reply_data_append"] {
        test(syscall);
    }
}

#[test]
fn ic0_msg_reject_code_works() {
    let mut test = ExecutionTestBuilder::new().build();
    let caller_id = test.universal_canister().unwrap();
    let callee_id = test.universal_canister().unwrap();
    let callee = wasm().message_payload().reject().build();
    let caller = wasm()
        .inter_update(
            callee_id,
            call_args()
                .other_side(callee)
                .on_reject(wasm().reject_code().int_to_blob().append_and_reply()),
        )
        .build();
    let result = test.ingress(caller_id, "update", caller).unwrap();
    assert_eq!(
        result,
        WasmResult::Reply(vec![RejectCode::CanisterReject as u8, 0, 0, 0])
    );
}

#[test]
fn ic0_msg_reject_code_is_not_available_outside_reject_callback() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    let payload = wasm()
        .reject_code()
        .int_to_blob()
        .append_and_reply()
        .build();
    let err = test.ingress(canister_id, "update", payload).unwrap_err();
    assert_eq!(ErrorCode::CanisterContractViolation, err.code());
    assert!(
        err.description()
            .contains("\"ic0_msg_reject_code\" cannot be executed in update mode"),
        "Unexpected error message: {}",
        err.description()
    );
}

#[test]
fn ic0_msg_reject_msg_size_and_copy_work() {
    let mut test = ExecutionTestBuilder::new().build();
    let caller_id = test.universal_canister().unwrap();
    let callee_id = test.universal_canister().unwrap();
    let callee = wasm().message_payload().reject().build();
    let caller = wasm()
        .inter_update(
            callee_id,
            call_args()
                .other_side(callee.clone())
                .on_reject(wasm().reject_message().append_and_reply()),
        )
        .build();
    let result = test.ingress(caller_id, "update", caller).unwrap();
    assert_eq!(result, WasmResult::Reply(callee));
}

#[test]
fn ic0_msg_reject_msg_size_is_not_available_outside_reject_callback() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    let payload = wasm()
        .msg_reject_msg_size()
        .int_to_blob()
        .append_and_reply()
        .build();
    let err = test.ingress(canister_id, "update", payload).unwrap_err();
    assert_eq!(ErrorCode::CanisterContractViolation, err.code());
    assert!(
        err.description()
            .contains("\"ic0_msg_reject_msg_size\" cannot be executed in update mode"),
        "Unexpected error message: {}",
        err.description()
    );
}

#[test]
fn ic0_msg_reject_msg_copy_is_not_available_outside_reject_callback() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    let payload = wasm().msg_reject_msg_copy(0, 1).append_and_reply().build();
    let err = test.ingress(canister_id, "update", payload).unwrap_err();
    assert_eq!(ErrorCode::CanisterContractViolation, err.code());
    assert!(
        err.description()
            .contains("\"ic0_msg_reject_msg_copy\" cannot be executed in update mode"),
        "Unexpected error message: {}",
        err.description()
    );
}

#[test]
fn ic0_msg_reject_msg_copy_called_with_length_that_exceeds_message_length() {
    let mut test = ExecutionTestBuilder::new().build();
    let caller_id = test.universal_canister().unwrap();
    let callee_id = test.universal_canister().unwrap();
    let callee = wasm().push_bytes("error".as_bytes()).reject().build();
    let caller = wasm()
        .inter_update(
            callee_id,
            call_args()
                .other_side(callee)
                .on_reject(wasm().msg_reject_msg_copy(0, 8).append_and_reply()),
        )
        .build();
    let err = test.ingress(caller_id, "update", caller).unwrap_err();
    assert_eq!(ErrorCode::CanisterContractViolation, err.code());
    assert!(
        err.description()
            .contains("ic0.msg_reject_msg_copy msg: src=0 + length=8 exceeds the slice size=5"),
        "Unexpected error message: {}",
        err.description()
    );
}

#[test]
fn ic0_canister_self_size_works() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "canister_self_size"
                (func $canister_self_size (result i32))
            )
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32 i32)))
            (func (export "canister_update test")
                ;; heap[0] = $canister_self_size()
                (i32.store (i32.const 0) (call $canister_self_size))
                ;; return heap[0]
                (call $msg_reply_data_append (i32.const 0) (i32.const 1))
                (call $msg_reply)
            )
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]).unwrap();
    assert_eq!(WasmResult::Reply(vec![10]), result);
}
#[test]
fn ic0_canister_self_copy_works() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "canister_self_copy"
                (func $canister_self_copy (param i32 i32 i32))
            )
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32 i32)))
            (func (export "canister_update test")
                ;; heap[0..4] = canister_id_bytes[0..4]
                (call $canister_self_copy (i32.const 0) (i32.const 0) (i32.const 4))
                ;; heap[4..10] = canister_id_bytes[4..8]
                (call $canister_self_copy (i32.const 4) (i32.const 4) (i32.const 6))
                ;; return heap[0..10]
                (call $msg_reply_data_append (i32.const 0) (i32.const 10))
                (call $msg_reply)
            )
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]).unwrap();
    assert_eq!(WasmResult::Reply(canister_id.get().into_vec()), result);
}

#[test]
fn ic0_call_has_no_effect_on_trap() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "call_new"
              (func $ic0_call_new
                (param i32 i32)
                (param $method_name_src i32)    (param $method_name_len i32)
                (param $reply_fun i32)          (param $reply_env i32)
                (param $reject_fun i32)         (param $reject_env i32)
            ))
            (import "ic0" "call_data_append" (func $ic0_call_data_append (param $src i32) (param $size i32)))
            (import "ic0" "call_perform" (func $ic0_call_perform (result i32)))
            (import "ic0" "trap" (func $ic_trap (param i32) (param i32)))
            (func (export "canister_update test")
                (call $ic0_call_new
                    (i32.const 100) (i32.const 10)  ;; callee canister id = 777
                    (i32.const 0) (i32.const 18)    ;; refers to "some_remote_method" on the heap
                    (i32.const 11) (i32.const 22)   ;; fictive on_reply closure
                    (i32.const 33) (i32.const 44))  ;; fictive on_reject closure
                (call $ic0_call_data_append
                    (i32.const 19) (i32.const 3))   ;; refers to "XYZ" on the heap
                (call $ic0_call_perform)
                drop
                (call $ic_trap (i32.const 0) (i32.const 18))
            )
            (memory 1)
            (data (i32.const 0) "some_remote_method XYZ")
            (data (i32.const 100) "\09\03\00\00\00\00\00\00\ff\01")
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterCalledTrap, err.code());
    assert_eq!(0, test.xnet_messages().len());
}

#[test]
fn ic0_call_perform_has_no_effect_on_trap() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "call_new"
                (func $ic0_call_new
                    (param i32 i32)
                    (param $method_name_src i32)    (param $method_name_len i32)
                    (param $reply_fun i32)          (param $reply_env i32)
                    (param $reject_fun i32)         (param $reject_env i32)
                )
            )
            (import "ic0" "call_data_append"
                (func $ic0_call_data_append (param $src i32) (param $size i32))
            )
            (import "ic0" "call_perform" (func $ic0_call_perform (result i32)))
            (import "ic0" "trap" (func $ic_trap (param i32) (param i32)))
            (func (export "canister_update test")
                (call $ic0_call_new
                    (i32.const 100) (i32.const 10)  ;; callee canister id = 777
                    (i32.const 0) (i32.const 18)    ;; refers to "some_remote_method" on the heap
                    (i32.const 11) (i32.const 22)   ;; fictive on_reply closure
                    (i32.const 33) (i32.const 44)   ;; fictive on_reject closure
                )
                (call $ic0_call_data_append
                    (i32.const 19) (i32.const 3)    ;; refers to "XYZ" on the heap
                )
                (drop (call $ic0_call_perform))
                (call $ic_trap (i32.const 0) (i32.const 18))
            )
            (memory 1)
            (data (i32.const 0) "some_remote_method XYZ")
            (data (i32.const 100) "\09\03\00\00\00\00\00\00\ff\01")
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterCalledTrap, err.code());
    assert_eq!(0, test.xnet_messages().len());
}

#[test]
fn ic0_call_cycles_add_deducts_cycles() {
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(MAX_NUM_INSTRUCTIONS.get())
        .build();
    let wat = r#"
        (module
            (import "ic0" "call_new"
                (func $ic0_call_new
                    (param i32 i32)
                    (param $method_name_src i32)    (param $method_name_len i32)
                    (param $reply_fun i32)          (param $reply_env i32)
                    (param $reject_fun i32)         (param $reject_env i32)
                )
            )
            (import "ic0" "call_cycles_add" (func $ic0_call_cycles_add (param i64)))
            (import "ic0" "call_perform" (func $ic0_call_perform (result i32)))
            (func (export "canister_update test")
                (call $ic0_call_new
                    (i32.const 100) (i32.const 10)  ;; callee canister id = 777
                    (i32.const 0) (i32.const 18)    ;; refers to "some_remote_method" on the heap
                    (i32.const 11) (i32.const 22)   ;; fictive on_reply closure
                    (i32.const 33) (i32.const 44)   ;; fictive on_reject closure
                )
                (call $ic0_call_cycles_add
                    (i64.const 10000000000)         ;; amount of cycles used to be transferred
                )
                (call $ic0_call_perform)
                drop
            )
            (memory 1)
            (data (i32.const 0) "some_remote_method XYZ")
            (data (i32.const 100) "\09\03\00\00\00\00\00\00\ff\01")
        )"#;
    let initial_cycles = Cycles::new(100_000_000_000);
    let canister_id = test
        .canister_from_cycles_and_wat(initial_cycles, wat)
        .unwrap();
    let ingress_status = test.ingress_raw(canister_id, "test", vec![]).1;
    let ingress_state = match ingress_status {
        IngressStatus::Known { state, .. } => state,
        IngressStatus::Unknown => unreachable!("Expected known ingress status"),
    };
    assert_eq!(IngressState::Processing, ingress_state);
    assert_eq!(1, test.xnet_messages().len());
    let mgr = test.cycles_account_manager();
    let messaging_fee = mgr.xnet_call_performed_fee(test.subnet_size())
        + mgr.xnet_call_bytes_transmitted_fee(
            test.xnet_messages()[0].payload_size_bytes(),
            test.subnet_size(),
        )
        + mgr.xnet_call_bytes_transmitted_fee(
            MAX_INTER_CANISTER_PAYLOAD_IN_BYTES,
            test.subnet_size(),
        )
        + mgr.execution_cost(MAX_NUM_INSTRUCTIONS, test.subnet_size());
    let transferred_cycles = Cycles::new(10_000_000_000);
    assert_eq!(
        initial_cycles - messaging_fee - transferred_cycles - test.execution_cost(),
        test.canister_state(canister_id).system_state.balance(),
    );
}

#[test]
fn ic0_call_cycles_add_has_no_effect_without_ic0_call_perform() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "call_new"
                (func $ic0_call_new
                    (param i32 i32)
                    (param $method_name_src i32) (param $method_name_len i32)
                    (param $reply_fun i32)       (param $reply_env i32)
                    (param $reject_fun i32)      (param $reject_env i32)
                )
            )
            (import "ic0" "call_cycles_add" (func $call_cycles_add (param i64)))
            (func (export "canister_update test")
                (call $ic0_call_new
                    (i32.const 100) (i32.const 10)  ;; callee canister id = 777
                    (i32.const 0) (i32.const 18)    ;; refers to "some_remote_method" on the heap
                    (i32.const 11) (i32.const 22)   ;; fictive on_reply closure
                    (i32.const 33) (i32.const 44)   ;; fictive on_reject closure
                )
                (call $call_cycles_add
                    (i64.const 10000000000)         ;; amount of cycles used to be transferred
                )
            )
            (memory 1)
            (data (i32.const 0) "some_remote_method XYZ")
            (data (i32.const 100) "\09\03\00\00\00\00\00\00\ff\01")
        )"#;

    let initial_cycles = Cycles::new(100_000_000_000);
    let canister_id = test
        .canister_from_cycles_and_wat(initial_cycles, wat)
        .unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
    assert_eq!(0, test.xnet_messages().len());
    // Cycles deducted by `ic0.call_cycles_add` are refunded.
    assert_eq!(
        initial_cycles - test.execution_cost(),
        test.canister_state(canister_id).system_state.balance(),
    );
}

#[test]
fn ic0_call_cycles_add128_up_to_deducts_cycles() {
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(MAX_NUM_INSTRUCTIONS.get())
        .build();
    let wat = r#"
        (module
            (import "ic0" "call_new"
                (func $ic0_call_new
                    (param i32 i32)
                    (param $method_name_src i32)    (param $method_name_len i32)
                    (param $reply_fun i32)          (param $reply_env i32)
                    (param $reject_fun i32)         (param $reject_env i32)
                )
            )
            (import "ic0" "call_cycles_add128_up_to" (func $ic0_call_cycles_add128_up_to (param i64 i64 i32)))
            (import "ic0" "call_perform" (func $ic0_call_perform (result i32)))
            (func (export "canister_update test")
                (call $ic0_call_new
                    (i32.const 100) (i32.const 10)  ;; callee canister id = 777
                    (i32.const 0) (i32.const 18)    ;; refers to "some_remote_method" on the heap
                    (i32.const 11) (i32.const 22)   ;; fictive on_reply closure
                    (i32.const 33) (i32.const 44)   ;; fictive on_reject closure
                )
                (call $ic0_call_cycles_add128_up_to
                    (i64.const 0)                       ;; amount of cycles used to be added - high
                    (i64.const 10000000000)             ;; amount of cycles used to be added - low
                    (i32.const 200)                     ;; where to write amount of cycles added
                )
                (call $ic0_call_perform)
                drop
            )
            (memory 1)
            (data (i32.const 0) "some_remote_method XYZ")
            (data (i32.const 100) "\09\03\00\00\00\00\00\00\ff\01")
        )"#;
    let initial_cycles = Cycles::new(100_000_000_000);
    let canister_id = test
        .canister_from_cycles_and_wat(initial_cycles, wat)
        .unwrap();
    let ingress_status = test.ingress_raw(canister_id, "test", vec![]).1;
    let ingress_state = match ingress_status {
        IngressStatus::Known { state, .. } => state,
        IngressStatus::Unknown => unreachable!("Expected known ingress status"),
    };
    assert_eq!(IngressState::Processing, ingress_state);
    assert_eq!(1, test.xnet_messages().len());
    let mgr = test.cycles_account_manager();
    let messaging_fee = mgr.xnet_call_performed_fee(test.subnet_size())
        + mgr.xnet_call_bytes_transmitted_fee(
            test.xnet_messages()[0].payload_size_bytes(),
            test.subnet_size(),
        )
        + mgr.xnet_call_bytes_transmitted_fee(
            MAX_INTER_CANISTER_PAYLOAD_IN_BYTES,
            test.subnet_size(),
        )
        + mgr.execution_cost(MAX_NUM_INSTRUCTIONS, test.subnet_size());
    let transferred_cycles = Cycles::new(10_000_000_000);
    assert_eq!(
        initial_cycles - messaging_fee - transferred_cycles - test.execution_cost(),
        test.canister_state(canister_id).system_state.balance(),
    );
}

#[test]
fn ic0_call_cycles_add128_up_to_limit_allows_performing_call() {
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(MAX_NUM_INSTRUCTIONS.get())
        .build();
    let wat = r#"
        (module
            (import "ic0" "call_new"
                (func $ic0_call_new
                    (param i32 i32)
                    (param $method_name_src i32)    (param $method_name_len i32)
                    (param $reply_fun i32)          (param $reply_env i32)
                    (param $reject_fun i32)         (param $reject_env i32)
                )
            )
            (import "ic0" "call_cycles_add128_up_to" (func $ic0_call_cycles_add128_up_to (param i64 i64 i32)))
            (import "ic0" "call_perform" (func $ic0_call_perform (result i32)))
            (import "ic0" "msg_reply_data_append" (func $msg_reply_data_append (param i32 i32)))
            (import "ic0" "msg_reply" (func $msg_reply))
            (func (export "canister_update test")
                (call $ic0_call_new
                    (i32.const 100) (i32.const 10)  ;; callee canister id = 777
                    (i32.const 0) (i32.const 18)    ;; refers to "some_remote_method" on the heap
                    (i32.const 11) (i32.const 22)   ;; fictive on_reply closure
                    (i32.const 33) (i32.const 44)   ;; fictive on_reject closure
                )
                (call $ic0_call_cycles_add128_up_to
                (i64.const 999000000000)            ;; amount of cycles used to be added - high
                (i64.const 0)                       ;; amount of cycles used to be added - low
                (i32.const 200)                     ;; where to write amount of cycles added
                )
                (call $ic0_call_perform)
                drop
                ;; return number of cycles attached
                (call $msg_reply_data_append (i32.const 200) (i32.const 16))
                (call $msg_reply)
            )
            (memory 1)
            (data (i32.const 0) "some_remote_method XYZ")
            (data (i32.const 100) "\09\03\00\00\00\00\00\00\ff\01")
        )"#;
    let initial_cycles = Cycles::new(100_000_000_000);
    let canister_id = test
        .canister_from_cycles_and_wat(initial_cycles, wat)
        .unwrap();
    let WasmResult::Reply(reply_bytes) = test.ingress(canister_id, "test", vec![]).unwrap() else {
        panic!("bad WasmResult")
    };
    let transferred_cycles =
        u128::from_le_bytes(reply_bytes.try_into().expect("bad number of reply bytes"));
    assert_eq!(1, test.xnet_messages().len());
    let mgr = test.cycles_account_manager();
    let messaging_fee = mgr.xnet_call_performed_fee(test.subnet_size())
        + mgr.xnet_call_bytes_transmitted_fee(
            test.xnet_messages()[0].payload_size_bytes(),
            test.subnet_size(),
        )
        + mgr.xnet_call_bytes_transmitted_fee(
            MAX_INTER_CANISTER_PAYLOAD_IN_BYTES,
            test.subnet_size(),
        )
        + mgr.execution_cost(MAX_NUM_INSTRUCTIONS, test.subnet_size());
    assert_eq!(
        initial_cycles - messaging_fee - transferred_cycles.into() - test.execution_cost(),
        test.canister_state(canister_id).system_state.balance(),
    );
}

#[test]
fn ic0_call_cycles_add128_up_to_has_no_effect_without_ic0_call_perform() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "call_new"
                (func $ic0_call_new
                    (param i32 i32)
                    (param $method_name_src i32) (param $method_name_len i32)
                    (param $reply_fun i32)       (param $reply_env i32)
                    (param $reject_fun i32)      (param $reject_env i32)
                )
            )
            (import "ic0" "call_cycles_add128_up_to" (func $call_cycles_add128_up_to (param i64 i64 i32)))
            (func (export "canister_update test")
                (call $ic0_call_new
                    (i32.const 100) (i32.const 10)  ;; callee canister id = 777
                    (i32.const 0) (i32.const 18)    ;; refers to "some_remote_method" on the heap
                    (i32.const 11) (i32.const 22)   ;; fictive on_reply closure
                    (i32.const 33) (i32.const 44)   ;; fictive on_reject closure
                )
                (call $call_cycles_add128_up_to
                    (i64.const 0)                   ;; amount of cycles used to be added - high
                    (i64.const 10000000000)         ;; amount of cycles used to be added - low
                    (i32.const 200)                 ;; where to write amount of cycles added
                )
            )
            (memory 1)
            (data (i32.const 0) "some_remote_method XYZ")
            (data (i32.const 100) "\09\03\00\00\00\00\00\00\ff\01")
        )"#;

    let initial_cycles = Cycles::new(100_000_000_000);
    let canister_id = test
        .canister_from_cycles_and_wat(initial_cycles, wat)
        .unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
    assert_eq!(0, test.xnet_messages().len());
    // Cycles deducted by `ic0.call_cycles_add128_up_to` are refunded.
    assert_eq!(
        initial_cycles - test.execution_cost(),
        test.canister_state(canister_id).system_state.balance(),
    );
}

const MINT_CYCLES: &str = r#"
    (module
        (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32) (param i32))
        )
        (import "ic0" "mint_cycles"
            (func $mint_cycles (param i64) (result i64))
        )
        (import "ic0" "msg_reply" (func $ic0_msg_reply))

        (func (export "canister_update test")
            (i64.store
                ;; store at the beginning of the heap
                (i32.const 0) ;; store at the beginning of the heap
                (call $mint_cycles (i64.const 10000000000))
            )
            (call $msg_reply_data_append (i32.const 0) (i32.const 8))
            (call $ic0_msg_reply)
        )
        (memory 1 1)
    )"#;

#[test]
fn ic0_mint_cycles_fails_on_application_subnet() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.canister_from_wat(MINT_CYCLES).unwrap();
    let initial_cycles = test.canister_state(canister_id).system_state.balance();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterContractViolation, err.code());
    assert!(err
        .description()
        .contains("ic0.mint_cycles cannot be executed"));
    let canister_state = test.canister_state(canister_id);
    assert_eq!(0, canister_state.system_state.queues().output_queues_len());
    assert_balance_equals(
        initial_cycles,
        canister_state.system_state.balance(),
        BALANCE_EPSILON,
    );
}

#[test]
fn ic0_mint_cycles_fails_on_system_subnet_non_cmc() {
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_type(SubnetType::System)
        .build();
    let canister_id = test.canister_from_wat(MINT_CYCLES).unwrap();
    let initial_cycles = test.canister_state(canister_id).system_state.balance();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterContractViolation, err.code());
    assert!(err
        .description()
        .contains("ic0.mint_cycles cannot be executed"));
    let canister_state = test.canister_state(canister_id);
    assert_eq!(0, canister_state.system_state.queues().output_queues_len());
    assert_balance_equals(
        initial_cycles,
        canister_state.system_state.balance(),
        BALANCE_EPSILON,
    );
}

#[test]
fn ic0_mint_cycles_succeeds_on_cmc() {
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_type(SubnetType::System)
        .build();
    let mut canister_id = test.canister_from_wat(MINT_CYCLES).unwrap();
    // This loop should finish after four iterations.
    while canister_id != CYCLES_MINTING_CANISTER_ID {
        canister_id = test.canister_from_wat(MINT_CYCLES).unwrap();
    }
    let initial_cycles = test.canister_state(canister_id).system_state.balance();
    let result = test.ingress(canister_id, "test", vec![]).unwrap();
    // ic0_mint() returns the minted amount: hex(10_000_000_000) = 0x2_54_0b_e4_00.
    assert_eq!(WasmResult::Reply(vec![0, 228, 11, 84, 2, 0, 0, 0]), result);
    let canister_state = test.canister_state(canister_id);
    assert_eq!(0, canister_state.system_state.queues().output_queues_len());
    assert_balance_equals(
        initial_cycles + Cycles::new(10_000_000_000),
        canister_state.system_state.balance(),
        BALANCE_EPSILON,
    );
}

#[test]
fn ic0_call_enqueues_request() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "call_new"
              (func $ic0_call_new
                (param i32 i32)
                (param $method_name_src i32)    (param $method_name_len i32)
                (param $reply_fun i32)          (param $reply_env i32)
                (param $reject_fun i32)         (param $reject_env i32)
            ))
            (import "ic0" "call_data_append" (func $ic0_call_data_append (param $src i32) (param $size i32)))
            (import "ic0" "call_perform" (func $ic0_call_perform (result i32)))

            (import "ic0" "msg_reply" (func $msg_reply))
            (func (export "canister_update test")
                (call $ic0_call_new
                    (i32.const 100) (i32.const 10)  ;; callee canister id = 777
                    (i32.const 0) (i32.const 18)    ;; refers to "some_remote_method" on the heap
                    (i32.const 11) (i32.const 22)   ;; fictive on_reply closure
                    (i32.const 33) (i32.const 44))  ;; fictive on_reject closure
                (call $ic0_call_data_append
                    (i32.const 19) (i32.const 3))   ;; refers to "XYZ" on the heap
                (call $ic0_call_perform)
                drop
                (call $msg_reply)
            )
            (memory 1 1)
            (data (i32.const 0) "some_remote_method XYZ")
            (data (i32.const 100) "\09\03\00\00\00\00\00\00\ff\01")
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]).unwrap();
    assert_eq!(WasmResult::Reply(vec![]), result);
    let canister_state = test.canister_state(canister_id);
    assert_eq!(1, canister_state.system_state.queues().output_queues_len());
}

#[test]
fn ic0_call_perform_enqueues_request() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "call_new"
                (func $ic0_call_new
                    (param i32 i32)
                    (param $method_name_src i32)    (param $method_name_len i32)
                    (param $reply_fun i32)          (param $reply_env i32)
                    (param $reject_fun i32)         (param $reject_env i32)
                )
            )
            (import "ic0" "call_data_append"
                (func $ic0_call_data_append (param $src i32) (param $size i32))
            )
            (import "ic0" "call_perform" (func $ic0_call_perform (result i32)))
            (import "ic0" "msg_reply" (func $msg_reply))
            (func (export "canister_update test")
                (call $ic0_call_new
                    (i32.const 100) (i32.const 10)  ;; callee canister id = 777
                    (i32.const 0) (i32.const 18)    ;; refers to "some_remote_method" on the heap
                    (i32.const 11) (i32.const 22)   ;; fictive on_reply closure
                    (i32.const 33) (i32.const 44)   ;; fictive on_reject closure
                )
                (call $ic0_call_data_append
                    (i32.const 19) (i32.const 3)    ;; refers to "XYZ" on the heap
                )
                (call $ic0_call_perform)
                drop
                (call $msg_reply)
            )
            (memory 1 1)
            (data (i32.const 0) "some_remote_method XYZ")
            (data (i32.const 100) "\09\03\00\00\00\00\00\00\ff\01")
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]).unwrap();
    assert_eq!(WasmResult::Reply(vec![]), result);
    let canister_state = test.canister_state(canister_id);
    assert_eq!(1, canister_state.system_state.queues().output_queues_len());
}

#[test]
fn wasm64_ic0_call_perform_enqueues_request() {
    let mut test = ExecutionTestBuilder::new().with_wasm64().build();
    let wat = r#"
        (module
            (import "ic0" "call_new"
                (func $ic0_call_new
                    (param i64 i64)
                    (param $method_name_src i64)    (param $method_name_len i64)
                    (param $reply_fun i64)          (param $reply_env i64)
                    (param $reject_fun i64)         (param $reject_env i64)
                )
            )
            (import "ic0" "call_data_append"
                (func $ic0_call_data_append (param $src i64) (param $size i64))
            )
            (import "ic0" "call_perform" (func $ic0_call_perform (result i32)))
            (import "ic0" "msg_reply" (func $msg_reply))
            (func (export "canister_update test")
                (call $ic0_call_new
                    (i64.const 100) (i64.const 10)  ;; callee canister id = 777
                    (i64.const 0) (i64.const 18)    ;; refers to "some_remote_method" on the heap
                    (i64.const 11) (i64.const 22)   ;; fictive on_reply closure
                    (i64.const 33) (i64.const 44)   ;; fictive on_reject closure
                )
                (call $ic0_call_data_append
                    (i64.const 19) (i64.const 3)    ;; refers to "XYZ" on the heap
                )
                (call $ic0_call_perform)
                drop
                (call $msg_reply)
            )
            (memory i64 1 1)
            (data (i64.const 0) "some_remote_method XYZ")
            (data (i64.const 100) "\09\03\00\00\00\00\00\00\ff\01")
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]).unwrap();
    assert_eq!(WasmResult::Reply(vec![]), result);
    let canister_state = test.canister_state(canister_id);
    assert_eq!(1, canister_state.system_state.queues().output_queues_len());
}

#[test]
fn ic0_trap_works() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "trap" (func $ic_trap (param i32) (param i32)))
            (func (export "canister_update test")
                (call $ic_trap (i32.const 0) (i32.const 3))
            )
            (data (i32.const 0) "Hi!")
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterCalledTrap,
        &format!(
            "Error from Canister {canister_id}: Canister called `ic0.trap` \
        with message: Hi!"
        ),
    );
}

#[test]
fn globals_are_updated() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_update test")
                (global.set 0 (i32.const 1))
            )
            (global (export "g") (mut i32) (i32.const 137))
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
    assert_eq!(
        Global::I32(1),
        test.execution_state(canister_id).exported_globals[0]
    );
}

#[test]
fn comparison_of_non_canonical_nans() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_update test")
                (global.set 0 (f32.eq (f32.const nan:0x1234) (f32.const nan:0x1234)))
            )
            (global (export "g") (mut i32) (i32.const 137))
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
    assert_eq!(
        Global::I32(0),
        test.execution_state(canister_id).exported_globals[0]
    );
}

#[test]
fn instruction_limit_is_respected() {
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(3)
        .build();
    let wat = r#"
        (module
            (func (export "canister_update test")
                (i32.const 0)
                (i32.const 0)
                (drop)
                (drop)
            )
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterInstructionLimitExceeded, err.code());
}

#[test]
fn subnet_available_memory_is_respected_by_memory_grow() {
    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory(9 * WASM_PAGE_SIZE as i64)
        .with_subnet_memory_reservation(0)
        .build();
    let wat = r#"
        (module
            (func (export "canister_update test")
                (drop (memory.grow (i32.const 10)))
            )
            (memory 1 20)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterOutOfMemory, err.code());
}

#[test]
fn subnet_available_memory_is_updated() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_update test")
                (drop (memory.grow (i32.const 10)))
            )
            (memory 1 20)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let initial_subnet_available_memory = test.subnet_available_memory();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
    assert_eq!(
        initial_subnet_available_memory.get_execution_memory() - 10 * WASM_PAGE_SIZE as i64,
        test.subnet_available_memory().get_execution_memory()
    );
    assert_eq!(
        initial_subnet_available_memory.get_message_memory(),
        test.subnet_available_memory().get_message_memory()
    )
}

#[test]
fn subnet_available_memory_is_updated_in_heartbeat() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_heartbeat")
                (drop (memory.grow (i32.const 10)))
            )
            (memory 1 20)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let initial_subnet_available_memory = test.subnet_available_memory();
    test.canister_task(canister_id, CanisterTask::Heartbeat);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(11)
    );
    assert_eq!(
        initial_subnet_available_memory.get_execution_memory() - 10 * WASM_PAGE_SIZE as i64,
        test.subnet_available_memory().get_execution_memory()
    );
    assert_eq!(
        initial_subnet_available_memory.get_message_memory(),
        test.subnet_available_memory().get_message_memory()
    )
}

#[test]
fn subnet_available_memory_is_updated_in_global_timer() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_global_timer")
                (drop (memory.grow (i32.const 10)))
            )
            (memory 1 20)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let initial_subnet_available_memory = test.subnet_available_memory();
    test.canister_task(canister_id, CanisterTask::GlobalTimer);
    assert_eq!(
        test.execution_state(canister_id).wasm_memory.size,
        NumWasmPages::new(11)
    );
    assert_eq!(
        initial_subnet_available_memory.get_execution_memory() - 10 * WASM_PAGE_SIZE as i64,
        test.subnet_available_memory().get_execution_memory()
    );
    assert_eq!(
        initial_subnet_available_memory.get_message_memory(),
        test.subnet_available_memory().get_message_memory()
    )
}

#[test]
fn subnet_available_memory_is_not_updated_in_query() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_query test")
                (drop (memory.grow (i32.const 10)))
            )
            (memory 1 20)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let initial_subnet_available_memory = test.subnet_available_memory();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
    assert_eq!(
        initial_subnet_available_memory.get_execution_memory(),
        test.subnet_available_memory().get_execution_memory()
    );
    assert_eq!(
        initial_subnet_available_memory.get_message_memory(),
        test.subnet_available_memory().get_message_memory()
    )
}

#[test]
fn subnet_available_memory_is_updated_by_canister_init() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_init")
                (drop (memory.grow (i32.const 10)))
            )
            (memory 1 20)
        )"#;
    let initial_subnet_available_memory = test.subnet_available_memory();
    test.canister_from_wat(wat).unwrap();
    assert!(
        initial_subnet_available_memory.get_execution_memory() - 10 * WASM_PAGE_SIZE as i64
            > test.subnet_available_memory().get_execution_memory()
    );
    assert_eq!(
        initial_subnet_available_memory.get_message_memory(),
        test.subnet_available_memory().get_message_memory()
    );
    let memory_used = test.state().memory_taken().execution().get() as i64;
    let canister_history_memory = 2 * size_of::<CanisterChange>() + size_of::<PrincipalId>();
    // canister history memory usage is not updated in SubnetAvailableMemory => we add it at RHS
    assert_eq!(
        test.subnet_available_memory().get_execution_memory(),
        initial_subnet_available_memory.get_execution_memory() - memory_used
            + canister_history_memory as i64
    );
}

#[test]
fn subnet_available_memory_is_updated_by_canister_start() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func $start
                (drop (memory.grow (i32.const 10)))
            )
            (start $start)
            (memory 1 20)
        )"#;
    let initial_subnet_available_memory = test.subnet_available_memory();
    let canister_id = test.canister_from_wat(wat).unwrap();
    assert!(
        initial_subnet_available_memory.get_execution_memory() - 10 * WASM_PAGE_SIZE as i64
            > test.subnet_available_memory().get_execution_memory()
    );
    assert_eq!(
        initial_subnet_available_memory.get_message_memory(),
        test.subnet_available_memory().get_message_memory()
    );
    let mem_before_upgrade = test.subnet_available_memory().get_execution_memory();
    let result = test.upgrade_canister(canister_id, wat::parse_str(wat).unwrap());
    assert_eq!(Ok(()), result);
    assert_eq!(
        mem_before_upgrade,
        test.subnet_available_memory().get_execution_memory()
    );
    let memory_used = test.state().memory_taken().execution().get() as i64;
    let canister_history_memory = 3 * size_of::<CanisterChange>() + size_of::<PrincipalId>();
    // canister history memory usage is not updated in SubnetAvailableMemory => we add it at RHS
    assert_eq!(
        test.subnet_available_memory().get_execution_memory(),
        initial_subnet_available_memory.get_execution_memory() - memory_used
            + canister_history_memory as i64
    );
    assert_eq!(
        initial_subnet_available_memory.get_message_memory(),
        test.subnet_available_memory().get_message_memory()
    );
}

#[test]
fn subnet_available_memory_is_updated_by_canister_pre_upgrade() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow"
                (func $stable_grow (param i32) (result i32))
            )
            (func (export "canister_pre_upgrade")
                (drop (call $stable_grow (i32.const 10)))
            )
            (memory 1 20)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let initial_subnet_available_memory = test.subnet_available_memory();
    let result = test.upgrade_canister(canister_id, wat::parse_str(wat).unwrap());
    assert_eq!(Ok(()), result);
    assert_eq!(
        initial_subnet_available_memory.get_execution_memory() - 10 * WASM_PAGE_SIZE as i64,
        test.subnet_available_memory().get_execution_memory()
    );
    assert_eq!(
        initial_subnet_available_memory.get_message_memory(),
        test.subnet_available_memory().get_message_memory()
    )
}

#[test]
fn subnet_available_memory_is_not_updated_by_canister_pre_upgrade_wasm_memory() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_pre_upgrade")
                (drop (memory.grow (i32.const 10)))
            )
            (memory 1 20)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let initial_subnet_available_memory = test.subnet_available_memory();
    let result = test.upgrade_canister(canister_id, wat::parse_str(wat).unwrap());
    assert_eq!(Ok(()), result);
    assert_eq!(
        initial_subnet_available_memory.get_execution_memory(),
        test.subnet_available_memory().get_execution_memory()
    );
    assert_eq!(
        initial_subnet_available_memory.get_message_memory(),
        test.subnet_available_memory().get_message_memory()
    )
}

#[test]
fn subnet_available_memory_is_updated_by_canister_post_upgrade() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_post_upgrade")
                (drop (memory.grow (i32.const 10)))
            )
            (memory 1 20)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let initial_subnet_available_memory = test.subnet_available_memory();
    let result = test.upgrade_canister(canister_id, wat::parse_str(wat).unwrap());
    assert_eq!(Ok(()), result);
    assert_eq!(
        initial_subnet_available_memory.get_execution_memory() - 10 * WASM_PAGE_SIZE as i64,
        test.subnet_available_memory().get_execution_memory()
    );
    assert_eq!(
        initial_subnet_available_memory.get_message_memory(),
        test.subnet_available_memory().get_message_memory()
    )
}

#[test]
fn subnet_available_memory_does_not_change_after_failed_execution() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_update test")
                (drop (memory.grow (i32.const 1)))
                unreachable
            )
            (memory 1 20)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let initial_subnet_available_memory = test.subnet_available_memory();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert_eq!(
        initial_subnet_available_memory.get_execution_memory(),
        test.subnet_available_memory().get_execution_memory()
    );
    assert_eq!(
        initial_subnet_available_memory.get_message_memory(),
        test.subnet_available_memory().get_message_memory()
    )
}

#[test]
fn subnet_available_memory_is_not_updated_when_allocation_reserved() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_update test")
                (drop (memory.grow (i32.const 10)))
            )
            (memory 1 20)
        )"#;
    let binary = wat::parse_str(wat).unwrap();
    let canister_id = test.create_canister(Cycles::new(1_000_000_000_000));
    let memory_allocation = NumBytes::from(1024 * 1024 * 1024);

    test.install_canister_with_allocation(canister_id, binary, None, Some(memory_allocation.get()))
        .unwrap();
    let initial_memory_used = test.state().memory_taken().execution();
    let canister_history_memory = 2 * size_of::<CanisterChange>() + size_of::<PrincipalId>();
    // canister history memory usage is not updated in SubnetAvailableMemory => we add it at RHS
    assert_eq!(
        initial_memory_used.get(),
        memory_allocation.get() + canister_history_memory as u64
    );
    let initial_subnet_available_memory = test.subnet_available_memory();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
    // memory taken should not change
    assert_eq!(
        initial_subnet_available_memory.get_execution_memory(),
        test.subnet_available_memory().get_execution_memory()
    );
    assert_eq!(
        initial_subnet_available_memory.get_message_memory(),
        test.subnet_available_memory().get_message_memory()
    );
    assert_eq!(initial_memory_used, test.state().memory_taken().execution());
}

#[test]
fn ic0_msg_cycles_available_returns_zero_for_ingress() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "msg_cycles_available"
                (func $msg_cycles_available (result i64))
            )
            (func (export "canister_update test")
                block
                    call $msg_cycles_available
                    i64.eqz
                    br_if 0
                    unreachable
                end)
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
}

#[test]
fn ic0_msg_cycles_available_works_for_calls() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "msg_cycles_available" (func $msg_cycles_available (result i64)))
            (import "ic0" "msg_reply" (func $msg_reply))
            (func (export "canister_update test")
                block
                    call $msg_cycles_available
                    i64.const 50
                    i64.eq
                    br_if 0
                    unreachable
                end
                (call $msg_reply)
            )
            (memory 1)
        )"#;
    let callee_id = test.canister_from_wat(wat).unwrap();
    let caller_id = test.universal_canister().unwrap();
    let caller = wasm()
        .call_with_cycles(callee_id, "test", call_args(), Cycles::from(50u128))
        .build();
    let result = test.ingress(caller_id, "update", caller).unwrap();
    assert_eq!(WasmResult::Reply(vec![]), result);
}

#[test]
fn wasm64_ic0_msg_cycles_available128_works_for_calls() {
    let mut test = ExecutionTestBuilder::new().with_wasm64().build();
    let wat = r#"
        (module
            (import "ic0" "msg_cycles_available128" (func $msg_cycles_available128 (param i64)))
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
              (func $ic0_msg_reply_data_append (param i64) (param i64)))
            (func (export "canister_update test")
                (call $msg_cycles_available128 (i64.const 0))
                (call $ic0_msg_reply_data_append (i64.const 0) (i64.const 16))
                (call $msg_reply)
            )
            (memory i64 1)
        )"#;
    let callee_id = test.canister_from_wat(wat).unwrap();
    let caller_id = test.universal_canister().unwrap();
    let caller = wasm()
        .call_with_cycles(callee_id, "test", call_args(), Cycles::from(50u128))
        .build();
    let result = test.ingress(caller_id, "update", caller).unwrap();

    let x = 50u128;
    let x = Vec::from(x.to_le_bytes());
    assert_eq!(WasmResult::Reply(x), result);
}

#[test]
fn wasm64_ic0_msg_cycles_accept128_works_for_calls() {
    let mut test = ExecutionTestBuilder::new().with_wasm64().build();
    let wat = r#"
        (module
            (import "ic0" "msg_cycles_accept128"
              (func $ic0_msg_cycles_accept128 (param i64) (param i64) (param i64)))
            (import "ic0" "msg_reply" (func $ic0_msg_reply))
            (import "ic0" "msg_reply_data_append"
              (func $ic0_msg_reply_data_append (param i64) (param i64)))
            (func (export "canister_update test")
                (call $ic0_msg_cycles_accept128 (i64.const 0) (i64.const 22) (i64.const 0))
                (call $ic0_msg_reply_data_append (i64.const 0) (i64.const 16))
                (call $ic0_msg_reply)
            )
            (memory i64 1)
        )"#;
    let callee_id = test.canister_from_wat(wat).unwrap();
    let caller_id = test.universal_canister().unwrap();
    let caller = wasm()
        .call_with_cycles(callee_id, "test", call_args(), Cycles::from(50u128))
        .build();
    let result = test.ingress(caller_id, "update", caller).unwrap();

    let x = 22u128;
    let x = Vec::from(x.to_le_bytes());
    assert_eq!(WasmResult::Reply(x), result);
}

#[test]
fn wasm_page_metrics_are_recorded_even_if_execution_fails() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_update write")
                (i32.store
                    (i32.const 0)
                    (i32.add (i32.load (i32.const 70000)) (i32.const 1))
                )
                (unreachable)
            )
            (memory 2 2)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "write", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
    assert_eq!(
        fetch_histogram_vec_stats(test.metrics_registry(), "hypervisor_dirty_pages"),
        metric_vec(&[
            (
                &[("api_type", "update"), ("memory_type", "wasm")],
                HistogramStats { count: 1, sum: 1.0 }
            ),
            (
                &[("api_type", "update"), ("memory_type", "stable")],
                HistogramStats { count: 1, sum: 0.0 }
            ),
        ])
    );
    for (labels, stats) in
        fetch_histogram_vec_stats(test.metrics_registry(), "hypervisor_accessed_pages").iter()
    {
        let mem_type = labels.get("memory_type");
        match mem_type.as_ref().map(|a| String::as_ref(*a)) {
            Some("wasm") => {
                assert_eq!(stats.count, 1);
                // We can't match exactly here because on MacOS the page size is different (16 KiB) so the
                // number of reported pages is different.
                assert!(stats.sum >= 2.0)
            }
            Some("stable") => {
                assert_eq!(stats.count, 1);
                assert_eq!(stats.sum, 0.0)
            }
            _ => panic!("Unexpected memory type"),
        }
    }
}

#[test]
#[cfg(not(all(target_arch = "aarch64", target_vendor = "apple")))]
fn query_stable_memory_metrics_are_recorded() {
    let mut test = ExecutionTestBuilder::new().build();
    // The following canister will touch 2 pages worth of stable memory.
    let wat = r#"
        (module
            (import "ic0" "stable64_write"
                (func $stable_write (param $offset i64) (param $src i64) (param $size i64))
            )
            (import "ic0" "stable64_grow" (func $stable_grow (param i64) (result i64)))
            (import "ic0" "msg_reply" (func $msg_reply))
            (func (export "canister_query go") (local i64)
                (local.set 0 (i64.const 0))
                (drop (call $stable_grow (i64.const 10)))
                (loop $loop
                    (call $stable_write (local.get 0) (i64.const 0) (i64.const 1))
                    (local.set 0 (i64.add (local.get 0) (i64.const 4096))) (;increment by OS page size;)
                    (br_if $loop (i64.lt_s (local.get 0) (i64.const 8192))) (;loop if value is within the memory amount;)
                )
                (call $msg_reply)
            )
            (memory (export "memory") 1)
        )"#.to_string();
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test
        .non_replicated_query(canister_id, "go", vec![])
        .unwrap();
    assert_eq!(WasmResult::Reply(vec![]), result);
    assert_eq!(
        fetch_histogram_vec_stats(test.metrics_registry(), "hypervisor_dirty_pages"),
        metric_vec(&[
            (
                &[
                    ("api_type", "non replicated query"),
                    ("memory_type", "wasm")
                ],
                HistogramStats { count: 1, sum: 0.0 }
            ),
            (
                &[
                    ("api_type", "non replicated query"),
                    ("memory_type", "stable")
                ],
                HistogramStats { count: 1, sum: 2.0 }
            ),
        ])
    );
    for (labels, stats) in
        fetch_histogram_vec_stats(test.metrics_registry(), "hypervisor_accessed_pages").iter()
    {
        assert_eq!(
            labels.get("api_type"),
            Some("non replicated query".to_owned()).as_ref()
        );
        let mem_type = labels.get("memory_type");
        match mem_type.as_ref().map(|a| String::as_ref(*a)) {
            Some("wasm") => {
                assert_eq!(stats.count, 1);
                // We can't match exactly here because on MacOS the page size is different (16 KiB) so the
                // number of reported pages is different.
                assert!(stats.sum >= 1.0)
            }
            Some("stable") => {
                assert_eq!(stats.count, 1);
                assert_eq!(stats.sum, 2.0)
            }
            _ => panic!("Unexpected memory type"),
        }
    }
}

#[test]
fn executing_non_existing_method_does_not_consume_cycles() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = "(module)";
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "foo", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterMethodNotFound, err.code());
    assert_eq!(wat_compilation_cost(wat), test.executed_instructions());
}

#[test]
fn grow_memory() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_init")
                (drop (memory.grow (i32.const 1)))
            )
            (memory 1 2)
        )"#;
    test.canister_from_wat(wat).unwrap();
}

#[test]
fn memory_access_between_min_and_max_canister_start() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func $start
                ;; An attempt to load heap[0..4] which should fail.
                (drop (i32.load (i32.const 65536)))
            )
            (start $start)
            (memory 1 2)
        )"#;
    let err = test.canister_from_wat(wat).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
}

#[test]
fn memory_access_between_min_and_max_ingress() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_update test")
                ;; An attempt to load heap[0..4] which should fail.
                (drop (i32.load (i32.const 65536)))
            )
            (memory 1 2)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
}

#[test]
fn upgrade_calls_pre_and_post_upgrade() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow"
                (func $stable_grow (param i32) (result i32))
            )
            (import "ic0" "stable_read"
                (func $stable_read (param $dst i32) (param $offset i32) (param $size i32))
            )
            (import "ic0" "stable_write"
                (func $stable_write (param $offset i32) (param $src i32) (param $size i32))
            )
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32))
            )
            (func (export "canister_query read")
                (call $msg_reply_data_append
                    (i32.const 0) ;; the counter from heap[0]
                    (i32.const 8)) ;; length
                (call $msg_reply))
            (func (export "canister_pre_upgrade")
                (drop (call $stable_grow (i32.const 1)))
                ;; Store [1, 0, 0, 0] to heap[0..4]
                (i32.store (i32.const 0) (i32.const 1))
                ;; Copy heap[0..4] to stable_memory[0..4]
                (call $stable_write (i32.const 0) (i32.const 0) (i32.const 4))
            )
            (func (export "canister_post_upgrade")
                ;; Copy stable_memory[0..4] to heap[4..8]
                (call $stable_read (i32.const 4) (i32.const 0) (i32.const 4))
            )
            (memory $memory 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "read", vec![]);
    assert_eq!(result, Ok(WasmResult::Reply(vec![0, 0, 0, 0, 0, 0, 0, 0])));
    let result = test.upgrade_canister(canister_id, wat::parse_str(wat).unwrap());
    assert_eq!(Ok(()), result);
    let result = test.ingress(canister_id, "read", vec![]);
    // The Wasm memory changes of `pre_upgrade` must be cleared.
    // The Wasm memory changes of `post_upgrade` must be visible.
    assert_eq!(result, Ok(WasmResult::Reply(vec![0, 0, 0, 0, 1, 0, 0, 0])));
}

#[test]
fn upgrade_without_pre_and_post_upgrade_succeeds() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = "(module)";
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.upgrade_canister(canister_id, wat::parse_str(wat).unwrap());
    assert_eq!(Ok(()), result);
    // Compilation occurs once for original installation and again for upgrade.
    assert_eq!(test.executed_instructions(), wat_compilation_cost(wat) * 2);
}

#[test]
fn install_code_calls_canister_init_and_start() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))
            (func (export "canister_query read")
                (call $msg_reply_data_append
                    (i32.const 0) ;; the counter from heap[0]
                    (i32.const 8)) ;; length
                (call $msg_reply))
            (func $start
                (i32.store (i32.const 0) (i32.const 1))
            )
            (func (export "canister_init")
                (i32.store (i32.const 4) (i32.const 2))
            )
            (memory $memory 1)
            (start $start)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let dirty_heap_cost = NumInstructions::from(2 * test.dirty_heap_page_overhead());
    assert_eq!(
        // Function is 1 instruction.
        NumInstructions::from(8) + wat_compilation_cost(wat) + dirty_heap_cost,
        test.executed_instructions()
    );
    let result = test.ingress(canister_id, "read", vec![]);
    assert_eq!(result, Ok(WasmResult::Reply(vec![1, 0, 0, 0, 2, 0, 0, 0])));
}

#[test]
fn install_code_without_canister_init_and_start_succeeds() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = "(module)";
    test.canister_from_wat(wat).unwrap();
    assert_eq!(wat_compilation_cost(wat), test.executed_instructions());
}

#[test]
fn canister_init_can_set_mutable_globals() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_init")
                (global.set 0 (i32.const 42))
            )
            (global (export "globals_must_be_exported") (mut i32) (i32.const 0))
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    assert_eq!(
        Global::I32(42),
        test.execution_state(canister_id).exported_globals[0]
    );
}

#[test]
fn declare_memory_beyond_max_size_1() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_init")
                (i32.store (i32.const 0) (i32.const 1))
            )
            (memory 65537)
        )"#;
    let err = test.canister_from_wat(wat).unwrap_err();
    assert_eq!(ErrorCode::CanisterInvalidWasm, err.code());
}

#[test]
fn declare_memory_beyond_max_size_2() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_init")
                (i32.store (i32.const 0) (i32.const 1))
            )
            (memory 1 65537)
        )"#;
    let err = test.canister_from_wat(wat).unwrap_err();
    assert_eq!(ErrorCode::CanisterInvalidWasm, err.code());
}

#[test]
fn grow_memory_beyond_max_size_0() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_update test")
                ;; growing memory past limit does not trigger trap or error
                ;; but should return -1
                (global.set 0 (memory.grow (i32.const 1)))
            )
            (memory 1 1)
            (global (export "g") (mut i32) (i32.const 137))
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
    assert_eq!(
        Global::I32(-1),
        test.execution_state(canister_id).exported_globals[0]
    );
}

#[test]
fn grow_memory_beyond_max_size_1() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_init")
                ;; growing memory past limit does not trigger trap or error
                (drop (memory.grow (i32.const 1)))
                ;; but accessing the memory triggers HeapOutOfBounds
                ;; page(2)[0;4] = 1
                (i32.store (i32.const 65536) (i32.const 1))
            )
            (memory 1 1)
        )"#;
    let err = test.canister_from_wat(wat).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
}

#[test]
fn memory_access_between_min_and_max_canister_init() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_init")
                ;; attempt to load page(1)[0;4] which should fail
                (drop (i32.load (i32.const 65536)))
            )
            (memory 1 2)
        )"#;
    let err = test.canister_from_wat(wat).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
}

#[test]
fn grow_memory_beyond_max_size_2() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_init")
                ;; growing memory past limit does not trigger trap or error
                (drop (memory.grow (i32.const 100)))
                ;; but accessing the memory triggers HeapOutOfBounds
                ;; page(3)[0;4] = 1
                (i32.store
                    (i32.add (i32.mul (i32.const 65536) (i32.const 2)) (i32.const 1))
                    (i32.const 1)
                )
            )
            (memory 1 2)
        )"#;
    let err = test.canister_from_wat(wat).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
}

#[test]
fn grow_memory_beyond_32_bit_limit_fails() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_init")
                ;; 65536 is the maximum number of 32-bit wasm memory pages
                (drop (memory.grow (i32.const 65537)))
                ;; grow failed so accessing the memory triggers HeapOutOfBounds
                (i32.store (i32.const 1) (i32.const 1))
            )
            (memory 0)
        )"#;
    let err = test.canister_from_wat(wat).unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());
}

const STABLE_MEMORY_WAT: &str = r#"
    (import "ic0" "msg_reply" (func $msg_reply))
    (import "ic0" "msg_reply_data_append"
        (func $msg_reply_data_append (param i32) (param i32))
    )
    (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
    (import "ic0" "stable_read"
        (func $stable_read (param $dst i32) (param $offset i32) (param $size i32))
    )
    (import "ic0" "stable_write"
        (func $stable_write (param $offset i32) (param $src i32) (param $size i32))
    )
    (import "ic0" "trap" (func $ic_trap (param i32) (param i32)))
    (func (export "canister_query read")
        ;; heap[8..12] = stable_memory[0..4]
        (call $stable_read (i32.const 8) (i32.const 0) (i32.const 4))
        ;; Return heap[8..12].
        (call $msg_reply_data_append
            (i32.const 8)     ;; heap offset = 8
            (i32.const 4))    ;; length = 4
        (call $msg_reply)     ;; call reply
    )
    (func (export "canister_update write")
        (call $stable_write (i32.const 0) (i32.const 0) (i32.const 4))
    )"#;

#[test]
fn changes_to_stable_memory_in_canister_init_are_rolled_back_on_failure() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = format!(
        r#"(module
            {}
            (func (export "canister_init")
                (drop (call $stable_grow (i32.const 1)))
                (call $stable_write (i32.const 0) (i32.const 0) (i32.const 4))
                (call $ic_trap (i32.const 0) (i32.const 12))
            )
            (memory 1)
            (data (i32.const 0) "abcd")  ;; Initial contents of the heap.
        )"#,
        STABLE_MEMORY_WAT
    );
    let canister_id = test.create_canister(Cycles::new(1_000_000_000_000));
    let err = test
        .install_canister(canister_id, wat::parse_str(wat).unwrap())
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterCalledTrap, err.code());
    assert_eq!(None, test.canister_state(canister_id).execution_state);
}

#[test]
fn changes_to_stable_memory_in_canister_pre_upgrade_are_rolled_back_on_failure() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = format!(
        r#"(module
            {}
            (func (export "canister_init")
                (drop (call $stable_grow (i32.const 1)))
            )
            (func (export "canister_pre_upgrade")
                ;; stable_memory[0..4] = heap[0..4] ("abcd")
                (call $stable_write (i32.const 0) (i32.const 0) (i32.const 4))
                (call $ic_trap (i32.const 0) (i32.const 12))
            )
            (memory 1)
            (data (i32.const 0) "abcd")  ;; Initial contents of the heap.
        )"#,
        STABLE_MEMORY_WAT
    );
    let canister_id = test.canister_from_wat(wat.clone()).unwrap();
    let result = test.ingress(canister_id, "read", vec![]);
    assert_eq!(result, Ok(WasmResult::Reply(vec![0, 0, 0, 0])));
    let err = test
        .upgrade_canister(canister_id, wat::parse_str(wat).unwrap())
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterCalledTrap, err.code());
    let result = test.ingress(canister_id, "read", vec![]);
    assert_eq!(result, Ok(WasmResult::Reply(vec![0, 0, 0, 0])));
}

#[test]
fn changes_to_stable_memory_in_canister_post_upgrade_are_rolled_back_on_failure() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = format!(
        r#"(module
            {}
            (func (export "canister_init")
                (drop (call $stable_grow (i32.const 1)))
            )
            (func (export "canister_post_upgrade")
                ;; stable_memory[0..4] = heap[0..4] ("abcd")
                (call $stable_write (i32.const 0) (i32.const 0) (i32.const 4))
                (call $ic_trap (i32.const 0) (i32.const 12))
            )
            (memory 1)
            (data (i32.const 0) "abcd")  ;; Initial contents of the heap.
        )"#,
        STABLE_MEMORY_WAT
    );
    let canister_id = test.canister_from_wat(wat.clone()).unwrap();
    let result = test.ingress(canister_id, "read", vec![]);
    assert_eq!(result, Ok(WasmResult::Reply(vec![0, 0, 0, 0])));
    let err = test
        .upgrade_canister(canister_id, wat::parse_str(wat).unwrap())
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterCalledTrap, err.code());
    let result = test.ingress(canister_id, "read", vec![]);
    assert_eq!(result, Ok(WasmResult::Reply(vec![0, 0, 0, 0])));
}

#[test]
fn upgrade_preserves_stable_memory() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = format!(
        r#"(module
            {}
            (func (export "canister_init")
                (drop (call $stable_grow (i32.const 1)))
            )
            (memory 1)
            (data (i32.const 0) "abcd")  ;; Initial contents of the heap.
        )"#,
        STABLE_MEMORY_WAT
    );
    let canister_id = test.canister_from_wat(wat.clone()).unwrap();
    let result = test.ingress(canister_id, "write", vec![]);
    assert_empty_reply(result);
    let result = test.ingress(canister_id, "read", vec![]);
    assert_eq!(result, Ok(WasmResult::Reply("abcd".as_bytes().to_vec())));
    test.upgrade_canister(canister_id, wat::parse_str(wat).unwrap())
        .unwrap();
    let result = test.ingress(canister_id, "read", vec![]);
    assert_eq!(result, Ok(WasmResult::Reply("abcd".as_bytes().to_vec())));
}

#[test]
fn reinstall_clears_stable_memory() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = format!(
        r#"(module
            {}
            (func (export "canister_init")
                (drop (call $stable_grow (i32.const 1)))
            )
            (memory 1)
            (data (i32.const 0) "abcd")  ;; Initial contents of the heap.
        )"#,
        STABLE_MEMORY_WAT
    );
    let canister_id = test.canister_from_wat(wat.clone()).unwrap();
    let result = test.ingress(canister_id, "write", vec![]);
    assert_empty_reply(result);
    let result = test.ingress(canister_id, "read", vec![]);
    assert_eq!(result, Ok(WasmResult::Reply("abcd".as_bytes().to_vec())));
    test.reinstall_canister(canister_id, wat::parse_str(wat).unwrap())
        .unwrap();
    let result = test.ingress(canister_id, "read", vec![]);
    assert_eq!(result, Ok(WasmResult::Reply(vec![0, 0, 0, 0])));
}

#[test]
fn cannot_execute_update_on_stopping_canister() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    test.stop_canister(canister_id);
    assert_matches!(
        test.canister_state(canister_id).system_state.status,
        CanisterStatus::Stopping {
            call_context_manager: _,
            stop_contexts: _
        }
    );
    let err = test.ingress(canister_id, "update", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterStopping, err.code());
    assert_eq!(
        format!("Canister {} is not running", canister_id),
        err.description()
    );
}

#[test]
fn cannot_execute_update_on_stopped_canister() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    test.stop_canister(canister_id);
    test.process_stopping_canisters();
    assert_eq!(
        CanisterStatus::Stopped,
        test.canister_state(canister_id).system_state.status
    );
    let err = test.ingress(canister_id, "update", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterStopped, err.code());
    assert_eq!(
        format!("Canister {} is not running", canister_id),
        err.description()
    );
}

#[test]
fn cannot_execute_query_on_stopping_canister() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    test.stop_canister(canister_id);
    assert_matches!(
        test.canister_state(canister_id).system_state.status,
        CanisterStatus::Stopping {
            call_context_manager: _,
            stop_contexts: _
        }
    );
    let err = test.ingress(canister_id, "query", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterStopping, err.code());
    assert_eq!(
        format!("Canister {} is not running", canister_id),
        err.description()
    );
}

#[test]
fn cannot_execute_query_on_stopped_canister() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    test.stop_canister(canister_id);
    test.process_stopping_canisters();
    assert_eq!(
        CanisterStatus::Stopped,
        test.canister_state(canister_id).system_state.status
    );
    let err = test.ingress(canister_id, "query", vec![]).unwrap_err();
    assert_eq!(ErrorCode::CanisterStopped, err.code());
    assert_eq!(
        format!("Canister {} is not running", canister_id),
        err.description()
    );
}

#[test]
fn ic0_trap_preserves_some_cycles() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "trap" (func $ic_trap (param i32) (param i32)))
            ;; globals must be exported to be accessible to hypervisor or persisted
            (global (export "g1") (mut i32) (i32.const -1))
            (global (export "g2") (mut i64) (i64.const -1))

            (func $func_that_traps
                (call $ic_trap (i32.const 0) (i32.const 12))
            )

            (memory $memory 1)
            (export "memory" (memory $memory))
            (export "canister_update update" (func $func_that_traps))
            (export "canister_query query" (func $func_that_traps))
            (data (i32.const 0) "Trap called!")
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let err = test.ingress(canister_id, "update", vec![]).unwrap_err();
    let expected_executed_instructions = NumInstructions::from(
        instruction_to_cost(&wasmparser::Operator::Call { function_index: 0 })
            + ic_embedders::wasmtime_embedder::system_api_complexity::overhead::TRAP.get()
            + 2 * instruction_to_cost(&wasmparser::Operator::I32Const { value: 0 })
            + 12 /* trap data */
            + 1, // Function is 1 instruction.
    );
    assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
    assert_eq!(
        test.executed_instructions(),
        expected_executed_instructions + wat_compilation_cost(wat)
    );

    let executed_instructions_before = test.executed_instructions();
    let err = test.ingress(canister_id, "query", vec![]).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
    assert_eq!(
        test.executed_instructions(),
        executed_instructions_before + expected_executed_instructions
    );
}

// If method is not exported, `execute_anonymous_query` fails.
#[test]
fn canister_anonymous_query_method_not_exported() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (memory $memory 1)
            (export "memory" (memory $memory))
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.anonymous_query(canister_id, "http_transform", vec![], vec![]);
    assert_eq!(
        result,
        Err(
            HypervisorError::MethodNotFound(WasmMethod::Query("http_transform".to_string()))
                .into_user_error(&canister_id)
        )
    );
}

// Using `execute_anonymous_query` to execute transform function on a http response succeeds.
#[test]
fn canister_anonymous_query_transform_http_response() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "msg_reply" (func $ic0_msg_reply))
            (import "ic0" "msg_arg_data_copy"
                (func $ic0_msg_arg_data_copy (param i32 i32 i32)))
            (import "ic0" "msg_arg_data_size"
                (func $ic0_msg_arg_data_size (result i32)))
            (import "ic0" "msg_reply_data_append"
                (func $ic0_msg_reply_data_append (param i32) (param i32)))
            (func $transform
                ;; Replies with the provided http_response argument without any modifications.
                (call $ic0_msg_arg_data_copy
                    (i32.const 0) ;; dst
                    (i32.const 0) ;; offset
                    (call $ic0_msg_arg_data_size) ;; size
                )
                (call $ic0_msg_reply_data_append
                    (i32.const 0) ;; src
                    (call $ic0_msg_arg_data_size) ;; size
                )
                (call $ic0_msg_reply)
            )
            (memory $memory 1)
            (export "memory" (memory $memory))
            (export "canister_query http_transform" (func $transform))
        )"#;

    let canister_id = test.canister_from_wat(wat).unwrap();
    let canister_http_response = CanisterHttpResponsePayload {
        status: 200,
        headers: vec![],
        body: vec![0, 1, 2],
    };
    let payload = Encode!(&canister_http_response).unwrap();
    let result = test.anonymous_query(canister_id, "http_transform", payload, vec![]);
    let transformed_canister_http_response = Decode!(
        result.unwrap().bytes().as_slice(),
        CanisterHttpResponsePayload
    )
    .unwrap();
    assert_eq!(canister_http_response, transformed_canister_http_response)
}

// Tests that execute_update produces a heap delta.
#[test]
fn update_message_produces_heap_delta() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_update hello")
                (i32.store (i32.const 10) (i32.const 10))
            )
            (memory (export "memory") 1)
        )"#;
    assert_eq!(NumBytes::from(0), test.state().metadata.heap_delta_estimate);
    let canister_id = test.canister_from_wat(wat).unwrap();
    assert_eq!(NumBytes::from(0), test.state().metadata.heap_delta_estimate);
    let result = test.ingress(canister_id, "hello", vec![]);
    assert_empty_reply(result);
    assert_eq!(
        NumBytes::from(PAGE_SIZE as u64),
        test.state().metadata.heap_delta_estimate
    );
}

#[test]
fn canister_start_produces_heap_delta() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (;0;)
                (i32.store (i32.const 10) (i32.const 10))
            )
            (memory (export "memory") 1)
            (start 0)
        )"#;
    assert_eq!(NumBytes::from(0), test.state().metadata.heap_delta_estimate);
    test.canister_from_wat(wat).unwrap();
    assert_eq!(
        NumBytes::from(PAGE_SIZE as u64),
        test.state().metadata.heap_delta_estimate
    );
}

#[test]
fn canister_init_produces_heap_delta() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_init")
                (i32.store (i32.const 10) (i32.const 10))
            )
            (memory (export "memory") 1)
        )"#;
    assert_eq!(NumBytes::from(0), test.state().metadata.heap_delta_estimate);
    test.canister_from_wat(wat).unwrap();
    assert_eq!(
        NumBytes::from(PAGE_SIZE as u64),
        test.state().metadata.heap_delta_estimate
    );
}

fn memory_module_wat(wasm_pages: i32) -> String {
    format!(
        r#"
        (module
            (import "ic0" "msg_reply"
                (func $ic0_msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $ic0_msg_reply_data_append (param i32) (param i32)))
            (import "ic0" "msg_arg_data_copy"
                (func $ic0_msg_arg_data_copy (param i32) (param i32) (param i32)))
            (import "ic0" "msg_arg_data_size"
                (func $ic0_msg_arg_data_size (result i32)))

            ;; $read(addr: i32, len: i32) -> &[u8]
            ;; Read the slice at the given location in memory.
            (func $read
                ;; copy the i32 `addr` to heap[0;4]
                (call $ic0_msg_arg_data_copy
                  (i32.const 0) ;; dst
                  (i32.const 0) ;; off
                  (i32.const 4) ;; len
                )
                ;; copy the i32 `len` to heap[4;8]
                (call $ic0_msg_arg_data_copy
                  (i32.const 4) ;; dst
                  (i32.const 4) ;; off
                  (i32.const 4) ;; len
                )
                (call $ic0_msg_reply_data_append
                  ;; addr
                  (i32.load (i32.const 0))
                  ;; size
                  (i32.load (i32.const 4))
                )
                (call $ic0_msg_reply)
            )

            ;; $write(addr: i32, bytes: &[u8])
            ;; Copies the slice into the memory starting at the given address.
            (func $write
                ;; copy the i32 `addr` to heap[0;4]
                (call $ic0_msg_arg_data_copy
                  (i32.const 0) ;; dst
                  (i32.const 0) ;; off
                  (i32.const 4) ;; len
                )
                ;; copy the remainder of the payload to the heap[addr;size]
                (call $ic0_msg_arg_data_copy
                  ;; addr
                  (i32.load (i32.const 0))
                  ;; offset
                  (i32.const 4)
                  ;; size
                  (i32.sub
                    (call $ic0_msg_arg_data_size)
                    (i32.const 4)
                  )
                )
            )

            ;; $grow_and_read() -> &[u8]
            ;; Grows the memory by 1 Wasm page (64KiB) and return its contents.
            (func $grow_and_read
                (call $ic0_msg_reply_data_append
                  ;; addr
                  (i32.mul (memory.grow (i32.const 1)) (i32.const 65536))
                  ;; size
                  (i32.const 65536)
                )
                (call $ic0_msg_reply)
            )

            ;; $grow_and_write(value: u8)
            ;; Grows the memory by 1 Wasm page (64KiB) and fills it with
            ;; the given value.
            (func $grow_and_write
                (call $ic0_msg_arg_data_copy
                  ;; addr
                  (i32.mul (memory.grow (i32.const 1)) (i32.const 65536))
                  ;; offset
                  (i32.const 0)
                  ;; size
                  (call $ic0_msg_arg_data_size)
                )
            )

            (memory {wasm_pages})

            (export "canister_update read" (func $read))
            (export "canister_update write" (func $write))
            (export "canister_update grow_and_read" (func $grow_and_read))
            (export "canister_update grow_and_write" (func $grow_and_write))
        )"#,
        wasm_pages = wasm_pages,
    )
}

const WASM_PAGE_SIZE: i32 = 65536;

// A helper for executing read/write/grow operations.
struct MemoryAccessor {
    test: ExecutionTest,
    canister_id: CanisterId,
}

impl MemoryAccessor {
    fn new(wasm_pages: i32) -> Self {
        let mut test = ExecutionTestBuilder::new().build();
        let wat = memory_module_wat(wasm_pages);
        let canister_id = test.canister_from_wat(wat).unwrap();
        Self { test, canister_id }
    }

    fn write(&mut self, addr: i32, bytes: &[u8]) {
        let mut payload = addr.to_le_bytes().to_vec();
        payload.extend(bytes.iter());
        let result = self.test.ingress(self.canister_id, "write", payload);
        assert_empty_reply(result);
    }

    fn read(&mut self, addr: i32, size: i32) -> Vec<u8> {
        let mut payload = addr.to_le_bytes().to_vec();
        payload.extend(size.to_le_bytes().to_vec());
        get_reply(self.test.ingress(self.canister_id, "read", payload))
    }

    fn grow_and_read(&mut self) -> Vec<u8> {
        get_reply(self.test.ingress(self.canister_id, "grow_and_read", vec![]))
    }

    fn grow_and_write(&mut self, bytes: &[u8]) {
        let result = self
            .test
            .ingress(self.canister_id, "grow_and_write", bytes.to_vec());
        assert_empty_reply(result);
    }

    #[cfg(not(all(target_arch = "aarch64", target_vendor = "apple")))]
    fn verify_dirty_pages(&self, is_dirty_page: &[bool]) {
        let execution_state = self.test.execution_state(self.canister_id);
        let mut actual_dirty = vec![false; is_dirty_page.len()];
        for (index, _) in execution_state.wasm_memory.page_map.delta_pages_iter() {
            assert!((index.get() as usize) < actual_dirty.len());
            actual_dirty[index.get() as usize] = true;
        }
        assert_eq!(is_dirty_page, &actual_dirty);
    }
}

#[test]
fn write_last_page() {
    let wasm_pages = 1;
    let memory_size = WASM_PAGE_SIZE * wasm_pages;
    let mut memory_accessor = MemoryAccessor::new(wasm_pages);
    memory_accessor.write(memory_size - 8, &[42; 8]);
}

#[test]
fn read_last_page() {
    let wasm_pages = 1;
    let memory_size = WASM_PAGE_SIZE * wasm_pages;
    let mut memory_accessor = MemoryAccessor::new(wasm_pages);
    assert_eq!(vec![0; 8], memory_accessor.read(memory_size - 8, 8));
}

#[test]
fn write_and_read_last_page() {
    let wasm_pages = 1;
    let memory_size = WASM_PAGE_SIZE * wasm_pages;
    let mut memory_accessor = MemoryAccessor::new(wasm_pages);
    memory_accessor.write(memory_size - 8, &[42; 8]);
    assert_eq!(vec![42; 8], memory_accessor.read(memory_size - 8, 8));
}

#[test]
fn read_after_grow() {
    let wasm_pages = 1;
    let mut memory_accessor = MemoryAccessor::new(wasm_pages);
    // Skip the beginning of the memory because it is used as a scratchpad.
    memory_accessor.write(100, &[42; WASM_PAGE_SIZE as usize - 100]);
    // The new page should have only zeros.
    assert_eq!(vec![0; 65536], memory_accessor.grow_and_read());
}

#[test]
fn write_after_grow() {
    let wasm_pages = 1;
    let mut memory_accessor = MemoryAccessor::new(wasm_pages);
    memory_accessor.grow_and_write(&[42; WASM_PAGE_SIZE as usize]);
    assert_eq!(
        vec![42; WASM_PAGE_SIZE as usize],
        memory_accessor.read(wasm_pages * WASM_PAGE_SIZE, 65536),
    );
}

#[derive(Debug, Clone)]
#[cfg(not(all(target_arch = "aarch64", target_vendor = "apple")))]
enum Operation {
    Read(i32),
    Write(i32, u8),
    GrowAndRead,
    GrowAndWrite(u8),
}

#[cfg(not(all(target_arch = "aarch64", target_vendor = "apple")))]
fn random_operations(
    num_pages: i32,
    num_operations: usize,
) -> impl Strategy<Value = Vec<Operation>> {
    // Make sure that the value to be written is non-zero because
    // pages are zero-initialized and overwriting them with zeros
    // does not necessarily dirty the pages.
    let operation = (0..100).prop_flat_map(move |p| match p {
        0 => Just(Operation::GrowAndRead).boxed(),
        1 => (1..100_u8).prop_map(Operation::GrowAndWrite).boxed(),
        _ => prop_oneof![
            (1..num_pages).prop_map(Operation::Read),
            (1..num_pages, 1..100_u8).prop_map(|(page, value)| Operation::Write(page, value))
        ]
        .boxed(),
    });
    prop::collection::vec(operation, 1..num_operations)
}

#[test]
#[cfg(not(all(target_arch = "aarch64", target_vendor = "apple")))]
fn random_memory_accesses() {
    // Limit the number of cases to keep the running time low.
    let config = ProptestConfig {
        cases: 20,
        failure_persistence: None,
        ..ProptestConfig::default()
    };
    let algorithm = config.rng_algorithm;
    let mut runner = TestRunner::new_with_rng(config, TestRng::deterministic_rng(algorithm));
    runner
        .run(&random_operations(10, 100), |operations| {
            const PAGES_PER_WASM_PAGE: i32 = WASM_PAGE_SIZE / 4096;
            let mut pages = vec![0_u8; 10 * PAGES_PER_WASM_PAGE as usize];
            let mut dirty = vec![false; 10 * PAGES_PER_WASM_PAGE as usize];
            let mut memory_accessor = MemoryAccessor::new(10);
            for op in operations {
                match op {
                    Operation::Read(page) => {
                        prop_assert_eq!(
                            vec![pages[page as usize]; 4096],
                            memory_accessor.read(page * 4096, 4096)
                        );
                        // Read uses the first page as a scratchpad for arguments.
                        dirty[0] = true;
                    }
                    Operation::Write(page, value) => {
                        // Pages are already zero initialized, so writing zero
                        // doesn't necessarily dirty them. Avoid zeros to make
                        // dirty page tracking in the test precise.
                        prop_assert!(value > 0);
                        memory_accessor.write(page * 4096, &[value; 4096]);

                        // Confirm that the write was correct by reading the page.
                        prop_assert_eq!(vec![value; 4096], memory_accessor.read(page * 4096, 4096));
                        pages[page as usize] = value;
                        dirty[page as usize] = true;
                        // Write uses the first page as a scratchpad for arguments.
                        dirty[0] = true;
                    }
                    Operation::GrowAndRead => {
                        prop_assert_eq!(vec![0; 65536], memory_accessor.grow_and_read());
                        pages.extend(vec![0_u8; PAGES_PER_WASM_PAGE as usize]);
                        dirty.extend(vec![false; PAGES_PER_WASM_PAGE as usize]);
                        // Read uses the first page as a scratchpad for arguments.
                        dirty[0] = true;
                    }
                    Operation::GrowAndWrite(value) => {
                        // Pages are already zero initialized, so writing zero
                        // doesn't necessarily dirty them. Avoid zeros to make
                        // dirty page tracking in the test precise.
                        prop_assert!(value > 0);
                        memory_accessor.grow_and_write(&[value; WASM_PAGE_SIZE as usize]);
                        // Confirm that the write was correct by reading the pages.
                        prop_assert_eq!(
                            vec![value; WASM_PAGE_SIZE as usize],
                            memory_accessor.read(pages.len() as i32 * 4096, WASM_PAGE_SIZE)
                        );
                        pages.extend(vec![value; PAGES_PER_WASM_PAGE as usize]);
                        dirty.extend(vec![true; PAGES_PER_WASM_PAGE as usize]);
                        // Write uses the first page as a scratchpad for arguments.
                        dirty[0] = true;
                    }
                }
            }
            memory_accessor.verify_dirty_pages(&dirty);
            Ok(())
        })
        .unwrap();
}

// Verify that the `memory.fill` instruction has cost linear with it's size
// argument.
#[test]
fn account_for_size_of_memory_fill_instruction() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (memory 1)
            (func (;0;)
            (memory.fill
                (i32.const 0)
                (i32.const 0)
                (i32.const 1000)))
            (start 0)
        )"#;
    assert_eq!(test.executed_instructions(), NumInstructions::from(0));
    test.canister_from_wat(wat).unwrap();
    assert!(test.executed_instructions() > NumInstructions::from(1000));
}

// Verify that the `memory.fill` with max u32 bytes triggers the out of
// instructions trap.
#[test]
fn memory_fill_can_trigger_out_of_instructions() {
    let mut test = ExecutionTestBuilder::new()
        .with_install_code_instruction_limit(4_000_000_000)
        .build();
    let wat = r#"
        (module
            (memory 65536)
            (func (;0;)
            (memory.fill
                (i32.const 0)
                (i32.const 0)
                (i32.const 4294967295))) ;;max u32
            (start 0)
        )"#;
    let err = test.canister_from_wat(wat).unwrap_err();
    assert_eq!(ErrorCode::CanisterInstructionLimitExceeded, err.code());
}

#[test]
fn broken_wasm_results_in_compilation_error() {
    let mut test = ExecutionTestBuilder::new().build();
    let binary = vec![0xca, 0xfe, 0xba, 0xbe];
    let err = test.canister_from_binary(binary).unwrap_err();
    assert_eq!(ErrorCode::CanisterInvalidWasm, err.code());
}

#[test]
fn can_extract_exported_functions() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func $write)
            (func $read)
            (export "canister_update write" (func $write))
            (export "canister_query read" (func $read))
            (memory (;0;) 2)
            (export "memory" (memory 0))
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let execution_state = test.execution_state(canister_id);
    let mut expected_exports = BTreeSet::new();
    expected_exports.insert(WasmMethod::Update("write".to_string()));
    expected_exports.insert(WasmMethod::Query("read".to_string()));
    assert_eq!(
        execution_state.exports,
        ExportedFunctions::new(expected_exports)
    );
}

#[test]
fn can_extract_exported_custom_sections() {
    let mut test = ExecutionTestBuilder::new().build();
    // The wasm file below contains the following custom sections
    // Custom start=0x0002586a end=0x00028d92 (size=0x00003528) "name"
    // Custom start=0x00028d98 end=0x00028ddc (size=0x00000044) "icp:public candid:service"
    // Custom start=0x00028de2 end=0x00028dfc (size=0x0000001a) "icp:private candid:args"
    // Custom start=0x00028e02 end=0x00028e30 (size=0x0000002e) "icp:private motoko:stable-types"

    let binary = include_bytes!("../../tests/test-data/custom_sections.wasm").to_vec();
    let canister_id = test.canister_from_binary(binary).unwrap();

    let execution_state = test.execution_state(canister_id);
    assert_eq!(
        execution_state
            .metadata
            .custom_sections()
            .get("candid:service")
            .unwrap()
            .visibility(),
        CustomSectionType::Public
    );
    assert_eq!(
        execution_state
            .metadata
            .custom_sections()
            .get("candid:args")
            .unwrap()
            .visibility(),
        CustomSectionType::Private
    );
    assert_eq!(
        execution_state
            .metadata
            .custom_sections()
            .get("motoko:stable-types")
            .unwrap()
            .visibility(),
        CustomSectionType::Private
    );
    // Only the valid custom sections names are extracted: icp:public <name> or icp:private <name>.
    assert_eq!(execution_state.metadata.custom_sections().len(), 3);
}

#[test]
fn execute_with_huge_cycle_balance() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_init"))
            (memory 0)
        )"#;
    test.canister_from_cycles_and_wat(Cycles::new(1u128 << 100), wat)
        .unwrap();
}

#[test]
fn install_gzip_compressed_module() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))
            (func $inc
                (i32.store
                    (i32.const 0)
                    (i32.add (i32.load (i32.const 0)) (i32.const 1))))
            (func $read
                (call $msg_reply_data_append
                    (i32.const 0) ;; the counter from heap[0]
                    (i32.const 4)) ;; length
                (call $msg_reply))
            (memory $memory 1)
            (export "canister_query read" (func $read))
            (export "canister_update inc" (func $inc))
        )"#;

    let binary = {
        let wasm = wat::parse_str(wat).unwrap();
        let mut encoder = libflate::gzip::Encoder::new(Vec::new()).unwrap();
        std::io::copy(&mut &wasm[..], &mut encoder).unwrap();
        encoder.finish().into_result().unwrap()
    };

    let canister_id = test.canister_from_binary(binary).unwrap();
    let result = test.ingress(canister_id, "inc", vec![]);
    assert_empty_reply(result);
    let result = test.ingress(canister_id, "read", vec![]);
    assert_eq!(result, Ok(WasmResult::Reply(vec![1, 0, 0, 0])));
}

#[test]
fn cycles_cannot_be_accepted_after_response() {
    let mut test = ExecutionTestBuilder::new().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create three canisters A, B, C.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let c_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    let transferred_cycles = Cycles::from(initial_cycles.get() / 2);

    // Canister C simply replies with the message that was sent to it.
    let c = wasm().message_payload().append_and_reply().build();

    // Canister B:
    // 1. Replies to canister A with the message that was sent to it.
    // 2. Calls canister C.
    // 3. In the reply callback accepts `transferred_cycles`.
    let b = wasm()
        .message_payload()
        .append_and_reply()
        .inter_update(
            c_id,
            call_args()
                .other_side(c.clone())
                .on_reply(wasm().accept_cycles(transferred_cycles)),
        )
        .build();

    // Canister A:
    // 1. Calls canister B and transfers cycles.
    // 2. Forwards the reply in the reply callback, which is the default
    //    behaviour of the universal canister.
    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args().other_side(b.clone()),
            transferred_cycles,
        )
        .build();
    let result = test.ingress(a_id, "update", a).unwrap();
    assert_matches!(result, WasmResult::Reply(_));

    // Canister A gets a refund for all transferred cycles.
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(a_id)
            - test.call_fee("update", &b)
            - test.reply_fee(&b)
    );

    // Canister B doesn't get the transferred cycles.
    assert_eq!(
        test.canister_state(b_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(b_id)
            - test.call_fee("update", &c)
            - test.reply_fee(&c)
    );

    // Canister C pays only for execution.
    assert_eq!(
        test.canister_state(c_id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(c_id)
    );
}

#[test]
fn cycles_are_refunded_if_not_accepted() {
    let mut test = ExecutionTestBuilder::new().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create three canisters A, B, C.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let c_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    let a_to_b_transferred = Cycles::from(initial_cycles.get() / 2);
    let a_to_b_accepted = Cycles::from(a_to_b_transferred.get() / 2);
    let b_to_c_transferred = a_to_b_accepted;
    let b_to_c_accepted = Cycles::from(b_to_c_transferred.get() / 2);

    // Canister C accepts some cycles and replies to canister B.
    let c = wasm()
        .accept_cycles(b_to_c_accepted)
        .message_payload()
        .append_and_reply()
        .build();

    // Canister B:
    // 1. Accepts some cycles.
    // 2. Replies to canister A.
    // 3. Calls canister C.
    // 4. Forwards the reply in the reply callback, which is the default
    //    behaviour of the universal canister.
    let b = wasm()
        .accept_cycles(a_to_b_accepted)
        .message_payload()
        .append_and_reply()
        .call_with_cycles(
            c_id,
            "update",
            call_args().other_side(c.clone()),
            b_to_c_transferred,
        )
        .build();

    // Canister A:
    // 1. Calls canister B and transfers some cycles to it.
    // 2. Forwards the reply in the reply callback, which is the default
    //    behaviour of the universal canister.
    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args().other_side(b.clone()),
            a_to_b_transferred,
        )
        .build();
    let result = test.ingress(a_id, "update", a).unwrap();
    assert_matches!(result, WasmResult::Reply(_));

    // Canister A gets a refund for all cycles not accepted by B.
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(a_id)
            - test.call_fee("update", &b)
            - test.reply_fee(&b)
            - a_to_b_accepted,
    );

    // Canister B gets all cycles it accepted and a refund for all cycles not
    // accepted by C.
    assert_eq!(
        test.canister_state(b_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(b_id)
            - test.call_fee("update", &c)
            - test.reply_fee(&c)
            + a_to_b_accepted
            - b_to_c_accepted
    );

    // Canister C get all cycles it accepted.
    assert_eq!(
        test.canister_state(c_id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(c_id) + b_to_c_accepted
    );
}

#[test]
fn cycles_are_refunded_if_callee_traps() {
    let mut test = ExecutionTestBuilder::new().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create two canisters: A and B.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    let a_to_b_transferred = Cycles::from(initial_cycles.get() / 2);
    let a_to_b_accepted = Cycles::from(a_to_b_transferred.get() / 2);

    // Canister B:
    // 1. Accepts some cycles.
    // 2. Replies to canister A.
    // 3. Calls trap.
    let b = wasm()
        .accept_cycles(a_to_b_accepted)
        .message_payload()
        .append_and_reply()
        .trap()
        .build();

    // Canister A:
    // 1. Calls canister B and transfers some cycles to it.
    // 2. Forwards the reject code and message in the reject callback.
    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b.clone())
                .on_reject(wasm().reject_message().reject()),
            a_to_b_transferred,
        )
        .build();

    let result = test.ingress(a_id, "update", a).unwrap();
    let reject_message = match result {
        WasmResult::Reply(_) => unreachable!("Expected reject, got {}", result),
        WasmResult::Reject(reject_message) => reject_message,
    };

    // Canister A gets a refund for all transferred cycles because canister B
    // trapped after accepting.
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(a_id)
            - test.call_fee("update", &b)
            - test.reject_fee(reject_message)
    );

    // Canister B doesn't get any transferred cycles.
    assert_eq!(
        test.canister_state(b_id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(b_id)
    );
}

#[test]
fn cycles_are_refunded_even_if_response_callback_traps() {
    let mut test = ExecutionTestBuilder::new().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create two canisters: A and B.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    let a_to_b_transferred = Cycles::from(initial_cycles.get() / 2);
    let a_to_b_accepted = Cycles::from(a_to_b_transferred.get() / 2);

    // Canister B accepts cycles and replies.
    let b = wasm()
        .accept_cycles(a_to_b_accepted)
        .message_payload()
        .append_and_reply()
        .build();

    // Canister A:
    // 1. Calls canister B and transfers some cycles to it.
    // 2. Calls trap in the reply callback.
    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args().other_side(b.clone()).on_reply(wasm().trap()),
            a_to_b_transferred,
        )
        .build();
    let err = test.ingress(a_id, "update", a).unwrap_err();
    assert_eq!(ErrorCode::CanisterCalledTrap, err.code());

    // Calling trap in the reply callback shouldn't affect the amount of
    // refunded cycles. Canister A gets all cycles that are not accepted by B.
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(a_id)
            - test.call_fee("update", &b)
            - test.reply_fee(&b)
            - a_to_b_accepted,
    );

    // Canister B gets cycles it accepted.
    assert_eq!(
        test.canister_state(b_id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(b_id) + a_to_b_accepted
    );
}

// TODO(RUN-175): Enable the test after the bug is fixed.
#[test]
#[ignore]
fn cycles_are_refunded_if_callee_is_a_query() {
    let mut test = ExecutionTestBuilder::new().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create two canisters: A and B.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    let a_to_b_transferred = (initial_cycles.get() / 2) as u64;

    // Canister B simply replies to canister A without accepting any cycles.
    // Note that it cannot accept cycles because it runs as a query.
    let b = wasm().message_payload().append_and_reply().build();

    // Canister A:
    // 1. Calls a query method of canister B and transfers some cycles to it.
    // 2. Forwards the reply in the reply callback, which is the default
    //    behaviour of the universal canister.
    let a = wasm()
        .call_with_cycles(
            b_id,
            "query",
            call_args().other_side(b.clone()),
            Cycles::from(a_to_b_transferred),
        )
        .build();
    let result = test.ingress(a_id, "update", a).unwrap();
    assert_matches!(result, WasmResult::Reply(_));

    // Canister should get a refund for all transferred cycles.
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(a_id)
            - test.call_fee("query", &b)
            - test.reply_fee(&b)
    );

    // Canister B doesn't get any transferred cycles.
    assert_eq!(
        test.canister_state(b_id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(b_id)
    );
}

#[test]
fn cycles_are_refunded_if_callee_is_uninstalled_before_execution() {
    let mut test = ExecutionTestBuilder::new().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create two canisters: A and B.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let a_to_b_transferred = (initial_cycles.get() / 2) as u64;

    // Canister B simply replies to canister A.
    let b = wasm().message_payload().append_and_reply().build();

    // Canister A:
    // 1. Calls canister B and transfers some cycles to it.
    // 2. Forwards the reject code and message in the reject callback.
    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b.clone())
                .on_reject(wasm().reject_message().reject()),
            Cycles::from(a_to_b_transferred),
        )
        .build();

    // Uninstall canister B before calling it.
    test.uninstall_code(b_id).unwrap();

    // Send a message to canister A which will call canister B.
    let result = test.ingress(a_id, "update", a).unwrap();
    let reject_message = match result {
        WasmResult::Reply(_) => unreachable!("Expected reject, got {}", result),
        WasmResult::Reject(reject_message) => reject_message,
    };

    // Canister A gets a refund for all transferred cycles.
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(a_id)
            - test.call_fee("update", &b)
            - test.reject_fee(reject_message)
    );

    // Canister B doesn't get any cycles.
    assert_eq!(
        test.canister_state(b_id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(b_id)
    );
}

#[test]
fn cycles_are_refunded_if_callee_is_uninstalled_after_execution() {
    // This test uses manual execution to get finer control over the execution
    // and message induction order.
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create three canisters: A, B, C.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let c_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    let a_to_b_transferred = Cycles::from(initial_cycles.get() / 2);
    let a_to_b_accepted = Cycles::from(a_to_b_transferred.get() / 2);
    let b_to_c_transferred = a_to_b_accepted;
    let b_to_c_accepted = Cycles::from(b_to_c_transferred.get() / 2);

    // Canister C accepts some cycles and replies.
    let c = wasm()
        .accept_cycles(b_to_c_accepted)
        .message_payload()
        .append_and_reply()
        .build();

    // Canister B:
    // 1. Accepts some cycles.
    // 2. Calls canister C and transfers some cycles to it.
    // 3. Forwards the reply of C to A.
    let b = wasm()
        .accept_cycles(a_to_b_accepted)
        .call_with_cycles(
            c_id,
            "update",
            call_args().other_side(c.clone()),
            b_to_c_transferred,
        )
        .build();

    // Canister A:
    // 1. Calls canister B and transfers some cycles to it.
    // 2. Forwards the reply of B to the ingress status.
    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b.clone())
                .on_reject(wasm().reject_message().reject()),
            a_to_b_transferred,
        )
        .build();

    // Execute canisters A and B.
    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);
    test.execute_message(a_id);
    test.induct_messages();
    test.execute_message(b_id);
    test.induct_messages();

    // Uninstall canister B, which generates a reject message for canister A.
    test.uninstall_code(b_id).unwrap();

    // Execute canister C and all the replies.
    test.execute_all();
    let ingress_status = test.ingress_status(&ingress_id);
    let result = check_ingress_status(ingress_status).unwrap();

    let reject_message = match result {
        WasmResult::Reply(_) => unreachable!("Expected reject, got: {:?}", result),
        WasmResult::Reject(reject_message) => reject_message,
    };
    assert!(
        reject_message.contains("Canister has been uninstalled"),
        "Unexpected error message: {}",
        reject_message
    );

    // Canister A gets all cycles that are not accepted by B.
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(a_id)
            - test.call_fee("update", &b)
            - test.reject_fee(reject_message)
            - a_to_b_accepted,
    );

    // Canister B gets all cycles it accepted and all cycles that canister C did
    // not accept.
    assert_eq!(
        test.canister_state(b_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(b_id)
            - test.call_fee("update", &c)
            - test.reply_fee(&c)
            + a_to_b_accepted
            - b_to_c_accepted
    );

    // Canister C gets all cycles it accepted.
    assert_eq!(
        test.canister_state(c_id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(c_id) + b_to_c_accepted
    );
}

#[test]
fn cycles_are_refunded_if_callee_is_reinstalled() {
    // This test uses manual execution to get finer control over the execution
    // and message induction order.
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create three canisters: A, B, C.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let c_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    let a_to_b_transferred = Cycles::from(initial_cycles.get() / 2);
    let a_to_b_accepted = Cycles::from(a_to_b_transferred.get() / 2);
    let b_to_c_transferred = a_to_b_accepted;
    let b_to_c_accepted = Cycles::from(b_to_c_transferred.get() / 2);

    // Canister C accepts some cycles and replies.
    let c = wasm()
        .accept_cycles(b_to_c_accepted)
        .message_payload()
        .append_and_reply()
        .build();

    // Canister B:
    // 1. Accepts some cycles.
    // 2. Calls canister C and transfers some cycles to it.
    // 3. Forwards the reply of C to A.
    let b = wasm()
        .accept_cycles(a_to_b_accepted)
        .call_with_cycles(
            c_id,
            "update",
            call_args().other_side(c.clone()),
            b_to_c_transferred,
        )
        .build();

    // Canister A:
    // 1. Calls canister B and transfers some cycles to it.
    // 2. Forwards the reply of B to the ingress status.
    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b.clone())
                .on_reject(wasm().reject_message().reject()),
            a_to_b_transferred,
        )
        .build();

    // Execute canisters A and B.
    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);
    test.execute_message(a_id);
    test.induct_messages();
    test.execute_message(b_id);
    test.induct_messages();

    // Reinstall canister B with the same code. Since the memory is cleared, the
    // reply callback will trap.
    test.reinstall_canister(b_id, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();

    // Execute canister C and all the replies.
    test.execute_all();
    let ingress_status = test.ingress_status(&ingress_id);
    let result = check_ingress_status(ingress_status).unwrap();
    let reject_message = match result {
        WasmResult::Reply(_) => unreachable!("Expected reject, got: {:?}", result),
        WasmResult::Reject(reject_message) => reject_message,
    };
    assert!(
        reject_message.contains("Canister called `ic0.trap` with message: panicked at")
            && reject_message.contains("get_callback: 1 out of bounds"),
        "Unexpected error message: {}",
        reject_message
    );

    // Canister A gets all cycles that are not accepted by B.
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(a_id)
            - test.call_fee("update", &b)
            - test.reject_fee(reject_message)
            - a_to_b_accepted,
    );

    // Canister B gets all cycles it accepted and all cycles that canister C did
    // not accept.
    assert_eq!(
        test.canister_state(b_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(b_id)
            - test.call_fee("update", &c)
            - test.reply_fee(&c)
            + a_to_b_accepted
            - b_to_c_accepted
    );

    // Canister C gets all cycles it accepted.
    assert_eq!(
        test.canister_state(c_id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(c_id) + b_to_c_accepted
    );
}

#[test]
fn cycles_are_refunded_if_callee_is_uninstalled_during_a_self_call() {
    // This test uses manual execution to get finer control over the execution
    // and message induction order.
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create two canisters: A and B.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    let a_to_b_transferred = Cycles::from(initial_cycles.get() / 2);
    let a_to_b_accepted = Cycles::from(a_to_b_transferred.get() / 2);
    let b_transferred_1 = Cycles::from(initial_cycles.get() / 2);
    let b_accepted_1 = Cycles::from(b_transferred_1.get() / 2);
    let b_transferred_2 = b_accepted_1;
    let b_accepted_2 = Cycles::from(b_transferred_2.get() / 2);

    // The update method #2 canister B accepts some cycles and then replies.
    let b_2 = wasm()
        .accept_cycles(b_accepted_2)
        .message_payload()
        .append_and_reply()
        .build();

    // The update method #1 of canister B:
    // 1. Accepts some cycles.
    // 2. Call the update method #2 and transfers some cycles.
    // 3. Forwards the reply to the caller.
    let b_1 = wasm()
        .accept_cycles(b_accepted_1)
        .call_with_cycles(
            b_id,
            "update",
            call_args().other_side(b_2.clone()),
            b_transferred_2,
        )
        .build();

    // The update method #0 of canister B:
    // 1. Call the update method #2 and transfers some cycles.
    // 2. Forwards the reject code and message to canister A.
    let b_0 = wasm()
        .accept_cycles(a_to_b_accepted)
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b_1.clone())
                .on_reject(wasm().reject_message().reject()),
            b_transferred_1,
        )
        .build();

    // Canister A:
    // 1. Call the update method #0 of B and transfers some cycles.
    // 2. Forwards the reject code and message to the ingress status.
    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b_0.clone())
                .on_reject(wasm().reject_message().reject()),
            a_to_b_transferred,
        )
        .build();

    // Execute canister A and methods #0 and #1 of canister B.
    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);
    test.execute_message(a_id);
    test.induct_messages();
    test.execute_message(b_id);
    test.induct_messages();
    test.execute_message(b_id);

    // Uninstall canister B, which generates reject messages for all call contexts.
    test.uninstall_code(b_id).unwrap();

    // Execute method #2 of canister B and all the replies.
    test.execute_all();
    let ingress_status = test.ingress_status(&ingress_id);
    let result = check_ingress_status(ingress_status).unwrap();
    let reject_message = match result {
        WasmResult::Reply(_) => unreachable!("Expected reject, got: {:?}", result),
        WasmResult::Reject(reject_message) => reject_message,
    };
    assert!(
        reject_message.contains("Canister has been uninstalled"),
        "Unexpected error message: {}",
        reject_message
    );

    // Canister A gets a refund for all cycles that B did not accept.
    assert_eq!(
        test.canister_state(a_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(a_id)
            - test.call_fee("update", &b_0)
            - test.reject_fee(reject_message.clone())
            - a_to_b_accepted
    );

    // Call canister b to get the "canister contains no Wasm module" without hard-coding it.
    let (ingress_id, _) = test.ingress_raw(b_id, "foo", vec![]);
    test.induct_messages();
    test.execute_all();
    let ingress_status = test.ingress_status(&ingress_id);
    let result = check_ingress_status(ingress_status).unwrap_err();
    // The reject message from method #2 of B to method #1.
    let reject_message_b_2_to_1 = format!("IC0537: {}", result.description(),);

    // Canister B gets the cycles it accepted from A.
    assert_eq!(
        test.canister_state(b_id).system_state.balance(),
        initial_cycles
            - test.canister_execution_cost(b_id)
            - test.call_fee("update", &b_1)
            - test.call_fee("update", &b_2)
            - test.reject_fee(reject_message)
            - test.reject_fee(reject_message_b_2_to_1)
            + a_to_b_accepted
    );
}

#[test]
fn cannot_send_request_to_stopping_canister() {
    let mut test = ExecutionTestBuilder::new().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create two canisters: A and B.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    // Canister B simply replies to canister A.
    let b = wasm().message_payload().append_and_reply().build();

    // Canister A:
    // 1. Calls canister B and transfers some cycles to it.
    // 2. Forwards the reply in the reply callback, which is the default
    //    behaviour of the universal canister.
    let a = wasm().inter_update(b_id, call_args().other_side(b)).build();

    // Move canister B to a stopping state before calling it.
    test.stop_canister(b_id);
    assert_matches!(
        test.canister_state(b_id).system_state.status,
        CanisterStatus::Stopping {
            call_context_manager: _,
            stop_contexts: _
        }
    );

    // Send a message to canister A which will call canister B.
    let ingress_status = test.ingress_raw(a_id, "update", a).1;

    // Canister B refuses to accept the message in its input queue.
    // The message is lost in the current test setup. In production
    // message routing would generate a reject message.
    assert_eq!(1, test.lost_messages().len());
    let ingress_state = match ingress_status {
        IngressStatus::Known { state, .. } => state,
        IngressStatus::Unknown => unreachable!("Expected known ingress status"),
    };
    assert_eq!(IngressState::Processing, ingress_state);
}

#[test]
fn cannot_send_request_to_stopped_canister() {
    let mut test = ExecutionTestBuilder::new().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create two canisters: A and B.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    // Canister B simply replies to canister A.
    let b = wasm().message_payload().append_and_reply().build();

    // Canister A:
    // 1. Calls canister B and transfers some cycles to it.
    // 2. Forwards the reply in the reply callback, which is the default
    //    behaviour of the universal canister.
    let a = wasm().inter_update(b_id, call_args().other_side(b)).build();

    // Stop canister B before calling it.
    test.stop_canister(b_id);
    test.process_stopping_canisters();
    assert_eq!(
        CanisterStatus::Stopped,
        test.canister_state(b_id).system_state.status
    );

    // Send a message to canister A which will call canister B.
    let ingress_status = test.ingress_raw(a_id, "update", a).1;

    // Canister B refuses to accept the message in its input queue.
    // The message is lost in the current test setup. In production
    // message routing would generate a reject message.
    assert_eq!(1, test.lost_messages().len());
    let ingress_state = match ingress_status {
        IngressStatus::Known { state, .. } => state,
        IngressStatus::Unknown => unreachable!("Expected known ingress status"),
    };
    assert_eq!(IngressState::Processing, ingress_state);
}

#[test]
fn cannot_stop_canister_with_open_call_context() {
    // This test uses manual execution to get finer control over the execution
    // and message induction order.
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create two canisters: A and B.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    // Canister B simply replies to canister A.
    let b = wasm().message_payload().append_and_reply().build();

    // Canister A calls canister B.
    let a = wasm()
        .inter_update(b_id, call_args().other_side(b.clone()))
        .build();

    // Enqueue ingress message to canister A but do not execute it (guaranteed
    // by "manual execution" option of the test).
    let (ingress_id, ingress_status) = test.ingress_raw(a_id, "update", a);
    assert_eq!(ingress_status, IngressStatus::Unknown);

    // Execute the ingress message and induct all messages to get the call
    // message to the input queue of canister B.
    test.execute_message(a_id);
    test.induct_messages();

    // Try to stop canister A.
    test.stop_canister(a_id);
    test.process_stopping_canisters();

    // Canister A cannot transition to the stopped state because it has an open
    // call context.
    assert_matches!(
        test.canister_state(a_id).system_state.status,
        CanisterStatus::Stopping {
            call_context_manager: _,
            stop_contexts: _
        }
    );

    // Execute the call in canister B.
    test.execute_message(b_id);

    // Get the reply back to canister A and execute it.
    test.induct_messages();
    test.execute_message(a_id);
    let ingress_status = test.ingress_status(&ingress_id);
    let result = check_ingress_status(ingress_status).unwrap();
    assert_eq!(result, WasmResult::Reply(b));

    // Now it should be possible to stop canister A.
    test.process_stopping_canisters();
    assert_eq!(
        test.canister_state(a_id).system_state.status,
        CanisterStatus::Stopped
    );
}

#[test]
fn can_use_more_instructions_during_install_code() {
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(1_000_000)
        .with_cost_to_compile_wasm_instruction(0)
        .with_install_code_instruction_limit(
            1_000_000 + wasm_compilation_cost(UNIVERSAL_CANISTER_WASM).get(),
        )
        .build();
    let canister_id = test.universal_canister().unwrap();
    let work = wasm().instruction_counter_is_at_least(1_000_000).build();

    // The update call should hit the instruction limit and fail.
    let err = test
        .ingress(canister_id, "update", work.clone())
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterInstructionLimitExceeded, err.code());

    // Set the pre-upgrade hook to do the same operation.
    let result = test
        .ingress(
            canister_id,
            "update",
            wasm().set_pre_upgrade(work).reply().build(),
        )
        .unwrap();
    assert_eq!(WasmResult::Reply(vec![]), result);

    // An upgrade of the canister succeeds because `install_code` has a
    // higher instruction limit.
    let result = test.upgrade_canister(canister_id, UNIVERSAL_CANISTER_WASM.to_vec());
    assert_eq!(Ok(()), result);
}

#[test]
fn dts_pause_resume_works_in_update_call() {
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(100_000_000)
        .with_slice_instruction_limit(1_000_000)
        .with_manual_execution()
        .build();
    let canister_id = test.universal_canister().unwrap();
    let work = wasm()
        .instruction_counter_is_at_least(1_000_000)
        .push_bytes(&[1, 2, 3, 4, 5])
        .append_and_reply()
        .build();

    // The workload above finishes in 2 slices.
    let (ingress_id, _) = test.ingress_raw(canister_id, "update", work);
    // Execute the first slice.
    test.execute_slice(canister_id);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::ContinueLong
    );
    // Execute the second slice.
    test.execute_slice(canister_id);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None
    );
    let ingress_status = test.ingress_status(&ingress_id);
    let result = check_ingress_status(ingress_status).unwrap();
    assert_eq!(result, WasmResult::Reply(vec![1, 2, 3, 4, 5]));
}

#[test]
fn dts_abort_works_in_update_call() {
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(100_000_000)
        .with_slice_instruction_limit(1_000_000)
        .with_manual_execution()
        .build();
    let canister_id = test.universal_canister().unwrap();
    let work = wasm()
        .instruction_counter_is_at_least(1_000_000)
        .push_bytes(&[1, 2, 3, 4, 5])
        .append_and_reply()
        .build();

    // The workload above finishes in 2 slices.
    let (ingress_id, _) = test.ingress_raw(canister_id, "update", work);
    let original_system_state = test.canister_state(canister_id).system_state.clone();
    let original_execution_cost = test.canister_execution_cost(canister_id);

    // Execute the first slice.
    test.execute_slice(canister_id);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::ContinueLong
    );
    assert_eq!(
        test.canister_state(canister_id).system_state.balance(),
        original_system_state.balance()
            - test
                .cycles_account_manager()
                .execution_cost(NumInstructions::from(100_000_000), test.subnet_size()),
    );
    assert_eq!(
        test.canister_state(canister_id)
            .system_state
            .call_context_manager(),
        original_system_state.call_context_manager()
    );

    // Abort before executing the last slice.
    test.abort_all_paused_executions();
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::ContinueLong
    );
    assert_eq!(
        fetch_int_counter(test.metrics_registry(), "executions_aborted"),
        Some(1)
    );

    // Now execute from scratch the first slice.
    test.execute_slice(canister_id);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::ContinueLong
    );
    assert_eq!(
        test.canister_state(canister_id).system_state.balance(),
        original_system_state.balance()
            - test
                .cycles_account_manager()
                .execution_cost(NumInstructions::from(100_000_000), test.subnet_size()),
    );
    assert_eq!(
        test.canister_state(canister_id)
            .system_state
            .call_context_manager(),
        original_system_state.call_context_manager()
    );

    // Execute the second slice.
    test.execute_slice(canister_id);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None
    );
    assert_eq!(
        test.canister_state(canister_id).system_state.balance(),
        original_system_state.balance()
            - (test.canister_execution_cost(canister_id) - original_execution_cost)
    );
    let ingress_status = test.ingress_status(&ingress_id);
    let result = check_ingress_status(ingress_status).unwrap();
    assert_eq!(result, WasmResult::Reply(vec![1, 2, 3, 4, 5]));
}

#[test]
fn dts_concurrent_subnet_available_change() {
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(100_000_000)
        .with_slice_instruction_limit(1_000_000)
        .with_manual_execution()
        .build();
    let canister_id = test.universal_canister().unwrap();
    let work = wasm()
        .instruction_counter_is_at_least(1_000_000)
        .reply()
        .build();

    // The workload above finishes in 2 slices.
    let (ingress_id, _) = test.ingress_raw(canister_id, "update", work);
    test.execute_slice(canister_id);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::ContinueLong
    );
    test.set_subnet_available_memory(SubnetAvailableMemory::new(0, 0, 0));
    while test.canister_state(canister_id).next_execution() == NextExecution::ContinueLong {
        test.execute_slice(canister_id);
    }
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None,
    );
    let ingress_status = test.ingress_status(&ingress_id);
    let err = check_ingress_status(ingress_status).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterOutOfMemory);
}

#[test]
fn system_state_apply_change_fails() {
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(100_000_000)
        .with_slice_instruction_limit(1_000_000)
        .with_manual_execution()
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let b = wasm()
        // The DTS must kick in.
        .instruction_counter_is_at_least(1_000_000)
        // The second slice should fail due to no memory
        .stable64_grow(1)
        .build();

    let a = wasm()
        .inter_update(
            b_id,
            call_args()
                .other_side(b)
                .on_reject(wasm().reject_message().reject()),
        )
        .build();

    let (ingress_id, _) = test.ingress_raw(a_id, "update", a);
    test.execute_message(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::None,
    );
    test.induct_messages();
    test.execute_slice(b_id);
    // No memory available after the first slice.
    test.set_subnet_available_memory(SubnetAvailableMemory::new(0, 0, 0));
    while test.canister_state(b_id).next_execution() == NextExecution::ContinueLong {
        test.execute_slice(b_id);
    }
    assert_eq!(
        test.canister_state(b_id).next_execution(),
        NextExecution::None,
    );
    test.induct_messages();
    test.execute_message(a_id);
    assert_eq!(
        test.canister_state(a_id).next_execution(),
        NextExecution::None,
    );
    let ingress_status = test.ingress_status(&ingress_id);
    let result = check_ingress_status(ingress_status).unwrap();
    match result {
        WasmResult::Reply(_) => unreachable!("Expected the canister to reject the message"),
        WasmResult::Reject(err) => {
            assert!(
                err.contains("exceeded its allowed memory allocation"),
                "{}",
                err
            );
        }
    };
}

#[test]
fn cycles_correct_if_update_fails() {
    let mut test = ExecutionTestBuilder::new().with_manual_execution().build();
    let initial_cycles = Cycles::new(1_000_000_000_000);

    // Create three canisters A, B, C.
    let a_id = test.universal_canister_with_cycles(initial_cycles).unwrap();
    let b_id = test.universal_canister_with_cycles(initial_cycles).unwrap();

    let transferred_cycles = Cycles::from(initial_cycles.get() / 2);

    // Canister B accepts all cycles, replies, and traps.
    let b = wasm()
        .accept_cycles(transferred_cycles)
        .message_payload()
        .append_and_reply()
        .trap()
        .build();

    // Canister A calls canister B and transfers cycles.
    let a = wasm()
        .call_with_cycles(
            b_id,
            "update",
            call_args().other_side(b),
            transferred_cycles,
        )
        .build();
    test.ingress_raw(a_id, "update", a);
    test.execute_message(a_id);
    test.induct_messages();
    let execution_cost_before = test.canister_execution_cost(b_id);
    test.execute_message(b_id);
    let execution_cost_after = test.canister_execution_cost(b_id);
    assert!(execution_cost_after > execution_cost_before);
    assert_eq!(
        test.canister_state(b_id).system_state.balance(),
        initial_cycles - test.canister_execution_cost(b_id)
    );
}

#[test]
fn call_with_best_effort_response_succeeds() {
    let mut test = ExecutionTestBuilder::new()
        .with_best_effort_responses(FlagStatus::Enabled)
        .build();

    let canister_id = test.universal_canister().unwrap();

    let result = test
        .ingress(
            canister_id,
            "update",
            wasm()
                .call_new(canister_id, "update", call_args())
                .call_with_best_effort_response(10)
                .call_perform()
                .reply()
                .build(),
        )
        .unwrap();

    assert_eq!(result, Reply(vec![]));
}

#[test]
fn call_with_best_effort_response_fails_when_timeout_is_set() {
    let mut test = ExecutionTestBuilder::new()
        .with_best_effort_responses(FlagStatus::Enabled)
        .build();

    let canister_id = test.universal_canister().unwrap();

    let err = test
        .ingress(
            canister_id,
            "update",
            wasm()
                .call_new(canister_id, "update", call_args())
                .call_with_best_effort_response(10)
                .call_with_best_effort_response(10)
                .build(),
        )
        .unwrap_err();

    assert!(
        err.description().contains("Canister violated contract: ic0_call_with_best_effort_response failed because a timeout is already set.")
    );

    assert_eq!(err.code(), ErrorCode::CanisterContractViolation);
}

fn call_with_best_effort_response_test_helper(
    start_time_seconds: u32,
    timeout_seconds: u32,
) -> CoarseTime {
    let mut test = ExecutionTestBuilder::new()
        .with_best_effort_responses(FlagStatus::Enabled)
        .with_manual_execution()
        .with_time(Time::from_secs_since_unix_epoch(start_time_seconds as u64).unwrap())
        .build();

    let canister_sender = test.universal_canister().unwrap();
    let canister_receiver = test.universal_canister().unwrap();

    let call_with_best_effort_response = wasm()
        .call_simple_with_cycles_and_best_effort_response(
            canister_receiver,
            "update",
            call_args(),
            Cycles::new(0),
            timeout_seconds,
        )
        .reply()
        .build();

    let _ = test.ingress_raw(canister_sender, "update", call_with_best_effort_response);

    // Execute Ingress message on `canister_sender`.
    test.execute_message(canister_sender);
    // Induct request from `canister_sender` to input queue of `canister_receiver`.
    test.induct_messages();

    match test
        .canister_state_mut(canister_receiver)
        .system_state
        .queues_mut()
        .pop_input()
        .unwrap()
    {
        CanisterMessage::Request(request) => request.deadline,
        _ => panic!("Unexpected result."),
    }
}

#[test]
fn call_with_best_effort_response_timeout_is_set_properly() {
    let start_time_seconds = 200;
    let timeout_seconds = 100;
    assert_eq!(
        call_with_best_effort_response_test_helper(start_time_seconds, timeout_seconds),
        CoarseTime::from_secs_since_unix_epoch(start_time_seconds + timeout_seconds)
    );
}

#[test]
fn call_with_best_effort_response_timeout_is_bounded() {
    let start_time_seconds = 200;
    let requested_timeout_seconds = MAX_CALL_TIMEOUT_SECONDS + 100;
    let bounded_timeout_seconds = MAX_CALL_TIMEOUT_SECONDS;
    // Verify that timeout is silently bounded by the `MAX_CALL_TIMEOUT_SECONDS`.
    assert_eq!(
        call_with_best_effort_response_test_helper(start_time_seconds, requested_timeout_seconds),
        CoarseTime::from_secs_since_unix_epoch(start_time_seconds + bounded_timeout_seconds)
    );
}

#[test]
fn ic0_msg_deadline_while_executing_ingress_message() {
    let start_time_seconds = 100;

    let mut test = ExecutionTestBuilder::new()
        .with_best_effort_responses(FlagStatus::Enabled)
        .with_time(Time::from_secs_since_unix_epoch(start_time_seconds as u64).unwrap())
        .build();

    let canister_id = test.universal_canister().unwrap();

    let msg = wasm().msg_deadline().reply_int64().build();

    match test.ingress(canister_id, "update", msg).unwrap() {
        WasmResult::Reply(result) => assert_eq!(
            Time::from(NO_DEADLINE).as_nanos_since_unix_epoch(),
            u64::from_le_bytes(result.try_into().unwrap())
        ),
        _ => panic!("Unexpected result"),
    };
}

#[test]
fn ic0_msg_deadline_when_deadline_is_not_set() {
    let start_time_seconds = 100;

    let mut test = ExecutionTestBuilder::new()
        .with_best_effort_responses(FlagStatus::Enabled)
        .with_time(Time::from_secs_since_unix_epoch(start_time_seconds as u64).unwrap())
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let msg = wasm()
        .call_simple(
            b_id,
            "update",
            call_args()
                .other_side(wasm().msg_deadline().reply_int64().build())
                .on_reply(wasm().message_payload().append_and_reply().build()),
        )
        .build();

    // Ingress message is sent to canister `A`, during its execution canister `A`
    // calls canister `B`. While executing the canister message, canister `B`
    // invokes `msg_deadline()` and attaches the result to a reply to canister `A`
    // message. Canister `A` forwards the received response as a reply to the
    // Ingress message.

    match test.ingress(a_id, "update", msg).unwrap() {
        WasmResult::Reply(result) => assert_eq!(
            Time::from(NO_DEADLINE).as_nanos_since_unix_epoch(),
            u64::from_le_bytes(result.try_into().unwrap())
        ),
        _ => panic!("Unexpected result"),
    };
}

#[test]
fn ic0_msg_deadline_when_deadline_is_set() {
    let start_time_seconds = 100;
    let timeout_seconds = 200;

    let mut test = ExecutionTestBuilder::new()
        .with_best_effort_responses(FlagStatus::Enabled)
        .with_time(Time::from_secs_since_unix_epoch(start_time_seconds as u64).unwrap())
        .build();

    let a_id = test.universal_canister().unwrap();
    let b_id = test.universal_canister().unwrap();

    let msg = wasm()
        .call_simple_with_cycles_and_best_effort_response(
            b_id,
            "update",
            call_args()
                .other_side(wasm().msg_deadline().reply_int64().build())
                .on_reply(wasm().message_payload().append_and_reply().build()),
            Cycles::new(0),
            timeout_seconds,
        )
        .build();

    // Ingress message is sent to canister `A`, during its execution canister `A`
    // calls canister `B` with `best-effort response`. While executing the canister
    // message, canister `B` invokes `msg_deadline()` and attaches the result to
    // a reply to canister `A` message. Canister `A` forwards the received response
    // as a reply to the Ingress message.

    match test.ingress(a_id, "update", msg).unwrap() {
        WasmResult::Reply(result) => assert_eq!(
            Time::from_secs_since_unix_epoch((start_time_seconds + timeout_seconds).into())
                .unwrap()
                .as_nanos_since_unix_epoch(),
            u64::from_le_bytes(result.try_into().unwrap())
        ),
        _ => panic!("Unexpected result"),
    };
}

fn display_page_map(page_map: PageMap, page_range: std::ops::Range<u64>) -> String {
    let mut contents = Vec::new();
    for page in page_range {
        contents.extend_from_slice(page_map.get_page(PageIndex::from(page)));
    }
    format!("[{}]", ic_utils::rle::display(&contents[..]))
}

// Grow memory multiple times first and write to newly added pages later.
#[test]
fn grow_memory_and_write_to_new_pages() {
    let wat = r#"
        (module
          (import "ic0" "msg_reply" (func $msg_reply))
          (import "ic0" "msg_reply_data_append"
            (func $msg_reply_data_append (param i32 i32)))
          (import "ic0" "msg_arg_data_copy"
            (func $ic0_msg_arg_data_copy (param i32) (param i32) (param i32)))

          (func $grow_by_one
            (drop (memory.grow (i32.const 1)))
            (call $msg_reply_data_append (i32.const 0) (i32.const 0))
            (call $msg_reply))

          ;; reads a byte from the beginning of a memory page
          (func $read_byte
            ;; copy the i32 page number into heap[0;4]
            (call $ic0_msg_arg_data_copy
              (i32.const 0) ;; dst
              (i32.const 0) ;; off
              (i32.const 4) ;; len
            )
            ;; copy page(n)[0;1] to heap[0;1]
            ;; we do this to make a Wasm instruction access out-of-bounds memory area and not
            ;; msg.reply system call. Both should fail but the failure path is different.
            (i32.store8
              (i32.const 4)
              (i32.load (i32.mul (i32.load (i32.const 0)) (i32.const 65536)))
            )
            (call $msg_reply_data_append
              (i32.const 4)
              (i32.const 1))
            (call $msg_reply))

          ;; writes a byte to the beginning of a memory page
          (func $write_byte
            ;; copy the i32 page number into heap[0;4]
            (call $ic0_msg_arg_data_copy
              (i32.const 0) ;; dst
              (i32.const 0) ;; off
              (i32.const 4) ;; len
            )
            ;; copy the u8 value heap[5;1]
            (call $ic0_msg_arg_data_copy
              (i32.const 4) ;; dst
              (i32.const 4) ;; off
              (i32.const 1) ;; len
            )
            (i32.store8
              ;; target address
              (i32.mul (i32.load (i32.const 0)) (i32.const 65536))
              ;; target value
              (i32.load8_u (i32.const 4))
            )
            (call $msg_reply_data_append (i32.const 0) (i32.const 0))
            (call $msg_reply))

          (global $counter (mut i32) (i32.const 10))
          (memory $memory 2 5)
          (export "canister_update grow_by_one" (func $grow_by_one))
          (export "canister_query read_byte" (func $read_byte))
          (export "canister_update write_byte" (func $write_byte))
        )"#;

    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.canister_from_wat(wat).unwrap();

    let num_pages = |n| (n * WASM_PAGE_SIZE as usize / PAGE_SIZE) as u64;

    // memory.size = 3
    test.ingress(canister_id, "grow_by_one", vec![])
        .expect("grow memory to 3");

    // memory.size = 4
    test.ingress(canister_id, "grow_by_one", vec![])
        .expect("grow memory to 4");

    // memory.size = 5
    test.ingress(canister_id, "grow_by_one", vec![])
        .expect("grow memory to 5");

    // memory.size = 5 (max limit)
    test.ingress(canister_id, "grow_by_one", vec![])
        .expect("grow memory to 6 attempt 1");
    test.ingress(canister_id, "grow_by_one", vec![])
        .expect("grow memory to 6 attempt 2");

    assert_eq!(
        display_page_map(
            test.execution_state(canister_id)
                .wasm_memory
                .page_map
                .clone(),
            0..num_pages(5)
        ),
        "[327680×00]"
    );

    let make_payload = |page_num: i32, value: u8| {
        let mut v = vec![];
        v.extend(page_num.to_le_bytes().to_vec());
        v.extend(value.to_le_bytes().to_vec());
        v
    };

    // Write to memory pages allocated to satisfy memory minimum size. We use
    // page(0) to unpack the payload so only write to page(1).
    test.ingress(canister_id, "write_byte", make_payload(1, 7))
        .unwrap();

    #[rustfmt::skip] // rustfmt breaks the explanatory comment at the bottom of this assert.
    assert_eq!(
        display_page_map(
            test.execution_state(canister_id).wasm_memory.page_map.clone(),
            0..num_pages(5)
        ),
        "[1×01 3×00 1×07 65531×00 1×07 262143×00]"
        //^^^^^^^^^^^^^^          ^^^
        //unpacked payload        value
    );

    let mut test_write_read = |page_num, value| {
        // 1. Grown memory page is zero-initialized
        let result = test
            .ingress(
                canister_id,
                "read_byte",
                i32::to_le_bytes(page_num).to_vec(),
            )
            .unwrap()
            .bytes()[0];
        assert_eq!(result, 0, "query result before write");
        // 2. Write a byte
        test.ingress(canister_id, "write_byte", make_payload(page_num, value))
            .unwrap();
        // 3. Read it back
        let result = test
            .ingress(
                canister_id,
                "read_byte",
                i32::to_le_bytes(page_num).to_vec(),
            )
            .unwrap()
            .bytes()[0];
        assert_eq!(result, value, "query result after write");
    };

    // Write data to the grown memory pages and read it back.
    test_write_read(3, 9);
    test_write_read(4, 10);
    test_write_read(2, 8);

    #[rustfmt::skip]
    assert_eq!(
        display_page_map(
            test.execution_state(canister_id).wasm_memory.page_map.clone(),
            0..num_pages(5)
        ),
        "[1×02 3×00 1×08 65531×00 1×07 65535×00 1×08 65535×00 1×09 65535×00 1×0a 65535×00]"
        //                        ^^^ page(1)   ^^^ page(2)   ^^^ page(3)   ^^^ page(4)
    );
}

#[test]
fn memory_out_of_bounds_accesses() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "stable64_grow" (func $stable64_grow (param i64) (result i64)))
            (import "ic0" "stable64_write"
                (func $stable64_write (param $offset i64) (param $src i64) (param $size i64))
            )
            (import "ic0" "stable64_read"
                (func $stable64_read (param $dst i64) (param $offset i64) (param $size i64))
            )
            (func (export "canister_init")
                (drop (call $stable64_grow (i64.const 1)))
            )
            (func (export "canister_update read_heap0")
                (drop (i32.load (i32.const 65532)))
            )
            (func (export "canister_update write_heap0")
                (i32.store (i32.const 65532) (i32.const 42))
            )
            (func (export "canister_update read_heap1")
                (drop (i32.load (i32.const 65533)))
            )
            (func (export "canister_update write_heap1")
                (i32.store (i32.const 65533) (i32.const 42))
            )
            (func (export "canister_update read_heap2")
                (drop (i32.load (i32.const 2147483647)))
            )
            (func (export "canister_update write_heap2")
                (i32.store (i32.const 2147483647) (i32.const 42))
            )
            (func (export "canister_update read_heap3")
                (drop (i32.load (i32.const -1)))
            )
            (func (export "canister_update write_heap3")
                (i32.store (i32.const -1) (i32.const 42))
            )
            (func (export "canister_update read_stable0")
                (call $stable64_read (i64.const 0) (i64.const 65532) (i64.const 4))
            )
            (func (export "canister_update write_stable0")
                (call $stable64_write (i64.const 65532) (i64.const 0) (i64.const 4))
            )
            (func (export "canister_update read_stable1")
                (call $stable64_read (i64.const 0) (i64.const 65533) (i64.const 4))
            )
            (func (export "canister_update write_stable1")
                (call $stable64_write (i64.const 65533) (i64.const 0) (i64.const 4))
            )
            (func (export "canister_update read_stable2")
                (call $stable64_read (i64.const 0) (i64.const 2147483647) (i64.const 4))
            )
            (func (export "canister_update write_stable2")
                (call $stable64_write (i64.const 2147483647) (i64.const 0) (i64.const 4))
            )
            (func (export "canister_update read_stable3")
                (call $stable64_read (i64.const 0) (i64.const -1) (i64.const 4))
            )
            (func (export "canister_update write_stable3")
                (call $stable64_write (i64.const -1) (i64.const 0) (i64.const 4))
            )
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "read_heap0", vec![]);
    assert_empty_reply(result);

    let result = test.ingress(canister_id, "write_heap0", vec![]);
    assert_empty_reply(result);

    let err = test.ingress(canister_id, "read_heap1", vec![]).unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterTrapped,
        &format!("Error from Canister {canister_id}: Canister trapped: heap out of bounds"),
    );

    let err = test
        .ingress(canister_id, "write_heap1", vec![])
        .unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterTrapped,
        &format!("Error from Canister {canister_id}: Canister trapped: heap out of bounds"),
    );

    let err = test.ingress(canister_id, "read_heap2", vec![]).unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterTrapped,
        &format!("Error from Canister {canister_id}: Canister trapped: heap out of bounds"),
    );

    let err = test
        .ingress(canister_id, "write_heap2", vec![])
        .unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterTrapped,
        &format!("Error from Canister {canister_id}: Canister trapped: heap out of bounds"),
    );

    let err = test.ingress(canister_id, "read_heap3", vec![]).unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterTrapped,
        &format!("Error from Canister {canister_id}: Canister trapped: heap out of bounds"),
    );

    let err = test
        .ingress(canister_id, "write_heap3", vec![])
        .unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterTrapped,
        &format!("Error from Canister {canister_id}: Canister trapped: heap out of bounds"),
    );

    let result = test.ingress(canister_id, "read_stable0", vec![]);
    assert_empty_reply(result);

    let result = test.ingress(canister_id, "write_stable0", vec![]);
    assert_empty_reply(result);

    let err = test
        .ingress(canister_id, "read_stable1", vec![])
        .unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterTrapped,
        &format!(
            "Error from Canister {canister_id}: Canister trapped: stable memory out of bounds"
        ),
    );

    let err = test
        .ingress(canister_id, "write_stable1", vec![])
        .unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterTrapped,
        &format!(
            "Error from Canister {canister_id}: Canister trapped: stable memory out of bounds"
        ),
    );

    let err = test
        .ingress(canister_id, "read_stable2", vec![])
        .unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterTrapped,
        &format!(
            "Error from Canister {canister_id}: Canister trapped: stable memory out of bounds"
        ),
    );

    let err = test
        .ingress(canister_id, "write_stable2", vec![])
        .unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterTrapped,
        &format!(
            "Error from Canister {canister_id}: Canister trapped: stable memory out of bounds"
        ),
    );

    let err = test
        .ingress(canister_id, "read_stable3", vec![])
        .unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterTrapped,
        &format!(
            "Error from Canister {canister_id}: Canister trapped: stable memory out of bounds"
        ),
    );
    let err = test
        .ingress(canister_id, "write_stable3", vec![])
        .unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterTrapped,
        &format!(
            "Error from Canister {canister_id}: Canister trapped: stable memory out of bounds"
        ),
    );
}

#[test]
fn division_by_zero() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32))
            )
            (func (export "canister_update div_f32")
                (f32.store (i32.const 0) (f32.div (f32.const 1) (f32.const 0)))
                (call $msg_reply_data_append (i32.const 0) (i32.const 4))
                (call $msg_reply)
            )
            (func (export "canister_update div_f64")
                (f64.store (i32.const 0) (f64.div (f64.const 1) (f64.const 0)))
                (call $msg_reply_data_append (i32.const 0) (i32.const 8))
                (call $msg_reply)
            )
            (func (export "canister_update div_u_i32")
                (drop (i32.div_u (i32.const 1) (i32.const 0)))
            )
            (func (export "canister_update div_s_i32")
                (drop (i32.div_s (i32.const -1) (i32.const 0)))
            )
            (func (export "canister_update div_u_i64")
                (drop (i64.div_u (i64.const 1) (i64.const 0)))
            )
            (func (export "canister_update div_s_i64")
                (drop (i64.div_s (i64.const -1) (i64.const 0)))
            )
            (memory 1 1)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let result = test.ingress(canister_id, "div_f32", vec![]).unwrap();
    match result {
        WasmResult::Reply(v) => {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&v);
            let res = f32::from_le_bytes(bytes);
            assert!(res.is_infinite());
        }
        WasmResult::Reject(_) => unreachable!("expected reply"),
    }

    let result = test.ingress(canister_id, "div_f64", vec![]).unwrap();
    match result {
        WasmResult::Reply(v) => {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&v);
            let res = f64::from_le_bytes(bytes);
            assert!(res.is_infinite());
        }
        WasmResult::Reject(_) => unreachable!("expected reply"),
    }

    let err = test.ingress(canister_id, "div_u_i32", vec![]).unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterTrapped,
        &format!("Error from Canister {canister_id}: Canister trapped: integer division by 0"),
    );

    let err = test.ingress(canister_id, "div_s_i32", vec![]).unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterTrapped,
        &format!("Error from Canister {canister_id}: Canister trapped: integer division by 0"),
    );

    let err = test.ingress(canister_id, "div_u_i64", vec![]).unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterTrapped,
        &format!("Error from Canister {canister_id}: Canister trapped: integer division by 0"),
    );

    let err = test.ingress(canister_id, "div_s_i64", vec![]).unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterTrapped,
        &format!("Error from Canister {canister_id}: Canister trapped: integer division by 0"),
    );
}

#[test]
#[cfg(not(all(target_arch = "aarch64", target_vendor = "apple")))]
fn charge_for_dirty_pages() {
    let mut test = ExecutionTestBuilder::new()
        .with_instruction_limit(100_000_000)
        .with_metering_type(ic_config::embedders::MeteringType::New)
        .build();
    let wat = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32))
            )
            (func $test (export "canister_update test")
                (i64.store (i32.const 0) (i64.const 17))
                (i64.store (i32.const 8) (i64.const 117))
                (call $msg_reply_data_append (i32.const 0) (i32.const 8))
                (call $msg_reply)
            )
            (func $test2 (export "canister_update test2")
                (i64.store (i32.const 0) (i64.const 27))
                (i64.store (i32.const 4096) (i64.const 227))
                (call $msg_reply_data_append (i32.const 0) (i32.const 8))
                (call $msg_reply)
            )
            (memory (export "memory") 10)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    let i0 = test.canister_executed_instructions(canister_id);
    let res = test.ingress(canister_id, "test", vec![]).unwrap();

    match res {
        WasmResult::Reply(v) => {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&v);
            let res = u64::from_le_bytes(bytes);
            assert_eq!(res, 17);
        }
        WasmResult::Reject(_) => unreachable!("expected reply"),
    }

    let i1 = test.canister_executed_instructions(canister_id);

    // we do the same as before, but touch one more page
    test.ingress(canister_id, "test2", vec![]).unwrap();
    let i2 = test.canister_executed_instructions(canister_id);

    let cdi = ic_config::subnet_config::SchedulerConfig::application_subnet().dirty_page_overhead;

    assert_eq!((i2 - i1) - (i1 - i0), cdi);

    // Run again with low message instruction limit
    // so that half of the dirty page cost gets rounded to zero
    let mut test = ExecutionTestBuilder::new()
        .with_install_code_instruction_limit(100_000_000)
        .with_instruction_limit((i1 - i0 - cdi / 2).get())
        .with_metering_type(ic_config::embedders::MeteringType::New)
        .build();

    let canister_id = test.canister_from_wat(wat).unwrap();
    let res = test.ingress(canister_id, "test", vec![]).unwrap();
    match res {
        WasmResult::Reply(v) => {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&v);
            let res = u64::from_le_bytes(bytes);
            assert_eq!(res, 17);
        }
        WasmResult::Reject(_) => unreachable!("expected reply"),
    }
    let i1a = test.canister_executed_instructions(canister_id);

    assert_eq!(i1a, i1 - cdi / 2);
}

#[test]
fn stable_grow_checks_freezing_threshold_in_update() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(1_000_000_000_000)
        .build();
    let canister_id = test.universal_canister().unwrap();
    test.update_freezing_threshold(canister_id, NumSeconds::new(1_000_000_000))
        .unwrap();
    let body = wasm().stable_grow(10_000).build();
    let err = test.ingress(canister_id, "update", body).unwrap_err();
    assert!(
        err.description()
            .contains("Canister cannot grow memory by 655360000 bytes due to insufficient cycles"),
        "Unexpected error: {}",
        err.description()
    );
    assert_eq!(err.code(), ErrorCode::InsufficientCyclesInMemoryGrow);
}

#[test]
fn stable64_grow_checks_freezing_threshold_in_update() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(1_000_000_000_000)
        .build();
    let canister_id = test.universal_canister().unwrap();
    test.update_freezing_threshold(canister_id, NumSeconds::new(1_000_000_000))
        .unwrap();
    let body = wasm().stable64_grow(10_000).build();
    let err = test.ingress(canister_id, "update", body).unwrap_err();
    assert!(
        err.description()
            .contains("Canister cannot grow memory by 655360000 bytes due to insufficient cycles"),
        "Unexpected error: {}",
        err.description()
    );
    assert_eq!(err.code(), ErrorCode::InsufficientCyclesInMemoryGrow);
}

#[test]
fn memory_grow_checks_freezing_threshold_in_update() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(1_000_000_000_000)
        .build();
    let wat = r#"
        (module
            (func (export "canister_update test")
                (drop (memory.grow (i32.const 10000)))
            )
            (memory 0)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    test.update_freezing_threshold(canister_id, NumSeconds::new(1_000_000_000))
        .unwrap();
    let err = test.ingress(canister_id, "test", vec![]).unwrap_err();
    assert!(
        err.description()
            .contains("Canister cannot grow memory by 655360000 bytes due to insufficient cycles"),
        "Unexpected error: {}",
        err.description()
    );
    assert_eq!(err.code(), ErrorCode::InsufficientCyclesInMemoryGrow);
}

#[test]
fn stable_grow_does_not_check_freezing_threshold_in_query() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(1_000_000_000_000)
        .build();
    let canister_id = test.universal_canister().unwrap();
    test.update_freezing_threshold(canister_id, NumSeconds::new(1_000_000_000))
        .unwrap();
    let body = wasm().stable_grow(10_000).build();
    let result = test.ingress(canister_id, "query", body);
    assert_empty_reply(result);
}

#[test]
fn stable64_grow_does_not_check_freezing_threshold_in_query() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(1_000_000_000_000)
        .build();
    let canister_id = test.universal_canister().unwrap();
    test.update_freezing_threshold(canister_id, NumSeconds::new(1_000_000_000))
        .unwrap();
    let body = wasm().stable64_grow(10_000).build();
    let result = test.ingress(canister_id, "query", body);
    assert_empty_reply(result);
}

#[test]
fn memory_grow_does_not_check_freezing_threshold_in_query() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(1_000_000_000_000)
        .build();
    let wat = r#"
        (module
            (func (export "canister_query test")
                (drop (memory.grow (i32.const 10000)))
            )
            (memory 0)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();
    test.update_freezing_threshold(canister_id, NumSeconds::new(1_000_000_000))
        .unwrap();
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
}

#[test]
fn stable_grow_does_not_check_freezing_threshold_in_reply() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(1_000_000_000_000)
        .build();
    let callee = test.universal_canister().unwrap();
    let canister_id = test.universal_canister().unwrap();
    test.update_freezing_threshold(canister_id, NumSeconds::new(1_000_000_000))
        .unwrap();
    let body = wasm()
        .inter_update(
            callee,
            call_args()
                .other_side(wasm().message_payload().append_and_reply())
                .on_reply(wasm().stable_grow(10_000).build()),
        )
        .build();
    let result = test.ingress(canister_id, "update", body);
    assert_empty_reply(result);
    assert_eq!(
        test.execution_state(canister_id).stable_memory.size,
        NumWasmPages::new(10_000)
    );
}

#[test]
fn stable_grow_does_not_check_freezing_threshold_in_reject() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(1_000_000_000_000)
        .build();
    let callee = test.universal_canister().unwrap();
    let canister_id = test.universal_canister().unwrap();
    test.update_freezing_threshold(canister_id, NumSeconds::new(1_000_000_000))
        .unwrap();
    let body = wasm()
        .inter_update(
            callee,
            call_args()
                .other_side(wasm().build())
                .on_reject(wasm().stable_grow(10_000).build()),
        )
        .build();
    let result = test.ingress(canister_id, "update", body);
    assert_empty_reply(result);
    assert_eq!(
        test.execution_state(canister_id).stable_memory.size,
        NumWasmPages::new(10_000)
    );
}

#[test]
fn stable_grow_checks_freezing_threshold_in_pre_upgrade() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(1_000_000_000_000)
        .build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
            (func (export "canister_pre_upgrade")
                (if (i32.ne (call $stable_grow (i32.const 10000)) (i32.const 0))
                    (then (unreachable))
                )
            )
            (memory 0)
        )"#;
    let wasm = wat::parse_str(wat).unwrap();
    let canister_id = test.canister_from_binary(wasm.clone()).unwrap();
    test.update_freezing_threshold(canister_id, NumSeconds::new(1_000_000_000))
        .unwrap();
    let err = test.upgrade_canister(canister_id, wasm).unwrap_err();
    assert!(
        err.description()
            .contains("Canister cannot grow memory by 655360000 bytes due to insufficient cycles"),
        "Unexpected error: {}",
        err.description()
    );
    assert_eq!(err.code(), ErrorCode::InsufficientCyclesInMemoryGrow);
}

#[test]
fn stable_grow_checks_freezing_threshold_in_post_upgrade() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(1_000_000_000_000)
        .build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
            (func (export "canister_post_upgrade")
                (if (i32.ne (call $stable_grow (i32.const 10000)) (i32.const 0))
                    (then (unreachable))
                )
            )
            (memory 0)
        )"#;
    let wasm = wat::parse_str(wat).unwrap();
    let canister_id = test.canister_from_binary(wasm.clone()).unwrap();
    test.update_freezing_threshold(canister_id, NumSeconds::new(1_000_000_000))
        .unwrap();
    let err = test.upgrade_canister(canister_id, wasm).unwrap_err();
    assert!(
        err.description()
            .contains("Canister cannot grow memory by 655360000 bytes due to insufficient cycles"),
        "Unexpected error: {}",
        err.description()
    );
    assert_eq!(err.code(), ErrorCode::InsufficientCyclesInMemoryGrow);
}

#[test]
fn stable_grow_checks_freezing_threshold_in_start() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(1_000_000_000_000)
        .build();
    let empty_wat = "(module)";
    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
            (func $start
                (if (i32.ne (call $stable_grow (i32.const 10000)) (i32.const 0))
                    (then (unreachable))
                )
            )
            (start $start)
            (memory 0)
        )"#;
    let wasm = wat::parse_str(wat).unwrap();
    let canister_id = test.canister_from_wat(empty_wat).unwrap();
    test.update_freezing_threshold(canister_id, NumSeconds::new(1_000_000_000))
        .unwrap();
    let err = test.upgrade_canister(canister_id, wasm).unwrap_err();
    assert!(
        err.description().contains("Canister cannot grow memory by"),
        "Unexpected error: {}",
        err.description()
    );
    assert_eq!(err.code(), ErrorCode::InsufficientCyclesInMemoryGrow);
}

#[test]
fn stable_grow_checks_freezing_threshold_in_init() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(1_000_000_000_000)
        .build();
    let wat = r#"
        (module
            (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
            (func (export "canister_init")
                (if (i32.ne (call $stable_grow (i32.const 10000)) (i32.const 0))
                    (then (unreachable))
                )
            )
            (memory 0)
        )"#;
    let wasm = wat::parse_str(wat).unwrap();
    let canister_id = test.create_canister(Cycles::new(1_000_000_000_000));
    test.update_freezing_threshold(canister_id, NumSeconds::new(1_000_000_000))
        .unwrap();
    let err = test.install_canister(canister_id, wasm).unwrap_err();
    assert!(
        err.description().contains("Canister cannot grow memory by"),
        "Unexpected error: {}",
        err.description()
    );
    assert_eq!(err.code(), ErrorCode::InsufficientCyclesInMemoryGrow);
}

#[test]
fn memory_grow_does_not_check_freezing_threshold_in_pre_upgrade() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(1_000_000_000_000)
        .build();
    let wat = r#"
        (module
            (func (export "canister_pre_upgrade")
                (if (i32.ne (memory.grow (i32.const 10000)) (i32.const 0))
                    (then (unreachable))
                )
            )
            (memory 0)
        )"#;
    let wasm = wat::parse_str(wat).unwrap();
    let canister_id = test.canister_from_binary(wasm.clone()).unwrap();
    test.update_freezing_threshold(canister_id, NumSeconds::new(1_000_000_000))
        .unwrap();
    test.upgrade_canister(canister_id, wasm).unwrap();
}

#[test]
fn memory_grow_checks_freezing_threshold_in_post_upgrade() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(1_000_000_000_000)
        .build();
    let wat = r#"
        (module
            (func (export "canister_post_upgrade")
                (if (i32.ne (memory.grow (i32.const 10000)) (i32.const 0))
                    (then (unreachable))
                )
            )
            (memory 0)
        )"#;
    let wasm = wat::parse_str(wat).unwrap();
    let canister_id = test.canister_from_binary(wasm.clone()).unwrap();
    test.update_freezing_threshold(canister_id, NumSeconds::new(1_000_000_000))
        .unwrap();
    let err = test.upgrade_canister(canister_id, wasm).unwrap_err();
    assert!(
        err.description()
            .contains("Canister cannot grow memory by 655360000 bytes due to insufficient cycles"),
        "Unexpected error: {}",
        err.description()
    );
    assert_eq!(err.code(), ErrorCode::InsufficientCyclesInMemoryGrow);
}

#[test]
fn memory_grow_checks_freezing_threshold_in_start() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(1_000_000_000_000)
        .build();
    let empty_wat = "(module)";
    let wat = r#"
        (module
            (func $start
                (if (i32.ne (memory.grow (i32.const 10000)) (i32.const 0))
                    (then (unreachable))
                )
            )
            (start $start)
            (memory 0)
        )"#;
    let wasm = wat::parse_str(wat).unwrap();
    let canister_id = test.canister_from_wat(empty_wat).unwrap();
    test.update_freezing_threshold(canister_id, NumSeconds::new(1_000_000_000))
        .unwrap();
    let err = test.upgrade_canister(canister_id, wasm).unwrap_err();
    assert!(
        err.description().contains("Canister cannot grow memory by"),
        "Unexpected error: {}",
        err.description()
    );
    assert_eq!(err.code(), ErrorCode::InsufficientCyclesInMemoryGrow);
}

#[test]
fn memory_grow_checks_freezing_threshold_in_init() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(1_000_000_000_000)
        .build();
    let wat = r#"
        (module
            (func (export "canister_init")
                (if (i32.ne (memory.grow (i32.const 10000)) (i32.const 0))
                    (then (unreachable))
                )
            )
            (memory 0)
        )"#;
    let wasm = wat::parse_str(wat).unwrap();
    let canister_id = test.create_canister(Cycles::new(1_000_000_000_000));
    test.update_freezing_threshold(canister_id, NumSeconds::new(1_000_000_000))
        .unwrap();
    let err = test.install_canister(canister_id, wasm).unwrap_err();
    assert!(
        err.description().contains("Canister cannot grow memory by"),
        "Unexpected error: {}",
        err.description()
    );
    assert_eq!(err.code(), ErrorCode::InsufficientCyclesInMemoryGrow);
}

#[test]
fn call_perform_checks_freezing_threshold_in_update() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(1_000_000_000_000)
        .build();
    let canister_id = test.universal_canister().unwrap();
    test.update_freezing_threshold(canister_id, NumSeconds::new(1_500_000_000))
        .unwrap();
    let body = wasm()
        .call_simple(
            canister_id,
            "update",
            call_args().other_side(wasm().message_payload().reply().build()),
        )
        .build();
    let err = test.ingress(canister_id, "update", body).unwrap_err();
    assert!(
        err.description().contains("call_perform failed"),
        "Unexpected error: {}",
        err.description()
    );
    assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
}

#[test]
fn call_perform_does_not_check_freezing_threshold_in_reply() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(1_000_000_000_000)
        .build();
    let callee = test.universal_canister().unwrap();
    let canister_id = test.universal_canister().unwrap();
    test.update_freezing_threshold(canister_id, NumSeconds::new(1_200_000_000))
        .unwrap();
    let body = wasm()
        .call_simple(
            callee,
            "update",
            call_args()
                .other_side(wasm().message_payload().append_and_reply().build())
                .on_reply(
                    wasm()
                        .call_simple(
                            callee,
                            "update",
                            call_args().other_side(wasm().stable_grow(10_000).reply().build()),
                        )
                        .build(),
                ),
        )
        .build();
    let result = test.ingress(canister_id, "update", body);
    assert_eq!(result, Ok(WasmResult::Reply(vec![])));
    assert_eq!(
        test.execution_state(callee).stable_memory.size,
        NumWasmPages::new(10_000)
    );
}

#[test]
fn call_perform_does_not_check_freezing_threshold_in_reject() {
    let mut test = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(1_000_000_000_000)
        .build();
    let callee = test.universal_canister().unwrap();
    let canister_id = test.universal_canister().unwrap();
    test.update_freezing_threshold(canister_id, NumSeconds::new(1_200_000_000))
        .unwrap();
    let body = wasm()
        .call_simple(
            callee,
            "update",
            call_args()
                .other_side(wasm().message_payload().reject().build())
                .on_reject(
                    wasm()
                        .call_simple(
                            callee,
                            "update",
                            call_args().other_side(wasm().stable_grow(10_000).reply().build()),
                        )
                        .build(),
                ),
        )
        .build();
    let result = test.ingress(canister_id, "update", body);
    assert_eq!(result, Ok(WasmResult::Reply(vec![])));
    assert_eq!(
        test.execution_state(callee).stable_memory.size,
        NumWasmPages::new(10_000)
    );
}

#[test]
fn memory_grow_succeeds_in_init_if_canister_has_memory_allocation() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_init")
                (if (i32.ne (memory.grow (i32.const 10000)) (i32.const 0))
                    (then (unreachable))
                )
            )
            (memory 0)
        )"#;
    let wasm = wat::parse_str(wat).unwrap();
    let empty_memory_usage = {
        let id = test.canister_from_binary(wasm.clone()).unwrap();
        test.canister_state(id).memory_usage()
    };
    let freezing_threshold = NumSeconds::new(1_000_000_000);
    let memory_allocation = 655360000 + empty_memory_usage.get();
    let freezing_threshold_cycles = test.cycles_account_manager().freeze_threshold_cycles(
        freezing_threshold,
        ic_types::MemoryAllocation::Reserved(NumBytes::new(memory_allocation)),
        NumBytes::new(0),
        NumBytes::new(0),
        ComputeAllocation::zero(),
        test.subnet_size(),
        Cycles::zero(),
    );

    // Overapproximation of the install code message cost.
    let install_code_cost = Cycles::new(1_000_000_000_000);

    // Install code should be a small fraction of the freezing threshold cycles.
    // If that's not the case, then we need to increase the freezing threshold.
    assert!(install_code_cost.get() < freezing_threshold_cycles.get() / 10);
    let initial_balance = freezing_threshold_cycles + install_code_cost;
    let canister_id = test
        .create_canister_with_allocation(initial_balance, None, Some(memory_allocation))
        .unwrap();
    test.update_freezing_threshold(canister_id, freezing_threshold)
        .unwrap();
    test.install_canister(canister_id, wasm).unwrap();
}

#[test]
fn memory_grow_succeeds_in_post_upgrade_if_the_same_amount_is_dropped_after_pre_upgrade() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_init")
                (if (i32.ne (memory.grow (i32.const 10000)) (i32.const 0))
                    (then (unreachable))
                )
            )
            (func (export "canister_post_upgrade")
                (if (i32.ne (memory.grow (i32.const 10000)) (i32.const 0))
                    (then (unreachable))
                )
            )
            (memory 0)
        )"#;
    let wasm = wat::parse_str(wat).unwrap();
    let freezing_threshold = NumSeconds::new(1_000_000_000);
    let memory_usage = 655_360_000 + 1_000_000;
    let freezing_threshold_cycles = test.cycles_account_manager().freeze_threshold_cycles(
        freezing_threshold,
        ic_types::MemoryAllocation::BestEffort,
        NumBytes::new(memory_usage),
        NumBytes::new(0),
        ComputeAllocation::zero(),
        test.subnet_size(),
        Cycles::zero(),
    );

    // Overapproximation of the install code message cost.
    let install_code_cost = Cycles::new(1_000_000_000_000);

    let initial_cycles = freezing_threshold_cycles + install_code_cost;

    let canister_id = test
        .canister_from_cycles_and_binary(initial_cycles, wasm.clone())
        .unwrap();

    test.upgrade_canister(canister_id, wasm).unwrap();
}

#[test]
fn stable_memory_grow_reserves_cycles() {
    const CYCLES: Cycles = Cycles::new(20_000_000_000_000);
    const CAPACITY: u64 = 1_000_000_000;
    const THRESHOLD: u64 = 500_000_000;
    const WASM_PAGE_SIZE: u64 = 65_536;
    // 7500 of stable memory pages is close to 500MB, but still leaves some room
    // for Wasm memory of the universal canister.
    const NUM_PAGES: u64 = 7_500;

    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory(CAPACITY as i64)
        .with_subnet_memory_threshold(THRESHOLD as i64)
        .with_subnet_memory_reservation(0)
        .build();

    let canister_id = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.into())
        .unwrap();

    test.update_freezing_threshold(canister_id, NumSeconds::new(0))
        .unwrap();
    test.canister_update_reserved_cycles_limit(canister_id, CYCLES)
        .unwrap();

    let balance_before = test.canister_state(canister_id).system_state.balance();
    let result = test
        .ingress(
            canister_id,
            "update",
            wasm()
                .stable64_grow(NUM_PAGES)
                // Access the last byte to make sure that growing succeeded.
                .stable64_read(NUM_PAGES * WASM_PAGE_SIZE - 1, 1)
                .push_bytes(&[])
                .append_and_reply()
                .build(),
        )
        .unwrap();
    assert_eq!(result, WasmResult::Reply(vec![]));
    let balance_after = test.canister_state(canister_id).system_state.balance();

    assert_eq!(
        test.canister_state(canister_id)
            .system_state
            .reserved_balance(),
        Cycles::zero()
    );
    // Message execution fee is an order of a few million cycles.
    assert!(balance_before - balance_after < Cycles::new(1_000_000_000));

    let subnet_memory_usage =
        CAPACITY - test.subnet_available_memory().get_execution_memory() as u64;
    let memory_usage_before = test.canister_state(canister_id).execution_memory_usage();
    let balance_before = test.canister_state(canister_id).system_state.balance();
    let result = test
        .ingress(
            canister_id,
            "update",
            wasm()
                .stable64_grow(NUM_PAGES)
                // Access the last byte to make sure that growing succeeded.
                .stable64_read(2 * NUM_PAGES * WASM_PAGE_SIZE - 1, 1)
                .push_bytes(&[])
                .append_and_reply()
                .build(),
        )
        .unwrap();
    assert_eq!(result, WasmResult::Reply(vec![]));
    let balance_after = test.canister_state(canister_id).system_state.balance();
    let memory_usage_after = test.canister_state(canister_id).execution_memory_usage();

    let reserved_cycles = test
        .canister_state(canister_id)
        .system_state
        .reserved_balance();

    assert_eq!(
        reserved_cycles,
        test.cycles_account_manager().storage_reservation_cycles(
            memory_usage_after - memory_usage_before,
            &ResourceSaturation::new(subnet_memory_usage, THRESHOLD, CAPACITY),
            test.subnet_size(),
        )
    );

    assert!(balance_before - balance_after > reserved_cycles);
}

#[test]
fn wasm_memory_grow_reserves_cycles() {
    const CYCLES: Cycles = Cycles::new(20_000_000_000_000);
    const CAPACITY: u64 = 1_000_000_000;
    const THRESHOLD: u64 = 500_000_000;

    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory(CAPACITY as i64)
        .with_subnet_memory_threshold(THRESHOLD as i64)
        .with_subnet_memory_reservation(0)
        .build();

    let wat = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))
            (func $update
                ;; 7500 Wasm pages is close to 500MB.
                (if (i32.eq (memory.grow (i32.const 7500)) (i32.const -1))
                  (then (unreachable))
                )
                (call $msg_reply)
            )
            (memory $memory 1)
            (export "canister_update update" (func $update))
        )"#;

    let wasm = wat::parse_str(wat).unwrap();

    let canister_id = test.canister_from_cycles_and_binary(CYCLES, wasm).unwrap();

    test.update_freezing_threshold(canister_id, NumSeconds::new(0))
        .unwrap();
    test.canister_update_reserved_cycles_limit(canister_id, CYCLES)
        .unwrap();

    let balance_before = test.canister_state(canister_id).system_state.balance();
    let result = test.ingress(canister_id, "update", vec![]).unwrap();
    assert_eq!(result, WasmResult::Reply(vec![]));
    let balance_after = test.canister_state(canister_id).system_state.balance();

    assert_eq!(
        test.canister_state(canister_id)
            .system_state
            .reserved_balance(),
        Cycles::zero()
    );
    // Message execution fee is an order of a few million cycles.
    assert!(balance_before - balance_after < Cycles::new(1_000_000_000));

    let subnet_memory_usage =
        CAPACITY - test.subnet_available_memory().get_execution_memory() as u64;
    let memory_usage_before = test.canister_state(canister_id).execution_memory_usage();
    let balance_before = test.canister_state(canister_id).system_state.balance();
    let result = test.ingress(canister_id, "update", vec![]).unwrap();
    assert_eq!(result, WasmResult::Reply(vec![]));
    let balance_after = test.canister_state(canister_id).system_state.balance();
    let memory_usage_after = test.canister_state(canister_id).execution_memory_usage();

    let reserved_cycles = test
        .canister_state(canister_id)
        .system_state
        .reserved_balance();

    assert_eq!(
        reserved_cycles,
        test.cycles_account_manager().storage_reservation_cycles(
            memory_usage_after - memory_usage_before,
            &ResourceSaturation::new(subnet_memory_usage, THRESHOLD, CAPACITY),
            test.subnet_size(),
        )
    );

    assert!(balance_before - balance_after > reserved_cycles);
}

#[test]
fn set_reserved_cycles_limit_below_existing_fails() {
    const CYCLES: Cycles = Cycles::new(20_000_000_000_000);
    const CAPACITY: u64 = 1_000_000_000;
    const THRESHOLD: u64 = 500_000_000;

    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory(CAPACITY as i64)
        .with_subnet_memory_threshold(THRESHOLD as i64)
        .with_subnet_memory_reservation(0)
        .build();

    let wat = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))
            (func $update
                ;; 7500 Wasm pages is close to 500MB.
                (if (i32.eq (memory.grow (i32.const 7500)) (i32.const -1))
                  (then (unreachable))
                )
                (call $msg_reply)
            )
            (memory $memory 1)
            (export "canister_update update" (func $update))
        )"#;

    let wasm = wat::parse_str(wat).unwrap();

    let canister_id = test.canister_from_cycles_and_binary(CYCLES, wasm).unwrap();

    test.update_freezing_threshold(canister_id, NumSeconds::new(0))
        .unwrap();
    test.canister_update_reserved_cycles_limit(canister_id, CYCLES)
        .unwrap();

    let balance_before = test.canister_state(canister_id).system_state.balance();
    let result = test.ingress(canister_id, "update", vec![]).unwrap();
    assert_eq!(result, WasmResult::Reply(vec![]));
    let balance_after = test.canister_state(canister_id).system_state.balance();

    assert_eq!(
        test.canister_state(canister_id)
            .system_state
            .reserved_balance(),
        Cycles::zero()
    );
    // Message execution fee is an order of a few million cycles.
    assert!(balance_before - balance_after < Cycles::new(1_000_000_000));

    let subnet_memory_usage =
        CAPACITY - test.subnet_available_memory().get_execution_memory() as u64;
    let memory_usage_before = test.canister_state(canister_id).execution_memory_usage();
    let balance_before = test.canister_state(canister_id).system_state.balance();
    let result = test.ingress(canister_id, "update", vec![]).unwrap();
    assert_eq!(result, WasmResult::Reply(vec![]));
    let balance_after = test.canister_state(canister_id).system_state.balance();
    let memory_usage_after = test.canister_state(canister_id).execution_memory_usage();

    let reserved_cycles = test
        .canister_state(canister_id)
        .system_state
        .reserved_balance();

    assert_eq!(
        reserved_cycles,
        test.cycles_account_manager().storage_reservation_cycles(
            memory_usage_after - memory_usage_before,
            &ResourceSaturation::new(subnet_memory_usage, THRESHOLD, CAPACITY),
            test.subnet_size(),
        )
    );

    assert!(balance_before - balance_after > reserved_cycles);

    let err = test
        .canister_update_reserved_cycles_limit(canister_id, Cycles::from(reserved_cycles.get() - 1))
        .unwrap_err();

    assert_eq!(err.code(), ErrorCode::ReservedCyclesLimitIsTooLow);
}

#[test]
fn upgrade_with_skip_pre_upgrade_preserves_stable_memory() {
    let mut test: ExecutionTest = ExecutionTestBuilder::new().build();
    let wat = format!(
        r#"(module
            {}
            (func (export "canister_init")
                (drop (call $stable_grow (i32.const 1)))
            )
            (func (export "canister_pre_upgrade")
                unreachable
            )
            (memory 1)
            (data (i32.const 0) "abcd")  ;; Initial contents of the heap.
        )"#,
        STABLE_MEMORY_WAT
    );
    let canister_id = test.canister_from_wat(wat.clone()).unwrap();
    let result = test.ingress(canister_id, "write", vec![]);
    assert_empty_reply(result);
    let result = test.ingress(canister_id, "read", vec![]);
    assert_eq!(result, Ok(WasmResult::Reply("abcd".as_bytes().to_vec())));

    // Check that the upgrade of the canister succeeds if pre_upgrade is skipped.
    test.upgrade_canister_v2(
        canister_id,
        wat::parse_str(wat.clone()).unwrap(),
        CanisterUpgradeOptions {
            skip_pre_upgrade: Some(true),
            wasm_memory_persistence: None,
        },
    )
    .unwrap();

    // Check that the canister traps if the pre_upgrade is executed.
    let err = test
        .upgrade_canister_v2(
            canister_id,
            wat::parse_str(wat).unwrap(),
            CanisterUpgradeOptions {
                skip_pre_upgrade: Some(false),
                wasm_memory_persistence: None,
            },
        )
        .unwrap_err();
    assert_eq!(ErrorCode::CanisterTrapped, err.code());

    let result = test.ingress(canister_id, "read", vec![]);
    assert_eq!(result, Ok(WasmResult::Reply("abcd".as_bytes().to_vec())));
}

#[test]
fn resource_saturation_scaling_works_in_regular_execution() {
    const CYCLES: Cycles = Cycles::new(20_000_000_000_000);
    const CAPACITY: u64 = 1_000_000_000;
    const THRESHOLD: u64 = 500_000_000;
    const SCALING: u64 = 4;

    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory(CAPACITY as i64)
        .with_subnet_memory_threshold(THRESHOLD as i64)
        .with_subnet_memory_reservation(0)
        .with_resource_saturation_scaling(SCALING as usize)
        .build();

    test.create_canister_with_allocation(CYCLES, None, Some(THRESHOLD / SCALING))
        .unwrap();

    let wat = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))
            (func $update
                ;; 7500 Wasm pages is close to 500MB.
                (if (i32.eq (memory.grow (i32.const 7500)) (i32.const -1))
                  (then (unreachable))
                )
                (call $msg_reply)
            )
            (memory $memory 1)
            (export "canister_update update" (func $update))
        )"#;

    let wasm = wat::parse_str(wat).unwrap();

    let canister_id = test.canister_from_cycles_and_binary(CYCLES, wasm).unwrap();

    test.update_freezing_threshold(canister_id, NumSeconds::new(0))
        .unwrap();
    test.canister_update_reserved_cycles_limit(canister_id, CYCLES)
        .unwrap();

    let subnet_memory_usage =
        CAPACITY - test.subnet_available_memory().get_execution_memory() as u64;
    let memory_usage_before = test.canister_state(canister_id).execution_memory_usage();
    let balance_before = test.canister_state(canister_id).system_state.balance();
    let result = test.ingress(canister_id, "update", vec![]).unwrap();
    assert_eq!(result, WasmResult::Reply(vec![]));
    let balance_after = test.canister_state(canister_id).system_state.balance();
    let memory_usage_after = test.canister_state(canister_id).execution_memory_usage();

    let reserved_cycles = test
        .canister_state(canister_id)
        .system_state
        .reserved_balance();

    assert_eq!(
        reserved_cycles,
        test.cycles_account_manager().storage_reservation_cycles(
            memory_usage_after - memory_usage_before,
            &ResourceSaturation::new(
                subnet_memory_usage / SCALING,
                THRESHOLD / SCALING,
                CAPACITY / SCALING
            ),
            test.subnet_size(),
        )
    );

    assert!(balance_before - balance_after > reserved_cycles);
}

#[test]
fn wasm_memory_grow_respects_reserved_cycles_limit() {
    const CYCLES: Cycles = Cycles::new(20_000_000_000_000);
    const CAPACITY: u64 = 1_000_000_000;

    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory(CAPACITY as i64)
        .with_subnet_memory_threshold(0)
        .with_subnet_memory_reservation(0)
        .build();

    let wat = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))
            (func $update
                ;; 7500 Wasm pages is close to 500MB.
                (if (i32.eq (memory.grow (i32.const 7500)) (i32.const -1))
                  (then (unreachable))
                )
                (call $msg_reply)
            )
            (memory $memory 1)
            (export "canister_update update" (func $update))
        )"#;

    let wasm = wat::parse_str(wat).unwrap();

    let canister_id = test.canister_from_cycles_and_binary(CYCLES, wasm).unwrap();

    test.update_freezing_threshold(canister_id, NumSeconds::new(0))
        .unwrap();

    test.canister_state_mut(canister_id)
        .system_state
        .set_reserved_balance_limit(Cycles::new(1));

    let err = test.ingress(canister_id, "update", vec![]).unwrap_err();

    assert_eq!(
        err.code(),
        ErrorCode::ReservedCyclesLimitExceededInMemoryGrow
    );
    assert!(err.description().contains("Canister cannot grow memory by"));
    assert!(err
        .description()
        .contains("due to its reserved cycles limit"));
}

#[test]
fn stable_memory_grow_respects_reserved_cycles_limit() {
    const CYCLES: Cycles = Cycles::new(20_000_000_000_000);
    const CAPACITY: u64 = 1_000_000_000;
    // The threshold should be large enough to allow the universal canister to
    // allocate Wasm memory before it starts allocating the stable memory.
    const THRESHOLD: u64 = 10_000_000;

    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory(CAPACITY as i64)
        .with_subnet_memory_threshold(THRESHOLD as i64)
        .with_subnet_memory_reservation(0)
        .build();

    let canister_id = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.into())
        .unwrap();

    test.update_freezing_threshold(canister_id, NumSeconds::new(0))
        .unwrap();

    test.canister_state_mut(canister_id)
        .system_state
        .set_reserved_balance_limit(Cycles::new(1));

    let err = test
        .ingress(
            canister_id,
            "update",
            wasm()
                .stable64_grow(7_500)
                .push_bytes(&[])
                .append_and_reply()
                .build(),
        )
        .unwrap_err();

    assert_eq!(
        err.code(),
        ErrorCode::ReservedCyclesLimitExceededInMemoryGrow
    );
    assert!(err.description().contains("Canister cannot grow memory by"));
    assert!(err
        .description()
        .contains("due to its reserved cycles limit"));
}

#[test]
fn stable_memory_grow_does_not_reserve_cycles_on_out_of_memory() {
    const CYCLES: Cycles = Cycles::new(200_000_000_000_000);
    const CAPACITY: u64 = 1_000_000_000;
    const THRESHOLD: u64 = CAPACITY / 2;

    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory(CAPACITY as i64)
        .with_subnet_memory_threshold(THRESHOLD as i64)
        .with_subnet_memory_reservation(0)
        .build();

    let canister_id = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.into())
        .unwrap();
    test.update_freezing_threshold(canister_id, NumSeconds::new(0))
        .unwrap();

    let reserved_cycles_before = test
        .canister_state(canister_id)
        .system_state
        .reserved_balance();
    test.ingress(
        canister_id,
        "update",
        wasm()
            // 16_000 Wasm pages is more than the 1GB capacity, so this
            // operation will fail with out-of-memory. However, the entire
            // execution still succeeds.
            .stable64_grow(16_000)
            .push_bytes(&[])
            .append_and_reply()
            .build(),
    )
    .unwrap();
    let reserved_cycles_after = test
        .canister_state(canister_id)
        .system_state
        .reserved_balance();
    assert_eq!(reserved_cycles_before, reserved_cycles_after);
}

fn generate_wat_to_touch_pages(pages_to_touch: usize) -> String {
    format!(
        r#"
    (module
        (import "ic0" "msg_reply" (func $msg_reply))
        (import "ic0" "msg_reply_data_append" (func $msg_reply_data_append (param i32 i32)))
        (func (export "canister_update test")
          (local $j i32)
          (loop $my_loop
            ;; add one OS page to $j
            local.get $j
            i32.const 4096
            i32.add
            local.set $j
            ;; store 1 to heap[$j]
            (i32.store (local.get $j) (i32.const 1))
            ;; loop if $j is less than number of OS pages that we want to touch
            local.get $j
            i32.const {bytes_to_touch}
            i32.lt_s
            br_if $my_loop
          )
          (call $msg_reply_data_append
                          (i32.const 0)
                          (i32.const 8))
          (call $msg_reply)
        )
        (memory $memory 128)
      )"#,
        bytes_to_touch = pages_to_touch * 4096
    )
}

#[test]
#[cfg(not(all(target_arch = "aarch64", target_vendor = "apple")))]
fn yield_triggers_dts_slice_with_many_dirty_pages() {
    let pages_to_touch = 100;
    let wat = generate_wat_to_touch_pages(pages_to_touch);

    const CYCLES: Cycles = Cycles::new(20_000_000_000_000);

    let mut test = ExecutionTestBuilder::new()
        .with_manual_execution()
        .with_max_dirty_pages_optimization_embedder_config(pages_to_touch - 1)
        .build();

    let wasm = wat::parse_str(wat).unwrap();
    let canister_id = test.canister_from_cycles_and_binary(CYCLES, wasm).unwrap();

    let _result = test.ingress_raw(canister_id, "test", vec![]);

    // The test touches `pages_to_touch`, but the embedder is configured to yield when `pages_to_touch - 1` pages are dirty.
    // Therefore, we should have two slices here.
    test.execute_slice(canister_id);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::ContinueLong
    );
    test.execute_slice(canister_id);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None
    );
}

#[test]
fn yield_does_not_trigger_dts_slice_without_enough_dirty_pages() {
    let pages_to_touch = 100;
    let wat = generate_wat_to_touch_pages(pages_to_touch);

    const CYCLES: Cycles = Cycles::new(20_000_000_000_000);

    let mut test = ExecutionTestBuilder::new()
        .with_manual_execution()
        .with_max_dirty_pages_optimization_embedder_config(pages_to_touch + 1)
        .build();

    let wasm = wat::parse_str(wat).unwrap();
    let canister_id = test.canister_from_cycles_and_binary(CYCLES, wasm).unwrap();

    let _result = test.ingress_raw(canister_id, "test", vec![]);

    // The test touches `pages_to_touch`, but the embedder is configured to yield when `pages_to_touch + 1` pages are dirty.
    // Therefore, we should have only 1 slice here.
    test.execute_slice(canister_id);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None
    );
}

#[test]
#[cfg(not(all(target_arch = "aarch64", target_vendor = "apple")))]
fn yield_abort_does_not_modify_state() {
    let pages_to_touch = 100;
    let wat = generate_wat_to_touch_pages(pages_to_touch);

    const CYCLES: Cycles = Cycles::new(20_000_000_000_000);

    let mut test = ExecutionTestBuilder::new()
        .with_manual_execution()
        .with_max_dirty_pages_optimization_embedder_config(pages_to_touch - 1)
        .build();

    let wasm = wat::parse_str(wat).unwrap();
    let canister_id = test.canister_from_cycles_and_binary(CYCLES, wasm).unwrap();

    let _result = test.ingress_raw(canister_id, "test", vec![]);

    // The test touches `pages_to_touch`, but the embedder is configured to yield when `pages_to_touch - 1` pages are dirty.
    // Therefore, we should have 2 slices here.
    test.execute_slice(canister_id);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::ContinueLong
    );
    // Abort before executing the last slice.
    test.abort_all_paused_executions();

    // Test that the abort means the canister's state is not modified.
    let mut dirty_pages = test
        .execution_state(canister_id)
        .wasm_memory
        .page_map
        .delta_pages_iter()
        .count();

    assert_eq!(dirty_pages, 0);

    // Start execution from scratch, let the slices execute fully and check dirty pages again.
    test.execute_slice(canister_id);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::ContinueLong
    );
    test.execute_slice(canister_id);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None
    );
    dirty_pages += test
        .execution_state(canister_id)
        .wasm_memory
        .page_map
        .delta_pages_iter()
        .count();
    // This time the dirty pages should be equal to `pages_to_touch`.
    assert_eq!(dirty_pages, pages_to_touch);
}

#[test]
#[cfg(not(all(target_arch = "aarch64", target_vendor = "apple")))]
fn yield_for_dirty_page_copy_triggers_dts_slice_with_many_pages_on_system_subnets() {
    let pages_to_touch = 100;
    let wat = generate_wat_to_touch_pages(pages_to_touch);

    const CYCLES: Cycles = Cycles::new(20_000_000_000_000);

    let mut test = ExecutionTestBuilder::new()
        .with_subnet_type(SubnetType::System)
        .with_slice_instruction_limit(
            SchedulerConfig::system_subnet()
                .max_instructions_per_slice
                .get(),
        )
        .with_instruction_limit(
            SchedulerConfig::system_subnet()
                .max_instructions_per_message
                .get(),
        )
        .with_manual_execution()
        .with_max_dirty_pages_optimization_embedder_config(pages_to_touch - 1)
        .build();

    let wasm = wat::parse_str(wat).unwrap();
    let canister_id = test.canister_from_cycles_and_binary(CYCLES, wasm).unwrap();

    let _result = test.ingress_raw(canister_id, "test", vec![]);

    // The test touches `pages_to_touch`, but the embedder is configured to yield when `pages_to_touch - 1` pages are dirty.
    // Therefore we should have two slices here.
    test.execute_slice(canister_id);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::ContinueLong
    );
    test.execute_slice(canister_id);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None
    );
}

#[test]
fn yield_for_dirty_page_copy_does_not_trigger_dts_slice_without_enough_dirty_pages_on_system_subnets(
) {
    let pages_to_touch = 100;
    let wat = generate_wat_to_touch_pages(pages_to_touch);

    const CYCLES: Cycles = Cycles::new(20_000_000_000_000);

    let mut test = ExecutionTestBuilder::new()
        .with_subnet_type(SubnetType::System)
        .with_slice_instruction_limit(
            SchedulerConfig::system_subnet()
                .max_instructions_per_slice
                .get(),
        )
        .with_instruction_limit(
            SchedulerConfig::system_subnet()
                .max_instructions_per_message
                .get(),
        )
        .with_manual_execution()
        .with_max_dirty_pages_optimization_embedder_config(pages_to_touch + 1)
        .build();

    let wasm = wat::parse_str(wat).unwrap();
    let canister_id = test.canister_from_cycles_and_binary(CYCLES, wasm).unwrap();

    let _result = test.ingress_raw(canister_id, "test", vec![]);

    // The test touches `pages_to_touch`, but the embedder is configured to yield when `pages_to_touch + 1` pages are dirty.
    // Therefore we should have only one slice here.
    test.execute_slice(canister_id);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None
    );
}

#[test]
fn yield_for_dirty_page_copy_does_not_trigger_on_system_subnets_without_dts() {
    let pages_to_touch = 100;
    let wat = generate_wat_to_touch_pages(pages_to_touch);

    const CYCLES: Cycles = Cycles::new(20_000_000_000_000);

    let mut test = ExecutionTestBuilder::new()
        .with_deterministic_time_slicing_disabled()
        .with_subnet_type(SubnetType::System)
        .with_manual_execution()
        .with_max_dirty_pages_optimization_embedder_config(pages_to_touch - 1)
        .build();

    let wasm = wat::parse_str(wat).unwrap();
    let canister_id = test.canister_from_cycles_and_binary(CYCLES, wasm).unwrap();

    let _result = test.ingress_raw(canister_id, "test", vec![]);

    // The test touches `pages_to_touch`, but the embedder is configured to yield when `pages_to_touch - 1` pages are dirty.
    // This should not happen for system subnets.
    test.execute_slice(canister_id);
    assert_eq!(
        test.canister_state(canister_id).next_execution(),
        NextExecution::None
    );
}

#[test]
fn declaring_too_many_tables_fails() {
    let wat = format!("(module {})", "(table 0 externref)".repeat(100));
    let mut test = ExecutionTestBuilder::new().build();
    let err = test.canister_from_wat(wat).unwrap_err();
    assert_eq!(ErrorCode::CanisterWasmEngineError, err.code());
    assert!(err.description().contains("table count too high"));
}

// Forces the universal canister to use at least `bytes` of Wasm memory and
// produces a reply from `bytes`.
fn use_wasm_memory_and_reply(bytes: u64) -> Vec<u8> {
    wasm()
        .stable64_grow(
            (bytes + WASM_PAGE_SIZE_IN_BYTES as u64 - 1) / WASM_PAGE_SIZE_IN_BYTES as u64,
        )
        .stable64_read(0, bytes)
        .blob_length()
        .reply_int()
        .build()
}

/// Sets the `wasm_memory_limit` of the given canister to its current memory
/// usage plus the given allowance:
/// - `wasm_memory_limit = wasm_memory_usage + allowance`
fn set_wasm_memory_limit(test: &mut ExecutionTest, canister_id: CanisterId, allowance: NumBytes) {
    let wasm_memory_usage =
        { test.execution_state(canister_id).wasm_memory.size.get() * WASM_PAGE_SIZE_IN_BYTES };

    test.canister_update_wasm_memory_limit(
        canister_id,
        NumBytes::new(wasm_memory_usage as u64) + allowance,
    )
    .unwrap();
}

#[test]
fn wasm_memory_limit_is_enforced_in_updates() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();

    // Warm up the canister before getting its memory usage.
    let result = test
        .ingress(canister_id, "update", use_wasm_memory_and_reply(100))
        .unwrap();
    assert_eq!(WasmResult::Reply(100_i32.to_le_bytes().to_vec()), result);

    set_wasm_memory_limit(&mut test, canister_id, NumBytes::from(5_000_000));

    // Using a small amount of memory should succeed.
    let result = test
        .ingress(canister_id, "update", use_wasm_memory_and_reply(100))
        .unwrap();
    assert_eq!(WasmResult::Reply(100_i32.to_le_bytes().to_vec()), result);

    // Using a large amount of memory should fail.
    let err = test
        .ingress(canister_id, "update", use_wasm_memory_and_reply(10_000_000))
        .unwrap_err();

    assert_eq!(err.code(), ErrorCode::CanisterWasmMemoryLimitExceeded);
}

#[test]
fn wasm_memory_limit_is_enforced_at_start_of_update() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();

    // Warm up the canister to make sure that the second update call does not
    // grow memory.
    let result = test
        .ingress(canister_id, "update", use_wasm_memory_and_reply(100))
        .unwrap();
    assert_eq!(WasmResult::Reply(100_i32.to_le_bytes().to_vec()), result);

    test.canister_update_wasm_memory_limit(canister_id, NumBytes::new(1))
        .unwrap();

    let err = test
        .ingress(
            canister_id,
            "update",
            wasm().push_bytes(&[]).append_and_reply().build(),
        )
        .unwrap_err();

    assert_eq!(err.code(), ErrorCode::CanisterWasmMemoryLimitExceeded);
}

#[test]
fn wasm_memory_limit_zero_means_unlimited() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();

    let result = test
        .ingress(canister_id, "update", use_wasm_memory_and_reply(100))
        .unwrap();
    assert_eq!(WasmResult::Reply(100_i32.to_le_bytes().to_vec()), result);

    // The execution fails.
    test.canister_update_wasm_memory_limit(canister_id, NumBytes::new(1))
        .unwrap();

    let err = test
        .ingress(
            canister_id,
            "update",
            wasm().push_bytes(&[]).append_and_reply().build(),
        )
        .unwrap_err();

    assert_eq!(err.code(), ErrorCode::CanisterWasmMemoryLimitExceeded);

    test.canister_update_wasm_memory_limit(canister_id, NumBytes::new(0))
        .unwrap();

    // The execution succeeds.
    test.ingress(
        canister_id,
        "update",
        wasm().push_bytes(&[]).append_and_reply().build(),
    )
    .unwrap();
}

#[test]
fn wasm_memory_limit_is_not_enforced_in_queries() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();

    // Warm up the canister before getting its memory usage.
    let result = test
        .ingress(canister_id, "query", use_wasm_memory_and_reply(100))
        .unwrap();
    assert_eq!(WasmResult::Reply(100_i32.to_le_bytes().to_vec()), result);

    set_wasm_memory_limit(&mut test, canister_id, NumBytes::from(5_000_000));

    // Using a large amount of memory should succeed because the Wasm memory
    // limit is not enforced in queries.
    let result = test
        .ingress(canister_id, "query", use_wasm_memory_and_reply(10_000_000))
        .unwrap();
    assert_eq!(
        WasmResult::Reply(10_000_000_i32.to_le_bytes().to_vec()),
        result
    );
}

#[test]
fn wasm_memory_limit_is_not_enforced_in_timer() {
    let mut test = ExecutionTestBuilder::new().build();
    let canister_id = test.universal_canister().unwrap();
    let set_timer = wasm()
        .set_global_timer_method(
            wasm()
                .stable64_grow(200)
                .stable64_read(0, 10_000_000)
                .push_bytes(&[1, 2, 3])
                .set_global_data_from_stack()
                .build(),
        )
        .reply()
        .build();

    // Warm up the canister before getting its memory usage.
    let result = test
        .ingress(canister_id, "update", use_wasm_memory_and_reply(100))
        .unwrap();
    assert_eq!(WasmResult::Reply(100_i32.to_le_bytes().to_vec()), result);

    set_wasm_memory_limit(&mut test, canister_id, NumBytes::from(5_000_000));

    let _ = test.ingress(canister_id, "update", set_timer).unwrap();

    test.canister_task(canister_id, CanisterTask::GlobalTimer);

    // Increase the limit to run the update call that fetches the result of the
    // timer execution.
    set_wasm_memory_limit(&mut test, canister_id, NumBytes::from(5_000_000));

    // The timer task should succeed because the Wasm memory limit is not
    // enforced in system tasks. Note that this will change in future after
    // canister logging is implemented, which will allow enforcing the limit in
    // system tasks as well.
    let result = test
        .ingress(
            canister_id,
            "update",
            wasm().get_global_data().append_and_reply().build(),
        )
        .unwrap();

    assert_eq!(WasmResult::Reply(vec![1, 2, 3]), result);
}

#[test]
fn wasm_memory_limit_is_not_enforced_in_response_callback() {
    let mut test = ExecutionTestBuilder::new().build();
    let caller_id = test.universal_canister().unwrap();
    let callee_id = test.universal_canister().unwrap();
    let callee = wasm().message_payload().reply().build();
    let caller = |size| {
        wasm()
            .inter_update(
                callee_id,
                call_args()
                    .other_side(callee.clone())
                    .on_reply(use_wasm_memory_and_reply(size)),
            )
            .build()
    };

    // Warm up the canister before getting its memory usage.
    let result = test.ingress(caller_id, "update", caller(100)).unwrap();
    assert_eq!(WasmResult::Reply(100_i32.to_le_bytes().to_vec()), result);

    set_wasm_memory_limit(&mut test, caller_id, NumBytes::from(5_000_000));

    // Using a large amount of memory should succeed because the Wasm memory
    // limit is not enforced in the response callback.
    let result = test
        .ingress(caller_id, "update", caller(10_000_000))
        .unwrap();
    assert_eq!(
        WasmResult::Reply(10_000_000_i32.to_le_bytes().to_vec()),
        result
    );
}

#[test]
fn wasm_memory_limit_is_not_enforced_in_pre_upgrade() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_pre_upgrade")
                (drop (memory.grow (i32.const 10)))
            )
            (memory 0)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();

    test.canister_update_wasm_memory_limit(canister_id, NumBytes::new(1))
        .unwrap();

    let wasm = wat::parse_str(wat).unwrap();

    // The pre-upgrade must succeed because the Wasm memory limit is not
    // enforced there.
    test.upgrade_canister(canister_id, wasm).unwrap();
}

#[test]
fn wasm_memory_limit_is_enforced_in_post_upgrade() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_post_upgrade")
                (drop (memory.grow (i32.const 10)))
            )
            (memory 0)
        )"#;
    let canister_id = test.canister_from_wat(wat).unwrap();

    test.canister_update_wasm_memory_limit(canister_id, NumBytes::new(1))
        .unwrap();

    let wasm = wat::parse_str(wat).unwrap();

    // The post-upgrade is expected to fail.
    let err = test.upgrade_canister(canister_id, wasm).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterWasmMemoryLimitExceeded);
}

#[test]
fn wasm_memory_limit_is_enforced_with_static_memory_in_post_upgrade() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_post_upgrade")
            )
            (memory 10)
        )"#;

    let canister_id = test.canister_from_wat(wat).unwrap();

    test.canister_update_wasm_memory_limit(canister_id, NumBytes::new(1))
        .unwrap();

    let wasm = wat::parse_str(wat).unwrap();

    // The post-upgrade is expected to fail.
    let err = test.upgrade_canister(canister_id, wasm).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterWasmMemoryLimitExceeded);
}

#[test]
fn wasm_memory_limit_is_enforced_in_init() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_init")
                (drop (memory.grow (i32.const 10)))
            )
            (memory 0)
        )"#;

    let canister_id = test.create_canister(Cycles::new(1_000_000_000_000));

    test.canister_update_wasm_memory_limit(canister_id, NumBytes::new(1))
        .unwrap();

    let wasm = wat::parse_str(wat).unwrap();

    // The canister init is expected to fail.
    let err = test.install_canister(canister_id, wasm).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterWasmMemoryLimitExceeded);
}

#[test]
fn wasm_memory_limit_is_enforced_with_static_memory_in_init() {
    let mut test = ExecutionTestBuilder::new().build();
    let wat = r#"
        (module
            (func (export "canister_init")
            )
            (memory 10)
        )"#;

    let canister_id = test.create_canister(Cycles::new(1_000_000_000_000));

    test.canister_update_wasm_memory_limit(canister_id, NumBytes::new(1))
        .unwrap();

    let wasm = wat::parse_str(wat).unwrap();

    // The canister init is expected to fail.
    let err = test.install_canister(canister_id, wasm).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterWasmMemoryLimitExceeded);
}

#[test]
fn wasm_memory_limit_cannot_exceed_256_tb() {
    let mut test = ExecutionTestBuilder::new().build();

    let canister_id = test.create_canister(Cycles::new(1_000_000_000_000));

    // Setting the limit to 2^48 works.
    test.canister_update_wasm_memory_limit(canister_id, NumBytes::new(1 << 4))
        .unwrap();

    // Setting the limit above 2^48 fails.
    let err = test
        .canister_update_wasm_memory_limit(canister_id, NumBytes::new((1 << 48) + 1))
        .unwrap_err();

    assert_eq!(err.code(), ErrorCode::CanisterContractViolation);
}

// Test the result that is close to 2^64.
#[test]
fn ic0_canister_cycle_balance_u64() {
    let mut test: ExecutionTest = ExecutionTestBuilder::new()
        .with_initial_canister_cycles((1 << 64) - 1)
        .build();
    let id = test.universal_canister().unwrap();
    let result = test
        .ingress(id, "update", wasm().cycles_balance().reply_int64().build())
        .unwrap();
    match result {
        WasmResult::Reply(response) => {
            let result = u64::from_le_bytes(response.try_into().unwrap());
            assert!(result >= (1 << 63));
        }
        WasmResult::Reject(err) => unreachable!("{:?}", err),
    }
}

// Test the result that is close to 2^64.
#[test]
fn ic0_msg_cycles_available_u64() {
    let mut test: ExecutionTest = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(2 * (1 << 64))
        .build();
    let caller_id = test.universal_canister().unwrap();
    let callee_id = test.universal_canister().unwrap();
    let callee = wasm().msg_cycles_available().reply_int64().build();
    let caller = wasm()
        .call_with_cycles(
            callee_id,
            "update",
            call_args()
                .other_side(callee)
                .on_reject(wasm().reject_message().reject())
                .on_reply(wasm().message_payload().append_and_reply()),
            Cycles::new((1 << 64) - 1),
        )
        .build();
    let result = test.ingress(caller_id, "update", caller).unwrap();
    match result {
        WasmResult::Reply(response) => {
            let result = u64::from_le_bytes(response.try_into().unwrap());
            assert!(result >= (1 << 63));
        }
        WasmResult::Reject(err) => unreachable!("{:?}", err),
    }
}

// Test the result that is close to 2^64.
#[test]
fn ic0_msg_cycles_refunded_u64() {
    let mut test: ExecutionTest = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(2 * (1 << 64))
        .build();
    let caller_id = test.universal_canister().unwrap();
    let callee_id = test.universal_canister().unwrap();
    let callee = wasm().push_int64(0).reply_int64().build();
    let caller = wasm()
        .call_with_cycles(
            callee_id,
            "update",
            call_args()
                .other_side(callee)
                .on_reject(wasm().reject_message().reject())
                .on_reply(wasm().msg_cycles_refunded().reply_int64()),
            Cycles::new((1 << 64) - 1),
        )
        .build();
    let result = test.ingress(caller_id, "update", caller).unwrap();
    match result {
        WasmResult::Reply(response) => {
            let result = u64::from_le_bytes(response.try_into().unwrap());
            assert!(result >= (1 << 63));
        }
        WasmResult::Reject(err) => unreachable!("{:?}", err),
    }
}

// Test the result that is close to 2^64.
#[test]
fn ic0_mint_cycles_u64() {
    let mut test: ExecutionTest = ExecutionTestBuilder::new()
        .with_initial_canister_cycles(1 << 64)
        .build();
    let wat = r#"
        (module
            (import "ic0" "mint_cycles" (func $mint_cycles (param i64) (result i64)))

            (func (export "canister_update test")
                (drop (call $mint_cycles (i64.const 18446744073709551615)))
            )
        )"#;
    let mut canister_id = test.canister_from_wat(wat).unwrap();
    // This loop should finish after four iterations.
    while canister_id != CYCLES_MINTING_CANISTER_ID {
        canister_id = test.canister_from_wat(wat).unwrap();
    }
    let result = test.ingress(canister_id, "test", vec![]);
    assert_empty_reply(result);
    assert!(
        test.canister_state(canister_id)
            .system_state
            .balance()
            .get()
            >= 2 * (1 << 64) - 10_000_000
    );
}
