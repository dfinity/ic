//! Fills an 18 GiB Wasm64 heap in blocks of 5, 6 and 7 GiB, one block per
//! update call, with a limit of 6 GiB on the heap pages a single message may
//! access.
//!
//! * 5 GiB blocks: three fit (15 GiB), the fourth cannot grow the heap.
//! * 6 GiB blocks: three fit exactly (18 GiB), the fourth cannot grow the
//!   heap. A block of exactly the limit is allowed.
//! * 7 GiB blocks: the heap could hold two, but a single message may not
//!   touch 7 GiB, so the very first block fails with
//!   `CanisterMemoryAccessLimitExceeded` and leaves the heap empty.
//!
//! The canister is `test-data/heap_blocks.wat`. Each test takes minutes: it
//! faults in millions of pages and the dirty pages are copied into the state.
//! Run one test at a time with a generous timeout, e.g.
//!
//! ```sh
//! bazel test //rs/execution_environment:execution_environment_misc_integration_tests/heap_blocks_test \
//!   --test_output=all --test_timeout=3600 --test_arg=--test-threads=1
//! ```

use ic_config::{
    embedders::MemoryPageLimit, execution_environment::Config as ExecutionConfig,
    subnet_config::SubnetConfig,
};
use ic_error_types::{ErrorCode, UserError};
use ic_management_canister_types_private::CanisterSettingsArgsBuilder;
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, StateMachineConfig, WasmResult};
use ic_sys::PAGE_SIZE;
use ic_types::{CanisterId, NumBytes, NumOsPages};
use ic_types_cycles::Cycles;

const GIB: u64 = 1 << 30;

/// The Wasm64 heap size made available to canisters.
const HEAP_SIZE: u64 = 18 * GIB;

/// The number of heap bytes (in whole pages) one message may access.
const ACCESSED_PAGE_LIMIT: u64 = 6 * GIB;

const HEAP_BLOCKS_WAT: &str = include_str!("test-data/heap_blocks.wat");

/// An application subnet whose canisters may grow their Wasm64 heap to
/// `HEAP_SIZE` and touch at most `ACCESSED_PAGE_LIMIT` of it per message.
fn state_machine() -> StateMachine {
    let subnet_type = SubnetType::Application;
    let mut subnet_config = SubnetConfig::new(subnet_type);
    // One message dirties gigabytes of heap. Without this the canister would
    // be rate limited for hundreds of rounds before the next block.
    subnet_config.scheduler_config.heap_delta_rate_limit = NumBytes::new(HEAP_SIZE);
    subnet_config.scheduler_config.subnet_heap_delta_capacity = NumBytes::new(100 * HEAP_SIZE);

    let mut execution_config = ExecutionConfig::default();
    execution_config.embedders_config.max_wasm64_memory_size = NumBytes::new(HEAP_SIZE);
    let limit = NumOsPages::new(ACCESSED_PAGE_LIMIT / PAGE_SIZE as u64);
    execution_config
        .embedders_config
        .wasm_memory_accessed_page_limit = MemoryPageLimit {
        message: limit,
        upgrade: limit,
        query: limit,
    };

    StateMachineBuilder::new()
        .with_config(Some(StateMachineConfig::new(
            subnet_config,
            execution_config,
        )))
        .with_subnet_type(subnet_type)
        .build()
}

/// Installs the heap blocks canister with enough cycles for an 18 GiB heap
/// and without the default 3 GiB Wasm memory limit.
fn install_heap_blocks_canister(env: &StateMachine) -> CanisterId {
    let settings = CanisterSettingsArgsBuilder::new()
        .with_wasm_memory_limit(HEAP_SIZE)
        .with_freezing_threshold(0)
        .build();
    env.install_canister_with_cycles(
        wat::parse_str(HEAP_BLOCKS_WAT).unwrap(),
        vec![],
        Some(settings),
        Cycles::new(1_000_000_000_000_000),
    )
    .unwrap()
}

/// Grows the heap by `gib` GiB and touches every page of the new block.
/// Returns the new heap size in bytes on success, `Ok(None)` if the heap
/// could not grow by the block, and the error if the message failed.
fn grow_and_touch(
    env: &StateMachine,
    canister_id: CanisterId,
    gib: usize,
) -> Result<Option<u64>, UserError> {
    // The canister takes the block size from the length of the argument.
    match env.execute_ingress(canister_id, "grow_and_touch", vec![0; gib])? {
        WasmResult::Reply(bytes) => Ok(Some(u64::from_le_bytes(bytes.try_into().unwrap()))),
        WasmResult::Reject(message) => {
            assert_eq!(message, "", "unexpected reject message");
            Ok(None)
        }
    }
}

/// Fills the heap in blocks of `gib` GiB until the heap cannot grow any
/// more, and checks that each block adds exactly `gib` GiB.
fn fill_heap_in_blocks(gib: usize) {
    let env = state_machine();
    let canister_id = install_heap_blocks_canister(&env);
    let block = gib as u64 * GIB;
    let expected_blocks = HEAP_SIZE / block;

    for i in 1..=expected_blocks {
        let size = grow_and_touch(&env, canister_id, gib)
            .unwrap_or_else(|err| panic!("block {i}: {err}"))
            .unwrap_or_else(|| panic!("block {i}: the heap did not grow"));
        assert_eq!(size, i * block, "heap size after block {i}");
    }
    // The next block does not fit any more: the canister cannot grow its
    // heap, but it is still running and nothing else fails.
    assert_eq!(grow_and_touch(&env, canister_id, gib).unwrap(), None);
}

#[test]
fn fill_heap_in_5_gib_blocks() {
    fill_heap_in_blocks(5);
}

#[test]
fn fill_heap_in_6_gib_blocks() {
    fill_heap_in_blocks(6);
}

/// A 7 GiB block fits into the heap but exceeds what one message may access:
/// the message fails before the 6 GiB + 1 page is mapped, its `memory.grow`
/// is rolled back, and the canister keeps working.
#[test]
fn fill_heap_in_7_gib_blocks_exceeds_the_accessed_page_limit() {
    let env = state_machine();
    let canister_id = install_heap_blocks_canister(&env);

    let err = grow_and_touch(&env, canister_id, 7).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterMemoryAccessLimitExceeded);
    assert!(
        err.description().contains("Wasm heap"),
        "unexpected error: {err}"
    );

    // The failed message did not grow the heap: a 5 GiB block still starts
    // at 0, and the canister can be filled with blocks within the limit.
    assert_eq!(grow_and_touch(&env, canister_id, 5).unwrap(), Some(5 * GIB));
    assert_eq!(
        grow_and_touch(&env, canister_id, 6).unwrap(),
        Some(11 * GIB)
    );
    assert_eq!(
        grow_and_touch(&env, canister_id, 7).unwrap_err().code(),
        ErrorCode::CanisterMemoryAccessLimitExceeded
    );
    assert_eq!(
        grow_and_touch(&env, canister_id, 6).unwrap(),
        Some(17 * GIB)
    );
}
