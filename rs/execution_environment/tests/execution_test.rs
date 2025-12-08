use assert_matches::assert_matches;
use candid::Encode;
use canister_test::CanisterInstallMode;
use ic_base_types::PrincipalId;
use ic_config::{
    execution_environment::{Config as HypervisorConfig, DEFAULT_WASM_MEMORY_LIMIT},
    subnet_config::{CyclesAccountManagerConfig, SubnetConfig},
};
use ic_embedders::wasmtime_embedder::system_api::MAX_CALL_TIMEOUT_SECONDS;
use ic_management_canister_types_private::{
    CanisterIdRecord, CanisterMetadataRequest, CanisterMetadataResponse, CanisterSettingsArgs,
    CanisterSettingsArgsBuilder, CanisterStatusResultV2, CreateCanisterArgs, DerivationPath,
    EcdsaKeyId, EmptyBlob, IC_00, LoadCanisterSnapshotArgs, MasterPublicKeyId, Method, Payload,
    SignWithECDSAArgs, TakeCanisterSnapshotArgs, UpdateSettingsArgs,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::NumWasmPages;
use ic_state_machine_tests::{
    ErrorCode, StateMachine, StateMachineBuilder, StateMachineConfig, UserError,
};
use ic_test_utilities_metrics::{
    fetch_gauge, fetch_histogram_vec_stats, fetch_int_counter, labels,
};
use ic_types::ingress::{IngressState, IngressStatus};
use ic_types::messages::MessageId;
use ic_types::{CanisterId, Cycles, NumBytes, Time, ingress::WasmResult, messages::NO_DEADLINE};
use ic_universal_canister::{UNIVERSAL_CANISTER_WASM, call_args, wasm};
use more_asserts::{assert_gt, assert_le, assert_lt};
use std::{convert::TryInto, str::FromStr, sync::Arc, time::Duration};

/// One megabyte for better readability.
const MIB: u64 = 1024 * 1024;
/// One gigabyte for better readability.
const GIB: u64 = 1024 * MIB;

/// One billion for better cycles readability.
const B: u128 = 1e9 as u128;

/// One trillion for better cycles readability.
const T: u128 = 1e12 as u128;

/// Initial cycles balance for canisters, should be big enough for a regular test.
const INITIAL_CYCLES_BALANCE: Cycles = Cycles::new(100 * T);

/// This is a canister that keeps a counter on the heap and exposes various test
/// methods. Exposed methods:
///  * "inc"       increment the counter
///  * "read"      read the counter value
///  * "persist"   copy the counter value to stable memory
///  * "load"      restore the counter value from stable memory
///  * "copy_to"   copy the counter value to the specified address on the heap
///  * "read_at"   read a 32-bit integer at the specified address on the heap
///  * "grow_page" grow stable memory by 1 page
///  * "grow_mem"  grow memory by the current counter value
const TEST_CANISTER: &str = r#"
(module
    (import "ic0" "msg_arg_data_copy"
    (func $msg_arg_data_copy (param $dst i32) (param $offset i32) (param $size i32)))
    (import "ic0" "msg_reply" (func $msg_reply))
    (import "ic0" "msg_reply_data_append"
    (func $msg_reply_data_append (param i32 i32)))
    (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
    (import "ic0" "stable_read"
    (func $stable_read (param $dst i32) (param $offset i32) (param $size i32)))
    (import "ic0" "stable_write"
    (func $stable_write (param $offset i32) (param $src i32) (param $size i32)))

    (func $inc

    ;; load the old counter value, increment, and store it back
    (i32.store

        ;; store at the beginning of the heap
        (i32.const 0) ;; store at the beginning of the heap

        ;; increment heap[0]
        (i32.add

        ;; the old value at heap[0]
        (i32.load (i32.const 0))

        ;; "1"
        (i32.const 1)
        )
    )
    (call $msg_reply_data_append (i32.const 0) (i32.const 0))
    (call $msg_reply)
    )

    (func $read
    ;; now we copied the counter address into heap[0]
    (call $msg_reply_data_append
        (i32.const 0) ;; the counter address from heap[0]
        (i32.const 4) ;; length
    )
    (call $msg_reply)
    )

    (func $copy_to
    (call $msg_arg_data_copy (i32.const 4) (i32.const 0) (i32.const 4))
    (i32.store (i32.load (i32.const 4)) (i32.load (i32.const 0)))
    (call $msg_reply)
    )

    (func $read_at
    (call $msg_arg_data_copy (i32.const 4) (i32.const 0) (i32.const 4))
    (call $msg_reply_data_append (i32.load (i32.const 4)) (i32.const 4))
    (call $msg_reply)
    )

    (func $grow_page
    (drop (call $stable_grow (i32.const 1)))
    (call $msg_reply)
    )

    (func $grow_mem
    (call $msg_arg_data_copy (i32.const 4) (i32.const 0) (i32.const 4))
    (i32.store (i32.const 4)
        (memory.grow (i32.load (i32.const 4))))
    (call $msg_reply_data_append (i32.const 4) (i32.const 4))
    (call $msg_reply)
    )

    (func $persist
    (call $stable_write
        (i32.const 0) ;; offset
        (i32.const 0) ;; src
        (i32.const 4) ;; length
    )
    (call $msg_reply)
    )

    (func $load
    (call $stable_read
        (i32.const 0) ;; dst
        (i32.const 0) ;; offset
        (i32.const 4) ;; length
    )
    (call $msg_reply)
    )

    (memory $memory 1)
    (export "memory" (memory $memory))
    (export "canister_query read" (func $read))
    (export "canister_query read_at" (func $read_at))
    (export "canister_update inc" (func $inc))
    (export "canister_update persist" (func $persist))
    (export "canister_update load" (func $load))
    (export "canister_update copy_to" (func $copy_to))
    (export "canister_update grow_page" (func $grow_page))
    (export "canister_update grow_mem" (func $grow_mem))
)"#;

const WASM_PAGE_SIZE_IN_BYTES: u64 = 64 * 1024; // 64KiB

/// Converts an integer into the representation expected by the TEST_CANISTER
/// canister.
fn from_int(n: i32) -> Vec<u8> {
    n.to_le_bytes().to_vec()
}

/// Converts a reply of the TEST_CANISTER canister into an integer.
fn to_int(v: Vec<u8>) -> i32 {
    i32::from_le_bytes(v.try_into().unwrap())
}

/// Creates a canister with cycles.
fn create_canister_with_cycles(
    env: &StateMachine,
    module: Vec<u8>,
    settings: Option<CanisterSettingsArgs>,
    cycles: Cycles,
) -> CanisterId {
    env.install_canister_with_cycles(module, vec![], settings, cycles)
        .unwrap()
}

/// Creates universal canister with cycles.
fn create_universal_canister_with_cycles(
    env: &StateMachine,
    settings: Option<CanisterSettingsArgs>,
    cycles: Cycles,
) -> CanisterId {
    create_canister_with_cycles(env, UNIVERSAL_CANISTER_WASM.to_vec(), settings, cycles)
}

/// The test checks that the canister heap is discarded on code
/// re-install, and that the heap stays discarded after a checkpoint
/// recovery. It's a common bug in execution to reset the heap in
/// memory, but not on disk, which results in corrupted checkpoints.
#[test]
fn test_canister_reinstall_restart() {
    let env = StateMachine::new();
    env.set_checkpoints_enabled(true);

    let canister_id = env.install_canister_wat(TEST_CANISTER, vec![], None);
    let val = env.query(canister_id, "read", vec![]).unwrap().bytes();
    assert_eq!(to_int(val), 0);

    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    let val = env.query(canister_id, "read", vec![]).unwrap().bytes();
    assert_eq!(to_int(val), 1);

    env.reinstall_canister_wat(canister_id, TEST_CANISTER, vec![]);
    let val = env.query(canister_id, "read", vec![]).unwrap().bytes();
    assert_eq!(to_int(val), 0);

    let env = env.restart_node();

    let val = env.query(canister_id, "read", vec![]).unwrap().bytes();
    assert_eq!(to_int(val), 0);
}

// The test checks that canisters cannot be called after unistall_code
// and it stays so after restart.
#[test]
fn test_canister_uninstall_restart() {
    let env = StateMachine::new();
    env.set_checkpoints_enabled(true);

    let canister_id = env.install_canister_wat(TEST_CANISTER, vec![], None);
    let val = env.query(canister_id, "read", vec![]).unwrap().bytes();
    assert_eq!(to_int(val), 0);

    env.uninstall_code(canister_id).unwrap();
    assert_eq!(
        env.query(canister_id, "read", vec![]).unwrap_err().code(),
        ErrorCode::CanisterWasmModuleNotFound
    );

    let env = env.restart_node();

    assert_eq!(
        env.query(canister_id, "read", vec![]).unwrap_err().code(),
        ErrorCode::CanisterWasmModuleNotFound
    );
}

#[test]
fn query_nonexisting_canister() {
    let env = StateMachine::new();
    env.tick(); // needed to create a certified state

    let canister_id = CanisterId::from_u64(0);
    assert_eq!(
        env.query(canister_id, "read", vec![]).unwrap_err().code(),
        ErrorCode::CanisterNotFound
    );
}

/// Same test as above, but checks the upgrade path when no upgrade
/// hooks are present instead of the re-install path.
#[test]
fn test_canister_upgrade_restart() {
    let env = StateMachine::new();
    env.set_checkpoints_enabled(true);

    let canister_id = env.install_canister_wat(TEST_CANISTER, vec![], None);
    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    let val = env.query(canister_id, "read", vec![]).unwrap().bytes();
    assert_eq!(to_int(val), 1);

    env.upgrade_canister_wat(canister_id, TEST_CANISTER, vec![]);
    let val = env.query(canister_id, "read", vec![]).unwrap().bytes();
    // there is no upgrade hooks in the canister, so the state must be wiped out.
    assert_eq!(to_int(val), 0);

    let env = env.restart_node();

    let val = env.query(canister_id, "read", vec![]).unwrap().bytes();
    assert_eq!(to_int(val), 0);
}

/// Tests that if you delete a canister, it stays deleted after a restart
#[test]
fn test_canister_delete_restart() {
    let env = StateMachine::new();
    env.set_checkpoints_enabled(true);

    let canister_id = env.install_canister_wat(TEST_CANISTER, vec![], None);
    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    let val = env.query(canister_id, "read", vec![]).unwrap().bytes();
    assert_eq!(to_int(val), 1);

    let env = env.restart_node();

    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    let val = env.query(canister_id, "read", vec![]).unwrap().bytes();
    assert_eq!(to_int(val), 2);

    let env = env.restart_node();

    env.stop_canister(canister_id).unwrap();
    env.delete_canister(canister_id).unwrap();

    assert_eq!(
        env.execute_ingress(canister_id, "inc", vec![])
            .unwrap_err()
            .code(),
        ErrorCode::CanisterNotFound
    );

    let env = env.restart_node();

    assert_eq!(
        env.execute_ingress(canister_id, "inc", vec![])
            .unwrap_err()
            .code(),
        ErrorCode::CanisterNotFound
    );
}

/// The test checks that the canister stable memory is discarded on code
/// re-install, and that the stable memory stays discarded after a checkpoint
/// recovery. It's a common bug in execution to reset a page map in memory, but
/// not on disk, which results in corrupted checkpoints.
#[test]
fn test_canister_stable_memory_reinstall_restart() {
    let env = StateMachine::new();
    env.set_checkpoints_enabled(true);

    let canister_id = env.install_canister_wat(TEST_CANISTER, vec![], None);
    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    let val = env.query(canister_id, "read", vec![]).unwrap().bytes();
    assert_eq!(to_int(val), 1);

    env.execute_ingress(canister_id, "grow_page", vec![])
        .unwrap();
    env.execute_ingress(canister_id, "persist", vec![]).unwrap();
    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    let val = env.query(canister_id, "read", vec![]).unwrap().bytes();
    assert_eq!(to_int(val), 2);

    env.execute_ingress(canister_id, "load", vec![]).unwrap();
    let val = env.query(canister_id, "read", vec![]).unwrap().bytes();
    assert_eq!(to_int(val), 1);

    env.reinstall_canister_wat(canister_id, TEST_CANISTER, vec![]);

    let env = env.restart_node();

    let val = env.query(canister_id, "read", vec![]).unwrap().bytes();
    assert_eq!(to_int(val), 0);

    env.execute_ingress(canister_id, "grow_page", vec![])
        .unwrap();
    env.execute_ingress(canister_id, "load", vec![]).unwrap();

    let val = env.query(canister_id, "read", vec![]).unwrap().bytes();
    assert_eq!(to_int(val), 0);
}

/// Same test as above, but checks the upgrade path when no upgrade
/// hooks are present instead of the re-install path.
#[test]
fn test_canister_stable_memory_upgrade_restart() {
    let env = StateMachine::new();
    env.set_checkpoints_enabled(true);

    let canister_id = env.install_canister_wat(TEST_CANISTER, vec![], None);
    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    let val = env.query(canister_id, "read", vec![]).unwrap().bytes();
    assert_eq!(to_int(val), 1);

    env.execute_ingress(canister_id, "grow_page", vec![])
        .unwrap();
    env.execute_ingress(canister_id, "persist", vec![]).unwrap();

    env.upgrade_canister_wat(canister_id, TEST_CANISTER, vec![]);

    let env = env.restart_node();

    let val = env.query(canister_id, "read", vec![]).unwrap().bytes();
    // there is no upgrade hooks in the canister, so the state must be wiped out.
    assert_eq!(to_int(val), 0);

    env.execute_ingress(canister_id, "load", vec![]).unwrap();

    let val = env.query(canister_id, "read", vec![]).unwrap().bytes();
    assert_eq!(to_int(val), 1);
}

/// Verifies that, if a canister runs out of cycles and is automatically
/// uninstalled by the system, then making a checkpoint doesn't crash.
/// This was a bug in the past that caused ICSUP-2400.
#[test]
fn test_canister_out_of_cycles() {
    // Start a node with a config where all computation/storage is free.
    let mut subnet_config = SubnetConfig::new(SubnetType::System);
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        subnet_config.clone(),
        HypervisorConfig::default(),
    ));
    env.set_checkpoints_enabled(true);

    let now = std::time::SystemTime::now();
    env.set_time(now);

    // Install a canister. By default, it has zero cycles.
    // Note that a compute allocation is assigned.
    let canister_id = env.install_canister_wat(
        TEST_CANISTER,
        vec![],
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_compute_allocation(1)
                .build(),
        ),
    );

    // Since all computation/storage is free, calling an update method should
    // succeed.
    env.execute_ingress(canister_id, "inc", vec![]).unwrap();

    // Modify the config so that compute allocations are charged for.
    subnet_config
        .cycles_account_manager_config
        .compute_percent_allocated_per_second_fee = Cycles::new(1);

    // Restart the node to pick up the new node configuration.
    let env = env.restart_node_with_config(StateMachineConfig::new(
        subnet_config,
        HypervisorConfig::default(),
    ));

    // Install a new wasm to trigger making a new checkpoint.
    env.install_canister_wat(TEST_CANISTER, vec![], None);

    // We don't charge for allocation periodically, we advance the state machine
    // time to trigger allocation charging.
    let now = now
        + 2 * CyclesAccountManagerConfig::application_subnet().duration_between_allocation_charges;
    env.set_time(now);
    env.tick();

    // Verify the original canister still exists (but with an empty wasm module).
    assert_eq!(
        env.execute_ingress(canister_id, "inc", vec![])
            .unwrap_err()
            .code(),
        ErrorCode::CanisterWasmModuleNotFound
    );
}

/*
running 1 test
ABC: charge_canisters_for_resource_allocation_and_usage
ABC: cycles 339_704_000 available 74_079_999_931_960 ok
ABC: cycles 300_005_000_000 available 74_079_660_227_960 ok
ABC: cycles 40_005_000_000 available 74_076_868_663_894 ok
ABC: charge_canisters_for_resource_allocation_and_usage
ABC: step 1
ABC: cycles 40_005_000_000 available 74_076_863_661_755 ok
ABC: charge_canisters_for_resource_allocation_and_usage
ABC: cycles 4_076_331_358 available 99_997_915_268_609 ok
ABC: cycles 0 available 99_993_838_937_251 ok
ABC: cycles 99_997_930_000_000 available 99_993_838_937_251 error
ABC: Charging canister rwlgt-iiaaa-aaaaa-aaaaa-cai for ComputeAllocation failed with Canister rwlgt-iiaaa-aaaaa-aaaaa-cai is out of cycles
ABC: Uninstalling canister rwlgt-iiaaa-aaaaa-aaaaa-cai because it ran out of cycles with err: CanisterOutOfCyclesError { canister_id: CanisterId(rwlgt-iiaaa-aaaaa-aaaaa-cai), available: Cycles(99993838937251), requested: Cycles(99997930000000), threshold: Cycles(0), reveal_top_up: false }
ABC: step 2
ABC: step 3
ABC: charge_canisters_for_resource_allocation_and_usage
ABC: cycles 0 available 0 ok
ABC: cycles 0 available 0 ok
ABC: cycles 0 available 0 ok
ABC: step 4
ABC: step 5
test canister_has_zero_balance_when_uninstalled_due_to_low_cycles ... ok

===
running 1 test
ABC: charge_canisters_for_resource_allocation_and_usage
ABC: cycles 339_704_000 available 74_079_996_164_740 ok
ABC: cycles 300_005_000_000 available 74_079_656_460_740 ok
ABC: cycles 40_005_000_000 available 74_076_864_896_674 ok
ABC: charge_canisters_for_resource_allocation_and_usage
ABC: step 1
ABC: cycles 40_005_000_000 available 74_076_859_894_535 ok
ABC: charge_canisters_for_resource_allocation_and_usage
ABC: cycles 4_090_865_085 available 99_997_915_268_609 ok
ABC: cycles 0 available 99_993_824_403_524 ok
ABC: cycles 99_997_930_000_000 available 99_993_824_403_524 error
ABC: Charging canister rwlgt-iiaaa-aaaaa-aaaaa-cai for ComputeAllocation failed with Canister rwlgt-iiaaa-aaaaa-aaaaa-cai is out of cycles
ABC: Uninstalling canister rwlgt-iiaaa-aaaaa-aaaaa-cai because it ran out of cycles with err: CanisterOutOfCyclesError { canister_id: CanisterId(rwlgt-iiaaa-aaaaa-aaaaa-cai), available: Cycles(99993824403524), requested: Cycles(99997930000000), threshold: Cycles(0), reveal_top_up: false }
ABC: step 2
ABC: step 3
ABC: charge_canisters_for_resource_allocation_and_usage
ABC: cycles 29 available 0 error
ABC: Charging canister rwlgt-iiaaa-aaaaa-aaaaa-cai for Memory failed with Canister rwlgt-iiaaa-aaaaa-aaaaa-cai is out of cycles
ABC: Uninstalling canister rwlgt-iiaaa-aaaaa-aaaaa-cai because it ran out of cycles with err: CanisterOutOfCyclesError { canister_id: CanisterId(rwlgt-iiaaa-aaaaa-aaaaa-cai), available: Cycles(0), requested: Cycles(29), threshold: Cycles(0), reveal_top_up: false }
ABC: step 4
*/

#[test]
fn canister_has_zero_balance_when_uninstalled_due_to_low_cycles() {
    let subnet_config = SubnetConfig::new(SubnetType::Application);
    let compute_percent_allocated_per_second_fee = subnet_config
        .cycles_account_manager_config
        .compute_percent_allocated_per_second_fee;

    let env = StateMachine::new_with_config(StateMachineConfig::new(
        subnet_config,
        HypervisorConfig::default(),
    ));

    let now = std::time::SystemTime::now();
    env.set_time(now);

    // Install the canister.
    let canister_id = create_universal_canister_with_cycles(
        &env,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_compute_allocation(1)
                .build(),
        ),
        INITIAL_CYCLES_BALANCE,
    );

    println!("ABC: step 1");
    // We don't charge for allocation periodically, we advance the state machine
    // time to trigger allocation charging. The canister should get uninstalled
    // since we simulate that enough time has passed to not be able to pay for
    // its compute allocation.
    let seconds_to_burn_balance = env.cycle_balance(canister_id) as u64
        / compute_percent_allocated_per_second_fee.get() as u64;
    env.advance_time(Duration::from_secs(seconds_to_burn_balance + 1));
    env.tick();

    println!("ABC: step 2");
    // Verify the original canister still exists but it's uninstalled and has a
    // zero cycle balance.
    assert_eq!(env.cycle_balance(canister_id), 0);
    assert_eq!(env.num_canisters_uninstalled_out_of_cycles(), 1);

    println!("ABC: step 3");
    // Advance the statem machine time a bit more and confirm the canister is
    // still uninstalled.
    for _ in 0..1 {
        env.advance_time(
            2 * CyclesAccountManagerConfig::application_subnet()
                .duration_between_allocation_charges,
        );
        env.tick();
    }

    println!("ABC: step 4");
    // Verify the original canister still exists but it's uninstalled and has a
    // zero cycle balance.
    assert_eq!(env.cycle_balance(canister_id), 0);
    assert_eq!(env.num_canisters_uninstalled_out_of_cycles(), 1);

    println!("ABC: step 5");
}

/// Verifies that incremental manifest computation correctly handles memory
/// grow and shrink.
#[test]
fn test_manifest_computation_memory_grow() {
    let env = StateMachine::new();
    env.set_checkpoints_enabled(true);

    let canister_id = env.install_canister_wat(TEST_CANISTER, vec![], None);
    let state_hash_1 = env.await_state_hash();

    let val = env
        .execute_ingress(canister_id, "grow_mem", from_int(200))
        .unwrap()
        .bytes();
    assert_eq!(to_int(val), 1);

    let state_hash_2 = env.await_state_hash();
    assert_ne!(state_hash_1, state_hash_2);

    env.reinstall_canister_wat(canister_id, TEST_CANISTER, vec![]);
    let state_hash_3 = env.await_state_hash();
    assert_ne!(state_hash_2, state_hash_3);
}

/// Verifies that incremental manifest computation correctly handles heap file
/// size changes.
#[test]
fn test_manifest_computation_memory_expand() {
    let env = StateMachine::new();
    env.set_checkpoints_enabled(true);

    let canister_id = env.install_canister_wat(TEST_CANISTER, vec![], None);
    env.execute_ingress(canister_id, "inc", vec![]).unwrap();

    let state_hash_1 = env.await_state_hash();

    // Grow the memory to ~6.4MiB
    let val = env
        .execute_ingress(canister_id, "grow_mem", from_int(100))
        .unwrap()
        .bytes();
    assert_eq!(to_int(val), 1);

    let state_hash_2 = env.await_state_hash();
    assert_ne!(state_hash_1, state_hash_2);

    // Increase the size of the heap file by dirting a page.
    env.execute_ingress(canister_id, "copy_to", from_int(2_000_000))
        .unwrap();

    let val = env
        .query(canister_id, "read_at", from_int(2_000_000))
        .unwrap()
        .bytes();
    assert_eq!(1, to_int(val));

    let state_hash_3 = env.await_state_hash();
    assert_ne!(state_hash_2, state_hash_3);
}

/// Verifies that the state machine can install gzip-compressed canister
/// modules.
#[test]
fn compressed_canisters_support() {
    let env = StateMachine::new();
    env.set_checkpoints_enabled(true);

    let test_canister_wasm = wat::parse_str(TEST_CANISTER).expect("invalid WAT");
    let compressed_wasm = {
        let mut encoder = libflate::gzip::Encoder::new(Vec::new()).unwrap();
        std::io::copy(&mut &test_canister_wasm[..], &mut encoder).unwrap();
        encoder.finish().into_result().unwrap()
    };
    let compressed_hash = ic_crypto_sha2::Sha256::hash(&compressed_wasm);

    let canister_id = env.install_canister(compressed_wasm, vec![], None).unwrap();

    assert_eq!(env.module_hash(canister_id), Some(compressed_hash));
    let env = env.restart_node();
    assert_eq!(env.module_hash(canister_id), Some(compressed_hash));

    let val = env.query(canister_id, "read", vec![]).unwrap().bytes();
    assert_eq!(to_int(val), 0);

    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    let val = env.query(canister_id, "read", vec![]).unwrap().bytes();
    assert_eq!(to_int(val), 1);
}

#[test]
fn test_state_machine_consumes_instructions() {
    let env = StateMachine::new();

    assert_eq!(env.instructions_consumed(), 0.0);

    let canister_id = env.install_canister_wat(TEST_CANISTER, vec![], None);
    env.execute_ingress(canister_id, "inc", vec![]).unwrap();

    let consumed = env.instructions_consumed();
    assert_le!(
        1000.0,
        consumed,
        "Expected the state machine to consume at least 1000 instructions, got {:?}",
        consumed
    );
}

#[test]
fn test_set_stable_memory() {
    let env = StateMachine::new();
    env.set_checkpoints_enabled(true);

    let from_id = env.install_canister_wat(TEST_CANISTER, vec![], None);

    env.execute_ingress(from_id, "inc", vec![]).unwrap();
    let val = env.query(from_id, "read", vec![]).unwrap().bytes();
    assert_eq!(to_int(val), 1);

    env.execute_ingress(from_id, "grow_page", vec![]).unwrap();
    env.execute_ingress(from_id, "persist", vec![]).unwrap();

    let memory = env.stable_memory(from_id);
    assert_eq!(memory.len(), 65536);

    let to_id = env.install_canister_wat(TEST_CANISTER, vec![], None);
    env.set_stable_memory(to_id, &memory);

    env.execute_ingress(to_id, "load", vec![]).unwrap();
    let val = env.query(to_id, "read", vec![]).unwrap().bytes();
    assert_eq!(to_int(val), 1);

    let to_memory = env.stable_memory(to_id);
    assert_eq!(memory, to_memory);
}

#[test]
fn can_query_cycle_balance_and_top_up_canisters() {
    let env = StateMachine::new();
    env.set_checkpoints_enabled(true);

    let canister_id = env.install_canister_wat(
        r#"
            (module
              (import "ic0" "msg_reply" (func $msg_reply))
              (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))
              (import "ic0" "canister_cycle_balance"
                (func $cycle_balance (result i64)))


              (func $balance
                (i64.store
                  (i32.const 0)
                  (call $cycle_balance))
                (call $msg_reply_data_append (i32.const 0) (i32.const 8))
                (call $msg_reply))


              (memory $memory 1)
              (export "memory" (memory $memory))
              (export "canister_query cycle_balance" (func $balance)))
    "#,
        vec![],
        None,
    );

    assert_eq!(0u128, env.cycle_balance(canister_id));
    assert_eq!(
        &0u64.to_le_bytes()[..],
        &env.query(canister_id, "cycle_balance", vec![])
            .unwrap()
            .bytes()[..]
    );

    const AMOUNT: u128 = 1_000_000u128;

    assert_eq!(AMOUNT, env.add_cycles(canister_id, AMOUNT));

    assert_eq!(AMOUNT, env.cycle_balance(canister_id));
    assert_eq!(
        &(AMOUNT as u64).to_le_bytes()[..],
        &env.query(canister_id, "cycle_balance", vec![])
            .unwrap()
            .bytes()[..]
    );
}

#[test]
fn exceeding_memory_capacity_fails_when_memory_allocation_changes() {
    let subnet_config = SubnetConfig::new(SubnetType::Application);
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        subnet_config,
        HypervisorConfig {
            subnet_memory_capacity: NumBytes::from(81 * MIB),
            subnet_memory_reservation: NumBytes::from(MIB),
            ..Default::default()
        },
    ));
    env.set_checkpoints_enabled(true);

    let now = std::time::SystemTime::now();
    env.set_time(now);

    // There are 4 cores by default so the subnet available memory is 80 / 4 = 20 MiB.
    // Set the memory to 20MiB + 1. Should fail.
    let res = env
        .create_canister_with_cycles_impl(
            None,
            INITIAL_CYCLES_BALANCE,
            Some(
                CanisterSettingsArgsBuilder::new()
                    .with_memory_allocation(20u64 * MIB + 1)
                    .build(),
            ),
        )
        .unwrap_err();
    assert_eq!(res.code(), ErrorCode::SubnetOversubscribed);

    // There are 4 cores by default so the subnet available memory is 80 / 4 = 20 MiB.
    // Set the memory to exactly 20MiB. Should succeed.
    env.create_canister_with_cycles_impl(
        None,
        INITIAL_CYCLES_BALANCE,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_memory_allocation(20u64 * MIB)
                .build(),
        ),
    )
    .unwrap();
}

#[test]
fn take_canister_snapshot_request_fails_when_subnet_capacity_reached() {
    let mut subnet_config = SubnetConfig::new(SubnetType::Application);
    subnet_config.scheduler_config.scheduler_cores = 2;
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        subnet_config,
        HypervisorConfig {
            subnet_memory_capacity: NumBytes::from(120 * MIB),
            subnet_memory_reservation: NumBytes::from(0),
            ..Default::default()
        },
    ));

    let now = std::time::SystemTime::now();
    env.set_time(now);
    env.set_checkpoints_enabled(false);

    let canister_id = create_universal_canister_with_cycles(
        &env,
        Some(CanisterSettingsArgsBuilder::new().build()),
        INITIAL_CYCLES_BALANCE,
    );
    env.execute_ingress(
        canister_id,
        "update",
        wasm()
            // As there are 2 scheduler cores, the memory capacity is 120 / 2 = 60 MiB per core.
            .memory_size_is_at_least(30 * MIB)
            .reply_data(&[42])
            .build(),
    )
    .expect("Error increasing the canister memory size");

    let other_canister_id = create_universal_canister_with_cycles(
        &env,
        Some(CanisterSettingsArgsBuilder::new().build()),
        INITIAL_CYCLES_BALANCE,
    );
    env.execute_ingress(
        other_canister_id,
        "update",
        wasm()
            // The memory capacity is (120 - 30) / 2 = 45 MiB per core.
            .memory_size_is_at_least(25 * MIB)
            .reply_data(&[42])
            .build(),
    )
    .expect("Error increasing the canister memory size");

    // This should take another 30 MiB on top of the 30 MiB of the canister state.
    // The available memory at this point is (120 - 30 - 25) / 2 = 32.5 MiB.
    env.take_canister_snapshot(TakeCanisterSnapshotArgs::new(canister_id, None, None, None))
        .unwrap();

    // Ensure that at least one round has passed between the attempts to take a snapshot.
    env.tick();

    // Taking a snapshot of the second canister should take another 25MiB, however the available
    // memory at this point is (120 - 30 - 25 - 30) / 2 = 17.5 MiB, so it should fail.
    let error = env
        .take_canister_snapshot(TakeCanisterSnapshotArgs::new(
            other_canister_id,
            None,
            None,
            None,
        ))
        .map(|_| ())
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::SubnetOversubscribed);
}

#[test]
fn load_canister_snapshot_request_fails_when_subnet_capacity_reached() {
    let mut subnet_config = SubnetConfig::new(SubnetType::Application);
    subnet_config.scheduler_config.scheduler_cores = 2;
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        subnet_config,
        HypervisorConfig {
            subnet_memory_capacity: NumBytes::from(120 * MIB),
            subnet_memory_reservation: NumBytes::from(0),
            ..Default::default()
        },
    ));

    let now = std::time::SystemTime::now();
    env.set_time(now);
    env.set_checkpoints_enabled(false);

    let canister_id = create_universal_canister_with_cycles(
        &env,
        Some(CanisterSettingsArgsBuilder::new().build()),
        INITIAL_CYCLES_BALANCE,
    );
    env.execute_ingress(
        canister_id,
        "update",
        wasm()
            // As there are 2 scheduler cores, the memory capacity is 120 / 2 = 60 MiB per core.
            .memory_size_is_at_least(30 * MIB)
            .reply_data(&[42])
            .build(),
    )
    .expect("Error increasing the canister memory size");

    let other_canister_id = create_universal_canister_with_cycles(
        &env,
        Some(CanisterSettingsArgsBuilder::new().build()),
        INITIAL_CYCLES_BALANCE,
    );
    env.execute_ingress(
        other_canister_id,
        "update",
        wasm()
            // The memory capacity is (120 - 30) / 2 = 45 MiB per core.
            .memory_size_is_at_least(25 * MIB)
            .reply_data(&[42])
            .build(),
    )
    .expect("Error increasing the canister memory size");

    // This should take another 30 MiB on top of the 30 MiB of the canister state.
    // The available memory at this point is (120 - 30 - 25) / 2 = 32.5 MiB.
    let snapshot_id = env
        .take_canister_snapshot(TakeCanisterSnapshotArgs::new(canister_id, None, None, None))
        .unwrap()
        .snapshot_id();

    // Ensure that at least one round has passed between the attempts to take a snapshot.
    env.tick();

    // Uninstall the first canister to free up some memory. This should free up 30MiB.
    // The available memory at this point should be (120 - 30 - 25 - 30 + 30) / 2 = 32.5 MiB.
    env.uninstall_code(canister_id).unwrap();

    // Taking a snapshot of the second canister should take another 25MiB,
    // making the available memory (120 - 30 - 25 - 30 + 30 - 25) / 2 = 20 MiB.
    env.take_canister_snapshot(TakeCanisterSnapshotArgs::new(
        other_canister_id,
        None,
        None,
        None,
    ))
    .unwrap();

    // Loading the snapshot back to the first canister should fail as there
    // is not enough memory available.
    let err = env
        .load_canister_snapshot(LoadCanisterSnapshotArgs::new(
            canister_id,
            snapshot_id,
            None,
        ))
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::SubnetOversubscribed);
}

#[test]
fn canister_snapshot_metrics_are_observed() {
    let mut subnet_config = SubnetConfig::new(SubnetType::Application);
    subnet_config.scheduler_config.scheduler_cores = 2;
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        subnet_config,
        HypervisorConfig {
            subnet_memory_capacity: NumBytes::from(120 * MIB),
            subnet_memory_reservation: NumBytes::from(0),
            ..Default::default()
        },
    ));

    let now = std::time::SystemTime::now();
    env.set_time(now);
    env.set_checkpoints_enabled(false);

    let canister_id = create_universal_canister_with_cycles(
        &env,
        Some(CanisterSettingsArgsBuilder::new().build()),
        INITIAL_CYCLES_BALANCE,
    );
    env.execute_ingress(
        canister_id,
        "update",
        wasm()
            // As there are 2 scheduler cores, the memory capacity is 120 / 2 = 60 MiB per core.
            .memory_size_is_at_least(30 * MIB)
            .reply_data(&[42])
            .build(),
    )
    .expect("Error increasing the canister memory size");

    let other_canister_id = create_universal_canister_with_cycles(
        &env,
        Some(CanisterSettingsArgsBuilder::new().build()),
        INITIAL_CYCLES_BALANCE,
    );
    env.execute_ingress(
        other_canister_id,
        "update",
        wasm()
            // The memory capacity is (120 - 30) / 2 = 45 MiB per core.
            .memory_size_is_at_least(25 * MIB)
            .reply_data(&[42])
            .build(),
    )
    .expect("Error increasing the canister memory size");

    env.take_canister_snapshot(TakeCanisterSnapshotArgs::new(canister_id, None, None, None))
        .unwrap();

    let gauge = fetch_gauge(
        env.metrics_registry(),
        "scheduler_canister_snapshots_memory_usage_bytes",
    )
    .unwrap();
    // The canister is using at least 30 MiB of memory (plus some more for the Wasm module etc).
    assert_gt!(gauge, (30 * MIB) as f64);

    let gauge = fetch_gauge(env.metrics_registry(), "scheduler_num_canister_snapshots").unwrap();
    assert_eq!(gauge, 1.0);
}

#[test]
fn canister_snapshot_metrics_are_consistent_after_canister_deletion() {
    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let canister_id = create_universal_canister_with_cycles(
        &env,
        Some(CanisterSettingsArgsBuilder::new().build()),
        INITIAL_CYCLES_BALANCE,
    );

    env.take_canister_snapshot(TakeCanisterSnapshotArgs::new(canister_id, None, None, None))
        .unwrap();

    let count = fetch_gauge(env.metrics_registry(), "scheduler_num_canister_snapshots").unwrap();
    assert_eq!(count, 1.0);
    let memory_usage = fetch_gauge(
        env.metrics_registry(),
        "scheduler_canister_snapshots_memory_usage_bytes",
    )
    .unwrap();
    assert_gt!(memory_usage, 0.0);

    env.stop_canister(canister_id)
        .expect("Error stopping canister.");
    env.delete_canister(canister_id)
        .expect("Error deleting canister.");

    let count = fetch_gauge(env.metrics_registry(), "scheduler_num_canister_snapshots").unwrap();
    assert_eq!(count, 0.0);
    let memory_usage = fetch_gauge(
        env.metrics_registry(),
        "scheduler_canister_snapshots_memory_usage_bytes",
    )
    .unwrap();
    assert_eq!(memory_usage, 0.0);
}

fn assert_replied(result: Result<WasmResult, UserError>) {
    match result {
        Ok(wasm_result) => match wasm_result {
            WasmResult::Reply(_) => {}
            WasmResult::Reject(err) => panic!("Unexpected reject: {err:?}"),
        },
        Err(err) => panic!("Got unexpected error: {err}"),
    }
}

// Asserts that the canister replied with the given expected number.
//
// This function panics if there was an error executing the message or the
// canister explicitly rejected it.
fn assert_replied_with(result: Result<WasmResult, UserError>, expected: i64) {
    match result {
        Ok(wasm_result) => match wasm_result {
            WasmResult::Reply(res) => {
                assert_eq!(i64::from_le_bytes(res[0..8].try_into().unwrap()), expected)
            }
            WasmResult::Reject(reject_message) => {
                panic!("Got unexpected reject: {reject_message}")
            }
        },
        Err(err) => panic!("Got unexpected error: {err}"),
    }
}

// Returns true iff the canister replied with the expected number.
fn replied_with(result: &Result<WasmResult, UserError>, expected: i64) -> bool {
    match result {
        Ok(wasm_result) => match wasm_result {
            WasmResult::Reply(res) => i64::from_le_bytes(res[0..8].try_into().unwrap()) == expected,
            WasmResult::Reject(_reject_message) => false,
        },
        Err(_) => false,
    }
}

fn assert_rejected(result: Result<WasmResult, UserError>) {
    match result {
        Ok(wasm_result) => match wasm_result {
            WasmResult::Reply(blob) => panic!("Unexpected reply: {blob:?}"),
            WasmResult::Reject(_err) => {}
        },
        Err(err) => panic!("Got unexpected error: {err}"),
    }
}

#[test]
fn exceeding_memory_capacity_fails_during_message_execution() {
    let subnet_config = SubnetConfig::new(SubnetType::Application);
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        subnet_config,
        HypervisorConfig {
            subnet_memory_capacity: NumBytes::from(21 * MIB),
            subnet_memory_reservation: NumBytes::from(MIB),
            ..Default::default()
        },
    ));
    env.set_checkpoints_enabled(true);

    let now = std::time::SystemTime::now();
    env.set_time(now);

    let canister_id = create_universal_canister_with_cycles(
        &env,
        Some(CanisterSettingsArgsBuilder::new().build()),
        INITIAL_CYCLES_BALANCE,
    );

    // Subnet has 20MiB memory capacity. There are `NUMBER_OF_EXECUTION_THREADS` ==
    // 4 running which means that the available subnet capacity would be split
    // across these many threads. If the canister is trying to allocate
    // 1MiB of memory, it'll keep succeeding until we reach 16MiB total allocated
    // capacity in the best case scenario and then should fail after that point because
    // the capacity split over 4 threads will be less than 1MiB (keep in mind the wasm
    // module of the canister also takes some space).
    let memory_to_allocate = MIB / WASM_PAGE_SIZE_IN_BYTES; // 1MiB in Wasm pages.
    let mut expected_result = 0;
    let mut iterations = 0;
    loop {
        let res = env.execute_ingress(
            canister_id,
            "update",
            wasm()
                .stable64_grow(memory_to_allocate)
                .reply_int64()
                .build(),
        );
        iterations += 1;
        if replied_with(&res, -1) {
            break;
        } else {
            assert_replied_with(res, expected_result);
            expected_result += memory_to_allocate as i64;
        }
    }
    assert_lt!(iterations, 16);
}

#[test]
fn subnet_memory_reservation_works() {
    let subnet_config = SubnetConfig::new(SubnetType::Application);
    let num_cores = subnet_config.scheduler_config.scheduler_cores as u64;
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        subnet_config,
        HypervisorConfig {
            subnet_memory_capacity: NumBytes::from(120 * MIB),
            subnet_memory_reservation: NumBytes::from(50 * MIB),
            ..Default::default()
        },
    ));

    let a_id = create_universal_canister_with_cycles(
        &env,
        Some(CanisterSettingsArgsBuilder::new().build()),
        INITIAL_CYCLES_BALANCE,
    );
    let b_id = create_universal_canister_with_cycles(
        &env,
        Some(CanisterSettingsArgsBuilder::new().build()),
        INITIAL_CYCLES_BALANCE,
    );

    let b = wasm()
        .accept_cycles(Cycles::from(1_000u128))
        .message_payload()
        .append_and_reply()
        .build();

    // The update call grow and the response callback both grow memory by
    // roughly `50MB / num_cores`.
    let a = wasm()
        .stable_grow(800)
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b)
                .on_reject(wasm().reject_message().reject())
                .on_reply(
                    wasm()
                        .stable_grow(800 / num_cores as u32)
                        .stable64_fill(0, 0, 1000 / num_cores)
                        .instruction_counter_is_at_least(1_000_000)
                        .message_payload()
                        .append_and_reply(),
                ),
            Cycles::from(2000u128),
        )
        .build();

    let res = env.execute_ingress(a_id, "update", a);
    assert_replied(res);
}

#[test]
fn subnet_memory_reservation_scales_with_number_of_cores() {
    let subnet_config = SubnetConfig::new(SubnetType::Application);
    let num_cores = subnet_config.scheduler_config.scheduler_cores as u64;
    assert_lt!(1, num_cores);
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        subnet_config,
        HypervisorConfig {
            subnet_memory_capacity: NumBytes::from(120 * MIB),
            subnet_memory_reservation: NumBytes::from(50 * MIB),
            ..Default::default()
        },
    ));

    let a_id = create_universal_canister_with_cycles(
        &env,
        Some(CanisterSettingsArgsBuilder::new().build()),
        INITIAL_CYCLES_BALANCE,
    );
    let b_id = create_universal_canister_with_cycles(
        &env,
        Some(CanisterSettingsArgsBuilder::new().build()),
        INITIAL_CYCLES_BALANCE,
    );

    let b = wasm()
        .accept_cycles(Cycles::from(1_000u128))
        .message_payload()
        .append_and_reply()
        .build();

    // The update call grow and the response callback both grow memory by
    // roughly 50MB. It should fail because there are at least two threads
    // and each threads gets `50MB / num_cores` reservation.
    let a = wasm()
        .stable_grow(800)
        .call_with_cycles(
            b_id,
            "update",
            call_args()
                .other_side(b)
                .on_reject(wasm().reject_message().reject())
                .on_reply(
                    wasm()
                        .stable_grow(800)
                        .stable64_fill(0, 0, 1000)
                        .instruction_counter_is_at_least(1_000_000)
                        .message_payload()
                        .append_and_reply(),
                ),
            Cycles::from(2000u128),
        )
        .build();

    let err = env.execute_ingress(a_id, "update", a).unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterTrapped,
        &format!("Error from Canister {a_id}: Canister trapped: stable memory out of bounds"),
    );
}

#[test]
fn canister_with_reserved_balance_is_not_uninstalled_too_early() {
    let subnet_config = SubnetConfig::new(SubnetType::Application);
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        subnet_config,
        HypervisorConfig::default(),
    ));

    let initial_cycles = Cycles::new(301 * B);
    let canister_a = create_universal_canister_with_cycles(
        &env,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_memory_allocation(100_000_000)
                .with_freezing_threshold(0)
                .build(),
        ),
        initial_cycles,
    );
    let canister_b = create_universal_canister_with_cycles(
        &env,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_memory_allocation(100_000_000)
                .with_freezing_threshold(0)
                .build(),
        ),
        initial_cycles,
    );

    // Reserve all cycles of canister B.
    {
        let mut state = env.get_latest_state().as_ref().clone();
        let canister = state.canister_state_mut(&canister_b).unwrap();
        canister
            .system_state
            .reserve_cycles(canister.system_state.balance())
            .unwrap();
        env.replace_canister_state(Arc::new(state), canister_b);
    }

    assert_eq!(env.cycle_balance(canister_b), 0);
    loop {
        env.advance_time(Duration::from_secs(2_000_000));
        env.tick();
        let canister_a_uninstalled = env.module_hash(canister_a).is_none();
        let canister_b_uninstalled = env.module_hash(canister_b).is_none();
        if canister_b_uninstalled {
            // If canister B got uninstalled, then canister A must also be
            // uninstalled because they started with the same cycle balance and
            // have the same memory allocation. Besides that, canister A was
            // created earlier.
            assert!(canister_a_uninstalled);
            break;
        }
    }
}

#[test]
fn canister_with_reserved_balance_is_not_frozen_too_early() {
    let subnet_config = SubnetConfig::new(SubnetType::Application);
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        subnet_config,
        HypervisorConfig::default(),
    ));

    let initial_cycles = Cycles::new(420 * B);

    let canister_id = create_universal_canister_with_cycles(
        &env,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_memory_allocation(100_000_000)
                .with_freezing_threshold(10_000_000)
                .build(),
        ),
        initial_cycles,
    );

    let result = env
        .execute_ingress(
            IC_00,
            Method::CanisterStatus,
            Encode!(&CanisterIdRecord::from(canister_id)).unwrap(),
        )
        .unwrap();

    let idle_cycles_burned_per_day = match result {
        WasmResult::Reply(reply) => CanisterStatusResultV2::decode(&reply)
            .unwrap()
            .idle_cycles_burned_per_day(),
        WasmResult::Reject(reject) => unreachable!("Unexpected reject {}", reject),
    };
    let seconds_per_day = 24 * 3500;
    let freezing_threshold = 10_000_000 * idle_cycles_burned_per_day / seconds_per_day;

    // Reserve most of the cycles of canister B.
    // The amount of remaining cycles in the main balance should be large enough
    // to start message execution but should be lower than the freezing
    // threshold.
    let reserved_cycles = Cycles::new(360 * B);
    {
        let mut state = env.get_latest_state().as_ref().clone();
        let canister = state.canister_state_mut(&canister_id).unwrap();
        canister
            .system_state
            .reserve_cycles(reserved_cycles)
            .unwrap();
        env.replace_canister_state(Arc::new(state), canister_id);
    }

    assert_lt!(env.cycle_balance(canister_id), freezing_threshold);

    let res = env.execute_ingress(
        canister_id,
        "update",
        wasm().message_payload().append_and_reply().build(),
    );
    assert_replied(res);
}

#[test]
fn test_create_canister_with_empty_blob_args() {
    // This test is checking backward compatibility without create canister args.
    let args = EmptyBlob {}.encode();

    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    env.set_checkpoints_enabled(false);
    let canister_a =
        create_universal_canister_with_cycles(&env, None, INITIAL_CYCLES_BALANCE * 100_u128);

    // Arrange.
    let create_canister = wasm()
        .call_with_cycles(
            IC_00,
            Method::CreateCanister,
            call_args().other_side(args),
            INITIAL_CYCLES_BALANCE,
        )
        .build();

    // Act.
    let res = env.execute_ingress(canister_a, "update", create_canister);

    // Assert.
    assert_replied(res);
}

#[test]
fn test_create_canister_with_different_controllers_amount() {
    const TEST_START: usize = 5;
    const THRESHOLD: usize = 10;
    const TEST_END: usize = 15;

    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    env.set_checkpoints_enabled(false);
    let canister_a =
        create_universal_canister_with_cycles(&env, None, INITIAL_CYCLES_BALANCE * 100_u128);

    for controllers_count in TEST_START..=TEST_END {
        // Arrange.
        let create_canister = wasm()
            .call_with_cycles(
                IC_00,
                Method::CreateCanister,
                call_args().other_side(
                    CreateCanisterArgs {
                        settings: Some(
                            CanisterSettingsArgsBuilder::new()
                                .with_controllers(vec![canister_a.into(); controllers_count])
                                .build(),
                        ),
                        sender_canister_version: None,
                    }
                    .encode(),
                ),
                INITIAL_CYCLES_BALANCE,
            )
            .build();

        // Act.
        let res = env.execute_ingress(canister_a, "update", create_canister);

        // Assert.
        if controllers_count <= THRESHOLD {
            // Assert that the canister was created with allowed amount of controllers.
            assert_replied(res);
        } else {
            // Assert that the canister was not created due to too many controllers.
            assert_rejected(res);
        }
    }
}

#[test]
fn test_update_settings_with_different_controllers_amount() {
    const TEST_START: usize = 5;
    const THRESHOLD: usize = 10;
    const TEST_END: usize = 15;

    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    env.set_checkpoints_enabled(false);
    let canister_a =
        create_universal_canister_with_cycles(&env, None, INITIAL_CYCLES_BALANCE * 100_u128);
    let canister_b = env.create_canister(Some(
        CanisterSettingsArgsBuilder::new()
            .with_controllers(vec![canister_a.into()])
            .build(),
    ));

    for controllers_count in TEST_START..=TEST_END {
        // Arrange.
        let update_settings = wasm()
            .call_with_cycles(
                IC_00,
                Method::UpdateSettings,
                call_args().other_side(
                    UpdateSettingsArgs::new(
                        canister_b,
                        CanisterSettingsArgsBuilder::new()
                            .with_controllers(vec![canister_a.into(); controllers_count])
                            .build(),
                    )
                    .encode(),
                ),
                INITIAL_CYCLES_BALANCE,
            )
            .build();

        // Act.
        let res = env.execute_ingress(canister_a, "update", update_settings);

        // Assert.
        if controllers_count <= THRESHOLD {
            // Assert that the canister was created with allowed amount of controllers.
            assert_replied(res);
        } else {
            // Assert that the canister was not created due to too many controllers.
            assert_rejected(res);
        }
    }
}

#[test]
fn execution_observes_oversize_messages() {
    let sm = StateMachine::new();

    let a_id = sm
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();

    // Canister A calls itself with a large message
    let a_calls_self_wasm = wasm()
        .stable_grow(100)
        .inter_update(
            a_id,
            call_args().eval_other_side(wasm().stable_read(0, 3 * 1024 * 1024).build()),
        )
        .build();
    let ingress_id = sm.send_ingress(
        PrincipalId::new_anonymous(),
        a_id,
        "update",
        a_calls_self_wasm,
    );

    assert!(matches!(
        sm.ingress_status(&ingress_id),
        IngressStatus::Known { .. }
    ));

    assert_eq!(
        1,
        fetch_int_counter(
            sm.metrics_registry(),
            "execution_environment_oversize_intra_subnet_messages_total"
        )
        .unwrap()
    );

    // Canister A calls B with a large message
    let b_id = sm
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();

    let a_calls_b_wasm = wasm()
        .inter_update(
            b_id,
            call_args().eval_other_side(wasm().stable_read(0, 3 * 1024 * 1024)),
        )
        .build();
    let ingress_id = sm.send_ingress(PrincipalId::new_anonymous(), a_id, "update", a_calls_b_wasm);

    assert!(matches!(
        sm.ingress_status(&ingress_id),
        IngressStatus::Known { .. }
    ));

    assert_eq!(
        2,
        fetch_int_counter(
            sm.metrics_registry(),
            "execution_environment_oversize_intra_subnet_messages_total"
        )
        .unwrap()
    );
}

#[test]
fn test_consensus_queue_invariant_on_exceeding_heap_delta_limit() {
    // Tests consensus queue invariant for the case of exceeding heap delta limit.
    // The test creates a universal canister that's used to both send an ECDSA
    // signing request but also to increase the stable memory to exceed the heap
    // delta limit.

    let heap_delta_limit = 100 * MIB;

    let mut subnet_config = SubnetConfig::new(SubnetType::Application);
    subnet_config.scheduler_config.subnet_heap_delta_capacity = NumBytes::new(heap_delta_limit);
    let key_id = EcdsaKeyId::from_str("Secp256k1:valid_key").unwrap();
    let env = StateMachineBuilder::new()
        .with_checkpoints_enabled(false)
        .with_config(Some(StateMachineConfig::new(
            subnet_config,
            HypervisorConfig::default(),
        )))
        .with_chain_key(MasterPublicKeyId::Ecdsa(key_id.clone()))
        .build();
    let canister_id = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            Cycles::new(1_000_000_000_000),
        )
        .unwrap();

    // Send SignWithECDSA message to trigger non-empty consensus queue.
    let _msg_id = env.send_ingress(
        PrincipalId::new_anonymous(),
        canister_id,
        "update",
        wasm()
            .call_with_cycles(
                IC_00,
                Method::SignWithECDSA,
                call_args().other_side(
                    Encode!(&SignWithECDSAArgs {
                        message_hash: [0; 32],
                        derivation_path: DerivationPath::new(Vec::new()),
                        key_id
                    })
                    .unwrap(),
                ),
                Cycles::new(2_000_000_000),
            )
            .build(),
    );

    // Tick #1: heap delta is below the limit, process sign_with_ecdsa message (no response yet)...
    assert_lt!(env.heap_delta_estimate_bytes(), heap_delta_limit);

    // and grow and fill stable memory with a bit more than `heap_delta_limit` data.
    let _msg_id = env.send_ingress(
        PrincipalId::new_anonymous(),
        canister_id,
        "update",
        wasm()
            .stable64_grow((heap_delta_limit / WASM_PAGE_SIZE_IN_BYTES) + 1)
            .stable64_fill(0, 42, heap_delta_limit + 1)
            .build(),
    );
    env.tick();

    // Tick #2: heap delta is above the limit, the response is added to consensus queue before executing the payload.
    assert_lt!(heap_delta_limit, env.heap_delta_estimate_bytes());
    env.tick();

    // Tick #3: round is executed normally.
    env.tick();
}

#[test]
fn heap_delta_initial_reserve_allows_round_executions_right_after_checkpoint() {
    fn setup(subnet_heap_delta_capacity: u64, heap_delta_initial_reserve: u64) -> StateMachine {
        let mut subnet_config = SubnetConfig::new(SubnetType::Application);
        subnet_config.scheduler_config.subnet_heap_delta_capacity =
            subnet_heap_delta_capacity.into();
        subnet_config.scheduler_config.heap_delta_initial_reserve =
            heap_delta_initial_reserve.into();

        StateMachineBuilder::new()
            .with_checkpoint_interval_length(11)
            .with_config(Some(StateMachineConfig::new(
                subnet_config,
                HypervisorConfig::default(),
            )))
            .build()
    }

    fn install_canister(env: &StateMachine) -> Result<CanisterId, UserError> {
        let wasm = wat::parse_str(TEST_CANISTER).expect("invalid WAT");
        env.install_canister_with_cycles(wasm, vec![], None, Cycles::new(301 * B))
    }

    fn send_ingress(env: &StateMachine, canister_id: &CanisterId) -> MessageId {
        env.send_ingress(PrincipalId::new_anonymous(), *canister_id, "inc", vec![])
    }

    ////////////////////////////////////////////////////////////////////
    // First test case. Making sure that the execution is happening
    // even with minimal heap delta capacity.

    // Set the heap delta capacity to minimum (2), with minimal initial reserve (1).
    let env = setup(1, 1);

    // With minimal subnet heap delta capacity we should start
    // the round execution anyway, so the canister installation should succeed.
    // One empty round is always performed when creating a `StateMachine`
    // (to have a certified state) and canister install takes 2 rounds
    // => we are now at Round 3.
    let canister_id = install_canister(&env).unwrap();
    // Assert the canister install does not touch the heap.
    assert_eq!(env.heap_delta_estimate_bytes(), 0);

    // The heap delta estimate is still zero, so the ingress execution should succeed.
    // Round 4.
    let msg_id = send_ingress(&env, &canister_id);
    let status = env.ingress_status(&msg_id);
    assert_matches!(
        status,
        IngressStatus::Known {
            state: IngressState::Completed(_),
            ..
        }
    );

    // Remember the heap delta estimate for the second test case.
    let ingress_heap_delta_estimate = env.heap_delta_estimate_bytes();

    // As the subnet capacity is at minimum, any other message execution
    // should be postponed after the next checkpoint.
    // Round 5.
    let msg_id = send_ingress(&env, &canister_id);

    // The ingress should be executed after the checkpoint.
    // Round 6-12.
    for _ in 6..=12 {
        env.tick();
        let status = env.ingress_status(&msg_id);
        assert_matches!(
            status,
            IngressStatus::Known {
                // Received, but not completed.
                state: IngressState::Received,
                ..
            }
        );
    }
    let status = env.ingress_status(&msg_id);
    assert_matches!(
        status,
        IngressStatus::Known {
            // Received, but not completed.
            state: IngressState::Received,
            ..
        }
    );
    // The `heap_delta_estimate` is reset after the checkpoint round, so the message
    // will be executed in round 12.
    // Round 12.
    env.tick();
    let status = env.ingress_status(&msg_id);
    assert_matches!(
        status,
        IngressStatus::Known {
            // Now completed.
            state: IngressState::Completed(_),
            ..
        }
    );

    ////////////////////////////////////////////////////////////////////
    // Second test case. Making sure that the heap delta is scaled.

    // Using previous estimates, set the heap delta capacity enough
    // to execute three ingress messages.
    // The initial reserve is just enough to execute one message.
    // The checkpoint interval length is 12 rounds.
    let env = setup(ingress_heap_delta_estimate * 3, ingress_heap_delta_estimate);

    // Install canister.
    // One empty round is always performed when creating a `StateMachine`
    // (to have a certified state) and canister install takes 2 rounds
    // => we are now at Round 3.
    let canister_id = install_canister(&env).unwrap();
    // Assert the canister install does not touch the heap.
    assert_eq!(env.heap_delta_estimate_bytes(), 0);

    // First ingress message should take `ingress_heap_delta_estimate`.
    // Round 4.
    let msg_id = send_ingress(&env, &canister_id);
    let status = env.ingress_status(&msg_id);
    assert_matches!(
        status,
        IngressStatus::Known {
            state: IngressState::Completed(_),
            ..
        }
    );

    // As there are a few rounds has passed, the second ingress message
    // execution should also succeed now.
    // Round 5.
    let msg_id = send_ingress(&env, &canister_id);
    let status = env.ingress_status(&msg_id);
    assert_matches!(
        status,
        IngressStatus::Known {
            state: IngressState::Completed(_),
            ..
        }
    );

    // The third message execution should be postponed to the second half
    // of the checkpoint interval (12 / 2 = 6):
    // - subnet heap delta capacity: 3 * ingress_heap_delta_estimate;
    // - heap delta initial reserve: ingress_heap_delta_estimate;
    // - remaining heap delta: capacity - reserve = 2 * ingress_heap_delta_estimate;
    // - scaled remaining heap delta: remaining heap delta / 2 = ingress_heap_delta_estimate;
    // - heap delta limit: capacity - scaled remaining heap delta = 2 * ingress_heap_delta_estimate;
    // - current heap delta: 2 * ingress_heap_delta_estimate.
    // Round 6 (message execution still skipped because of equality between heap delta limit and current heap delta).
    let msg_id = send_ingress(&env, &canister_id);
    let status = env.ingress_status(&msg_id);
    assert_matches!(
        status,
        IngressStatus::Known {
            state: IngressState::Received,
            ..
        }
    );

    // Round 7.
    env.tick();

    // The third message must be executed now that current heap delta is less than heap delta limit.
    let status = env.ingress_status(&msg_id);
    assert_matches!(
        status,
        IngressStatus::Known {
            state: IngressState::Completed(_),
            ..
        }
    );
}

const DIRTY_PAGE_CANISTER: &str = r#"
    (module
        (func $dirty (i32.store (i32.const 1) (i32.const 2)))
        (start $dirty)
        (memory $memory 1)
    )"#;

#[test]
fn current_interval_length_works_on_app_subnets() {
    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let wasm = wat::parse_str(DIRTY_PAGE_CANISTER).unwrap();
    let _canister_id = env
        .install_canister_with_cycles(wasm, vec![], None, Cycles::new(301 * B))
        .unwrap();

    // One empty round is always performed when creating a `StateMachine`
    // (to have a certified state) and canister install takes 2 rounds
    // => we are now at Round 3.
    for _ in 3..500 {
        // Assert there is a dirty page.
        assert!(env.heap_delta_estimate_bytes() > 0);
        env.tick();
    }
    // Assert there are no dirty pages after the checkpoint.
    assert_eq!(env.heap_delta_estimate_bytes(), 0);
}

#[test]
fn current_interval_length_works_on_system_subnets() {
    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::System)
        .build();

    let wasm = wat::parse_str(DIRTY_PAGE_CANISTER).unwrap();
    let _canister_id = env
        .install_canister_with_cycles(wasm, vec![], None, Cycles::new(100_000_000_000))
        .unwrap();

    // One empty round is always performed when creating a `StateMachine`
    // (to have a certified state) and canister install takes 2 rounds
    // => we are now at Round 3.
    for _ in 3..200 {
        // Assert there is a dirty page.
        assert!(env.heap_delta_estimate_bytes() > 0);
        env.tick();
    }
    // Assert there are no dirty pages after the checkpoint.
    assert_eq!(env.heap_delta_estimate_bytes(), 0);
}

// To run the test:
//     bazel test //rs/execution_environment:execution_environment_misc_integration_tests/execution_test --test_arg=system_subnets_are_not_rate_limited --test_arg=--include-ignored
#[test]
#[ignore]
fn system_subnets_are_not_rate_limited() {
    const GIB: u64 = 1024 * MIB;
    const WASM_PAGE_SIZE: u64 = 65_536;
    const SUBNET_HEAP_DELTA_CAPACITY: u64 = 140 * GIB;
    // It's a bit less than 2GiB, otherwise the vector allocation in canister traps.
    const DIRTY_2G_CHUNK: u64 = 2 * GIB - WASM_PAGE_SIZE;

    fn send_2g_ingress(i: u64, env: &StateMachine, canister_id: &CanisterId) -> MessageId {
        env.send_ingress(
            PrincipalId::new_anonymous(),
            *canister_id,
            "update",
            wasm()
                .stable64_grow(DIRTY_2G_CHUNK / WASM_PAGE_SIZE)
                // Stable fill allocates a vector first, so there will be ~4GiB
                // of dirty pages in the first round.
                .stable64_fill(i * DIRTY_2G_CHUNK, 1, DIRTY_2G_CHUNK)
                .reply_data(&[42])
                .build(),
        )
    }

    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::System)
        .build();

    let canister_id = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            Cycles::new(100_000_000_000),
        )
        .unwrap();

    // For 140GiB subnet heap delta capacity we should be able to iterate
    // `140 / 2 = 70` times (taking into account 2GiB of dirty Wasm heap).
    for i in 0..SUBNET_HEAP_DELTA_CAPACITY / DIRTY_2G_CHUNK {
        let msg_id = send_2g_ingress(i, &env, &canister_id);
        let status = env.ingress_status(&msg_id);
        assert_matches!(
            status,
            IngressStatus::Known {
                state: IngressState::Completed(_),
                ..
            }
        );
    }
    // Assert that we reached the subnet heap delta capacity (140 GiB) in 70 rounds.
    assert!(env.heap_delta_estimate_bytes() >= SUBNET_HEAP_DELTA_CAPACITY);

    // Once the subnet capacity is reached, there should be no further executions.
    let msg_id = send_2g_ingress(70, &env, &canister_id);
    let status = env.ingress_status(&msg_id);
    assert_matches!(
        status,
        IngressStatus::Known {
            state: IngressState::Received,
            ..
        }
    );
}

#[test]
fn toolchain_error_message() {
    let sm = StateMachine::new();

    // Will fail validation because two memories are defined.
    let wat = r#"
        (module
            (func $update)
            (memory 1)
            (memory 1)
            (export "canister_update update" (func $update))
        )"#;

    let wasm = wat::parse_str(wat).unwrap();

    let err = sm
        .install_canister_with_cycles(wasm, vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap_err();

    assert_eq!(
        err.description(),
        "Error from Canister \
    rwlgt-iiaaa-aaaaa-aaaaa-cai: Canister's Wasm module is not valid: Wasmtime \
    failed to validate wasm module wasmtime::Module::validate() failed with \
    multiple memories (at offset 0x14).\n\
    If you are running this canister in a test environment (e.g., dfx), make sure the test environment is up to date. Otherwise, this is likely an error with the compiler/CDK toolchain being used to \
    build the canister. Please report the error to IC devs on the forum: \
    https://forum.dfinity.org and include which language/CDK was used to \
    create the canister."
    );
}

fn helper_best_effort_responses(
    start_time_seconds: u32,
    timeout_seconds: Option<u32>,
    expected_deadline_seconds: u32,
) {
    let subnet_config = SubnetConfig::new(SubnetType::Application);

    let env = StateMachineBuilder::new()
        .with_time(Time::from_secs_since_unix_epoch(start_time_seconds as u64).unwrap())
        .with_config(Some(StateMachineConfig::new(
            subnet_config,
            HypervisorConfig::default(),
        )))
        .build();

    let sender: CanisterId = create_universal_canister_with_cycles(
        &env,
        Some(CanisterSettingsArgsBuilder::new().build()),
        INITIAL_CYCLES_BALANCE,
    );

    let receiver: CanisterId = create_universal_canister_with_cycles(
        &env,
        Some(CanisterSettingsArgsBuilder::new().build()),
        INITIAL_CYCLES_BALANCE,
    );

    let call_args = call_args()
        .other_side(wasm().msg_deadline().reply_int64())
        .on_reply(wasm().message_payload().append_and_reply());

    let msg = if let Some(timeout_seconds) = timeout_seconds {
        wasm()
            .call_simple_with_cycles_and_best_effort_response(
                receiver,
                "update",
                call_args,
                Cycles::new(0),
                timeout_seconds,
            )
            .build()
    } else {
        wasm().call_simple(receiver, "update", call_args).build()
    };

    // Ingress message is sent to canister `A`, during its execution canister `A`
    // calls canister `B`. While executing the canister message, canister `B`
    // invokes `msg_deadline()` and attaches the result to a reply to canister
    // `A` message. Canister `A` forwards the received response as a reply to
    // the Ingress message.

    match env.execute_ingress(sender, "update", msg).unwrap() {
        WasmResult::Reply(result) => assert_eq!(
            Time::from_secs_since_unix_epoch(expected_deadline_seconds as u64)
                .unwrap()
                .as_nanos_since_unix_epoch(),
            u64::from_le_bytes(result.try_into().unwrap())
        ),
        _ => panic!("Unexpected result"),
    };
}

#[test]
fn best_effort_responses_no_timeout() {
    // When no timeout is set, ic0_msg_deadline() should return constant (=0)
    // representing that the call is not best-effort call.
    let start_time_seconds = 100;

    let expected_deadline_seconds = NO_DEADLINE.as_secs_since_unix_epoch();

    helper_best_effort_responses(start_time_seconds, None, expected_deadline_seconds);
}

#[test]
fn best_effort_responses_timeout_larger_than_max_allowed() {
    // `timeout_seconds` should be upper bounded with the `MAX_CALL_TIMEOUT_SECONDS`.
    let start_time_seconds = 100;
    let timeout_seconds = 2 * MAX_CALL_TIMEOUT_SECONDS;
    let expected_deadline_seconds = start_time_seconds + MAX_CALL_TIMEOUT_SECONDS;

    helper_best_effort_responses(
        start_time_seconds,
        Some(timeout_seconds),
        expected_deadline_seconds,
    );
}

#[test]
fn best_effort_responses_valid_timeout() {
    // When `timeout_seconds` is smaller than `MAX_CALL_TIMEOUT_SECONDS` than the
    // value of `deadline` should be equal to `start_time_seconds` + `timeout_seconds`.
    let start_time_seconds = 100;
    let timeout_seconds = 150;
    let expected_deadline_seconds = start_time_seconds + timeout_seconds;

    helper_best_effort_responses(
        start_time_seconds,
        Some(timeout_seconds),
        expected_deadline_seconds,
    );
}

#[test]
fn test_malicious_input() {
    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let wasm = wat::parse_str(
            r#"(module
                  (import "ic0" "msg_reply" (func $msg_reply))
                  (import "ic0" "msg_reply_data_append"
                    (func $msg_reply_data_append (param i32) (param i32)))
                  (import "ic0" "msg_arg_data_size"
                    (func $msg_arg_data_size (result i32)))
                  (import "ic0" "msg_arg_data_copy"
                    (func $msg_arg_data_copy (param i32) (param i32) (param i32)))
                  (import "ic0" "msg_caller_size"
                    (func $msg_caller_size (result i32)))
                  (import "ic0" "msg_caller_copy"
                    (func $msg_caller_copy (param i32) (param i32) (param i32)))
                  (import "ic0" "data_certificate_copy"
                    (func $data_certificate_copy (param i32) (param i32) (param i32)))
                  (import "ic0" "data_certificate_size"
                    (func $data_certificate_size (result i32)))
                  (import "ic0" "data_certificate_present"
                    (func $data_certificate_present (result i32)))
                  (import "ic0" "certified_data_set"
                    (func $certified_data_set (param i32) (param i32)))
                  (import "ic0" "call_new"
                    (func $ic0_call_new
                    (param i32 i32)
                    (param $method_name_src i32)    (param $method_name_len i32)
                    (param $reply_fun i32)          (param $reply_env i32)
                    (param $reject_fun i32)         (param $reject_env i32)
                  ))
                  (import "ic0" "call_perform" (func $ic0_call_perform (result i32)))

                  (func $proxy_msg_reply_data_append
                    (call $msg_arg_data_copy (i32.const 0) (i32.const 0) (call $msg_arg_data_size))
                    (call $msg_reply_data_append (i32.load (i32.const 0)) (i32.load (i32.const 4)))
                    (call $msg_reply))

                  (func $proxy_msg_arg_data_copy_from_buffer_without_input
                    (call $msg_arg_data_copy (i32.const 0) (i32.const 0) (i32.const 10)))

                  (func $proxy_msg_arg_data_copy_to_oob_buffer
                    (call $msg_arg_data_copy (i32.const 65536) (i32.const 0) (i32.const 10))
                    (call $msg_reply))

                  (func $proxy_msg_arg_data_copy_return_last_4_bytes
                    (call $msg_arg_data_copy (i32.const 0) (i32.const 0) (i32.const 65536))
                    (call $msg_reply_data_append (i32.const 65532) (i32.const 4))
                    (call $msg_reply))

                  ;; All the function below are not used
                  (func $proxy_data_certificate_present
                    (i32.const 0)
                    (call $data_certificate_present)
                    (i32.store)
                    (call $msg_reply_data_append (i32.const 0) (i32.const 1))
                    (call $msg_reply))

                  (func $proxy_certified_data_set
                    (call $msg_arg_data_copy (i32.const 0) (i32.const 0) (call $msg_arg_data_size))
                    (call $certified_data_set (i32.const 0) (call $msg_arg_data_size))
                    (call $msg_reply_data_append (i32.const 0) (call $msg_arg_data_size))
                    (call $msg_reply))

                  (func $proxy_data_certificate_copy
                    (call $data_certificate_copy (i32.const 0) (i32.const 0) (i32.const 32))
                    (call $msg_reply_data_append (i32.const 0) (i32.const 32))
                    (call $msg_reply))

                  (func $f_100 (result i32)
                    i32.const 100)
                  (func $f_200 (result i32)
                    i32.const 200)

                  (type $return_i32 (func (result i32))) ;; if this was f32, type checking would fail
                  (func $callByIndex
                    (i32.const 0)
                    (call_indirect (type $return_i32) (i32.const 0))
                    (i32.store)
                    (call $msg_reply_data_append (i32.const 0) (i32.const 4))
                    (call $msg_reply))

                  (table funcref (elem $f_100 $f_200))
                  (memory $memory 1)
                  (export "memory" (memory $memory))
                  (export "canister_query callByIndex" (func $callByIndex))
                  (export "canister_query proxy_msg_reply_data_append" (func $proxy_msg_reply_data_append))
                  (export "canister_query proxy_msg_arg_data_copy_from_buffer_without_input" (func $proxy_msg_arg_data_copy_from_buffer_without_input))
                  (export "canister_query proxy_msg_arg_data_copy_to_oob_buffer" (func $proxy_msg_arg_data_copy_to_oob_buffer))
                  (export "canister_query proxy_data_certificate_present" (func $proxy_data_certificate_present))
                  (export "canister_update proxy_certified_data_set" (func $proxy_certified_data_set))
                  (export "canister_query proxy_data_certificate_copy" (func $proxy_data_certificate_copy))
                  )"#,
        ).unwrap();

    let canister_id = create_canister_with_cycles(&env, wasm.clone(), None, INITIAL_CYCLES_BALANCE);

    helper_tests_for_illegal_wasm_memory_access(&env, &canister_id);

    helper_tests_for_stale_data_in_buffer_between_calls(&env, &canister_id);

    helper_tests_for_illegal_data_buffer_access(&env, &canister_id);
}

fn helper_tests_for_illegal_wasm_memory_access(env: &StateMachine, canister_id: &CanisterId) {
    // msg_reply_data_append(0, 65536) => expect no error
    let ret_val = env.query(
        *canister_id,
        "proxy_msg_reply_data_append",
        vec![0, 0, 0, 0, 0, 0, 1, 0],
    );

    assert!(
        ret_val.is_ok(),
        "msg_reply_data_append(0, 65536) failed. Error: {}",
        ret_val.unwrap_err()
    );

    // msg_reply_data_append(0, 65537) => expect no error
    let ret_val = env
        .query(
            *canister_id,
            "proxy_msg_reply_data_append",
            vec![0, 0, 0, 0, 1, 0, 1, 0],
        )
        .unwrap_err();

    assert_eq!(ret_val.code(), ErrorCode::CanisterContractViolation);

    let containing_str =
        "violated contract: msg.reply: src=0 + length=65537 exceeds the slice size=65536";

    assert!(
        ret_val.description().contains(containing_str),
        "expected msg_reply_data_append(0, 65537) to fail"
    );

    // msg_reply_data_append(65536, 10) => expect error
    let ret_val = env
        .query(
            *canister_id,
            "proxy_msg_reply_data_append",
            vec![0, 0, 1, 0, 10, 0, 0, 0],
        )
        .unwrap_err();

    assert_eq!(ret_val.code(), ErrorCode::CanisterContractViolation);

    let containing_str =
        "violated contract: msg.reply: src=65536 + length=10 exceeds the slice size=65536";

    assert!(
        ret_val.description().contains(containing_str),
        "expected msg_reply_data_append(65536, 10) to fail"
    );
}

fn helper_tests_for_stale_data_in_buffer_between_calls(
    env: &StateMachine,
    canister_id: &CanisterId,
) {
    // Between every query the input data buffer is expected to be reset
    // and no stale data from previous query can be found. The following
    // test check this case
    let mut input = vec![10; (32 * 1024) + 8];
    for i in input.iter_mut().take(8) {
        *i = 0;
    }
    input[0] = 8; //bytes 0x00 0x00 0x00 0x08 start index = 8 - Little Endian
    input[5] = 128; //bytes 0x00 0x00 0x80 0x00 size = 32768 - Little Endian
    let ret_val = env.query(*canister_id, "proxy_msg_reply_data_append", input);

    assert!(
        ret_val.is_ok(),
        "Check for stale data step 1 failed. Error: {}",
        ret_val.unwrap_err()
    );

    let data = match ret_val.unwrap() {
        WasmResult::Reply(data) => data,
        WasmResult::Reject(msg) => panic!("Unexpected reject {msg}."),
    };

    assert_eq!(
        [10, 10, 10, 10],
        &data[0..4],
        "first read - expected [10, 10, 10, 10] at data index 0 to 4 {:?}",
        &data[0..4]
    );
    assert_eq!(
        [10, 10, 10, 10],
        &data[32764..32768],
        "first read - expected [10, 10, 10, 10] at data index 32765 to 32768 {:?}",
        &data[32764..32768]
    );

    let ret_val = env.query(
        *canister_id,
        "proxy_msg_reply_data_append",
        vec![8, 0, 0, 0, 0, 128, 0, 0],
    );

    assert!(
        ret_val.is_ok(),
        "Check for stale data step 2 failed. Error: {}",
        ret_val.unwrap_err()
    );

    let data = match ret_val.unwrap() {
        WasmResult::Reply(data) => data,
        WasmResult::Reject(msg) => panic!("Unexpected reject {msg}."),
    };

    assert_eq!(
        [0, 0, 0, 0],
        &data[0..4],
        "second read - stale data present, expected [0, 0, 0, 0] at data index 0 to 4 {:?}",
        &data[0..4]
    );
    assert_eq!(
        [0, 0, 0, 0],
        &data[32764..32768],
        "second read - stale data present, expected [0, 0, 0, 0] at data index 32765 to 32768 {:?}",
        &data[32764..32768]
    );
}

fn helper_tests_for_illegal_data_buffer_access(env: &StateMachine, canister_id: &CanisterId) {
    // No input given but still read the input buffer
    let ret_val = env
        .query(
            *canister_id,
            "proxy_msg_arg_data_copy_from_buffer_without_input",
            vec![],
        )
        .unwrap_err();

    assert_eq!(ret_val.code(), ErrorCode::CanisterContractViolation);

    let containing_str = "violated contract: ic0.msg_arg_data_copy payload: src=0 + length=10 exceeds the slice size=0";

    assert!(
        ret_val.description().contains(containing_str),
        "Should return error if try to read input buffer on no input"
    );

    // copy data from argument buffer to out of bound internal buffer
    let ret_val = env
        .query(
            *canister_id,
            "proxy_msg_arg_data_copy_to_oob_buffer",
            vec![1; 10],
        )
        .unwrap_err();

    assert_eq!(ret_val.code(), ErrorCode::CanisterContractViolation);

    let containing_str = "violated contract: ic0.msg_arg_data_copy heap: src=65536 + length=10 exceeds the slice size=65536";

    assert!(
        ret_val.description().contains(containing_str),
        "Should return error if input data is copied to out of bound internal buffer. Instead, it returns unexpected message: {}.",
        ret_val.description()
    );
}

fn fetch_wasm_memory_limit(env: &StateMachine, canister_id: CanisterId) -> NumBytes {
    let limit: u64 = env
        .canister_status(canister_id)
        .unwrap()
        .unwrap()
        .settings()
        .wasm_memory_limit()
        .0
        .try_into()
        .unwrap();
    NumBytes::new(limit)
}

#[test]
fn set_wasm_memory_limit_below_memory_usage() {
    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let wat = r#"(module
        (import "ic0" "msg_reply" (func $msg_reply))
        (func (export "canister_update test") (call $msg_reply))
        (memory $memory 65535)
    )"#;

    let canister_id = env
        .install_canister_with_cycles(
            wat::parse_str(wat).unwrap(),
            vec![],
            Some(
                CanisterSettingsArgsBuilder::new()
                    .with_wasm_memory_limit(10_000_000_000)
                    .build(),
            ),
            Cycles::new(1_000_000 * B),
        )
        .unwrap();

    let wasm_memory_limit = fetch_wasm_memory_limit(&env, canister_id);
    assert_eq!(wasm_memory_limit, NumBytes::new(10_000_000_000));

    env.update_settings(
        &canister_id,
        CanisterSettingsArgsBuilder::new()
            .with_wasm_memory_limit(10)
            .build(),
    )
    .unwrap();

    let wasm_memory_limit = fetch_wasm_memory_limit(&env, canister_id);
    assert_eq!(wasm_memory_limit, NumBytes::new(10));

    let err = env
        .execute_ingress(
            canister_id,
            "test",
            wasm().push_bytes(&[1, 2, 3]).append_and_reply().build(),
        )
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterWasmMemoryLimitExceeded);
}

#[test]
fn set_wasm_memory_limit_to_4_gib() {
    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let initial_cycles = Cycles::new(1_000_000 * B);
    let canister_id = create_universal_canister_with_cycles(&env, None, initial_cycles);

    env.update_settings(
        &canister_id,
        CanisterSettingsArgsBuilder::new()
            .with_wasm_memory_limit(4 * 1024 * 1024 * 1024)
            .build(),
    )
    .unwrap();

    let wasm_memory_limit = fetch_wasm_memory_limit(&env, canister_id);
    assert_eq!(wasm_memory_limit, NumBytes::new(4 * 1024 * 1024 * 1024));

    let result = env
        .execute_ingress(
            canister_id,
            "update",
            wasm().push_bytes(&[1, 2, 3]).append_and_reply().build(),
        )
        .unwrap();
    assert_eq!(result, WasmResult::Reply(vec![1, 2, 3]));
}

#[test]
fn set_wasm_memory_limit_to_zero() {
    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let initial_cycles = Cycles::new(1_000_000 * B);
    let canister_id = create_universal_canister_with_cycles(&env, None, initial_cycles);

    env.update_settings(
        &canister_id,
        CanisterSettingsArgsBuilder::new()
            .with_wasm_memory_limit(0)
            .build(),
    )
    .unwrap();

    let wasm_memory_limit = fetch_wasm_memory_limit(&env, canister_id);
    assert_eq!(wasm_memory_limit, NumBytes::new(0));

    // The Wasm memory limit of 0 means that there is no limit.
    let result = env
        .execute_ingress(
            canister_id,
            "update",
            wasm().push_bytes(&[1, 2, 3]).append_and_reply().build(),
        )
        .unwrap();
    assert_eq!(result, WasmResult::Reply(vec![1, 2, 3]));
}

#[test]
fn set_wasm_memory_limit_from_another_canister() {
    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let initial_cycles = Cycles::new(1_000_000 * B);
    let canister1 = create_universal_canister_with_cycles(&env, None, initial_cycles);
    let canister2 = create_universal_canister_with_cycles(
        &env,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![PrincipalId::new_anonymous(), canister1.get()])
                .build(),
        ),
        initial_cycles,
    );

    let result = env
        .execute_ingress(
            canister1,
            "update",
            wasm()
                .call_simple(
                    IC_00,
                    "update_settings",
                    call_args()
                        .other_side(
                            UpdateSettingsArgs {
                                canister_id: canister2.get(),
                                settings: CanisterSettingsArgsBuilder::new()
                                    .with_wasm_memory_limit(4 * 1024 * 1024 * 1024)
                                    .build(),
                                sender_canister_version: None,
                            }
                            .encode(),
                        )
                        .on_reply(wasm().message_payload().append_and_reply())
                        .on_reject(wasm().reject_message().reject()),
                )
                .build(),
        )
        .unwrap();

    assert_eq!(result, WasmResult::Reply(EmptyBlob.encode()));

    let wasm_memory_limit = fetch_wasm_memory_limit(&env, canister2);
    assert_eq!(wasm_memory_limit, NumBytes::new(4 * 1024 * 1024 * 1024));

    let result = env
        .execute_ingress(
            canister2,
            "update",
            wasm().push_bytes(&[1, 2, 3]).append_and_reply().build(),
        )
        .unwrap();
    assert_eq!(result, WasmResult::Reply(vec![1, 2, 3]));
}

#[test]
fn canister_create_with_default_wasm_memory_limit() {
    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let initial_cycles = Cycles::new(301 * B);
    let canister_id = create_universal_canister_with_cycles(&env, None, initial_cycles);

    let wasm_memory_limit = fetch_wasm_memory_limit(&env, canister_id);
    assert_eq!(wasm_memory_limit, DEFAULT_WASM_MEMORY_LIMIT);
}

#[test]
fn initialize_default_wasm_memory_limit_with_low_memory_usage() {
    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let initial_cycles = Cycles::new(301 * B);
    let canister_id = create_universal_canister_with_cycles(&env, None, initial_cycles);

    let wasm_memory_limit = fetch_wasm_memory_limit(&env, canister_id);
    assert_eq!(wasm_memory_limit, DEFAULT_WASM_MEMORY_LIMIT);

    // Clear the Wasm memory limit.
    {
        let mut state = env.get_latest_state().as_ref().clone();
        let canister = state.canister_state_mut(&canister_id).unwrap();
        canister.system_state.wasm_memory_limit = None;
        env.replace_canister_state(Arc::new(state), canister_id);
    }

    env.tick();

    let wasm_memory_limit = fetch_wasm_memory_limit(&env, canister_id);
    assert_eq!(wasm_memory_limit, DEFAULT_WASM_MEMORY_LIMIT);
}

#[test]
fn initialize_default_wasm_memory_limit_with_high_memory_usage() {
    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let wat = r#"(module
        (import "ic0" "msg_reply" (func $msg_reply))
        (func $grow_mem
            (drop (memory.grow (i32.const 49152)))
            (call $msg_reply)
        )
        (export "canister_update grow_mem" (func $grow_mem))
        (memory $memory 0)
    )"#;

    let initial_cycles = Cycles::new(1_000_000 * B);
    let canister_id = env
        .install_canister_with_cycles(
            wat::parse_str(wat).unwrap(),
            vec![],
            Some(
                CanisterSettingsArgsBuilder::new()
                    .with_wasm_memory_limit(10_000_000_000)
                    .build(),
            ),
            initial_cycles,
        )
        .unwrap();

    let wasm_memory_limit = fetch_wasm_memory_limit(&env, canister_id);
    assert_eq!(wasm_memory_limit, NumBytes::new(10_000_000_000));

    env.execute_ingress(canister_id, "grow_mem", vec![])
        .unwrap();

    // Check Wasm memory usage and clear the Wasm memory limit.
    {
        let mut state = env.get_latest_state().as_ref().clone();
        let canister = state.canister_state_mut(&canister_id).unwrap();
        canister.system_state.wasm_memory_limit = None;
        assert_eq!(
            canister.execution_state.as_ref().unwrap().wasm_memory.size,
            NumWasmPages::new(49152)
        );
        env.replace_canister_state(Arc::new(state), canister_id);
    }

    env.tick();

    let wasm_memory_limit = fetch_wasm_memory_limit(&env, canister_id);
    // The initialized Wasm memory should be the average of the current memory
    // usage and the hard limit of 4GiB.
    assert_eq!(
        wasm_memory_limit,
        NumBytes::new((49152 + 65536) / 2 * WASM_PAGE_SIZE_IN_BYTES)
    );
}

#[test]
fn do_not_initialize_wasm_memory_limit_if_it_is_not_empty() {
    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let wat = "(module)";
    let initial_cycles = Cycles::new(1_000_000 * B);
    let canister_id = env
        .install_canister_with_cycles(
            wat::parse_str(wat).unwrap(),
            vec![],
            Some(
                CanisterSettingsArgsBuilder::new()
                    .with_wasm_memory_limit(10_000_000_000)
                    .build(),
            ),
            initial_cycles,
        )
        .unwrap();

    let wasm_memory_limit = fetch_wasm_memory_limit(&env, canister_id);
    assert_eq!(wasm_memory_limit, NumBytes::new(10_000_000_000));

    env.tick();

    let wasm_memory_limit = fetch_wasm_memory_limit(&env, canister_id);
    assert_eq!(wasm_memory_limit, NumBytes::new(10_000_000_000));
}

/// Even if a Wasm module has inital memory size 0, it is allowed to have data
/// segments of length 0 inserted at address 0. This test checks that such data
/// segments don't trigger any of our critical errors.
#[test]
fn no_critical_error_on_empty_data_segment() {
    let env = StateMachine::new();
    let wat: &str = r#"
        (module
            (memory (;0;) i64 0)
            (data (;0;) (i64.const 0) "")
        )
    "#;
    let _id = env.install_canister_wat(wat, vec![], None);

    // A module with an empty data segment outside of memory should fail to
    // install, but not trigger any critical errors.
    let wat: &str = r#"
        (module
            (memory (;0;) i64 0)
            (data (;0;) (i64.const 1) "")
        )
    "#;
    let wasm = wat::parse_str(wat).unwrap();
    let id = env.create_canister(None);
    let error = env
        .install_wasm_in_mode(id, CanisterInstallMode::Install, wasm, vec![])
        .unwrap_err();
    error.assert_contains(
        ErrorCode::CanisterInvalidWasm,
        "Wasm module has invalid data segment of 0 bytes at 1.",
    );
}

#[test]
fn failed_stable_memory_grow_cost_and_time_single_canister() {
    let num_wasm_pages = 116 * GIB / WASM_PAGE_SIZE_IN_BYTES;

    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let canister_id = create_universal_canister_with_cycles(&env, None, INITIAL_CYCLES_BALANCE);

    let timer = std::time::Instant::now();
    let initial_balance = env.cycle_balance(canister_id);
    let _res = env.execute_ingress(
        canister_id,
        "update",
        wasm()
            .stable64_grow(num_wasm_pages)
            .stable64_write(0, &[42])
            .trap()
            .build(),
    );
    let elapsed_ms = timer.elapsed().as_millis();
    let cycles_m = (initial_balance - env.cycle_balance(canister_id)) / 1000 / 1000;
    assert!(
        elapsed_ms < 10_000,
        "Test timed out after {elapsed_ms} ms and {cycles_m} M cycles"
    );
    assert!(cycles_m > 5);
}

#[test]
fn failed_stable_memory_grow_cost_and_time_multiple_canisters() {
    let num_wasm_pages = 116 * GIB / WASM_PAGE_SIZE_IN_BYTES;
    let num_canisters = 128;

    let env = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();

    let mut canister_ids = vec![];
    for _ in 0..num_canisters {
        let canister_id = create_universal_canister_with_cycles(&env, None, INITIAL_CYCLES_BALANCE);
        canister_ids.push(canister_id);
    }

    let timer = std::time::Instant::now();
    let mut total_initial_balance = 0;
    let mut payload = ic_state_machine_tests::PayloadBuilder::new();
    for canister_id in &canister_ids {
        let balance = env.cycle_balance(*canister_id);
        total_initial_balance += balance;
        payload = payload.ingress(
            PrincipalId::new_anonymous(),
            *canister_id,
            "update",
            wasm()
                .stable64_grow(num_wasm_pages)
                .stable64_write(0, &[42])
                .trap()
                .build(),
        );
    }
    env.execute_payload(payload);
    let elapsed_ms = timer.elapsed().as_millis();
    let mut total_balance = 0;
    for canister_id in &canister_ids {
        let balance = env.cycle_balance(*canister_id);
        total_balance += balance;
    }
    let cycles_m = (total_initial_balance - total_balance) / 1000 / 1000;
    assert!(
        elapsed_ms < 10_000,
        "Test timed out after {elapsed_ms} ms and {cycles_m} M cycles"
    );
    assert!(cycles_m > 800);
}

/// Verifies that canister liquid cycle balance can be used to transfer as many cycles as possible.
#[test]
fn test_canister_liquid_cycle_balance() {
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        SubnetConfig::new(SubnetType::Application),
        HypervisorConfig::default(),
    ));

    // Install the universal canister.
    let canister_id = create_universal_canister_with_cycles(&env, None, INITIAL_CYCLES_BALANCE);

    // Read the liquid cycle balance of the universal canister.
    let res = env
        .execute_ingress(
            canister_id,
            "update",
            wasm().liquid_cycles_balance128().append_and_reply().build(),
        )
        .unwrap();
    let liquid_balance = match res {
        WasmResult::Reply(blob) => u128::from_le_bytes(blob.try_into().unwrap()),
        WasmResult::Reject(msg) => panic!("Unexpected reject: {msg}"),
    };

    // Install another universal canister to receive as many cycles as possible from the existing universal canister.
    let callee = create_universal_canister_with_cycles(&env, None, INITIAL_CYCLES_BALANCE);

    // Make an inter-canister call to the other universal canister attaching the maximum amount of cycles.
    // The other universal canister accepts as many cycles as possible and replies with the actual amount of accepted cycles.
    // The caller universal canister then forwards the actual amount of accepted cycles in the ingress message reply.
    let res = env
        .execute_ingress(
            canister_id,
            "update",
            wasm()
                .call_with_max_cycles(
                    callee,
                    "update",
                    call_args()
                        .other_side(wasm().accept_cycles(u128::MAX).append_and_reply().build())
                        .on_reject(wasm().reject_message().trap())
                        .on_reply(wasm().message_payload().append_and_reply()),
                )
                .build(),
        )
        .unwrap();
    let accepted_cycles = match res {
        WasmResult::Reply(blob) => u128::from_le_bytes(blob.try_into().unwrap()),
        WasmResult::Reject(msg) => panic!("Unexpected reject: {msg}"),
    };
    assert!(0 < accepted_cycles && accepted_cycles < liquid_balance);

    // Lost cycles consist of the cost of an inter-canister call and the cost of an ingress message.
    // We assert that the lost cycles are less than 100B (this value was derived by printing the actual value in the test and rounding up)
    // and that the accepted cycles are way more than that.
    let lost_cycles = liquid_balance - accepted_cycles;
    assert!(lost_cycles < 100 * B);
    assert!(accepted_cycles > INITIAL_CYCLES_BALANCE.get() - 100 * B);

    // Finally, we assert that the cycles have indeed moved from one universal canister to the other one.
    // The remaining balance of the sender is larger than the lost cycles by the unspent cycles in the execution of the ingress message,
    // but still less than 100B.
    let balance = env.cycle_balance(canister_id);
    assert!(balance < 100 * B);
    // The receiver now holds the joint cycles balance of both canisters at the beginning minus some overhead.
    let receiver_balance = env.cycle_balance(callee);
    assert!(receiver_balance > 2 * INITIAL_CYCLES_BALANCE.get() - 100 * B);
}

/// Test that a message which results in many calls with large payloads (2 GB in
/// total) hits the instruction limit. This ensures that we don't have messages
/// over 2GB being sent over the sandbox IPC channel.
#[test]
fn large_ipc_call_fails() {
    let wasm = canister_test::Project::cargo_bin_maybe_from_env("call_loop_canister", &[]);
    let subnet_config = SubnetConfig::new(SubnetType::System);
    let instruction_limit = subnet_config.scheduler_config.max_instructions_per_message;
    let env = StateMachineBuilder::new()
        .with_config(Some(StateMachineConfig::new(
            subnet_config,
            HypervisorConfig::default(),
        )))
        .build();

    let canister_id = env
        .install_canister_with_cycles(wasm.bytes(), vec![], None, INITIAL_CYCLES_BALANCE)
        .unwrap();

    // Canister takes the number of bytes to send during one message in
    // megabytes. We send 2 GB total.
    let err = env
        .execute_ingress(canister_id, "send_calls", Encode!(&(2 * 1024_u32)).unwrap())
        .unwrap_err();
    let expected_error = format!(
        "Error from Canister \
        rwlgt-iiaaa-aaaaa-aaaaa-cai: Canister exceeded the limit of {instruction_limit} instructions \
        for single message execution."
    );
    err.assert_contains(ErrorCode::CanisterInstructionLimitExceeded, &expected_error);
}

#[test]
fn get_canister_metadata() {
    let env = StateMachine::new();
    let canister_with_metadata = env.install_canister_wat(
        r#"(module
(memory $memory 1)
(export "memory" (memory $memory))
(@custom "icp:public my_public_section" "my_public_section_value")
)"#,
        vec![],
        None,
    );
    let universal_canister =
        create_universal_canister_with_cycles(&env, None, INITIAL_CYCLES_BALANCE);
    let canister_metadata_args =
        CanisterMetadataRequest::new(canister_with_metadata, "my_public_section".to_string())
            .encode();

    // Call the canister metadata method through an inter-canister call should succeed.
    let get_canister_metadata = wasm()
        .call_simple(
            IC_00,
            Method::CanisterMetadata,
            call_args().other_side(canister_metadata_args.clone()),
        )
        .build();
    let res = env
        .execute_ingress(universal_canister, "update", get_canister_metadata)
        .unwrap();
    let reply = match res {
        WasmResult::Reply(blob) => blob,
        WasmResult::Reject(msg) => panic!("Unexpected reject: {msg}"),
    };
    let response = CanisterMetadataResponse::decode(&reply).unwrap();
    assert_eq!(response.value(), b"my_public_section_value");

    // Call the canister metadata method through an ingress message should fail.
    let err = env
        .execute_ingress(IC_00, Method::CanisterMetadata, canister_metadata_args)
        .unwrap_err();
    err.assert_contains(
        ErrorCode::CanisterRejectedMessage,
        "Only canisters can call ic00 method canister_metadata",
    );
}

#[test]
fn test_canister_status_via_query_call() {
    fn canister_status_count(env: &StateMachine) -> u64 {
        fetch_histogram_vec_stats(
            env.metrics_registry(),
            "execution_subnet_query_message_duration_seconds",
        )
        .get(&labels(&[
            ("method_name", "query_ic00_canister_status"),
            ("status", "success"),
        ]))
        .map_or(0, |stats| stats.count)
    }

    let subnet_config = SubnetConfig::new(SubnetType::Application);
    let env = StateMachineBuilder::new()
        .with_config(Some(StateMachineConfig::new(
            subnet_config,
            HypervisorConfig::default(),
        )))
        .build();
    let canister_id = create_universal_canister_with_cycles(
        &env,
        Some(CanisterSettingsArgsBuilder::new().build()),
        INITIAL_CYCLES_BALANCE,
    );

    assert_eq!(canister_status_count(&env), 0);

    let result = env.query(
        CanisterId::ic_00(),
        "canister_status",
        CanisterIdRecord::from(canister_id).encode(),
    );

    assert!(result.is_ok());
    assert_eq!(canister_status_count(&env), 1);
}
