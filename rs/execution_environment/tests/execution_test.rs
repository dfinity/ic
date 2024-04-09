use candid::Encode;
use ic_base_types::PrincipalId;
use ic_config::{
    execution_environment::Config as HypervisorConfig,
    subnet_config::{CyclesAccountManagerConfig, SubnetConfig},
};
use ic_management_canister_types::{
    CanisterIdRecord, CanisterSettingsArgs, CanisterSettingsArgsBuilder, CanisterStatusResultV2,
    CreateCanisterArgs, EmptyBlob, Method, Payload, UpdateSettingsArgs, IC_00,
};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{
    ErrorCode, IngressStatus, StateMachine, StateMachineBuilder, StateMachineConfig, UserError,
};
use ic_test_utilities_metrics::fetch_int_counter;
use ic_types::{ingress::WasmResult, CanisterId, Cycles, NumBytes};
use ic_universal_canister::{call_args, wasm, UNIVERSAL_CANISTER_WASM};
use std::{convert::TryInto, sync::Arc, time::Duration};

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
    create_canister_with_cycles(env, UNIVERSAL_CANISTER_WASM.into(), settings, cycles)
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

    // We don't charge for allocation periodically, we advance the state machine
    // time to trigger allocation charging. The canister should get uninstalled
    // since we simulate that enough time has passed to not be able to pay for
    // its compute allocation.
    let seconds_to_burn_balance = env.cycle_balance(canister_id) as u64
        / compute_percent_allocated_per_second_fee.get() as u64;
    env.advance_time(Duration::from_secs(seconds_to_burn_balance + 1));
    env.tick();

    // Verify the original canister still exists but it's uninstalled and has a
    // zero cycle balance.
    assert_eq!(env.cycle_balance(canister_id), 0);
    assert_eq!(env.num_canisters_uninstalled_out_of_cycles(), 1);

    // Advance the statem machine time a bit more and confirm the canister is
    // still uninstalled.
    env.advance_time(
        2 * CyclesAccountManagerConfig::application_subnet().duration_between_allocation_charges,
    );
    env.tick();

    // Verify the original canister still exists but it's uninstalled and has a
    // zero cycle balance.
    assert_eq!(env.cycle_balance(canister_id), 0);
    assert_eq!(env.num_canisters_uninstalled_out_of_cycles(), 1);
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
    assert!(
        consumed >= 1000.0,
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
            subnet_memory_capacity: NumBytes::from(21 * 1024 * 1024), // 21 MiB,
            subnet_memory_reservation: NumBytes::from(1024 * 1024),   // 1 MiB
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

    // Set the memory to 20MiB + 1. Should fail.
    let res = env
        .update_settings(
            &canister_id,
            CanisterSettingsArgsBuilder::new()
                .with_memory_allocation(20u64 * 1024 * 1024 + 1)
                .build(),
        )
        .unwrap_err();
    assert_eq!(res.code(), ErrorCode::SubnetOversubscribed);

    // Set the memory to exactly 20MiB. Should succeed.
    env.update_settings(
        &canister_id,
        CanisterSettingsArgsBuilder::new()
            .with_memory_allocation(20u64 * 1024 * 1024)
            .build(),
    )
    .unwrap();
}

fn assert_replied(result: Result<WasmResult, UserError>) {
    match result {
        Ok(wasm_result) => match wasm_result {
            WasmResult::Reply(_) => {}
            WasmResult::Reject(err) => panic!("Unexpected reject: {:?}", err),
        },
        Err(err) => panic!("Got unexpected error: {}", err),
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
                panic!("Got unexpected reject: {}", reject_message)
            }
        },
        Err(err) => panic!("Got unexpected error: {}", err),
    }
}

fn assert_rejected(result: Result<WasmResult, UserError>) {
    match result {
        Ok(wasm_result) => match wasm_result {
            WasmResult::Reply(blob) => panic!("Unexpected reply: {:?}", blob),
            WasmResult::Reject(_err) => {}
        },
        Err(err) => panic!("Got unexpected error: {}", err),
    }
}

#[test]
fn exceeding_memory_capacity_fails_during_message_execution() {
    let subnet_config = SubnetConfig::new(SubnetType::Application);
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        subnet_config,
        HypervisorConfig {
            subnet_memory_capacity: NumBytes::from(21 * 1024 * 1024), // 21 MiB,
            subnet_memory_reservation: NumBytes::from(1024 * 1024),   // 1 MiB
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
    // capacity and then should fail after that point because the capacity split
    // over 4 threads will be less than 1MiB (keep in mind the wasm module of the
    // canister also takes some space).
    let memory_to_allocate = 1024 * 1024 / WASM_PAGE_SIZE_IN_BYTES; // 1MiB in Wasm pages.
    let mut expected_result = 0;
    for _ in 0..15 {
        let res = env.execute_ingress(
            canister_id,
            "update",
            wasm()
                .stable64_grow(memory_to_allocate)
                .reply_int64()
                .build(),
        );
        assert_replied_with(res, expected_result);
        expected_result += memory_to_allocate as i64;
    }

    // Canister tries to grow by another `memory_to_allocate` pages, should fail and
    // the return value will be -1.
    let res = env.execute_ingress(
        canister_id,
        "update",
        wasm()
            .stable64_grow(memory_to_allocate)
            .reply_int64()
            .build(),
    );
    assert_replied_with(res, -1);
}

#[test]
fn max_canister_memory_respected_even_when_no_memory_allocation_is_set() {
    let subnet_config = SubnetConfig::new(SubnetType::Application);
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        subnet_config,
        HypervisorConfig {
            max_canister_memory_size: NumBytes::from(10 * 1024 * 1024), // 10 MiB,
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

    // Growing the memory by 200 pages exceeds the 10MiB max canister
    // memory size we set and should fail.
    let res = env.execute_ingress(
        canister_id,
        "update",
        wasm().stable64_grow(200).reply_int64().build(),
    );
    assert_replied_with(res, -1);

    // Growing the memory by 50 pages doesn't exceed the 10MiB max canister
    // memory size we set and should succeed.
    let res = env.execute_ingress(
        canister_id,
        "update",
        wasm().stable64_grow(50).reply_int64().build(),
    );
    assert_replied_with(res, 0);
}

#[test]
fn subnet_memory_reservation_works() {
    let subnet_config = SubnetConfig::new(SubnetType::Application);
    let num_cores = subnet_config.scheduler_config.scheduler_cores as u64;
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        subnet_config,
        HypervisorConfig {
            subnet_memory_capacity: NumBytes::from(120 * 1024 * 1024),
            subnet_memory_reservation: NumBytes::from(50 * 1024 * 1024),
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
    assert!(num_cores > 1);
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        subnet_config,
        HypervisorConfig {
            subnet_memory_capacity: NumBytes::from(120 * 1024 * 1024),
            subnet_memory_reservation: NumBytes::from(50 * 1024 * 1024),
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
    assert_eq!(
        err.description(),
        format!("Canister {} trapped: stable memory out of bounds", a_id)
    );
    assert_eq!(err.code(), ErrorCode::CanisterTrapped);
}

#[test]
fn canister_with_memory_allocation_does_not_fail_when_growing_wasm_memory() {
    let subnet_config = SubnetConfig::new(SubnetType::Application);
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        subnet_config,
        HypervisorConfig {
            subnet_memory_capacity: NumBytes::from(100_000_000),
            subnet_memory_reservation: NumBytes::from(0),
            ..Default::default()
        },
    ));

    let wat = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))
            (func $update
                (if (i32.ne (memory.grow (i32.const 400)) (i32.const 1))
                  (then (unreachable))
                )
                (call $msg_reply)
            )
            (memory $memory 1)
            (export "canister_update update" (func $update))
        )"#;

    let wasm = wat::parse_str(wat).unwrap();

    let a_id = create_canister_with_cycles(
        &env,
        wasm.clone(),
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_memory_allocation(50_000_000)
                .with_freezing_threshold(0)
                .build(),
        ),
        INITIAL_CYCLES_BALANCE,
    );
    let _b_id = create_canister_with_cycles(
        &env,
        wasm,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_memory_allocation(45_000_000)
                .with_freezing_threshold(0)
                .build(),
        ),
        INITIAL_CYCLES_BALANCE,
    );

    let res = env.execute_ingress(a_id, "update", vec![]);
    assert_replied(res);
}

#[test]
fn canister_with_memory_allocation_does_not_fail_when_growing_stable_memory() {
    let subnet_config = SubnetConfig::new(SubnetType::Application);
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        subnet_config,
        HypervisorConfig {
            subnet_memory_capacity: NumBytes::from(100_000_000),
            subnet_memory_reservation: NumBytes::from(0),
            ..Default::default()
        },
    ));

    let a_id = create_universal_canister_with_cycles(
        &env,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_memory_allocation(50_000_000)
                .build(),
        ),
        INITIAL_CYCLES_BALANCE,
    );
    let _b_id = create_universal_canister_with_cycles(
        &env,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_memory_allocation(45_000_000)
                .build(),
        ),
        INITIAL_CYCLES_BALANCE,
    );

    let a = wasm()
        .stable64_grow(600)
        .stable64_read(30_000_000, 8)
        .message_payload()
        .append_and_reply()
        .build();

    let res = env.execute_ingress(a_id, "update", a);
    assert_replied(res);
}

#[test]
fn canister_with_memory_allocation_cannot_grow_wasm_memory_above_allocation() {
    let subnet_config = SubnetConfig::new(SubnetType::Application);
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        subnet_config,
        HypervisorConfig {
            subnet_memory_capacity: NumBytes::from(100_000_000),
            subnet_memory_reservation: NumBytes::from(0),
            ..Default::default()
        },
    ));

    let wat = r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))
            (func $update
                (if (i32.ne (memory.grow (i32.const 400)) (i32.const 1))
                  (then (unreachable))
                )
                (call $msg_reply)
            )
            (memory $memory 1)
            (export "canister_update update" (func $update))
        )"#;

    let wasm = wat::parse_str(wat).unwrap();

    let a_id = create_canister_with_cycles(
        &env,
        wasm.clone(),
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_memory_allocation(300 * 64 * 1024)
                .with_freezing_threshold(0)
                .build(),
        ),
        INITIAL_CYCLES_BALANCE,
    );

    let err = env.execute_ingress(a_id, "update", vec![]).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterOutOfMemory);
}

#[test]
fn canister_with_memory_allocation_cannot_grow_stable_memory_above_allocation() {
    let subnet_config = SubnetConfig::new(SubnetType::Application);
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        subnet_config,
        HypervisorConfig {
            subnet_memory_capacity: NumBytes::from(100_000_000),
            subnet_memory_reservation: NumBytes::from(0),
            ..Default::default()
        },
    ));

    let a_id = create_universal_canister_with_cycles(
        &env,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_memory_allocation(300 * 64 * 1024)
                .build(),
        ),
        INITIAL_CYCLES_BALANCE,
    );

    let a = wasm()
        .stable64_grow(400)
        .stable64_read(30_000_000, 8)
        .message_payload()
        .append_and_reply()
        .build();

    let err = env.execute_ingress(a_id, "update", a).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterTrapped);
}

#[test]
fn canister_with_reserved_balance_is_not_uninstalled_too_early() {
    let subnet_config = SubnetConfig::new(SubnetType::Application);
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        subnet_config,
        HypervisorConfig::default(),
    ));

    let initial_cycles = Cycles::new(100 * B);
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

    let initial_cycles = Cycles::new(200 * B);

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
    let reserved_cycles = Cycles::new(180 * B);
    {
        let mut state = env.get_latest_state().as_ref().clone();
        let canister = state.canister_state_mut(&canister_id).unwrap();
        canister
            .system_state
            .reserve_cycles(reserved_cycles)
            .unwrap();
        env.replace_canister_state(Arc::new(state), canister_id);
    }

    assert!(env.cycle_balance(canister_id) < freezing_threshold);

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
            UNIVERSAL_CANISTER_WASM.into(),
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
            UNIVERSAL_CANISTER_WASM.into(),
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
