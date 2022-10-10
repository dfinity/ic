use ic_config::{
    execution_environment::Config as HypervisorConfig,
    subnet_config::{CyclesAccountManagerConfig, SubnetConfigs},
};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{
    CanisterSettingsArgs, ErrorCode, PrincipalId, StateMachine, StateMachineConfig, SubnetId,
    UserError,
};
use ic_types::{ingress::WasmResult, Cycles, NumBytes};
use ic_universal_canister::{wasm, UNIVERSAL_CANISTER_WASM};
use std::convert::TryInto;

const INITIAL_CYCLES_BALANCE: Cycles = Cycles::new(100_000_000_000_000);

/// This is a canister that keeps a counter on the heap and exposes various test
/// methods. Exposed methods:
///  * "inc"       increment the counter
///  * "read"      read the counter value
///  * "persist"   copy the counter value to stable memory
///  * "load"      restore the counter value from stable memory
///  * "copy_to"   copy the counter value to the specified address on the heap
///  * "read_at"   read an 32-bit integer at the specified address on the heap
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
              (export "canister_update grow_mem" (func $grow_mem)))"#;

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
    let mut subnet_config = SubnetConfigs::default().own_subnet_config(SubnetType::System);
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
        Some(CanisterSettingsArgs {
            controller: None,
            controllers: None,
            compute_allocation: Some(candid::Nat::from(1)),
            memory_allocation: None,
            freezing_threshold: None,
        }),
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

/// Verifies that the state machine automatically removes stopped canisters
/// outside of the assigned canister range.
#[test]
fn automatic_stopped_canister_removal() {
    let env = StateMachine::new();

    let canister_id_1 = env.install_canister_wat(TEST_CANISTER, vec![], None);
    let canister_id_2 = env.install_canister_wat(TEST_CANISTER, vec![], None);
    let canister_id_3 = env.install_canister_wat(TEST_CANISTER, vec![], None);

    let own_subnet = env.get_subnet_id();
    let new_subnet = SubnetId::from(PrincipalId::new_subnet_test_id(404));

    env.prepare_canister_migrations(canister_id_1..=canister_id_1, own_subnet, new_subnet);
    env.prepare_canister_migrations(canister_id_2..=canister_id_2, own_subnet, new_subnet);

    env.reroute_canister_range(canister_id_1..=canister_id_1, new_subnet);
    env.reroute_canister_range(canister_id_2..=canister_id_2, new_subnet);

    env.execute_ingress(canister_id_1, "inc", vec![]).unwrap();
    env.execute_ingress(canister_id_2, "inc", vec![]).unwrap();
    env.execute_ingress(canister_id_3, "inc", vec![]).unwrap();

    env.stop_canister(canister_id_1).unwrap();
    env.stop_canister(canister_id_2).unwrap();

    env.execute_ingress(canister_id_3, "inc", vec![]).unwrap();

    // Canisters will not be removed if they have corresponding entries in canister migrations.
    let user_error_1 = env
        .execute_ingress(canister_id_1, "inc", vec![])
        .unwrap_err();
    assert_eq!(user_error_1.code(), ErrorCode::CanisterStopped);

    let user_error_2 = env
        .execute_ingress(canister_id_2, "inc", vec![])
        .unwrap_err();
    assert_eq!(user_error_2.code(), ErrorCode::CanisterStopped);

    // After removing the canister migrations entries, canisters not the routing table will be deleted.
    env.complete_canister_migrations(canister_id_1..=canister_id_1, vec![own_subnet, new_subnet]);
    let user_error_1 = env
        .execute_ingress(canister_id_1, "inc", vec![])
        .unwrap_err();
    assert_eq!(user_error_1.code(), ErrorCode::CanisterNotFound);

    let user_error_2 = env
        .execute_ingress(canister_id_2, "inc", vec![])
        .unwrap_err();
    assert_eq!(user_error_2.code(), ErrorCode::CanisterStopped);
}

/// Verifies that the state machine can install gzip-compressed canister
/// modules.
#[test]
fn compressed_canisters_support() {
    let env = StateMachine::new();
    env.set_checkpoints_enabled(true);

    let test_canister_wasm = wabt::wat2wasm(TEST_CANISTER).expect("invalid WAT");
    let compressed_wasm = {
        let mut encoder = libflate::gzip::Encoder::new(Vec::new()).unwrap();
        std::io::copy(&mut &test_canister_wasm[..], &mut encoder).unwrap();
        encoder.finish().into_result().unwrap()
    };
    let compressed_hash = ic_crypto_sha::Sha256::hash(&compressed_wasm);

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
    let subnet_config = SubnetConfigs::default().own_subnet_config(SubnetType::Application);
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        subnet_config,
        HypervisorConfig {
            subnet_memory_capacity: NumBytes::from(20 * 1024 * 1024), // 20 MiB,
            ..Default::default()
        },
    ));
    env.set_checkpoints_enabled(true);

    let now = std::time::SystemTime::now();
    env.set_time(now);

    let canister_id = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.into(),
            vec![],
            Some(CanisterSettingsArgs {
                controller: None,
                controllers: None,
                compute_allocation: None,
                memory_allocation: None,
                freezing_threshold: None,
            }),
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();

    // Set the memory to 20MiB + 1. Should fail.
    let res = env
        .update_settings(
            &canister_id,
            CanisterSettingsArgs {
                controller: None,
                controllers: None,
                compute_allocation: None,
                memory_allocation: Some(candid::Nat::from(20u64 * 1024 * 1024 + 1)),
                freezing_threshold: None,
            },
        )
        .unwrap_err();
    assert_eq!(res.code(), ErrorCode::SubnetOversubscribed);

    // Set the memory to exactly 20MiB. Should succeed.
    env.update_settings(
        &canister_id,
        CanisterSettingsArgs {
            controller: None,
            controllers: None,
            compute_allocation: None,
            memory_allocation: Some(candid::Nat::from(20u64 * 1024 * 1024)),
            freezing_threshold: None,
        },
    )
    .unwrap();
}

// Asserts that the canister replied with the given expected number.
//
// This function panics if there was an error executing the message or the
// canister explicitly rejected it.
fn assert_replied(result: Result<WasmResult, UserError>, expected: i64) {
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

#[test]
fn exceeding_memory_capacity_fails_during_message_execution() {
    let subnet_config = SubnetConfigs::default().own_subnet_config(SubnetType::Application);
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        subnet_config,
        HypervisorConfig {
            subnet_memory_capacity: NumBytes::from(20 * 1024 * 1024), // 20 MiB,
            ..Default::default()
        },
    ));
    env.set_checkpoints_enabled(true);

    let now = std::time::SystemTime::now();
    env.set_time(now);

    let canister_id = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.into(),
            vec![],
            Some(CanisterSettingsArgs {
                controller: None,
                controllers: None,
                compute_allocation: None,
                memory_allocation: None,
                freezing_threshold: None,
            }),
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();

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
        assert_replied(res, expected_result);
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
    assert_replied(res, -1);
}

#[test]
fn max_canister_memory_respected_even_when_no_memory_allocation_is_set() {
    let subnet_config = SubnetConfigs::default().own_subnet_config(SubnetType::Application);
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

    let canister_id = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.into(),
            vec![],
            Some(CanisterSettingsArgs {
                controller: None,
                controllers: None,
                compute_allocation: None,
                memory_allocation: None,
                freezing_threshold: None,
            }),
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();

    // Growing the memory by 200 pages exceeds the 10MiB max canister
    // memory size we set and should fail.
    let res = env.execute_ingress(
        canister_id,
        "update",
        wasm().stable64_grow(200).reply_int64().build(),
    );
    assert_replied(res, -1);

    // Growing the memory by 50 pages doesn't exceed the 10MiB max canister
    // memory size we set and should succeed.
    let res = env.execute_ingress(
        canister_id,
        "update",
        wasm().stable64_grow(50).reply_int64().build(),
    );
    assert_replied(res, 0);
}
