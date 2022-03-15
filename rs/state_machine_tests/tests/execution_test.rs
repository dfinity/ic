use ic_config::subnet_config::{CyclesAccountManagerConfig, SubnetConfigs};
use ic_error_types::ErrorCode;
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::StateMachine;
use ic_types::ic00::CanisterSettingsArgs;
use ic_types::{Cycles, PrincipalId, SubnetId};

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

/// Converts an integer into the representation expected by the TEST_CANISTER
/// canister.
fn from_int(n: i32) -> Vec<u8> {
    n.to_le_bytes().to_vec()
}

/// Converts a reply of the TEST_CANISTER canister into an integer.
fn to_int(v: Vec<u8>) -> i32 {
    use std::convert::TryInto;
    i32::from_le_bytes(v.try_into().unwrap())
}

/// The test checks that the canister heap is discarded on code
/// re-install, and that the heap stays discarded after a checkpoint
/// recovery. It's a common bug in execution to reset the heap in
/// memory, but not on disk, which results in corrupted checkpoints.
#[tokio::test]
async fn test_canister_reinstall_restart() {
    let env = StateMachine::new();

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
#[tokio::test]
async fn test_canister_upgrade_restart() {
    let env = StateMachine::new();

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

/// The test checks that the canister stable memory is discarded on code
/// re-install, and that the stable memory stays discarded after a checkpoint
/// recovery. It's a common bug in execution to reset a page map in memory, but
/// not on disk, which results in corrupted checkpoints.
#[tokio::test]
async fn test_canister_stable_memory_reinstall_restart() {
    let env = StateMachine::new();

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
#[tokio::test]
async fn test_canister_stable_memory_upgrade_restart() {
    let env = StateMachine::new();

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
#[tokio::test]
async fn test_canister_out_of_cycles() {
    // Start a node with a config where all computation/storage is free.
    let mut config = SubnetConfigs::default().own_subnet_config(SubnetType::System);
    let env = StateMachine::new_with_config(config.clone());

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
    config
        .cycles_account_manager_config
        .compute_percent_allocated_per_second_fee = Cycles::new(1);

    // Restart the node to pick up the new node configuration.
    let env = env.restart_node_with_config(config);

    // Install a new wasm to trigger making a new checkpoint.
    env.install_canister_wat(TEST_CANISTER, vec![], None);

    // We don't charge for allocation every round, so need to trigger multiple
    // rounds until allocation charging has occured.
    for _ in 0..(2 * CyclesAccountManagerConfig::application_subnet()
        .duration_between_allocation_charges)
        .as_secs()
    {
        let _ = env.execute_ingress(canister_id, "inc", vec![]);
    }

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
#[tokio::test]
async fn test_manifest_computation_memory_grow() {
    let env = StateMachine::new();

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
#[tokio::test]
async fn test_manifest_computation_memory_expand() {
    let env = StateMachine::new();

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

#[tokio::test]
async fn automatic_stopped_canister_removal() {
    let env = StateMachine::new();

    let canister_id_1 = env.install_canister_wat(TEST_CANISTER, vec![], None);
    let canister_id_2 = env.install_canister_wat(TEST_CANISTER, vec![], None);

    let new_subnet = SubnetId::from(PrincipalId::new_subnet_test_id(404));
    env.reroute_canister_range(canister_id_1..=canister_id_1, new_subnet);
    env.execute_ingress(canister_id_1, "inc", vec![]).unwrap();
    env.execute_ingress(canister_id_2, "inc", vec![]).unwrap();

    env.stop_canister(canister_id_1).unwrap();
    env.execute_ingress(canister_id_2, "inc", vec![]).unwrap();
    let user_error = env
        .execute_ingress(canister_id_1, "inc", vec![])
        .unwrap_err();
    assert_eq!(user_error.code(), ErrorCode::CanisterNotFound);
}

#[tokio::test]
async fn compressed_canisters_support() {
    let env = StateMachine::new();

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
