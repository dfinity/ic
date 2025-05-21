use ic_management_canister_types_private::{
    ReadCanisterSnapshotMetadataArgs, TakeCanisterSnapshotArgs,
};
use ic_state_machine_tests::StateMachineBuilder;

#[test]
fn upload_snapshot_with_checkpoint() {
    let env = StateMachineBuilder::new()
        .with_snapshot_download_enabled(true)
        .with_snapshot_upload_enabled(true)
        .build();

    let counter_canister_wasm = wat::parse_str(COUNTER_CANISTER_WAT).unwrap();

    let canister_id = env
        .install_canister(counter_canister_wasm.clone(), vec![], None)
        .unwrap();
    let snapshot_id = env
        .take_canister_snapshot(TakeCanisterSnapshotArgs::new(canister_id, None))
        .unwrap()
        .snapshot_id();
    let module_dl = env
        .get_snapshot_canister_module(&ReadCanisterSnapshotMetadataArgs::new(
            canister_id,
            snapshot_id,
        ))
        .unwrap();

    assert_eq!(counter_canister_wasm, module_dl);
}

/// Counter canister that also grows the stable memory by one page on "inc".
const COUNTER_CANISTER_WAT: &str = r#"
(module
  (import "ic0" "msg_reply" (func $msg_reply))
  (import "ic0" "msg_reply_data_append"
  (func $msg_reply_data_append (param i32 i32)))
  (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))

  (func $read
    (i32.store
      (i32.const 0)
      (global.get 0)
    )
    (call $msg_reply_data_append
      (i32.const 0)
      (i32.const 4)
    )
    (call $msg_reply)
  )
  
  (func $write
    (i32.const 1)
    (call $stable_grow)
    (drop)
    (global.set 0
      (i32.add
        (global.get 0)
        (i32.const 1)
      )
    )
    (call $read)
  )

  (memory $memory 1)
  (export "memory" (memory $memory))
  (global (export "counter_global") (mut i32) (i32.const 0))
  (export "canister_query read" (func $read))
  (export "canister_update inc" (func $write))
)
"#;
