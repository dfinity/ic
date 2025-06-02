use ic_management_canister_types_private::{
    LoadCanisterSnapshotArgs, ReadCanisterSnapshotMetadataArgs, TakeCanisterSnapshotArgs,
    UploadCanisterSnapshotMetadataArgs,
};
use ic_state_machine_tests::StateMachineBuilder;
use ic_types::SnapshotId;

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
    // grow stable by by 80 pages ~5.2MB
    let num_pages = 80;
    for _ in 0..num_pages {
        env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    }
    let snapshot_id = env
        .take_canister_snapshot(TakeCanisterSnapshotArgs::new(canister_id, None))
        .unwrap()
        .snapshot_id();
    let md_args = ReadCanisterSnapshotMetadataArgs::new(canister_id, snapshot_id);
    let md = env.read_canister_snapshot_metadata(&md_args).unwrap();
    let module_dl = env.get_snapshot_module(&md_args).unwrap();
    assert_eq!(counter_canister_wasm, module_dl);
    let heap_dl = env.get_snapshot_heap(&md_args).unwrap();
    let stable_memory_dl = env.get_snapshot_stable_memory(&md_args).unwrap();
    let chunk_store_dl = env.get_snapshot_chunk_store(&md_args).unwrap();
    assert_eq!(stable_memory_dl.len(), num_pages * (1 << 16));
    assert!(stable_memory_dl.ends_with(&[num_pages as u8, 0, 0, 0]));
    println!(
        "{}, {}, {}, {}",
        module_dl.len(),
        heap_dl.len(),
        stable_memory_dl.len(),
        chunk_store_dl.len()
    );
    let args = UploadCanisterSnapshotMetadataArgs::new(
        canister_id,
        None,
        module_dl.len() as u64,
        md.exported_globals,
        heap_dl.len() as u64,
        stable_memory_dl.len() as u64,
        md.certified_data,
        None,
        None,
    );
    let snapshot_id = env
        .upload_canister_snapshot_metadata(&args)
        .unwrap()
        .snapshot_id;
    env.upload_snapshot_module(canister_id, snapshot_id.clone(), module_dl, None, None)
        .unwrap();
    env.upload_snapshot_heap(canister_id, snapshot_id.clone(), heap_dl, None, None)
        .unwrap();
    // spread stable memory upload over a checkpoint event
    env.upload_snapshot_stable_memory(
        canister_id,
        snapshot_id.clone(),
        stable_memory_dl,
        None,
        None,
    )
    .unwrap();
    // TODO
    // change state to be overwritten:
    let res_1 = env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    println!("{:?}", res);
    let load_args = LoadCanisterSnapshotArgs::new(
        canister_id,
        SnapshotId::try_from(snapshot_id).unwrap(),
        None,
    );
    env.load_canister_snapshot(load_args).unwrap();
    let res_2 = env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    assert_eq!(res_1, res_2);
}

/// Counter canister that also grows the stable memory by one page on "inc".
const COUNTER_CANISTER_WAT: &str = r#"
(module
  (import "ic0" "msg_reply" (func $msg_reply))
  (import "ic0" "msg_reply_data_append"
  (func $msg_reply_data_append (param i32 i32)))
  (import "ic0" "stable_grow" (func $stable_grow (param i32) (result i32)))
  (import "ic0" "stable_write" (func $stable_write (param $offset i32) (param $src i32) (param $size i32)))

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
    ;; grow by a page
    (i32.const 1)
    (call $stable_grow)
    (drop)
    ;; update the counter
    (global.set 0
      (i32.add
        (global.get 0)
        (i32.const 1)
      )
    )
    ;; write the new value to the new page
    (i32.store
      (i32.const 0)
      (global.get 0)
    )
    (call $stable_write (i32.sub (i32.mul (global.get 0) (i32.const 65536)) (i32.const 4)) (i32.const 0) (i32.const 4))
    (call $read)
  )

  (memory $memory 1)
  (export "memory" (memory $memory))
  (global (export "counter_global") (mut i32) (i32.const 0))
  (export "canister_query read" (func $read))
  (export "canister_update inc" (func $write))
)
"#;
