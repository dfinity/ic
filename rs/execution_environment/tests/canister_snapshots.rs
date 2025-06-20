use canister_test::WasmResult;
use ic_error_types::ErrorCode;
use ic_management_canister_types_private::{
    CanisterSnapshotDataOffset, Global, LoadCanisterSnapshotArgs, OnLowWasmMemoryHookStatus,
    ReadCanisterSnapshotMetadataArgs, TakeCanisterSnapshotArgs, UploadCanisterSnapshotDataArgs,
    UploadCanisterSnapshotMetadataArgs, UploadChunkArgs,
};
use ic_state_machine_tests::{StateMachine, StateMachineBuilder};
use ic_types::CanisterId;

#[test]
fn upload_snapshot_module_with_checkpoint() {
    let env = StateMachineBuilder::new()
        .with_snapshot_download_enabled(true)
        .with_snapshot_upload_enabled(true)
        .build();
    let counter_canister_wasm = wat::parse_str(COUNTER_GROW_CANISTER_WAT).unwrap();
    let canister_id = env
        .install_canister(counter_canister_wasm.clone(), vec![], None)
        .unwrap();
    const SLICE_SIZE: u64 = 1_000_000;
    let num_slices = 10;
    let args = UploadCanisterSnapshotMetadataArgs::new(
        canister_id,
        None,
        SLICE_SIZE * num_slices,
        vec![],
        0,
        0,
        vec![],
        None,
        None,
    );
    let snapshot_id = env
        .upload_canister_snapshot_metadata(&args)
        .unwrap()
        .snapshot_id;
    let mut original_module = vec![];
    for i in 0..num_slices {
        let slice = [i as u8; SLICE_SIZE as usize];
        env.upload_canister_snapshot_data(&UploadCanisterSnapshotDataArgs::new(
            canister_id,
            snapshot_id,
            CanisterSnapshotDataOffset::WasmModule {
                offset: i * SLICE_SIZE,
            },
            slice.to_vec(),
        ))
        .unwrap();
        original_module.append(&mut slice.to_vec());
        if i % 3 == 0 {
            env.checkpointed_tick();
        }
    }
    // check if the module is as written
    let md_args = ReadCanisterSnapshotMetadataArgs::new(canister_id, snapshot_id);
    let module_dl = env.get_snapshot_module(&md_args).unwrap();
    assert_eq!(original_module, module_dl);
}

#[test]
fn upload_snapshot_with_checkpoint() {
    let env = StateMachineBuilder::new()
        .with_snapshot_download_enabled(true)
        .with_snapshot_upload_enabled(true)
        .build();
    let counter_canister_wasm = wat::parse_str(COUNTER_GROW_CANISTER_WAT).unwrap();
    let canister_id = env
        .install_canister(counter_canister_wasm.clone(), vec![], None)
        .unwrap();
    // grow stable by 80 pages ~5.2MB so that we have to upload in several slices.
    // each grow also writes the counter value to the end of the page.
    let num_pages = 80;
    for _ in 0..num_pages {
        env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    }
    // upload some chunks
    let chunk_1 = vec![1, 2, 3, 4, 5];
    let chunk_args = UploadChunkArgs {
        canister_id: canister_id.into(),
        chunk: chunk_1.clone(),
    };
    env.upload_chunk(chunk_args).unwrap();
    let chunk_2 = vec![6, 7, 8];
    let chunk_args = UploadChunkArgs {
        canister_id: canister_id.into(),
        chunk: chunk_2.clone(),
    };
    env.upload_chunk(chunk_args).unwrap();
    // take snapshot to learn valid metadata
    let snapshot_id_orig = env
        .take_canister_snapshot(TakeCanisterSnapshotArgs::new(canister_id, None))
        .unwrap()
        .snapshot_id();
    let md_args = ReadCanisterSnapshotMetadataArgs::new(canister_id, snapshot_id_orig);
    let md = env.read_canister_snapshot_metadata(&md_args).unwrap();
    // download all data
    let module_dl = env.get_snapshot_module(&md_args).unwrap();
    assert_eq!(counter_canister_wasm, module_dl);
    let heap_dl = env.get_snapshot_heap(&md_args).unwrap();
    let stable_memory_dl = env.get_snapshot_stable_memory(&md_args).unwrap();
    let chunk_store_dl = env.get_snapshot_chunk_store(&md_args).unwrap();
    assert_eq!(stable_memory_dl.len(), num_pages * (1 << 16));
    assert!(stable_memory_dl.ends_with(&[num_pages as u8, 0, 0, 0]));

    // create a new snapshot via metadata upload
    let args = UploadCanisterSnapshotMetadataArgs::new(
        canister_id,
        None,
        module_dl.len() as u64,
        md.exported_globals.clone(),
        heap_dl.len() as u64,
        stable_memory_dl.len() as u64,
        md.certified_data.clone(),
        None,
        None,
    );
    let snapshot_id = env
        .upload_canister_snapshot_metadata(&args)
        .unwrap()
        .snapshot_id;
    env.upload_snapshot_module(canister_id, snapshot_id, module_dl, None, None)
        .unwrap();
    env.upload_snapshot_heap(canister_id, snapshot_id, heap_dl, None, None)
        .unwrap();
    // upload first chunk before checkpoint
    env.upload_canister_snapshot_data(&UploadCanisterSnapshotDataArgs::new(
        canister_id,
        snapshot_id,
        CanisterSnapshotDataOffset::WasmChunk,
        chunk_1.clone(),
    ))
    .unwrap();
    // spread stable memory upload over a checkpoint event
    env.upload_snapshot_stable_memory(canister_id, snapshot_id, &stable_memory_dl, None, Some(1))
        .unwrap();
    env.checkpointed_tick();
    env.upload_snapshot_stable_memory(canister_id, snapshot_id, &stable_memory_dl, Some(1), None)
        .unwrap();
    // upload second chunk after checkpoint
    env.upload_canister_snapshot_data(&UploadCanisterSnapshotDataArgs::new(
        canister_id,
        snapshot_id,
        CanisterSnapshotDataOffset::WasmChunk,
        chunk_2.clone(),
    ))
    .unwrap();
    // change state to be overwritten:
    let res_1 = env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    let load_args = LoadCanisterSnapshotArgs::new(canister_id, snapshot_id, None);
    env.load_canister_snapshot(load_args).unwrap();
    // compare metadata
    let snapshot_id_2 = env
        .take_canister_snapshot(TakeCanisterSnapshotArgs::new(canister_id, None))
        .unwrap()
        .snapshot_id();
    let md_args_2 = ReadCanisterSnapshotMetadataArgs::new(canister_id, snapshot_id_2);
    let md_2 = env.read_canister_snapshot_metadata(&md_args_2).unwrap();
    assert_eq!(md.stable_memory_size, md_2.stable_memory_size);
    assert_eq!(md.wasm_chunk_store, md_2.wasm_chunk_store);
    let stable_memory_dl_2 = env.get_snapshot_stable_memory(&md_args_2).unwrap();
    assert_eq!(stable_memory_dl, stable_memory_dl_2);
    let res_2 = env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    // this implies that the module and heap were restored properly
    assert_eq!(res_1, res_2);
    let chunk_store_dl_2 = env.get_snapshot_chunk_store(&md_args_2).unwrap();
    assert_eq!(chunk_store_dl, chunk_store_dl_2);
    // perform another checkpoint and make sure the canister endpoint behaves as expected
    env.checkpointed_tick();
    let res = env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    assert_eq!(res, WasmResult::Reply(u32::to_le_bytes(82).to_vec()));
}

#[test]
fn load_snapshot_inconsistent_metadata_hook_status_fails() {
    let env = StateMachineBuilder::new()
        .with_snapshot_download_enabled(true)
        .with_snapshot_upload_enabled(true)
        .build();
    let counter_canister_wasm = wat::parse_str(COUNTER_GROW_CANISTER_WAT).unwrap();
    let canister_id = env
        .install_canister(counter_canister_wasm.clone(), vec![], None)
        .unwrap();

    env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    // take snapshot to learn valid metadata
    let snapshot_id_orig = env
        .take_canister_snapshot(TakeCanisterSnapshotArgs::new(canister_id, None))
        .unwrap()
        .snapshot_id();
    let md_args = ReadCanisterSnapshotMetadataArgs::new(canister_id, snapshot_id_orig);
    let md = env.read_canister_snapshot_metadata(&md_args).unwrap();
    // download all data
    let module_dl = env.get_snapshot_module(&md_args).unwrap();
    assert_eq!(counter_canister_wasm, module_dl);
    let heap_dl = env.get_snapshot_heap(&md_args).unwrap();
    let stable_memory_dl = env.get_snapshot_stable_memory(&md_args).unwrap();

    let original_args = UploadCanisterSnapshotMetadataArgs::new(
        canister_id,
        None,
        module_dl.len() as u64,
        md.exported_globals.clone(),
        heap_dl.len() as u64,
        stable_memory_dl.len() as u64,
        md.certified_data.clone(),
        None,
        None,
    );

    // load the snapshot with inconsistent hook status
    load_faulty_snapshot(
        &env,
        || {
            let mut args = original_args.clone();
            args.on_low_wasm_memory_hook_status = Some(OnLowWasmMemoryHookStatus::Ready);
            args
        },
        "uploaded snapshot is inconsistent with the canister's state",
        canister_id,
        &module_dl,
        &heap_dl,
        &stable_memory_dl,
    );
    // load the snapshot with inconsistent hook status
    load_faulty_snapshot(
        &env,
        || {
            let mut args = original_args.clone();
            args.on_low_wasm_memory_hook_status = Some(OnLowWasmMemoryHookStatus::Executed);
            args
        },
        "uploaded snapshot is inconsistent with the canister's state",
        canister_id,
        &module_dl,
        &heap_dl,
        &stable_memory_dl,
    );
    // load the snapshot with inconsistent globals
    load_faulty_snapshot(
        &env,
        || {
            let mut args = original_args.clone();
            args.exported_globals = vec![Global::I32(1), Global::I64(1999996623), Global::I32(2)];
            args
        },
        "Wasm exported globals of canister module and snapshot metadata do not match",
        canister_id,
        &module_dl,
        &heap_dl,
        &stable_memory_dl,
    );
}

fn load_faulty_snapshot(
    env: &StateMachine,
    md_gen: impl Fn() -> UploadCanisterSnapshotMetadataArgs,
    expect_str: &str,
    canister_id: CanisterId,
    module_dl: &[u8],
    heap_dl: &[u8],
    stable_memory_dl: &[u8],
) {
    let args = md_gen();

    let snapshot_id = env
        .upload_canister_snapshot_metadata(&args)
        .unwrap()
        .snapshot_id;
    env.upload_snapshot_module(canister_id, snapshot_id, module_dl, None, None)
        .unwrap();
    env.upload_snapshot_heap(canister_id, snapshot_id, heap_dl, None, None)
        .unwrap();
    env.upload_snapshot_stable_memory(canister_id, snapshot_id, stable_memory_dl, None, None)
        .unwrap();
    let _ = env.execute_ingress(canister_id, "inc", vec![]).unwrap();
    let load_args = LoadCanisterSnapshotArgs::new(canister_id, snapshot_id, None);
    let err = env.load_canister_snapshot(load_args).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidManagementPayload);
    assert!(err.description().contains(expect_str));
}

/// Counter canister that also grows the stable memory by one page on "inc".
/// Also writes the counter value at the end of each new page, allowing
/// us to verify the stable memory contents.
const COUNTER_GROW_CANISTER_WAT: &str = r#"
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
