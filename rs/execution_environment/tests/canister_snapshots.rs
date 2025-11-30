use candid::{Decode, Reserved};
use canister_test::WasmResult;
use ic_base_types::SnapshotId;
use ic_config::execution_environment::Config as ExecutionConfig;
use ic_config::subnet_config::SubnetConfig;
use ic_error_types::ErrorCode;
use ic_management_canister_types_private::{
    CanisterChangeDetails, CanisterIdRecord, CanisterSettingsArgsBuilder,
    CanisterSnapshotDataOffset, Global, GlobalTimer, LoadCanisterSnapshotArgs,
    OnLowWasmMemoryHookStatus, ReadCanisterSnapshotMetadataArgs,
    ReadCanisterSnapshotMetadataResponse, SnapshotSource, TakeCanisterSnapshotArgs,
    UploadCanisterSnapshotDataArgs, UploadCanisterSnapshotMetadataArgs, UploadChunkArgs,
};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, StateMachineConfig};
use ic_test_utilities::universal_canister::{
    UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM, UNIVERSAL_CANISTER_WASM, wasm,
};
use ic_types::{CanisterId, Cycles};

// Asserts that two snapshots are equal modulo their source, timestamp, and canister version (transient values).
fn assert_snapshot_eq(
    env: &StateMachine,
    canister_1: CanisterId,
    snapshot_1: SnapshotId,
    canister_2: CanisterId,
    snapshot_2: SnapshotId,
) {
    // Download and compare snapshot metadata.
    let download_args_1 = ReadCanisterSnapshotMetadataArgs::new(canister_1, snapshot_1);
    let mut metadata_1 = env
        .read_canister_snapshot_metadata(&download_args_1)
        .unwrap();
    let download_args_2 = ReadCanisterSnapshotMetadataArgs::new(canister_2, snapshot_2);
    let metadata_2 = env
        .read_canister_snapshot_metadata(&download_args_2)
        .unwrap();
    metadata_1.source = metadata_2.source;
    metadata_1.taken_at_timestamp = metadata_2.taken_at_timestamp;
    metadata_1.canister_version = metadata_2.canister_version;
    assert_eq!(metadata_1, metadata_2);

    // Download and compare snapshot (binary) data.
    let module_download_1 = env.get_snapshot_module(&download_args_1).unwrap();
    let module_download_2 = env.get_snapshot_module(&download_args_2).unwrap();
    assert_eq!(module_download_1, module_download_2);

    let heap_download_1 = env.get_snapshot_heap(&download_args_1).unwrap();
    let heap_download_2 = env.get_snapshot_heap(&download_args_2).unwrap();
    assert_eq!(heap_download_1, heap_download_2);

    let stable_memory_download_1 = env.get_snapshot_stable_memory(&download_args_1).unwrap();
    let stable_memory_download_2 = env.get_snapshot_stable_memory(&download_args_2).unwrap();
    assert_eq!(stable_memory_download_1, stable_memory_download_2);

    let chunk_store_download_1 = env.get_snapshot_chunk_store(&download_args_1).unwrap();
    let chunk_store_download_2 = env.get_snapshot_chunk_store(&download_args_2).unwrap();
    assert_eq!(chunk_store_download_1, chunk_store_download_2);
}

// Downloads snapshot of `canister_id` identified by `snapshot_id` and uploads it to `target_canister_id`.
// Returns the snapshot id of the uploaded snapshot.
fn download_upload_snapshot(
    env: &StateMachine,
    canister_id: CanisterId,
    snapshot_id: SnapshotId,
    target_canister_id: CanisterId,
) -> SnapshotId {
    // Download snapshot metadata.
    let download_args = ReadCanisterSnapshotMetadataArgs::new(canister_id, snapshot_id);
    let metadata = env.read_canister_snapshot_metadata(&download_args).unwrap();

    // Download snapshot (binary) data.
    let module_download = env.get_snapshot_module(&download_args).unwrap();
    let heap_download = env.get_snapshot_heap(&download_args).unwrap();
    let stable_memory_download = env.get_snapshot_stable_memory(&download_args).unwrap();
    let chunk_store_download = env.get_snapshot_chunk_store(&download_args).unwrap();

    // Upload snapshot metadata.
    let upload_args = UploadCanisterSnapshotMetadataArgs::new(
        target_canister_id,
        None, /* replace_snapshot */
        module_download.len() as u64,
        metadata.globals.clone(),
        heap_download.len() as u64,
        stable_memory_download.len() as u64,
        metadata.certified_data.clone(),
        metadata.global_timer,
        metadata.on_low_wasm_memory_hook_status,
    );
    let uploaded_snapshot_id = env
        .upload_canister_snapshot_metadata(&upload_args)
        .unwrap()
        .snapshot_id;

    // Upload snapshot (binary) data.
    env.upload_snapshot_module(
        target_canister_id,
        uploaded_snapshot_id,
        &module_download,
        None,
        None,
    )
    .unwrap();
    env.upload_snapshot_heap(
        target_canister_id,
        uploaded_snapshot_id,
        &heap_download,
        None,
        None,
    )
    .unwrap();
    env.upload_snapshot_stable_memory(
        target_canister_id,
        uploaded_snapshot_id,
        &stable_memory_download,
        None,
        None,
    )
    .unwrap();
    for (_, chunk) in chunk_store_download {
        env.upload_canister_snapshot_data(&UploadCanisterSnapshotDataArgs::new(
            target_canister_id,
            uploaded_snapshot_id,
            CanisterSnapshotDataOffset::WasmChunk,
            chunk,
        ))
        .unwrap();
    }

    uploaded_snapshot_id
}

// Take a fresh snapshot and returns its metadata to inspect the current canister state.
fn get_current_metadata(
    env: &StateMachine,
    canister_id: CanisterId,
) -> ReadCanisterSnapshotMetadataResponse {
    let inspect_snapshot_id = env
        .take_canister_snapshot(TakeCanisterSnapshotArgs::new(canister_id, None, None, None))
        .unwrap()
        .snapshot_id();
    let download_args = ReadCanisterSnapshotMetadataArgs::new(canister_id, inspect_snapshot_id);
    env.read_canister_snapshot_metadata(&download_args).unwrap()
}

// This function performs the following test scenario:
// - install a canister provided in WAT;
// - take a snapshot of the canister;
// - ensure that the globals in the snapshot match `expected_globals`;
// - if `download_upload`, then download the snapshot, upload the snapshot,
//   and check that the uploaded snapshot matches the original snapshot;
// - load the snapshot onto the canister;
// - execute an update call to verify the canister can execute successfully after loading the snapshot;
// - take another snapshot to check the canister state after loading the snapshot.
fn take_download_upload_load_snapshot_roundtrip(
    canister_wat: &str,
    expected_globals: Vec<Global>,
    download_upload: bool,
) {
    let env = StateMachineBuilder::new()
        .with_snapshot_download_enabled(true)
        .with_snapshot_upload_enabled(true)
        .build();

    let canister_wasm = wat::parse_str(canister_wat).unwrap();
    let canister_id = env.install_canister(canister_wasm, vec![], None).unwrap();

    let snapshot_id = env
        .take_canister_snapshot(TakeCanisterSnapshotArgs::new(canister_id, None, None, None))
        .unwrap()
        .snapshot_id();
    let download_args = ReadCanisterSnapshotMetadataArgs::new(canister_id, snapshot_id);
    let metadata = env.read_canister_snapshot_metadata(&download_args).unwrap();
    assert_eq!(metadata.globals, expected_globals);

    let load_snapshot_id = if download_upload {
        let uploaded_snapshot_id =
            download_upload_snapshot(&env, canister_id, snapshot_id, canister_id);
        assert_snapshot_eq(
            &env,
            canister_id,
            snapshot_id,
            canister_id,
            uploaded_snapshot_id,
        );

        uploaded_snapshot_id
    } else {
        snapshot_id
    };

    let load_snapshot_args = LoadCanisterSnapshotArgs::new(canister_id, load_snapshot_id, None);
    env.load_canister_snapshot(load_snapshot_args).unwrap();

    // Ensure that the canister can successfully execute a message after loading a snapshot.
    env.execute_ingress(canister_id, "run", vec![]).unwrap();

    // We take one more snapshot to inspect the canister state after loading the snapshot in a previous step.
    let inspect_snapshot_id = env
        .take_canister_snapshot(TakeCanisterSnapshotArgs::new(canister_id, None, None, None))
        .unwrap()
        .snapshot_id();
    assert_snapshot_eq(
        &env,
        canister_id,
        load_snapshot_id,
        canister_id,
        inspect_snapshot_id,
    );
}

// Performs the test scenario from `take_download_upload_load_snapshot_roundtrip`
// with `download_upload` set to both `false` and `true`
// on a matrix of (WAT) canisters with no global:
// - memory is 32-bit or 64-bit.
#[test]
fn take_download_upload_load_snapshot_roundtrip_no_globals() {
    for memory in ["", "i64"] {
        let wat = format!(
            r#"
(module
  (import "ic0" "msg_reply" (func $msg_reply))
  (func $run
    (call $msg_reply)
  )
  (export "canister_update run" (func $run))
  (memory {memory} 1)
)"#
        );
        for download_upload in [false, true] {
            take_download_upload_load_snapshot_roundtrip(&wat, vec![], download_upload);
        }
    }
}

// Performs the test scenario from `take_download_upload_load_snapshot_roundtrip`
// with `download_upload` set to both `false` and `true`
// on a matrix of (WAT) canisters with a single global:
// - the global is exported or not,
// - the global is mutable or not,
// - memory is 32-bit or 64-bit.
#[test]
fn take_download_upload_load_snapshot_roundtrip_one_global() {
    for is_exported in [false, true] {
        for is_mutable in [false, true] {
            for memory in ["", "i64"] {
                let exported = if is_exported {
                    "(export \"my_global\")"
                } else {
                    ""
                };
                let mutable = if is_mutable { "(mut i32)" } else { "i32" };
                let wat = format!(
                    r#"
(module
  (import "ic0" "msg_reply" (func $msg_reply))
  (func $run
    (call $msg_reply)
  )
  (export "canister_update run" (func $run))
  (global {exported} {mutable} (i32.const 42))
  (memory {memory} 1)
)"#
                );
                // The current implementation includes all globals that are exported or mutable.
                let expected_globals = if is_exported || is_mutable {
                    vec![Global::I32(42)]
                } else {
                    vec![]
                };
                for download_upload in [false, true] {
                    take_download_upload_load_snapshot_roundtrip(
                        &wat,
                        expected_globals.clone(),
                        download_upload,
                    );
                }
            }
        }
    }
}

fn test_env_for_global_timer_on_low_wasm_memory()
-> (StateMachine, CanisterId, SnapshotId, WasmResult) {
    let env = StateMachineBuilder::new()
        .with_snapshot_download_enabled(true)
        .with_snapshot_upload_enabled(true)
        .build();

    // Set the wasm memory limit explicitly to `4 GiB` (the default is lower)
    // and the wasm memory threshold to `4 GiB - 30 MiB` so that growing the (32-bit) wasm memory by `30 MiB` triggers the on low wasm memory hook.
    let wasm_memory_limit = 4 << 30;
    let wasm_memory_increase = 30 << 20;
    let settings = CanisterSettingsArgsBuilder::new()
        .with_wasm_memory_limit(wasm_memory_limit)
        .with_wasm_memory_threshold(wasm_memory_limit - wasm_memory_increase)
        .build();
    // Define the on low wasm memory hook to bump a global counter if executed.
    let set_on_low_wasm_memory = wasm()
        .set_on_low_wasm_memory_method(wasm().inc_global_counter().build())
        .build();
    let canister_id = env
        .install_canister(
            UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec(),
            set_on_low_wasm_memory.clone(),
            Some(settings),
        )
        .unwrap();

    // Set the global timer into far future and grow wasm memory by at least `30 MiB` to trigger the on low wasm memory hook.
    let now = env.get_time().as_nanos_since_unix_epoch();
    let global_timer = now + 1_000_000; // set global timer in many rounds from now so that it stays active up until the canister is reinstalled
    env.execute_ingress(
        canister_id,
        "update",
        wasm()
            .api_global_timer_set(global_timer)
            .push_equal_bytes(42, wasm_memory_increase as u32)
            .reply()
            .build(),
    )
    .unwrap();

    // Execute one more ingress to ensure the on low wasm memory hook was executed.
    env.execute_ingress(canister_id, "update", wasm().reply().build())
        .unwrap();

    let current_metadata = get_current_metadata(&env, canister_id);
    assert!(matches!(
        current_metadata.global_timer.unwrap(),
        GlobalTimer::Active(_)
    ));
    assert!(matches!(
        current_metadata.on_low_wasm_memory_hook_status.unwrap(),
        OnLowWasmMemoryHookStatus::Executed
    ));

    let snapshot_id = env
        .take_canister_snapshot(TakeCanisterSnapshotArgs::new(canister_id, None, None, None))
        .unwrap()
        .snapshot_id();

    // The value of the counter bumped by on low wasm memory hook.
    let on_low_wasm_memory_hook = env
        .execute_ingress(
            canister_id,
            "update",
            wasm().get_global_counter().reply_int64().build(),
        )
        .unwrap();

    // Reinstall the canister to make the global timer deactivated (this is a protocol feature)
    // and the on low wasm memory hook condition not satisfied (because the wasm memory is reset upon reinstall).
    env.reinstall_canister(
        canister_id,
        UNIVERSAL_CANISTER_NO_HEARTBEAT_WASM.to_vec(),
        set_on_low_wasm_memory,
    )
    .unwrap();

    let current_metadata = get_current_metadata(&env, canister_id);
    assert!(matches!(
        current_metadata.global_timer.unwrap(),
        GlobalTimer::Inactive
    ));
    assert!(matches!(
        current_metadata.on_low_wasm_memory_hook_status.unwrap(),
        OnLowWasmMemoryHookStatus::ConditionNotSatisfied
    ));

    (env, canister_id, snapshot_id, on_low_wasm_memory_hook)
}

// Tests that the state of global timer and on low wasm memory hook
// are restored when loading a snapshot created by `upload_canister_snapshot_metadata`.
#[test]
fn download_upload_load_snapshot_global_timer_on_low_wasm_memory() {
    let (env, canister_id, snapshot_id, on_low_wasm_memory_hook) =
        test_env_for_global_timer_on_low_wasm_memory();

    let uploaded_snapshot_id =
        download_upload_snapshot(&env, canister_id, snapshot_id, canister_id);
    assert_snapshot_eq(
        &env,
        canister_id,
        snapshot_id,
        canister_id,
        uploaded_snapshot_id,
    );

    let load_snapshot_args = LoadCanisterSnapshotArgs::new(canister_id, uploaded_snapshot_id, None);
    env.load_canister_snapshot(load_snapshot_args).unwrap();

    // Execute one more ingress to ensure the on low wasm memory hook was executed if scheduled (which should not be the case).
    env.execute_ingress(canister_id, "update", wasm().reply().build())
        .unwrap();

    // We take one more snapshot to inspect the canister state after loading the snapshot in a previous step.
    let inspect_snapshot_id = env
        .take_canister_snapshot(TakeCanisterSnapshotArgs::new(canister_id, None, None, None))
        .unwrap()
        .snapshot_id();
    assert_snapshot_eq(
        &env,
        canister_id,
        uploaded_snapshot_id,
        canister_id,
        inspect_snapshot_id,
    );

    // On low wasm memory hook was not executed one more time.
    let current_on_low_wasm_memory_hook = env
        .execute_ingress(
            canister_id,
            "update",
            wasm().get_global_counter().reply_int64().build(),
        )
        .unwrap();
    assert_eq!(current_on_low_wasm_memory_hook, on_low_wasm_memory_hook);
}

// Tests that the state of global timer and on low wasm memory hook
// are not restored when loading a snapshot created by `take_canister_snapshot`.
#[test]
fn take_load_snapshot_global_timer_on_low_wasm_memory() {
    let (env, canister_id, snapshot_id, on_low_wasm_memory_hook) =
        test_env_for_global_timer_on_low_wasm_memory();

    let load_snapshot_args = LoadCanisterSnapshotArgs::new(canister_id, snapshot_id, None);
    env.load_canister_snapshot(load_snapshot_args).unwrap();

    // Execute one more ingress to ensure the on low wasm memory hook was executed if scheduled.
    env.execute_ingress(canister_id, "update", wasm().reply().build())
        .unwrap();

    let current_metadata = get_current_metadata(&env, canister_id);

    // Global timer was not reset.
    assert!(matches!(
        current_metadata.global_timer.unwrap(),
        GlobalTimer::Inactive
    ));
    // On low wasm memory hook was not reset and thus it was executed one more time.
    assert!(matches!(
        current_metadata.on_low_wasm_memory_hook_status.unwrap(),
        OnLowWasmMemoryHookStatus::Executed
    ));
    let current_on_low_wasm_memory_hook = env
        .execute_ingress(
            canister_id,
            "update",
            wasm().get_global_counter().reply_int64().build(),
        )
        .unwrap();
    assert_ne!(current_on_low_wasm_memory_hook, on_low_wasm_memory_hook);
}

#[test]
fn upload_and_load_snapshot_with_invalid_wasm() {
    let env = StateMachineBuilder::new()
        .with_snapshot_download_enabled(true)
        .with_snapshot_upload_enabled(true)
        .build();

    let canister_id = env.create_canister(None);

    // Upload snapshot metadata.
    // A wasm module consisting of 42 zeros is invalid.
    let upload_args = UploadCanisterSnapshotMetadataArgs::new(
        canister_id,
        None,   /* replace_snapshot */
        42,     /* wasm_module_size */
        vec![], /* globals */
        0,      /* wasm_memory_size */
        0,      /* stable_memory_size */
        vec![], /* certified_data */
        None,   /* global_timer */
        None,   /* on_low_wasm_memory_hook_status */
    );
    let uploaded_snapshot_id = env
        .upload_canister_snapshot_metadata(&upload_args)
        .unwrap()
        .snapshot_id;

    let load_snapshot_args = LoadCanisterSnapshotArgs::new(canister_id, uploaded_snapshot_id, None);
    let err = env.load_canister_snapshot(load_snapshot_args).unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterInvalidWasm);
    assert!(err.description().contains("Canister's Wasm module is not valid: Failed to decode wasm module: unsupported canister module format."));
}

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
        .take_canister_snapshot(TakeCanisterSnapshotArgs::new(canister_id, None, None, None))
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
        md.globals.clone(),
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
        .take_canister_snapshot(TakeCanisterSnapshotArgs::new(canister_id, None, None, None))
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
        .take_canister_snapshot(TakeCanisterSnapshotArgs::new(canister_id, None, None, None))
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
        md.globals.clone(),
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
            args.globals = vec![Global::I32(1), Global::I64(1999996623), Global::I32(2)];
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

#[test]
fn take_frozen_canister_snapshot_fails() {
    // Create application subnet `StateMachine`.
    let subnet_type = SubnetType::Application;
    let subnet_config = SubnetConfig::new(subnet_type);
    let execution_config = ExecutionConfig::default();
    let config = StateMachineConfig::new(subnet_config, execution_config);
    let env = StateMachineBuilder::new()
        .with_config(Some(config))
        .with_subnet_type(subnet_type)
        .build();

    // Deploy a universal canister.
    const T: u128 = 1_000_000_000_000;
    let initial_cycles = 10 * T;
    let canister_id = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            initial_cycles.into(),
        )
        .unwrap();

    // Increase memory usage of the universal canister.
    env.execute_ingress(
        canister_id,
        "update",
        wasm().stable_grow(1000).reply().build(),
    )
    .unwrap();

    // Make the universal canister frozen by increasing its freezing threshold until it becomes frozen.
    let mut freezing_threshold = 1;
    loop {
        let settings = CanisterSettingsArgsBuilder::new()
            .with_freezing_threshold(freezing_threshold)
            .build();
        env.update_settings(&canister_id, settings).unwrap();

        // Check if the canister is frozen.
        let res = env.execute_ingress(canister_id, "update", wasm().reply().build());
        match res {
            Ok(_) => {
                freezing_threshold <<= 1;
            }
            Err(err) => {
                // should be frozen
                assert_eq!(err.code(), ErrorCode::CanisterOutOfCycles);
                break;
            }
        }
    }

    // Unfreeze the canister by halving its freezing threshold.
    freezing_threshold >>= 1;
    let settings = CanisterSettingsArgsBuilder::new()
        .with_freezing_threshold(freezing_threshold)
        .build();
    env.update_settings(&canister_id, settings).unwrap();

    // Check that the canister is no longer frozen.
    env.execute_ingress(canister_id, "update", wasm().reply().build())
        .unwrap();

    // Taking a snapshot would make the canister frozen so the call fails.
    let args = TakeCanisterSnapshotArgs {
        canister_id: canister_id.get(),
        replace_snapshot: None,
        uninstall_code: None,
        sender_canister_version: None,
    };
    let err = env.take_canister_snapshot(args).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InsufficientCyclesInMemoryGrow);
}

#[test]
fn load_canister_snapshot_works_on_another_canister() {
    let subnet_type = SubnetType::Application;
    let subnet_config = SubnetConfig::new(subnet_type);
    let execution_config = ExecutionConfig::default();
    let config = StateMachineConfig::new(subnet_config, execution_config);
    let env = StateMachineBuilder::new()
        .with_config(Some(config))
        .with_snapshot_download_enabled(true)
        .with_subnet_type(subnet_type)
        .build();

    const T: u128 = 1_000_000_000_000;
    let initial_cycles = 10 * T;
    let canister_id_1 = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            initial_cycles.into(),
        )
        .unwrap();

    let canister_id_2 = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            initial_cycles.into(),
        )
        .unwrap();

    env.execute_ingress(
        canister_id_1,
        "update",
        wasm().stable_grow(100).reply().build(),
    )
    .unwrap();

    let canister_version_at_snapshot = env
        .get_latest_state()
        .canister_state(&canister_id_1)
        .unwrap()
        .system_state
        .canister_version;

    let snapshot_1 = env
        .take_canister_snapshot(TakeCanisterSnapshotArgs::new(
            canister_id_1,
            None,
            None,
            None,
        ))
        .unwrap();
    let snapshot_id_1 = snapshot_1.snapshot_id();
    let snapshot_taken_at_timestamp = snapshot_1.taken_at_timestamp();

    // Loading a canister snapshot belonging to `canister_id_1` on `canister_id_2` should
    // fail if there is non-empty page delta in the shared page map.
    // This limitation will be lifted in the future.
    let err = env
        .load_canister_snapshot(LoadCanisterSnapshotArgs::new(
            canister_id_2,
            snapshot_id_1,
            None,
        ))
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterRejectedMessage);
    assert_eq!(
        err.description(),
        format!(
            "Snapshot {} is not currently loadable on the specified canister {}. Try again later. The call should succeed if you wait sufficiently long (usually ten minutes).",
            snapshot_id_1, canister_id_2
        ),
    );

    // Checkpoint the state before loading the snapshot to ensure that
    // there no outstanding page delta in the shared page map by the
    // two canisters (the one owning the snapshot and the one loading it).
    env.checkpointed_tick();

    // Loading a canister snapshot belonging to `canister_id_1` on `canister_id_2` succeeds.
    env.load_canister_snapshot(LoadCanisterSnapshotArgs::new(
        canister_id_2,
        snapshot_id_1,
        None,
    ))
    .unwrap();

    // The two canisters now should have the same state (equivalently, their current snapshots should be equal).
    let snapshot_id_2 = env
        .take_canister_snapshot(TakeCanisterSnapshotArgs::new(
            canister_id_2,
            None,
            None,
            None,
        ))
        .unwrap()
        .snapshot_id();
    assert_snapshot_eq(
        &env,
        canister_id_1,
        snapshot_id_1,
        canister_id_2,
        snapshot_id_2,
    );

    // Verify that the latest canister history change is a `load_snapshot` with
    // with the expected `from_canister_id` set appropriately to the canister
    // that the snapshot belongs to.
    let history = env.get_canister_history(canister_id_2);
    let latest_change_details = history.get_changes(1).next().unwrap().details();
    assert_eq!(
        latest_change_details,
        &CanisterChangeDetails::load_snapshot(
            canister_version_at_snapshot,
            snapshot_id_1,
            snapshot_taken_at_timestamp,
            SnapshotSource::TakenFromCanister(Reserved),
            Some(canister_id_1),
        ),
    );
}

#[test]
fn canister_snapshots_and_memory_allocation() {
    let env = StateMachine::new();

    // We first fill the subnet with canisters having 100 GiB of memory allocation each.
    let mut canisters = vec![];
    loop {
        let settings = CanisterSettingsArgsBuilder::new()
            .with_memory_allocation(100 << 30)
            .build();
        match env.create_canister_with_cycles_impl(None, Cycles::zero(), Some(settings)) {
            Ok(WasmResult::Reply(bytes)) => {
                let canister_id = Decode!(&bytes, CanisterIdRecord).unwrap().get_canister_id();
                canisters.push(canister_id);
            }
            Ok(WasmResult::Reject(err)) => panic!("Unexpected reject: {}", err),
            Err(err) => {
                assert_eq!(err.code(), ErrorCode::SubnetOversubscribed);
                break;
            }
        }
    }

    // Now we unset the memory allocation of the last canister, i.e.,
    // make its memory allocation best-effort.
    // Since this canister is the only canister with best-effort memory allocation
    // and the other canisters do not exceed their memory allocation of 100 GiB,
    // it is effectively still guaranteed that this last canister can grow
    // its memory usage up to 100 GiB.
    let best_effort_canister_id = canisters.last().unwrap();
    env.update_settings(
        best_effort_canister_id,
        CanisterSettingsArgsBuilder::new()
            .with_memory_allocation(0)
            .build(),
    )
    .unwrap();

    // For each canister (including the last best-effort canister),
    // we deploy the universal canister WASM,
    // grow stable memory to 40 GiB, and take a canister snapshot.
    // This should succeed because the overall memory usage is ~80 GiB
    // which is well within the memory allocation of 100 GiB.
    for canister_id in canisters {
        env.install_existing_canister(canister_id, UNIVERSAL_CANISTER_WASM.to_vec(), vec![])
            .unwrap();
        env.execute_ingress(
            canister_id,
            "update",
            wasm().stable64_grow(655360).reply().build(),
        )
        .unwrap(); // 40 GiB
        let args = TakeCanisterSnapshotArgs {
            canister_id: canister_id.get(),
            replace_snapshot: None,
            uninstall_code: None,
            sender_canister_version: None,
        };
        env.take_canister_snapshot(args).unwrap();
    }
}
