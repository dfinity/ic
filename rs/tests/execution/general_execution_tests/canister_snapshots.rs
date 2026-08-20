use candid::Principal;
use ic_agent::agent::RejectCode;
use ic_base_types::CanisterId;
use ic_management_canister_types_private::{
    CanisterSnapshotDataOffset, LoadCanisterSnapshotArgs, Payload, UploadCanisterSnapshotDataArgs,
    UploadCanisterSnapshotMetadataArgs, UploadCanisterSnapshotMetadataResponse,
};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl};
use ic_system_test_driver::util::{assert_reject_msg, block_on};
use ic_utils::interfaces::ManagementCanister;
use slog::warn;

/// Uploads a snapshot with 2MiB wasm_memory_size for a `(memory 1 1)` module,
/// loads it, and verifies that execution fails gracefully (rather than panicking):
/// the module's declared max of 1 page cannot be grown to the snapshot's 32 pages.
pub fn upload_and_load_snapshot_with_wasm_memory(env: TestEnv) {
    let logger = env.logger();
    let app_node = env.get_first_healthy_application_node_snapshot();
    let agent = app_node.build_default_agent();
    block_on(async move {
        let mgr = ManagementCanister::create(&agent);
        let (canister_principal,) = mgr
            .create_canister()
            .as_provisional_create_with_amount(None)
            .with_effective_canister_id(app_node.effective_canister_id())
            .call_and_wait()
            .await
            .expect("Failed to create canister");
        let canister_id = CanisterId::unchecked_from_principal(canister_principal.into());
        warn!(
            logger,
            "upload_and_load_snapshot_with_wasm_memory: created canister {}", canister_id
        );

        const MIB_2: u64 = 2 * 1024 * 1024;
        let wasm = wat::parse_str(
            r#"
(module
  (import "ic0" "msg_reply" (func $msg_reply))
  (import "ic0" "msg_reply_data_append" (func $msg_reply_data_append (param i32 i32)))
  (func $read
    (call $msg_reply_data_append (i32.const 0) (i32.const 4))
    (call $msg_reply)
  )
  (func $write
    (i32.store
      (i32.const 0)
      (i32.add (i32.load (i32.const 0)) (i32.const 1))
    )
    (call $read)
  )
  (memory 1 1)
  (export "canister_query read" (func $read))
  (export "canister_update inc" (func $write))
)"#,
        )
        .unwrap();

        let ic00 = Principal::management_canister();

        // Upload snapshot metadata claiming 2MiB (32 pages) of wasm memory.
        let metadata_args = UploadCanisterSnapshotMetadataArgs::new(
            canister_id,
            None,              // replace_snapshot
            wasm.len() as u64, // wasm_module_size
            vec![],            // globals
            MIB_2,             // wasm_memory_size (2 MiB = 32 pages)
            0,                 // stable_memory_size
            vec![],            // certified_data
            None,              // global_timer
            None,              // on_low_wasm_memory_hook_status
        );
        let response_bytes = agent
            .update(&ic00, "upload_canister_snapshot_metadata")
            .with_effective_canister_id(canister_principal)
            .with_arg(metadata_args.encode())
            .call_and_wait()
            .await
            .expect("Failed to upload snapshot metadata");
        let snapshot_id = UploadCanisterSnapshotMetadataResponse::decode(&response_bytes)
            .unwrap()
            .snapshot_id;

        // Upload the wasm module into the snapshot.
        agent
            .update(&ic00, "upload_canister_snapshot_data")
            .with_effective_canister_id(canister_principal)
            .with_arg(
                UploadCanisterSnapshotDataArgs::new(
                    canister_id,
                    snapshot_id,
                    CanisterSnapshotDataOffset::WasmModule { offset: 0 },
                    wasm,
                )
                .encode(),
            )
            .call_and_wait()
            .await
            .expect("Failed to upload snapshot wasm module");

        // Build a 2MiB heap with counter=42 encoded at address 0.
        let mut heap = vec![0_u8; MIB_2 as usize];
        heap[..4].copy_from_slice(&42_u32.to_le_bytes());

        // Upload the heap in 1MiB chunks to stay within the 2MiB message limit.
        const CHUNK_SIZE: usize = 1024 * 1024;
        for (i, chunk) in heap.chunks(CHUNK_SIZE).enumerate() {
            let offset = (i * CHUNK_SIZE) as u64;
            agent
                .update(&ic00, "upload_canister_snapshot_data")
                .with_effective_canister_id(canister_principal)
                .with_arg(
                    UploadCanisterSnapshotDataArgs::new(
                        canister_id,
                        snapshot_id,
                        CanisterSnapshotDataOffset::WasmMemory { offset },
                        chunk.to_vec(),
                    )
                    .encode(),
                )
                .call_and_wait()
                .await
                .expect("Failed to upload snapshot heap chunk");
        }

        agent
            .update(&ic00, "load_canister_snapshot")
            .with_effective_canister_id(canister_principal)
            .with_arg(LoadCanisterSnapshotArgs::new(canister_id, snapshot_id, None).encode())
            .call_and_wait()
            .await
            .expect("Failed to load snapshot");

        // Execution fails gracefully: the `(memory 1 1)` module's declared max of 1 page
        // cannot be grown to the snapshot's 32 pages (2 MiB).
        let result = agent
            .update(&canister_principal, "inc")
            .call_and_wait()
            .await;
        assert_reject_msg(
            result,
            RejectCode::CanisterError,
            "Failed to grow wasm memory by 31 page(s) to 32 page(s): exceeds module's declared maximum",
        );
    });
}
