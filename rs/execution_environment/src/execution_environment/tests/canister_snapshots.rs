use assert_matches::assert_matches;
use candid::{Decode, Encode};
use ic_base_types::NumBytes;
use ic_config::subnet_config::SubnetConfig;
use ic_cycles_account_manager::ResourceSaturation;
use ic_error_types::{ErrorCode, RejectCode};
use ic_management_canister_types_private::{
    self as ic00, CanisterChange, CanisterChangeDetails, CanisterSettingsArgsBuilder,
    CanisterSnapshotDataKind, CanisterSnapshotResponse, ChunkHash, ClearChunkStoreArgs,
    DeleteCanisterSnapshotArgs, GlobalTimer, ListCanisterSnapshotArgs, LoadCanisterSnapshotArgs,
    Method, OnLowWasmMemoryHookStatus, Payload as Ic00Payload, ReadCanisterSnapshotDataArgs,
    ReadCanisterSnapshotDataResponse, ReadCanisterSnapshotMetadataArgs,
    ReadCanisterSnapshotMetadataResponse, SnapshotSource, TakeCanisterSnapshotArgs,
    UpdateSettingsArgs, UploadChunkArgs,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    canister_state::{
        execution_state::{WasmBinary, WasmExecutionMode},
        system_state::{wasm_chunk_store::CHUNK_SIZE, CyclesUseCase},
        WASM_PAGE_SIZE_IN_BYTES,
    },
    metadata_state::UnflushedCheckpointOp,
    CanisterState, ExecutionState, SchedulerState,
};
use ic_sys::PAGE_SIZE;
use ic_test_utilities_execution_environment::{
    cycles_reserved_for_app_and_verified_app_subnets, get_output_messages, ExecutionTest,
    ExecutionTestBuilder,
};
use ic_test_utilities_types::ids::{canister_test_id, subnet_test_id};
use ic_types::{
    ingress::WasmResult,
    messages::{Payload, RejectContext, RequestOrResponse},
    time::UNIX_EPOCH,
    CanisterId, Cycles, NumInstructions, SnapshotId,
};
use ic_types_test_utils::ids::user_test_id;
use ic_universal_canister::{wasm, UNIVERSAL_CANISTER_WASM};
use more_asserts::assert_gt;
use serde_bytes::ByteBuf;
use std::borrow::Borrow;

const WASM_EXECUTION_MODE: WasmExecutionMode = WasmExecutionMode::Wasm32;

#[test]
fn take_canister_snapshot_decode_round_trip() {
    let canister_id = canister_test_id(4);
    let snapshot_id = SnapshotId::from((canister_id, 6));
    let args = ic00::TakeCanisterSnapshotArgs::new(canister_test_id(4), Some(snapshot_id));
    let encoded_args = args.encode();
    assert_eq!(
        args,
        TakeCanisterSnapshotArgs::decode(encoded_args.as_slice()).unwrap()
    );

    let response = CanisterSnapshotResponse::new(
        &snapshot_id,
        UNIX_EPOCH.as_nanos_since_unix_epoch(),
        NumBytes::from(65),
    );
    let encoded_response = response.encode();
    assert_eq!(
        response,
        CanisterSnapshotResponse::decode(encoded_response.as_slice()).unwrap()
    );
}

#[test]
fn take_canister_snapshot_decode_fails() {
    let canister_id = canister_test_id(4);
    let args = ic00::TakeCanisterSnapshotArgs {
        canister_id: canister_id.get(),
        replace_snapshot: Some(ByteBuf::from(vec![4, 5, 6, 6])), // Invalid snapshot ID.
    };
    let encoded_args = args.encode();
    let err = TakeCanisterSnapshotArgs::decode(encoded_args.as_slice()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidManagementPayload,);
}

#[test]
fn snapshot_request_rejected_because_decode_args_fail() {
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_manual_execution()
        .with_caller(own_subnet, caller_canister)
        .build();

    // Inject a take_canister_snapshot request.
    test.inject_call_to_ic00(
        Method::TakeCanisterSnapshot,
        Encode!().unwrap(),
        Cycles::new(1_000_000_000),
    );

    test.execute_subnet_message();

    let (receiver, response) = &get_output_messages(test.state_mut()).pop().unwrap();
    assert_matches!(response, RequestOrResponse::Response(_));
    if let RequestOrResponse::Response(res) = response {
        assert_eq!(res.originator, *receiver);
        assert_matches!(res.response_payload, Payload::Reject(_));
        if let Payload::Reject(context) = &res.response_payload {
            assert!(context.message().contains("Error decoding candid"));
        }
    }
}

#[test]
fn take_canister_snapshot_fails_canister_not_found() {
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_manual_execution()
        .with_caller(own_subnet, caller_canister)
        .build();

    let canister_id = canister_test_id(4);
    let snapshot_id = SnapshotId::from((canister_id, 6));
    let args: TakeCanisterSnapshotArgs =
        TakeCanisterSnapshotArgs::new(canister_id, Some(snapshot_id));
    // Inject a take_canister_snapshot request.
    test.inject_call_to_ic00(
        Method::TakeCanisterSnapshot,
        args.encode(),
        Cycles::new(1_000_000_000),
    );

    test.execute_subnet_message();

    let (receiver, response) = &get_output_messages(test.state_mut()).pop().unwrap();
    assert_matches!(response, RequestOrResponse::Response(_));
    if let RequestOrResponse::Response(res) = response {
        assert_eq!(res.originator, *receiver);
        assert_eq!(
            res.response_payload,
            Payload::Reject(RejectContext::new(
                RejectCode::DestinationInvalid,
                format!("Canister {} not found.", canister_id)
            ))
        );
    }
}

#[test]
fn take_canister_snapshot_fails_invalid_controller() {
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_manual_execution()
        .with_caller(own_subnet, caller_canister)
        .build();

    // Create new canister.
    let canister_id = test
        .create_canister_with_allocation(Cycles::new(1_000_000_000_000_000), None, None)
        .unwrap();

    // Create `TakeCanisterSnapshot`.
    let snapshot_id = SnapshotId::from((canister_id, 6));
    let args: TakeCanisterSnapshotArgs =
        TakeCanisterSnapshotArgs::new(canister_id, Some(snapshot_id));
    // Inject a take_canister_snapshot request.
    test.inject_call_to_ic00(
        Method::TakeCanisterSnapshot,
        args.encode(),
        Cycles::new(1_000_000_000),
    );
    test.execute_subnet_message();

    // Reject expected: caller is not a controller of the canister.
    let (receiver, response) = &get_output_messages(test.state_mut()).pop().unwrap();
    assert_matches!(response, RequestOrResponse::Response(_));
    if let RequestOrResponse::Response(res) = response {
        assert_eq!(res.originator, *receiver);
        res.response_payload.assert_contains_reject(
            RejectCode::CanisterError,
            &format!(
                "Only the controllers of the canister {} can control it.\n\
                    Canister's controllers: {}\n\
                    Sender's ID: {}",
                canister_id,
                test.user_id().get(),
                caller_canister.get(),
            ),
        );
    }

    // Verify the canister exists in the `ReplicatedState`.
    assert!(test.state().canister_state(&canister_id).is_some());
}

#[test]
fn take_canister_snapshot_fails_invalid_replace_snapshot_id() {
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_manual_execution()
        .with_caller(own_subnet, caller_canister)
        .build();

    // Create canister and update controllers.
    let canister_id = test
        .create_canister_with_allocation(Cycles::new(1_000_000_000_000_000), None, None)
        .unwrap();
    let controllers = vec![caller_canister.get(), test.user_id().get()];
    test.canister_update_controller(canister_id, controllers)
        .unwrap();

    // Create `TakeCanisterSnapshot` request with non-existent snapshot ID.
    let snapshot_id = SnapshotId::from((canister_id, 6));
    let args: TakeCanisterSnapshotArgs =
        TakeCanisterSnapshotArgs::new(canister_id, Some(snapshot_id));
    // Inject a take_canister_snapshot request.
    test.inject_call_to_ic00(
        Method::TakeCanisterSnapshot,
        args.encode(),
        Cycles::new(1_000_000_000),
    );
    test.execute_subnet_message();

    let (receiver, response) = &get_output_messages(test.state_mut()).pop().unwrap();
    assert_matches!(response, RequestOrResponse::Response(_));
    if let RequestOrResponse::Response(res) = response {
        assert_eq!(res.originator, *receiver);
        res.response_payload.assert_contains_reject(
            RejectCode::DestinationInvalid,
            &format!(
                "Could not find the snapshot ID {} for canister {}.",
                snapshot_id, canister_id
            ),
        );
    }

    // Verify the canister exists in the `ReplicatedState`.
    assert!(test.state().canister_state(&canister_id).is_some());
}

#[test]
fn take_canister_snapshot_fails_canister_does_not_own_replace_snapshot() {
    const CYCLES: Cycles = Cycles::new(20_000_000_000_000);
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_manual_execution()
        .with_caller(own_subnet, caller_canister)
        .build();

    // Create canisters.
    let canister_id_1 = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();
    let canister_id_2 = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();

    // Take a snapshot for canister_1.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id_1, None);
    let result = test.subnet_message("take_canister_snapshot", args.encode());
    assert!(result.is_ok());
    let response = CanisterSnapshotResponse::decode(&result.unwrap().bytes()).unwrap();
    let snapshot_id = response.snapshot_id();

    // Take a snapshot for the canister_2. Provide replace snapshot.
    let args: TakeCanisterSnapshotArgs =
        TakeCanisterSnapshotArgs::new(canister_id_2, Some(snapshot_id));
    let error = test
        .subnet_message("take_canister_snapshot", args.encode())
        .unwrap_err();

    assert_eq!(error.code(), ErrorCode::CanisterRejectedMessage);
    let message = format!(
        "The snapshot {} does not belong to canister {}",
        snapshot_id, canister_id_2,
    )
    .to_string();
    assert!(error.description().contains(&message));

    // Verify the canisters exists in the `ReplicatedState`.
    assert!(test.state().canister_state(&canister_id_1).is_some());
    assert!(test.state().canister_state(&canister_id_2).is_some());
}

#[test]
fn canister_request_take_canister_snapshot_creates_new_snapshots() {
    const CYCLES: Cycles = Cycles::new(20_000_000_000_000);
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_caller(own_subnet, caller_canister)
        .build();

    // Create canister and update controllers.
    let canister_id = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();
    let controllers = vec![caller_canister.get(), test.user_id().get()];
    test.canister_update_controller(canister_id, controllers)
        .unwrap();

    // Upload chunk.
    let chunk = vec![1, 2, 3, 4, 5];
    let upload_args = UploadChunkArgs {
        canister_id: canister_id.into(),
        chunk,
    };
    let result = test.subnet_message("upload_chunk", upload_args.encode());
    assert!(result.is_ok());

    // Take a snapshot for the canister.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
    let result = test.subnet_message("take_canister_snapshot", args.encode());
    assert!(result.is_ok());
    let response = CanisterSnapshotResponse::decode(&result.unwrap().bytes()).unwrap();
    let snapshot_id = response.snapshot_id();

    assert!(test.state().canister_snapshots.contains(&snapshot_id));
    assert!(test.state().canister_snapshots.contains(&snapshot_id));

    assert!(test.state().canister_snapshots.contains(&snapshot_id));

    let snapshot = test.state().canister_snapshots.get(snapshot_id).unwrap();
    assert_eq!(
        *snapshot.canister_module(),
        test.canister_state(canister_id)
            .execution_state
            .as_ref()
            .unwrap()
            .wasm_binary
            .binary
    );
    assert_eq!(
        *snapshot.chunk_store(),
        test.canister_state(canister_id)
            .system_state
            .wasm_chunk_store
    );
    // Confirm that `snapshots_memory_usage` is updated correctly.
    assert_eq!(
        test.canister_state(canister_id)
            .system_state
            .snapshots_memory_usage,
        test.state()
            .canister_snapshots
            .compute_memory_usage_by_canister(canister_id),
    );

    // Grow the canister's memory before taking another snapshot.
    test.ingress(
        canister_id,
        "update",
        wasm()
            .memory_size_is_at_least(20 * 1024 * 1024) // 20 MiB
            .reply_data(&[42])
            .build(),
    )
    .unwrap();

    // Take a new snapshot for the canister, and provide a replacement snapshot ID.
    let args: TakeCanisterSnapshotArgs =
        TakeCanisterSnapshotArgs::new(canister_id, Some(snapshot_id));
    let result = test.subnet_message("take_canister_snapshot", args.encode());
    assert!(result.is_ok());
    let new_snapshot_id = CanisterSnapshotResponse::decode(&result.unwrap().bytes())
        .unwrap()
        .snapshot_id();

    // Check that old snapshot ID was deleted.
    assert_ne!(new_snapshot_id, snapshot_id);
    assert!(!test.state().canister_snapshots.contains(&snapshot_id));
    assert!(test.state().canister_snapshots.contains(&new_snapshot_id));

    // Confirm that `snapshots_memory_usage` is updated correctly.
    assert_eq!(
        test.canister_state(canister_id)
            .system_state
            .snapshots_memory_usage,
        test.state()
            .canister_snapshots
            .compute_memory_usage_by_canister(canister_id),
    );
}

#[test]
fn take_canister_snapshot_fails_when_limit_is_reached() {
    const CYCLES: Cycles = Cycles::new(20_000_000_000_000);
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let max_snapshots_per_canister = 5;
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_caller(own_subnet, caller_canister)
        .with_max_snapshots_per_canister(max_snapshots_per_canister)
        .build();

    // Create canister and update controllers.
    let canister_id = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();
    let controllers = vec![caller_canister.get(), test.user_id().get()];
    test.canister_update_controller(canister_id, controllers)
        .unwrap();

    // Upload chunk.
    let chunk = vec![1, 2, 3, 4, 5];
    let upload_args = UploadChunkArgs {
        canister_id: canister_id.into(),
        chunk,
    };
    let result = test.subnet_message("upload_chunk", upload_args.encode());
    assert!(result.is_ok());

    // Take a snapshot for the canister.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
    let result = test.subnet_message("take_canister_snapshot", args.encode());
    assert!(result.is_ok());
    let response = CanisterSnapshotResponse::decode(&result.unwrap().bytes()).unwrap();
    let snapshot_id = response.snapshot_id();

    assert!(test.state().canister_snapshots.contains(&snapshot_id));
    assert!(test.state().canister_snapshots.contains(&snapshot_id));

    assert!(test.state().canister_snapshots.contains(&snapshot_id));

    let snapshot = test.state().canister_snapshots.get(snapshot_id).unwrap();
    assert_eq!(
        *snapshot.canister_module(),
        test.canister_state(canister_id)
            .execution_state
            .as_ref()
            .unwrap()
            .wasm_binary
            .binary
    );
    assert_eq!(
        *snapshot.chunk_store(),
        test.canister_state(canister_id)
            .system_state
            .wasm_chunk_store
    );

    // Take some more snapshots until just before the limit is reached. Should succeed.
    for _ in 0..(max_snapshots_per_canister - 1) {
        let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
        test.subnet_message("take_canister_snapshot", args.encode())
            .unwrap();
    }

    // Take a new snapshot for the canister without providing a replacement ID.
    // Should fail as we have already created `max_snapshots_per_canister`` above.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
    let error = test
        .subnet_message("take_canister_snapshot", args.encode())
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::CanisterRejectedMessage);
    assert_eq!(
        error.description(),
        format!(
            "Canister {} has reached the maximum number of snapshots allowed: {}.",
            canister_id, max_snapshots_per_canister,
        )
    );
}

fn grow_stable_memory(
    test: &mut ExecutionTest,
    canister_id: CanisterId,
    wasm_page_size: u64,
    num_pages: u64,
) {
    let result = test
        .ingress(
            canister_id,
            "update",
            wasm()
                .stable64_grow(num_pages)
                // Access the last byte to make sure that growing succeeded.
                .stable64_read(num_pages * wasm_page_size - 1, 1)
                .push_bytes(&[])
                .append_and_reply()
                .build(),
        )
        .unwrap();
    assert_eq!(result, WasmResult::Reply(vec![]));
}

#[test]
fn canister_request_take_canister_cycles_reserved_for_app_and_verified_app_subnets() {
    cycles_reserved_for_app_and_verified_app_subnets(|subnet_type| {
        const CYCLES: Cycles = Cycles::new(20_000_000_000_000);
        const CAPACITY: u64 = 1_000_000_000;
        const THRESHOLD: u64 = CAPACITY / 2;
        const WASM_PAGE_SIZE: u64 = 65_536;
        // 7500 of stable memory pages is close to 500MB, but still leaves some room
        // for Wasm memory of the universal canister.
        const NUM_PAGES: u64 = 7_500;

        let mut test = ExecutionTestBuilder::new()
            .with_subnet_type(subnet_type)
            .with_heap_delta_rate_limit(NumBytes::new(1_000_000_000))
            .with_subnet_execution_memory(CAPACITY as i64)
            .with_subnet_memory_reservation(0)
            .with_subnet_memory_threshold(THRESHOLD as i64)
            .build();

        // Create canister.
        let canister_id = test
            .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.to_vec())
            .unwrap();
        test.canister_update_reserved_cycles_limit(canister_id, CYCLES)
            .unwrap();

        // Increase memory usage.
        grow_stable_memory(&mut test, canister_id, WASM_PAGE_SIZE, NUM_PAGES);

        // Get the reserve balance before taking a canister snapshot.
        let reserved_cycles_before = test
            .canister_state(canister_id)
            .system_state
            .reserved_balance();
        let subnet_memory_usage_before =
            CAPACITY - test.subnet_available_memory().get_execution_memory() as u64;

        // Take a snapshot for the canister.
        let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
        test.subnet_message("take_canister_snapshot", args.encode())
            .unwrap();

        // Get the reserve balance after taking a canister snapshot.
        let reserved_cycles_after = test
            .canister_state(canister_id)
            .system_state
            .reserved_balance();
        let subnet_memory_usage_after =
            CAPACITY - test.subnet_available_memory().get_execution_memory() as u64;

        assert!(reserved_cycles_after > reserved_cycles_before);
        assert_eq!(
            reserved_cycles_after - reserved_cycles_before,
            test.cycles_account_manager().storage_reservation_cycles(
                NumBytes::from(subnet_memory_usage_after - subnet_memory_usage_before),
                &ResourceSaturation::new(subnet_memory_usage_before, THRESHOLD, CAPACITY),
                test.subnet_size(),
            )
        );
    });
}

#[test]
fn canister_snapshot_reserves_cycles_difference() {
    cycles_reserved_for_app_and_verified_app_subnets(|subnet_type| {
        const CYCLES: Cycles = Cycles::new(200_000_000_000_000);
        const CAPACITY: u64 = 2_000_000_000;
        const THRESHOLD: u64 = CAPACITY / 4;
        const WASM_PAGE_SIZE: u64 = 65_536;
        // 7500 of stable memory pages is close to 500MB, but still leaves some room
        // for Wasm memory of the universal canister.
        const NUM_PAGES: u64 = 7_500;

        let mut test = ExecutionTestBuilder::new()
            .with_subnet_type(subnet_type)
            .with_heap_delta_rate_limit(NumBytes::new(1_000_000_000))
            .with_subnet_execution_memory(CAPACITY as i64)
            .with_subnet_memory_reservation(0)
            .with_subnet_memory_threshold(THRESHOLD as i64)
            .build();

        let canister_id = test
            .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.to_vec())
            .unwrap();
        test.canister_update_reserved_cycles_limit(canister_id, CYCLES)
            .unwrap();
        grow_stable_memory(&mut test, canister_id, WASM_PAGE_SIZE, NUM_PAGES);

        // Get the reserve balance before taking a canister snapshot.
        let initial_reserved_cycles = test
            .canister_state(canister_id)
            .system_state
            .reserved_balance();
        // Make sure there are no reserved cycles.
        assert_eq!(initial_reserved_cycles, Cycles::zero());

        // Take a snapshot 1 for the canister.
        let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
        let result = test
            .subnet_message("take_canister_snapshot", args.encode())
            .unwrap();
        let snapshot_id_1 = CanisterSnapshotResponse::decode(&result.bytes())
            .unwrap()
            .snapshot_id();
        let reserved_cycles_after_snapshot_1 = test
            .canister_state(canister_id)
            .system_state
            .reserved_balance();

        // Take a snapshot 2 for the canister by replacing previous snapshot.
        let args: TakeCanisterSnapshotArgs =
            TakeCanisterSnapshotArgs::new(canister_id, Some(snapshot_id_1));
        let result = test
            .subnet_message("take_canister_snapshot", args.encode())
            .unwrap();
        let snapshot_id_2 = CanisterSnapshotResponse::decode(&result.bytes())
            .unwrap()
            .snapshot_id();
        let reserved_cycles_after_snapshot_2 = test
            .canister_state(canister_id)
            .system_state
            .reserved_balance();
        // Make sure the reserved cycles are the same.
        assert_eq!(
            reserved_cycles_after_snapshot_1,
            reserved_cycles_after_snapshot_2
        );

        // Delete the Snapshot.
        let args: DeleteCanisterSnapshotArgs =
            DeleteCanisterSnapshotArgs::new(canister_id, snapshot_id_2);
        test.subnet_message("delete_canister_snapshot", args.encode())
            .unwrap();
        let reserved_cycles_after_delete = test
            .canister_state(canister_id)
            .system_state
            .reserved_balance();
        // Make sure the reserved cycles are the same.
        assert_eq!(
            reserved_cycles_after_snapshot_2,
            reserved_cycles_after_delete
        );

        // Take a new snapshot 3 for the canister.
        let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
        test.subnet_message("take_canister_snapshot", args.encode())
            .unwrap();
        let reserved_cycles_after_a_new_snapshot = test
            .canister_state(canister_id)
            .system_state
            .reserved_balance();
        // Make sure the reserved cycles are increased even more than before.
        assert!(
            reserved_cycles_after_a_new_snapshot
                > reserved_cycles_after_snapshot_1 + reserved_cycles_after_snapshot_1
                    - reserved_cycles_after_snapshot_2
        );
    });
}

#[test]
fn take_canister_snapshot_fails_subnet_memory_exceeded() {
    const CYCLES: Cycles = Cycles::new(20_000_000_000_000);
    const CAPACITY: u64 = 500_000_000;
    const THRESHOLD: u64 = CAPACITY / 2;
    const WASM_PAGE_SIZE: u64 = 65_536;
    const NUM_PAGES: u64 = 2_400;

    let mut test = ExecutionTestBuilder::new()
        .with_heap_delta_rate_limit(NumBytes::new(1_000_000_000))
        .with_subnet_execution_memory(CAPACITY as i64)
        .with_subnet_memory_reservation(0)
        .with_subnet_memory_threshold(THRESHOLD as i64)
        .build();

    let mut canisters = vec![];
    for _ in 0..2 {
        // Create canister.
        let canister_id = test
            .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.to_vec())
            .unwrap();
        test.canister_update_reserved_cycles_limit(canister_id, CYCLES)
            .unwrap();

        // Increase memory usage.
        grow_stable_memory(&mut test, canister_id, WASM_PAGE_SIZE, NUM_PAGES);
        canisters.push(canister_id);
    }

    // Take a snapshot of first canister.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canisters[0], None);
    test.subnet_message("take_canister_snapshot", args.encode())
        .unwrap();

    // Taking a snapshot of second canister.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canisters[1], None);
    let result = test.subnet_message("take_canister_snapshot", args.encode());
    assert!(result.is_err());
    if let Err(err) = result {
        assert_eq!(err.code(), ErrorCode::SubnetOversubscribed);
    }
}

#[test]
fn take_canister_snapshot_works_when_enough_subnet_memory_after_replacing_old_snapshot() {
    const CYCLES: Cycles = Cycles::new(20_000_000_000_000);
    const CAPACITY: u64 = 500 * 1024 * 1024; // 500 MiB
    const THRESHOLD: u64 = CAPACITY / 2;

    let mut test = ExecutionTestBuilder::new()
        .with_heap_delta_rate_limit(NumBytes::new(1_000_000_000))
        .with_subnet_execution_memory(CAPACITY as i64)
        .with_subnet_memory_reservation(0)
        .with_subnet_memory_threshold(THRESHOLD as i64)
        .build();

    let mut canisters = vec![];
    // Create 2 canisters that use 100MiB of memory. This should allow for having 2 snapshots of them as
    // well with 500MiB capacity but not for a third one (unless it replaces one of the previous ones).
    for _ in 0..2 {
        // Create canister.
        let canister_id = test
            .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.to_vec())
            .unwrap();
        test.canister_update_reserved_cycles_limit(canister_id, CYCLES)
            .unwrap();

        // Grow the canister's memory before taking a snapshot.
        test.ingress(
            canister_id,
            "update",
            wasm()
                .memory_size_is_at_least(100 * 1024 * 1024) // 100 MiB
                .reply_data(&[42])
                .build(),
        )
        .unwrap();
        canisters.push(canister_id);
    }

    // Take a snapshot of first canister.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canisters[0], None);
    let result = test
        .subnet_message("take_canister_snapshot", args.encode())
        .unwrap();
    let snapshot_id = CanisterSnapshotResponse::decode(&result.bytes())
        .unwrap()
        .snapshot_id();

    // Taking a snapshot of second canister.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canisters[1], None);
    test.subnet_message("take_canister_snapshot", args.encode())
        .unwrap();

    // Grow the first canister's memory before taking another snapshot.
    test.ingress(
        canisters[0],
        "update",
        wasm()
            .memory_size_is_at_least(120 * 1024 * 1024) // 120 MiB
            .reply_data(&[42])
            .build(),
    )
    .unwrap();

    // Taking another snapshot of the first canister while replacing the old one
    // should work.
    let args: TakeCanisterSnapshotArgs =
        TakeCanisterSnapshotArgs::new(canisters[0], Some(snapshot_id));
    test.subnet_message("take_canister_snapshot", args.encode())
        .unwrap();
}

#[test]
fn take_canister_snapshot_does_not_reduce_subnet_available_memory_when_failing_to_create_snapshot()
{
    const CYCLES: Cycles = Cycles::new(20_000_000_000_000);
    const CAPACITY: u64 = 500 * 1024 * 1024; // 500 MiB
    const THRESHOLD: u64 = CAPACITY / 2;

    let mut test = ExecutionTestBuilder::new()
        .with_heap_delta_rate_limit(NumBytes::new(1_000_000_000))
        .with_subnet_execution_memory(CAPACITY as i64)
        .with_subnet_memory_reservation(0)
        .with_subnet_memory_threshold(THRESHOLD as i64)
        .build();

    let canister_id = test.create_canister(CYCLES);

    let subnet_available_memory_before_taking_snapshot =
        test.subnet_available_memory().get_execution_memory();

    // Take a snapshot of the canister, should fail because the canister is empty.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
    let result = test.subnet_message("take_canister_snapshot", args.encode());
    assert_eq!(
        result.unwrap_err().code(),
        ErrorCode::CanisterRejectedMessage
    );

    let subnet_available_memory_after_taking_snapshot =
        test.subnet_available_memory().get_execution_memory();

    // Since the snapshot was not created, the subnet available memory should not have changed.
    assert_eq!(
        subnet_available_memory_before_taking_snapshot,
        subnet_available_memory_after_taking_snapshot
    );
}

#[test]
fn take_canister_snapshot_increases_heap_delta() {
    const CYCLES: Cycles = Cycles::new(20_000_000_000_000);
    const CAPACITY: u64 = 1_000_000_000;
    const THRESHOLD: u64 = CAPACITY / 2;

    const WASM_PAGE_SIZE: u64 = 65_536;
    // 7500 of stable memory pages is close to 500MB, but still leaves some room
    // for Wasm memory of the universal canister.
    const NUM_PAGES: u64 = 7_500;

    let mut test = ExecutionTestBuilder::new()
        .with_subnet_execution_memory(CAPACITY as i64)
        .with_subnet_memory_reservation(0)
        .with_subnet_memory_threshold(THRESHOLD as i64)
        .build();

    // Create canister.
    let canister_id = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();
    test.canister_update_reserved_cycles_limit(canister_id, CYCLES)
        .unwrap();

    // Increase memory usage.
    grow_stable_memory(&mut test, canister_id, WASM_PAGE_SIZE, NUM_PAGES);
    let heap_delta_before = test.state().metadata.heap_delta_estimate;

    // Take a snapshot of the canister.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
    test.subnet_message("take_canister_snapshot", args.encode())
        .unwrap();

    let heap_delta_after = test.state().metadata.heap_delta_estimate;

    assert!(heap_delta_after > heap_delta_before);
}

#[test]
fn take_canister_snapshot_fails_when_heap_delta_rate_limited() {
    const CYCLES: Cycles = Cycles::new(20_000_000_000_000);
    const CAPACITY: u64 = 500_000_000;
    const THRESHOLD: u64 = CAPACITY / 2;
    const WASM_PAGE_SIZE: u64 = 65_536;
    const NUM_PAGES: u64 = 2_400;

    let mut test = ExecutionTestBuilder::new()
        .with_heap_delta_rate_limit(NumBytes::new(80_000))
        .with_subnet_execution_memory(CAPACITY as i64)
        .with_subnet_memory_reservation(0)
        .with_subnet_memory_threshold(THRESHOLD as i64)
        .build();

    let initial_heap_delta_estimate = test.state().metadata.heap_delta_estimate;

    // Create canister.
    let canister_id = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();
    test.canister_update_reserved_cycles_limit(canister_id, CYCLES)
        .unwrap();

    // Increase memory usage.
    grow_stable_memory(&mut test, canister_id, WASM_PAGE_SIZE, NUM_PAGES);

    // Take a snapshot of the canister.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
    let result = test.subnet_message("take_canister_snapshot", args.encode());
    let snapshot_id = CanisterSnapshotResponse::decode(&result.unwrap().bytes())
        .unwrap()
        .snapshot_id();
    let heap_delta_estimate_after_taking_snapshot = test.state().metadata.heap_delta_estimate;
    assert_gt!(
        heap_delta_estimate_after_taking_snapshot,
        initial_heap_delta_estimate,
        "Expected the heap delta estimate to increase after taking a snapshot"
    );
    let initial_subnet_available_memory = test.subnet_available_memory();

    // Taking another snapshot.
    let args: TakeCanisterSnapshotArgs =
        TakeCanisterSnapshotArgs::new(canister_id, Some(snapshot_id));
    let error = test
        .subnet_message("take_canister_snapshot", args.encode())
        .unwrap_err();

    assert_eq!(error.code(), ErrorCode::CanisterHeapDeltaRateLimited);
    let message = format!("Canister {} is heap delta rate limited", canister_id).to_string();
    assert!(error.description().contains(&message));
    assert_eq!(
        test.subnet_available_memory(),
        initial_subnet_available_memory
    );

    let heap_delta_estimate_after_taking_snapshot_again = test.state().metadata.heap_delta_estimate;
    assert_eq!(
        heap_delta_estimate_after_taking_snapshot_again, heap_delta_estimate_after_taking_snapshot,
        "Expected the heap delta estimate to remain the same after failing to take snapshot"
    );
}

#[test]
fn take_canister_snapshot_fails_when_canister_would_be_frozen() {
    const CYCLES: Cycles = Cycles::new(1_000_000_000_000);
    const CAPACITY: u64 = 500_000_000;
    const THRESHOLD: u64 = CAPACITY / 2;
    const WASM_PAGE_SIZE: u64 = 65_536;
    const NUM_PAGES: u64 = 2_400;

    let mut test = ExecutionTestBuilder::new()
        .with_heap_delta_rate_limit(NumBytes::new(1_000_000))
        .with_subnet_execution_memory(CAPACITY as i64)
        .with_subnet_memory_reservation(0)
        .with_subnet_memory_threshold(THRESHOLD as i64)
        .build();

    // Create canister.
    let canister_id = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();
    test.canister_update_reserved_cycles_limit(canister_id, CYCLES)
        .unwrap();

    // Increase memory usage.
    grow_stable_memory(&mut test, canister_id, WASM_PAGE_SIZE, NUM_PAGES);

    // Make balance just a bit higher than freezing threshold, so `take_canister_snapshot` fails.
    let threshold = test.freezing_threshold(canister_id);
    let new_balance = threshold + Cycles::from(1_000_u128);
    let to_remove = test.canister_state(canister_id).system_state.balance() - new_balance;
    test.canister_state_mut(canister_id)
        .system_state
        .remove_cycles(to_remove, CyclesUseCase::BurnedCycles);

    let initial_subnet_available_memory = test.subnet_available_memory();

    // Taking a snapshot of the canister will decrease the balance.
    // Increase the canister balance to be able to take a new snapshot.
    let scheduler_config = SubnetConfig::new(SubnetType::Application).scheduler_config;
    let canister_snapshot_size = test.canister_state(canister_id).snapshot_size_bytes();
    let instructions = scheduler_config.canister_snapshot_baseline_instructions
        + NumInstructions::new(canister_snapshot_size.get());
    let expected_charge = test.cycles_account_manager().execution_cost(
        instructions,
        test.subnet_size(),
        WASM_EXECUTION_MODE,
    );
    test.canister_state_mut(canister_id)
        .system_state
        .add_cycles(expected_charge, CyclesUseCase::NonConsumed);

    // Take a snapshot of the canister.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
    let error = test
        .subnet_message("take_canister_snapshot", args.encode())
        .unwrap_err();

    assert_eq!(error.code(), ErrorCode::InsufficientCyclesInMemoryGrow);
    assert!(
        error
            .description()
            .contains("additional cycles are required"),
        "Unexpected error: {}",
        error.description()
    );
    assert_eq!(
        test.subnet_available_memory(),
        initial_subnet_available_memory
    );
}

#[test]
fn chunk_size_multiple_of_os_page_size() {
    assert!(CHUNK_SIZE % PAGE_SIZE as u64 == 0);
}

#[test]
fn take_snapshot_with_maximal_chunk_store() {
    let mut test = ExecutionTestBuilder::new()
        .with_snapshot_metadata_download()
        .with_heap_delta_rate_limit(u64::MAX.into())
        .build();

    // Create new canister.
    let canister_id = test
        .canister_from_cycles_and_binary(
            Cycles::new(1_000_000_000_000_000),
            UNIVERSAL_CANISTER_WASM.to_vec(),
        )
        .unwrap();

    let mut chunk_hashes = vec![];
    // The chunk store may have no more than 100 entries.
    // If this test fails, the wasm chunk store size or the
    // max number of stored chunks may have changed.
    for i in 0..100u32 {
        let chunk = i.to_be_bytes().to_vec();
        let upload_args = UploadChunkArgs {
            canister_id: canister_id.into(),
            chunk,
        };
        let WasmResult::Reply(bytes) = test
            .subnet_message("upload_chunk", upload_args.encode())
            .unwrap()
        else {
            panic!("Expected Reply")
        };
        let hash = Decode!(&bytes, ChunkHash).unwrap();
        chunk_hashes.push(hash.hash);
    }
    // this one should fail
    let chunk = vec![42; 42];
    let upload_args = UploadChunkArgs {
        canister_id: canister_id.into(),
        chunk,
    };
    test.subnet_message("upload_chunk", upload_args.encode())
        .unwrap_err();

    // Take a snapshot of the canister.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
    let result = test.subnet_message("take_canister_snapshot", args.encode());
    let snapshot_id = CanisterSnapshotResponse::decode(&result.unwrap().bytes())
        .unwrap()
        .snapshot_id();

    let args = ReadCanisterSnapshotMetadataArgs::new(canister_id, snapshot_id);
    let WasmResult::Reply(bytes) = test
        .subnet_message("read_canister_snapshot_metadata", args.encode())
        .unwrap()
    else {
        panic!("expected WasmResult::Reply")
    };
    let metadata = Decode!(&bytes, ReadCanisterSnapshotMetadataResponse).unwrap();
    let mut returned_chunk_hashes = metadata.wasm_chunk_store;
    returned_chunk_hashes.sort();
    let returned_chunk_hashes = returned_chunk_hashes
        .iter()
        .map(|x| x.hash.clone())
        .collect::<Vec<Vec<u8>>>();
    chunk_hashes.sort();
    assert_eq!(returned_chunk_hashes, chunk_hashes);
}

#[test]
fn test_delete_canister_snapshot_decode_round_trip() {
    let canister_id = canister_test_id(4);
    let snapshot_id = SnapshotId::from((canister_id, 6));
    let args = ic00::DeleteCanisterSnapshotArgs::new(canister_id, snapshot_id);
    let encoded_args = args.encode();
    assert_eq!(
        args,
        DeleteCanisterSnapshotArgs::decode(encoded_args.as_slice()).unwrap()
    );
}

#[test]
fn delete_canister_snapshot_fails_canister_not_found() {
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_caller(own_subnet, caller_canister)
        .build();

    let canister_id = canister_test_id(10);
    let snapshot_id = SnapshotId::from((canister_id, 3));
    let args: DeleteCanisterSnapshotArgs =
        DeleteCanisterSnapshotArgs::new(canister_id, snapshot_id);
    let error = test
        .subnet_message("delete_canister_snapshot", args.encode())
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::CanisterNotFound);
    let message = format!("Canister {} not found.", canister_id,).to_string();
    assert!(error.description().contains(&message));
}

#[test]
fn delete_canister_snapshot_fails_snapshot_not_found() {
    const CYCLES: Cycles = Cycles::new(1_000_000_000_000);
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_caller(own_subnet, caller_canister)
        .build();

    // Create canister.
    let canister_id = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();

    // Delete canister snapshot fails because snapshot does not exist.
    let snapshot_id = SnapshotId::from((canister_id, 3));
    let args: DeleteCanisterSnapshotArgs =
        DeleteCanisterSnapshotArgs::new(canister_id, snapshot_id);
    let error = test
        .subnet_message("delete_canister_snapshot", args.encode())
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::CanisterSnapshotNotFound);
    let message = format!(
        "Could not find the snapshot ID {} for canister {}",
        snapshot_id, canister_id,
    )
    .to_string();
    assert!(error.description().contains(&message));
    assert!(test.state().canister_state(&canister_id).is_some());
}

#[test]
fn delete_canister_snapshot_fails_snapshot_does_not_belong_to_canister() {
    const CYCLES: Cycles = Cycles::new(1_000_000_000_000);
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_caller(own_subnet, caller_canister)
        .build();

    // Create canister.
    let canister_id_1 = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();
    let canister_id_2 = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();

    // Take a snapshot.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id_1, None);
    let result = test.subnet_message("take_canister_snapshot", args.encode());
    assert!(result.is_ok());
    let response = CanisterSnapshotResponse::decode(&result.unwrap().bytes()).unwrap();
    let snapshot_id = response.snapshot_id();
    assert!(test.state().canister_snapshots.get(snapshot_id).is_some());

    let initial_canister_state = test.state().canister_state(&canister_id_2).unwrap().clone();

    // Delete canister snapshot fails because snapshot does not belong to `canister_id_2`.
    let args: DeleteCanisterSnapshotArgs =
        DeleteCanisterSnapshotArgs::new(canister_id_2, snapshot_id);
    let error = test
        .subnet_message("delete_canister_snapshot", args.encode())
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::CanisterRejectedMessage);
    let message = format!(
        "The snapshot {} does not belong to canister {}",
        snapshot_id, canister_id_2,
    )
    .to_string();
    assert!(error.description().contains(&message));
    assert!(test.state().canister_state(&canister_id_2).is_some());
    assert_eq!(
        initial_canister_state,
        test.state().canister_state(&canister_id_2).unwrap().clone()
    );
}

#[test]
fn delete_canister_snapshot_succeeds() {
    const CYCLES: Cycles = Cycles::new(1_000_000_000_000);
    const CAPACITY: u64 = 1_000_000_000_000;
    const THRESHOLD: u64 = CAPACITY / 2;

    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_subnet_execution_memory(CAPACITY as i64)
        .with_subnet_memory_reservation(0)
        .with_subnet_memory_threshold(THRESHOLD as i64)
        .with_caller(own_subnet, caller_canister)
        .build();

    // Create canister.
    let canister_id = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();

    // Take a snapshot.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
    let result = test.subnet_message("take_canister_snapshot", args.encode());
    assert!(result.is_ok());
    let response = CanisterSnapshotResponse::decode(&result.unwrap().bytes()).unwrap();
    let snapshot_id = response.snapshot_id();
    assert!(test.state().canister_snapshots.get(snapshot_id).is_some());
    let subnet_available_memory_after_taking_snapshot =
        test.subnet_available_memory().get_execution_memory() as u64;

    // Confirm that `snapshots_memory_usage` is updated correctly.
    assert_eq!(
        test.canister_state(canister_id)
            .system_state
            .snapshots_memory_usage,
        test.state()
            .canister_snapshots
            .compute_memory_usage_by_canister(canister_id),
    );

    // Deletes canister snapshot successfully.
    let args: DeleteCanisterSnapshotArgs =
        DeleteCanisterSnapshotArgs::new(canister_id, snapshot_id);
    let result = test.subnet_message("delete_canister_snapshot", args.encode());
    let subnet_available_memory_after_deleting_snapshot =
        test.subnet_available_memory().get_execution_memory() as u64;

    assert!(result.is_ok());
    assert!(test.state().canister_snapshots.get(snapshot_id).is_none());
    assert!(test.state().canister_state(&canister_id).is_some());

    assert_eq!(
        test.canister_state(canister_id)
            .system_state
            .snapshots_memory_usage,
        test.state()
            .canister_snapshots
            .compute_memory_usage_by_canister(canister_id),
    );

    assert_gt!(
        subnet_available_memory_after_deleting_snapshot,
        subnet_available_memory_after_taking_snapshot,
        "Expected subnet available memory to increase after deleting a snapshot"
    );
}

#[test]
fn list_canister_snapshot_fails_canister_not_found() {
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_caller(own_subnet, caller_canister)
        .build();

    let canister_id = canister_test_id(10);
    let args: ListCanisterSnapshotArgs = ListCanisterSnapshotArgs::new(canister_id);
    let error = test
        .subnet_message("list_canister_snapshots", args.encode())
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::CanisterNotFound);
    let message = format!("Canister {} not found.", canister_id,).to_string();
    assert!(error.description().contains(&message));
}

#[test]
fn list_canister_snapshot_fails_invalid_controller() {
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_manual_execution()
        .with_caller(own_subnet, caller_canister)
        .build();

    // Create new canister.
    let canister_id = test
        .create_canister_with_allocation(Cycles::new(1_000_000_000_000_000), None, None)
        .unwrap();

    let prev_canister_state = test.state().canister_state(&canister_id).unwrap().clone();

    // Create `ListCanisterSnapshot` request.
    let args: ListCanisterSnapshotArgs = ListCanisterSnapshotArgs::new(canister_id);
    test.inject_call_to_ic00(
        Method::ListCanisterSnapshots,
        args.encode(),
        Cycles::new(1_000_000_000),
    );
    test.execute_subnet_message();

    // Reject expected: caller is not a controller of the canister.
    let (receiver, response) = &get_output_messages(test.state_mut()).pop().unwrap();
    assert_matches!(response, RequestOrResponse::Response(_));
    if let RequestOrResponse::Response(res) = response {
        assert_eq!(res.originator, *receiver);
        res.response_payload.assert_contains_reject(
            RejectCode::CanisterError,
            &format!(
                "Only the controllers of the canister {} can control it.\n\
                    Canister's controllers: {}\n\
                    Sender's ID: {}",
                canister_id,
                test.user_id().get(),
                caller_canister.get(),
            ),
        );
    }

    // Verify the canister exists in the `ReplicatedState` and is unchanged.
    assert_eq!(
        *test.state().canister_state(&canister_id).unwrap(),
        prev_canister_state
    );
}

#[test]
fn list_canister_snapshot_succeeds() {
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_caller(own_subnet, caller_canister)
        .build();

    // Create new canister.
    let canister_id = test
        .canister_from_cycles_and_binary(
            Cycles::new(1_000_000_000_000_000),
            UNIVERSAL_CANISTER_WASM.to_vec(),
        )
        .unwrap();

    // Take a snapshot of the canister.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
    let result = test.subnet_message("take_canister_snapshot", args.encode());
    let snapshot_id = CanisterSnapshotResponse::decode(&result.unwrap().bytes())
        .unwrap()
        .snapshot_id();

    // Get the canister snapshot list.
    let args: ListCanisterSnapshotArgs = ListCanisterSnapshotArgs::new(canister_id);
    let result = test
        .subnet_message("list_canister_snapshots", args.encode())
        .unwrap();
    if let WasmResult::Reply(data) = result {
        let snapshots = Decode!(&data, Vec<CanisterSnapshotResponse>).unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].snapshot_id(), snapshot_id);
    }
}

#[test]
fn load_canister_snapshot_decode_round_trip() {
    let canister_id = canister_test_id(4);
    let snapshot_id = SnapshotId::from((canister_id, 6));
    let args = ic00::LoadCanisterSnapshotArgs::new(canister_test_id(4), snapshot_id, Some(5u64));
    let encoded_args = args.encode();
    assert_eq!(
        args,
        LoadCanisterSnapshotArgs::decode(encoded_args.as_slice()).unwrap()
    );
}

#[test]
fn load_canister_snapshot_fails_canister_not_found() {
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_caller(own_subnet, caller_canister)
        .build();

    let canister_id = canister_test_id(10);
    let snapshot_id = SnapshotId::from((canister_id, 6));
    let args: LoadCanisterSnapshotArgs =
        LoadCanisterSnapshotArgs::new(canister_id, snapshot_id, None);
    let error = test
        .subnet_message("load_canister_snapshot", args.encode())
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::CanisterNotFound);
    let message = format!("Canister {} not found.", canister_id,).to_string();
    assert!(error.description().contains(&message));
}

#[test]
fn load_canister_snapshot_fails_invalid_controller() {
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_manual_execution()
        .with_caller(own_subnet, caller_canister)
        .build();

    // Create new canister.
    let canister_id = test
        .create_canister_with_allocation(Cycles::new(1_000_000_000_000_000), None, None)
        .unwrap();
    let snapshot_id = SnapshotId::from((canister_id, 6));

    let prev_canister_state = test.state().canister_state(&canister_id).unwrap().clone();

    // Create `LoadCanisterSnapshot` request.
    let args: LoadCanisterSnapshotArgs =
        LoadCanisterSnapshotArgs::new(canister_id, snapshot_id, None);
    test.inject_call_to_ic00(
        Method::LoadCanisterSnapshot,
        args.encode(),
        Cycles::new(1_000_000_000),
    );
    test.execute_subnet_message();

    // Reject expected: caller is not a controller of the canister.
    let (receiver, response) = &get_output_messages(test.state_mut()).pop().unwrap();
    assert_matches!(response, RequestOrResponse::Response(_));
    if let RequestOrResponse::Response(res) = response {
        assert_eq!(res.originator, *receiver);
        res.response_payload.assert_contains_reject(
            RejectCode::CanisterError,
            &format!(
                "Only the controllers of the canister {} can control it.\n\
                    Canister's controllers: {}\n\
                    Sender's ID: {}",
                canister_id,
                test.user_id().get(),
                caller_canister.get(),
            ),
        );
    }

    // Verify the canister exists in the `ReplicatedState` and is unchanged.
    assert_eq!(
        *test.state().canister_state(&canister_id).unwrap(),
        prev_canister_state
    );
}

#[test]
fn load_canister_snapshot_fails_snapshot_not_found() {
    const CYCLES: Cycles = Cycles::new(1_000_000_000_000);
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_caller(own_subnet, caller_canister)
        .build();

    // Create canister.
    let canister_id = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();

    // Load canister snapshot fails because snapshot does not exist.
    let snapshot_id = SnapshotId::from((canister_id, 3));
    let args: LoadCanisterSnapshotArgs =
        LoadCanisterSnapshotArgs::new(canister_id, snapshot_id, None);
    let error = test
        .subnet_message("load_canister_snapshot", args.encode())
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::CanisterSnapshotNotFound);
    let message = format!(
        "Could not find the snapshot ID {} for canister {}",
        snapshot_id, canister_id,
    )
    .to_string();
    assert!(error.description().contains(&message));
    assert!(test.state().canister_state(&canister_id).is_some());
}

#[test]
fn load_canister_snapshot_fails_snapshot_does_not_belong_to_canister() {
    const CYCLES: Cycles = Cycles::new(1_000_000_000_000);
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_caller(own_subnet, caller_canister)
        .build();

    // Create canister.
    let canister_id_1 = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();
    let canister_id_2 = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();

    // Take a snapshot.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id_1, None);
    let result = test.subnet_message("take_canister_snapshot", args.encode());
    assert!(result.is_ok());
    let response = CanisterSnapshotResponse::decode(&result.unwrap().bytes()).unwrap();
    let snapshot_id = response.snapshot_id();
    assert!(test.state().canister_snapshots.get(snapshot_id).is_some());

    let initial_canister_state = test.state().canister_state(&canister_id_2).unwrap().clone();

    // Loading a canister snapshot fails because snapshot does not belong to `canister_id_2`.
    let args: LoadCanisterSnapshotArgs =
        LoadCanisterSnapshotArgs::new(canister_id_2, snapshot_id, None);
    let error = test
        .subnet_message("load_canister_snapshot", args.encode())
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::CanisterRejectedMessage);
    let message = format!(
        "The snapshot {} does not belong to canister {}",
        snapshot_id, canister_id_2,
    )
    .to_string();
    assert!(error.description().contains(&message));
    assert!(test.state().canister_state(&canister_id_2).is_some());
    assert_eq!(
        initial_canister_state,
        test.state().canister_state(&canister_id_2).unwrap().clone()
    );
}

#[test]
fn load_canister_snapshot_fails_when_heap_delta_rate_limited() {
    const CYCLES: Cycles = Cycles::new(20_000_000_000_000);
    const CAPACITY: u64 = 500_000_000;
    const THRESHOLD: u64 = CAPACITY / 2;
    const WASM_PAGE_SIZE: u64 = 65_536;
    const NUM_PAGES: u64 = 2_400;

    let mut test = ExecutionTestBuilder::new()
        .with_heap_delta_rate_limit(NumBytes::new(150_000))
        .with_subnet_execution_memory(CAPACITY as i64)
        .with_subnet_memory_reservation(0)
        .with_subnet_memory_threshold(THRESHOLD as i64)
        .build();

    let initial_heap_delta_estimate = test.state().metadata.heap_delta_estimate;

    // Create canister.
    let canister_id = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();
    test.canister_update_reserved_cycles_limit(canister_id, CYCLES)
        .unwrap();

    // Increase memory usage.
    grow_stable_memory(&mut test, canister_id, WASM_PAGE_SIZE, NUM_PAGES);

    // Take a snapshot of the canister.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
    let result = test.subnet_message("take_canister_snapshot", args.encode());
    let snapshot_id = CanisterSnapshotResponse::decode(&result.unwrap().bytes())
        .unwrap()
        .snapshot_id();

    let heap_delta_estimate_after_taking_snapshot = test.state().metadata.heap_delta_estimate;

    assert_gt!(
        heap_delta_estimate_after_taking_snapshot,
        initial_heap_delta_estimate,
        "Expected the heap delta estimate to increase after taking a snapshot"
    );

    // Load canister snapshot back into the canister. This should succeed as there's
    // still enough heap delta available.
    let args: LoadCanisterSnapshotArgs =
        LoadCanisterSnapshotArgs::new(canister_id, snapshot_id, None);
    let result = test.subnet_message("load_canister_snapshot", args.encode());
    assert!(result.is_ok());

    let heap_delta_estimate_after_loading_snapshot = test.state().metadata.heap_delta_estimate;

    assert_gt!(
        heap_delta_estimate_after_loading_snapshot,
        heap_delta_estimate_after_taking_snapshot,
        "Expected the heap delta estimate to increase after loading a snapshot"
    );

    // Load the same snapshot again. This should fail as the canister is heap delta rate limited.
    let args: LoadCanisterSnapshotArgs =
        LoadCanisterSnapshotArgs::new(canister_id, snapshot_id, None);
    let error = test
        .subnet_message("load_canister_snapshot", args.encode())
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::CanisterHeapDeltaRateLimited);
    let message = format!("Canister {} is heap delta rate limited", canister_id).to_string();
    assert!(error.description().contains(&message));

    let heap_delta_estimate_after_loading_snapshot_again =
        test.state().metadata.heap_delta_estimate;
    assert_eq!(
        heap_delta_estimate_after_loading_snapshot_again,
        heap_delta_estimate_after_loading_snapshot,
        "Expected the heap delta estimate to remain the same after failing to load snapshot"
    );
}

#[test]
fn load_canister_snapshot_succeeds() {
    const CYCLES: Cycles = Cycles::new(1_000_000_000_000);
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_caller(own_subnet, caller_canister)
        .build();

    let canister_id = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();

    // Upload chunk.
    let chunk = vec![1, 2, 3, 4, 5];
    let upload_args = UploadChunkArgs {
        canister_id: canister_id.into(),
        chunk,
    };
    let result = test.subnet_message("upload_chunk", upload_args.encode());
    assert!(result.is_ok());

    // Take a snapshot.
    let (snapshot_id, snapshot_taken_at_timestamp) = helper_take_snapshot(&mut test, canister_id);

    let canister_version_before = test
        .state()
        .canister_state(&canister_id)
        .unwrap()
        .system_state
        .canister_version;
    assert_eq!(canister_version_before, 1u64);

    let canister_history = test
        .state()
        .canister_state(&canister_id)
        .unwrap()
        .system_state
        .get_canister_history()
        .clone();
    let history_before = canister_history
        .get_changes(canister_history.get_total_num_changes() as usize)
        .map(|c| (**c).clone())
        .collect::<Vec<CanisterChange>>();

    // Clear chunk after taking the snapshot.
    let clear_args = ClearChunkStoreArgs {
        canister_id: canister_id.into(),
    };
    let result = test.subnet_message("clear_chunk_store", clear_args.encode());
    assert!(result.is_ok());
    // Verify chunk store contains no data.
    assert!(test
        .state()
        .canister_state(&canister_id)
        .unwrap()
        .system_state
        .wasm_chunk_store
        .keys()
        .next()
        .is_none());

    // Load an existing snapshot.
    helper_load_snapshot(&mut test, canister_id, snapshot_id);

    // Verify chunk store contains data.
    assert!(test
        .state()
        .canister_state(&canister_id)
        .unwrap()
        .system_state
        .wasm_chunk_store
        .keys()
        .next()
        .is_some());

    // Checks after state changed through loading.
    let canister_version_after = test
        .state()
        .canister_state(&canister_id)
        .unwrap()
        .system_state
        .canister_version;
    // Canister version should be bumped after loading a snapshot.
    assert!(canister_version_after > canister_version_before);
    assert_eq!(canister_version_after, 2u64);

    // Entry in canister history should contain the information of
    // the snapshot that was loaded back into the canister.
    let canister_history = test
        .state()
        .canister_state(&canister_id)
        .unwrap()
        .system_state
        .get_canister_history()
        .clone();
    let history_after = canister_history
        .get_changes(canister_history.get_total_num_changes() as usize)
        .map(|c| (**c).clone())
        .collect::<Vec<CanisterChange>>();
    assert_ne!(history_before, history_after);
    let last_canister_change: &CanisterChange = history_after.last().unwrap();
    assert_eq!(
        *last_canister_change.details(),
        CanisterChangeDetails::load_snapshot(
            canister_version_before,
            snapshot_id.to_vec(),
            snapshot_taken_at_timestamp
        )
    );
    let unflushed_changes = test.state_mut().metadata.unflushed_checkpoint_ops.take();
    assert_eq!(unflushed_changes.len(), 2);
    let expected_unflushed_changes = vec![
        UnflushedCheckpointOp::TakeSnapshot(canister_id, snapshot_id),
        UnflushedCheckpointOp::LoadSnapshot(canister_id, snapshot_id),
    ];
    assert_eq!(expected_unflushed_changes, unflushed_changes);
}

fn helper_take_snapshot(test: &mut ExecutionTest, canister_id: CanisterId) -> (SnapshotId, u64) {
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
    let result = test.subnet_message("take_canister_snapshot", args.encode());
    assert!(result.is_ok());
    let response = CanisterSnapshotResponse::decode(&result.unwrap().bytes()).unwrap();
    let snapshot_id = response.snapshot_id();
    let snapshot_taken_at_timestamp = response.taken_at_timestamp();
    assert!(test.state().canister_snapshots.get(snapshot_id).is_some());

    (snapshot_id, snapshot_taken_at_timestamp)
}

fn helper_load_snapshot(
    test: &mut ExecutionTest,
    canister_id: CanisterId,
    snapshot_id: SnapshotId,
) {
    let args: LoadCanisterSnapshotArgs =
        LoadCanisterSnapshotArgs::new(canister_id, snapshot_id, None);
    let result = test.subnet_message("load_canister_snapshot", args.encode());
    assert!(result.is_ok());
}

fn helper_delete_snapshot(
    test: &mut ExecutionTest,
    canister_id: CanisterId,
    snapshot_id: SnapshotId,
) {
    let args: DeleteCanisterSnapshotArgs =
        DeleteCanisterSnapshotArgs::new(canister_id, snapshot_id);
    test.subnet_message("delete_canister_snapshot", args.encode())
        .unwrap();
}

#[test]
fn take_and_delete_canister_snapshot_updates_hook_condition() {
    const CYCLES: Cycles = Cycles::new(1_000_000_000_000);
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_caller(own_subnet, caller_canister)
        .build();

    let canister_id = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();

    test.subnet_message(
        Method::UpdateSettings,
        UpdateSettingsArgs {
            canister_id: canister_id.get(),
            settings: CanisterSettingsArgsBuilder::new()
                .with_wasm_memory_limit(100_000_000)
                .with_memory_allocation(9_000_000)
                .with_wasm_memory_threshold(4_000_000)
                .build(),
            sender_canister_version: None,
        }
        .encode(),
    )
    .unwrap();

    assert_eq!(
        test.canister_state_mut(canister_id)
            .system_state
            .task_queue
            .peek_hook_status(),
        OnLowWasmMemoryHookStatus::ConditionNotSatisfied
    );

    // Take a snapshot.
    let (snapshot_id, _) = helper_take_snapshot(&mut test, canister_id);

    assert_eq!(
        test.canister_state_mut(canister_id)
            .system_state
            .task_queue
            .peek_hook_status(),
        OnLowWasmMemoryHookStatus::Ready
    );

    // Delete a snapshot.
    helper_delete_snapshot(&mut test, canister_id, snapshot_id);

    assert_eq!(
        test.canister_state_mut(canister_id)
            .system_state
            .task_queue
            .peek_hook_status(),
        OnLowWasmMemoryHookStatus::ConditionNotSatisfied
    );
}

#[test]
fn load_canister_snapshot_updates_hook_condition() {
    const CYCLES: Cycles = Cycles::new(1_000_000_000_000);
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_caller(own_subnet, caller_canister)
        .build();

    let canister_id = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();

    test.subnet_message(
        Method::UpdateSettings,
        UpdateSettingsArgs {
            canister_id: canister_id.get(),
            settings: CanisterSettingsArgsBuilder::new()
                .with_wasm_memory_limit(100_000_000)
                .with_memory_allocation(10_000_000)
                .with_wasm_memory_threshold(5_000_000)
                .build(),
            sender_canister_version: None,
        }
        .encode(),
    )
    .unwrap();

    // Take a snapshot.
    let (snapshot_id, _) = helper_take_snapshot(&mut test, canister_id);

    // Upgrade canister with empty Wasm.
    let empty_wasm = wat::parse_str(
        r#"
        (module
            (memory 1)
        )"#,
    )
    .unwrap();
    test.upgrade_canister(canister_id, empty_wasm).unwrap();

    assert_eq!(
        test.canister_state_mut(canister_id)
            .system_state
            .task_queue
            .peek_hook_status(),
        OnLowWasmMemoryHookStatus::ConditionNotSatisfied
    );

    // Load an existing snapshot.
    helper_load_snapshot(&mut test, canister_id, snapshot_id);

    assert_eq!(
        test.canister_state_mut(canister_id)
            .system_state
            .task_queue
            .peek_hook_status(),
        OnLowWasmMemoryHookStatus::Ready
    );
}

#[test]
fn snapshot_is_deleted_with_canister_delete() {
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_caller(own_subnet, caller_canister)
        .build();

    // Create new canister.
    let canister_id = test
        .canister_from_cycles_and_binary(
            Cycles::new(1_000_000_000_000_000),
            UNIVERSAL_CANISTER_WASM.to_vec(),
        )
        .unwrap();

    // Take a snapshot of the canister.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
    let result = test.subnet_message("take_canister_snapshot", args.encode());
    let snapshot_id = CanisterSnapshotResponse::decode(&result.unwrap().bytes())
        .unwrap()
        .snapshot_id();
    assert!(test.state().canister_snapshots.get(snapshot_id).is_some());

    // Delete the canister, snapshot is also deleted.
    test.stop_canister(canister_id);
    test.process_stopping_canisters();
    test.delete_canister(canister_id).unwrap();

    // Canister is deleted together with the canister snapshot.
    assert!(test.state().canister_state(&canister_id).is_none());
    assert!(test.state().canister_snapshots.get(snapshot_id).is_none());
}

#[test]
fn take_canister_snapshot_charges_canister_cycles() {
    const CYCLES: Cycles = Cycles::new(1_000_000_000_000_000);
    const WASM_PAGE_SIZE: u64 = 65_536;
    // 7500 of stable memory pages is close to 500MB, but still leaves some room
    // for Wasm memory of the universal canister.
    const NUM_PAGES: u64 = 7_500;
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);

    let subnet_type = SubnetType::Application;
    let scheduler_config = SubnetConfig::new(subnet_type).scheduler_config;

    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_caller(own_subnet, caller_canister)
        .build();

    // Create canister.
    let canister_id = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();
    test.canister_update_reserved_cycles_limit(canister_id, CYCLES)
        .unwrap();

    // Increase memory usage.
    grow_stable_memory(&mut test, canister_id, WASM_PAGE_SIZE, NUM_PAGES);
    let canister_snapshot_size = test.canister_state(canister_id).snapshot_size_bytes();

    let initial_balance = test.canister_state(canister_id).system_state.balance();
    let instructions = scheduler_config.canister_snapshot_baseline_instructions
        + NumInstructions::new(canister_snapshot_size.get());

    // Take a snapshot of the canister will decrease the balance.
    let expected_charge = test.cycles_account_manager().execution_cost(
        instructions,
        test.subnet_size(),
        WASM_EXECUTION_MODE,
    );

    // Take a snapshot for the canister.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
    let result = test.subnet_message("take_canister_snapshot", args.encode());
    let snapshot_id = CanisterSnapshotResponse::decode(&result.unwrap().bytes())
        .unwrap()
        .snapshot_id();
    assert!(test.state().canister_snapshots.get(snapshot_id).is_some());

    assert_eq!(
        test.canister_state(canister_id).system_state.balance(),
        initial_balance - expected_charge,
    );
}

#[test]
fn load_canister_snapshot_charges_canister_cycles() {
    const CYCLES: Cycles = Cycles::new(1_000_000_000_000_000);
    const WASM_PAGE_SIZE: u64 = 65_536;
    // 7500 of stable memory pages is close to 500MB, but still leaves some room
    // for Wasm memory of the universal canister.
    const NUM_PAGES: u64 = 500;
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);

    let subnet_type = SubnetType::Application;
    let scheduler_config = SubnetConfig::new(subnet_type).scheduler_config;

    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_caller(own_subnet, caller_canister)
        .build();

    // Create canister.
    let canister_id = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();
    test.canister_update_reserved_cycles_limit(canister_id, CYCLES)
        .unwrap();

    // Increase memory usage.
    grow_stable_memory(&mut test, canister_id, WASM_PAGE_SIZE, NUM_PAGES);
    // Take a snapshot for the canister.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
    let result = test.subnet_message("take_canister_snapshot", args.encode());
    let snapshot_id = CanisterSnapshotResponse::decode(&result.unwrap().bytes())
        .unwrap()
        .snapshot_id();
    assert!(test.state().canister_snapshots.get(snapshot_id).is_some());

    let canister_snapshot_size = test.canister_state(canister_id).snapshot_size_bytes();
    let initial_balance = test.canister_state(canister_id).system_state.balance();
    let instructions = scheduler_config.canister_snapshot_baseline_instructions
        + NumInstructions::new(canister_snapshot_size.get());

    // Load a snapshot of the canister will decrease the balance.
    let expected_charge = test.cycles_account_manager().execution_cost(
        instructions,
        test.subnet_size(),
        WASM_EXECUTION_MODE,
    );

    // Load an existing snapshot will decrease the balance.
    let args: LoadCanisterSnapshotArgs =
        LoadCanisterSnapshotArgs::new(canister_id, snapshot_id, None);
    let result = test.subnet_message("load_canister_snapshot", args.encode());
    assert!(result.is_ok());
    assert!(
        test.canister_state(canister_id).system_state.balance() < initial_balance - expected_charge
    );
}

#[test]
fn snapshot_must_include_globals() {
    let wat = r#"
    (module
        (import "ic0" "msg_reply" (func $msg_reply))
        (import "ic0" "msg_reply_data_append"
          (func $msg_reply_data_append (param i32 i32)))

        (func $read_global
          (i32.store
            (i32.const 0)
            (global.get 0)
          )
          (call $msg_reply_data_append
            (i32.const 0)
            (i32.const 4))
          (call $msg_reply)
        )

        (func $increase_global
          (global.set 0
            (i32.add
              (global.get 0)
              (i32.const 1)
            )
          )
          (call $msg_reply)
        )

        (memory $memory 1)
        (export "memory" (memory $memory))
        (global (export "counter") (mut i32) (i32.const 0))
        (export "canister_query read_global" (func $read_global))
        (export "canister_update increase_global" (func $increase_global))
      )"#;
    let wasm = wat::parse_str(wat).unwrap();

    let mut test = ExecutionTestBuilder::new().build();

    // Create canister.
    let canister_id = test.canister_from_binary(wasm).unwrap();

    // Check that global is initially 0
    let result = test
        .non_replicated_query(canister_id, "read_global", vec![])
        .unwrap();
    assert_eq!(result, WasmResult::Reply(vec![0, 0, 0, 0]));

    // Increase global to 1
    test.ingress(canister_id, "increase_global", vec![])
        .unwrap();

    // Check that global is now 1
    let result = test
        .non_replicated_query(canister_id, "read_global", vec![])
        .unwrap();
    assert_eq!(result, WasmResult::Reply(vec![1, 0, 0, 0]));

    // Take a snapshot.
    let args = TakeCanisterSnapshotArgs::new(canister_id, None);
    let result = test
        .subnet_message("take_canister_snapshot", args.encode())
        .unwrap();
    let response = CanisterSnapshotResponse::decode(&result.bytes()).unwrap();
    let snapshot_id = response.snapshot_id();

    // Load the snapshot.
    let args = LoadCanisterSnapshotArgs::new(canister_id, snapshot_id, None);
    test.subnet_message("load_canister_snapshot", args.encode())
        .unwrap();

    // Check that global is still 1
    let result = test
        .non_replicated_query(canister_id, "read_global", vec![])
        .unwrap();
    assert_eq!(result, WasmResult::Reply(vec![1, 0, 0, 0]));
}

#[test]
fn read_canister_snapshot_metadata_succeeds() {
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_snapshot_metadata_download()
        .with_own_subnet_id(own_subnet)
        .with_caller(own_subnet, caller_canister)
        .build();
    // Create new canister.
    let uni_canister_wasm = UNIVERSAL_CANISTER_WASM.to_vec();
    let canister_id = test
        .canister_from_cycles_and_binary(
            Cycles::new(1_000_000_000_000_000),
            uni_canister_wasm.clone(),
        )
        .unwrap();

    // Upload chunk.
    let chunk = vec![1, 2, 3, 4, 5];
    let upload_args = UploadChunkArgs {
        canister_id: canister_id.into(),
        chunk,
    };
    test.subnet_message("upload_chunk", upload_args.encode())
        .unwrap();

    // Grow the stable memory
    let stable_pages = 13;
    let payload = wasm().stable64_grow(stable_pages).reply().build();
    test.ingress(canister_id, "update", payload).unwrap();
    // Set some cert data
    let cert_data = [42];
    let payload = wasm().certified_data_set(&cert_data).reply().build();
    test.ingress(canister_id, "update", payload).unwrap();
    // Set a global timer
    let timestamp = 43;
    let payload = wasm().api_global_timer_set(timestamp).reply().build();
    test.ingress(canister_id, "update", payload).unwrap();

    // Take a snapshot of the canister.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
    let result = test.subnet_message("take_canister_snapshot", args.encode());
    let snapshot_id = CanisterSnapshotResponse::decode(&result.unwrap().bytes())
        .unwrap()
        .snapshot_id();

    // Get the metadata
    let args = ReadCanisterSnapshotMetadataArgs::new(canister_id, snapshot_id);
    let WasmResult::Reply(bytes) = test
        .subnet_message("read_canister_snapshot_metadata", args.encode())
        .unwrap()
    else {
        panic!("expected WasmResult::Reply")
    };
    let metadata = Decode!(&bytes, ReadCanisterSnapshotMetadataResponse).unwrap();
    assert_eq!(metadata.source, SnapshotSource::TakenFromCanister);
    assert_eq!(
        metadata.stable_memory_size,
        WASM_PAGE_SIZE_IN_BYTES as u64 * stable_pages
    );
    assert_eq!(metadata.wasm_module_size, uni_canister_wasm.len() as u64);
    assert_eq!(metadata.wasm_chunk_store.len(), 1);
    assert_eq!(metadata.certified_data, cert_data);
    assert_eq!(metadata.global_timer, Some(GlobalTimer::Active(timestamp)));
    assert_eq!(
        metadata.on_low_wasm_memory_hook_status,
        Some(OnLowWasmMemoryHookStatus::ConditionNotSatisfied)
    );
    assert_eq!(metadata.canister_version, 4);
}

#[test]
fn read_canister_snapshot_metadata_fails_canister_and_snapshot_must_match() {
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_snapshot_metadata_download()
        .with_own_subnet_id(own_subnet)
        .with_manual_execution()
        .with_caller(own_subnet, caller_canister)
        .build();

    // Create canister
    let canister_id = test
        .canister_from_cycles_and_binary(
            Cycles::new(1_000_000_000_000_000),
            UNIVERSAL_CANISTER_WASM.to_vec(),
        )
        .unwrap();

    // Create other canister.
    let other_canister_id = test
        .canister_from_cycles_and_binary(
            Cycles::new(1_000_000_000_000_000),
            UNIVERSAL_CANISTER_WASM.to_vec(),
        )
        .unwrap();

    // Take a snapshot of the first canister.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
    let result = test.subnet_message("take_canister_snapshot", args.encode());
    let snapshot_id = CanisterSnapshotResponse::decode(&result.unwrap().bytes())
        .unwrap()
        .snapshot_id();

    // Try to access metadata via the wrong canister id
    let args = ReadCanisterSnapshotMetadataArgs::new(other_canister_id, snapshot_id);
    let error = test
        .subnet_message("read_canister_snapshot_metadata", args.encode())
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::CanisterRejectedMessage);

    // Try to access metadata via a bad snapshot id
    let args = ReadCanisterSnapshotMetadataArgs::new(canister_id, (canister_id, 42).into());
    let error = test
        .subnet_message("read_canister_snapshot_metadata", args.encode())
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::CanisterSnapshotNotFound);
}

#[test]
fn read_canister_snapshot_metadata_fails_invalid_controller() {
    let own_subnet = subnet_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_snapshot_metadata_download()
        .with_own_subnet_id(own_subnet)
        .with_manual_execution()
        .build();
    // Create new canister.
    let uni_canister_wasm = UNIVERSAL_CANISTER_WASM.to_vec();
    let canister_id = test
        .canister_from_cycles_and_binary(
            Cycles::new(1_000_000_000_000_000),
            uni_canister_wasm.clone(),
        )
        .unwrap();

    // Take a snapshot of the canister.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
    let result = test.subnet_message("take_canister_snapshot", args.encode());
    let snapshot_id = CanisterSnapshotResponse::decode(&result.unwrap().bytes())
        .unwrap()
        .snapshot_id();

    // Non-controller user tries to get metadata
    test.set_user_id(user_test_id(42));
    let args = ReadCanisterSnapshotMetadataArgs::new(canister_id, snapshot_id);
    let error = test
        .subnet_message("read_canister_snapshot_metadata", args.encode())
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::CanisterInvalidController);
}

fn read_canister_snapshot_data(
    test: &mut ExecutionTest,
    args: &ReadCanisterSnapshotDataArgs,
) -> Vec<u8> {
    let WasmResult::Reply(bytes) = test
        .subnet_message("read_canister_snapshot_data", args.encode())
        .unwrap()
    else {
        panic!("expected WasmResult::Reply")
    };
    let ReadCanisterSnapshotDataResponse { chunk } =
        Decode!(&bytes, ReadCanisterSnapshotDataResponse).unwrap();
    chunk
}

#[test]
fn read_canister_snapshot_data_succeeds() {
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_snapshot_metadata_download()
        .with_own_subnet_id(own_subnet)
        .with_caller(own_subnet, caller_canister)
        .build();
    // Create new canister.
    let uni_canister_wasm = UNIVERSAL_CANISTER_WASM.to_vec();
    let canister_id = test
        .canister_from_cycles_and_binary(
            Cycles::new(1_000_000_000_000_000),
            uni_canister_wasm.clone(),
        )
        .unwrap();
    // Upload chunk 1.
    let chunk1 = vec![1, 2, 3, 4, 5];
    let upload_args = UploadChunkArgs {
        canister_id: canister_id.into(),
        chunk: chunk1.clone(),
    };
    test.subnet_message("upload_chunk", upload_args.encode())
        .unwrap();
    // Upload chunk 2.
    let chunk2 = vec![6, 7, 8];
    let upload_args = UploadChunkArgs {
        canister_id: canister_id.into(),
        chunk: chunk2.clone(),
    };
    test.subnet_message("upload_chunk", upload_args.encode())
        .unwrap();
    // Grow the stable memory
    let stable_pages = 65;
    let payload = wasm().stable64_grow(stable_pages).reply().build();
    test.ingress(canister_id, "update", payload).unwrap();

    // Take a snapshot of the canister.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
    let result = test.subnet_message("take_canister_snapshot", args.encode());
    let snapshot_id = CanisterSnapshotResponse::decode(&result.unwrap().bytes())
        .unwrap()
        .snapshot_id();

    // Get the metadata
    let args = ReadCanisterSnapshotMetadataArgs::new(canister_id, snapshot_id);
    let WasmResult::Reply(bytes) = test
        .subnet_message("read_canister_snapshot_metadata", args.encode())
        .unwrap()
    else {
        panic!("expected WasmResult::Reply")
    };
    let ReadCanisterSnapshotMetadataResponse {
        wasm_module_size,
        wasm_memory_size,
        stable_memory_size,
        wasm_chunk_store,
        ..
    } = Decode!(&bytes, ReadCanisterSnapshotMetadataResponse).unwrap();

    // Test getting all binary snapshot data
    // wasm module
    verify_data_wasm_module(
        &mut test,
        canister_id,
        snapshot_id,
        wasm_module_size,
        uni_canister_wasm,
    );

    // canister heap
    verify_data_wasm_heap(&mut test, canister_id, snapshot_id, wasm_memory_size);

    // stable memory
    verify_data_stable_memory(
        &mut test,
        canister_id,
        snapshot_id,
        stable_memory_size,
        stable_pages,
    );

    // chunk store
    assert_eq!(wasm_chunk_store.len(), 2);
    let args_chunk_1 = ReadCanisterSnapshotDataArgs::new(
        canister_id,
        snapshot_id,
        CanisterSnapshotDataKind::WasmChunk {
            hash: wasm_chunk_store[0].hash.clone(),
        },
    );
    let args_chunk_2 = ReadCanisterSnapshotDataArgs::new(
        canister_id,
        snapshot_id,
        CanisterSnapshotDataKind::WasmChunk {
            hash: wasm_chunk_store[1].hash.clone(),
        },
    );
    let chunk_1 = read_canister_snapshot_data(&mut test, &args_chunk_1);
    let chunk_2 = read_canister_snapshot_data(&mut test, &args_chunk_2);
    let mut original = vec![chunk1, chunk2];
    let mut returned = vec![chunk_1, chunk_2];
    original.sort();
    returned.sort();
    assert_eq!(original, returned);
}

fn verify_data_wasm_module(
    test: &mut ExecutionTest,
    canister_id: CanisterId,
    snapshot_id: SnapshotId,
    wasm_module_size: u64,
    uni_canister_wasm: Vec<u8>,
) {
    let args_module = ReadCanisterSnapshotDataArgs::new(
        canister_id,
        snapshot_id,
        CanisterSnapshotDataKind::WasmModule {
            offset: 0,
            // currently about 184k, so it fits in a single 2MB slice
            size: wasm_module_size,
        },
    );
    let chunk = read_canister_snapshot_data(test, &args_module);
    assert_eq!(chunk, uni_canister_wasm);
}

fn verify_data_wasm_heap(
    test: &mut ExecutionTest,
    canister_id: CanisterId,
    snapshot_id: SnapshotId,
    wasm_memory_size: u64,
) {
    // wasm_memory_size ~ 3_276_800 does not fit into one 2MB slice
    let max_chunk_size = 2 * 1000 * 1000;
    let rest = wasm_memory_size - max_chunk_size;
    let args_main = ReadCanisterSnapshotDataArgs::new(
        canister_id,
        snapshot_id,
        CanisterSnapshotDataKind::MainMemory {
            offset: 0,
            size: max_chunk_size,
        },
    );
    let chunk = read_canister_snapshot_data(test, &args_main);
    assert_eq!(chunk.len(), max_chunk_size as usize);
    // second part
    let args_main = ReadCanisterSnapshotDataArgs::new(
        canister_id,
        snapshot_id,
        CanisterSnapshotDataKind::MainMemory {
            offset: max_chunk_size,
            size: rest,
        },
    );
    let chunk = read_canister_snapshot_data(test, &args_main);
    assert_eq!(chunk.len(), rest as usize);
}

fn verify_data_stable_memory(
    test: &mut ExecutionTest,
    canister_id: CanisterId,
    snapshot_id: SnapshotId,
    stable_memory_size: u64,
    stable_pages: u64,
) {
    // stable_memory_size ~ 4259840 does not fit into one 2MB slice
    let max_chunk_size = 2 * 1000 * 1000;
    let mut total_len = 0;
    let rest = stable_memory_size - max_chunk_size * 2;
    // slice 1
    let args_stable = ReadCanisterSnapshotDataArgs::new(
        canister_id,
        snapshot_id,
        CanisterSnapshotDataKind::StableMemory {
            offset: 0,
            size: max_chunk_size,
        },
    );
    let chunk = read_canister_snapshot_data(test, &args_stable);
    assert_eq!(chunk.len(), max_chunk_size as usize);
    total_len += chunk.len();
    // slice 2
    let args_stable = ReadCanisterSnapshotDataArgs::new(
        canister_id,
        snapshot_id,
        CanisterSnapshotDataKind::StableMemory {
            offset: max_chunk_size,
            size: max_chunk_size,
        },
    );
    let chunk = read_canister_snapshot_data(test, &args_stable);
    assert_eq!(chunk.len(), max_chunk_size as usize);
    total_len += chunk.len();
    // slice 3
    let args_stable = ReadCanisterSnapshotDataArgs::new(
        canister_id,
        snapshot_id,
        CanisterSnapshotDataKind::StableMemory {
            offset: max_chunk_size * 2,
            size: rest,
        },
    );
    let chunk = read_canister_snapshot_data(test, &args_stable);
    total_len += chunk.len();
    assert_eq!(total_len, stable_pages as usize * WASM_PAGE_SIZE_IN_BYTES);
}

#[test]
fn read_canister_snapshot_data_fails_bad_slice() {
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_snapshot_metadata_download()
        .with_own_subnet_id(own_subnet)
        .with_caller(own_subnet, caller_canister)
        .build();
    // Create new canister.
    let uni_canister_wasm = UNIVERSAL_CANISTER_WASM.to_vec();
    let canister_id = test
        .canister_from_cycles_and_binary(
            Cycles::new(1_000_000_000_000_000),
            uni_canister_wasm.clone(),
        )
        .unwrap();
    // Grow the stable memory
    let stable_pages = 3;
    let payload = wasm().stable64_grow(stable_pages).reply().build();
    test.ingress(canister_id, "update", payload).unwrap();

    // Take a snapshot of the canister.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
    let result = test.subnet_message("take_canister_snapshot", args.encode());
    let snapshot_id = CanisterSnapshotResponse::decode(&result.unwrap().bytes())
        .unwrap()
        .snapshot_id();

    // get metadata
    let args = ReadCanisterSnapshotMetadataArgs::new(canister_id, snapshot_id);
    let WasmResult::Reply(bytes) = test
        .subnet_message("read_canister_snapshot_metadata", args.encode())
        .unwrap()
    else {
        panic!("expected WasmResult::Reply")
    };
    let md = Decode!(&bytes, ReadCanisterSnapshotMetadataResponse).unwrap();

    // wasm module bad slice fails
    let args_module = ReadCanisterSnapshotDataArgs::new(
        canister_id,
        snapshot_id,
        CanisterSnapshotDataKind::WasmModule {
            offset: 0,
            size: 1 + uni_canister_wasm.len() as u64,
        },
    );
    let Err(err) = test.subnet_message("read_canister_snapshot_data", args_module.encode()) else {
        panic!("Expected Err(e)");
    };
    assert_eq!(err.code(), ErrorCode::InvalidManagementPayload);
    let max_slice_size = 2 * 1000 * 1000;
    // wasm heap bad slice fails: slice too large
    let args_module = ReadCanisterSnapshotDataArgs::new(
        canister_id,
        snapshot_id,
        CanisterSnapshotDataKind::MainMemory {
            offset: 0,
            size: 1 + max_slice_size,
        },
    );
    let Err(err) = test.subnet_message("read_canister_snapshot_data", args_module.encode()) else {
        panic!("Expected Err(e)");
    };
    assert_eq!(err.code(), ErrorCode::InvalidManagementPayload);
    // wasm heap bad slice fails: exceeds last page
    let pages = md.wasm_memory_size / PAGE_SIZE as u64;
    let args_module = ReadCanisterSnapshotDataArgs::new(
        canister_id,
        snapshot_id,
        CanisterSnapshotDataKind::MainMemory {
            offset: (pages - 1) * PAGE_SIZE as u64,
            size: PAGE_SIZE as u64 + 1000,
        },
    );
    let Err(err) = test.subnet_message("read_canister_snapshot_data", args_module.encode()) else {
        panic!("Expected Err(e)");
    };
    assert_eq!(err.code(), ErrorCode::InvalidManagementPayload);
    // stable memory bad slice fails: slice too large
    let args_module = ReadCanisterSnapshotDataArgs::new(
        canister_id,
        snapshot_id,
        CanisterSnapshotDataKind::StableMemory {
            offset: 0,
            size: 1 + max_slice_size,
        },
    );
    let Err(err) = test.subnet_message("read_canister_snapshot_data", args_module.encode()) else {
        panic!("Expected Err(e)");
    };
    assert_eq!(err.code(), ErrorCode::InvalidManagementPayload);
    // stable memory bad slice fails: execeeds last page
    let pages = md.stable_memory_size / PAGE_SIZE as u64;
    let args_module = ReadCanisterSnapshotDataArgs::new(
        canister_id,
        snapshot_id,
        CanisterSnapshotDataKind::StableMemory {
            offset: (pages - 1) * PAGE_SIZE as u64,
            size: PAGE_SIZE as u64 + 1000,
        },
    );
    let Err(err) = test.subnet_message("read_canister_snapshot_data", args_module.encode()) else {
        panic!("Expected Err(e)");
    };
    assert_eq!(err.code(), ErrorCode::InvalidManagementPayload);
}

#[test]
fn read_canister_snapshot_data_fails_invalid_controller() {
    let own_subnet = subnet_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_snapshot_metadata_download()
        .with_own_subnet_id(own_subnet)
        .with_manual_execution()
        .build();
    // Create new canister.
    let uni_canister_wasm = UNIVERSAL_CANISTER_WASM.to_vec();
    let canister_id = test
        .canister_from_cycles_and_binary(
            Cycles::new(1_000_000_000_000_000),
            uni_canister_wasm.clone(),
        )
        .unwrap();

    // Take a snapshot of the canister.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
    let result = test.subnet_message("take_canister_snapshot", args.encode());
    let snapshot_id = CanisterSnapshotResponse::decode(&result.unwrap().bytes())
        .unwrap()
        .snapshot_id();

    // Non-controller user tries to get metadata
    test.set_user_id(user_test_id(42));
    let args = ReadCanisterSnapshotDataArgs::new(
        canister_id,
        snapshot_id,
        CanisterSnapshotDataKind::MainMemory { offset: 0, size: 0 },
    );
    let error = test
        .subnet_message("read_canister_snapshot_data", args.encode())
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::CanisterInvalidController);
}

#[test]
fn read_canister_snapshot_data_fails_canister_and_snapshot_must_match() {
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_snapshot_metadata_download()
        .with_own_subnet_id(own_subnet)
        .with_manual_execution()
        .with_caller(own_subnet, caller_canister)
        .build();

    // Create canister
    let canister_id = test
        .canister_from_cycles_and_binary(
            Cycles::new(1_000_000_000_000_000),
            UNIVERSAL_CANISTER_WASM.to_vec(),
        )
        .unwrap();

    // Create other canister.
    let other_canister_id = test
        .canister_from_cycles_and_binary(
            Cycles::new(1_000_000_000_000_000),
            UNIVERSAL_CANISTER_WASM.to_vec(),
        )
        .unwrap();

    // Take a snapshot of the first canister.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
    let result = test.subnet_message("take_canister_snapshot", args.encode());
    let snapshot_id = CanisterSnapshotResponse::decode(&result.unwrap().bytes())
        .unwrap()
        .snapshot_id();

    // Try to access metadata via the wrong canister id
    let args = ReadCanisterSnapshotDataArgs::new(
        other_canister_id,
        snapshot_id,
        CanisterSnapshotDataKind::MainMemory { offset: 0, size: 0 },
    );
    let error = test
        .subnet_message("read_canister_snapshot_data", args.encode())
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::CanisterRejectedMessage);

    // Try to access metadata via a bad snapshot id
    let args = ReadCanisterSnapshotDataArgs::new(
        canister_id,
        (canister_id, 42).into(),
        CanisterSnapshotDataKind::MainMemory { offset: 0, size: 0 },
    );
    let error = test
        .subnet_message("read_canister_snapshot_data", args.encode())
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::CanisterSnapshotNotFound);
}

/// Early warning system / stumbling block forcing the authors of changes adding
/// or removing canister state fields to think about and/or ask the Execution
/// team to think about any repercussions to the canister snapshot logic.
///
/// If you do find yourself having to make changes to this function, it is quite
/// possible that you have not broken anything. But there is a non-zero chance
/// for changes to the structure of the canister state to also require changes
/// to the canister snapshot logic or risk breaking it. Which is why this brute
/// force check exists.
///
/// See `CanisterSnapshot::from_canister()` for more context.
#[allow(dead_code)]
fn canister_snapshot_change_guard_do_not_modify_without_reading_doc_comment() {
    let mut test = ExecutionTestBuilder::new().build();
    let uc = test.universal_canister().unwrap();
    let canister_state = test.canister_state(uc).clone();

    //
    // DO NOT MODIFY WITHOUT READING DOC COMMENT!
    //
    let CanisterState {
        // There is a separate test for SystemState.
        system_state: _,
        execution_state,
        scheduler_state,
    } = canister_state;

    //
    // DO NOT MODIFY WITHOUT READING DOC COMMENT!
    //
    let ExecutionState {
        canister_root: _,
        wasm_binary,
        wasm_memory: _,
        stable_memory: _,
        exported_globals: _,
        exports: _,
        metadata: _,
        last_executed_round: _,
        next_scheduled_method: _,
        wasm_execution_mode: _,
    } = execution_state.unwrap();

    //
    // DO NOT MODIFY WITHOUT READING DOC COMMENT!
    //
    let WasmBinary {
        binary: _,
        embedder_cache: _,
    } = wasm_binary.borrow();

    //
    // DO NOT MODIFY WITHOUT READING DOC COMMENT!
    //
    let SchedulerState {
        last_full_execution_round: _,
        compute_allocation: _,
        accumulated_priority: _,
        priority_credit: _,
        long_execution_mode: _,
        heap_delta_debit: _,
        install_code_debit: _,
        time_of_last_allocation_charge: _,
        total_query_stats: _,
    } = scheduler_state;
}
