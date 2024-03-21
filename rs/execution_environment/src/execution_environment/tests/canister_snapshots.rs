use assert_matches::assert_matches;
use candid::Encode;
use ic_base_types::NumBytes;
use ic_config::flag_status::FlagStatus;
use ic_cycles_account_manager::ResourceSaturation;
use ic_error_types::{ErrorCode, RejectCode};
use ic_management_canister_types::{
    self as ic00, DeleteCanisterSnapshotArgs, Method, Payload as Ic00Payload,
    TakeCanisterSnapshotArgs, TakeCanisterSnapshotResponse, UploadChunkArgs,
};
use ic_replicated_state::canister_state::system_state::CyclesUseCase;
use ic_test_utilities_execution_environment::{
    get_output_messages, ExecutionTest, ExecutionTestBuilder,
};
use ic_test_utilities_types::ids::{canister_test_id, subnet_test_id};
use ic_types::{
    ingress::WasmResult,
    messages::{Payload, RejectContext, RequestOrResponse},
    time::UNIX_EPOCH,
    CanisterId, Cycles, SnapshotId,
};
use ic_universal_canister::{call_args, wasm, UNIVERSAL_CANISTER_WASM};
use serde_bytes::ByteBuf;

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

    let response = TakeCanisterSnapshotResponse::new(
        &snapshot_id,
        UNIX_EPOCH.as_nanos_since_unix_epoch(),
        NumBytes::from(65),
    );
    let encoded_response = response.encode();
    assert_eq!(
        response,
        TakeCanisterSnapshotResponse::decode(encoded_response.as_slice()).unwrap()
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
        .with_snapshots(FlagStatus::Enabled)
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
fn take_canister_snapshot_request_rejected_because_feature_is_disabled() {
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
        assert_eq!(
            res.response_payload,
            Payload::Reject(RejectContext::new(
                RejectCode::CanisterError,
                "This API is not enabled on this subnet"
            ))
        );
    }
}

#[test]
fn take_snapshot_ingress_rejected_because_feature_is_disabled() {
    let mut test = ExecutionTestBuilder::new()
        .with_snapshots(FlagStatus::Disabled)
        .build();
    let uni = test.universal_canister().unwrap();

    let snapshot_methods = [
        Method::TakeCanisterSnapshot,
        Method::LoadCanisterSnapshot,
        Method::DeleteCanisterSnapshot,
        Method::ListCanisterSnapshots,
    ];
    for method in snapshot_methods {
        let call = wasm()
            .call_simple(
                ic00::IC_00,
                method,
                call_args()
                    .other_side(vec![])
                    .on_reject(wasm().reject_message().reject()),
            )
            .build();
        let result = test.ingress(uni, "update", call).unwrap();
        let expected_result = WasmResult::Reject(
            format!("Unable to route management canister request {}: UserError(UserError {{ code: CanisterRejectedMessage, description: {} }})",
             method,
            "\"Snapshotting API is not yet implemented\""));
        assert_eq!(result, expected_result);
    }
}

#[test]
fn list_canister_snapshot_request_rejected_because_feature_is_not_implemented() {
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_manual_execution()
        .with_snapshots(FlagStatus::Enabled)
        .with_caller(own_subnet, caller_canister)
        .build();

    let canister_id = canister_test_id(4);
    let snapshot_id = SnapshotId::from((canister_id, 6));
    let args: TakeCanisterSnapshotArgs =
        TakeCanisterSnapshotArgs::new(canister_id, Some(snapshot_id));
    // Inject a list canister snapshots request.
    test.inject_call_to_ic00(
        Method::ListCanisterSnapshots,
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
                RejectCode::CanisterReject,
                "Canister snapshotting API is not yet implemented."
            ))
        );
    }
}

#[test]
fn take_canister_snapshot_fails_canister_not_found() {
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_manual_execution()
        .with_snapshots(FlagStatus::Enabled)
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
        .with_snapshots(FlagStatus::Enabled)
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
        assert_eq!(
            res.response_payload,
            Payload::Reject(RejectContext::new(
                RejectCode::CanisterError,
                format!(
                    "Only the controllers of the canister {} can control it.\n\
                    Canister's controllers: {}\n\
                    Sender's ID: {}",
                    canister_id,
                    test.user_id().get(),
                    caller_canister.get(),
                )
            ))
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
        .with_snapshots(FlagStatus::Enabled)
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
        assert_eq!(
            res.response_payload,
            Payload::Reject(RejectContext::new(
                RejectCode::DestinationInvalid,
                format!(
                    "Could not find the snapshot ID {} for canister {}",
                    snapshot_id, canister_id
                ),
            ))
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
        .with_snapshots(FlagStatus::Enabled)
        .with_caller(own_subnet, caller_canister)
        .build();

    // Create canisters.
    let canister_id_1 = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.into())
        .unwrap();
    let canister_id_2 = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.into())
        .unwrap();

    // Take a snapshot for canister_1.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id_1, None);
    let result = test.subnet_message("take_canister_snapshot", args.encode());
    assert!(result.is_ok());
    let response = TakeCanisterSnapshotResponse::decode(&result.unwrap().bytes()).unwrap();
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
        .with_snapshots(FlagStatus::Enabled)
        .with_caller(own_subnet, caller_canister)
        .build();

    // Create canister and update controllers.
    let canister_id = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.into())
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
    let response = TakeCanisterSnapshotResponse::decode(&result.unwrap().bytes()).unwrap();
    let snapshot_id = response.snapshot_id();

    assert!(test.state().canister_snapshots.contains(&snapshot_id));
    assert!(test.state().canister_snapshots.contains(&snapshot_id));

    assert!(test.state().canister_snapshots.contains(&snapshot_id));

    let snapshot = test.state().canister_snapshots.get(snapshot_id).unwrap();
    assert_eq!(
        *snapshot.canister_module().unwrap(),
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

    // Take a new snapshot for the canister, and provide a replacement snapshot ID.
    let args: TakeCanisterSnapshotArgs =
        TakeCanisterSnapshotArgs::new(canister_id, Some(snapshot_id));
    let result = test.subnet_message("take_canister_snapshot", args.encode());
    assert!(result.is_ok());
    let new_snapshot_id = TakeCanisterSnapshotResponse::decode(&result.unwrap().bytes())
        .unwrap()
        .snapshot_id();

    // Check that old snapshot ID was deleted.
    assert_ne!(new_snapshot_id, snapshot_id);
    assert!(!test.state().canister_snapshots.contains(&snapshot_id));
    assert!(test.state().canister_snapshots.contains(&new_snapshot_id));
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
fn canister_request_take_canister_reserves_cycles() {
    const CYCLES: Cycles = Cycles::new(20_000_000_000_000);
    const CAPACITY: u64 = 1_000_000_000;
    const THRESHOLD: u64 = CAPACITY / 2;
    const WASM_PAGE_SIZE: u64 = 65_536;
    // 7500 of stable memory pages is close to 500MB, but still leaves some room
    // for Wasm memory of the universal canister.
    const NUM_PAGES: u64 = 7_500;

    let mut test = ExecutionTestBuilder::new()
        .with_snapshots(FlagStatus::Enabled)
        .with_heap_delta_rate_limit(NumBytes::new(1_000_000_000))
        .with_subnet_execution_memory(CAPACITY as i64)
        .with_subnet_memory_reservation(0)
        .with_subnet_memory_threshold(THRESHOLD as i64)
        .build();

    // Create canister.
    let canister_id = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.into())
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
}

#[test]
fn take_canister_snapshot_fails_subnet_memory_exceeded() {
    const CYCLES: Cycles = Cycles::new(20_000_000_000_000);
    const CAPACITY: u64 = 500_000_000;
    const THRESHOLD: u64 = CAPACITY / 2;
    const WASM_PAGE_SIZE: u64 = 65_536;
    const NUM_PAGES: u64 = 2_400;

    let mut test = ExecutionTestBuilder::new()
        .with_snapshots(FlagStatus::Enabled)
        .with_heap_delta_rate_limit(NumBytes::new(1_000_000_000))
        .with_subnet_execution_memory(CAPACITY as i64)
        .with_subnet_memory_reservation(0)
        .with_subnet_memory_threshold(THRESHOLD as i64)
        .build();

    let mut canisters = vec![];
    for _ in 0..2 {
        // Create canister.
        let canister_id = test
            .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.into())
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
fn take_canister_snapshot_increases_heap_delta() {
    const CYCLES: Cycles = Cycles::new(20_000_000_000_000);
    const CAPACITY: u64 = 1_000_000_000;
    const THRESHOLD: u64 = CAPACITY / 2;

    const WASM_PAGE_SIZE: u64 = 65_536;
    // 7500 of stable memory pages is close to 500MB, but still leaves some room
    // for Wasm memory of the universal canister.
    const NUM_PAGES: u64 = 7_500;

    let mut test = ExecutionTestBuilder::new()
        .with_snapshots(FlagStatus::Enabled)
        .with_subnet_execution_memory(CAPACITY as i64)
        .with_subnet_memory_reservation(0)
        .with_subnet_memory_threshold(THRESHOLD as i64)
        .build();

    // Create canister.
    let canister_id = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.into())
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
        .with_snapshots(FlagStatus::Enabled)
        .with_heap_delta_rate_limit(NumBytes::new(1_000_000))
        .with_subnet_execution_memory(CAPACITY as i64)
        .with_subnet_memory_reservation(0)
        .with_subnet_memory_threshold(THRESHOLD as i64)
        .build();

    // Create canister.
    let canister_id = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.into())
        .unwrap();
    test.canister_update_reserved_cycles_limit(canister_id, CYCLES)
        .unwrap();

    // Increase memory usage.
    grow_stable_memory(&mut test, canister_id, WASM_PAGE_SIZE, NUM_PAGES);

    // Take a snapshot of the canister.
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
    let result = test.subnet_message("take_canister_snapshot", args.encode());
    let snapshot_id = TakeCanisterSnapshotResponse::decode(&result.unwrap().bytes())
        .unwrap()
        .snapshot_id();
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
}

#[test]
fn take_canister_snapshot_fails_when_canister_would_be_frozen() {
    const CYCLES: Cycles = Cycles::new(1_000_000_000_000);
    const CAPACITY: u64 = 500_000_000;
    const THRESHOLD: u64 = CAPACITY / 2;
    const WASM_PAGE_SIZE: u64 = 65_536;
    const NUM_PAGES: u64 = 2_400;

    let mut test = ExecutionTestBuilder::new()
        .with_snapshots(FlagStatus::Enabled)
        .with_heap_delta_rate_limit(NumBytes::new(1_000_000))
        .with_subnet_execution_memory(CAPACITY as i64)
        .with_subnet_memory_reservation(0)
        .with_subnet_memory_threshold(THRESHOLD as i64)
        .build();

    // Create canister.
    let canister_id = test
        .canister_from_cycles_and_binary(CYCLES, UNIVERSAL_CANISTER_WASM.into())
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
fn test_delete_canister_snapshot_decode_fails() {
    let canister_id = canister_test_id(4);
    let args = ic00::DeleteCanisterSnapshotArgs {
        canister_id: canister_id.get(),
        snapshot_id: vec![4, 5, 6, 6], // Invalid snapshot ID.
    };
    let encoded_args = args.encode();
    let err = DeleteCanisterSnapshotArgs::decode(encoded_args.as_slice()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidManagementPayload,);
}
