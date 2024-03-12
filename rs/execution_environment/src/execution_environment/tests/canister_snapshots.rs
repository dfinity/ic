use assert_matches::assert_matches;
use candid::Encode;
use ic_config::flag_status::FlagStatus;
use ic_error_types::RejectCode;
use ic_management_canister_types::{
    self as ic00, DeleteCanisterSnapshotArgs, Method, Payload as Ic00Payload,
    TakeCanisterSnapshotArgs, TakeCanisterSnapshotResponse,
};
use ic_replicated_state::canister_snapshots::SnapshotId;
use ic_test_utilities_execution_environment::{get_output_messages, ExecutionTestBuilder};
use ic_test_utilities_types::ids::{canister_test_id, subnet_test_id};
use ic_types::{
    ingress::WasmResult,
    messages::{Payload, RejectContext, RequestOrResponse},
    time::UNIX_EPOCH,
    Cycles,
};
use ic_universal_canister::{call_args, wasm};

#[test]
fn test_take_canister_snapshot_decode_round_trip() {
    let snapshot_id = SnapshotId::new(6);
    let args = ic00::TakeCanisterSnapshotArgs::new(canister_test_id(4), Some(snapshot_id.get()));
    let encoded_args = args.encode();
    assert_eq!(
        args,
        TakeCanisterSnapshotArgs::decode(encoded_args.as_slice()).unwrap()
    );

    let response = TakeCanisterSnapshotResponse::new(
        snapshot_id.get(),
        UNIX_EPOCH.as_nanos_since_unix_epoch(),
        65,
    );
    let encoded_response = response.encode();
    assert_eq!(
        response,
        TakeCanisterSnapshotResponse::decode(encoded_response.as_slice()).unwrap()
    );
}

#[test]
fn test_request_snapshot_rejected_because_decode_args_fail() {
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
fn test_request_snapshot_rejected_because_feature_is_enabled() {
    let own_subnet = subnet_test_id(1);
    let caller_canister = canister_test_id(1);
    let mut test = ExecutionTestBuilder::new()
        .with_own_subnet_id(own_subnet)
        .with_manual_execution()
        .with_snapshots(FlagStatus::Enabled)
        .with_caller(own_subnet, caller_canister)
        .build();

    let snapshot_id = SnapshotId::new(6);
    let args: TakeCanisterSnapshotArgs =
        TakeCanisterSnapshotArgs::new(canister_test_id(4), Some(snapshot_id.get()));
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
                RejectCode::CanisterReject,
                "Canister snapshotting API is not yet implemented."
            ))
        );
    }
}

#[test]
fn test_request_snapshot_rejected_because_feature_is_disabled() {
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
fn test_ingress_snapshot_rejected_because_feature_is_disabled() {
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
        let expected_result = WasmResult::Reject(format!("Unable to route management canister request {}: UserError(UserError {{ code: CanisterRejectedMessage, description: {} }})", method, "\"Snapshotting API is not yet implemented\""));
        assert_eq!(result, expected_result);
    }
}

#[test]
fn test_delete_canister_snapshot_decode_round_trip() {
    let snapshot_id = SnapshotId::new(6);
    let args = ic00::DeleteCanisterSnapshotArgs::new(canister_test_id(4), snapshot_id.get());
    let encoded_args = args.encode();
    assert_eq!(
        args,
        DeleteCanisterSnapshotArgs::decode(encoded_args.as_slice()).unwrap()
    );
}
