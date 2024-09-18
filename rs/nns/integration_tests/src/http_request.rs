use candid::{Decode, Encode};
use ic_base_types::CanisterId;
use ic_canisters_http_types::{HttpRequest, HttpResponse};
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, REGISTRY_CANISTER_ID,
    ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    state_test_helpers::{setup_nns_canisters, state_machine_builder_for_nns_tests},
};
use ic_state_machine_tests::{StateMachine, WasmResult};
use serde_bytes::ByteBuf;

fn setup_state_machine_with_nns_canisters() -> StateMachine {
    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);
    state_machine
}

fn test_http_request_decoding_quota_for_canister(
    state_machine: &StateMachine,
    canister_id: CanisterId,
) {
    // The anonymous end-user sends a small HTTP request. This should succeed.
    let http_request = HttpRequest {
        method: "GET".to_string(),
        url: "/metrics".to_string(),
        headers: vec![],
        body: ByteBuf::from(vec![42; 1_000]),
    };
    let http_request_bytes = Encode!(&http_request).unwrap();
    let response = match state_machine
        .execute_ingress(canister_id, "http_request", http_request_bytes)
        .unwrap()
    {
        WasmResult::Reply(bytes) => Decode!(&bytes, HttpResponse).unwrap(),
        WasmResult::Reject(reason) => panic!("Unexpected reject: {}", reason),
    };
    assert_eq!(response.status_code, 200);

    // The anonymous end-user sends a large HTTP request. This should be rejected.
    let mut large_http_request = http_request;
    large_http_request.body = ByteBuf::from(vec![42; 1_000_000]);
    let large_http_request_bytes = Encode!(&large_http_request).unwrap();
    let err = state_machine
        .execute_ingress(canister_id, "http_request", large_http_request_bytes)
        .unwrap_err();
    let expected_err = "failed to decode";
    assert!(err.description().contains(expected_err));
}

#[test]
fn test_http_request_decoding_quota() {
    let state_machine = setup_state_machine_with_nns_canisters();

    for canister_id in [
        REGISTRY_CANISTER_ID,
        GOVERNANCE_CANISTER_ID,
        LEDGER_CANISTER_ID,
        ROOT_CANISTER_ID,
        CYCLES_MINTING_CANISTER_ID,
        SNS_WASM_CANISTER_ID,
    ] {
        test_http_request_decoding_quota_for_canister(&state_machine, canister_id);
    }
}
