use candid::{Decode, Encode};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    state_test_helpers::{setup_nns_canisters, state_machine_builder_for_nns_tests, update},
};
use ic_state_machine_tests::StateMachine;
use registry_canister::pb::v1::{ApiBoundaryNodeIdRecord, GetApiBoundaryNodeIdsRequest};

fn setup_state_machine_with_nns_canisters() -> StateMachine {
    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);
    state_machine
}

#[test]
fn test_get_api_boundary_node_ids() {
    let state_machine = setup_state_machine_with_nns_canisters();

    let raw_response = update(
        &state_machine,
        REGISTRY_CANISTER_ID,
        "get_api_boundary_node_ids",
        Encode!(&GetApiBoundaryNodeIdsRequest {}).unwrap(),
    )
    .expect("update failed");

    let response: Result<Vec<ApiBoundaryNodeIdRecord>, String> = Decode!(
        raw_response.as_slice(),
        Result<Vec<ApiBoundaryNodeIdRecord>, String>
    )
    .expect("Decoding failed");

    assert_eq!(response.expect("Response error"), vec![]);
}
