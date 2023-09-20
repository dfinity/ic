use candid::{Decode, Encode};
use ic_canisters_http_types::{HttpRequest, HttpResponse};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    state_test_helpers::{query, setup_nns_canisters},
};
use ic_state_machine_tests::StateMachine;
use serde_bytes::ByteBuf;

#[test]
fn test_neuron_indexes_migrations() {
    let state_machine = StateMachine::new();
    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    // Let heartbeat run.
    for _ in 0..10 {
        state_machine.tick();
    }

    // TODO(NNS1-2413): change to checking validation result once they are ready.
    let response_bytes = query(
        &state_machine,
        GOVERNANCE_CANISTER_ID,
        "http_request",
        Encode!(&HttpRequest {
            url: "/metrics".to_string(),
            method: "GET".to_string(),
            headers: vec![],
            body: ByteBuf::new(),
        })
        .unwrap(),
    )
    .unwrap();
    let response: HttpResponse = Decode!(&response_bytes, HttpResponse).unwrap();
    let response_body = String::from_utf8(response.body.into_vec()).unwrap();

    assert!(response_body.contains("governance_subaccount_index_len 3 "));
    assert!(response_body.contains("governance_principal_index_len 3 "));
    assert!(response_body.contains("governance_following_index_len 0 "));
    assert!(response_body.contains("governance_known_neuron_index_len 0 "));
}
