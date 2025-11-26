use candid::{Decode, Encode};
use ic_base_types::PrincipalId;
use ic_http_types::{HttpRequest, HttpResponse};
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord, canister_status::CanisterStatusResult,
};
use ic_nns_constants::ROOT_CANISTER_ID;
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    state_test_helpers::{
        query, set_up_universal_canister, setup_nns_canisters, update_with_sender,
    },
};
use ic_state_machine_tests::StateMachine;
use serde_bytes::ByteBuf;

/// Test that the canister_status failure does not cause an incorrect increase
/// in the `nns_root_open_canister_status_calls_count` metric.
#[test]
fn test_canister_status_call_tracking() {
    // Setup the test
    let nns_init_payload = NnsInitPayloadsBuilder::new().build();
    let machine = StateMachine::new();
    setup_nns_canisters(&machine, nns_init_payload);

    // Create a test canister without setting NNS Root as controller.
    let universal = set_up_universal_canister(&machine, None);

    // Canister status call should fail as NNS Root is not a controller.
    assert!(
        update_with_sender::<_, CanisterStatusResult>(
            &machine,
            ROOT_CANISTER_ID,
            "canister_status",
            CanisterIdRecord::from(universal),
            PrincipalId::new_anonymous(),
        )
        .is_err()
    );

    // Queries the HTTP metrics endpoint.
    let response_bytes = query(
        &machine,
        ROOT_CANISTER_ID,
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

    // If there is any in-flight proxied canister call, the below string will
    // appear in the response body, like:
    // nns_root_in_flight_proxied_canister_call_count{method_name="canister_status",caller="...",callee="..."} 1
    assert!(!response_body.contains("nns_root_in_flight_proxied_canister_call_count{method_name="));
}
