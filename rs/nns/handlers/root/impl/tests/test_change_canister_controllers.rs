use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord,
    canister_status::CanisterStatusResult,
    management_canister_client::{
        MockManagementCanisterClient, MockManagementCanisterClientCall,
        MockManagementCanisterClientReply,
    },
    update_settings::{CanisterSettings, UpdateSettings},
};
use ic_nns_constants::{ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID};
use ic_nns_handler_root::canister_management::change_canister_controllers;
use ic_nns_handler_root_interface::{
    ChangeCanisterControllersRequest, ChangeCanisterControllersResponse,
    ChangeCanisterControllersResult,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    state_test_helpers::{
        set_controllers, set_up_universal_canister, setup_nns_canisters, update_with_sender,
    },
};
use ic_state_machine_tests::StateMachine;
use maplit::btreeset;
use std::collections::BTreeSet;

#[tokio::test]
async fn test_change_canister_controllers_handles_replica_errors() {
    let target_canister_id = CanisterId::from_u64(42).get();
    let expected_replica_error_code = 1_i32;
    let expected_replica_error_description = "ERROR!".to_string();

    // Create a shared MockManagementCanisterClient, and load it with the one reply
    // the test expects to be served.
    let mut client =
        MockManagementCanisterClient::new(vec![MockManagementCanisterClientReply::UpdateSettings(
            Err((
                expected_replica_error_code,
                expected_replica_error_description.clone(),
            )),
        )]);

    let response = change_canister_controllers(
        ChangeCanisterControllersRequest {
            target_canister_id,
            new_controllers: vec![ROOT_CANISTER_ID.get()],
        },
        &mut client,
    )
    .await;

    match response.change_canister_controllers_result {
        ChangeCanisterControllersResult::Ok(_) => {
            panic!("Expected change_canister_controllers to fail")
        }
        ChangeCanisterControllersResult::Err(error) => {
            assert_eq!(error.code, Some(expected_replica_error_code));
            assert_eq!(error.description, expected_replica_error_description);
        }
    }

    // There should be one call to the ManagementCanisterClient now
    let mut client_calls = client.get_calls_snapshot();
    assert_eq!(client_calls.len(), 1);
    assert_eq!(
        client_calls.pop().unwrap(),
        MockManagementCanisterClientCall::UpdateSettings(UpdateSettings {
            canister_id: target_canister_id,
            settings: CanisterSettings {
                controllers: Some(vec![ROOT_CANISTER_ID.get()]),
                ..Default::default()
            },
            sender_canister_version: None,
        })
    )
}

/// Test that the NNS root canister integrates correctly with the management canister via
/// the change_canister_controllers API.
#[test]
fn test_change_canister_controllers_integrates_with_management_canister() {
    // Setup the test
    let nns_init_payload = NnsInitPayloadsBuilder::new().build();
    let machine = StateMachine::new();
    setup_nns_canisters(&machine, nns_init_payload);

    // Create a test canister for NNS root to own
    let universal = set_up_universal_canister(&machine, None);
    set_controllers(
        &machine,
        PrincipalId::new_anonymous(),
        universal,
        vec![ROOT_CANISTER_ID.get()],
    );

    // Get the status of the universal canister and check its current controllers
    let status: CanisterStatusResult = update_with_sender(
        &machine,
        ROOT_CANISTER_ID,
        "canister_status",
        CanisterIdRecord::from(universal),
        PrincipalId::new_anonymous(),
    )
    .unwrap();
    assert_eq!(status.settings.controllers, vec![ROOT_CANISTER_ID.get()]);

    // Create a test canister id to add as a controller
    let test_canister_id = CanisterId::from_u64(1);

    // calls to change_canister_controllers from unauthorized callers should fail
    let unauthorized_caller = CanisterId::from_u64(1000).get();

    let err = update_with_sender::<_, ChangeCanisterControllersResponse>(
        &machine,
        ROOT_CANISTER_ID,
        "change_canister_controllers",
        ChangeCanisterControllersRequest {
            target_canister_id: universal.get(),
            new_controllers: vec![ROOT_CANISTER_ID.get(), test_canister_id.get()],
        },
        unauthorized_caller,
    )
    .unwrap_err();
    assert!(err.contains("Only the SNS-W canister is allowed to call this method"));

    // calls to change_canister_controllers from SNS-W should succeed
    let response: ChangeCanisterControllersResponse = update_with_sender(
        &machine,
        ROOT_CANISTER_ID,
        "change_canister_controllers",
        ChangeCanisterControllersRequest {
            target_canister_id: universal.get(),
            new_controllers: vec![ROOT_CANISTER_ID.get(), test_canister_id.get()],
        },
        SNS_WASM_CANISTER_ID.get(),
    )
    .unwrap();

    match response.change_canister_controllers_result {
        ChangeCanisterControllersResult::Ok(_result) => (),
        ChangeCanisterControllersResult::Err(error) => {
            panic!(
                "Expected change_canister_controllers to return a successful response. Instead found {error:?}"
            );
        }
    }

    // Get the status of the universal canister and check its controllers have been updated
    let status: CanisterStatusResult = update_with_sender(
        &machine,
        ROOT_CANISTER_ID,
        "canister_status",
        CanisterIdRecord::from(universal),
        PrincipalId::new_anonymous(),
    )
    .unwrap();

    let actual_controllers: BTreeSet<PrincipalId> =
        status.settings.controllers.iter().cloned().collect();
    let expected_controllers = btreeset! {ROOT_CANISTER_ID.get(), test_canister_id.get()};

    assert_eq!(actual_controllers, expected_controllers);
}
