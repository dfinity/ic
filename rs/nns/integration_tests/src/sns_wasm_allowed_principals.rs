use candid::{Decode, Encode};
use ic_base_types::PrincipalId;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, SNS_WASM_CANISTER_ID};
use ic_nns_test_utils::common::NnsInitPayloadsBuilder;
use ic_nns_test_utils::state_test_helpers::setup_nns_canisters;
use ic_sns_init::pb::v1::SnsInitPayload;
use ic_sns_wasm::pb::v1::{
    update_allowed_principals_response, DeployNewSnsRequest, DeployNewSnsResponse,
    GetAllowedPrincipalsRequest, GetAllowedPrincipalsResponse, UpdateAllowedPrincipalsRequest,
    UpdateAllowedPrincipalsResponse,
};
use ic_state_machine_tests::StateMachine;
use ic_types::ingress::WasmResult;

/// Integration test for the allowed_principals functionality in the sns_wasm canister.
///
/// The test consists of several steps:
/// - Set up NNS canisters, initially the list allowed_principals is empty.
/// - Query allowed_principals, verify is empty.
/// - Try deploying an SNS, verify it fails, as there is no principal allowed to do it.
/// - Try updating the allowed_principals field from a test principal. Verify it fails.
/// - Try updating the allowed_principals field from the Governance canister. Verify it works.
/// - Try deploying an SNS from the allowed principal, verify the fail is not related to the principal.
///
/// A more complete test of the deployment of an sns is done in
/// rs/nns/sns-wasm/tests/deploy_new_sns.rs
#[test]
fn test_sns_wasm_allowed_principals() {
    // The principal that will later be added to allowed_principals.
    let allowed_principal = PrincipalId::new_user_test_id(1879);

    let mut state_machine = StateMachine::new();
    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    let get_allowed_principals_response = get_sns_wasm_allowed_principals(&mut state_machine);
    assert!(get_allowed_principals_response
        .allowed_principals
        .is_empty());

    let deploy_new_sns_response = deploy_new_sns_as(&mut state_machine, allowed_principal);
    match deploy_new_sns_response.error {
        Some(sns_wasm_error) => assert!(sns_wasm_error
            .message
            .contains("Caller is not in allowed principals list. Cannot deploy an sns.")),
        _ => panic!("Err: deploy_new_sns response should be error."),
    }

    let update_allowed_principals_response = update_allowed_principals_as(
        &mut state_machine,
        allowed_principal,
        PrincipalId::new_user_test_id(1),
    );
    match update_allowed_principals_response.update_allowed_principals_result {
        Some(update_allowed_principals_response::UpdateAllowedPrincipalsResult::Error(sns_wasm_error)) => assert!(sns_wasm_error.message.contains("Only Governance can call update_allowed_principals")),
        _ => panic!("Err: update_allowed_principals response should be error when not called as the Governance canister.")
    }

    let update_allowed_principals_response = update_allowed_principals_as(
        &mut state_machine,
        allowed_principal,
        GOVERNANCE_CANISTER_ID.into(),
    );
    match update_allowed_principals_response.update_allowed_principals_result {
        Some(
            update_allowed_principals_response::UpdateAllowedPrincipalsResult::AllowedPrincipals(
                update_allowed_principals_result,
            ),
        ) => {
            assert_eq!(
                update_allowed_principals_result.allowed_principals,
                vec![allowed_principal]
            )
        }
        _ => panic!("Error when calling update_allowed_principals as the Governance canister."),
    }

    let get_allowed_principals_response = get_sns_wasm_allowed_principals(&mut state_machine);
    assert_eq!(
        get_allowed_principals_response.allowed_principals,
        vec![allowed_principal]
    );

    let deploy_new_sns_response = deploy_new_sns_as(&mut state_machine, allowed_principal);
    if let Some(sns_wasm_error) = deploy_new_sns_response.error {
        assert!(!sns_wasm_error
            .message
            .contains("Caller is not in allowed principals list. Cannot deploy an sns."));
    }
}

fn get_sns_wasm_allowed_principals(
    state_machine: &mut StateMachine,
) -> GetAllowedPrincipalsResponse {
    let result = state_machine
        .execute_ingress(
            SNS_WASM_CANISTER_ID,
            "get_allowed_principals",
            Encode!(&GetAllowedPrincipalsRequest {}).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!(
                "get_allowed_principals was rejected by the sns-wasm canister: {:#?}",
                reject
            )
        }
    };
    Decode!(&result, GetAllowedPrincipalsResponse).unwrap()
}

fn deploy_new_sns_as(
    state_machine: &mut StateMachine,
    sender: PrincipalId,
) -> DeployNewSnsResponse {
    let result = state_machine
        .execute_ingress_as(
            sender,
            SNS_WASM_CANISTER_ID,
            "deploy_new_sns",
            Encode!(&DeployNewSnsRequest {
                sns_init_payload: Some(SnsInitPayload::with_valid_values_for_testing()),
            })
            .unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!(
                "deploy_new_sns was rejected by the sns-wasm canister: {:#?}",
                reject
            )
        }
    };
    Decode!(&result, DeployNewSnsResponse).unwrap()
}

fn update_allowed_principals_as(
    state_machine: &mut StateMachine,
    added_principal_id: PrincipalId,
    sender: PrincipalId,
) -> UpdateAllowedPrincipalsResponse {
    let result = state_machine
        .execute_ingress_as(
            sender,
            SNS_WASM_CANISTER_ID,
            "update_allowed_principals",
            Encode!(&UpdateAllowedPrincipalsRequest {
                added_principals: vec![added_principal_id],
                removed_principals: vec![],
            })
            .unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!(
                "update_allowed_principals was rejected by the sns-wasm canister: {:#?}",
                reject
            )
        }
    };
    Decode!(&result, UpdateAllowedPrincipalsResponse).unwrap()
}
