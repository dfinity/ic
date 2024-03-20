use candid::Encode;
use canister_test::Project;
use common::set_up_state_machine_with_nns;
use ic_nns_constants::SNS_WASM_CANISTER_ID;
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    sns_wasm::{get_sns_subnet_ids, update_sns_subnet_list, update_sns_subnet_list_via_proposal},
    state_test_helpers::{self, create_canister},
};
use ic_sns_wasm::pb::v1::UpdateSnsSubnetListRequest;
use ic_state_machine_tests::StateMachine;
use ic_types::PrincipalId;

pub mod common;

#[test]
fn test_update_sns_subnet_list_can_be_called_via_nns_proposal() {
    let machine = set_up_state_machine_with_nns();

    let principal = PrincipalId::new_user_test_id(1);
    let request = UpdateSnsSubnetListRequest {
        sns_subnet_ids_to_add: vec![principal],
        sns_subnet_ids_to_remove: vec![],
    };
    update_sns_subnet_list_via_proposal(&machine, &request);

    let response = get_sns_subnet_ids(&machine, SNS_WASM_CANISTER_ID);
    assert!(response.sns_subnet_ids.contains(&principal));
}

#[test]
fn test_update_sns_subnet_list_cannot_be_called_directly() {
    // We don't want the underlying warnings of the StateMachine
    state_test_helpers::reduce_state_machine_logging_unless_env_set();
    let machine = StateMachine::new();

    let nns_init_payload = NnsInitPayloadsBuilder::new().build();

    let sns_wasm_bin = Project::cargo_bin_maybe_from_env("sns-wasm-canister", &[]);

    let sns_wasm_canister_id = create_canister(
        &machine,
        sns_wasm_bin,
        Some(Encode!(&nns_init_payload.sns_wasms).unwrap()),
        None,
    );

    let principal = PrincipalId::new_user_test_id(1);
    let request = UpdateSnsSubnetListRequest {
        sns_subnet_ids_to_add: vec![principal],
        sns_subnet_ids_to_remove: vec![],
    };
    let response1 = update_sns_subnet_list(&machine, sns_wasm_canister_id, &request);
    assert!(response1.error.is_some());

    let response2 = get_sns_subnet_ids(&machine, sns_wasm_canister_id);
    assert!(!response2.sns_subnet_ids.contains(&principal));
}
