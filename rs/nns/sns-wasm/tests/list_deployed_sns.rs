use crate::common::EXPECTED_SNS_CREATION_FEE;
use canister_test::Project;
use common::set_up_state_machine_with_nns;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, SNS_WASM_CANISTER_ID};
use ic_nns_test_utils::sns_wasm;
use ic_sns_init::pb::v1::SnsInitPayload;
use ic_sns_wasm::{
    pb::v1::{DeployedSns, ListDeployedSnsesResponse},
    sns_wasm::assert_unique_canister_ids,
};

pub mod common;

#[test]
fn list_deployed_snses_lists_created_sns_instances() {
    let wasm = Project::cargo_bin_maybe_from_env("sns-wasm-canister", &[]);

    let machine = set_up_state_machine_with_nns();

    sns_wasm::add_dummy_wasms_to_sns_wasms(&machine, None);

    // Add cycles to the SNS-W canister to deploy two SNSes.
    machine.add_cycles(SNS_WASM_CANISTER_ID, EXPECTED_SNS_CREATION_FEE * 2);

    let sns_init_payload = SnsInitPayload {
        dapp_canisters: None,
        ..SnsInitPayload::with_valid_values_for_testing_post_execution()
    };

    let sns_1 = {
        let response = sns_wasm::deploy_new_sns(
            &machine,
            GOVERNANCE_CANISTER_ID,
            SNS_WASM_CANISTER_ID,
            sns_init_payload.clone(),
        );
        assert_eq!(response.error, None);
        response.canisters.unwrap()
    };

    let sns_2 = {
        let response = sns_wasm::deploy_new_sns(
            &machine,
            GOVERNANCE_CANISTER_ID,
            SNS_WASM_CANISTER_ID,
            sns_init_payload,
        );
        assert_eq!(response.error, None);
        response.canisters.unwrap()
    };

    // Assert that canister IDs are unique.
    assert_unique_canister_ids(&sns_1, &sns_2);

    // Also check that deployed SNSes are persisted across upgrades
    machine
        .upgrade_canister(SNS_WASM_CANISTER_ID, wasm.bytes(), vec![])
        .unwrap();

    let response = sns_wasm::list_deployed_snses(&machine, SNS_WASM_CANISTER_ID);

    assert_eq!(
        response,
        ListDeployedSnsesResponse {
            instances: vec![DeployedSns::from(sns_1), DeployedSns::from(sns_2),]
        }
    );
}
