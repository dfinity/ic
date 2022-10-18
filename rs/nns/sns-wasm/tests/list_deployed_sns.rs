use canister_test::Project;
use common::set_up_state_machine_with_nns;
use ic_base_types::CanisterId;
use ic_nns_constants::SNS_WASM_CANISTER_ID;
use ic_nns_test_utils::sns_wasm;
use ic_nns_test_utils::state_test_helpers::set_up_universal_canister;
use ic_sns_init::pb::v1::SnsInitPayload;
use ic_sns_wasm::{
    pb::v1::{DeployedSns, ListDeployedSnsesResponse},
    sns_wasm::assert_unique_canister_ids,
};
use ic_types::Cycles;

pub mod common;

#[test]
fn list_deployed_snses_lists_created_sns_instances() {
    let wasm = Project::cargo_bin_maybe_from_env("sns-wasm-canister", &[]);

    // The canister id the wallet canister will have.
    let wallet_canister_id = CanisterId::from_u64(11);

    let machine = set_up_state_machine_with_nns(vec![wallet_canister_id.into()]);

    // Enough cycles for 2 SNS deploys
    let wallet_canister =
        set_up_universal_canister(&machine, Some(Cycles::new(50_000_000_000_000 * 2)));

    sns_wasm::add_dummy_wasms_to_sns_wasms(&machine);

    let sns_1 = sns_wasm::deploy_new_sns(
        &machine,
        wallet_canister,
        SNS_WASM_CANISTER_ID,
        SnsInitPayload::with_valid_values_for_testing(),
        50_000_000_000_000,
    )
    .canisters
    .unwrap();

    let sns_2 = sns_wasm::deploy_new_sns(
        &machine,
        wallet_canister,
        SNS_WASM_CANISTER_ID,
        SnsInitPayload::with_valid_values_for_testing(),
        50_000_000_000_000,
    )
    .canisters
    .unwrap();

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
