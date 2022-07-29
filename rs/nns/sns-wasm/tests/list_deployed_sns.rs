use canister_test::Project;
use ic_nns_test_utils::sns_wasm;
use ic_nns_test_utils::state_test_helpers::set_up_universal_canister;
use ic_sns_init::pb::v1::SnsInitPayload;
use ic_sns_wasm::pb::v1::{DeployedSns, ListDeployedSnsesResponse};
use ic_types::Cycles;
pub mod common;
use common::set_up_state_machine_with_nns;
use ic_nns_constants::SNS_WASM_CANISTER_ID;

#[test]
fn list_deployed_snses_lists_created_sns_instances() {
    let wasm = Project::cargo_bin_maybe_use_path_relative_to_rs(
        "nns/sns-wasm",
        "sns-wasm-canister",
        &[], // features
    );

    let machine = set_up_state_machine_with_nns();

    // Enough cycles for 2 SNS deploys
    let wallet_canister =
        set_up_universal_canister(&machine, Some(Cycles::new(50_000_000_000_000 * 2)));

    sns_wasm::add_dummy_wasms_to_sns_wasms(&machine);

    let root_1 = sns_wasm::deploy_new_sns(
        &machine,
        wallet_canister,
        SNS_WASM_CANISTER_ID,
        SnsInitPayload::with_valid_values_for_testing(),
        50_000_000_000_000,
    )
    .canisters
    .unwrap()
    .root;

    let root_2 = sns_wasm::deploy_new_sns(
        &machine,
        wallet_canister,
        SNS_WASM_CANISTER_ID,
        SnsInitPayload::with_valid_values_for_testing(),
        50_000_000_000_000,
    )
    .canisters
    .unwrap()
    .root;

    assert_ne!(root_1, root_2);

    // Also check that deployed SNSes are persisted across upgrades
    machine
        .upgrade_canister(SNS_WASM_CANISTER_ID, wasm.bytes(), vec![])
        .unwrap();

    let response = sns_wasm::list_deployed_snses(&machine, SNS_WASM_CANISTER_ID);

    assert_eq!(
        response,
        ListDeployedSnsesResponse {
            instances: vec![
                DeployedSns {
                    root_canister_id: root_1,
                },
                DeployedSns {
                    root_canister_id: root_2,
                },
            ]
        }
    );
}
