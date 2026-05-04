use crate::common::EXPECTED_SNS_CREATION_FEE;
use canister_test::Project;
use common::set_up_state_machine_with_nns;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, SNS_WASM_CANISTER_ID};
use ic_nns_test_utils::{
    sns_wasm,
    sns_wasm::{add_dummy_wasms_to_sns_wasms, test_wasm, wasm_map_to_sns_version},
};
use ic_sns_init::pb::v1::SnsInitPayload;
use ic_sns_wasm::pb::v1::{GetNextSnsVersionRequest, SnsCanisterType, SnsUpgrade, SnsVersion};

pub mod common;

/// Add WASMs, perform a canister upgrade, then assert that the added WASMs and upgrade
/// path are still available
#[test]
fn test_sns_wasm_upgrade() {
    let sns_wasm_wasm = Project::cargo_bin_maybe_from_env("sns-wasm-canister", &[]);

    let machine = set_up_state_machine_with_nns();

    // Add cycles to the SNS-W canister to deploy an SNS.
    machine.add_cycles(SNS_WASM_CANISTER_ID, EXPECTED_SNS_CREATION_FEE);

    let types_to_wasms_one = add_dummy_wasms_to_sns_wasms(&machine, None);
    let types_to_wasms_two = add_dummy_wasms_to_sns_wasms(&machine, Some(1));

    let first_version = wasm_map_to_sns_version(&types_to_wasms_one);

    let first_gov_wasm_hash = types_to_wasms_one
        .get(&SnsCanisterType::Governance)
        .unwrap()
        .sha256_hash();

    // Insert custom path
    let custom_version = SnsVersion {
        governance_wasm_hash: types_to_wasms_two
            .get(&SnsCanisterType::Governance)
            .unwrap()
            .sha256_hash()
            .to_vec(),
        ..first_version.clone()
    };

    // This path dead-ends, but we are only checking storage persistence
    let custom_paths = vec![SnsUpgrade {
        current_version: Some(first_version.clone()),
        next_version: Some(custom_version),
    }];

    // Next we deploy an SNS so that we can add a custom path for it.

    let sns_init_payload = SnsInitPayload {
        dapp_canisters: None,
        ..SnsInitPayload::with_valid_values_for_testing_post_execution()
    };

    let sns_1_response = sns_wasm::deploy_new_sns(
        &machine,
        GOVERNANCE_CANISTER_ID,
        SNS_WASM_CANISTER_ID,
        sns_init_payload,
    );
    assert_eq!(sns_1_response.error, None);

    let sns_1 = sns_1_response.canisters.unwrap();

    sns_wasm::insert_upgrade_path_entries_via_proposal(
        &machine,
        custom_paths,
        Some(sns_1.governance()),
    );

    // Ensure the wasm is correct before upgrade
    let get_wasm_response =
        sns_wasm::get_wasm(&machine, SNS_WASM_CANISTER_ID, &first_gov_wasm_hash);
    assert_eq!(
        types_to_wasms_one
            .get(&SnsCanisterType::Governance)
            .cloned()
            .unwrap(),
        get_wasm_response.wasm.unwrap()
    );

    machine
        .upgrade_canister(SNS_WASM_CANISTER_ID, sns_wasm_wasm.clone().bytes(), vec![])
        .unwrap();

    // Ensure the basic wasm response is the same after upgrade
    let get_wasm_response =
        sns_wasm::get_wasm(&machine, SNS_WASM_CANISTER_ID, &first_gov_wasm_hash);
    assert_eq!(
        types_to_wasms_one
            .get(&SnsCanisterType::Governance)
            .cloned()
            .unwrap(),
        get_wasm_response.wasm.unwrap()
    );

    // Assert the upgrade path is retained after the upgrade
    let next_version_response = sns_wasm::get_next_sns_version(
        &machine,
        SNS_WASM_CANISTER_ID,
        GetNextSnsVersionRequest {
            current_version: Some(first_version.clone()),
            governance_canister_id: None,
        },
    );
    let expected_next_version = SnsVersion {
        root_wasm_hash: types_to_wasms_two
            .get(&SnsCanisterType::Root)
            .unwrap()
            .sha256_hash()
            .to_vec(),
        ..wasm_map_to_sns_version(&types_to_wasms_one)
    };
    assert_eq!(next_version_response, expected_next_version.into());

    // Assert the custom upgrade path is retained after the upgrade
    let next_version_response = sns_wasm::get_next_sns_version(
        &machine,
        SNS_WASM_CANISTER_ID,
        GetNextSnsVersionRequest {
            current_version: Some(first_version),
            governance_canister_id: Some(sns_1.governance().into()),
        },
    );
    let expected_next_version = SnsVersion {
        governance_wasm_hash: types_to_wasms_two
            .get(&SnsCanisterType::Governance)
            .unwrap()
            .sha256_hash()
            .to_vec(),
        ..wasm_map_to_sns_version(&types_to_wasms_one)
    };
    assert_eq!(next_version_response, expected_next_version.into());

    // Assert that a new WASM can be added after the upgrade
    let sns_wasm2 = test_wasm(SnsCanisterType::Ledger, Some(50));
    let expected_hash2 = sns_wasm2.sha256_hash();

    let get_wasm_response2 = sns_wasm::get_wasm(&machine, SNS_WASM_CANISTER_ID, &expected_hash2);
    assert!(get_wasm_response2.wasm.is_none());

    sns_wasm::add_wasm_via_proposal(&machine, sns_wasm2);

    // Assert that this WASM can be retrieved after upgrade
    machine
        .upgrade_canister(SNS_WASM_CANISTER_ID, sns_wasm_wasm.bytes(), vec![])
        .unwrap();

    let get_wasm_response3 = sns_wasm::get_wasm(&machine, SNS_WASM_CANISTER_ID, &expected_hash2);
    assert!(get_wasm_response3.wasm.is_some());
    assert_eq!(
        expected_hash2,
        get_wasm_response3.wasm.unwrap().sha256_hash()
    );
}
