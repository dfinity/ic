use canister_test::Project;
use ic_nns_constants::SNS_WASM_CANISTER_ID;
use ic_nns_test_utils::sns_wasm;
use ic_nns_test_utils::sns_wasm::{smallest_valid_wasm, test_wasm1};
use ic_sns_wasm::pb::v1::SnsVersion;
pub mod common;
use common::set_up_state_machine_with_nns;

/// Add WASMs, perform a canister upgrade, then assert that the added WASMs and upgrade
/// path are still available
#[test]
fn test_sns_wasm_upgrade() {
    let wasm = Project::cargo_bin_maybe_from_env("sns-wasm-canister", &[]);

    let machine = set_up_state_machine_with_nns();

    let sns_wasm = smallest_valid_wasm();
    let expected_hash = sns_wasm.sha256_hash();

    // Ensure the WASM is not aleady there
    let get_wasm_response = sns_wasm::get_wasm(&machine, SNS_WASM_CANISTER_ID, &expected_hash);
    assert!(get_wasm_response.wasm.is_none());

    // Ensure we get the expected response
    sns_wasm::add_wasm_via_proposal(&machine, sns_wasm, &expected_hash);

    machine
        .upgrade_canister(SNS_WASM_CANISTER_ID, wasm.clone().bytes(), vec![])
        .unwrap();

    let get_wasm_response = sns_wasm::get_wasm(&machine, SNS_WASM_CANISTER_ID, &expected_hash);
    assert!(get_wasm_response.wasm.is_some());
    assert_eq!(expected_hash, get_wasm_response.wasm.unwrap().sha256_hash());

    // Assert the upgrade path is retained after the upgrade
    let next_version_response = sns_wasm::get_next_sns_version(
        &machine,
        SNS_WASM_CANISTER_ID,
        SnsVersion::default().into(),
    );
    let expected_next_version = SnsVersion {
        governance_wasm_hash: expected_hash.to_vec(),
        ..Default::default()
    };
    assert_eq!(next_version_response, expected_next_version.into());

    // Assert that a new WASM can be added after the upgrade
    let sns_wasm2 = test_wasm1();
    let expected_hash2 = sns_wasm2.sha256_hash();

    let get_wasm_response2 = sns_wasm::get_wasm(&machine, SNS_WASM_CANISTER_ID, &expected_hash2);
    assert!(get_wasm_response2.wasm.is_none());

    sns_wasm::add_wasm_via_proposal(&machine, sns_wasm2, &expected_hash2);

    // Assert that this WASM can be retrieved after upgrade
    machine
        .upgrade_canister(SNS_WASM_CANISTER_ID, wasm.bytes(), vec![])
        .unwrap();

    let get_wasm_response3 = sns_wasm::get_wasm(&machine, SNS_WASM_CANISTER_ID, &expected_hash2);
    assert!(get_wasm_response3.wasm.is_some());
    assert_eq!(
        expected_hash2,
        get_wasm_response3.wasm.unwrap().sha256_hash()
    );
}
