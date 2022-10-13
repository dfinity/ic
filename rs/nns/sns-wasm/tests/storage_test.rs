use ic_nns_constants::SNS_WASM_CANISTER_ID;
use ic_nns_test_utils::sns_wasm;
use ic_nns_test_utils::sns_wasm::smallest_valid_wasm;
use ic_sns_wasm::pb::v1::SnsVersion;
pub mod common;
use common::set_up_state_machine_with_nns;

#[test]
fn test_basic_storage() {
    let machine = set_up_state_machine_with_nns(vec![]);

    let sns_wasm = smallest_valid_wasm();
    let expected_hash = sns_wasm.sha256_hash();

    // Ensure it is not aleady there
    let get_wasm_response = sns_wasm::get_wasm(&machine, SNS_WASM_CANISTER_ID, &expected_hash);
    assert!(get_wasm_response.wasm.is_none());

    sns_wasm::add_wasm_via_proposal(&machine, sns_wasm, &expected_hash);

    let get_wasm_response = sns_wasm::get_wasm(&machine, SNS_WASM_CANISTER_ID, &expected_hash);
    assert!(get_wasm_response.wasm.is_some());
    assert_eq!(expected_hash, get_wasm_response.wasm.unwrap().sha256_hash());

    // Assert the upgrade path was also updated
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
}
