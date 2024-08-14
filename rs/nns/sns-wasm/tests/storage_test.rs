use common::set_up_state_machine_with_nns;
use ic_nns_constants::SNS_WASM_CANISTER_ID;
use ic_nns_test_utils::{sns_wasm, sns_wasm::test_wasm};
use ic_sns_wasm::pb::v1::{GetNextSnsVersionRequest, SnsCanisterType, SnsVersion};

pub mod common;

#[test]
fn test_basic_storage() {
    let machine = set_up_state_machine_with_nns();

    let sns_wasm = test_wasm(SnsCanisterType::Governance, None);
    let expected_hash = sns_wasm.sha256_hash();

    // Ensure it is not already there
    let get_wasm_response = sns_wasm::get_wasm(&machine, SNS_WASM_CANISTER_ID, &expected_hash);
    assert!(get_wasm_response.wasm.is_none());

    sns_wasm::add_wasm_via_proposal(&machine, sns_wasm);

    let get_wasm_response = sns_wasm::get_wasm(&machine, SNS_WASM_CANISTER_ID, &expected_hash);
    assert!(get_wasm_response.wasm.is_some());
    assert_eq!(expected_hash, get_wasm_response.wasm.unwrap().sha256_hash());

    // Assert the upgrade path was also updated
    let next_version_response = sns_wasm::get_next_sns_version(
        &machine,
        SNS_WASM_CANISTER_ID,
        GetNextSnsVersionRequest {
            current_version: Some(SnsVersion::default()),
            governance_canister_id: None,
        },
    );
    let expected_next_version = SnsVersion {
        governance_wasm_hash: expected_hash.to_vec(),
        ..Default::default()
    };
    assert_eq!(next_version_response, expected_next_version.into());
}
