use candid::Encode;
use canister_test::Project;
use ic_nns_test_utils::sns_wasm;
use ic_nns_test_utils::sns_wasm::{smallest_valid_wasm, test_wasm1};
use ic_nns_test_utils::state_test_helpers::create_canister;
use ic_sns_wasm::init::SnsWasmCanisterInitPayload;
use ic_sns_wasm::pb::v1::{add_wasm_response, AddWasmResponse, SnsVersion};
use ic_state_machine_tests::StateMachine;

/// Add WASMs, perform a canister upgrade, then assert that the added WASMs and upgrade
/// path are still available
#[test]
fn test_sns_wasm_upgrade() {
    let machine = StateMachine::new();
    let wasm = Project::cargo_bin_maybe_use_path_relative_to_rs(
        "nns/sns-wasm",
        "sns-wasm-canister",
        &[], // features
    );

    // Step 1.b: Build and install canister.
    let sns_wasm_id = create_canister(
        &machine,
        wasm.clone(),
        Some(
            Encode!(&SnsWasmCanisterInitPayload {
                sns_subnet_ids: vec![]
            })
            .unwrap(),
        ),
        None,
    );

    let sns_wasm = smallest_valid_wasm();
    let expected_hash = sns_wasm.sha256_hash();

    // Ensure the WASM is not aleady there
    let get_wasm_response = sns_wasm::get_wasm(&machine, sns_wasm_id, &expected_hash);
    assert!(get_wasm_response.wasm.is_none());

    // Ensure we get the expected response
    let add_wasm_response = sns_wasm::add_wasm(&machine, sns_wasm_id, sns_wasm, &expected_hash);
    assert_eq!(
        add_wasm_response,
        AddWasmResponse {
            result: Some(add_wasm_response::Result::Hash(expected_hash.to_vec()))
        }
    );

    machine
        .upgrade_canister(sns_wasm_id, wasm.clone().bytes(), vec![])
        .unwrap();

    let get_wasm_response = sns_wasm::get_wasm(&machine, sns_wasm_id, &expected_hash);
    assert!(get_wasm_response.wasm.is_some());
    assert_eq!(expected_hash, get_wasm_response.wasm.unwrap().sha256_hash());

    // Assert the upgrade path is retained after the upgrade
    let next_version_response =
        sns_wasm::get_next_sns_version(&machine, sns_wasm_id, SnsVersion::default().into());
    let expected_next_version = SnsVersion {
        governance_wasm_hash: expected_hash.to_vec(),
        ..Default::default()
    };
    assert_eq!(next_version_response, expected_next_version.into());

    // Assert that a new WASM can be added after the upgrade
    let sns_wasm2 = test_wasm1();
    let expected_hash2 = sns_wasm2.sha256_hash();

    let get_wasm_response2 = sns_wasm::get_wasm(&machine, sns_wasm_id, &expected_hash2);
    assert!(get_wasm_response2.wasm.is_none());

    let add_wasm_response = sns_wasm::add_wasm(&machine, sns_wasm_id, sns_wasm2, &expected_hash2);
    assert_eq!(
        add_wasm_response,
        AddWasmResponse {
            result: Some(add_wasm_response::Result::Hash(expected_hash2.to_vec()))
        }
    );

    // Assert that this WASM can be retrieved after upgrade
    machine
        .upgrade_canister(sns_wasm_id, wasm.bytes(), vec![])
        .unwrap();

    let get_wasm_response3 = sns_wasm::get_wasm(&machine, sns_wasm_id, &expected_hash2);
    assert!(get_wasm_response3.wasm.is_some());
    assert_eq!(
        expected_hash2,
        get_wasm_response3.wasm.unwrap().sha256_hash()
    );
}
