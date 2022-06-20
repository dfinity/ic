use candid::Encode;
use canister_test::Project;
use ic_nns_test_utils::sns_wasm;
use ic_nns_test_utils::sns_wasm::smallest_valid_wasm;
use ic_nns_test_utils::state_test_helpers::create_canister;
use ic_sns_wasm::init::SnsWasmCanisterInitPayload;
use ic_sns_wasm::pb::v1::add_wasm_response::AddWasmOk;
use ic_sns_wasm::pb::v1::{add_wasm_response, AddWasmResponse};
use ic_state_machine_tests::StateMachine;

#[test]
fn test_basic_storage() {
    let machine = StateMachine::new();
    let wasm = Project::cargo_bin_maybe_use_path_relative_to_rs(
        "nns/sns-wasm",
        "sns-wasm-canister",
        &[], // features
    );
    // Step 1.b: Build and install canister.
    let sns_wasm_id = create_canister(
        &machine,
        wasm,
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

    // Ensure it is not aleady there
    let get_wasm_response = sns_wasm::get_wasm(&machine, sns_wasm_id, &expected_hash);
    assert!(get_wasm_response.wasm.is_none());

    // Ensure we get the expected response
    let add_wasm_response = sns_wasm::add_wasm(&machine, sns_wasm_id, sns_wasm, &expected_hash);
    assert_eq!(
        add_wasm_response,
        AddWasmResponse {
            result: Some(add_wasm_response::Result::Ok(AddWasmOk {
                hash: expected_hash.to_vec()
            }))
        }
    );

    let get_wasm_response = sns_wasm::get_wasm(&machine, sns_wasm_id, &expected_hash);
    assert!(get_wasm_response.wasm.is_some());
    assert_eq!(expected_hash, get_wasm_response.wasm.unwrap().sha256_hash());
}
