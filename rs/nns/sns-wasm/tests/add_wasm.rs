use common::{install_sns_wasm, set_up_state_machine_with_nns};
use ic_nns_constants::SNS_WASM_CANISTER_ID;
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    sns_wasm,
    sns_wasm::{add_wasm, add_wasm_via_proposal, build_root_sns_wasm},
    state_test_helpers,
};
use ic_sns_wasm::pb::v1::{add_wasm_response, SnsWasmError};
use ic_state_machine_tests::StateMachine;

pub mod common;

#[test]
fn test_sns_wasms_can_be_added_via_nns_proposal() {
    let machine = set_up_state_machine_with_nns();

    let root_wasm = build_root_sns_wasm();
    let root_hash = root_wasm.sha256_hash();
    add_wasm_via_proposal(&machine, root_wasm.clone());

    let response = sns_wasm::get_wasm(&machine, SNS_WASM_CANISTER_ID, &root_hash);
    let sns_wasm = response.wasm.unwrap();
    assert_eq!(sns_wasm, root_wasm)
}

#[test]
fn test_add_wasm_cannot_be_called_directly() {
    let machine = set_up_state_machine_with_nns();

    let root_wasm = build_root_sns_wasm();
    let root_hash = root_wasm.sha256_hash();
    let response = add_wasm(&machine, SNS_WASM_CANISTER_ID, root_wasm, &root_hash);

    assert_eq!(
        response.result.unwrap(),
        add_wasm_response::Result::Error(SnsWasmError {
            message: "add_wasm can only be called by NNS Governance".into()
        })
    );
}

#[test]
fn test_add_wasm_can_be_called_directly_if_access_controls_are_disabled() {
    state_test_helpers::reduce_state_machine_logging_unless_env_set();
    let machine = StateMachine::new();

    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_sns_dedicated_subnets(machine.get_subnet_ids())
        .with_sns_wasm_access_controls(false)
        .build();

    let sns_wasm_canister_id = install_sns_wasm(&machine, &nns_init_payload);

    let root_wasm = build_root_sns_wasm();
    let root_hash = root_wasm.sha256_hash();
    let response = add_wasm(&machine, sns_wasm_canister_id, root_wasm, &root_hash);

    assert_eq!(
        response.result.unwrap(),
        add_wasm_response::Result::Hash(root_hash.to_vec())
    );
}
