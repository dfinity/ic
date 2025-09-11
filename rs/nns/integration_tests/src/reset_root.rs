use ic_crypto_sha2::Sha256;
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_PRINCIPAL};
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::{LIFELINE_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_governance_api::{
    NnsFunction, manage_neuron_response::Command,
    proposal_submission_helpers::create_external_update_proposal_candid,
};
use ic_nns_test_utils::{
    common::{NnsInitPayloadsBuilder, build_root_wasm, modify_wasm_bytes},
    governance::HardResetNnsRootToVersionPayload,
    state_test_helpers::{
        nns_governance_make_proposal, nns_wait_for_proposal_execution, setup_nns_canisters,
        state_machine_builder_for_nns_tests, update_with_sender,
    },
};

#[test]
fn test_reset_root_with_governance_proposal() {
    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    // First, see what the canister hash is for root
    let root_status = state_machine
        .canister_status_as(LIFELINE_CANISTER_ID.into(), ROOT_CANISTER_ID)
        .unwrap()
        .unwrap();
    let root_version = root_status.module_hash().unwrap();

    // Execute proposal
    let new_root = modify_wasm_bytes(&build_root_wasm().bytes(), 42);

    let new_root_version = Sha256::hash(&new_root);

    assert_ne!(root_version, new_root_version);

    let neuron_id = NeuronId {
        id: TEST_NEURON_1_ID,
    };

    let proposal = create_external_update_proposal_candid(
        "Tea. Earl Grey. Hot.",
        "Make It So",
        "",
        NnsFunction::HardResetNnsRootToVersion,
        HardResetNnsRootToVersionPayload {
            wasm_module: new_root,
            init_arg: vec![],
        },
    );

    let response = nns_governance_make_proposal(
        &state_machine,
        *TEST_NEURON_1_OWNER_PRINCIPAL,
        neuron_id,
        &proposal,
    );

    let proposal_id = match response.command.unwrap() {
        Command::MakeProposal(response) => response.proposal_id.unwrap(),
        other_response => {
            panic!("Response not expected MakeProposal, instead: {other_response:?} ")
        }
    };

    nns_wait_for_proposal_execution(&state_machine, proposal_id.id);

    let root_status = state_machine
        .canister_status_as(LIFELINE_CANISTER_ID.into(), ROOT_CANISTER_ID)
        .unwrap()
        .unwrap();
    let root_version: [u8; 32] = root_status.module_hash().unwrap().try_into().unwrap();
    // Assert the root canister was upgraded
    assert_eq!(new_root_version, root_version);
}

#[test]
fn test_other_controllers_cannot_reset_root() {
    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    // First, see what the canister hash is for root
    let root_status = state_machine
        .canister_status_as(LIFELINE_CANISTER_ID.into(), ROOT_CANISTER_ID)
        .unwrap()
        .unwrap();
    let root_version = root_status.module_hash().unwrap();

    // Execute proposal
    let new_root = modify_wasm_bytes(&build_root_wasm().bytes(), 42);

    let new_root_version = Sha256::hash(&new_root);

    assert_ne!(root_version, new_root_version);

    let payload = HardResetNnsRootToVersionPayload {
        wasm_module: new_root,
        init_arg: vec![],
    };

    let response: Result<(), String> = update_with_sender(
        &state_machine,
        LIFELINE_CANISTER_ID,
        "hard_reset_root_to_version",
        payload,
        *TEST_NEURON_1_OWNER_PRINCIPAL,
    );

    assert!(response.is_err());
    assert!(response.unwrap_err().contains(
        "Error from Canister rno2w-sqaaa-aaaaa-aaacq-cai: Canister called `ic0.trap` with message: 'assertion failed at lifeline.mo",
    ));
}
