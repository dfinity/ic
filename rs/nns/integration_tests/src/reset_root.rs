use dfn_candid::candid_one;
use ic_crypto_sha2::Sha256;
use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_PRINCIPAL;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::{LIFELINE_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_governance::{
    init::TEST_NEURON_1_ID,
    {
        pb::v1::{manage_neuron_response::Command, NnsFunction},
        proposals::proposal_submission::create_external_update_proposal_candid,
    },
};
use ic_nns_test_utils::{
    common::{build_root_wasm, modify_wasm_bytes, NnsInitPayloadsBuilder},
    governance::HardResetNnsRootToVersionPayload,
    state_test_helpers::{
        nns_governance_make_proposal, nns_wait_for_proposal_execution, setup_nns_canisters,
        update_with_sender,
    },
};
use ic_state_machine_tests::StateMachine;

#[test]
fn test_reset_root_with_governance_proposal() {
    let mut state_machine = StateMachine::new();
    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    // First, see what the canister hash is for root
    let root_version = state_machine.module_hash(ROOT_CANISTER_ID).unwrap();

    // Execute proposal
    let new_root = modify_wasm_bytes(&build_root_wasm().bytes(), "yolo");

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
        &mut state_machine,
        *TEST_NEURON_1_OWNER_PRINCIPAL,
        neuron_id,
        &proposal,
    );

    let proposal_id = match response.command.unwrap() {
        Command::MakeProposal(response) => response.proposal_id.unwrap(),
        other_response => panic!(
            "Response not expected MakeProposal, instead: {:?} ",
            other_response
        ),
    };

    nns_wait_for_proposal_execution(&mut state_machine, proposal_id.id);

    // Assert the root canister was upgraded
    assert_eq!(
        new_root_version,
        state_machine.module_hash(ROOT_CANISTER_ID).unwrap()
    );
}

#[test]
fn test_other_controllers_cannot_reset_root() {
    let state_machine = StateMachine::new();
    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    // First, see what the canister hash is for root
    let root_version = state_machine.module_hash(ROOT_CANISTER_ID).unwrap();

    // Execute proposal
    let new_root = modify_wasm_bytes(&build_root_wasm().bytes(), "yolo");

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
        candid_one,
        payload,
        *TEST_NEURON_1_OWNER_PRINCIPAL,
    );

    assert!(response.is_err());
    assert!(response.unwrap_err().contains(
        "Canister rno2w-sqaaa-aaaaa-aaacq-cai trapped explicitly: assertion failed at lifeline.mo",
    ));
}
