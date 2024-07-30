use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_nns_governance::pb::v1::{
    manage_neuron_response::Command, proposal::Action, update_canister_settings::CanisterSettings,
    Proposal, UpdateCanisterSettings,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    neuron_helpers::get_neuron_1,
    state_test_helpers::{
        nns_governance_make_proposal, nns_wait_for_proposal_failure, setup_nns_canisters,
        state_machine_builder_for_nns_tests,
    },
};

#[test]
fn test_update_canister_settings() {
    // Step 1: Set up the NNS canisters and get the neuron.
    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);
    let n1 = get_neuron_1();

    // Step 2: Make a proposal to update settings of the registry canister.
    let propose_response = nns_governance_make_proposal(
        &state_machine,
        n1.principal_id,
        n1.neuron_id,
        &Proposal {
            title: Some("Update canister settings".to_string()),
            action: Some(Action::UpdateCanisterSettings(UpdateCanisterSettings {
                canister_id: Some(REGISTRY_CANISTER_ID.get()),
                settings: Some(CanisterSettings {
                    memory_allocation: Some(1 << 32),
                    ..Default::default()
                }),
            })),
            ..Default::default()
        },
    );
    let proposal_id = match propose_response.command.unwrap() {
        Command::MakeProposal(response) => response.proposal_id.unwrap(),
        _ => panic!("Propose didn't return MakeProposal"),
    };

    // Step 3: make sure it fails to execute since it's fully implemented yet.
    // TODO(NNS1-2522): test that the proposal is executed successfully after it's fully
    // implemented.
    nns_wait_for_proposal_failure(&state_machine, proposal_id.id);
}
