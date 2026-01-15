use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_3_OWNER_PRINCIPAL,
};
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_governance_api::{
    MakeProposalRequest, Motion, ProposalActionRequest, manage_neuron_response::Command,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    state_test_helpers::{
        nns_create_super_powerful_neuron, nns_governance_get_proposal_info_as_anonymous,
        nns_governance_make_proposal, setup_nns_canisters, state_machine_builder_for_nns_tests,
    },
};
use ic_state_machine_tests::StateMachine;
use ic_types::PrincipalId;
use icp_ledger::Tokens;
use std::time::Duration;

fn make_motion_proposal(
    state_machine: &StateMachine,
    sender: PrincipalId,
    neuron_id: NeuronId,
) -> ProposalId {
    let response = nns_governance_make_proposal(
        state_machine,
        sender,
        neuron_id,
        &MakeProposalRequest {
            title: Some("Some title".to_string()),
            summary: "Some summary".to_string(),
            url: "".to_string(),
            action: Some(ProposalActionRequest::Motion(Motion {
                motion_text: "Motion text".to_string(),
            })),
        },
    );
    match response.command {
        Some(Command::MakeProposal(make_proposal_response)) => {
            make_proposal_response.proposal_id.unwrap()
        }
        _ => panic!("Failed to make motion proposal: {response:?}"),
    }
}

fn is_proposal_executed(state_machine: &StateMachine, proposal_id: ProposalId) -> bool {
    let proposal_info =
        nns_governance_get_proposal_info_as_anonymous(state_machine, proposal_id.id);
    proposal_info.executed_timestamp_seconds > 0
}

#[test]
fn test_proposal_no_voting_power_spike() {
    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    let proposal_id = make_motion_proposal(
        &state_machine,
        *TEST_NEURON_1_OWNER_PRINCIPAL,
        NeuronId::from_u64(TEST_NEURON_1_ID),
    );

    // Because the neuron 1 has a lot of voting power, the proposal should be executed immediately.
    assert!(is_proposal_executed(&state_machine, proposal_id));
}

#[test]
fn test_proposal_with_voting_power_spike() {
    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    // For a few days, proposals made by a neuron which wields a lot of voting power should be
    // executed immediately.
    for _ in 0..10 {
        let proposal_id = make_motion_proposal(
            &state_machine,
            *TEST_NEURON_1_OWNER_PRINCIPAL,
            NeuronId::from_u64(TEST_NEURON_1_ID),
        );
        assert!(is_proposal_executed(&state_machine, proposal_id));

        state_machine.advance_time(Duration::from_secs(60 * 60 * 24));
    }

    // Now we create a super powerful neuron, which will cause a spike in voting power compared to
    // previous days.
    let super_powerful_neuron_id = nns_create_super_powerful_neuron(
        &state_machine,
        *TEST_NEURON_3_OWNER_PRINCIPAL,
        Tokens::from_tokens(1_000_000).unwrap(),
    );
    let proposal_id = make_motion_proposal(
        &state_machine,
        *TEST_NEURON_3_OWNER_PRINCIPAL,
        super_powerful_neuron_id,
    );
    assert!(!is_proposal_executed(&state_machine, proposal_id));

    // Using the previous neuron, we create a proposal which should be executed immediately.
    let proposal_id = make_motion_proposal(
        &state_machine,
        *TEST_NEURON_1_OWNER_PRINCIPAL,
        NeuronId::from_u64(TEST_NEURON_1_ID),
    );
    assert!(is_proposal_executed(&state_machine, proposal_id));

    // The neurons with a lot of voting power before the spike can still pass proposals.
    let proposal_id = make_motion_proposal(
        &state_machine,
        *TEST_NEURON_1_OWNER_PRINCIPAL,
        NeuronId::from_u64(TEST_NEURON_1_ID),
    );
    assert!(is_proposal_executed(&state_machine, proposal_id));
}
