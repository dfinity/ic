use assert_matches::assert_matches;
use ic_base_types::PrincipalId;
use ic_nns_common::types::ProposalId;
use ic_nns_governance::pb::v1::{
    governance_error::ErrorType,
    manage_neuron_response::{Command, RegisterVoteResponse},
    Vote,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    neuron_helpers::{
        get_neuron_1, get_neuron_2, get_neuron_3, get_nonexistent_neuron, get_some_proposal,
        get_unauthorized_neuron, submit_proposal,
    },
    state_test_helpers::{
        get_pending_proposals, nns_cast_vote, nns_governance_get_full_neuron,
        nns_governance_make_proposal, setup_nns_canisters, state_machine_builder_for_nns_tests,
    },
};
use ic_state_machine_tests::StateMachine;

const INVALID_PROPOSAL_ID: u64 = 69420;

fn setup_state_machine_with_nns_canisters() -> StateMachine {
    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);
    state_machine
}

#[test]
fn unauthorized_neuron_cannot_create_proposal() {
    let mut state_machine = setup_state_machine_with_nns_canisters();
    let unauthorized_neuron = get_unauthorized_neuron();
    let proposal = get_some_proposal();
    let response = nns_governance_make_proposal(
        &mut state_machine,
        unauthorized_neuron.principal_id,
        unauthorized_neuron.neuron_id,
        &proposal,
    )
    .command
    .expect("Making NNS proposal failed");

    assert_matches!(response, Command::Error(ref err) if err.error_type() == ErrorType::NotAuthorized);
    assert_matches!(response, Command::Error(ref err) if err.error_message.contains("Caller not authorized to propose"));
}

#[test]
fn unauthorized_neuron_cannot_vote_on_nonexistent_proposal() {
    let mut state_machine = setup_state_machine_with_nns_canisters();
    let unauthorized_neuron = get_unauthorized_neuron();

    let response = nns_cast_vote(
        &mut state_machine,
        unauthorized_neuron.principal_id,
        unauthorized_neuron.neuron_id,
        INVALID_PROPOSAL_ID,
        Vote::Yes,
    )
    .command
    .expect("Casting vote failed");

    assert_matches!(response, Command::Error(ref err) if err.error_type() == ErrorType::NotAuthorized);
    assert_matches!(response, Command::Error(ref err) if err.error_message.contains("Caller is not authorized to vote for neuron"));
}

#[test]
fn anonymous_principal_cannot_vote_on_nonexistent_proposal() {
    let mut state_machine = setup_state_machine_with_nns_canisters();
    let n1 = get_neuron_1();

    let response = nns_cast_vote(
        &mut state_machine,
        PrincipalId::new_anonymous(),
        n1.neuron_id,
        INVALID_PROPOSAL_ID,
        Vote::Yes,
    )
    .command
    .expect("Casting vote failed");

    assert_matches!(response, Command::Error(ref err) if err.error_type() == ErrorType::NotAuthorized);
    assert_matches!(response, Command::Error(ref err) if err.error_message.contains("Caller is not authorized to vote for neuron"));
}

#[test]
fn anonymous_principal_cannot_vote_on_existent_proposal() {
    let mut state_machine = setup_state_machine_with_nns_canisters();
    let n1 = get_neuron_1();
    let proposal_id = submit_proposal(&mut state_machine, &n1);

    let response = nns_cast_vote(
        &mut state_machine,
        PrincipalId::new_anonymous(),
        n1.neuron_id,
        proposal_id.0,
        Vote::Yes,
    )
    .command
    .expect("Casting vote failed");

    assert_matches!(response, Command::Error(ref err) if err.error_type() == ErrorType::NotAuthorized);
    assert_matches!(response, Command::Error(ref err) if err.error_message.contains("Caller is not authorized to vote for neuron"));
}

#[test]
fn neuron_cannot_vote_on_nonexistent_proposal() {
    let mut state_machine = setup_state_machine_with_nns_canisters();
    let n1 = get_neuron_1();

    let response = nns_cast_vote(
        &mut state_machine,
        n1.principal_id,
        n1.neuron_id,
        INVALID_PROPOSAL_ID,
        Vote::Yes,
    )
    .command
    .expect("Casting vote failed");

    assert_matches!(response, Command::Error(ref err) if err.error_type() == ErrorType::NotFound);
    assert_matches!(response, Command::Error(ref err) if err.error_message.contains("Can't find proposal"));
}

#[test]
fn propose_and_vote_with_other_neuron() {
    let mut state_machine = setup_state_machine_with_nns_canisters();
    let n1 = get_neuron_1();
    let n2 = get_neuron_2();
    let proposal_id = submit_proposal(&mut state_machine, &n1);

    let response = nns_cast_vote(
        &mut state_machine,
        n2.principal_id,
        n2.neuron_id,
        proposal_id.0,
        Vote::No,
    )
    .command
    .expect("Casting vote failed");

    assert_eq!(response, Command::RegisterVote(RegisterVoteResponse {}));
}

#[test]
fn proposer_neuron_cannot_vote_explicitly() {
    let mut state_machine = setup_state_machine_with_nns_canisters();
    let n1 = get_neuron_1();

    let proposal_id = submit_proposal(&mut state_machine, &n1);

    // neuron 1 already implicitly voted when submitting the proposal
    let response = nns_cast_vote(
        &mut state_machine,
        n1.principal_id,
        n1.neuron_id,
        proposal_id.0,
        Vote::Yes,
    )
    .command
    .expect("Casting vote failed");

    assert_matches!(response, Command::Error(ref err) if err.error_type() == ErrorType::PreconditionFailed);
    assert_matches!(response, Command::Error(ref err) if err.error_message.contains("Neuron already voted"));
}

#[test]
fn neuron_cannot_vote_twice() {
    let mut state_machine = setup_state_machine_with_nns_canisters();
    let n1 = get_neuron_1();
    let n2 = get_neuron_2();
    let proposal_id = submit_proposal(&mut state_machine, &n1);

    // vote once with neuron 2
    let response_1 = nns_cast_vote(
        &mut state_machine,
        n2.principal_id,
        n2.neuron_id,
        proposal_id.0,
        Vote::Yes,
    )
    .command
    .expect("Casting vote failed");

    assert_eq!(response_1, Command::RegisterVote(RegisterVoteResponse {}));

    // vote again with neuron 2
    let response_2 = nns_cast_vote(
        &mut state_machine,
        n2.principal_id,
        n2.neuron_id,
        proposal_id.0,
        Vote::Yes,
    )
    .command
    .expect("Casting vote failed");

    assert_matches!(response_2, Command::Error(ref err) if err.error_type() == ErrorType::PreconditionFailed);
    assert_matches!(response_2, Command::Error(ref err) if err.error_message.contains("Neuron already voted"));
}

#[test]
fn nonexistent_neuron_cannot_vote() {
    let mut state_machine = setup_state_machine_with_nns_canisters();
    let n1 = get_neuron_1();
    let nonexistent_neuron = get_nonexistent_neuron();
    let proposal_id = submit_proposal(&mut state_machine, &n1);

    let response = nns_cast_vote(
        &mut state_machine,
        nonexistent_neuron.principal_id,
        nonexistent_neuron.neuron_id,
        proposal_id.0,
        Vote::Yes,
    )
    .command
    .expect("Casting vote failed");

    assert_matches!(response, Command::Error(ref err) if err.error_type() == ErrorType::NotFound);
    assert_matches!(response, Command::Error(ref err) if err.error_message.contains("Neuron not found"));
}

#[test]
fn cannot_submit_proposals_with_insufficient_funds() {
    let mut state_machine = setup_state_machine_with_nns_canisters();
    let n3 = get_neuron_3();
    let proposal = get_some_proposal();

    // neuron 3 does not have enough funds to submit proposal. when proposal gets rejected, it needs to cover reject_cost_e8s. See also NNS1-297.
    let response =
        nns_governance_make_proposal(&mut state_machine, n3.principal_id, n3.neuron_id, &proposal)
            .command
            .expect("Making NNS proposal failed");

    assert_matches!(response, Command::Error(ref err) if err.error_type() == ErrorType::InsufficientFunds);
    assert_matches!(response, Command::Error(ref err) if err.error_message.contains("Neuron doesn't have enough minted stake to submit proposal"));
}

#[test]
fn can_vote_on_proposal_with_insufficient_funds() {
    let mut state_machine = setup_state_machine_with_nns_canisters();
    let n2 = get_neuron_2();
    let n3 = get_neuron_3();

    // however, proposal can be voted on even when the voting neuron has insufficient funds for submitting proposals
    let proposal_id = submit_proposal(&mut state_machine, &n2);
    let response = nns_cast_vote(
        &mut state_machine,
        n3.principal_id,
        n3.neuron_id,
        proposal_id.0,
        Vote::Yes,
    )
    .command
    .expect("Casting vote failed");

    assert_eq!(response, Command::RegisterVote(RegisterVoteResponse {}));
}

#[test]
fn failed_proposal_causes_reject_cost_deduction_for_proposer() {
    let mut state_machine = setup_state_machine_with_nns_canisters();
    let n1 = get_neuron_1();
    let n2 = get_neuron_2();

    let n2_funds_before =
        nns_governance_get_full_neuron(&mut state_machine, n2.principal_id, n2.neuron_id.id)
            .expect("Could not retrieve neuron info")
            .stake_e8s();

    let proposal_id = submit_proposal(&mut state_machine, &n2);

    // vote "no" with heavy neuron 1 to cause the proposal to fail
    let response = nns_cast_vote(
        &mut state_machine,
        n1.principal_id,
        n1.neuron_id,
        proposal_id.0,
        Vote::No,
    )
    .command
    .expect("Casting vote failed");

    assert_eq!(response, Command::RegisterVote(RegisterVoteResponse {}));

    let n2_funds_after =
        nns_governance_get_full_neuron(&mut state_machine, n2.principal_id, n2.neuron_id.id)
            .expect("Could not retrieve neuron info")
            .stake_e8s();

    assert!(n2_funds_before > n2_funds_after);
}

#[test]
fn cannot_vote_on_future_proposal() {
    let mut state_machine = setup_state_machine_with_nns_canisters();
    let n1 = get_neuron_1();
    let n2 = get_neuron_2();
    let future_proposal_id = ProposalId(1);

    let response = nns_cast_vote(
        &mut state_machine,
        n1.principal_id,
        n1.neuron_id,
        future_proposal_id.0,
        Vote::Yes,
    )
    .command
    .expect("Casting vote failed");

    assert_matches!(response, Command::Error(ref err) if err.error_type() == ErrorType::NotFound);
    assert_matches!(response, Command::Error(ref err) if err.error_message.contains("Can't find proposal"));

    let proposal_id = submit_proposal(&mut state_machine, &n2);
    assert_eq!(proposal_id, future_proposal_id);

    let pending_proposals = get_pending_proposals(&mut state_machine);
    let proposal = pending_proposals
        .iter()
        .find(|p| p.id == Some(ic_nns_common::pb::v1::ProposalId { id: proposal_id.0 }))
        .unwrap();

    // either there is no ballot registered for neuron 1 or it is unspecified
    if proposal.ballots.contains_key(&n1.neuron_id.id) {
        assert_eq!(proposal.ballots[&n1.neuron_id.id].vote(), Vote::Unspecified);
    }
}
