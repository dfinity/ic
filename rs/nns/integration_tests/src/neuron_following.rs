use assert_matches::assert_matches;
use ic_nns_common::{pb::v1::NeuronId, types::ProposalId};
use ic_nns_governance_api::pb::v1::{
    governance_error::ErrorType,
    manage_neuron_response::{Command, FollowResponse},
    Tally, Topic, Vote,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    neuron_helpers::{
        get_neuron_1, get_neuron_2, get_neuron_3, get_nonexistent_neuron, get_unauthorized_neuron,
        submit_proposal, TestNeuronOwner,
    },
    state_test_helpers::{
        get_neuron_ids, nns_cast_vote, nns_governance_get_full_neuron,
        nns_governance_get_proposal_info, nns_governance_get_proposal_info_as_anonymous,
        nns_set_followees_for_neuron, nns_split_neuron, setup_nns_canisters,
        state_machine_builder_for_nns_tests,
    },
};
use ic_state_machine_tests::StateMachine;

const VALID_TOPIC: i32 = Topic::ParticipantManagement as i32;
const INVALID_TOPIC: i32 = 69420;
const PROTOCOAL_CANISTER_MANAGEMENT_TOPIC: i32 = Topic::ProtocolCanisterManagement as i32;
const NEURON_MANAGEMENT_TOPIC: i32 = Topic::NeuronManagement as i32;
const VOTING_POWER_NEURON_1: u64 = 1_404_004_106;
const VOTING_POWER_NEURON_2: u64 = 140_400_410;
const VOTING_POWER_NEURON_3: u64 = 14_040_040;

fn setup_state_machine_with_nns_canisters() -> StateMachine {
    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);
    state_machine
}

#[test]
fn follow_another() {
    let state_machine = setup_state_machine_with_nns_canisters();

    let n1 = get_neuron_1();
    let n2 = get_neuron_2();

    // neuron 1 follows neuron 2
    set_followees_on_topic(&state_machine, &n1, &[n2.neuron_id], VALID_TOPIC);
}

#[test]
fn follow_itself() {
    let state_machine = setup_state_machine_with_nns_canisters();

    let n1 = get_neuron_1();

    // cycles are allowed; neurons can follow themselves
    set_followees_on_topic(&state_machine, &n1, &[n1.neuron_id], VALID_TOPIC);
}

#[test]
fn follow_on_invalid_topic() {
    let state_machine = setup_state_machine_with_nns_canisters();

    let n1 = get_neuron_1();
    let n2 = get_neuron_2();

    // neurons cannot follow another neuron on an invalid topic
    let result = nns_set_followees_for_neuron(
        &state_machine,
        n1.principal_id,
        n1.neuron_id,
        &[n2.neuron_id],
        INVALID_TOPIC,
    )
    .command
    .expect("Manage neuron command failed");

    assert_matches!(result,
        Command::Error(err)
        if err.error_type() == ErrorType::InvalidCommand
        && err.error_message.contains("Not a known topic number."));
}

#[test]
fn unauthorized_neuron_cannot_follow_neuron() {
    let state_machine = setup_state_machine_with_nns_canisters();

    let n1 = get_neuron_1();
    let unauthorized_neuron = get_unauthorized_neuron();

    // the unauthorized neuron cannot follow n1
    let result = nns_set_followees_for_neuron(
        &state_machine,
        unauthorized_neuron.principal_id,
        unauthorized_neuron.neuron_id,
        &[n1.neuron_id],
        VALID_TOPIC,
    )
    .command
    .expect("Manage neuron command failed");

    assert_matches!(result,
        Command::Error(err)
        if err.error_type() == ErrorType::NotAuthorized);
}

#[test]
fn nonexistent_neuron_cannot_follow_neuron() {
    let state_machine = setup_state_machine_with_nns_canisters();

    let n1 = get_neuron_1();
    let nonexistent_neuron = get_nonexistent_neuron();

    // the non-existing neuron cannot follow a neuron
    let result = nns_set_followees_for_neuron(
        &state_machine,
        nonexistent_neuron.principal_id,
        nonexistent_neuron.neuron_id,
        &[n1.neuron_id],
        VALID_TOPIC,
    )
    .command
    .expect("Manage neuron command failed");

    assert_matches!(result,
        Command::Error(err)
        if err.error_type() == ErrorType::NotFound);
}

#[test]
fn neuron_follow_nonexistent_neuron() {
    let state_machine = setup_state_machine_with_nns_canisters();

    let n1 = get_neuron_1();
    let nonexistent_neuron = get_nonexistent_neuron();

    // neurons are allowed to follow nonexistent neurons
    set_followees_on_topic(
        &state_machine,
        &n1,
        &[nonexistent_neuron.neuron_id],
        VALID_TOPIC,
    );
}

#[test]
fn unfollow_all_in_a_topic() {
    let state_machine = setup_state_machine_with_nns_canisters();

    let n1 = get_neuron_1();
    let n2 = get_neuron_2();

    // n1 follows n2
    set_followees_on_topic(&state_machine, &n1, &[n2.neuron_id], VALID_TOPIC);
    // n1 unfollows all (n2)
    clear_followees_on_topic(&state_machine, &n1, VALID_TOPIC);
}

#[test]
fn follow_existing_and_nonexistent_neurons() {
    let state_machine = setup_state_machine_with_nns_canisters();

    let n1 = get_neuron_1();
    let n2 = get_neuron_2();
    let nonexistent_neuron = get_nonexistent_neuron();

    // n1 can follow a mix of existent and nonexistent neurons
    set_followees_on_topic(
        &state_machine,
        &n1,
        &[nonexistent_neuron.neuron_id, n2.neuron_id],
        VALID_TOPIC,
    );
}

#[test]
fn follow_same_neuron_multiple_times() {
    let state_machine = setup_state_machine_with_nns_canisters();

    let n1 = get_neuron_1();
    let n2 = get_neuron_2();

    // neurons can follow the same neuron multiple times
    set_followees_on_topic(
        &state_machine,
        &n1,
        &[n2.neuron_id, n2.neuron_id, n2.neuron_id],
        VALID_TOPIC,
    );
}

#[test]
fn vote_propagation_with_following() {
    let state_machine = setup_state_machine_with_nns_canisters();

    let n1 = get_neuron_1();
    let n2 = get_neuron_2();
    let n3 = get_neuron_3();

    // make a proposal via n2 before setting up followees
    let proposal_id = submit_proposal(&state_machine, &n2);

    let votes = get_yes_votes(&state_machine, &proposal_id);
    assert_eq!(votes, VOTING_POWER_NEURON_2);

    let ballot_n2 = check_ballots(&state_machine, &proposal_id, &n2);
    assert_eq!(ballot_n2, (VOTING_POWER_NEURON_2, Vote::Yes));

    // make n1 follow n2
    set_followees_on_topic(
        &state_machine,
        &n1,
        &[n2.neuron_id],
        PROTOCOAL_CANISTER_MANAGEMENT_TOPIC,
    );

    // voting doesn't get propagated by mutating the following graph
    let votes = get_yes_votes(&state_machine, &proposal_id);
    assert_eq!(votes, VOTING_POWER_NEURON_2);
    let ballot_n1 = check_ballots(&state_machine, &proposal_id, &n1);
    assert_eq!(ballot_n1, (VOTING_POWER_NEURON_1, Vote::Unspecified));
    let ballot_n2 = check_ballots(&state_machine, &proposal_id, &n2);
    assert_eq!(ballot_n2, (VOTING_POWER_NEURON_2, Vote::Yes));

    // re-vote explicitly, still no change
    nns_cast_vote(
        &state_machine,
        n2.principal_id,
        n2.neuron_id,
        proposal_id.0,
        Vote::Yes,
    );
    let votes = get_yes_votes(&state_machine, &proposal_id);
    assert_eq!(votes, VOTING_POWER_NEURON_2);

    // n1 needs to vote explicitly
    nns_cast_vote(
        &state_machine,
        n1.principal_id,
        n1.neuron_id,
        proposal_id.0,
        Vote::Yes,
    );
    let votes = get_yes_votes(&state_machine, &proposal_id);
    assert_eq!(votes, 1_544_404_516);
    let ballot_n1 = check_ballots(&state_machine, &proposal_id, &n1);
    assert_eq!(ballot_n1, (VOTING_POWER_NEURON_1, Vote::Yes));

    // make n3 follow n2
    set_followees_on_topic(
        &state_machine,
        &n3,
        &[n2.neuron_id],
        PROTOCOAL_CANISTER_MANAGEMENT_TOPIC,
    );

    // make n2 follow n1
    set_followees_on_topic(
        &state_machine,
        &n2,
        &[n1.neuron_id],
        PROTOCOAL_CANISTER_MANAGEMENT_TOPIC,
    );

    // now n1 and n2 follow each other (circle), and n3 follows n2
    // make another proposal via n2 now that followees are set up
    let proposal_id = submit_proposal(&state_machine, &n2);

    // verify that all three neurons did vote
    let votes = get_yes_votes(&state_machine, &proposal_id);
    assert_eq!(
        votes,
        VOTING_POWER_NEURON_1 + VOTING_POWER_NEURON_2 + VOTING_POWER_NEURON_3
    );
    let ballot_n1 = check_ballots(&state_machine, &proposal_id, &n1);
    assert_eq!(ballot_n1, (VOTING_POWER_NEURON_1, Vote::Yes));
    let ballot_n2 = check_ballots(&state_machine, &proposal_id, &n2);
    assert_eq!(ballot_n2, (VOTING_POWER_NEURON_2, Vote::Yes));
    let ballot_n3 = check_ballots(&state_machine, &proposal_id, &n3);
    assert_eq!(ballot_n3, (VOTING_POWER_NEURON_3, Vote::Yes));

    // split n1 and build a follow chain like this:
    // n2 -> n1a -> n3 -> n1
    let n1a_id = split_neuron(&state_machine, &n1, 500_000_000);
    let n1a = TestNeuronOwner {
        neuron_id: n1a_id,
        principal_id: n1.principal_id,
    };

    // make n2 follow n1a
    set_followees_on_topic(
        &state_machine,
        &n2,
        &[n1a.neuron_id],
        PROTOCOAL_CANISTER_MANAGEMENT_TOPIC,
    );

    // at this point n2 is not influential
    let influential = get_neuron_ids(&state_machine, n1a.principal_id);
    assert_eq!(influential.len(), 2);
    assert!(influential.contains(&n1a.neuron_id.id));
    assert!(influential.contains(&n1.neuron_id.id));

    // same following, different topic
    set_followees_on_topic(
        &state_machine,
        &n2,
        &[n1a.neuron_id],
        NEURON_MANAGEMENT_TOPIC,
    );

    // at this point n2 becomes influential (a `NeuronManagement` follower to n1a)
    let influential = get_neuron_ids(&state_machine, n1a.principal_id);
    assert_eq!(influential.len(), 3);
    assert!(influential.contains(&n1a.neuron_id.id));
    assert!(influential.contains(&n1.neuron_id.id));
    assert!(influential.contains(&n2.neuron_id.id));

    // change following, in `NeuronManagement` topic
    set_followees_on_topic(
        &state_machine,
        &n3,
        &[n1a.neuron_id],
        NEURON_MANAGEMENT_TOPIC,
    );
    // at this point n3 becomes influential (a `NeuronManagement` follower to n1a)
    let influential = get_neuron_ids(&state_machine, n1a.principal_id);
    assert_eq!(influential.len(), 4);
    assert!(influential.contains(&n1a.neuron_id.id));
    assert!(influential.contains(&n1.neuron_id.id));
    assert!(influential.contains(&n2.neuron_id.id));
    assert!(influential.contains(&n3.neuron_id.id));

    // change following, in `NeuronManagement` topic
    set_followees_on_topic(
        &state_machine,
        &n2,
        &[n3.neuron_id],
        NEURON_MANAGEMENT_TOPIC,
    );
    // at this point n2 ceases to be influential (as a `NeuronManagement` follower
    // to n1a)
    let influential = get_neuron_ids(&state_machine, n1a.principal_id);
    assert_eq!(influential.len(), 3);
    assert!(influential.contains(&n1a.neuron_id.id));
    assert!(influential.contains(&n1.neuron_id.id));
    assert!(influential.contains(&n3.neuron_id.id));

    set_followees_on_topic(
        &state_machine,
        &n1a,
        &[n3.neuron_id],
        PROTOCOAL_CANISTER_MANAGEMENT_TOPIC,
    );

    set_followees_on_topic(
        &state_machine,
        &n3,
        &[n1.neuron_id],
        PROTOCOAL_CANISTER_MANAGEMENT_TOPIC,
    );

    // fire off a new proposal by n1, and see all neurons voting
    // immediately along the chain
    let proposal_id = submit_proposal(&state_machine, &n1);

    // verify that all four neurons did vote
    let votes = get_yes_votes(&state_machine, &proposal_id);
    assert_eq!(
        votes,
        702_002_052 + 701_988_012 + VOTING_POWER_NEURON_2 + VOTING_POWER_NEURON_3
    );
    let ballot_n1 = check_ballots(&state_machine, &proposal_id, &n1);
    assert_eq!(ballot_n1, (702_002_052, Vote::Yes));
    let ballot_n1a = check_ballots(&state_machine, &proposal_id, &n1a);
    assert_eq!(ballot_n1a, (701_988_012, Vote::Yes));
    let ballot_n2 = check_ballots(&state_machine, &proposal_id, &n2);
    assert_eq!(ballot_n2, (VOTING_POWER_NEURON_2, Vote::Yes));
    let ballot_n3 = check_ballots(&state_machine, &proposal_id, &n3);
    assert_eq!(ballot_n3, (VOTING_POWER_NEURON_3, Vote::Yes));
}

fn split_neuron(state_machine: &StateMachine, neuron: &TestNeuronOwner, amount: u64) -> NeuronId {
    let response = nns_split_neuron(state_machine, neuron.principal_id, neuron.neuron_id, amount);
    if let Command::Split(resp) = response.command.unwrap() {
        resp.created_neuron_id.unwrap()
    } else {
        panic!("funny ManageNeuronResponse")
    }
}

fn check_ballots(
    state_machine: &StateMachine,
    proposal_id: &ProposalId,
    neuron: &TestNeuronOwner,
) -> (u64, Vote) {
    let info = nns_governance_get_proposal_info(state_machine, proposal_id.0, neuron.principal_id);
    let ballots = info.ballots;
    assert!(!ballots.is_empty());
    let ballot = &ballots[&(neuron.neuron_id).id];
    (ballot.voting_power, Vote::try_from(ballot.vote).unwrap())
}

fn get_yes_votes(state_machine: &StateMachine, proposal_id: &ProposalId) -> u64 {
    let info = nns_governance_get_proposal_info_as_anonymous(state_machine, proposal_id.0);
    match info.latest_tally {
        Some(Tally { yes, .. }) => yes,
        _ => panic!("funny tally"),
    }
}

fn clear_followees_on_topic(state_machine: &StateMachine, neuron: &TestNeuronOwner, topic: i32) {
    let result = nns_set_followees_for_neuron(
        state_machine,
        neuron.principal_id,
        neuron.neuron_id,
        &[],
        topic,
    )
    .command
    .expect("Manage neuron command failed");

    assert_eq!(result, Command::Follow(FollowResponse {}));
    let updated_neuron =
        nns_governance_get_full_neuron(state_machine, neuron.principal_id, neuron.neuron_id.id)
            .expect("Could not retrieve updated neuron");
    assert!(&updated_neuron.followees.is_empty());
}

/// make neuron follow the neurons in followees
fn set_followees_on_topic(
    state_machine: &StateMachine,
    neuron: &TestNeuronOwner,
    followees: &[NeuronId],
    topic: i32,
) {
    let result = nns_set_followees_for_neuron(
        state_machine,
        neuron.principal_id,
        neuron.neuron_id,
        followees,
        topic,
    )
    .command
    .expect("Manage neuron command failed");

    assert_eq!(result, Command::Follow(FollowResponse {}));
    let updated_neuron =
        nns_governance_get_full_neuron(state_machine, neuron.principal_id, neuron.neuron_id.id)
            .expect("Could not retrieve updated neuron");
    let actual_followees = &updated_neuron.followees[&topic].followees;
    assert_eq!(actual_followees, &followees);
}
