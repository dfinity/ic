use super::*;

use ic_stable_structures::DefaultMemoryImpl;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager};

fn create_test_store() -> VotingHistoryStore {
    let memory_manager = MemoryManager::init(DefaultMemoryImpl::default());
    let memory = memory_manager.get(MemoryId::new(0));
    VotingHistoryStore::new(memory)
}

fn neuron_id(id: u64) -> NeuronId {
    NeuronId { id }
}

fn proposal_id(id: u64) -> ProposalId {
    ProposalId { id }
}

#[test]
fn test_record_and_retrieve_single_vote() {
    let mut store = create_test_store();

    let empty_votes = store.list_neuron_votes(neuron_id(1), None, Some(100));
    assert_eq!(empty_votes, vec![]);

    store.record_vote(neuron_id(123), proposal_id(456), Vote::Yes);

    let votes = store.list_neuron_votes(neuron_id(123), None, Some(100));
    assert_eq!(votes, vec![(proposal_id(456), Vote::Yes)]);
}

#[test]
fn test_record_multiple_votes_same_neuron() {
    let mut store = create_test_store();

    let test_neuron_id = neuron_id(123);
    store.record_vote(test_neuron_id, proposal_id(2), Vote::Yes);
    store.record_vote(test_neuron_id, proposal_id(1), Vote::No);
    store.record_vote(test_neuron_id, proposal_id(4), Vote::Unspecified);
    store.record_vote(test_neuron_id, proposal_id(3), Vote::Yes);

    // Votes should be returned in descending order by proposal ID
    assert_eq!(
        store.list_neuron_votes(test_neuron_id, None, Some(100)),
        vec![
            (proposal_id(4), Vote::Unspecified),
            (proposal_id(3), Vote::Yes),
            (proposal_id(2), Vote::Yes),
            (proposal_id(1), Vote::No),
        ]
    );
}

#[test]
fn test_record_votes_different_neurons() {
    let mut store = create_test_store();

    let neuron_id_1 = neuron_id(100);
    let neuron_id_2 = neuron_id(200);
    let proposal_id_1 = proposal_id(1);
    let proposal_id_2 = proposal_id(2);

    store.record_vote(neuron_id_2, proposal_id_1, Vote::Unspecified);
    store.record_vote(neuron_id_1, proposal_id_1, Vote::Yes);
    store.record_vote(neuron_id_1, proposal_id_2, Vote::No);
    store.record_vote(neuron_id_2, proposal_id_2, Vote::Yes);

    // Votes should be returned in descending order by proposal ID
    assert_eq!(
        store.list_neuron_votes(neuron_id_1, None, Some(100)),
        vec![(proposal_id_2, Vote::No), (proposal_id_1, Vote::Yes)]
    );
    assert_eq!(
        store.list_neuron_votes(neuron_id_2, None, Some(100)),
        vec![
            (proposal_id_2, Vote::Yes),
            (proposal_id_1, Vote::Unspecified),
        ]
    );
}

#[test]
fn test_overwrite_existing_vote() {
    let mut store = create_test_store();

    let test_neuron_id = neuron_id(123);
    let test_proposal_id = proposal_id(456);

    store.record_vote(test_neuron_id, test_proposal_id, Vote::Unspecified);

    let votes = store.list_neuron_votes(test_neuron_id, None, Some(100));
    assert_eq!(votes, vec![(test_proposal_id, Vote::Unspecified)]);

    store.record_vote(test_neuron_id, test_proposal_id, Vote::No);

    let votes = store.list_neuron_votes(test_neuron_id, None, Some(100));
    assert_eq!(votes, vec![(test_proposal_id, Vote::No)]);
}

#[test]
fn test_list_neuron_votes_with_limit() {
    let mut store = create_test_store();
    let test_neuron_id = neuron_id(123);

    for i in 1..=5 {
        store.record_vote(test_neuron_id, proposal_id(i), Vote::Yes);
    }

    let votes = store.list_neuron_votes(test_neuron_id, None, Some(3));
    assert_eq!(
        votes,
        vec![
            (proposal_id(5), Vote::Yes),
            (proposal_id(4), Vote::Yes),
            (proposal_id(3), Vote::Yes),
        ]
    );
}

#[test]
fn test_list_neuron_votes_with_before_proposal() {
    let mut store = create_test_store();
    let test_neuron_id = neuron_id(123);

    for i in 1..=10 {
        store.record_vote(test_neuron_id, proposal_id(i), Vote::Yes);
    }

    let votes = store.list_neuron_votes(test_neuron_id, Some(proposal_id(8)), Some(3));
    assert_eq!(
        votes,
        vec![
            (proposal_id(7), Vote::Yes),
            (proposal_id(6), Vote::Yes),
            (proposal_id(5), Vote::Yes),
        ]
    );

    let votes = store.list_neuron_votes(test_neuron_id, Some(proposal_id(1)), Some(10));
    assert_eq!(votes, vec![]);
}

#[test]
fn test_pagination_sync_entire_voting_history() {
    let mut store = create_test_store();
    let test_neuron_id = neuron_id(42);

    let proposal_ids = vec![1, 3, 5, 7, 9, 12, 15, 18, 20, 25];
    for &id in &proposal_ids {
        store.record_vote(test_neuron_id, proposal_id(id), Vote::Yes);
    }

    let mut all_votes = Vec::new();
    let mut before_proposal = None;
    let limit = 3;

    loop {
        let batch = store.list_neuron_votes(test_neuron_id, before_proposal, Some(limit));

        if batch.is_empty() {
            break;
        }

        all_votes.extend(batch.clone());

        before_proposal = Some(batch.last().unwrap().0);
    }

    assert_eq!(
        all_votes,
        vec![
            (proposal_id(25), Vote::Yes),
            (proposal_id(20), Vote::Yes),
            (proposal_id(18), Vote::Yes),
            (proposal_id(15), Vote::Yes),
            (proposal_id(12), Vote::Yes),
            (proposal_id(9), Vote::Yes),
            (proposal_id(7), Vote::Yes),
            (proposal_id(5), Vote::Yes),
            (proposal_id(3), Vote::Yes),
            (proposal_id(1), Vote::Yes),
        ]
    );
}
