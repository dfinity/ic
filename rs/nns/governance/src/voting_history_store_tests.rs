use super::*;

use ic_stable_structures::memory_manager::{MemoryId, MemoryManager};
use ic_stable_structures::DefaultMemoryImpl;

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

    let empty_votes = store.list_neuron_votes(neuron_id(1));
    assert_eq!(empty_votes, vec![]);

    store.record_vote(neuron_id(123), proposal_id(456), Vote::Yes);

    let votes = store.list_neuron_votes(neuron_id(123));
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

    assert_eq!(
        store.list_neuron_votes(test_neuron_id),
        vec![
            (proposal_id(1), Vote::No),
            (proposal_id(2), Vote::Yes),
            (proposal_id(3), Vote::Yes),
            (proposal_id(4), Vote::Unspecified),
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

    assert_eq!(
        store.list_neuron_votes(neuron_id_1),
        vec![(proposal_id_1, Vote::Yes), (proposal_id_2, Vote::No)]
    );
    assert_eq!(
        store.list_neuron_votes(neuron_id_2),
        vec![
            (proposal_id_1, Vote::Unspecified),
            (proposal_id_2, Vote::Yes)
        ]
    );
}

#[test]
fn test_overwrite_existing_vote() {
    let mut store = create_test_store();

    let test_neuron_id = neuron_id(123);
    let test_proposal_id = proposal_id(456);

    store.record_vote(test_neuron_id, test_proposal_id, Vote::Unspecified);

    let votes = store.list_neuron_votes(test_neuron_id);
    assert_eq!(votes, vec![(test_proposal_id, Vote::Unspecified)]);

    store.record_vote(test_neuron_id, test_proposal_id, Vote::No);

    let votes = store.list_neuron_votes(test_neuron_id);
    assert_eq!(votes, vec![(test_proposal_id, Vote::No)]);
}
