use crate::voting_history_store::ListNeuronVotesOrder;
use crate::{pb::v1::Vote, voting_history_store::VotingHistoryStore};

use canbench_rs::{BenchResult, bench_fn};
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_stable_structures::DefaultMemoryImpl;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn create_bench_store() -> VotingHistoryStore {
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

/// Populates the voting history store with votes for a specific neuron and background votes
/// from many other neurons.
fn populate_votes(
    store: &mut VotingHistoryStore,
    target_neuron_votes: u64,
    background_votes: u64,
    _rng: &mut impl Rng,
) {
    // Add votes for the target neuron (neuron_id = 1)
    let target_neuron = neuron_id(1);
    for i in 0..target_neuron_votes {
        let vote = match i % 3 {
            0 => Vote::Yes,
            1 => Vote::No,
            _ => Vote::Unspecified,
        };
        store.record_vote(target_neuron, proposal_id(i), vote);
    }

    // Add background votes from other neurons (neuron_id = 2 to 1001)
    // We distribute the background votes across 1,000 neurons
    // For 100K background votes: 100 votes per neuron
    // For 1M background votes: 1,000 votes per neuron
    let background_neurons_count = 1_000u64;
    let votes_per_background_neuron = background_votes / background_neurons_count;

    for neuron_idx in 2..=(background_neurons_count + 1) {
        let background_neuron = neuron_id(neuron_idx);
        for vote_idx in 0..votes_per_background_neuron {
            let vote = match (neuron_idx + vote_idx) % 3 {
                0 => Vote::Yes,
                1 => Vote::No,
                _ => Vote::Unspecified,
            };
            // Use a different proposal id range to avoid conflicts with target neuron
            let proposal_idx =
                target_neuron_votes + neuron_idx * votes_per_background_neuron + vote_idx;
            store.record_vote(background_neuron, proposal_id(proposal_idx), vote);
        }
    }
}

/// Benchmark function for list_neuron_votes with specified parameters
fn list_neuron_votes_benchmark(target_neuron_votes: u64, background_votes: u64) -> BenchResult {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let mut store = create_bench_store();

    // Setup: populate the store with votes
    populate_votes(&mut store, target_neuron_votes, background_votes, &mut rng);

    let target_neuron = neuron_id(1);

    bench_fn(|| {
        let _votes = store.list_neuron_votes(
            target_neuron,
            ListNeuronVotesOrder::Ascending,
            None,
            target_neuron_votes,
        );
    })
}

// Benchmarks for 10K votes by target neuron with 100K background votes
#[canbench_rs::bench(raw)]
fn list_neuron_votes_10k_target_100k_background() -> BenchResult {
    list_neuron_votes_benchmark(10_000, 100_000)
}

// Benchmarks for 100K votes by target neuron with 100K background votes
#[canbench_rs::bench(raw)]
fn list_neuron_votes_100k_target_100k_background() -> BenchResult {
    list_neuron_votes_benchmark(100_000, 100_000)
}

// Benchmarks for 1M votes by target neuron with 100K background votes
#[canbench_rs::bench(raw)]
fn list_neuron_votes_1m_target_100k_background() -> BenchResult {
    list_neuron_votes_benchmark(1_000_000, 100_000)
}
