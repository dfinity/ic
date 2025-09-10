use crate::pb::v1::Vote;

use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_stable_structures::{
    memory_manager::VirtualMemory, storable::Bound, DefaultMemoryImpl, StableBTreeMap, Storable,
};
use std::borrow::Cow;

type DefaultMemory = VirtualMemory<DefaultMemoryImpl>;

pub struct VotingHistoryStore {
    neuron_proposal_to_vote: StableBTreeMap<(NeuronId, ProposalId), Vote, DefaultMemory>,
}

type StorableVote = u8;

impl From<Vote> for StorableVote {
    fn from(vote: Vote) -> Self {
        match vote {
            Vote::Unspecified => 0,
            Vote::Yes => 1,
            Vote::No => 2,
        }
    }
}

impl From<StorableVote> for Vote {
    fn from(vote: StorableVote) -> Self {
        match vote {
            1 => Vote::Yes,
            2 => Vote::No,
            _ => Vote::Unspecified,
        }
    }
}

impl Storable for Vote {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let storable_vote = StorableVote::from(*self);
        Cow::Owned(vec![storable_vote])
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        let storable_vote = StorableVote::from_bytes(bytes);
        Vote::from(storable_vote)
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 1,
        is_fixed_size: true,
    };
}

impl VotingHistoryStore {
    pub fn new(memory: DefaultMemory) -> Self {
        Self {
            neuron_proposal_to_vote: StableBTreeMap::init(memory),
        }
    }

    pub fn record_vote(&mut self, neuron_id: NeuronId, proposal_id: ProposalId, vote: Vote) {
        self.neuron_proposal_to_vote
            .insert((neuron_id, proposal_id), vote);
    }

    #[allow(dead_code)]
    pub fn list_neuron_votes(&self, neuron_id: NeuronId) -> Vec<(ProposalId, Vote)> {
        let min_key = (neuron_id, ProposalId::MIN);
        let max_key = (neuron_id, ProposalId::MAX);
        self.neuron_proposal_to_vote
            .range(min_key..=max_key)
            .map(|((_neuron_id, proposal_id), vote)| (proposal_id, vote))
            .collect()
    }
}

#[cfg(test)]
#[path = "voting_history_store_tests.rs"]
mod tests;
