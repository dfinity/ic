use crate::pb::v1::Vote;

use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_stable_structures::{
    DefaultMemoryImpl, StableBTreeMap, Storable, memory_manager::VirtualMemory, storable::Bound,
};
use std::borrow::Cow;

type DefaultMemory = VirtualMemory<DefaultMemoryImpl>;

pub struct VotingHistoryStore {
    neuron_proposal_to_vote:
        StableBTreeMap<(NeuronId, u64 /* sequence number */), (ProposalId, Vote), DefaultMemory>,
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

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ListNeuronVotesOrder {
    Ascending,
    Descending,
}

impl VotingHistoryStore {
    pub fn new(memory: DefaultMemory) -> Self {
        Self {
            neuron_proposal_to_vote: StableBTreeMap::init(memory),
        }
    }

    pub fn record_vote(&mut self, neuron_id: NeuronId, proposal_id: ProposalId, vote: Vote) {
        let highest_sequence_number = self
            .neuron_proposal_to_vote
            .range((neuron_id, u64::MIN)..=(neuron_id, u64::MAX))
            .next_back()
            .map(|((_neuron_id, sequence_number), _value)| sequence_number)
            .unwrap_or(0);
        self.neuron_proposal_to_vote.insert(
            (neuron_id, highest_sequence_number + 1),
            (proposal_id, vote),
        );
    }

    #[allow(dead_code)]
    pub fn list_neuron_votes(
        &self,
        neuron_id: NeuronId,
        order: ListNeuronVotesOrder,
        after_index: Option<u64>,
        limit: u64,
    ) -> (Vec<(ProposalId, Vote)>, u64, u64) {
        use std::ops::Bound::{Excluded, Included};

        let limit = limit as usize;
        let range_bounds = match (order, after_index) {
            (ListNeuronVotesOrder::Ascending, Some(after_index)) => (
                Excluded((neuron_id, after_index)),
                Included((neuron_id, u64::MAX)),
            ),
            (ListNeuronVotesOrder::Descending, Some(after_index)) => (
                Included((neuron_id, u64::MIN)),
                Excluded((neuron_id, after_index)),
            ),
            (_, None) => (
                Included((neuron_id, u64::MIN)),
                Included((neuron_id, u64::MAX)),
            ),
        };

        let mut range = self.neuron_proposal_to_vote.range(range_bounds);
        let mut votes = vec![];
        let mut highest_sequence_number = 0;
        for ((_neuron_id, sequence_number), (proposal_id, vote)) in range.by_ref().take(limit) {
            votes.push((proposal_id, vote));
            highest_sequence_number = sequence_number;
        }
        let remaining_votes = range.count();
        (votes, highest_sequence_number, remaining_votes as u64)
    }
}

#[cfg(test)]
#[path = "voting_history_store_tests.rs"]
mod tests;

#[cfg(feature = "canbench-rs")]
#[path = "voting_history_store_benches.rs"]
mod benches;
