use crate::pb::v1::{ArchivedBallots, BallotInfo, Vote};

use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_stable_structures::{
    memory_manager::VirtualMemory, storable::Bound, DefaultMemoryImpl, StableBTreeMap, Storable,
};
use prost::Message;
use std::borrow::Cow;

type DefaultMemory = VirtualMemory<DefaultMemoryImpl>;

static MINIMUM_ENTRIES_AFTER_ARCHIVE: usize = 100;
static NUMBER_OF_ENTRIES_PER_ARCHIVE: usize = 1000;

pub struct BallotStore {
    ballots: StableBTreeMap<(NeuronId, u64 /* index */), BallotInfo, DefaultMemory>,
    archived_ballots: StableBTreeMap<(NeuronId, u64 /* index */), ArchivedBallots, DefaultMemory>,
}

impl From<[BallotInfo; NUMBER_OF_ENTRIES_PER_ARCHIVE]> for ArchivedBallots {
    fn from(ballots: [BallotInfo; NUMBER_OF_ENTRIES_PER_ARCHIVE]) -> Self {
        let mut proposal_id_diffs = vec![0; NUMBER_OF_ENTRIES_PER_ARCHIVE];
        let mut votes = vec![0; NUMBER_OF_ENTRIES_PER_ARCHIVE / 4];
        for i in 0..NUMBER_OF_ENTRIES_PER_ARCHIVE {
            let current_proposal_id = ballots[i]
                .proposal_id
                .expect("proposal_id is always Some")
                .id;
            let previous_proposal_id = if i == 0 {
                0
            } else {
                ballots[i - 1]
                    .proposal_id
                    .expect("proposal_id is always Some")
                    .id
            };
            proposal_id_diffs[i] = current_proposal_id.saturating_sub(previous_proposal_id) as i32;
            let vote_as_2_bits = match ballots[i].vote() {
                Vote::Unspecified => 0,
                Vote::Yes => 1,
                Vote::No => 2,
            };
            votes[i / 4] |= vote_as_2_bits << (i % 4 * 2);
        }
        Self {
            proposal_id_diffs,
            votes,
        }
    }
}

impl From<ArchivedBallots> for [BallotInfo; NUMBER_OF_ENTRIES_PER_ARCHIVE] {
    fn from(archived_ballots: ArchivedBallots) -> Self {
        let ArchivedBallots {
            proposal_id_diffs,
            votes,
        } = archived_ballots;
        let mut ballots = [BallotInfo {
            proposal_id: None,
            vote: Vote::Unspecified as i32,
        }; NUMBER_OF_ENTRIES_PER_ARCHIVE];
        ballots[0].proposal_id = Some(ProposalId {
            id: proposal_id_diffs[0] as u64,
        });
        for i in 1..NUMBER_OF_ENTRIES_PER_ARCHIVE {
            let previous_proposal_id = ballots[i - 1]
                .proposal_id
                .expect("proposal_id is always Some")
                .id;
            let current_proposal_id =
                previous_proposal_id.saturating_add(proposal_id_diffs[i] as u64);
            ballots[i].proposal_id = Some(ProposalId {
                id: current_proposal_id,
            });
            ballots[i].vote = match votes[i / 4] >> (i % 4 * 2) & 3 {
                0 => Vote::Unspecified as i32,
                1 => Vote::Yes as i32,
                2 => Vote::No as i32,
                _ => panic!("Invalid vote: {}", votes[i / 4] >> (i % 4 * 2) & 3),
            };
        }
        ballots
    }
}

impl Storable for ArchivedBallots {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::from(self.encode_to_vec())
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self::decode(&bytes[..]).expect("Unable to deserialize ArchivedBallots.")
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl BallotStore {
    pub fn new(ballots_memory: DefaultMemory, archived_ballots_memory: DefaultMemory) -> Self {
        Self {
            ballots: StableBTreeMap::init(ballots_memory),
            archived_ballots: StableBTreeMap::init(archived_ballots_memory),
        }
    }

    pub fn record_ballot(&mut self, neuron_id: NeuronId, proposal_id: ProposalId, vote: Vote) {
        let max_key = (neuron_id, u64::MAX);
        let largest_index = self
            .ballots
            .range(..=max_key)
            .last()
            .map(|((_, index), _)| index);
        let next_index = largest_index.map(|index| index + 1).unwrap_or(0);
        self.ballots.insert(
            (neuron_id, next_index),
            BallotInfo {
                proposal_id: Some(proposal_id),
                vote: vote as i32,
            },
        );
    }

    pub fn list_neuron_ballots(
        &self,
        neuron_id: NeuronId,
        offset: u64,
        limit: u64,
    ) -> Vec<BallotInfo> {
        let min_key = (neuron_id, 0);
        let max_key = (neuron_id, u64::MAX);
        self.ballots
            .range(min_key..=max_key)
            .skip(offset as usize)
            .take(limit as usize)
            .map(|(_, value)| value)
            .collect()
    }

    pub fn list_neuron_recent_ballots(&self, neuron_id: NeuronId, limit: u64) -> Vec<BallotInfo> {
        let min_key = (neuron_id, 0);
        let max_key = (neuron_id, u64::MAX);
        self.ballots
            .range(min_key..=max_key)
            .rev()
            .take(limit as usize)
            .map(|(_, value)| value)
            .collect()
    }

    pub fn archive_ballots(&mut self, neuron_id: NeuronId) {
        let min_key = (neuron_id, u64::MIN);
        let max_key = (neuron_id, u64::MAX);
        let mut ballots_iter = self.ballots.range(min_key..=max_key);
        let (keys_to_remove, ballots_to_archive): (Vec<(_, _)>, Vec<BallotInfo>) = ballots_iter
            .by_ref()
            .take(NUMBER_OF_ENTRIES_PER_ARCHIVE)
            .unzip();
        if ballots_iter.count() < MINIMUM_ENTRIES_AFTER_ARCHIVE {
            return;
        }
        for key in keys_to_remove {
            self.ballots.remove(&key);
        }
        let ballots_to_archive: [BallotInfo; NUMBER_OF_ENTRIES_PER_ARCHIVE] = ballots_to_archive
            .try_into()
            .expect("Unexpected number of ballots");
        self.append_archived_ballots(neuron_id, ballots_to_archive);
    }

    fn append_archived_ballots(
        &mut self,
        neuron_id: NeuronId,
        archived_ballots: [BallotInfo; NUMBER_OF_ENTRIES_PER_ARCHIVE],
    ) {
        let max_key = (neuron_id, u64::MAX);
        let largest_index = self
            .archived_ballots
            .range(..=max_key)
            .last()
            .map(|((_, index), _)| index);
        let next_index = largest_index.map(|index| index + 1).unwrap_or(0);
        self.archived_ballots.insert(
            (neuron_id, next_index),
            ArchivedBallots::from(archived_ballots),
        );
    }
}
