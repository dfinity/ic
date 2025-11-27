use ic_nns_governance_api::Vote;

use super::{NeuronStore, NeuronStoreError};

use crate::{
    neuron::Neuron,
    pb::v1::{Ballot, NeuronIdToVotingPowerMap, VotingPowerEconomics, VotingPowerTotal},
    storage::neurons::NeuronSections,
};

use std::collections::HashMap;

/// The snapshot of voting power for all eligible neurons at a given time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VotingPowerSnapshot {
    /// A map of neuron ID to its voting power.
    voting_power_map: HashMap<u64, u64>,

    /// The total deciding voting power of all eligible neurons.
    total_deciding_voting_power: u64,

    /// The total potential voting power of all eligible neurons.
    total_potential_voting_power: u64,
}

impl VotingPowerSnapshot {
    /// Although the snapshot should only be computed by the neuron store, we need to
    /// create it for testing purposes.
    #[cfg(any(test, feature = "canbench-rs"))]
    pub fn new_for_test(
        voting_power_map: HashMap<u64, u64>,
        total_potential_voting_power: u64,
    ) -> Self {
        let total_deciding_voting_power = voting_power_map.values().sum();
        Self {
            voting_power_map,
            total_deciding_voting_power,
            total_potential_voting_power,
        }
    }

    /// Constructs ballots from the snapshot. Returns both the ballots and
    /// total_potential_voting_power.
    pub fn create_ballots_and_total_potential_voting_power(
        self,
    ) -> (
        HashMap<u64, Ballot>,
        u64, /* total_potential_voting_power */
    ) {
        let VotingPowerSnapshot {
            voting_power_map,
            total_deciding_voting_power: _,
            total_potential_voting_power,
        } = self;

        let ballots = voting_power_map
            .into_iter()
            .map(|(neuron_id, voting_power)| {
                (
                    neuron_id,
                    Ballot {
                        voting_power,
                        vote: Vote::Unspecified as i32,
                    },
                )
            })
            .collect();

        (ballots, total_potential_voting_power)
    }

    pub fn total_potential_voting_power(&self) -> u64 {
        self.total_potential_voting_power
    }
}

impl From<VotingPowerSnapshot> for (NeuronIdToVotingPowerMap, VotingPowerTotal) {
    fn from(snapshot: VotingPowerSnapshot) -> Self {
        let VotingPowerSnapshot {
            voting_power_map,
            total_deciding_voting_power,
            total_potential_voting_power,
        } = snapshot;

        (
            NeuronIdToVotingPowerMap { voting_power_map },
            VotingPowerTotal {
                total_deciding_voting_power,
                total_potential_voting_power,
            },
        )
    }
}

impl From<(NeuronIdToVotingPowerMap, VotingPowerTotal)> for VotingPowerSnapshot {
    fn from(
        (voting_power_map, voting_power_total): (NeuronIdToVotingPowerMap, VotingPowerTotal),
    ) -> Self {
        let NeuronIdToVotingPowerMap { voting_power_map } = voting_power_map;
        let VotingPowerTotal {
            total_deciding_voting_power,
            total_potential_voting_power,
        } = voting_power_total;

        Self {
            voting_power_map,
            total_deciding_voting_power,
            total_potential_voting_power,
        }
    }
}

fn get_voting_power_as_u64(
    voting_power: u128,
    error: NeuronStoreError,
) -> Result<u64, NeuronStoreError> {
    if voting_power > (u64::MAX as u128) {
        return Err(error);
    }
    Ok(voting_power as u64)
}

impl NeuronStore {
    /// Computes the voting power snapshot for a standard proposal.
    pub fn compute_voting_power_snapshot_for_standard_proposal(
        &self,
        voting_power_economics: &VotingPowerEconomics,
        now_seconds: u64,
    ) -> Result<VotingPowerSnapshot, NeuronStoreError> {
        let mut voting_power_map = HashMap::new();
        let mut total_deciding_voting_power: u128 = 0;
        let mut total_potential_voting_power: u128 = 0;

        let min_dissolve_delay_seconds = voting_power_economics
            .neuron_minimum_dissolve_delay_to_vote_seconds
            .unwrap_or(VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS);

        let mut process_neuron = |neuron: &Neuron| {
            if neuron.is_inactive(now_seconds)
                || neuron.dissolve_delay_seconds(now_seconds) < min_dissolve_delay_seconds
            {
                return;
            }

            let voting_power = neuron.deciding_voting_power(voting_power_economics, now_seconds);
            // We don't handle overflow here, as in `get_voting_power_as_u64` below,
            // the input arguments bigger than u64::MAX will result in an error.
            total_deciding_voting_power =
                total_deciding_voting_power.saturating_add(voting_power as u128);
            total_potential_voting_power = total_potential_voting_power
                .saturating_add(neuron.potential_voting_power(now_seconds) as u128);
            voting_power_map.insert(neuron.id().id, voting_power);
        };

        // Active neurons iterator already makes distinctions between stable and heap neurons.
        self.with_active_neurons_iter_sections(
            |iter| {
                for neuron in iter {
                    process_neuron(&neuron);
                }
            },
            NeuronSections::NONE,
        );

        let total_deciding_voting_power = get_voting_power_as_u64(
            total_deciding_voting_power,
            NeuronStoreError::TotalDecidingVotingPowerOverflow,
        )?;
        let total_potential_voting_power = get_voting_power_as_u64(
            total_potential_voting_power,
            NeuronStoreError::TotalPotentialVotingPowerOverflow,
        )?;

        Ok(VotingPowerSnapshot {
            voting_power_map,
            total_deciding_voting_power,
            total_potential_voting_power,
        })
    }
}
