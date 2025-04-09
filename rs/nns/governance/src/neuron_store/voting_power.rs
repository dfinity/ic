use crate::pb::v1::{NeuronIdToVotingPowerMap, VotingPowerTotal};

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

#[cfg(any(test, feature = "canbench-rs"))]
impl VotingPowerSnapshot {
    /// Although the snapshot should only be computed by the neuron store, we need to
    /// create it for testing purposes.
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
