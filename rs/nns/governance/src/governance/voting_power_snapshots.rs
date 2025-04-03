#![allow(unused)]
use crate::{
    governance::LOG_PREFIX,
    neuron_store::voting_power::VotingPowerSnapshot,
    pb::v1::{Ballot, VotingPowerMap, VotingPowerTotal},
};

use ic_stable_structures::{
    memory_manager::VirtualMemory, storable::Bound, DefaultMemoryImpl, StableBTreeMap, Storable,
};
use prost::Message;
use std::{borrow::Cow, collections::HashMap};

const MAX_VOTING_POWER_SNAPSHOTS: u64 = 7;
const MULTIPLIER_THRESHOLD_FOR_VOTING_POWER_SPIKE: u64 = 2;

type VM = VirtualMemory<DefaultMemoryImpl>;

pub(crate) struct VotingPowerSnapshots {
    voting_power_maps: StableBTreeMap<u64, VotingPowerMap, VM>,
    voting_power_totals: StableBTreeMap<u64, VotingPowerTotal, VM>,
}

fn insert_and_truncate<Value: Storable>(
    map: &mut StableBTreeMap<u64, Value, VM>,
    timestamp_seconds: u64,
    value: Value,
) {
    let existing_value = map.insert(timestamp_seconds, value);
    if let Some(existing_value) = existing_value {
        ic_cdk::eprintln!(
            "{}Somehow the voting power snapshot is taken multiple times at \
            the same timestamp {}",
            LOG_PREFIX,
            timestamp_seconds,
        );
    }
    while map.len() > MAX_VOTING_POWER_SNAPSHOTS {
        let (first_key, _) = map
            .first_key_value()
            .expect("No first key value even though the length is checked right before.");
        map.remove(&first_key);
    }
}

impl VotingPowerSnapshots {
    pub fn new(maps_memory: VM, totals_memory: VM) -> Self {
        Self {
            voting_power_maps: StableBTreeMap::new(maps_memory),
            voting_power_totals: StableBTreeMap::new(totals_memory),
        }
    }

    /// Records a voting power snapshot at the given timestamp. Oldest snapshots are removed
    /// if the number of snapshots exceeds the maximum allowed.
    pub(crate) fn snapshot_voting_power(
        &mut self,
        timestamp_seconds: u64,
        snapshot: VotingPowerSnapshot,
    ) {
        let (voting_power_map, voting_power_total) =
            <(VotingPowerMap, VotingPowerTotal)>::from(snapshot);
        insert_and_truncate(
            &mut self.voting_power_maps,
            timestamp_seconds,
            voting_power_map,
        );
        insert_and_truncate(
            &mut self.voting_power_totals,
            timestamp_seconds,
            voting_power_total,
        );
    }

    /// Given a total potential voting power, checks if there is a voting power spike and returns
    /// the previous voting power map if a spike is detected along with the snapshot timestamp. If
    /// no spike is detected, it returns None.
    pub(crate) fn previous_ballots_if_voting_power_spike_detected(
        &self,
        total_potential_voting_power: u64,
    ) -> Option<(u64, VotingPowerSnapshot)> {
        // Step 1: find the timestamp with the minimum potential voting power. Exit if no snapshot is found.
        let Some((
            timestamp_with_minimum_total_potential_voting_power,
            totals_with_minimum_total_potential_voting_power,
        )) = self
            .voting_power_totals
            .iter()
            .min_by_key(|(_, snapshot)| snapshot.total_potential_voting_power)
        else {
            return None;
        };

        // Step 2: determine whether there is a voting power spike. Exit if a spike is not detected.
        let voting_power_spike_detected = total_potential_voting_power
            > totals_with_minimum_total_potential_voting_power
                .total_potential_voting_power
                .saturating_mul(MULTIPLIER_THRESHOLD_FOR_VOTING_POWER_SPIKE);
        if !voting_power_spike_detected {
            return None;
        }

        // Step 3: find the voting power map for the timestamp with the minimum potential voting power.
        let Some(voting_power_map) = self
            .voting_power_maps
            .get(&timestamp_with_minimum_total_potential_voting_power)
        else {
            ic_cdk::eprintln!(
                "{}Voting power map not found for timestamp {} while the totals \
                are found. This should not happen.",
                LOG_PREFIX,
                timestamp_with_minimum_total_potential_voting_power,
            );
            return None;
        };

        // Step 4: returns the previous voting power map since a voting power spike is detected.
        let previous_voting_power_snapshot = VotingPowerSnapshot::from((
            voting_power_map,
            totals_with_minimum_total_potential_voting_power,
        ));
        Some((
            timestamp_with_minimum_total_potential_voting_power,
            previous_voting_power_snapshot,
        ))
    }

    /// Returns the latest snapshot timestamp in seconds. If there are no snapshots, it returns None.
    pub(crate) fn latest_snapshot_timestamp_seconds(&self) -> Option<u64> {
        self.voting_power_totals
            .last_key_value()
            .map(|(timestamp, _)| timestamp)
    }
}

impl Storable for VotingPowerMap {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::from(self.encode_to_vec())
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self::decode(&bytes[..]).expect("Unable to deserialize VotingPowerMap.")
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for VotingPowerTotal {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::from(self.encode_to_vec())
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self::decode(&bytes[..]).expect("Unable to deserialize VotingPowerTotal.")
    }

    const BOUND: Bound = Bound::Unbounded;
}

#[path = "voting_power_snapshots_tests.rs"]
#[cfg(test)]
mod tests;
