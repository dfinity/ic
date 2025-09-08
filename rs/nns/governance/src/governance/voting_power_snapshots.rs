#![allow(unused)]
use crate::{
    governance::{LOG_PREFIX, MAX_FOLLOWEES_PER_TOPIC},
    neuron_store::voting_power::VotingPowerSnapshot,
    pb::v1::{Ballot, NeuronIdToVotingPowerMap, VotingPowerTotal},
};

use ic_cdk::eprintln;
use ic_nervous_system_common::ONE_MONTH_SECONDS;
use ic_stable_structures::{
    DefaultMemoryImpl, StableBTreeMap, Storable, memory_manager::VirtualMemory, storable::Bound,
};
use prost::Message;
use std::{borrow::Cow, collections::HashMap};

/// The maximum number of voting power snapshots to keep.
const MAX_VOTING_POWER_SNAPSHOTS: u64 = 7;
/// The multiplier used to define what is a "voting power spike": if the current total voting
/// power is more than this multiplier times the minimum total voting power in the snapshots,
/// then we consider it a spike.
const MULTIPLIER_THRESHOLD_FOR_VOTING_POWER_SPIKE: f64 = 1.5;
/// The maximum staleness of a voting power snapshot. This is usually not needed since
/// the snapshots should be added frequently. However, we do not want to use a snapshot that is too
/// old, in the event of a failure in taking the snapshots.
const MAXIMUM_STALENESS_SECONDS: u64 = ONE_MONTH_SECONDS * 3;

type DefaultMemory = VirtualMemory<DefaultMemoryImpl>;
type TimestampSeconds = u64;

/// A collection of voting power snapshots, each associated with a timestamp. The totals are used to
/// detect whether there is a spike of total voting power, and the voting power per neuron is used
/// to create ballots if a spike is detected. Note that a snapshot is stored in 2 separate
/// `StableBTreeMap` so that the totals can be checked without having to load the entire
/// `NeuronIdToVotingPowerMap` into memory.
pub(crate) struct VotingPowerSnapshots {
    neuron_id_to_voting_power_maps:
        StableBTreeMap<TimestampSeconds, NeuronIdToVotingPowerMap, DefaultMemory>,
    voting_power_totals: StableBTreeMap<TimestampSeconds, VotingPowerTotal, DefaultMemory>,
}

fn insert_and_truncate<Value: Storable>(
    map: &mut StableBTreeMap<TimestampSeconds, Value, DefaultMemory>,
    timestamp_seconds: TimestampSeconds,
    value: Value,
) {
    let existing_value = map.insert(timestamp_seconds, value);

    // Log if we just clobbered an existing entry, because it is a exceedingly unlikely
    // that this would happen in practice.
    if let Some(existing_value) = existing_value {
        eprintln!(
            "{}Somehow the voting power snapshot is taken multiple times at \
	            the same timestamp {}",
            LOG_PREFIX, timestamp_seconds,
        );
    }

    // Drop earlier entries from map.
    while map.len() > MAX_VOTING_POWER_SNAPSHOTS {
        let (first_key, _) = map
            .first_key_value()
            .expect("No first key value even though the length is checked right before.");
        map.remove(&first_key);
    }
}

impl VotingPowerSnapshots {
    pub fn new(maps_memory: DefaultMemory, totals_memory: DefaultMemory) -> Self {
        Self {
            neuron_id_to_voting_power_maps: StableBTreeMap::init(maps_memory),
            voting_power_totals: StableBTreeMap::init(totals_memory),
        }
    }

    /// Returns whether the latest snapshot is a voting power spike.
    pub fn is_latest_snapshot_a_spike(&self, now_seconds: TimestampSeconds) -> bool {
        // If there are no snapshots, then there is no spike.
        let Some((_, latest_totals)) = self.voting_power_totals.last_key_value() else {
            return false;
        };

        self.totals_entry_with_minimum_total_potential_voting_power_if_voting_power_spiked(
            now_seconds,
            latest_totals.total_potential_voting_power,
        )
        .is_some()
    }

    /// Records a voting power snapshot at the given timestamp. Oldest snapshots are removed
    /// if the number of snapshots exceeds the maximum allowed.
    pub(crate) fn record_voting_power_snapshot(
        &mut self,
        timestamp_seconds: TimestampSeconds,
        snapshot: VotingPowerSnapshot,
    ) {
        let (voting_power_map, voting_power_total) =
            <(NeuronIdToVotingPowerMap, VotingPowerTotal)>::from(snapshot);
        // We are being defensive here to make sure that the voting power snapshot is not taken as a
        // neuron management proposal, which is a special case where the ballots are created from
        // NeuronManagement topic followees rather than all voting eligible neurons.
        if voting_power_total.total_potential_voting_power <= MAX_FOLLOWEES_PER_TOPIC as u64 {
            ic_cdk::println!(
                "Voting power total is less than MAX_FOLLOWEES_PER_TOPIC. This should not happen."
            );
            return;
        }
        insert_and_truncate(
            &mut self.neuron_id_to_voting_power_maps,
            timestamp_seconds,
            voting_power_map,
        );
        insert_and_truncate(
            &mut self.voting_power_totals,
            timestamp_seconds,
            voting_power_total,
        );
    }

    /// Given a total potential voting power, checks if there is a voting power spike. If a spike is
    /// detected, it returns the timestamp and totals of the snapshot with the minimum total
    /// potential voting power. If no spike is detected, it returns None.
    fn totals_entry_with_minimum_total_potential_voting_power_if_voting_power_spiked(
        &self,
        now_seconds: TimestampSeconds,
        current_total_potential_voting_power: u64,
    ) -> Option<(TimestampSeconds, VotingPowerTotal)> {
        let (
            timestamp_with_minimum_total_potential_voting_power,
            totals_with_minimum_total_potential_voting_power,
        ) = self
            .voting_power_totals
            .iter()
            .filter(|(created_at, _)| {
                let age = now_seconds - created_at;
                age <= MAXIMUM_STALENESS_SECONDS
            })
            .min_by_key(|(_, snapshot)| snapshot.total_potential_voting_power)?;

        let voting_power_spike_detected = (current_total_potential_voting_power as f64)
            > (totals_with_minimum_total_potential_voting_power.total_potential_voting_power
                as f64)
                * MULTIPLIER_THRESHOLD_FOR_VOTING_POWER_SPIKE;
        if voting_power_spike_detected {
            Some((
                timestamp_with_minimum_total_potential_voting_power,
                totals_with_minimum_total_potential_voting_power,
            ))
        } else {
            None
        }
    }

    /// Given a total potential voting power, checks if there is a voting power spike and returns
    /// the previous voting power map if a spike is detected along with the snapshot timestamp. If
    /// no spike is detected, it returns None. The definition of a spike is based on the constant
    /// `MULTIPLIER_THRESHOLD_FOR_VOTING_POWER_SPIKE`.
    pub(crate) fn previous_ballots_if_voting_power_spike_detected(
        &self,
        total_potential_voting_power: u64,
        now_seconds: TimestampSeconds,
    ) -> Option<(TimestampSeconds, VotingPowerSnapshot)> {
        // Step 0: skip the check in test mode when the snapshots are not yet full. Otherwise it
        // would be difficult to get around the spike detection in tests, and a lot of test setups
        // involve creating a lot of voting power.
        if cfg!(feature = "test") && self.voting_power_totals.len() < MAX_VOTING_POWER_SNAPSHOTS {
            return None;
        }

        // Step 1: find the voting power totals entry with the minimum total potential voting power,
        // if a spike is detected.
        let Some((
            timestamp_with_minimum_total_potential_voting_power,
            totals_with_minimum_total_potential_voting_power,
        )) = self.totals_entry_with_minimum_total_potential_voting_power_if_voting_power_spiked(
            now_seconds,
            total_potential_voting_power,
        )
        else {
            eprintln!(
                "{}Voting power totals are empty. No voting power spike detected.",
                LOG_PREFIX,
            );
            return None;
        };

        // Step 2: find the voting power map for the timestamp with the minimum potential voting power.
        let Some(voting_power_map) = self
            .neuron_id_to_voting_power_maps
            .get(&timestamp_with_minimum_total_potential_voting_power)
        else {
            eprintln!(
                "{}Voting power map not found for timestamp {} while the totals \
                are found. This should not happen.",
                LOG_PREFIX, timestamp_with_minimum_total_potential_voting_power,
            );
            return None;
        };

        // Step 3: returns one of the previous voting power maps (with minimum total potential
        // voting power) since a voting power spike is detected.
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
    pub(crate) fn latest_snapshot_timestamp_seconds(&self) -> Option<TimestampSeconds> {
        self.voting_power_totals
            .last_key_value()
            .map(|(timestamp, _)| timestamp)
    }
}

impl Storable for NeuronIdToVotingPowerMap {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::from(self.encode_to_vec())
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self::decode(&bytes[..]).expect("Unable to deserialize NeuronIdToVotingPowerMap.")
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

#[path = "voting_power_snapshots_benches.rs"]
#[cfg(feature = "canbench-rs")]
mod benches;
