use super::*;
use crate::{neuron_store::voting_power, pb::v1::Vote};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager},
    VectorMemory,
};

fn voting_power_map(voting_powers: Vec<u64>) -> HashMap<u64, u64> {
    voting_powers
        .into_iter()
        .enumerate()
        .map(|(i, vp)| (i as u64, vp))
        .collect()
}

fn voting_power_snapshot(
    voting_powers: Vec<u64>,
    total_potential_voting_power: u64,
) -> VotingPowerSnapshot {
    let voting_power_map = voting_power_map(voting_powers);
    VotingPowerSnapshot::new_for_test(voting_power_map, total_potential_voting_power)
}

#[test]
fn test_snapshot_voting_power() {
    let memory_manager = MemoryManager::init(DefaultMemoryImpl::default());
    let mut snapshots = VotingPowerSnapshots::new(
        memory_manager.get(MemoryId::new(0)),
        memory_manager.get(MemoryId::new(1)),
    );

    // Initially, there are no snapshots, so the latest snapshot timestamp is None, and we
    // should not disable early adoption since there is no data.
    assert_eq!(snapshots.latest_snapshot_timestamp_seconds(), None);
    assert_eq!(
        snapshots.previous_ballots_if_voting_power_spike_detected(u64::MAX),
        None
    );

    // After making a snapshot, the latest snapshot timestamp should be the timestamp of the
    // snapshot.
    snapshots.snapshot_voting_power(1, voting_power_snapshot(vec![9], 10));
    assert_eq!(snapshots.latest_snapshot_timestamp_seconds(), Some(1));
    // We should disable early adoption if the deciding voting power is more than 2 times the
    // minimum voting power in the first snapshot.
    assert_eq!(
        snapshots.previous_ballots_if_voting_power_spike_detected(10),
        None
    );
    assert_eq!(
        snapshots.previous_ballots_if_voting_power_spike_detected(20),
        None
    );
    assert_eq!(
        snapshots.previous_ballots_if_voting_power_spike_detected(21),
        Some((1, voting_power_snapshot(vec![9], 10)))
    );

    for i in 2..=7 {
        // The minimum voting power in the snapshots is still 10 over the next 6
        snapshots.snapshot_voting_power(i, voting_power_snapshot(vec![19], 20));
        assert_eq!(snapshots.latest_snapshot_timestamp_seconds(), Some(i));
        assert_eq!(
            snapshots.previous_ballots_if_voting_power_spike_detected(20),
            None
        );
        assert_eq!(
            snapshots.previous_ballots_if_voting_power_spike_detected(21),
            Some((1, voting_power_snapshot(vec![9], 10)))
        );
    }

    // After the 7th snapshot, the first snapshot is removed, and the minimum voting power in
    // the snapshots is now 20.
    snapshots.snapshot_voting_power(8, voting_power_snapshot(vec![19], 20));
    assert_eq!(snapshots.latest_snapshot_timestamp_seconds(), Some(8));
    assert_eq!(
        snapshots.previous_ballots_if_voting_power_spike_detected(20),
        None
    );
    assert_eq!(
        snapshots.previous_ballots_if_voting_power_spike_detected(40),
        None
    );
    let (timestamp, previous_snapshot) = snapshots
        .previous_ballots_if_voting_power_spike_detected(41)
        .unwrap();
    // Since t = 2..=7 have the same voting power, using any of them is valid.
    assert!(
        timestamp >= 2 && timestamp <= 7,
        "Timestamp is expected to be between 2 and 7, but is {}",
        timestamp
    );
    assert_eq!(previous_snapshot, voting_power_snapshot(vec![19], 20));
}
