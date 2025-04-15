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
fn test_record_voting_power_snapshot() {
    let memory_manager = MemoryManager::init(DefaultMemoryImpl::default());
    let mut snapshots = VotingPowerSnapshots::new(
        memory_manager.get(MemoryId::new(0)),
        memory_manager.get(MemoryId::new(1)),
    );

    // Initially, there are no snapshots, so the latest snapshot timestamp is None, and we
    // should not disable early adoption since there is no data.
    assert_eq!(snapshots.latest_snapshot_timestamp_seconds(), None);
    assert_eq!(
        snapshots.previous_ballots_if_voting_power_spike_detected(u64::MAX, 0),
        None
    );

    // After making a snapshot, the latest snapshot timestamp should be the timestamp of the
    // snapshot.
    snapshots.record_voting_power_snapshot(1, voting_power_snapshot(vec![9], 10));
    assert_eq!(snapshots.latest_snapshot_timestamp_seconds(), Some(1));
    // We should disable early adoption if the deciding voting power is more than 2 times the
    // minimum voting power in the first snapshot.
    assert_eq!(
        snapshots.previous_ballots_if_voting_power_spike_detected(10, 1),
        None
    );
    assert_eq!(
        snapshots.previous_ballots_if_voting_power_spike_detected(14, 1),
        None
    );
    assert_eq!(
        snapshots.previous_ballots_if_voting_power_spike_detected(16, 1),
        Some((1, voting_power_snapshot(vec![9], 10)))
    );

    for i in 0..6 {
        let timestamp_seconds = 2 + i;
        // The minimum voting power in the snapshots is still 10 over the next 6
        snapshots.record_voting_power_snapshot(
            timestamp_seconds,
            voting_power_snapshot(vec![9, 10 + i], 20 + i),
        );
        assert_eq!(
            snapshots.latest_snapshot_timestamp_seconds(),
            Some(timestamp_seconds)
        );
        assert_eq!(
            snapshots.previous_ballots_if_voting_power_spike_detected(14, timestamp_seconds),
            None
        );
        assert_eq!(
            snapshots.previous_ballots_if_voting_power_spike_detected(16, timestamp_seconds),
            Some((1, voting_power_snapshot(vec![9], 10)))
        );
    }

    // After the 7th snapshot, the first snapshot is removed, and the minimum total potential voting
    // power in the retained snapshots is now 20 on the timestamp 2.
    snapshots.record_voting_power_snapshot(8, voting_power_snapshot(vec![9, 16], 26));
    assert_eq!(snapshots.latest_snapshot_timestamp_seconds(), Some(8));
    assert_eq!(
        snapshots.previous_ballots_if_voting_power_spike_detected(14, 8),
        None
    );
    assert_eq!(
        snapshots.previous_ballots_if_voting_power_spike_detected(29, 8),
        None
    );
    assert_eq!(
        snapshots.previous_ballots_if_voting_power_spike_detected(31, 8),
        Some((2, voting_power_snapshot(vec![9, 10], 20)))
    );

    // After 4 months, the snapshots are considered stale, and the voting power spike
    // detection is disabled.
    assert_eq!(
        snapshots.previous_ballots_if_voting_power_spike_detected(u64::MAX, ONE_MONTH_SECONDS * 4),
        None,
    );
}
