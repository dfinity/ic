use super::*;
use crate::{neuron_store::voting_power, pb::v1::Vote};
use ic_stable_structures::{
    VectorMemory,
    memory_manager::{MemoryId, MemoryManager},
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

    // Initially, there are no snapshots, so the latest snapshot timestamp is None, and we do not
    // return previous ballots since there is no data.
    assert_eq!(snapshots.latest_snapshot_timestamp_seconds(), None);
    assert_eq!(
        snapshots.previous_ballots_if_voting_power_spike_detected(u64::MAX, 0),
        None
    );

    // After making a snapshot, the latest snapshot timestamp should be the timestamp of the
    // snapshot.
    snapshots.record_voting_power_snapshot(1, voting_power_snapshot(vec![90], 100));
    assert_eq!(snapshots.latest_snapshot_timestamp_seconds(), Some(1));
    // We should return previous ballots if the deciding voting power is more than 1.5 times the
    // minimum voting power in the first snapshot.
    assert!(!snapshots.is_latest_snapshot_a_spike(1));

    for i in 0..6 {
        let timestamp_seconds = 2 + i;

        let use_previous_ballots = snapshots
            .previous_ballots_if_voting_power_spike_detected(u64::MAX, timestamp_seconds)
            .is_some();

        if cfg!(feature = "test") {
            // In the test environment, we do not use previous ballots when the snapshots are not full,
            // since a lot of test setups involve creating a lot of voting power.
            assert!(!use_previous_ballots);
        } else {
            // In the production environment, we use previous ballots as long as there is at least one
            // snapshot, so that when we recover from a false positive (by removing some snapshots), we
            // can still have the spike detection mechanism in place.
            assert!(use_previous_ballots);
        }

        // The minimum voting power in the snapshots is still 100 over the next 6
        snapshots.record_voting_power_snapshot(
            timestamp_seconds,
            voting_power_snapshot(vec![90, 10 + i], 110 + i),
        );
        assert_eq!(
            snapshots.latest_snapshot_timestamp_seconds(),
            Some(timestamp_seconds)
        );
        assert!(!snapshots.is_latest_snapshot_a_spike(timestamp_seconds));
    }

    // After the 7th snapshot, the first snapshot is removed, and the minimum total potential voting
    // power in the retained snapshots is now 20 on the timestamp 2.
    snapshots.record_voting_power_snapshot(8, voting_power_snapshot(vec![90, 16], 116));
    assert_eq!(snapshots.latest_snapshot_timestamp_seconds(), Some(8));
    assert_eq!(
        snapshots.previous_ballots_if_voting_power_spike_detected(151, 8),
        None
    );
    assert_eq!(
        snapshots.previous_ballots_if_voting_power_spike_detected(164, 8),
        None
    );
    assert_eq!(
        snapshots.previous_ballots_if_voting_power_spike_detected(166, 8),
        Some((2, voting_power_snapshot(vec![90, 10], 110)))
    );
    assert!(!snapshots.is_latest_snapshot_a_spike(8));

    // The 9th snapshot is a spike, and `is_latest_snapshot_a_spike` should return true.
    snapshots.record_voting_power_snapshot(9, voting_power_snapshot(vec![90, 90], 200));
    assert_eq!(snapshots.latest_snapshot_timestamp_seconds(), Some(9));
    assert_eq!(
        snapshots.previous_ballots_if_voting_power_spike_detected(166, 9),
        None
    );
    assert_eq!(
        snapshots.previous_ballots_if_voting_power_spike_detected(177, 9),
        Some((3, voting_power_snapshot(vec![90, 11], 111)))
    );
    assert!(snapshots.is_latest_snapshot_a_spike(9));

    // After 4 months, the snapshots are considered stale, and the voting power spike
    // detection is disabled.
    assert_eq!(
        snapshots.previous_ballots_if_voting_power_spike_detected(u64::MAX, ONE_MONTH_SECONDS * 4),
        None,
    );
}
