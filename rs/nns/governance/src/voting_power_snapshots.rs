use crate::pb::v1::governance::VotingPowerSnapshot;

use std::collections::VecDeque;

const MAX_VOTING_POWER_SNAPSHOTS: usize = 7;
const MULTIPLIER_THRESHOLD_FOR_VOTING_POWER_SPIKE: u64 = 2;

#[derive(Default, Clone, Debug)]
pub struct VotingPowerSnapshots {
    snapshots: VecDeque<VotingPowerSnapshot>,
}

impl From<Vec<VotingPowerSnapshot>> for VotingPowerSnapshots {
    fn from(snapshots: Vec<VotingPowerSnapshot>) -> Self {
        Self {
            snapshots: snapshots.into_iter().collect(),
        }
    }
}

impl From<VotingPowerSnapshots> for Vec<VotingPowerSnapshot> {
    fn from(snapshots: VotingPowerSnapshots) -> Self {
        snapshots.snapshots.into()
    }
}

impl VotingPowerSnapshots {
    pub fn snapshot_voting_power(&mut self, deciding_voting_power: u64, timestamp_seconds: u64) {
        self.snapshots.push_back(VotingPowerSnapshot {
            deciding_voting_power,
            timestamp_seconds,
        });
        while self.snapshots.len() > MAX_VOTING_POWER_SNAPSHOTS {
            self.snapshots.pop_front();
        }
    }

    pub fn should_disable_early_adoption(&self, deciding_voting_power: u64) -> bool {
        let minimum_voting_power_in_snapshot = self
            .snapshots
            .iter()
            .map(|snapshot| snapshot.deciding_voting_power)
            .min();
        let minimum_voting_power_in_snapshot = match minimum_voting_power_in_snapshot {
            Some(minimum_voting_power_in_snapshot) => minimum_voting_power_in_snapshot,
            None => return false,
        };
        deciding_voting_power
            > minimum_voting_power_in_snapshot * MULTIPLIER_THRESHOLD_FOR_VOTING_POWER_SPIKE
    }

    pub fn latest_snapshot_timestamp_seconds(&self) -> Option<u64> {
        self.snapshots
            .back()
            .map(|snapshot| snapshot.timestamp_seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_voting_power() {
        let mut snapshots = VotingPowerSnapshots::default();

        // Initially, there are no snapshots, so the latest snapshot timestamp is None, and we
        // should not disable early adoption since there is no data.
        assert_eq!(snapshots.latest_snapshot_timestamp_seconds(), None);
        assert!(!snapshots.should_disable_early_adoption(u64::MAX));

        // After making a snapshot, the latest snapshot timestamp should be the timestamp of the
        // snapshot.
        snapshots.snapshot_voting_power(10, 1);
        assert_eq!(snapshots.latest_snapshot_timestamp_seconds(), Some(1));
        // We should disable early adoption if the deciding voting power is more than 2 times the
        // minimum voting power in the first snapshot.
        assert!(!snapshots.should_disable_early_adoption(10));
        assert!(!snapshots.should_disable_early_adoption(20));
        assert!(snapshots.should_disable_early_adoption(21));

        for i in 2..=7 {
            // The minimum voting power in the snapshots is still 10 over the next 6 snapshots.
            snapshots.snapshot_voting_power(20, i);
            assert_eq!(snapshots.latest_snapshot_timestamp_seconds(), Some(i));
            assert!(!snapshots.should_disable_early_adoption(20));
            assert!(snapshots.should_disable_early_adoption(21));
        }

        // After the 7th snapshot, the first snapshot is removed, and the minimum voting power in
        // the snapshots is now 20.
        snapshots.snapshot_voting_power(20, 8);
        assert_eq!(snapshots.latest_snapshot_timestamp_seconds(), Some(8));
        assert!(!snapshots.should_disable_early_adoption(20));
        assert!(!snapshots.should_disable_early_adoption(40));
        assert!(snapshots.should_disable_early_adoption(41));
    }
}
