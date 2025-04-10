use crate::governance::voting_power_snapshots::VotingPowerSnapshots;
use crate::governance::Governance;

use ic_nervous_system_timer_task::RecurringSyncTask;
use std::cell::RefCell;
use std::thread::LocalKey;
use std::time::Duration;

/// A task to snapshot the voting power every day, so that the snapshot can be used to disable
/// early adoption of proposals if such proposals have unusually high voting power.
pub(super) struct SnapshotVotingPowerTask {
    governance: &'static LocalKey<RefCell<Governance>>,
    snapshots: &'static LocalKey<RefCell<VotingPowerSnapshots>>,
}

const VOTING_POWER_SNAPSHOT_INTERVAL: Duration = Duration::from_secs(60 * 60 * 24);

impl SnapshotVotingPowerTask {
    pub fn new(
        governance: &'static LocalKey<RefCell<Governance>>,
        snapshots: &'static LocalKey<RefCell<VotingPowerSnapshots>>,
    ) -> Self {
        Self {
            governance,
            snapshots,
        }
    }
}

impl RecurringSyncTask for SnapshotVotingPowerTask {
    fn execute(self) -> (Duration, Self) {
        let (now_seconds, voting_power_snapshot) = self.governance.with_borrow_mut(|governance| {
            let now_seconds = governance.env.now();
            let voting_power_economics = governance.voting_power_economics();
            let voting_power_snapshot = governance
                .neuron_store
                .compute_voting_power_snapshot_for_standard_proposal(
                    voting_power_economics,
                    now_seconds,
                )
                .expect("Voting power snapshot failed");

            (now_seconds, voting_power_snapshot)
        });

        self.snapshots.with_borrow_mut(|snapshots| {
            snapshots.record_voting_power_snapshot(now_seconds, voting_power_snapshot);
        });

        (VOTING_POWER_SNAPSHOT_INTERVAL, self)
    }

    fn initial_delay(&self) -> Duration {
        let now_seconds = self
            .governance
            .with_borrow(|governance| governance.env.now());
        let last_snapshot_timestamp_seconds = self
            .snapshots
            .with_borrow(|snapshots| snapshots.latest_snapshot_timestamp_seconds());
        match last_snapshot_timestamp_seconds {
            Some(last_snapshot_timestamp_seconds) => {
                let next_snapshot_timestamp_seconds =
                    last_snapshot_timestamp_seconds + VOTING_POWER_SNAPSHOT_INTERVAL.as_secs();
                let delay_seconds = next_snapshot_timestamp_seconds.saturating_sub(now_seconds);
                Duration::from_secs(delay_seconds)
            }
            None => Duration::from_secs(0),
        }
    }

    const NAME: &'static str = "snapshot_voting_power";
}

#[cfg(test)]
mod tests {
    use super::*;

    use ic_nns_common::pb::v1::NeuronId;
    use ic_stable_structures::{
        memory_manager::{MemoryId, MemoryManager},
        DefaultMemoryImpl,
    };
    use ic_types::PrincipalId;
    use icp_ledger::Subaccount;
    use std::{collections::HashMap, sync::Arc};

    use crate::{
        neuron::{DissolveStateAndAge, NeuronBuilder},
        pb::v1::{Ballot, Governance as GovernanceProto, NetworkEconomics, VotingPowerEconomics},
        test_utils::{MockEnvironment, MockRandomness, StubCMC, StubIcpLedger},
    };

    thread_local! {
        static MOCK_ENVIRONMENT: Arc<MockEnvironment> = Arc::new(
            MockEnvironment::new(Default::default(), 0));
        static TEST_GOVERNANCE: RefCell<Governance> = RefCell::new(new_governance_for_test());
        static TEST_MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
            RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
        static TEST_VOTING_POWER_SNAPSHOTS: RefCell<VotingPowerSnapshots> = RefCell::new({
            TEST_MEMORY_MANAGER.with_borrow(|memory_manager| {
                VotingPowerSnapshots::new(memory_manager.get(MemoryId::new(0)), memory_manager.get(MemoryId::new(1)))
            })
        });
    }

    fn set_time(now: u64) {
        MOCK_ENVIRONMENT.with(|env| env.now_setter()(now));
    }

    fn new_governance_for_test() -> Governance {
        let mut governance = Governance::new(
            GovernanceProto {
                economics: Some(NetworkEconomics {
                    voting_power_economics: Some(VotingPowerEconomics::DEFAULT),
                    ..Default::default()
                }),
                ..Default::default()
            },
            MOCK_ENVIRONMENT.with(|env| env.clone()),
            Arc::new(StubIcpLedger {}),
            Arc::new(StubCMC {}),
            Box::new(MockRandomness::new()),
        );
        let dissolve_delay_seconds =
            VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS;
        governance
            .neuron_store
            .add_neuron(
                NeuronBuilder::new(
                    NeuronId { id: 1 },
                    Subaccount::try_from([1u8; 32].as_slice()).unwrap(),
                    PrincipalId::new_self_authenticating(b"neuron-id"),
                    DissolveStateAndAge::NotDissolving {
                        dissolve_delay_seconds,
                        aging_since_timestamp_seconds: governance.env.now(),
                    },
                    123_456_789,
                )
                .with_cached_neuron_stake_e8s(1_000_000_000)
                .build(),
            )
            .unwrap();

        governance
    }

    #[test]
    fn test_execute() {
        TEST_VOTING_POWER_SNAPSHOTS.with_borrow(|snapshots| {
            // Before the first snapshot, the latest snapshot timestamp should be None, and we
            // should not disable early adoption without any snapshots.
            assert_eq!(snapshots.latest_snapshot_timestamp_seconds(), None);
            assert_eq!(
                snapshots.previous_ballots_if_voting_power_spike_detected(u64::MAX, 0),
                None
            )
        });

        let task = SnapshotVotingPowerTask::new(&TEST_GOVERNANCE, &TEST_VOTING_POWER_SNAPSHOTS);
        let (delay, _) = task.execute();

        assert_eq!(delay, VOTING_POWER_SNAPSHOT_INTERVAL);
        let now_seconds = TEST_GOVERNANCE.with_borrow(|governance| governance.env.now());
        TEST_VOTING_POWER_SNAPSHOTS.with_borrow(|snapshots| {
            // After the first snapshot, the latest snapshot timestamp should be the current time,
            // and we should disable early adoption given a large deciding voting power.
            assert_eq!(
                snapshots.latest_snapshot_timestamp_seconds(),
                Some(now_seconds)
            );
            let (timestamp, previous_snapshot) = snapshots
                .previous_ballots_if_voting_power_spike_detected(u64::MAX, 0)
                .unwrap();

            // We only do some sanity checks here to make sure the task is working as expected.
            assert_eq!(timestamp, now_seconds);
            let (ballots, total_potential_voting_power) =
                <(HashMap<u64, Ballot>, u64)>::from(previous_snapshot);
            assert!(ballots.get(&1).unwrap().voting_power > 0);
            assert!(total_potential_voting_power > 0);
        });
    }

    #[test]
    fn test_initial_delay() {
        let task = SnapshotVotingPowerTask::new(&TEST_GOVERNANCE, &TEST_VOTING_POWER_SNAPSHOTS);
        let one_day_seconds = 60 * 60 * 24;

        // Initially, the task should run immediately.
        set_time(one_day_seconds);
        assert_eq!(task.initial_delay(), Duration::from_secs(0));

        // After execution and a half day, the task should run after a half day.
        let (new_delay, task) = task.execute();
        assert_eq!(new_delay, VOTING_POWER_SNAPSHOT_INTERVAL);
        set_time(one_day_seconds + one_day_seconds / 2);
        assert_eq!(
            task.initial_delay(),
            Duration::from_secs(one_day_seconds / 2)
        );

        // After execution and 1.5 days (for some reason the task wasn't run), the task should run
        // immediately.
        let (new_delay, task) = task.execute();
        assert_eq!(new_delay, VOTING_POWER_SNAPSHOT_INTERVAL);
        set_time(3 * one_day_seconds);
        assert_eq!(task.initial_delay(), Duration::from_secs(0));
    }
}
