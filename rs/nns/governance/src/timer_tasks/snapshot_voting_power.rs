use crate::governance::Governance;
use crate::governance::voting_power_snapshots::VotingPowerSnapshots;

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
        let now_seconds = self
            .governance
            .with_borrow(|governance| governance.env.now());
        if self
            .snapshots
            .with_borrow(|snapshots| snapshots.is_latest_snapshot_a_spike(now_seconds))
        {
            return (VOTING_POWER_SNAPSHOT_INTERVAL, self);
        }

        let voting_power_snapshot = self.governance.with_borrow_mut(|governance| {
            let voting_power_economics = governance.voting_power_economics();
            governance
                .neuron_store
                .compute_voting_power_snapshot_for_standard_proposal(
                    voting_power_economics,
                    now_seconds,
                )
                .expect("Voting power snapshot failed")
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
                let next_snapshot_timestamp_seconds = last_snapshot_timestamp_seconds
                    .saturating_add(VOTING_POWER_SNAPSHOT_INTERVAL.as_secs());
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

    use ic_nervous_system_common::ONE_DAY_SECONDS;
    use ic_nns_common::pb::v1::NeuronId;
    use ic_stable_structures::{
        DefaultMemoryImpl,
        memory_manager::{MemoryId, MemoryManager},
    };
    use ic_types::PrincipalId;
    use icp_ledger::Subaccount;
    use std::sync::Arc;

    use ic_nns_governance_api as api;

    use crate::{
        neuron::{DissolveStateAndAge, NeuronBuilder},
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
            api::Governance {
                economics: Some(api::NetworkEconomics {
                    voting_power_economics: Some(api::VotingPowerEconomics::DEFAULT),
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
            api::VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS;
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
            // should not return any previous ballots.
            assert_eq!(snapshots.latest_snapshot_timestamp_seconds(), None);
            assert_eq!(
                snapshots.previous_ballots_if_voting_power_spike_detected(u64::MAX, 0),
                None
            )
        });

        let mut task = SnapshotVotingPowerTask::new(&TEST_GOVERNANCE, &TEST_VOTING_POWER_SNAPSHOTS);
        let mut now_seconds = 0;

        for i in 0..7 {
            now_seconds = i * ONE_DAY_SECONDS;
            set_time(now_seconds);
            let (delay, new_task) = task.execute();
            assert_eq!(delay.as_secs(), ONE_DAY_SECONDS);
            task = new_task;
        }

        TEST_VOTING_POWER_SNAPSHOTS.with_borrow(|snapshots| {
            // After the first snapshot, the latest snapshot timestamp should be the current time,
            // and we should disable early adoption given a large deciding voting power.
            assert_eq!(
                snapshots.latest_snapshot_timestamp_seconds(),
                Some(now_seconds)
            );
            let (_timestamp, previous_snapshot) = snapshots
                .previous_ballots_if_voting_power_spike_detected(u64::MAX, now_seconds)
                .unwrap();

            // We only do some sanity checks here to make sure the task is working as expected.
            let (ballots, total_potential_voting_power) =
                previous_snapshot.create_ballots_and_total_potential_voting_power();
            assert!(ballots.get(&1).unwrap().voting_power > 0);
            assert!(total_potential_voting_power > 0);
        });

        // Run the task again after a day, with a doubled voting power.
        now_seconds += ONE_DAY_SECONDS;
        set_time(now_seconds);
        TEST_GOVERNANCE.with_borrow_mut(|governance| {
            governance
                .neuron_store
                .with_neuron_mut(&NeuronId { id: 1 }, |neuron| {
                    neuron.cached_neuron_stake_e8s *= 2
                })
                .unwrap();
        });
        let (_, task) = task.execute();
        TEST_VOTING_POWER_SNAPSHOTS.with_borrow(|snapshots| {
            assert_eq!(
                snapshots.latest_snapshot_timestamp_seconds(),
                Some(now_seconds)
            );
        });

        // Run the task again after another day should not do anything since there is a spike in the snapshots.
        now_seconds += ONE_DAY_SECONDS;
        set_time(now_seconds);
        task.execute();
        TEST_VOTING_POWER_SNAPSHOTS.with_borrow(|snapshots| {
            assert_eq!(
                snapshots.latest_snapshot_timestamp_seconds(),
                Some(now_seconds - ONE_DAY_SECONDS)
            );
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
