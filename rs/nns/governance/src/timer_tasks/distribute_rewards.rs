use crate::governance::Governance;
use ic_nervous_system_timer_task::{PeriodicSyncTask, TimerTaskMetricsRegistry};
use ic_nervous_system_timers::{clear_timer, TimerId};
use std::cell::RefCell;
use std::thread::LocalKey;
use std::time::Duration;

thread_local! {
    static REWARDS_TIMER_ID: RefCell<Option<TimerId>> = RefCell::new(None);
}

/// TODO DO NOT MERGE how to test this in context of integration test
fn cancel_distribute_pending_rewards_timer() {
    REWARDS_TIMER_ID.with(|id| {
        if let Some(timer_id) = id.borrow_mut().take() {
            clear_timer(timer_id);
        }
    });
}

pub fn run_distribute_rewards_periodic_task(
    gov: &'static LocalKey<RefCell<Governance>>,
    metrics_registry: &'static LocalKey<RefCell<TimerTaskMetricsRegistry>>,
) {
    REWARDS_TIMER_ID.with(|id| {
        if id.borrow().is_none() {
            let timer_id = DistributeRewardsTask::new(gov).schedule(metrics_registry);
            id.borrow_mut().replace(timer_id);
        }
    });
}

#[derive(Copy, Clone)]
struct DistributeRewardsTask {
    governance: &'static LocalKey<RefCell<Governance>>,
}

impl DistributeRewardsTask {
    pub fn new(governance: &'static LocalKey<RefCell<Governance>>) -> Self {
        Self { governance }
    }
}

impl PeriodicSyncTask for DistributeRewardsTask {
    fn execute(self) {
        self.governance.with_borrow_mut(|governance| {
            let work_left = governance.distribute_pending_rewards();
            if !work_left {
                cancel_distribute_pending_rewards_timer();
            }
        });
    }

    const NAME: &'static str = "distribute_rewards";
    const INTERVAL: Duration = Duration::from_secs(2);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canister_state::{governance_mut, set_governance_for_tests};
    use crate::governance::Governance;
    use crate::reward::distribution::RewardsDistribution;
    use crate::test_utils::{MockEnvironment, MockRandomness, StubCMC, StubIcpLedger};
    use crate::timer_tasks::distribute_rewards::REWARDS_TIMER_ID;
    use ic_nervous_system_timers::test::run_pending_timers_every_interval_for_count;
    use ic_nns_common::pb::v1::NeuronId;
    use std::sync::Arc;

    #[test]
    fn test_reward_scheduling_and_cancelling() {
        let governance_proto = crate::pb::v1::Governance::default();

        let governance = Governance::new(
            governance_proto,
            Arc::new(MockEnvironment::new(Default::default(), 0)),
            Arc::new(StubIcpLedger {}),
            Arc::new(StubCMC {}),
            Box::new(MockRandomness::new()),
        );

        set_governance_for_tests(governance);
        let governance = governance_mut();

        // In this test, we don't care that rewards are actually distributed, only that the
        // timer is scheduled and then cancelled.  Other tests cover that the rewards are distributed.
        let mut distribution = RewardsDistribution::new();
        for id in 0..10 {
            distribution.add_reward(NeuronId { id }, 10);
        }
        // create 2 distributions
        governance.schedule_pending_rewards_distribution(1, distribution.clone());
        assert!(REWARDS_TIMER_ID.with(|id| id.borrow().is_some()));

        run_pending_timers_every_interval_for_count(DistributeRewardsTask::INTERVAL, 3);

        assert!(REWARDS_TIMER_ID.with(|id| id.borrow().is_none()));
    }
}
