use crate::governance::Governance;
use ic_nervous_system_timer_task::{PeriodicSyncTask, TimerTaskMetricsRegistry};
use ic_nervous_system_timers::{TimerId, clear_timer};
use std::cell::RefCell;
use std::thread::LocalKey;
use std::time::Duration;

thread_local! {
    static REWARDS_TIMER_ID: RefCell<Option<TimerId>> = const { RefCell::new(None) };
}

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
    use crate::canister_state::{GOVERNANCE, legacy_governance_mut, set_governance_for_tests};
    use crate::governance::Governance;
    use crate::reward::distribution::RewardsDistribution;
    use crate::test_utils::{MockEnvironment, MockRandomness, StubCMC, StubIcpLedger};
    use crate::timer_tasks::distribute_rewards::REWARDS_TIMER_ID;
    use ic_nervous_system_timers::test::{
        existing_timer_ids, has_timer_task, run_pending_timers_every_interval_for_count,
    };
    use ic_nns_common::pb::v1::NeuronId;
    use std::sync::Arc;

    #[test]
    fn test_reward_scheduling_and_cancelling() {
        thread_local! {
            static METRICS_REGISTRY: RefCell<TimerTaskMetricsRegistry> = RefCell::new(TimerTaskMetricsRegistry::default());
        }

        let governance = Governance::new(
            Default::default(),
            Arc::new(MockEnvironment::new(Default::default(), 0)),
            Arc::new(StubIcpLedger {}),
            Arc::new(StubCMC {}),
            Box::new(MockRandomness::new()),
        );

        set_governance_for_tests(governance);
        let governance = legacy_governance_mut();

        // In this test, we don't care that rewards are actually distributed, only that the
        // timer is scheduled and then cancelled.  Other tests cover that the rewards are distributed.
        let mut distribution = RewardsDistribution::new();
        for id in 0..10 {
            distribution.add_reward(NeuronId { id }, 10);
        }

        // Schedule the rewards distribution
        governance.schedule_pending_rewards_distribution(1, distribution.clone());
        let timer_id = REWARDS_TIMER_ID.with(|id| (*id.borrow()).unwrap());
        assert_eq!(existing_timer_ids().len(), 1);

        // Attempt to schedule the task again, which should fail
        run_distribute_rewards_periodic_task(&GOVERNANCE, &METRICS_REGISTRY);

        // Another timer should not be scheduled
        assert_eq!(existing_timer_ids().len(), 1);
        // Existing timer should be the only one scheduled.
        assert!(has_timer_task(timer_id));

        // We run this 10x b/c test version of is_over_instructions_limit returns true every
        // other time it's called.
        run_pending_timers_every_interval_for_count(DistributeRewardsTask::INTERVAL, 10);

        assert!(REWARDS_TIMER_ID.with(|id| id.borrow().is_none()));
        assert_eq!(existing_timer_ids().len(), 0);
    }
}
