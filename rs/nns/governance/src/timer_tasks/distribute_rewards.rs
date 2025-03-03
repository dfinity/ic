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
