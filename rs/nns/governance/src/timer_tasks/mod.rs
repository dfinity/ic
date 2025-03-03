use ic_nervous_system_timer_task::{RecurringAsyncTask, TimerTaskMetricsRegistry};
use seeding::SeedingTask;
use std::cell::RefCell;

use crate::canister_state::GOVERNANCE;
use crate::timer_tasks::reward_distribution::CalculateDistributableRewardsTask;

mod reward_distribution;
mod seeding;

thread_local! {
    static METRICS_REGISTRY: RefCell<TimerTaskMetricsRegistry> = RefCell::new(TimerTaskMetricsRegistry::default());
}

pub fn schedule_tasks() {
    SeedingTask::new(&GOVERNANCE).schedule(&METRICS_REGISTRY);
    CalculateDistributableRewardsTask::new(&GOVERNANCE).schedule(&METRICS_REGISTRY);
}
