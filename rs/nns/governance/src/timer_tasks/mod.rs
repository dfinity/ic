use calculate_distributable_rewards::CalculateDistributableRewardsTask;
use ic_metrics_encoder::MetricsEncoder;
use ic_nervous_system_timer_task::{
    RecurringAsyncTask, RecurringSyncTask, TimerTaskMetricsRegistry,
};
use prune_following::PruneFollowingTask;
use seeding::SeedingTask;
use snapshot_voting_power::SnapshotVotingPowerTask;
use std::cell::RefCell;

use crate::{canister_state::GOVERNANCE, storage::VOTING_POWER_SNAPSHOTS};

mod calculate_distributable_rewards;
mod distribute_rewards;
mod prune_following;
mod seeding;
mod snapshot_voting_power;

thread_local! {
    static METRICS_REGISTRY: RefCell<TimerTaskMetricsRegistry> = RefCell::new(TimerTaskMetricsRegistry::default());
}

pub fn schedule_tasks() {
    SeedingTask::new(&GOVERNANCE).schedule(&METRICS_REGISTRY);
    CalculateDistributableRewardsTask::new(&GOVERNANCE).schedule(&METRICS_REGISTRY);
    PruneFollowingTask::new(&GOVERNANCE).schedule(&METRICS_REGISTRY);
    SnapshotVotingPowerTask::new(&GOVERNANCE, &VOTING_POWER_SNAPSHOTS).schedule(&METRICS_REGISTRY);

    run_distribute_rewards_periodic_task();
}

pub fn run_distribute_rewards_periodic_task() {
    distribute_rewards::run_distribute_rewards_periodic_task(&GOVERNANCE, &METRICS_REGISTRY);
}

/// Encodes the metrics for timer tasks.
pub fn encode_timer_task_metrics(encoder: &mut MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    METRICS_REGISTRY.with(|registry| registry.borrow().encode("governance", encoder))
}
