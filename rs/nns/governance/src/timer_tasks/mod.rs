use calculate_distributable_rewards::CalculateDistributableRewardsTask;
use finalize_maturity_disbursements::FinalizeMaturityDisbursementsTask;
use ic_metrics_encoder::MetricsEncoder;
use ic_nervous_system_timer_task::{
    PeriodicSyncTask, RecurringAsyncTask, RecurringSyncTask, TimerTaskMetricsRegistry,
};
use neuron_data_validation::NeuronDataValidationTask;
use prune_following::PruneFollowingTask;
use seeding::SeedingTask;
use snapshot_voting_power::SnapshotVotingPowerTask;
use std::cell::RefCell;
use unstake_maturity_of_dissolved_neurons::UnstakeMaturityOfDissolvedNeuronsTask;

use crate::{canister_state::GOVERNANCE, storage::VOTING_POWER_SNAPSHOTS};

mod calculate_distributable_rewards;
mod distribute_rewards;
mod finalize_maturity_disbursements;
mod neuron_data_validation;
mod prune_following;
mod seeding;
mod snapshot_voting_power;
mod unstake_maturity_of_dissolved_neurons;

thread_local! {
    static METRICS_REGISTRY: RefCell<TimerTaskMetricsRegistry> = RefCell::new(TimerTaskMetricsRegistry::default());
}

pub fn schedule_tasks() {
    SeedingTask::new(&GOVERNANCE).schedule(&METRICS_REGISTRY);
    CalculateDistributableRewardsTask::new(&GOVERNANCE).schedule(&METRICS_REGISTRY);
    PruneFollowingTask::new(&GOVERNANCE).schedule(&METRICS_REGISTRY);
    SnapshotVotingPowerTask::new(&GOVERNANCE, &VOTING_POWER_SNAPSHOTS).schedule(&METRICS_REGISTRY);
    FinalizeMaturityDisbursementsTask::new(&GOVERNANCE).schedule(&METRICS_REGISTRY);
    UnstakeMaturityOfDissolvedNeuronsTask::new(&GOVERNANCE).schedule(&METRICS_REGISTRY);
    NeuronDataValidationTask::new(&GOVERNANCE).schedule(&METRICS_REGISTRY);

    run_distribute_rewards_periodic_task();
}

pub fn run_distribute_rewards_periodic_task() {
    distribute_rewards::run_distribute_rewards_periodic_task(&GOVERNANCE, &METRICS_REGISTRY);
}

/// Encodes the metrics for timer tasks.
pub fn encode_timer_task_metrics(encoder: &mut MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    METRICS_REGISTRY.with(|registry| registry.borrow().encode("governance", encoder))
}
