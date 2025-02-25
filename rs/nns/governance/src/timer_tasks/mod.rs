use ic_nervous_system_timer_task::RecurringAsyncTask;
use seeding::SeedingTask;

use crate::canister_state::GOVERNANCE;
use crate::timer_tasks::reward_distribution::CalculateDistributableRewardsTask;

mod reward_distribution;
mod seeding;

pub fn schedule_tasks() {
    SeedingTask::new(&GOVERNANCE).schedule();
    CalculateDistributableRewardsTask::new(&GOVERNANCE).schedule();
}
