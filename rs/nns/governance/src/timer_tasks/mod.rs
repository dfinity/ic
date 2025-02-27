use ic_nervous_system_timer_task::RecurringAsyncTask;
use seeding::SeedingTask;

use crate::canister_state::GOVERNANCE;

mod seeding;

pub fn schedule_tasks() {
    SeedingTask::new(&GOVERNANCE).schedule();
}
