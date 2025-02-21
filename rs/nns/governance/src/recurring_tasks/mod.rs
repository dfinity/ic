use batch_adjust_neuron_storage::BatchAdjustNeuronsStorageTask;
use ic_nervous_system_recurring_task::{MetricsRegistry, RecurringAsyncTask, RecurringSyncTask};
use prune_following::PruneFollowingTask;
use seeding::SeedingTask;
use spawn_neurons::SpawnNeuronsTask;
use std::{cell::RefCell, thread::LocalKey};

use crate::{governance::Governance, is_prune_following_enabled};

mod batch_adjust_neuron_storage;
mod prune_following;
mod seeding;
mod spawn_neurons;

thread_local! {
    static METRICS_REGISTRY: RefCell<MetricsRegistry> = RefCell::new(MetricsRegistry::default());
}

pub fn schedule_tasks(governance: &'static LocalKey<RefCell<Governance>>) {
    BatchAdjustNeuronsStorageTask::new(governance).schedule(&METRICS_REGISTRY);
    SeedingTask::new(governance).schedule(&METRICS_REGISTRY);
    if is_prune_following_enabled() {
        PruneFollowingTask::new(governance).schedule(&METRICS_REGISTRY);
    }
}
