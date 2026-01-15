use crate::governance::Governance;

use ic_nervous_system_timer_task::PeriodicSyncTask;
use std::{cell::RefCell, thread::LocalKey, time::Duration};

const NEURON_DATA_VALIDATION_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Copy, Clone)]
pub(super) struct NeuronDataValidationTask {
    governance: &'static LocalKey<RefCell<Governance>>,
}

impl NeuronDataValidationTask {
    pub fn new(governance: &'static LocalKey<RefCell<Governance>>) -> Self {
        Self { governance }
    }
}

impl PeriodicSyncTask for NeuronDataValidationTask {
    fn execute(self) {
        self.governance.with_borrow_mut(|governance| {
            governance.maybe_run_validations();
        });
    }

    const NAME: &'static str = "neuron_data_validation";
    const INTERVAL: Duration = NEURON_DATA_VALIDATION_INTERVAL;
}
