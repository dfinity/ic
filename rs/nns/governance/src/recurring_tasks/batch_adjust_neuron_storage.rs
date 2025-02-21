use crate::governance::Governance;

use ic_nervous_system_recurring_task::RecurringSyncTask;
use ic_nns_common::pb::v1::NeuronId;
use std::{cell::RefCell, ops::Bound, thread::LocalKey, time::Duration};

const ADJUST_NEURON_STORAGE_BATCH_INTERVAL: Duration = Duration::from_secs(5);
const ADJUST_NEURON_STORAGE_ROUND_INTERVAL: Duration = Duration::from_secs(3600);

pub(super) struct BatchAdjustNeuronsStorageTask {
    governance: &'static LocalKey<RefCell<Governance>>,
    next: Bound<NeuronId>,
}

impl BatchAdjustNeuronsStorageTask {
    pub fn new(governance: &'static LocalKey<RefCell<Governance>>) -> Self {
        Self {
            governance,
            next: Bound::Unbounded,
        }
    }
}

impl RecurringSyncTask for BatchAdjustNeuronsStorageTask {
    fn execute(self) -> (Duration, Self) {
        let next = self
            .governance
            .with_borrow_mut(|governance| governance.batch_adjust_neurons_storage(self.next));
        let next_delay = if next == Bound::Unbounded {
            ADJUST_NEURON_STORAGE_ROUND_INTERVAL
        } else {
            ADJUST_NEURON_STORAGE_BATCH_INTERVAL
        };
        (
            next_delay,
            BatchAdjustNeuronsStorageTask {
                governance: self.governance,
                next,
            },
        )
    }

    fn initial_delay(&self) -> Duration {
        Duration::from_secs(0)
    }

    const NAME: &'static str = "BatchAdjustNeuronsStorage";
}
