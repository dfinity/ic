use crate::governance::Governance;

use ic_nervous_system_timer_task::PeriodicSyncTask;
use std::{cell::RefCell, thread::LocalKey, time::Duration};

/// The interval at which the maturity of dissolved neurons is unstaked. The value is chosen so that
/// even if there is some bug with the task causing it to run out of instructions ever time (50B),
/// given the 2B DTS slice and assuming 1 round per second, there should still be room for other
/// tasks as it will only take 25 seconds to run through the task.
const UNSTAKE_MATURITY_OF_DISSOLVED_NEURONS_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Copy, Clone)]
pub(super) struct UnstakeMaturityOfDissolvedNeuronsTask {
    governance: &'static LocalKey<RefCell<Governance>>,
}

impl UnstakeMaturityOfDissolvedNeuronsTask {
    pub fn new(governance: &'static LocalKey<RefCell<Governance>>) -> Self {
        Self { governance }
    }
}

impl PeriodicSyncTask for UnstakeMaturityOfDissolvedNeuronsTask {
    fn execute(self) {
        self.governance.with_borrow_mut(|governance| {
            governance.unstake_maturity_of_dissolved_neurons();
        });
    }

    const NAME: &'static str = "unstake_maturity_of_dissolved_neurons";
    const INTERVAL: Duration = UNSTAKE_MATURITY_OF_DISSOLVED_NEURONS_INTERVAL;
}
