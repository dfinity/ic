use crate::governance::{
    Governance,
    disburse_maturity::{finalize_maturity_disbursement, get_delay_until_next_finalization},
};

use async_trait::async_trait;
use ic_nervous_system_timer_task::RecurringAsyncTask;
use std::{cell::RefCell, thread::LocalKey, time::Duration};

pub(super) struct FinalizeMaturityDisbursementsTask {
    governance: &'static LocalKey<RefCell<Governance>>,
}

impl FinalizeMaturityDisbursementsTask {
    pub fn new(governance: &'static LocalKey<RefCell<Governance>>) -> Self {
        Self { governance }
    }
}

#[async_trait]
impl RecurringAsyncTask for FinalizeMaturityDisbursementsTask {
    async fn execute(self) -> (Duration, Self) {
        let delay = finalize_maturity_disbursement(self.governance).await;
        (delay, self)
    }

    fn initial_delay(&self) -> Duration {
        self.governance
            .with_borrow(get_delay_until_next_finalization)
    }

    const NAME: &'static str = "finalize_maturity_disbursements";
}
