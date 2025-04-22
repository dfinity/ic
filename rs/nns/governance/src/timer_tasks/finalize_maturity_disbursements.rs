use crate::governance::{
    disburse_maturity::{finalize_maturity_disbursement, get_delay_until_next_finalization},
    Governance,
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

// We do not retry the task more frequently than once a minute, so that if there is anything wrong
// with the task, we don't use too many resources. How this is chosen: assuming the task can max out
// the 50B instruction limit and it takes 2B instructions per DTS slice, then the task can run for
// 25 rounds; with 1.5 rounds per second, it will take ~ 16 seconds to run. The minimum task
// interval is chosen to be larger than 16 seconds so that the canister would be able to do other
// work in the meantime.
const RETRY_INTERVAL: Duration = Duration::from_secs(60);

#[async_trait]
impl RecurringAsyncTask for FinalizeMaturityDisbursementsTask {
    async fn execute(self) -> (Duration, Self) {
        match finalize_maturity_disbursement(self.governance).await {
            Ok(_) => (self.delay_until_next_run(), self),
            Err(err) => {
                ic_cdk::println!("FinalizeMaturityDisbursementsTask failed: {}", err);
                (RETRY_INTERVAL, self)
            }
        }
    }

    fn initial_delay(&self) -> Duration {
        self.delay_until_next_run()
    }

    const NAME: &'static str = "finalize_maturity_disbursements";
}

impl FinalizeMaturityDisbursementsTask {
    /// Returns the time until the next maturity disbursement is due.
    fn delay_until_next_run(&self) -> Duration {
        self.governance
            .with_borrow(|governance| get_delay_until_next_finalization(governance, RETRY_INTERVAL))
    }
}
