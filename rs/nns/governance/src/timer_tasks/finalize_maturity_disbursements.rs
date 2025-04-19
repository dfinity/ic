use crate::governance::{
    disburse_maturity::{
        finalize_maturity_disbursement, next_maturity_disbursement_to_finalize,
        DISBURSEMENT_DELAY_SECONDS,
    },
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

// We do not run the task more frequently than once a minute, so that if there is anything wrong
// with the task, we don't use too many resources. How this is chosen: assuming the task can max out
// the 50B instruction limit and it takes 2B instructions per DTS slice, then the task can run for
// 25 rounds; with 1.5 rounds per second, it will take ~ 16 seconds to run. The minimum task
// interval is chosen to be larger than 16 seconds so that the canister would be able to do other
// work in the meantime.
const MINIMUM_TASK_INTERVAL: Duration = Duration::from_secs(60);

#[async_trait]
impl RecurringAsyncTask for FinalizeMaturityDisbursementsTask {
    async fn execute(self) -> (Duration, Self) {
        let (now_seconds, maturity_disbursement_finalization) =
            self.governance.with_borrow(|governance| {
                let now_seconds = governance.env.now();
                let maturity_disbursement_finalization = next_maturity_disbursement_to_finalize(
                    &governance.neuron_store,
                    &governance.heap_data.in_flight_commands,
                    governance
                        .heap_data
                        .cached_daily_maturity_modulation_basis_points,
                    now_seconds,
                );
                (now_seconds, maturity_disbursement_finalization)
            });
        let maturity_disbursement_finalization = match maturity_disbursement_finalization {
            Err(error) => {
                ic_cdk::eprintln!("Error finalizing maturity disbursement: {:?}", error);
                return (MINIMUM_TASK_INTERVAL, self);
            }
            Ok(None) => {
                return (self.delay_until_next_run(), self);
            }
            Ok(Some(maturity_disbursement_finalization)) => maturity_disbursement_finalization,
        };

        finalize_maturity_disbursement(
            self.governance,
            maturity_disbursement_finalization,
            now_seconds,
        )
        .await;

        (self.delay_until_next_run(), self)
    }

    fn initial_delay(&self) -> Duration {
        self.delay_until_next_run()
    }

    const NAME: &'static str = "finalize_maturity_disbursements";
}

impl FinalizeMaturityDisbursementsTask {
    /// Returns the time until the next maturity disbursement is due.
    fn delay_until_next_run(&self) -> Duration {
        let (now_seconds, next_maturity_disbursement_finalization_timestamp) =
            self.governance.with_borrow(|governance| {
                let now_seconds = governance.env.now();
                let next_maturity_disbursement_finalization_timestamp = governance
                    .neuron_store
                    .get_next_maturity_disbursement_finalization_timestamp();
                (
                    now_seconds,
                    next_maturity_disbursement_finalization_timestamp,
                )
            });
        let Some(next_maturity_disbursement_finalization_timestamp) =
            next_maturity_disbursement_finalization_timestamp
        else {
            // There is no maturity disbursement at all, and sin
            return Duration::from_secs(DISBURSEMENT_DELAY_SECONDS);
        };
        let delay = Duration::from_secs(
            next_maturity_disbursement_finalization_timestamp.saturating_sub(now_seconds),
        );
        delay.min(MINIMUM_TASK_INTERVAL)
    }
}
