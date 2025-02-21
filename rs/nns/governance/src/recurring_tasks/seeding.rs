use async_trait::async_trait;
use ic_management_canister_types_private::IC_00;
use ic_nervous_system_recurring_task::RecurringAsyncTask;
use ic_nervous_system_runtime::{CdkRuntime, Runtime};
use std::{cell::RefCell, thread::LocalKey, time::Duration};

use crate::governance::{Governance, LOG_PREFIX};

pub(super) struct SeedingTask {
    governance: &'static LocalKey<RefCell<Governance>>,
}

impl SeedingTask {
    pub fn new(governance: &'static LocalKey<RefCell<Governance>>) -> Self {
        Self { governance }
    }
}

const SEEDING_INTERVAL: Duration = Duration::from_secs(3600);
const RETRY_SEEDING_INTERVAL: Duration = Duration::from_secs(30);

#[async_trait]
impl RecurringAsyncTask for SeedingTask {
    async fn execute(self) -> (Duration, Self) {
        let result: Result<([u8; 32],), (i32, String)> =
            CdkRuntime::call_with_cleanup(IC_00, "raw_rand", ()).await;

        let next_delay = match result {
            Ok((seed,)) => {
                self.governance.with_borrow_mut(|governance| {
                    governance.env.seed_rng(seed);
                });
                SEEDING_INTERVAL
            }
            Err((code, msg)) => {
                println!(
                    "{}Error seeding RNG. Error Code: {}. Error Message: {}",
                    LOG_PREFIX, code, msg
                );
                RETRY_SEEDING_INTERVAL
            }
        };

        (next_delay, self)
    }

    fn initial_delay(&self) -> Duration {
        Duration::from_secs(0)
    }

    const NAME: &'static str = "Seeding";
}
