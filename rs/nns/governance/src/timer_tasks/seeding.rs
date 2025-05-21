use crate::governance::{Governance, LOG_PREFIX};
use async_trait::async_trait;
use candid::{Decode, Encode};
use ic_cdk::println;
use ic_management_canister_types_private::IC_00;
use ic_nervous_system_timer_task::RecurringAsyncTask;
use std::{cell::RefCell, thread::LocalKey, time::Duration};

pub(super) struct SeedingTask {
    governance: &'static LocalKey<RefCell<Governance>>,
}

impl SeedingTask {
    pub fn new(governance: &'static LocalKey<RefCell<Governance>>) -> Self {
        Self { governance }
    }
}

// Seeding interval seeks to find a balance between the need for rng secrecy, and
// avoiding the overhead of frequent reseeding.
const SEEDING_INTERVAL: Duration = Duration::from_secs(3600);
const RETRY_SEEDING_INTERVAL: Duration = Duration::from_secs(30);

#[async_trait]
impl RecurringAsyncTask for SeedingTask {
    async fn execute(self) -> (Duration, Self) {
        let env = self
            .governance
            .with_borrow(|governance| governance.env.clone());

        let result: Result<Vec<u8>, (Option<i32>, String)> = env
            .call_canister_method(IC_00, "raw_rand", Encode!().unwrap())
            .await;

        let next_delay = match result {
            Ok(bytes) => {
                let seed = Decode!(&bytes, [u8; 32]).unwrap();
                self.governance.with_borrow_mut(|governance| {
                    governance.seed_rng(seed);
                });
                SEEDING_INTERVAL
            }
            Err((code, msg)) => {
                println!(
                    "{}Error seeding RNG. Error Code: {:?}. Error Message: {}",
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

    const NAME: &'static str = "seeding";
}
