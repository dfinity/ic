use crate::canister::{NodeRewardsCanister, current_time};
use ic_nervous_system_timer_task::RecurringSyncTask;
use std::cell::RefCell;
use std::thread::LocalKey;
use std::time::Duration;
// ================================================================================================
// HOURLY SYNC TASK
// ================================================================================================

const SECS_PER_HOUR: u64 = 3600;
const SYNC_OFFSET: u64 = 5 * 60; // 5 minutes in seconds

// The frequency of regular registry syncs.  This is set to 1 hour to avoid
// making too many requests.  Before meaningful calculations are made, however, the
// registry data should be updated.
const SYNC_INTERVAL_SECONDS: Duration = Duration::from_secs(60 * 60); // 1 hour

#[derive(Copy, Clone)]
pub struct HourlySyncTask {
    canister: &'static LocalKey<RefCell<NodeRewardsCanister>>,
}

impl HourlySyncTask {
    pub fn new(canister: &'static LocalKey<RefCell<NodeRewardsCanister>>) -> Self {
        Self { canister }
    }

    fn default_delay() -> Duration {
        let now_secs = current_time().as_secs_since_unix_epoch();
        let since_hour = now_secs % SECS_PER_HOUR;

        // Target is 5 minutes into the current hour if we haven't passed it yet,
        // otherwise 5 minutes into the next hour.
        let next_sync_target_secs = if since_hour < SYNC_OFFSET {
            now_secs - since_hour + SYNC_OFFSET
        } else {
            now_secs - since_hour + SECS_PER_HOUR + SYNC_OFFSET
        };

        Duration::from_secs(next_sync_target_secs - now_secs)
    }
}

impl RecurringSyncTask for HourlySyncTask {
    fn execute(self) -> (Duration, Self) {
        ic_cdk::futures::spawn_017_compat(async move {
            match NodeRewardsCanister::sync(self.canister).await {
                Ok(_) => {
                    ic_cdk::println!("Successfully synced subnets metrics and local registry");
                }
                Err(e) => {
                    ic_cdk::println!("Failed to sync local registry: {:?}", e)
                }
            };
        });

        (SYNC_INTERVAL_SECONDS, self)
    }

    fn initial_delay(&self) -> Duration {
        Duration::from_secs(0)
    }
    const NAME: &'static str = "hourly_sync";
}
