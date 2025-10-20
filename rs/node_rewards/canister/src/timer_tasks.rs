use crate::canister::{NodeRewardsCanister, current_time};
use ic_nervous_system_timer_task::RecurringSyncTask;
use std::cell::RefCell;
use std::thread::LocalKey;
use std::time::Duration;

const SECS_PER_HOUR: u64 = 3600;

// This offset makes sure that the first sync of the day happens at 00:05, times that guarantees
// All the subnets have collected metrics for the previous day
const SYNC_OFFSET: u64 = 5 * 60; // 5 minutes in seconds

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

        // Target is delaying execution until the next hour plus SYNC_OFFSET.
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
            match NodeRewardsCanister::schedule_registry_sync(self.canister).await {
                Ok(_) => {
                    ic_cdk::println!("Successfully synced local registry");
                    match NodeRewardsCanister::schedule_metrics_sync(self.canister).await {
                        Ok(_) => {
                            ic_cdk::println!("Successfully synced subnets metrics")
                        }
                        Err(e) => {
                            ic_cdk::println!("Failed to sync subnets metrics: {:?}", e)
                        }
                    }
                }
                Err(e) => {
                    ic_cdk::println!("Failed to sync local registry: {:?}", e)
                }
            };
        });

        (Self::default_delay(), self)
    }

    fn initial_delay(&self) -> Duration {
        Duration::from_secs(0)
    }
    const NAME: &'static str = "hourly_sync";
}
