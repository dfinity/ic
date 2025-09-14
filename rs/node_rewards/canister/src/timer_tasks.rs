use crate::canister::{BackfillRewardableNodesStatus, NodeRewardsCanister, current_time};
use async_trait::async_trait;
use ic_cdk_timers::{TimerId, clear_timer};
use ic_nervous_system_timer_task::{
    PeriodicSyncTask, RecurringAsyncTask, TimerTaskMetricsRegistry,
};
use std::cell::RefCell;
use std::thread::LocalKey;
use std::time::Duration;

thread_local! {
    static CACHE_SYNC_TIMER_ID: RefCell<Option<TimerId>> = const { RefCell::new(None) };
}

#[derive(Copy, Clone)]
pub struct DailySyncTask {
    canister: &'static LocalKey<RefCell<NodeRewardsCanister>>,
    metrics: &'static LocalKey<RefCell<TimerTaskMetricsRegistry>>,
}

const DAY_IN_SECONDS: u64 = 60 * 60 * 24;
const DAILY_SYNC_AT_SECONDS_AFTER_MIDNIGHT: u64 = 5 * 60; // 5 minutes after midnight
const RETRY_DELAY: Duration = Duration::from_secs(10 * 60); // 10 minutes

impl DailySyncTask {
    pub fn new(
        canister: &'static LocalKey<RefCell<NodeRewardsCanister>>,
        metrics: &'static LocalKey<RefCell<TimerTaskMetricsRegistry>>,
    ) -> Self {
        Self { canister, metrics }
    }

    fn default_delay(&self) -> Duration {
        let now_secs = current_time().as_secs_since_unix_epoch();
        let since_midnight = now_secs % DAY_IN_SECONDS;
        let mut next_sync_target_secs =
            now_secs + DAILY_SYNC_AT_SECONDS_AFTER_MIDNIGHT - since_midnight;
        if since_midnight > DAILY_SYNC_AT_SECONDS_AFTER_MIDNIGHT {
            // already past today's SYNC_AT_SECONDS_AFTER_MIDNIGHT → use tomorrow
            next_sync_target_secs += DAY_IN_SECONDS;
        };

        Duration::from_secs(next_sync_target_secs)
    }
}

#[async_trait]
impl RecurringAsyncTask for DailySyncTask {
    async fn execute(self) -> (Duration, Self) {
        let registry_sync_result = NodeRewardsCanister::schedule_registry_sync(self.canister).await;
        let delay = match registry_sync_result {
            Ok(_) => {
                run_rewardable_nodes_backfill_task(self.canister, self.metrics);

                ic_cdk::futures::spawn_017_compat(async move {
                    NodeRewardsCanister::schedule_metrics_sync(self.canister).await
                });
                self.default_delay()
            }
            Err(e) => {
                ic_cdk::println!("Failed to sync registry: {:?}", e);
                RETRY_DELAY
            }
        };

        (delay, self)
    }

    fn initial_delay(&self) -> Duration {
        Duration::from_secs(0)
    }
    const NAME: &'static str = "daily_sync";
}

#[derive(Copy, Clone)]
pub struct RewardableNodesBackfillTask {
    canister: &'static LocalKey<RefCell<NodeRewardsCanister>>,
}

impl RewardableNodesBackfillTask {
    pub fn new(canister: &'static LocalKey<RefCell<NodeRewardsCanister>>) -> Self {
        Self { canister }
    }
}

impl PeriodicSyncTask for RewardableNodesBackfillTask {
    fn execute(self) {
        let backfill_status = self
            .canister
            .with_borrow(|canister| canister.backfill_rewardable_nodes());

        match backfill_status {
            BackfillRewardableNodesStatus::Completed => {
                CACHE_SYNC_TIMER_ID.with(|id| {
                    if let Some(timer_id) = id.borrow_mut().take() {
                        clear_timer(timer_id);
                    }
                });
                ic_cdk::println!("Backfill completed");
            }
            BackfillRewardableNodesStatus::NotCompleted => {
                ic_cdk::println!("Backfill not completed");
            }
        }
    }

    const NAME: &'static str = "rewardable_nodes_backfill";
    const INTERVAL: Duration = Duration::from_secs(2);
}

fn run_rewardable_nodes_backfill_task(
    canister: &'static LocalKey<RefCell<NodeRewardsCanister>>,
    metrics: &'static LocalKey<RefCell<TimerTaskMetricsRegistry>>,
) {
    CACHE_SYNC_TIMER_ID.with(|id| {
        if id.borrow().is_none() {
            let timer_id = RewardableNodesBackfillTask::new(canister).schedule(metrics);
            id.borrow_mut().replace(timer_id);
        }
    });
}
