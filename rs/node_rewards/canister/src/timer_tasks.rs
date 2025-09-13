use crate::canister::{NodeRewardsCanister, current_time};
use crate::telemetry;
use async_trait::async_trait;
use ic_cdk_timers::{TimerId, clear_timer};
use ic_nervous_system_timer_task::{
    PeriodicSyncTask, RecurringAsyncTask, RecurringSyncTask, TimerTaskMetricsRegistry,
};
use rewards_calculation::performance_based_algorithm::DataProvider;
use rewards_calculation::types::DayUtc;
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
const SYNC_AT_SECONDS_AFTER_MIDNIGHT: u64 = 5 * 60; // 5 minutes after midnight
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
        let mut next_sync_target_secs = now_secs + SYNC_AT_SECONDS_AFTER_MIDNIGHT - since_midnight;
        if since_midnight > SYNC_AT_SECONDS_AFTER_MIDNIGHT {
            // already past today's SYNC_AT_SECONDS_AFTER_MIDNIGHT → use tomorrow
            next_sync_target_secs += DAY_IN_SECONDS;
        };

        Duration::from_secs(next_sync_target_secs)
    }
}

impl RecurringSyncTask for DailySyncTask {
    fn execute(self) -> (Duration, Self) {
        let mut delay: Duration = self.default_delay();
        ic_cdk::futures::spawn_017_compat(async move {
            let registry_sync_result =
                NodeRewardsCanister::schedule_registry_sync(self.canister).await;
            match registry_sync_result {
                Ok(_) => {
                    run_cache_sync_periodic_task(self.canister, self.metrics);

                    NodeRewardsCanister::schedule_metrics_sync(self.canister).await;
                }
                Err(e) => {
                    ic_cdk::println!("Failed to sync local registry: {:?}", e);
                    ic_cdk::println!("Retry registry sync in: {} secs", RETRY_DELAY.as_secs());

                    delay = RETRY_DELAY;
                }
            }
        });

        (delay, self)
    }

    fn initial_delay(&self) -> Duration {
        Duration::from_secs(0)
    }
    const NAME: &'static str = "daily_sync";
}

#[derive(Copy, Clone)]
pub struct CacheSyncTask {
    canister: &'static LocalKey<RefCell<NodeRewardsCanister>>,
}

impl CacheSyncTask {
    pub fn new(canister: &'static LocalKey<RefCell<NodeRewardsCanister>>) -> Self {
        Self { canister }
    }
}

const CACHE_BACKFILL_START_DAY: u64 = 1746057600; // 1st May 2025

impl PeriodicSyncTask for CacheSyncTask {
    fn execute(self) {
        ic_cdk::println!("Executing cache sync task");

        let mut instructions_counter = telemetry::InstructionCounter::default();
        let today = DayUtc::from_secs(current_time().as_secs_since_unix_epoch());
        let start_backfill_day = DayUtc::from_secs(CACHE_BACKFILL_START_DAY);
        let end_backfill_day = today.previous_day();
        let maybe_day_to_backfill: Option<DayUtc> = start_backfill_day
            .days_until(&end_backfill_day)
            .unwrap()
            .into_iter()
            .rev()
            .filter(|day| {
                self.canister
                    .with_borrow(|c| !c.get_rewardable_nodes(day).is_ok())
            })
            .next();

        ic_cdk::println!(
            "instructions counter for evaluating cache: {}",
            instructions_counter.lap()
        );

        if let Some(day_to_backfill) = maybe_day_to_backfill {
            NodeRewardsCanister::backfill_rewardable_nodes(self.canister, &day_to_backfill)
                .unwrap_or_else(|e| ic_cdk::println!("Failed to backfill: {:?}", e));
            ic_cdk::println!(
                "instructions counter cache sync: {}",
                instructions_counter.lap()
            );
            ic_cdk::println!("Cache sync task finished: {}", instructions_counter.sum());
        } else {
            CACHE_SYNC_TIMER_ID.with(|id| {
                if let Some(timer_id) = id.borrow_mut().take() {
                    clear_timer(timer_id);
                    ic_cdk::println!("Timer cleared");
                }
            });
        }
    }

    const NAME: &'static str = "cache_sync";
    const INTERVAL: Duration = Duration::from_secs(2);
}

fn run_cache_sync_periodic_task(
    canister: &'static LocalKey<RefCell<NodeRewardsCanister>>,
    metrics: &'static LocalKey<RefCell<TimerTaskMetricsRegistry>>,
) {
    CACHE_SYNC_TIMER_ID.with(|id| {
        if id.borrow().is_none() {
            let timer_id = CacheSyncTask::new(canister).schedule(metrics);
            id.borrow_mut().replace(timer_id);
        }
    });
}
