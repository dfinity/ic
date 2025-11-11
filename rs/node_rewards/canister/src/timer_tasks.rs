use crate::canister::{NodeRewardsCanister, current_time};
use crate::telemetry;
use chrono::{DateTime, Days, NaiveDate};
use ic_nervous_system_common::ONE_DAY_SECONDS;
use ic_nervous_system_timer_task::RecurringSyncTask;
use ic_node_rewards_canister_api::DateUtc;
use ic_node_rewards_canister_api::provider_rewards_calculation::GetNodeProvidersRewardsCalculationRequest;
use ic_node_rewards_canister_api::providers_rewards::GetNodeProvidersRewardsRequest;
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
        let instruction_counter = telemetry::InstructionCounter::default();

        telemetry::PROMETHEUS_METRICS.with_borrow_mut(|m| m.mark_last_sync_start());
        ic_cdk::futures::spawn_017_compat(async move {
            match NodeRewardsCanister::schedule_registry_sync(self.canister).await {
                Ok(_) => {
                    ic_cdk::println!("Successfully synced local registry");
                    match NodeRewardsCanister::schedule_metrics_sync(self.canister).await {
                        Ok(_) => {
                            telemetry::PROMETHEUS_METRICS
                                .with_borrow_mut(|m| m.mark_last_sync_success());
                            ic_cdk::println!("Successfully synced subnets metrics")
                        }
                        Err(e) => {
                            telemetry::PROMETHEUS_METRICS
                                .with_borrow_mut(|m| m.mark_last_sync_failure());
                            ic_cdk::println!("Failed to sync subnets metrics: {:?}", e)
                        }
                    }
                }
                Err(e) => {
                    telemetry::PROMETHEUS_METRICS.with_borrow_mut(|m| m.mark_last_sync_failure());
                    ic_cdk::println!("Failed to sync local registry: {:?}", e)
                }
            };
        });

        telemetry::PROMETHEUS_METRICS
            .with_borrow_mut(|m| m.record_last_sync_instructions(instruction_counter.sum()));

        (Self::default_delay(), self)
    }

    fn initial_delay(&self) -> Duration {
        Duration::from_secs(0)
    }
    const NAME: &'static str = "hourly_sync";
}

#[derive(Copy, Clone)]
pub struct GetNodeProvidersRewardsInstructionsExporter {
    canister: &'static LocalKey<RefCell<NodeRewardsCanister>>,
}

impl GetNodeProvidersRewardsInstructionsExporter {
    pub fn new(canister: &'static LocalKey<RefCell<NodeRewardsCanister>>) -> Self {
        Self { canister }
    }

    fn default_delay() -> Duration {
        until_ten_minutes_past_midnight()
    }
}
impl RecurringSyncTask for GetNodeProvidersRewardsInstructionsExporter {
    fn execute(self) -> (Duration, Self) {
        // Yesterday
        let to_day = yesterday().pred_opt().unwrap();
        // Yesterday - 35 days
        let from_day = to_day.checked_sub_days(Days::new(35)).unwrap();

        let request = GetNodeProvidersRewardsRequest {
            from_day: DateUtc::from(from_day),
            to_day: DateUtc::from(to_day),
        };

        let instruction_counter = telemetry::InstructionCounter::default();
        if let Err(e) = NodeRewardsCanister::get_node_providers_rewards(self.canister, request) {
            ic_cdk::println!("Failed to get node providers rewards: {:?}", e);
        }

        telemetry::PROMETHEUS_METRICS.with_borrow_mut(|m| {
            m.record_last_get_node_providers_rewards_instructions(instruction_counter.sum())
        });

        ic_cdk::println!("GetNodeProvidersRewardsInstructionsExporter done");

        (Self::default_delay(), self)
    }

    fn initial_delay(&self) -> Duration {
        Duration::from_secs(0)
    }
    const NAME: &'static str = "get_node_providers_rewards_metrics";
}

#[derive(Copy, Clone)]
pub struct NodeProvidersRewardsExporter {
    canister: &'static LocalKey<RefCell<NodeRewardsCanister>>,
}

impl NodeProvidersRewardsExporter {
    pub fn new(canister: &'static LocalKey<RefCell<NodeRewardsCanister>>) -> Self {
        Self { canister }
    }

    fn default_delay() -> Duration {
        until_ten_minutes_past_midnight()
    }
}
impl RecurringSyncTask for NodeProvidersRewardsExporter {
    fn execute(self) -> (Duration, Self) {
        let rewards_dates_stored =
            telemetry::PROMETHEUS_METRICS.with_borrow_mut(|m| m.rewards_dates_stored());

        let yesterday = yesterday();
        let days_ago_35 = yesterday.checked_sub_days(Days::new(35)).unwrap();

        let mut rewards_dates_missing: Vec<NaiveDate> = days_ago_35
            .iter_days()
            .take_while(|d| *d <= yesterday)
            .filter(|d| !rewards_dates_stored.contains(d))
            .collect();

        if let Some(date) = rewards_dates_missing.pop() {
            let request = GetNodeProvidersRewardsCalculationRequest {
                day: DateUtc::from(date),
            };
            match NodeRewardsCanister::get_node_providers_rewards_calculation(
                self.canister,
                request,
            ) {
                Ok(rewards) => {
                    telemetry::PROMETHEUS_METRICS
                        .with_borrow_mut(|m| m.record_node_providers_rewards(date, rewards));
                    telemetry::PROMETHEUS_METRICS.with_borrow_mut(|m| {
                        m.remove_rewards_date(days_ago_35.pred_opt().unwrap())
                    });
                }
                Err(e) => {
                    ic_cdk::println!("Failed to get node providers rewards calculation: {:?}", e)
                }
            }
        }

        if let Some(next_date_to_backfill) = rewards_dates_missing.pop() {
            let date_str = next_date_to_backfill.format("%Y-%m-%d").to_string();
            ic_cdk::println!(
                "GetNodeProvidersRewardsInstructionsExporter next backfill: {}",
                date_str
            );
            (Duration::from_secs(1), self)
        } else {
            ic_cdk::println!("GetNodeProvidersRewardsInstructionsExporter done");
            (Self::default_delay(), self)
        }
    }

    fn initial_delay(&self) -> Duration {
        Duration::from_secs(0)
    }
    const NAME: &'static str = "node_provider_rewards_exporter";
}

pub fn yesterday() -> NaiveDate {
    DateTime::from_timestamp_nanos(current_time().as_nanos_since_unix_epoch() as i64)
        .date_naive()
        .pred_opt()
        .unwrap()
}

fn until_ten_minutes_past_midnight() -> Duration {
    let now_secs = current_time().as_secs_since_unix_epoch();
    let since_midnight = now_secs % ONE_DAY_SECONDS;

    let next_sync_target_secs = if since_midnight < 2 * SYNC_OFFSET {
        now_secs - since_midnight + 2 * SYNC_OFFSET
    } else {
        now_secs - since_midnight + ONE_DAY_SECONDS + 2 * SYNC_OFFSET
    };

    Duration::from_secs(next_sync_target_secs - now_secs)
}
