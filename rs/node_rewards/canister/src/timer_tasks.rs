use crate::canister::{NodeRewardsCanister, current_time};
use crate::telemetry;
use async_trait::async_trait;
use chrono::{DateTime, Days, NaiveDate};
#[cfg(not(target_arch = "wasm32"))]
use futures::FutureExt;
#[cfg(target_arch = "wasm32")]
use ic_cdk::futures::spawn;
use ic_cdk_timers::clear_timer;
use ic_nervous_system_common::ONE_DAY_SECONDS;
use ic_nervous_system_timer_task::set_timer;
use ic_node_rewards_canister_api::DateUtc;
use ic_node_rewards_canister_api::providers_rewards::GetNodeProvidersRewardsRequest;
use std::cell::{Cell, RefCell};
use std::future::Future;
use std::rc::Rc;
use std::thread::LocalKey;
use std::time::Duration;

const SECS_PER_HOUR: u64 = 3600;

// This offset makes sure that the first sync of the day happens at 00:05, times that guarantees
// All the subnets have collected metrics for the previous day
const SYNC_OFFSET: u64 = 5 * 60; // 5 minutes in seconds

const RETRY_FAILED_SYNC_SECS: u64 = 5 * 60; // 5 minutes in seconds

/// How long after starting an execution the recovery timer presumes it trapped.
///
/// Should stay well above the longest a legitimate execution can take,
/// including the timeouts of every call it awaits — the sync awaits calls that
/// give up after the CDK's default 300s, so this is comfortably above that.
/// Kept separate from [`RETRY_FAILED_SYNC_SECS`]: sharing one number left the
/// deadline exactly equal to those call timeouts, so a single unresponsive
/// callee was guaranteed to trip it.
///
/// Tripping it is no longer harmful — see [`RescheduleOnce`] — so this value
/// only decides how eagerly a trapped execution is replaced, not whether the
/// task can fork. That matters, because the registry-sync phase is a loop of
/// sequential calls whose length is not bounded in code: no constant here can
/// be *proven* to exceed the worst case.
const RECOVERY_DELAY_SECS: u64 = 30 * 60; // 30 minutes in seconds

/// Guards the two paths that can reschedule a task — normal completion and the
/// recovery timer — so that an execution always has exactly one successor.
/// Whichever path claims it first wins; the other stands down.
///
/// This is what keeps a slow execution from forking the chain. The recovery
/// timer cannot distinguish "trapped" from "still awaiting responses", and with
/// this it does not need to: it takes over the chain, and the execution it gave
/// up on quietly declines to reschedule when it eventually finishes. Without
/// it, an execution that outlived its recovery delay produced *two*
/// successors, each of which forked again — enough forks and every call the
/// canister makes fails to be enqueued.
#[derive(Clone)]
struct RescheduleOnce(Rc<Cell<bool>>);

impl RescheduleOnce {
    fn new() -> Self {
        Self(Rc::new(Cell::new(false)))
    }

    /// Returns `true` for the first caller only.
    fn claim(&self) -> bool {
        !self.0.replace(true)
    }
}

fn spawn_in_canister_env(future: impl Future<Output = ()> + Sized + 'static) {
    #[cfg(target_arch = "wasm32")]
    {
        spawn(future);
    }
    // This is needed for tests
    #[cfg(not(target_arch = "wasm32"))]
    {
        future
            .now_or_never()
            .expect("Future could not execute in non-WASM environment");
    }
}

#[async_trait(?Send)]
pub trait RecurringAsyncTaskNonSend: Clone + Sized + 'static {
    async fn execute(self) -> (Duration, Self);
    fn initial_delay(&self) -> Duration;
    fn recovery_delay(&self) -> Duration;

    fn schedule_with_delay(self, delay: Duration) {
        set_timer(delay, async move {
            // Exactly one successor per execution, whichever path gets there
            // first. See [`RescheduleOnce`].
            let reschedule = RescheduleOnce::new();

            // Set a recovery timer before spawning the task. The timer callback
            // and the spawned future run in different IC messages, so if the
            // spawned future traps, the recovery timer survives and will reschedule the task.
            let recovery = self.clone();
            let recovery_delay = recovery.recovery_delay();
            let recovery_reschedule = reschedule.clone();
            let recovery_timer_id = set_timer(recovery_delay, async move {
                if recovery_reschedule.claim() {
                    ic_cdk::println!(
                        "Task {} recovery timer fired — rescheduling after suspected trap.",
                        Self::NAME,
                    );
                    recovery.schedule_with_delay(recovery_delay);
                }
            });

            spawn_in_canister_env(async move {
                let (new_delay, new_task) = self.execute().await;

                clear_timer(recovery_timer_id);
                if reschedule.claim() {
                    new_task.schedule_with_delay(new_delay);
                } else {
                    // The recovery timer already took over the chain; forking a
                    // second one here is what multiplied concurrent syncs.
                    ic_cdk::println!(
                        "Task {} finished after its recovery timer rescheduled it; not scheduling a second successor.",
                        Self::NAME,
                    );
                }
            });
        });
    }

    fn schedule(self) {
        let initial_delay = self.initial_delay();
        self.schedule_with_delay(initial_delay);
    }

    const NAME: &'static str;
}

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

// TODO: Make this task Send once MetricsManager and StableCanisterRegistryClient are Send.
#[async_trait(?Send)]
impl RecurringAsyncTaskNonSend for HourlySyncTask {
    async fn execute(self) -> (Duration, Self) {
        let instruction_counter = telemetry::InstructionCounter::default();
        telemetry::PROMETHEUS_METRICS.with_borrow_mut(|m| m.mark_last_sync_start());

        // First sync the local registry
        if let Err(e) = NodeRewardsCanister::schedule_registry_sync(self.canister).await {
            telemetry::PROMETHEUS_METRICS.with_borrow_mut(|m| m.mark_last_sync_failure());
            ic_cdk::println!("Failed to sync local registry: {:?}", e);

            return (Duration::from_secs(RETRY_FAILED_SYNC_SECS), self);
        }

        // Then sync the subnets metrics
        if let Err(e) = NodeRewardsCanister::schedule_metrics_sync(self.canister).await {
            telemetry::PROMETHEUS_METRICS.with_borrow_mut(|m| m.mark_last_sync_failure());
            ic_cdk::println!("Failed to sync subnets metrics: {:?}", e);

            return (Duration::from_secs(RETRY_FAILED_SYNC_SECS), self);
        }

        telemetry::PROMETHEUS_METRICS.with_borrow_mut(|m| {
            m.mark_last_sync_success();
            m.record_last_sync_instructions(instruction_counter.sum());
        });

        ic_cdk::println!("Successfully synced registry and subnets metrics");

        (Self::default_delay(), self)
    }

    fn initial_delay(&self) -> Duration {
        Duration::from_secs(0)
    }

    fn recovery_delay(&self) -> Duration {
        Duration::from_secs(RECOVERY_DELAY_SECS)
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
        let now_secs = current_time().as_secs_since_unix_epoch();
        let since_midnight = now_secs % ONE_DAY_SECONDS;

        let next_sync_target_secs = if since_midnight < 2 * SYNC_OFFSET {
            now_secs - since_midnight + 2 * SYNC_OFFSET
        } else {
            now_secs - since_midnight + ONE_DAY_SECONDS + 2 * SYNC_OFFSET
        };

        Duration::from_secs(next_sync_target_secs - now_secs)
    }
}
#[async_trait(?Send)]
impl RecurringAsyncTaskNonSend for GetNodeProvidersRewardsInstructionsExporter {
    async fn execute(self) -> (Duration, Self) {
        let to_day = yesterday().pred_opt().unwrap();
        let from_day = to_day.checked_sub_days(Days::new(35)).unwrap();

        let request = GetNodeProvidersRewardsRequest {
            from_day: DateUtc::from(from_day),
            to_day: DateUtc::from(to_day),
            algorithm_version: None,
        };

        let instruction_counter = telemetry::InstructionCounter::default();
        match NodeRewardsCanister::get_node_providers_rewards(self.canister, request).await {
            Ok(_) => {
                telemetry::PROMETHEUS_METRICS.with_borrow_mut(|m| {
                    m.mark_last_get_node_providers_rewards_success();
                    m.record_last_get_node_providers_rewards_instructions(
                        instruction_counter.sum(),
                    );
                });
            }
            Err(e) => {
                // The instruction metrics are deliberately left alone. A calculation that gives up
                // partway through costs less than one that finishes, so recording it would show
                // the cost falling at the moment rewards stopped being computed. What reports the
                // failure is the success timestamp above going stale.
                ic_cdk::println!("Failed to get node providers rewards: {:?}", e);
            }
        }

        (Self::default_delay(), self)
    }

    fn initial_delay(&self) -> Duration {
        Duration::from_secs(0)
    }
    fn recovery_delay(&self) -> Duration {
        Duration::from_secs(RECOVERY_DELAY_SECS)
    }
    const NAME: &'static str = "get_node_providers_rewards_metrics";
}

pub fn yesterday() -> NaiveDate {
    DateTime::from_timestamp_nanos(current_time().as_nanos_since_unix_epoch() as i64)
        .date_naive()
        .pred_opt()
        .unwrap()
}

#[cfg(feature = "test")]
pub mod test_tasks {
    use super::*;
    use std::cell::Cell;

    const TEST_RECOVERY_DELAY_SECS: u64 = 10;
    const SUCCESS_TASK_DELAY_SECS: u64 = 5;

    thread_local! {
        static PANIC_TASK_COUNTER: Cell<u64> = const { Cell::new(0) };
        static SUCCESS_TASK_COUNTER: Cell<u64> = const { Cell::new(0) };
    }

    pub fn get_panic_task_counter() -> u64 {
        PANIC_TASK_COUNTER.with(|c| c.get())
    }

    pub fn get_success_task_counter() -> u64 {
        SUCCESS_TASK_COUNTER.with(|c| c.get())
    }

    #[derive(Clone)]
    pub struct PanickingRecoveryTask;

    #[async_trait(?Send)]
    impl RecurringAsyncTaskNonSend for PanickingRecoveryTask {
        async fn execute(self) -> (Duration, Self) {
            PANIC_TASK_COUNTER.with(|c| c.set(c.get() + 1));

            ic_cdk::call::Call::unbounded_wait(ic_cdk::api::canister_self(), "__self_call")
                .await
                .unwrap();

            panic!("intentional panic for recovery timer test");
        }

        fn initial_delay(&self) -> Duration {
            Duration::from_secs(0)
        }

        fn recovery_delay(&self) -> Duration {
            Duration::from_secs(TEST_RECOVERY_DELAY_SECS)
        }

        const NAME: &'static str = "panicking_recovery_task";
    }

    #[derive(Clone)]
    pub struct SuccessRecoveryTask;

    #[async_trait(?Send)]
    impl RecurringAsyncTaskNonSend for SuccessRecoveryTask {
        async fn execute(self) -> (Duration, Self) {
            SUCCESS_TASK_COUNTER.with(|c| c.set(c.get() + 1));

            ic_cdk::call::Call::unbounded_wait(ic_cdk::api::canister_self(), "__self_call")
                .await
                .unwrap();

            (Duration::from_secs(SUCCESS_TASK_DELAY_SECS), self)
        }

        fn initial_delay(&self) -> Duration {
            Duration::from_secs(0)
        }

        fn recovery_delay(&self) -> Duration {
            Duration::from_secs(TEST_RECOVERY_DELAY_SECS)
        }

        const NAME: &'static str = "success_recovery_task";
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An execution and its recovery timer share one token, so exactly one of
    /// them schedules the successor. Both scheduling means the chain forks, and
    /// forks multiply until the canister runs out of call capacity.
    #[test]
    fn only_the_first_claimant_reschedules() {
        let reschedule = RescheduleOnce::new();
        let recovery = reschedule.clone();

        assert!(
            recovery.claim(),
            "the recovery timer claims an unclaimed token"
        );
        assert!(
            !reschedule.claim(),
            "the execution must stand down once the recovery timer has taken over"
        );
        assert!(!recovery.claim(), "a token cannot be claimed twice");
    }

    /// The common case: the execution finishes first, so it reschedules and the
    /// recovery timer does not, even if it somehow fires afterwards.
    #[test]
    fn execution_claims_before_recovery() {
        let reschedule = RescheduleOnce::new();
        let recovery = reschedule.clone();

        assert!(reschedule.claim());
        assert!(!recovery.claim());
    }
}
