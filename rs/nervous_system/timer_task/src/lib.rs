//! This module contains traits for defining timer tasks that runs indefinitely during the lifetime
//! of a canister.
//!
//! There are two dimensions regarding the types of tasks:
//! 1. Sync vs. async: whether the task is synchronous or asynchronous.
//! 2. Recurring vs. periodic: whether the task is scheduled to run at variable intervals (depending
//!    on the task's logic) or at fixed intervals.
//!
//! When the tasks are defined to implement the traits in this module, metrics are automatically
//! collected for each task into a `MetricsRegistry`. The metrics include the number of times the
//! task has run, the number of instructions used by the task, and a histogram of the number of
//! instructions used by the task.
//!
//! More considerations about the task types:
//! - Sync tasks are atomic, so its metrics include a count which increments when the task finishes.
//!   It's impossible for a sync task to start but not finish, or rather, such state can never be
//!   observed due to the execution model.
//! - Async tasks are not atomic, so its metrics include two counts: the number of tasks that have
//!   started but not finished, and the number of tasks that have finished. Its instruction metrics
//!   come from the `call_context_instruction_counter` which measures across multiple messages within
//!   the same call context.
//! - Periodic tasks are defined as a closure that can run multiple times. Therefore, its context is
//!   typically managed outside of the closure (e.g. part of the canister state). Note that if the
//!   task panics in one iteration, it will still be scheduled to run at the next interval. Usually,
//!   the task member should only contain a reference to the canister state. Note that if the task
//!   interval is T, the task will be scheduled to run at t=T, t=2T, t=3T, and so on, but NOT t = 0.
//! - Recurring tasks are repeatedly scheduled after its completion, and therefore there is more
//!   flexibility in how the next iteration can be scheduled, both in terms of the delay and the task
//!   itself. For example, the task can contain a cursor, and the cursor for the next iteration can
//!   be computed after the current iteration finishes, so can the delay. Note that if the task
//!   panics in one iteration, it will NOT be scheduled again. It can, however, catch any errors and
//!   implement its own retry logic by specifying the next task (e.g. the same as the one failed) and
//!   a new delay (e.g. exponential backoff).
//!
//! # Example
//!
//! ```
//! struct SomeRecurringSyncTask {
//!     state: &'static LocalKey<RefCell<CanisterState>>,
//!     cursor: SomeCursor,
//! }
//!
//! impl RecurringSyncTask for SomeRecurringSyncTask {
//!   fn execute(self) -> (Duration, Self) {
//!     let result = self.state.with_borrow_mut(|state| state.do_something(self.cursor));
//!     match result {
//!         Ok(new_cursor) => (SUCCEED_DELAY, SomeTask { state: self.state, cursor: new_cursor }),
//!         Err(_) => (RETRY_DELAY, self),
//!    }
//!   fn initial_delay(&self) -> Duration { Duration::from_secs(0) }
//!
//!   const NAME: &'static str = "some_recurring_sync_task";
//! }
//!
//!
//! struct SomePeriodicSyncTask {
//!     state: &'static LocalKey<RefCell<CanisterState>>,
//! }
//!
//! impl PeriodicSyncTask for SomePeriodicSyncTask {
//!   fn execute(self) {
//!    self.state.with_borrow_mut(|state| state.do_something());
//!   }
//!
//!   const NAME: &'static str = "some_periodic_sync_task";
//!   const INTERVAL: Duration = Duration::from_secs(10);
//! }
//!
//! struct SomeRecurringAsyncTask {
//!     state: &'static LocalKey<RefCell<CanisterState>>,
//!     cursor: SomeCursor,
//! }
//!
//! #[async_trait]
//! impl RecurringAsyncTask for SomeRecurringAsyncTask {
//!   async fn execute(self) -> (Duration, Self) {
//!     let result = self.state.with_borrow_mut(|state| state.do_something(self.cursor)).await;
//!     match result {
//!       Ok(new_cursor) => (SUCCEED_DELAY, SomeTask { state: self.state, cursor: new_cursor }),
//!       Err(_) => (RETRY_DELAY, self),
//!     }
//!   }
//!
//!   fn initial_delay(&self) -> Duration { Duration::from_secs(0) }
//!
//!   const NAME: &'static str = "some_recurring_async_task";
//! }
//!
//! struct SomePeriodicAsyncTask {
//!     state: &'static LocalKey<RefCell<CanisterState>>,
//! }
//!
//! #[async_trait]
//! impl PeriodicAsyncTask for SomePeriodicAsyncTask {
//!   async fn execute(self) {
//!     self.state.with_borrow_mut(|state| state.do_something()).await;
//!   }
//!
//!   const NAME: &'static str = "some_periodic_async_task";
//!   const INTERVAL: Duration = Duration::from_secs(10);
//! }
//!
//! thread_local! {
//!   static METRICS_REGISTRY: RefCell<MetricsRegistry> = RefCell::new(MetricsRegistry::default());
//!   static STATE: RefCell<CanisterState> = RefCell::new(CanisterState::default());
//! }
//!
//! fn schedule_tasks() {
//!   SomeRecurringSyncTask::new(&STATE).schedule(&METRICS_REGISTRY);
//!   SomePeriodicSyncTask::new(&STATE).schedule(&METRICS_REGISTRY);
//!   SomeRecurringAsyncTask::new(&STATE).schedule(&METRICS_REGISTRY);
//!   SomePeriodicAsyncTask::new(&STATE).schedule(&METRICS_REGISTRY);
//! }
//! ```

#![allow(deprecated)]

mod metrics;

pub use metrics::MetricsRegistry as TimerTaskMetricsRegistry;

use async_trait::async_trait;
#[cfg(not(target_arch = "wasm32"))]
use futures::FutureExt;
#[cfg(target_arch = "wasm32")]
use ic_cdk::spawn;
use ic_nervous_system_time_helpers::now_seconds;
pub use ic_nervous_system_timers::{TimerId, set_timer, set_timer_interval};
use metrics::{MetricsRegistryRef, with_async_metrics, with_sync_metrics};
use std::future::Future;
use std::time::Duration;

/// This function is used to spawn a future in a way that is compatible with both the WASM and
/// non-WASM environments that are used for testing.  This only actually spawns in the case where
/// the WASM is running in the IC, or has some other source of asynchrony.  Otherwise, it
/// immediately executes.s
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

/// Returns the number of instructions executed in the current message. Returns 0 if not running in
/// a WASM.
fn instruction_counter() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        ic_cdk::api::instruction_counter()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        0
    }
}

/// Returns the number of instructions executed in the current call context. Useful for measuring
/// instructions across multiple messages. Returns 0 if not running in a WASM.
fn call_context_instruction_counter() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        ic_cdk::api::call_context_instruction_counter()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        0
    }
}

pub trait RecurringSyncTask: Sized + 'static {
    fn execute(self) -> (Duration, Self);
    fn initial_delay(&self) -> Duration;

    fn schedule_with_delay(self, delay: Duration, metrics_registry: MetricsRegistryRef) {
        set_timer(delay, async move {
            let instructions_before = instruction_counter();

            let (new_delay, new_task) = self.execute();

            let instructions_used = instruction_counter() - instructions_before;
            with_sync_metrics(metrics_registry, Self::NAME, |metrics| {
                metrics.record(instructions_used, now_seconds());
            });

            new_task.schedule_with_delay(new_delay, metrics_registry);
        });
    }

    fn schedule(self, metrics_registry: MetricsRegistryRef) {
        let initial_delay = self.initial_delay();
        self.schedule_with_delay(initial_delay, metrics_registry);
    }

    const NAME: &'static str;
}

#[async_trait]
pub trait RecurringAsyncTask: Sized + 'static {
    async fn execute(self) -> (Duration, Self);
    fn initial_delay(&self) -> Duration;

    fn schedule_with_delay(self, delay: Duration, metrics_registry: MetricsRegistryRef) {
        set_timer(delay, async move {
            spawn_in_canister_env(async move {
                let instructions_before = call_context_instruction_counter();
                with_async_metrics(metrics_registry, Self::NAME, |metrics| {
                    metrics.record_start(now_seconds());
                });

                let (new_delay, new_task) = self.execute().await;

                let instructions_used = call_context_instruction_counter() - instructions_before;
                with_async_metrics(metrics_registry, Self::NAME, |metrics| {
                    metrics.record_finish(instructions_used, now_seconds());
                });
                new_task.schedule_with_delay(new_delay, metrics_registry);
            });
        });
    }

    fn schedule(self, metrics_registry: MetricsRegistryRef) {
        let initial_delay = self.initial_delay();
        self.schedule_with_delay(initial_delay, metrics_registry);
    }

    const NAME: &'static str;
}

pub trait PeriodicSyncTask: Copy + Sized + 'static {
    // TODO: can periodic tasks have a state that is mutable across invocations?
    fn execute(self);

    fn schedule(self, metrics_registry: MetricsRegistryRef) -> TimerId {
        set_timer_interval(Self::INTERVAL, move || async move {
            let instructions_before = instruction_counter();

            self.execute();

            let instructions_used = instruction_counter() - instructions_before;
            with_sync_metrics(metrics_registry, Self::NAME, |metrics| {
                metrics.record(instructions_used, now_seconds());
            });
        })
    }

    const NAME: &'static str;
    const INTERVAL: Duration;
}

#[async_trait]
pub trait PeriodicAsyncTask: Copy + Sized + 'static {
    async fn execute(self);

    fn schedule(self, metrics_registry: MetricsRegistryRef) -> TimerId {
        set_timer_interval(Self::INTERVAL, move || async move {
            spawn_in_canister_env(async move {
                let instructions_before = call_context_instruction_counter();
                with_async_metrics(metrics_registry, Self::NAME, |metrics| {
                    metrics.record_start(now_seconds());
                });

                self.execute().await;

                let instructions_used = call_context_instruction_counter() - instructions_before;
                with_async_metrics(metrics_registry, Self::NAME, |metrics| {
                    metrics.record_finish(instructions_used, now_seconds());
                });
            });
        })
    }

    const NAME: &'static str;
    const INTERVAL: Duration;
}
