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
//!  started but not finished, and the number of tasks that have finished. Its instruction metrics
//!  come from the `call_context_instruction_counter` which measures across multiple messages within
//!  the same call context.
//! - Periodic tasks are defined as a closure that can run multiple times. Therefore, its context is
//!  typically managed outside of the closure (e.g. part of the canister state). Note that if the
//!  task panics in one iteration, it will still be scheduled to run at the next interval. Usually,
//!  the task member should only contain a reference to the canister state. Note that if the task
//!  interval is T, the task will be scheduled to run at t=T, t=2T, t=3T, and so on, but NOT t = 0.
//! - Recurring tasks are repeatedly scheduled after its completion, and therefore there is more
//!  flexibility in how the next iteration can be scheduled, both in terms of the delay and the task
//!  itself. For example, the task can contain a cursor, and the cursor for the next iteration can
//!  be computed after the current iteration finishes, so can the delay. Note that if the task
//!  panics in one iteration, it will NOT be scheduled again. It can, however, catch any errors and
//!  implement its own retry logic by specifying the next task (e.g. the same as the one failed) and
//!  a new delay (e.g. exponential backoff).
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
//!   const NAME: &'static str = "SomeRecurringSyncTask";
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
//!   const NAME: &'static str = "SomePeriodicTask";
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
//!   const NAME: &'static str = "SomeRecurringAsyncTask";
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
//!   const NAME: &'static str = "SomePeriodicAsyncTask";
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

use async_trait::async_trait;
use ic_cdk::spawn;
use ic_cdk_timers::{set_timer, set_timer_interval};
use std::{cell::RefCell, collections::HashMap, thread::LocalKey, time::Duration};

#[derive(Default)]
struct SyncTaskMetrics {
    count: u64,
    instruction: InstructionMetrics,
}

impl SyncTaskMetrics {
    fn record_finish(&mut self, instructions_used: u64) {
        self.count += 1;
        self.instruction.record(instructions_used);
    }
}

#[derive(Default)]
struct AsyncTaskMetrics {
    finished_count: u64,
    outstanding_count: u64,
    instruction: InstructionMetrics,
}

impl AsyncTaskMetrics {
    fn record_start(&mut self) {
        self.outstanding_count += 1;
    }

    fn record_finish(&mut self, instructions_used: u64) {
        self.outstanding_count -= 1;
        self.finished_count += 1;
        self.instruction.record(instructions_used);
    }
}

#[derive(Default)]
struct InstructionMetrics {
    sum: u128,
    histogram: InstructionHistogram,
}

pub const INSTRUCTION_BUCKET_COUNT: usize = 29;
pub const INSTRUCTION_BUCKETS: [u64; INSTRUCTION_BUCKET_COUNT] = [
    10_000,
    20_000,
    50_000,
    100_000,
    200_000,
    500_000,
    1_000_000,
    2_000_000,
    5_000_000,
    10_000_000,
    20_000_000,
    50_000_000,
    100_000_000,
    200_000_000,
    500_000_000,
    1_000_000_000,
    2_000_000_000,
    5_000_000_000,
    10_000_000_000,
    20_000_000_000,
    50_000_000_000,
    100_000_000_000,
    200_000_000_000,
    500_000_000_000,
    1_000_000_000_000,
    2_000_000_000_000,
    5_000_000_000_000,
    10_000_000_000_000,
    u64::MAX,
];
type InstructionHistogram = [u64; INSTRUCTION_BUCKET_COUNT];

impl InstructionMetrics {
    fn record(&mut self, instruction_count: u64) {
        self.sum += instruction_count as u128;
        for (i, &bucket) in INSTRUCTION_BUCKETS.iter().enumerate() {
            if instruction_count <= bucket {
                self.histogram[i] += 1;
                break;
            }
        }
    }
}

#[derive(Default)]
pub struct MetricsRegistry {
    sync_metrics: HashMap<String, SyncTaskMetrics>,
    async_metrics: HashMap<String, AsyncTaskMetrics>,
}

type MetricsRegistryRef = &'static LocalKey<RefCell<MetricsRegistry>>;

fn with_sync_metrics(
    task_name: &'static str,
    metrics_registry: MetricsRegistryRef,
    f: impl FnOnce(&mut SyncTaskMetrics),
) {
    metrics_registry.with_borrow_mut(|metrics_registry| {
        let task_metrics = metrics_registry
            .sync_metrics
            .entry(task_name.to_string())
            .or_default();
        f(task_metrics);
    });
}

fn with_async_metrics(
    task_name: &'static str,
    metrics_registry: MetricsRegistryRef,
    f: impl FnOnce(&mut AsyncTaskMetrics),
) {
    metrics_registry.with_borrow_mut(|metrics_registry| {
        let task_metrics = metrics_registry
            .async_metrics
            .entry(task_name.to_string())
            .or_default();
        f(task_metrics);
    });
}

pub trait RecurringSyncTask: Sized + 'static {
    fn execute(self) -> (Duration, Self);
    fn initial_delay(&self) -> Duration;

    fn schedule_with_delay(self, delay: Duration, registry: MetricsRegistryRef) {
        set_timer(delay, move || {
            let instructions_before = ic_cdk::api::instruction_counter();

            let (new_delay, new_task) = self.execute();

            let instructions_after = ic_cdk::api::instruction_counter();
            with_sync_metrics(Self::NAME, registry, |metrics| {
                metrics.record_finish(instructions_after - instructions_before);
            });
            new_task.schedule_with_delay(new_delay, registry);
        });
    }

    fn schedule(self, registry: MetricsRegistryRef) {
        let initial_delay = self.initial_delay();
        self.schedule_with_delay(initial_delay, registry);
    }

    const NAME: &'static str;
}

#[async_trait]
pub trait RecurringAsyncTask: Sized + 'static {
    async fn execute(self) -> (Duration, Self);
    fn initial_delay(&self) -> Duration;

    fn schedule_with_delay(self, delay: Duration, registry: MetricsRegistryRef) {
        set_timer(delay, move || {
            spawn(async move {
                with_async_metrics(Self::NAME, registry, |metrics| {
                    metrics.record_start();
                });
                let instructions_before = ic_cdk::api::call_context_instruction_counter();

                let (new_delay, new_task) = self.execute().await;

                let instructions_after = ic_cdk::api::call_context_instruction_counter();
                with_async_metrics(Self::NAME, registry, |metrics| {
                    metrics.record_finish(instructions_after - instructions_before);
                });
                new_task.schedule_with_delay(new_delay, registry);
            });
        });
    }

    fn schedule(self, registry: MetricsRegistryRef) {
        let initial_delay = self.initial_delay();
        self.schedule_with_delay(initial_delay, registry);
    }

    const NAME: &'static str;
}

pub trait PeriodicSyncTask: Copy + Sized + 'static {
    // TODO: can periodic tasks have a state that is mutable across invocations?
    fn execute(self);

    fn schedule(self, registry: MetricsRegistryRef) {
        set_timer_interval(Self::INTERVAL, move || {
            let instructions_before = ic_cdk::api::instruction_counter();

            self.execute();

            let instructions_after = ic_cdk::api::instruction_counter();
            let instructions_used = instructions_after - instructions_before;
            with_sync_metrics(Self::NAME, registry, |metrics| {
                metrics.record_finish(instructions_used);
            });
        });
    }

    const NAME: &'static str;
    const INTERVAL: Duration;
}

#[async_trait]
pub trait PeriodicAsyncTask: Copy + Sized + 'static {
    async fn execute(self);

    fn schedule(self, registry: MetricsRegistryRef) {
        set_timer_interval(Self::INTERVAL, move || {
            spawn(async move {
                with_async_metrics(Self::NAME, registry, |metrics| {
                    metrics.record_start();
                });
                let instructions_before = ic_cdk::api::call_context_instruction_counter();

                self.execute().await;

                let instructions_after = ic_cdk::api::call_context_instruction_counter();
                let instructions_used = instructions_after - instructions_before;
                with_async_metrics(Self::NAME, registry, |metrics| {
                    metrics.record_finish(instructions_used);
                });
            });
        });
    }

    const NAME: &'static str;
    const INTERVAL: Duration;
}
