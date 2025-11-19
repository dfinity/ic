use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use ic_base_types::CanisterId;
use ic_metrics::MetricsRegistry;

use self::{
    internal::{Query, QuerySchedulerInternal},
    thread_pool::QueryThreadPool,
};

mod internal;
mod thread_pool;

#[cfg(test)]
mod tests;

/// The query scheduler accepts and executes non-replicated queries (user
/// queries, system queries, and ingress filter queries). It currently
/// schedules each canister that has queries in a round-robin fashion.
/// When a canister is scheduled and starts executing, it is allowed to execute
/// multiple queries until it reaches the `time_slice_per_canister` limit.
/// The algorithm also ensures that each canister executes on at most
/// `max_threads_per_canister` threads, which is necessary to avoid performance
/// regression due to the memory bottleneck in the sandbox process.
#[derive(Clone)]
pub(crate) struct QueryScheduler {
    scheduler: QuerySchedulerInternal,
    // This field is not actually used. Its only purpose is to keep the
    // thread-pool alive.
    _thread_pool: Arc<Mutex<QueryThreadPool>>,
}

impl QueryScheduler {
    /// Creates a query scheduler with `num_threads` threads.
    /// If the new scheduling algorithm is enabled, then it guarantees that
    /// there are no more than `max_threads_per_canister` threads processing
    /// queries from the same canister concurrently at any point of time.
    /// The `time_slice_per_canister` parameter defines how long a canister runs
    /// once it is scheduled for execution.
    pub fn new(
        num_threads: usize,
        max_threads_per_canister: usize,
        time_slice_per_canister: Duration,
        metrics_registry: &MetricsRegistry,
    ) -> Self {
        let scheduler = QuerySchedulerInternal::new(
            max_threads_per_canister,
            time_slice_per_canister,
            metrics_registry,
        );
        let thread_pool =
            QueryThreadPool::new(num_threads, time_slice_per_canister, scheduler.clone());
        Self {
            scheduler,
            _thread_pool: Arc::new(Mutex::new(thread_pool)),
        }
    }

    /// Adds the given query closure to the query queue of the given canister.
    /// The query closure will be invoked at some point in the future according
    /// to the scheduling algorithm. The closure should execute the query and
    /// return the execution duration.
    pub fn push<F>(&self, canister_id: CanisterId, query: F)
    where
        F: FnOnce() -> Duration + Send + 'static,
    {
        self.scheduler.push(canister_id, Query(Box::new(query)));
    }
}
