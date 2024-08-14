use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};

use ic_base_types::CanisterId;
use ic_metrics::{buckets::decimal_buckets_with_zero, MetricsRegistry};
use prometheus::Histogram;
use tracing::instrument;

/// An estimate of the average query execution duration. It is used at the
/// start when there are no stats about the actual query execution duration.
/// The value of this constant doesn't affect correctness of the algorithm
/// and can be set to any reasonable duration from 1ms to 1000ms.
pub(crate) const DEFAULT_QUERY_DURATION: Duration = Duration::from_millis(5);

pub(crate) struct QuerySchedulerMetrics {
    pub queue_length: Histogram,
}

impl QuerySchedulerMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            queue_length: metrics_registry.histogram(
                "execution_query_scheduler_queue_length",
                "The length of the query queue sampled for each arriving query",
                decimal_buckets_with_zero(0, 4),
            ),
        }
    }
}

/// The closure that executes a query and returns the execution duration.
pub(crate) struct Query(pub Box<dyn FnOnce() -> Duration + Send + 'static>);

impl Query {
    #[instrument(skip_all)]
    pub fn execute(self) -> Duration {
        self.0()
    }
}

/// Contains the query queues and execution stats of a canister.
pub(crate) struct CanisterData {
    // All incoming queries are pushed into this FIFO queue.
    incoming: VecDeque<Query>,

    // Queries are executed in batches. This FIFO queue contains queries from
    // the previous batch that did not get enough execution time. These queries
    // will be executed in subsequent batches and take priority over `incoming`
    // queries.
    leftover: VecDeque<Query>,

    // The average query execution duration observed so far.
    // For simplicity, it is initialized with `DEFAULT_QUERY_DURATION`.
    average_query_duration: Duration,

    // The current number of threads executing queries of this canister.
    active_threads: usize,

    // Indicates whether this canister has been added to the `scheduled`
    // canister queue of the scheduler. This flag is needed to ensure that a
    // canister is not added multiple times to the queue.
    has_been_scheduled: bool,
}

impl CanisterData {
    fn new() -> Self {
        Self {
            incoming: Default::default(),
            leftover: Default::default(),
            average_query_duration: DEFAULT_QUERY_DURATION,
            active_threads: 0,
            has_been_scheduled: false,
        }
    }

    fn has_queries(&self) -> bool {
        !(self.incoming.is_empty() && self.leftover.is_empty())
    }

    // Returns true if the canister is blocked due to the max thread capacity
    // and cannot execute new queries until the pending executions finish.
    fn is_waiting_for_pending_executions(&self, max_threads_per_canister: usize) -> bool {
        self.active_threads >= max_threads_per_canister
    }

    // Returns true if the canister should be added to the `scheduled` canister
    // queue of the scheduler.
    fn should_be_scheduled(&self, max_threads_per_canister: usize) -> bool {
        self.has_queries() && !self.is_waiting_for_pending_executions(max_threads_per_canister)
    }

    // Returns the number of queries that can be executed in one batch based on
    // the batch execution time limit and the average query execution duration.
    // The result is guaranteed to be at least 1.
    fn queries_per_time_slice(&self, time_slice_per_canister: Duration) -> usize {
        (time_slice_per_canister.as_micros() / self.average_query_duration.as_micros().max(1))
            .max(1) as usize
    }
}

/// The implementation of a round-robin scheduling algorithm.
/// When a canister is scheduled to run, it executes a batch of queries.
/// The number of queries in a batch is variable and depends on the average
/// query execution duration observed for that canister so far.
///
/// The target duration of each batch is `time_slice_per_canister`. If this limit
/// is exceeded, then all the remaining queries in the batch are returned to the
/// `leftover` queue of the canister.
struct QuerySchedulerCore {
    // Per-canister query queues and execution stats.
    canisters: HashMap<CanisterId, CanisterData>,

    // The round-robin queue of canisters.
    // Invariant: if a canister is in this queue, then:
    // - its `has_been_scheduled` flag is set.
    // - it has at least one query to execute.
    // - the number of currently running threads of this canister is below
    //   the `max_threads_per_canister` limit.
    scheduled: VecDeque<CanisterId>,

    // The limit on the number of concurrently running threads per canister.
    max_threads_per_canister: usize,

    // The time limit for executing a batch of queries.
    time_slice_per_canister: Duration,

    // This flag is set to true if tear-down was requested.
    // It is used to stop query execution threads.
    tearing_down: bool,

    // The query scheduler metrics.
    metrics: QuerySchedulerMetrics,
}

impl QuerySchedulerCore {
    fn new(
        max_threads_per_canister: usize,
        time_slice_per_canister: Duration,
        metrics_registry: &MetricsRegistry,
    ) -> Self {
        Self {
            canisters: HashMap::default(),
            scheduled: VecDeque::default(),
            max_threads_per_canister,
            time_slice_per_canister,
            tearing_down: false,
            metrics: QuerySchedulerMetrics::new(metrics_registry),
        }
    }

    /// Adds the given query to the `incoming` queue of the given canister.
    /// It also adds the canister to the round-robin queue if needed.
    fn push(&mut self, canister_id: CanisterId, query: Query) {
        let canister = self
            .canisters
            .entry(canister_id)
            .or_insert_with(CanisterData::new);
        canister.incoming.push_back(query);

        self.metrics
            .queue_length
            .observe((canister.incoming.len() + canister.leftover.len()) as f64);

        if !canister.has_been_scheduled
            && canister.should_be_scheduled(self.max_threads_per_canister)
        {
            canister.has_been_scheduled = true;
            self.scheduled.push_back(canister_id);
        }

        #[cfg(debug_assertions)]
        self.verify_invariants();
    }

    /// Returns a batch of queries to execute if there are any.
    fn pop(&mut self) -> Option<(CanisterId, Vec<Query>)> {
        let canister_id = self.scheduled.pop_front()?;
        // It is safe to unwrap here because of the invariants in
        // `validate_invariants()`: each canister in the round-robin list must
        // be present in the canister table.
        let canister = self.canisters.get_mut(&canister_id).unwrap();
        debug_assert!(canister.has_been_scheduled);
        canister.has_been_scheduled = false;

        let total = canister.queries_per_time_slice(self.time_slice_per_canister);

        // Collect queries from the `leftover` queue first.
        let from_leftover = total.min(canister.leftover.len());
        let mut result: Vec<_> = canister.leftover.drain(0..from_leftover).collect();

        // Get the remaining queries from the `incoming` queue.
        let from_incoming = (total - from_leftover).min(canister.incoming.len());
        result.extend(canister.incoming.drain(0..from_incoming));

        // Follows from the main invariant.
        debug_assert!(!result.is_empty());

        canister.active_threads += 1;

        // We removed the canister from the schedule at the beginning of this
        // method and cleared `has_been_scheduled`.
        debug_assert!(!canister.has_been_scheduled);
        if canister.should_be_scheduled(self.max_threads_per_canister) {
            canister.has_been_scheduled = true;
            self.scheduled.push_back(canister_id);
        }

        #[cfg(debug_assertions)]
        self.verify_invariants();

        Some((canister_id, result))
    }

    // This is called by the query execution thread after it finished executing
    // a batch of queries.
    fn notify_finished_execution(
        &mut self,
        canister_id: CanisterId,
        average_query_duration: Duration,
        leftover: Vec<Query>,
    ) {
        let canister = self.canisters.get_mut(&canister_id).unwrap();
        canister.average_query_duration =
            (canister.average_query_duration + average_query_duration) / 2;

        canister.leftover.extend(leftover);
        canister.active_threads -= 1;

        if !canister.has_been_scheduled
            && canister.should_be_scheduled(self.max_threads_per_canister)
        {
            canister.has_been_scheduled = true;
            self.scheduled.push_back(canister_id);
        }

        #[cfg(debug_assertions)]
        self.verify_invariants();
    }

    fn notify_teardown(&mut self) {
        self.tearing_down = true;
    }

    fn is_tearing_down(&self) -> bool {
        self.tearing_down
    }

    #[cfg(debug_assertions)]
    fn verify_invariants(&self) {
        for canister_id in self.scheduled.iter() {
            let canister = self.canisters.get(canister_id).unwrap();
            debug_assert!(canister.has_been_scheduled);
            debug_assert!(canister.should_be_scheduled(self.max_threads_per_canister));
        }
        for (canister_id, canister) in self.canisters.iter() {
            if canister.should_be_scheduled(self.max_threads_per_canister) {
                debug_assert!(canister.has_been_scheduled);
                debug_assert!(self.scheduled.contains(canister_id))
            } else {
                debug_assert!(!canister.has_been_scheduled);
                debug_assert!(!self.scheduled.contains(canister_id))
            }
        }
    }
}

/// A thread-safe wrapper around the actual scheduler.
#[derive(Clone)]
pub(crate) struct QuerySchedulerInternal {
    core: Arc<Mutex<QuerySchedulerCore>>,
    // This condition variable is used to notify threads about new queries and a
    // tear-down request.
    work_is_available: Arc<Condvar>,
}

impl QuerySchedulerInternal {
    pub fn new(
        max_threads_per_canister: usize,
        time_slice_per_canister: Duration,
        metrics_registry: &MetricsRegistry,
    ) -> Self {
        Self {
            core: Arc::new(Mutex::new(QuerySchedulerCore::new(
                max_threads_per_canister,
                time_slice_per_canister,
                metrics_registry,
            ))),
            work_is_available: Arc::new(Condvar::new()),
        }
    }

    /// Adds the given query to the queue of the given canister.
    pub fn push(&self, canister_id: CanisterId, query: Query) {
        let mut core = self.core.lock().unwrap();
        core.push(canister_id, query);
        if !core.scheduled.is_empty() {
            self.work_is_available.notify_one();
        }
    }

    /// Returns a batch of queries. If there are no queries available for
    /// execution, then this function blocks.
    ///
    /// It returns `None` if a teardown was requested using `notify_teardown()`.
    pub fn pop(&self) -> Option<(CanisterId, Vec<Query>)> {
        let mut core = self.core.lock().unwrap();
        loop {
            if core.is_tearing_down() {
                return None;
            }
            match core.pop() {
                Some(result) => return Some(result),
                None => {
                    core = self.work_is_available.wait(core).unwrap();
                }
            }
        }
    }

    #[cfg(test)]
    pub fn try_pop(&self) -> Option<(CanisterId, Vec<Query>)> {
        let mut core = self.core.lock().unwrap();
        core.pop()
    }

    // This is called by the query execution thread after it finished executing
    // a batch of queries.
    pub fn notify_finished_execution(
        &self,
        canister_id: CanisterId,
        average_query_duration: Duration,
        leftover: Vec<Query>,
    ) {
        let mut core = self.core.lock().unwrap();
        core.notify_finished_execution(canister_id, average_query_duration, leftover);
        if !core.scheduled.is_empty() {
            self.work_is_available.notify_one();
        }
    }

    /// Notifies all waiting threads about teardown, so that they exit without
    /// waiting for more queries.
    pub fn notify_teardown(&self) {
        let mut core = self.core.lock().unwrap();
        core.notify_teardown();
        self.work_is_available.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use ic_types_test_utils::ids::canister_test_id;

    use super::*;

    #[test]
    fn query_scheduler_metrics_recorded() {
        let metrics_registry = MetricsRegistry::new();
        let scheduler =
            QuerySchedulerInternal::new(2, Duration::from_millis(100), &metrics_registry);

        scheduler.push(
            canister_test_id(0),
            Query(Box::new(move || std::time::Duration::from_millis(100))),
        );

        scheduler.push(
            canister_test_id(0),
            Query(Box::new(move || std::time::Duration::from_millis(100))),
        );

        let core = scheduler.core.lock().unwrap();
        assert_eq!(2, core.metrics.queue_length.get_sample_count());
        assert_eq!(1 + 2, core.metrics.queue_length.get_sample_sum() as usize);
    }
}
