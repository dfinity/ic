use std::time::Duration;

use super::internal::QuerySchedulerInternal;

/// Manages a thread-pool where each thread polls queries from `scheduler` and
/// executes them. The threads stop when the thread-pool object is dropped.
pub(crate) struct QueryThreadPool {
    threads: Vec<std::thread::JoinHandle<()>>,
    scheduler: QuerySchedulerInternal,
}

impl QueryThreadPool {
    /// Creates a thread-pool with `num_threads` threads. Each thread runs in a
    /// loop that polls `scheduler` to get a batch of queries for a single
    /// canister. The queries are executed one by one until the total execution
    /// duration exceeds `time_slice_per_canister`.
    pub fn new(
        num_threads: usize,
        time_slice_per_canister: Duration,
        scheduler: QuerySchedulerInternal,
    ) -> Self {
        let mut threads = vec![];
        for _ in 0..num_threads {
            let scheduler = scheduler.clone();
            let thread = std::thread::Builder::new()
                .name("query_execution".to_string())
                .spawn(move || {
                    query_execution_thread(time_slice_per_canister, scheduler);
                })
                .unwrap();
            threads.push(thread);
        }
        Self { threads, scheduler }
    }
}

impl Drop for QueryThreadPool {
    fn drop(&mut self) {
        self.scheduler.notify_teardown();
        let threads = std::mem::take(&mut self.threads);
        for thread in threads.into_iter() {
            thread.join().unwrap();
        }
    }
}

// The body of each thread in the thread-pool.
fn query_execution_thread(time_slice_per_canister: Duration, scheduler: QuerySchedulerInternal) {
    loop {
        match scheduler.pop() {
            None => break,
            Some((canister_id, queries)) => {
                let mut iter = queries.into_iter();
                let mut query_duration_sum = Duration::ZERO;
                let mut query_duration_cnt = 0;
                for query in iter.by_ref() {
                    let query_duration = query.execute();
                    query_duration_sum += query_duration;
                    query_duration_cnt += 1;
                    if query_duration_sum >= time_slice_per_canister {
                        break;
                    }
                }
                let average_query_duration = query_duration_sum / query_duration_cnt.max(1);
                let leftover = iter.collect();
                scheduler.notify_finished_execution(canister_id, average_query_duration, leftover)
            }
        }
    }
}
