use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use ic_metrics::MetricsRegistry;
use ic_types_test_utils::ids::canister_test_id;

use crate::query_handler::query_scheduler::internal::DEFAULT_QUERY_DURATION;

use super::{
    QueryScheduler,
    internal::{Query, QuerySchedulerInternal},
};

#[test]
fn query_scheduler_does_not_starve_canisters() {
    let metrics_registry = MetricsRegistry::new();
    let scheduler = QueryScheduler::new(1, 1, Duration::from_millis(1), &metrics_registry);
    let canister_count = 3;
    let execution_count = Arc::new(AtomicU32::default());
    let schedule = Arc::new(Mutex::new(vec![]));
    for c in 0..canister_count as u64 {
        for _ in 0..10 {
            let execution_count = Arc::clone(&execution_count);
            let schedule = Arc::clone(&schedule);
            scheduler.push(canister_test_id(c), move || {
                let duration = std::time::Duration::from_millis(10);
                std::thread::sleep(duration);
                schedule.lock().unwrap().push(c);
                execution_count.fetch_add(1, Ordering::SeqCst);
                duration
            })
        }
    }
    loop {
        if execution_count.load(Ordering::SeqCst) > 4 * canister_count {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let schedule = schedule.lock().unwrap();
    for c in 0..canister_count as u64 {
        assert!(schedule.contains(&c));
    }
}

#[test]
fn query_scheduler_with_single_threaded_canister() {
    let metrics_registry = MetricsRegistry::new();
    let scheduler = QueryScheduler::new(4, 1, Duration::from_millis(1), &metrics_registry);
    let execution_count = Arc::new(AtomicU32::default());
    let thread_count = Arc::new(AtomicU32::default());
    for _ in 0..100 {
        let execution_count = Arc::clone(&execution_count);
        let thread_count = Arc::clone(&thread_count);
        scheduler.push(canister_test_id(0), move || {
            assert_eq!(thread_count.fetch_add(1, Ordering::SeqCst), 0);
            let duration = std::time::Duration::from_millis(10);
            std::thread::sleep(duration);
            assert_eq!(thread_count.fetch_sub(1, Ordering::SeqCst), 1);
            execution_count.fetch_add(1, Ordering::SeqCst);
            duration
        });
    }
    loop {
        if execution_count.load(Ordering::SeqCst) > 10 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

#[test]
fn query_scheduler_respects_max_threads_per_canister() {
    let metrics_registry = MetricsRegistry::new();
    let scheduler = QuerySchedulerInternal::new(2, Duration::from_millis(1), &metrics_registry);
    for _ in 0..100 {
        scheduler.push(
            canister_test_id(0),
            Query(Box::new(move || std::time::Duration::from_millis(1000))),
        );
    }
    let batch1 = scheduler.pop().unwrap();
    assert!(!batch1.1.is_empty());

    let batch2 = scheduler.pop().unwrap();
    assert!(!batch2.1.is_empty());

    let batch3 = scheduler.try_pop();
    assert!(batch3.is_none());

    scheduler.notify_finished_execution(
        canister_test_id(0),
        std::time::Duration::from_millis(1000),
        vec![],
    );

    let batch4 = scheduler.pop().unwrap();
    assert!(!batch4.1.is_empty());

    let batch5 = scheduler.try_pop();
    assert!(batch5.is_none());
}

#[test]
fn query_scheduler_does_round_robin() {
    let metrics_registry = MetricsRegistry::new();
    let scheduler = QuerySchedulerInternal::new(2, Duration::from_millis(1), &metrics_registry);

    for c in 0..10 {
        for _ in 0..100 {
            scheduler.push(
                canister_test_id(c),
                Query(Box::new(move || std::time::Duration::from_millis(1000))),
            );
        }
    }

    for c in 0..10 {
        let (canister_id, queries) = scheduler.pop().unwrap();
        assert_eq!(canister_test_id(c), canister_id);
        assert!(!queries.is_empty());
    }

    for c in 0..10 {
        let (canister_id, queries) = scheduler.pop().unwrap();
        assert_eq!(canister_test_id(c), canister_id);
        assert!(!queries.is_empty());
    }

    for c in 0..10 {
        scheduler.notify_finished_execution(
            canister_test_id(c),
            std::time::Duration::from_millis(1000),
            vec![],
        );
    }

    for c in 0..10 {
        let (canister_id, queries) = scheduler.pop().unwrap();
        assert_eq!(canister_test_id(c), canister_id);
        assert!(!queries.is_empty());
    }
}

#[test]
fn query_scheduler_adjusts_batch_size() {
    let metrics_registry = MetricsRegistry::new();
    let scheduler = QuerySchedulerInternal::new(2, Duration::from_millis(100), &metrics_registry);

    for _ in 0..100 {
        scheduler.push(
            canister_test_id(0),
            Query(Box::new(move || std::time::Duration::from_millis(50))),
        );
    }

    let (_, queries) = scheduler.pop().unwrap();

    assert_eq!(
        queries.len(),
        100 / DEFAULT_QUERY_DURATION.as_millis() as usize
    );

    scheduler.notify_finished_execution(
        canister_test_id(0),
        std::time::Duration::from_millis(50),
        vec![],
    );

    let (_, queries) = scheduler.pop().unwrap();

    assert_eq!(
        queries.len(),
        100 / ((DEFAULT_QUERY_DURATION.as_millis() + 50) / 2) as usize
    );
}

#[test]
fn query_scheduler_drains_leftover_queue_before_new_queries() {
    let metrics_registry = MetricsRegistry::new();
    let scheduler = QuerySchedulerInternal::new(2, Duration::from_millis(100), &metrics_registry);

    for i in 0..100 {
        scheduler.push(
            canister_test_id(0),
            Query(Box::new(move || std::time::Duration::from_millis(i))),
        );
    }

    let (_, queries) = scheduler.pop().unwrap();

    scheduler.notify_finished_execution(
        canister_test_id(0),
        std::time::Duration::from_millis(1),
        queries,
    );

    let (_, queries) = scheduler.pop().unwrap();

    for (i, q) in queries.into_iter().enumerate() {
        assert_eq!(q.execute(), std::time::Duration::from_millis(i as u64));
    }
}

#[test]
fn query_scheduler_properly_reads_leftover_queries() {
    let metrics_registry = MetricsRegistry::new();
    let scheduler = QuerySchedulerInternal::new(2, Duration::from_millis(100), &metrics_registry);

    scheduler.push(
        canister_test_id(0),
        Query(Box::new(move || std::time::Duration::from_millis(100))),
    );

    scheduler.push(
        canister_test_id(0),
        Query(Box::new(move || std::time::Duration::from_millis(100))),
    );

    let (_, mut queries) = scheduler.pop().unwrap();

    assert_eq!(queries.len(), 2);
    queries.remove(0);

    scheduler.notify_finished_execution(
        canister_test_id(0),
        std::time::Duration::from_millis(100),
        queries,
    );

    let (_, queries) = scheduler.pop().unwrap();

    assert_eq!(queries.len(), 1);
}
