//! Regression test for DEFI-2950 / DEFI-2491: the ICP Rosetta block store must
//! not starve the async runtime.
//!
//! ICP Rosetta serves its endpoints from `async` handlers running on a `tokio`
//! multi-threaded runtime, but the block store's query methods are **blocking**
//! (synchronous `rusqlite` behind a `std::sync::Mutex<Connection>`, with no
//! `.await` points). When several such calls run concurrently they occupy all
//! `tokio` worker threads for the whole duration of the work, and no other async
//! task — a `/health` request, `/metrics`, the watchdog heartbeat — can make
//! progress. This is the runtime-starvation bottleneck analysed in DEFI-2491.
//!
//! This test reproduces that scenario deterministically: it runs a small, fixed
//! number of worker threads, hammers the block store from several concurrent
//! tasks, and concurrently runs a lightweight "canary" task that only sleeps and
//! counts ticks (it never touches the database). If the store blocks the worker
//! threads, the canary is starved and makes almost no progress.
//!
//! * On `master` (blocking store) the canary is starved -> this test FAILS.
//! * After migrating the store to async SQLite (`tokio-rusqlite`) the worker
//!   threads stay free -> the canary keeps ticking -> this test PASSES.
//!
//! The test is intentionally independent of absolute query latency: the hammer
//! loop contains no `.await`, so on `master` a single scheduled hammer monopol-
//! ises a worker thread for the entire load window regardless of how fast an
//! individual query is. What changes after the migration is that each store call
//! becomes an `.await` point that yields the worker while the query runs on the
//! store's dedicated background thread.

use ic_ledger_canister_blocks_synchronizer::blocks::{Blocks, RosettaDbConfig};
use ic_ledger_canister_blocks_synchronizer_test_utils::sample_data::Scribe;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Deliberately small so the starvation is deterministic regardless of the host
/// core count (production integrators are recommended to run with ~4 CPUs).
///
/// The assertion is wall-clock based (it compares canary ticks against an ideal
/// tick count), so it assumes the test can actually run its threads in parallel:
/// the two tokio worker threads plus the `block_on`/canary thread. The bazel
/// target reserves CPUs accordingly (`tags = ["cpu:4"]`) to keep it from
/// under-ticking and flaking on an oversubscribed CI runner.
const WORKER_THREADS: usize = 2;
/// More concurrent DB tasks than worker threads, so every worker is kept busy.
const NUM_HAMMER_TASKS: usize = 8;
/// How long the concurrent database load runs.
const LOAD_WINDOW: Duration = Duration::from_secs(2);
/// The canary tries to wake up this often.
const CANARY_TICK: Duration = Duration::from_millis(10);

#[test]
fn block_store_does_not_starve_async_runtime() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(WORKER_THREADS)
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    runtime.block_on(async {
        // Build and populate an in-memory store.
        let mut store = Blocks::new_in_memory(RosettaDbConfig::default_disabled())
            .await
            .expect("failed to create in-memory block store");
        let scribe = Scribe::new_with_sample_data(10, 100);
        for hb in &scribe.blockchain {
            store.push(hb).await.expect("failed to push block");
        }
        let num_blocks = scribe.blockchain.len() as u64;
        assert!(num_blocks > 0, "expected a non-empty test blockchain");
        let store = Arc::new(store);

        // Canary: only sleeps and counts ticks; never touches the database.
        let canary_ticks = Arc::new(AtomicU64::new(0));
        let canary = {
            let canary_ticks = canary_ticks.clone();
            tokio::spawn(async move {
                let start = Instant::now();
                while start.elapsed() < LOAD_WINDOW {
                    tokio::time::sleep(CANARY_TICK).await;
                    canary_ticks.fetch_add(1, Ordering::Relaxed);
                }
            })
        };

        // Hammer tasks: continuously read from the store for the whole window.
        let db_ops = Arc::new(AtomicU64::new(0));
        let hammers: Vec<_> = (0..NUM_HAMMER_TASKS)
            .map(|task_idx| {
                let store = store.clone();
                let db_ops = db_ops.clone();
                tokio::spawn(async move {
                    let start = Instant::now();
                    let mut block_idx = (task_idx as u64) % num_blocks;
                    while start.elapsed() < LOAD_WINDOW {
                        // NOTE: on `master` this is a blocking, synchronous call
                        // with no `.await`, so it monopolises the worker thread.
                        // After the async-SQLite migration this becomes
                        // `store.get_hashed_block(&block_idx).await`.
                        let _ = store.get_hashed_block(&block_idx).await;
                        db_ops.fetch_add(1, Ordering::Relaxed);
                        block_idx = (block_idx + 1) % num_blocks;
                    }
                })
            })
            .collect();

        canary.await.expect("canary task panicked");
        for hammer in hammers {
            hammer.await.expect("hammer task panicked");
        }

        let ticks = canary_ticks.load(Ordering::Relaxed);
        let ops = db_ops.load(Ordering::Relaxed);
        // Ideal number of ticks if the canary were never starved.
        let ideal_ticks = (LOAD_WINDOW.as_millis() / CANARY_TICK.as_millis()) as u64;
        // Require the canary to have made at least a quarter of its ideal
        // progress. Under starvation it manages ~0; with a non-blocking store it
        // manages close to `ideal_ticks`.
        let min_expected_ticks = ideal_ticks / 4;

        println!(
            "canary ticks: {ticks}/{ideal_ticks} (min expected {min_expected_ticks}), \
             db ops completed: {ops}, worker threads: {WORKER_THREADS}, \
             hammer tasks: {NUM_HAMMER_TASKS}"
        );

        assert!(
            ops > 0,
            "sanity check failed: hammer tasks did not perform any DB operations"
        );
        assert!(
            ticks >= min_expected_ticks,
            "async runtime was starved by the block store: the canary only ticked \
             {ticks} times out of an ideal {ideal_ticks} (required at least \
             {min_expected_ticks}) while {ops} blocking DB operations ran on \
             {WORKER_THREADS} worker threads. This means the block store's query \
             methods block the tokio worker threads instead of yielding (see \
             DEFI-2491)."
        );
    });
}
