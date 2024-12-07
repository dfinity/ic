use canister_test::{Canister, Runtime, Wasm};
use chrono::Utc;
use futures::future::join_all;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::get_dependency_path;
use ic_system_test_driver::driver::test_env_api::{HasPublicApiUrl, HasVm, IcNodeSnapshot};
use ic_system_test_driver::util::{runtime_from_url, MetricsFetcher, UniversalCanister};
use slog::info;
use std::collections::BTreeMap;
use std::env;
use std::fmt::Debug;
use std::str::FromStr;
use std::time::Duration;

const STORE_TO_STABLE_RETRIES: u64 = 3;

pub const SUCCESSFUL_STATE_SYNC_DURATION_SECONDS_SUM: &str =
    "state_sync_duration_seconds_sum{status=\"ok\"}";
pub const SUCCESSFUL_STATE_SYNC_DURATION_SECONDS_COUNT: &str =
    "state_sync_duration_seconds_count{status=\"ok\"}";

const LATEST_CERTIFIED_HEIGHT: &str = "state_manager_latest_certified_height";
const LAST_MANIFEST_HEIGHT: &str = "state_manager_last_computed_manifest_height";
const REPLICATED_STATE_PURGE_HEIGHT_DISK: &str = "replicated_state_purge_height_disk";

pub async fn rejoin_test(
    env: &TestEnv,
    allowed_failures: usize,
    dkg_interval: u64,
    rejoin_node: IcNodeSnapshot,
    agent_node: IcNodeSnapshot,
    nodes_to_kill: impl Iterator<Item = IcNodeSnapshot>,
) {
    let logger = env.logger();
    info!(
        logger,
        "Installing universal canister on a node {} ...",
        agent_node.get_public_url()
    );

    let agent = agent_node.build_default_agent_async().await;
    let universal_canister =
        UniversalCanister::new_with_retries(&agent, agent_node.effective_canister_id(), &logger)
            .await;

    let res = fetch_metrics::<u64>(
        &logger,
        rejoin_node.clone(),
        vec![SUCCESSFUL_STATE_SYNC_DURATION_SECONDS_COUNT],
    )
    .await;
    let base_count = res[SUCCESSFUL_STATE_SYNC_DURATION_SECONDS_COUNT][0];

    info!(
        logger,
        "Killing a node: {} ...",
        rejoin_node.get_public_url()
    );
    rejoin_node.vm().kill();
    rejoin_node
        .await_status_is_unavailable()
        .expect("Node still healthy");

    info!(logger, "Making some canister update calls ...");
    let canister_update_calls = 3 * dkg_interval;
    for i in 0..canister_update_calls {
        info!(logger, "Performing canister update call {i}");
        store_and_read_stable(&logger, i.to_le_bytes().as_slice(), &universal_canister).await;
    }

    info!(logger, "Killing {} nodes ...", allowed_failures);
    for node_to_kill in nodes_to_kill {
        info!(logger, "Killing node {} ...", node_to_kill.get_public_url());
        node_to_kill.vm().kill();
        node_to_kill
            .await_status_is_unavailable()
            .expect("Node still healthy");
    }

    info!(logger, "Start the first killed node again...");
    rejoin_node.vm().start();
    rejoin_node
        .await_status_is_healthy()
        .expect("Started node did not report healthy status");

    info!(logger, "Checking for subnet progress...");
    let message = b"This beautiful prose should be persisted for future generations";
    store_and_read_stable(&logger, message, &universal_canister).await;

    info!(
        logger,
        "Checking for the state sync count metrics indicating that a successful state sync has happened"
    );
    let res = fetch_metrics::<u64>(
        &logger,
        rejoin_node.clone(),
        vec![SUCCESSFUL_STATE_SYNC_DURATION_SECONDS_COUNT],
    )
    .await;
    assert!(res[SUCCESSFUL_STATE_SYNC_DURATION_SECONDS_COUNT][0] > base_count);

    let res = fetch_metrics::<f64>(
        &logger,
        rejoin_node.clone(),
        vec![SUCCESSFUL_STATE_SYNC_DURATION_SECONDS_SUM],
    )
    .await;
    info!(
        logger,
        "State sync finishes successfully in {} seconds",
        res[SUCCESSFUL_STATE_SYNC_DURATION_SECONDS_SUM][0],
    );
}

pub async fn rejoin_test_large_state(
    env: TestEnv,
    allowed_failures: usize,
    size_level: usize,
    num_canisters: usize,
    dkg_interval: u64,
    rejoin_node: IcNodeSnapshot,
    agent_node: IcNodeSnapshot,
    nodes_to_kill: impl Iterator<Item = IcNodeSnapshot>,
) {
    let logger = env.logger();
    info!(
        logger,
        "Installing universal canister on a node {} ...",
        agent_node.get_public_url()
    );
    let agent = agent_node.build_default_agent_async().await;
    let universal_canister =
        UniversalCanister::new_with_retries(&agent, agent_node.effective_canister_id(), &logger)
            .await;

    let endpoint_runtime = runtime_from_url(
        agent_node.get_public_url(),
        agent_node.effective_canister_id(),
    );
    let canisters = install_statesync_test_canisters(env, &endpoint_runtime, num_canisters).await;

    info!(
        logger,
        "Start expanding the canister heap. The total size of all canisters will be {} MiB.",
        size_level * num_canisters * 128
    );
    modify_canister_heap(
        logger.clone(),
        canisters.clone(),
        size_level,
        num_canisters,
        false,
        0,
    )
    .await;

    // Kill the rejoin node after it has a checkpoint so that we can test both `copy_chunks` and `fetch_chunks` in the state sync.
    info!(logger, "Waiting for the rejoin_node to have a checkpoint");
    wait_for_manifest(&logger, dkg_interval + 1, rejoin_node.clone()).await;

    let res = fetch_metrics::<u64>(
        &logger,
        rejoin_node.clone(),
        vec![SUCCESSFUL_STATE_SYNC_DURATION_SECONDS_COUNT],
    )
    .await;
    let base_count = res[SUCCESSFUL_STATE_SYNC_DURATION_SECONDS_COUNT][0];

    info!(
        logger,
        "Killing a node: {} ...",
        rejoin_node.get_public_url()
    );
    rejoin_node.vm().kill();
    rejoin_node
        .await_status_is_unavailable()
        .expect("Node still healthy");

    // Note that how the canister heap is modified is decided by the random seed.
    // Make sure to provide a different seed than the one used in the previous `modify_canister_heap` call.
    // In the following call, we skip odd-indexed canisters so that some canisters remain the same while others change.
    info!(
        logger,
        "Start modifying the canister heap but skip odd-indexed canisters"
    );
    modify_canister_heap(
        logger.clone(),
        canisters.clone(),
        size_level,
        num_canisters,
        true,
        1,
    )
    .await;

    info!(logger, "Get the latest certified height of an active node");
    let message = b"Are you actively making progress?";
    store_and_read_stable(&logger, message, &universal_canister).await;
    let res =
        fetch_metrics::<u64>(&logger, agent_node.clone(), vec![LATEST_CERTIFIED_HEIGHT]).await;
    let latest_certified_height = res[LATEST_CERTIFIED_HEIGHT][0];

    // Wait for the next CUP to make sure the second round of state modification is persisted to a new checkpoint.
    info!(logger, "Waiting for the next CUP");
    wait_for_cup(&logger, latest_certified_height, agent_node.clone()).await;

    info!(logger, "Killing {} nodes ...", allowed_failures);
    for node_to_kill in nodes_to_kill {
        info!(logger, "Killing node {} ...", node_to_kill.get_public_url());
        node_to_kill.vm().kill();
        node_to_kill
            .await_status_is_unavailable()
            .expect("Node still healthy");
    }

    info!(logger, "Start the first killed node again...");
    rejoin_node.vm().start();
    rejoin_node
        .await_status_is_healthy()
        .expect("Started node did not report healthy status");

    info!(logger, "Checking for subnet progress...");
    let message = b"This beautiful prose should be persisted for future generations";
    store_and_read_stable(&logger, message, &universal_canister).await;

    info!(
        logger,
        "Checking for the state sync count metrics indicating that a successful state sync has happened"
    );
    let res = fetch_metrics::<u64>(
        &logger,
        rejoin_node.clone(),
        vec![SUCCESSFUL_STATE_SYNC_DURATION_SECONDS_COUNT],
    )
    .await;
    assert!(res[SUCCESSFUL_STATE_SYNC_DURATION_SECONDS_COUNT][0] > base_count);

    let res = fetch_metrics::<f64>(
        &logger,
        rejoin_node.clone(),
        vec![SUCCESSFUL_STATE_SYNC_DURATION_SECONDS_SUM],
    )
    .await;
    info!(
        logger,
        "State sync finishes successfully in {} seconds",
        res[SUCCESSFUL_STATE_SYNC_DURATION_SECONDS_SUM][0],
    );
}

pub async fn fetch_metrics<T>(
    log: &slog::Logger,
    node: IcNodeSnapshot,
    labels: Vec<&str>,
) -> BTreeMap<String, Vec<T>>
where
    T: Copy + Debug + FromStr,
{
    const NUM_RETRIES: u32 = 200;
    const BACKOFF_TIME_MILLIS: u64 = 500;

    let metrics = MetricsFetcher::new(
        std::iter::once(node),
        labels.iter().map(|&label| label.to_string()).collect(),
    );
    for i in 0..NUM_RETRIES {
        let metrics_result = metrics.fetch::<T>().await;
        match metrics_result {
            Ok(result) => {
                if labels.iter().all(|&label| result.contains_key(label)) {
                    info!(log, "Metrics successfully scraped {:?}.", result);
                    return result;
                } else {
                    info!(log, "Metrics not available yet, attempt {i}.");
                }
            }
            Err(e) => {
                info!(log, "Could not scrape metrics: {e}, attempt {i}.");
            }
        }
        tokio::time::sleep(Duration::from_millis(BACKOFF_TIME_MILLIS)).await;
    }
    panic!("Couldn't obtain metrics after {NUM_RETRIES} attempts.");
}

async fn store_and_read_stable(
    logger: &slog::Logger,
    message: &[u8],
    universal_canister: &UniversalCanister<'_>,
) {
    let mut attempts = 1;
    // There seem to be situations where we need to retry this, especially after the subnet just unstalled itself and
    // a rejoining node reports healthy again. Not 100% clear why that is.
    while let Err(err) = universal_canister.try_store_to_stable(0, message).await {
        if attempts >= STORE_TO_STABLE_RETRIES {
            panic!("Failed to write to stable memory.");
        }
        info!(logger, "Retrying writing to stable: {:?}", err);
        attempts += 1;
    }
    assert_eq!(
        universal_canister
            .try_read_stable(0, message.len() as u32)
            .await,
        message.to_vec()
    );
}

async fn install_statesync_test_canisters(
    env: TestEnv,
    endpoint_runtime: &Runtime,
    num_canisters: usize,
) -> Vec<Canister> {
    let logger = env.logger();
    let wasm = Wasm::from_file(get_dependency_path(
        env::var("STATESYNC_TEST_CANISTER_WASM_PATH")
            .expect("STATESYNC_TEST_CANISTER_WASM_PATH not set"),
    ));
    let mut futures: Vec<_> = Vec::new();
    for canister_idx in 0..num_canisters {
        let new_wasm = wasm.clone();
        let new_logger = logger.clone();
        futures.push(async move {
            // Each canister is allocated with slightly more than 1GB of memory
            // and the memory will later grow by the `expand_state` calls.
            let canister = new_wasm
                .clone()
                .install(endpoint_runtime)
                .with_memory_allocation(1056 * 1024 * 1024)
                .bytes(Vec::new())
                .await
                .unwrap_or_else(|_| {
                    panic!("Installation of the canister_idx={} failed.", canister_idx)
                });
            info!(
                new_logger,
                "Installed canister (#{:?}) {}",
                canister_idx,
                canister.canister_id(),
            );
            canister
        });
    }
    join_all(futures).await
}

async fn modify_canister_heap(
    logger: slog::Logger,
    canisters: Vec<Canister<'_>>,
    size_level: usize,
    num_canisters: usize,
    skip_odd_indexed_canister: bool,
    seed: usize,
) {
    for x in 1..=size_level {
        info!(
            logger,
            "Start modifying canisters {} times, it is now {}",
            x,
            Utc::now()
        );
        for (i, canister) in canisters.iter().enumerate() {
            if skip_odd_indexed_canister && i % 2 == 1 {
                continue;
            }
            let seed_for_canister = i + (x - 1) * num_canisters + seed;
            let payload = (x as u32, seed_for_canister as u32);
            // Each call will expand the memory by writing a chunk of 128 MiB.
            // There are 8 chunks in the canister, so the memory will grow by 1 GiB after 8 calls.
            let _res: Result<u64, String> = canister
                .update_("expand_state", dfn_candid::candid, payload)
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "Calling expand_state() on canister {} failed: {}",
                        canister.canister_id_vec8()[0],
                        e
                    )
                });
        }
        info!(
            logger,
            "Expanded canisters {} times, it is now {}",
            x,
            Utc::now()
        );
    }
}

// The function waits for the manifest reaching or surpassing the given height and returns the manifest height.
async fn wait_for_manifest(log: &slog::Logger, height: u64, node: IcNodeSnapshot) -> u64 {
    let num_retries = height + 1;
    const BACKOFF_TIME_SECONDS: u64 = 5;

    for _ in 0..num_retries {
        let res = fetch_metrics::<u64>(log, node.clone(), vec![LAST_MANIFEST_HEIGHT]).await;
        let last_manifest_height = res[LAST_MANIFEST_HEIGHT][0];
        if last_manifest_height >= height {
            info!(log, "Manifest height {} reached.", last_manifest_height);
            return last_manifest_height;
        }
        tokio::time::sleep(Duration::from_secs(BACKOFF_TIME_SECONDS)).await;
    }
    panic!("Couldn't get a manifest at height {}.", height);
}

// The function waits for the CUP reaching or surpassing the given height and returns the CUP height.
//
// The `replicated_state_purge_height_disk` represents the height of the last CUP.
// Practically speaking, there should be little gap between the manifest and the last CUP reach the same new height.
// However we still use CUP height here because conceptually it indicates a new state sync can be triggered base on that.
async fn wait_for_cup(log: &slog::Logger, height: u64, node: IcNodeSnapshot) -> u64 {
    let num_retries = height + 1;
    const BACKOFF_TIME_SECONDS: u64 = 5;

    for _ in 0..num_retries {
        let res =
            fetch_metrics::<u64>(log, node.clone(), vec![REPLICATED_STATE_PURGE_HEIGHT_DISK]).await;
        let last_cup_height = res[REPLICATED_STATE_PURGE_HEIGHT_DISK][0];
        if last_cup_height >= height {
            info!(log, "CUP height {} reached.", last_cup_height);
            return last_cup_height;
        }
        tokio::time::sleep(Duration::from_secs(BACKOFF_TIME_SECONDS)).await;
    }
    panic!("Couldn't get a CUP at height {}.", height);
}
