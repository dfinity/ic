use candid::{Encode, Principal};
use canister_test::{Canister, Runtime, Wasm};
use futures::future::join_all;
use ic_agent::Agent;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::get_dependency_path;
use ic_system_test_driver::driver::test_env_api::retry_async;
use ic_system_test_driver::driver::test_env_api::{HasPublicApiUrl, HasVm, IcNodeSnapshot};
use ic_system_test_driver::util::{MetricsFetcher, UniversalCanister, runtime_from_url};
use ic_types::PrincipalId;
use ic_types::messages::ReplicaHealthStatus;
use ic_universal_canister::wasm;
use ic_utils::interfaces::management_canister::ManagementCanister;
use slog::Logger;
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

pub const STATE_SYNC_SIZE_BYTES_TOTAL_FETCH: &str = "state_sync_size_bytes_total{op=\"fetch\"}";
pub const STATE_SYNC_SIZE_BYTES_TOTAL_HARDLINK_FILES: &str =
    "state_sync_size_bytes_total{op=\"hardlink_files\"}";
pub const STATE_SYNC_SIZE_BYTES_TOTAL_COPY_CHUNKS: &str =
    "state_sync_size_bytes_total{op=\"copy_chunks\"}";

const LATEST_CERTIFIED_HEIGHT: &str = "state_manager_latest_certified_height";
const LAST_MANIFEST_HEIGHT: &str = "state_manager_last_computed_manifest_height";
const REPLICATED_STATE_PURGE_HEIGHT_DISK: &str = "replicated_state_purge_height_disk";

const METRIC_PROCESS_BATCH_PHASE_DURATION: &str = "mr_process_batch_phase_duration_seconds";

const GIB: u64 = 1 << 30;

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

    assert_state_sync_has_happened(&logger, rejoin_node, base_count).await;
}

pub async fn rejoin_test_large_state(
    env: TestEnv,
    allowed_failures: usize,
    canister_size_gib: u64,
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
    let canisters = install_statesync_test_canisters(&env, &endpoint_runtime, num_canisters).await;

    info!(
        logger,
        "Start writing random data to the canister stable memory for each canister. The total size of all canisters will be about {} GiB.",
        num_canisters as u64 * canister_size_gib,
    );

    write_random_data_to_stable_memory(
        logger.clone(),
        canisters.clone(),
        false,
        0,
        canister_size_gib,
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

    // Note that the canister stable memory is modified based on the random seed.
    // Make sure to provide a different seed than the one used in the previous `write_random_data_to_stable_memory` call.
    // In the following call, we skip odd-indexed canisters so that some canisters remain the same while others change.
    info!(
        logger,
        "Start modifying canister stable memory by new random data"
    );

    write_random_data_to_stable_memory(
        logger.clone(),
        canisters.clone(),
        true,
        0,
        canister_size_gib,
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

    assert_state_sync_has_happened(&logger, rejoin_node, base_count).await;
}

async fn deploy_seed_canister(
    ic00: &ManagementCanister<'_>,
    effective_canister_id: PrincipalId,
) -> Principal {
    let seed_canister_id = ic00
        .create_canister()
        .as_provisional_create_with_amount(None)
        .with_effective_canister_id(effective_canister_id.0)
        .call_and_wait()
        .await
        .expect("Failed to create a seed canister")
        .0;
    let seed_canister_wasm_path = get_dependency_path(
        env::var("STATESYNC_TEST_CANISTER_WASM_PATH")
            .expect("STATESYNC_TEST_CANISTER_WASM_PATH not set"),
    );
    let seed_canister_wasm = std::fs::read(seed_canister_wasm_path)
        .expect("Could not read STATESYNC_TEST_CANISTER_WASM_PATH");
    ic00.install(&seed_canister_id, &seed_canister_wasm)
        .await
        .expect("Failed to install a seed canister");
    seed_canister_id
}

async fn deploy_busy_canister(agent: &Agent, effective_canister_id: PrincipalId, logger: &Logger) {
    let universal_canister =
        UniversalCanister::new_with_retries(agent, effective_canister_id, logger).await;
    universal_canister
        .update(
            wasm()
                .set_heartbeat(
                    wasm()
                        .instruction_counter_is_at_least(1_800_000_000)
                        .build(),
                )
                .reply()
                .build(),
        )
        .await
        .expect("Failed to set up a busy canister.");
}

async fn deploy_canisters_for_long_rounds(
    logger: &slog::Logger,
    nodes: Vec<IcNodeSnapshot>,
    num_canisters: usize,
) {
    let init_node = nodes[0].clone();
    let agent = init_node.build_default_agent_async().await;
    let ic00 = ManagementCanister::create(&agent);

    let num_seed_canisters = 4;
    info!(
        logger,
        "Deploying {} seed canisters on a node {} ...",
        num_seed_canisters,
        init_node.get_public_url()
    );
    let mut create_seed_canisters_futs = vec![];
    for _ in 0..num_seed_canisters {
        create_seed_canisters_futs.push(deploy_seed_canister(
            &ic00,
            init_node.effective_canister_id(),
        ));
    }
    let seed_canisters = join_all(create_seed_canisters_futs).await;

    let num_canisters_per_seed_canister = num_canisters / num_seed_canisters;
    info!(
        logger,
        "Creating {} canisters via the seed canisters ...",
        num_canisters_per_seed_canister * num_seed_canisters,
    );
    let mut create_many_canisters_futs = vec![];
    for seed_canister_id in seed_canisters {
        let bytes = Encode!(&num_canisters_per_seed_canister)
            .expect("Failed to candid encode argument for a seed canister");
        let fut = agent
            .update(&seed_canister_id, "create_many_canisters")
            .with_arg(bytes)
            .call_and_wait();
        create_many_canisters_futs.push(fut);
    }
    let res = join_all(create_many_canisters_futs).await;
    for r in res {
        r.expect("Failed to create canisters via a seed canister");
    }

    // We deploy 8 "busy" canisters: this way,
    // there are 2 canisters per each of the 4 scheduler threads
    // and thus every thread executes 2 x 1.8B = 3.6B instructions.
    let num_busy_canisters = 8;
    info!(
        logger,
        "Deploying {} busy canisters on a node {} ...",
        num_busy_canisters,
        init_node.get_public_url()
    );
    let mut create_busy_canisters_futs = vec![];
    for _ in 0..num_busy_canisters {
        create_busy_canisters_futs.push(deploy_busy_canister(
            &agent,
            init_node.effective_canister_id(),
            logger,
        ));
    }
    join_all(create_busy_canisters_futs).await;
}

pub async fn rejoin_test_long_rounds(
    env: TestEnv,
    nodes: Vec<IcNodeSnapshot>,
    num_canisters: usize,
    dkg_interval: u64,
) {
    let logger = env.logger();
    deploy_canisters_for_long_rounds(&logger, nodes.clone(), num_canisters).await;

    // Sort nodes by their average duration to process a batch.
    let mut average_process_batch_durations = vec![];
    for node in &nodes {
        let duration = average_process_batch_duration(&logger, node.clone()).await;
        average_process_batch_durations.push(duration);
    }
    let mut paired: Vec<_> = average_process_batch_durations
        .into_iter()
        .zip(nodes.into_iter())
        .collect();
    paired.sort_by(|(k1, _), (k2, _)| k1.total_cmp(k2));
    let sorted_nodes: Vec<_> = paired.into_iter().map(|(_, v)| v).collect();

    // The fastest node will be the reference node used to check
    // the latest certified height of the subnet.
    let reference_node = sorted_nodes[0].clone();

    // The restarted node will be the slowest node
    // required for consensus in terms of batch processing time:
    // this way, the restarted node cannot catch up with the subnet
    // without additional measures (to be implemented in the future).
    // E.g., for `n = 13`, we have `f = 4` and the nodes at indices
    // `0`, `1`, ..., `n - (f + 1)` are required for consensus,
    // i.e., we restart the node at (0-based) index
    // `n - (f + 1) = n - (n / 3 + 1)`.
    let n = sorted_nodes.len();
    let rejoin_node = sorted_nodes[n - (n / 3 + 1)].clone();

    info!(
        logger,
        "Killing a node: {} ...",
        rejoin_node.get_public_url()
    );
    rejoin_node.vm().kill();
    rejoin_node
        .await_status_is_unavailable()
        .expect("Node still healthy");

    // Wait for the subnet to produce a CUP and then restart the rejoin_node.
    // This way, the restarted node starts from that CUP
    // and we can assert it to catch up until the next CUP.
    info!(logger, "Waiting for a CUP ...");
    let reference_node_status = reference_node
        .status_async()
        .await
        .expect("Failed to get status of reference_node");
    let latest_certified_height = reference_node_status
        .certified_height
        .expect("Failed to get certified height of reference_node")
        .get();
    wait_for_cup(&logger, latest_certified_height, reference_node.clone()).await;

    info!(logger, "Start the killed node again ...");
    rejoin_node.vm().start();

    info!(logger, "Waiting for the next CUP ...");
    let last_cup_height = wait_for_cup(
        &logger,
        latest_certified_height + dkg_interval + 1,
        reference_node.clone(),
    )
    .await;

    let rejoin_node_status = rejoin_node
        .status_async()
        .await
        .expect("Failed to get status of rejoin_node");
    let rejoin_node_certified_height = rejoin_node_status
        .certified_height
        .expect("Failed to get certified height of rejoin_node")
        .get();
    assert!(
        rejoin_node_certified_height >= last_cup_height,
        "The rejoin_node certified height {} is less than the last CUP height {}.",
        rejoin_node_certified_height,
        last_cup_height
    );
    let rejoin_node_health_status = rejoin_node_status
        .replica_health_status
        .expect("Failed to get replica health status of rejoin_node");
    assert_eq!(rejoin_node_health_status, ReplicaHealthStatus::Healthy);
}

pub async fn assert_state_sync_has_happened(
    logger: &slog::Logger,
    rejoin_node: IcNodeSnapshot,
    base_count: u64,
) -> f64 {
    const NUM_RETRIES: u32 = 300;
    const BACKOFF_TIME_MILLIS: u64 = 1000;

    info!(
        logger,
        "Checking for the state sync count metrics indicating that a successful state sync has happened"
    );

    // We retry a few times as we observed a pontential race condition where it
    // still reads a slightly older value from the metrics, even though the
    // state sync has already happened. This is a workaround to make the test
    // more robust.
    for _i in 0..NUM_RETRIES {
        let count = fetch_metrics::<u64>(
            logger,
            rejoin_node.clone(),
            vec![SUCCESSFUL_STATE_SYNC_DURATION_SECONDS_COUNT],
        )
        .await;
        if count[SUCCESSFUL_STATE_SYNC_DURATION_SECONDS_COUNT][0] > base_count {
            let time = fetch_metrics::<f64>(
                logger,
                rejoin_node.clone(),
                vec![SUCCESSFUL_STATE_SYNC_DURATION_SECONDS_SUM],
            )
            .await;
            info!(
                logger,
                "State sync finishes successfully in {} seconds",
                time[SUCCESSFUL_STATE_SYNC_DURATION_SECONDS_SUM][0],
            );

            let stats = fetch_metrics::<u64>(
                logger,
                rejoin_node.clone(),
                vec![
                    STATE_SYNC_SIZE_BYTES_TOTAL_FETCH,
                    STATE_SYNC_SIZE_BYTES_TOTAL_HARDLINK_FILES,
                    STATE_SYNC_SIZE_BYTES_TOTAL_COPY_CHUNKS,
                ],
            )
            .await;

            info!(
                logger,
                "State sync size summary, fetch: {} bytes, hardlink files: {} bytes, copy chunks: {} bytes",
                stats[STATE_SYNC_SIZE_BYTES_TOTAL_FETCH][0],
                stats[STATE_SYNC_SIZE_BYTES_TOTAL_HARDLINK_FILES][0],
                stats[STATE_SYNC_SIZE_BYTES_TOTAL_COPY_CHUNKS][0],
            );

            return time[SUCCESSFUL_STATE_SYNC_DURATION_SECONDS_SUM][0];
        }
        tokio::time::sleep(Duration::from_millis(BACKOFF_TIME_MILLIS)).await;
    }
    panic!("Couldn't verify that a state sync has happened after {NUM_RETRIES} attempts.");
}

async fn average_process_batch_duration(log: &slog::Logger, node: IcNodeSnapshot) -> f64 {
    let label_sum = format!("{METRIC_PROCESS_BATCH_PHASE_DURATION}_sum");
    let label_count = format!("{METRIC_PROCESS_BATCH_PHASE_DURATION}_count");
    let metrics = fetch_metrics::<f64>(log, node.clone(), vec![&label_sum, &label_count]).await;
    let sums: Vec<_> = metrics
        .iter()
        .filter_map(|(k, v)| {
            if k.starts_with(&label_sum) {
                Some(v)
            } else {
                None
            }
        })
        .collect();
    let counts: Vec<_> = metrics
        .iter()
        .filter_map(|(k, v)| {
            if k.starts_with(&label_count) {
                Some(v)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(sums.len(), counts.len());
    sums.iter()
        .zip(counts.iter())
        .map(|(x, y)| x[0] / y[0])
        .sum()
}

pub async fn fetch_metrics<T>(
    log: &slog::Logger,
    node: IcNodeSnapshot,
    labels: Vec<&str>,
) -> BTreeMap<String, Vec<T>>
where
    T: Copy + Debug + FromStr,
{
    const NUM_RETRIES: u32 = 500;
    const BACKOFF_TIME_MILLIS: u64 = 1000;

    let metrics = MetricsFetcher::new(
        std::iter::once(node),
        labels.iter().map(|&label| label.to_string()).collect(),
    );
    for i in 0..NUM_RETRIES {
        let metrics_result = metrics.fetch::<T>().await;
        match metrics_result {
            Ok(result) => {
                if labels
                    .iter()
                    .all(|&label| result.iter().any(|(k, _)| k.starts_with(label)))
                {
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

pub async fn install_statesync_test_canisters<'a>(
    env: &'a TestEnv,
    endpoint_runtime: &'a Runtime,
    num_canisters: usize,
) -> Vec<Canister<'a>> {
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
            // and the memory will later grow by the `write_random_data` calls.
            let canister = new_wasm
                .clone()
                .install(endpoint_runtime)
                .with_memory_allocation(1056 * 1024 * 1024)
                .bytes(Vec::new())
                .await
                .unwrap_or_else(|_| {
                    panic!("Installation of the canister_idx={canister_idx} failed.")
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

pub async fn write_random_data_to_stable_memory(
    logger: slog::Logger,
    canisters: Vec<Canister<'_>>,
    skip_odd_indexed_canister: bool,
    write_offset: u64,
    write_size_gib: u64,
    seed: u64,
) {
    let writes = canisters
        .iter()
        .enumerate()
        .filter(|(idx, _)| !(skip_odd_indexed_canister && idx % 2 == 1))
        .map(|(idx, canister)| {
            let logger_clone = logger.clone();
            async move {
                for x in 0..write_size_gib {
                    let seed_for_canister = idx as u64 * 10000 + x * 100 + seed;
                    let cur_offset = write_offset + x * GIB;
                    let payload = (cur_offset, GIB, seed_for_canister);

                    let _res: Result<(), String> = retry_async(
                        "Trying to write stable memory",
                        &logger_clone,
                        Duration::from_secs(500),
                        Duration::from_secs(5),
                        async || {
                            canister
                                .update_("write_random_data", dfn_candid::candid, payload)
                                .await
                                .map_err(|err| anyhow::anyhow!("{}", err))
                        },
                    )
                    .await
                    .unwrap_or_else(|err| {
                        panic!("Calling write_random_data() on canister {canister:?} at offset: {cur_offset}, failed: {err}",)
                    });

                    info!(
                        logger_clone,
                        "Wrote random data to the {}th canister {:?} {} times",
                        idx,
                        canister,
                        x + 1,
                    );
                }
            }
        })
        .collect::<Vec<_>>();

    join_all(writes).await;
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
    panic!("Couldn't get a manifest at height {height}.");
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
    panic!("Couldn't get a CUP at height {height}.");
}
