/* tag::catalog[]

Title:: Nodes can rejoin a subnet under load

Runbook::
. setup the testnet of 3f + 1 nodes
. pick a random node and install the universal canister through it
. install some state sync test canisters through it
. expand the heap of all canisters to `size_level` * 128 MiB
. pick another random node rejoin_node and wait for it creating a checkpoint
. kill the rejoined node and wait for the subnet producing a new CUP
. kill f random nodes
. start the rejoin_node
. wait a few seconds before checking the success condition

Success::
.. if an update can be made to the universal canister and queried back
.. if the status of the rejoined node turns healthy
.. if the state sync duration metrics of the rejoin_node indicate the state sync has happened

end::catalog[] */

use super::rejoin_test::{
    fetch_metrics, store_and_read_stable, SUCCESSFUL_STATE_SYNC_DURATION_SECONDS_COUNT,
    SUCCESSFUL_STATE_SYNC_DURATION_SECONDS_SUM,
};
use crate::message_routing::common::{install_statesync_test_canisters, modify_canister_heap};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::ic::{
    AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, Subnet, VmResources,
};
use ic_system_test_driver::driver::pot_dsl::{PotSetupFn, SysTestFn};
use ic_system_test_driver::driver::prometheus_vm::{HasPrometheus, PrometheusVm};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, HasVm, IcNodeContainer, IcNodeSnapshot,
};
use ic_system_test_driver::util::{block_on, runtime_from_url, UniversalCanister};
use ic_types::Height;
use slog::info;
use std::time::Duration;

const DKG_INTERVAL: u64 = 499;

const LAST_MANIFEST_HEIGHT: &str = "state_manager_last_computed_manifest_height";
const REPLICATED_STATE_PURGE_HEIGHT_DISK: &str = "replicated_state_purge_height_disk";
const LATEST_CERTIFIED_HEIGHT: &str = "state_manager_latest_certified_height";

#[derive(Clone, Debug)]
pub struct Config {
    nodes_count: usize,
    size_level: usize,
    num_canisters: usize,
}

impl Config {
    pub fn new(nodes_count: usize, size_level: usize, num_canisters: usize) -> Config {
        Config {
            nodes_count,
            size_level,
            num_canisters,
        }
    }

    /// Builds the IC instance.
    pub fn build(self) -> impl PotSetupFn {
        move |env: TestEnv| setup(env, self)
    }

    /// Returns a test function based on this configuration.
    pub fn test(self) -> impl SysTestFn {
        move |env: TestEnv| test(env, self)
    }
}

// Generic setup
fn setup(env: TestEnv, config: Config) {
    assert!(
        config.nodes_count >= 4,
        "at least 4 nodes are required for state sync"
    );
    assert!(
        config.size_level >= 1 && config.size_level <= 8,
        "the size level should be between 1 and 8"
    );
    PrometheusVm::default()
        .start(&env)
        .expect("failed to start prometheus VM");

    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_default_vm_resources(VmResources {
                    vcpus: None,
                    memory_kibibytes: Some(AmountOfMemoryKiB::new(
                        (24 + 2 * config.num_canisters as u64) * 1024 * 1024,
                    )),
                    boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(
                        100 + 2 * config.num_canisters as u64,
                    )),
                })
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(config.nodes_count),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });

    env.sync_with_prometheus();
}

fn test(env: TestEnv, config: Config) {
    block_on(test_async(env, config));
}

async fn test_async(env: TestEnv, config: Config) {
    let mut nodes = env.topology_snapshot().root_subnet().nodes();
    let agent_node = nodes.next().unwrap();
    let rejoin_node = nodes.next().unwrap();
    let allowed_failures = (config.nodes_count - 1) / 3;
    rejoin_test_large_state(
        env,
        allowed_failures,
        config.size_level,
        config.num_canisters,
        DKG_INTERVAL,
        rejoin_node.clone(),
        agent_node.clone(),
        nodes.take(allowed_failures),
    )
    .await;
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
    store_and_read_stable(message, &universal_canister).await;
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
    store_and_read_stable(message, &universal_canister).await;

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
