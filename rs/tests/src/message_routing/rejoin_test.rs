/* tag::catalog[]

Title:: Nodes can rejoin a subnet under load

Runbook::
. setup the testnet of 3f + 1 nodes
. pick a random node and install the universal canister through it
. pick another random node rejoin_node and kill it
. make a number of updates to the universal canister
. kill f random nodes
. start the rejoin_node
. wait a few seconds before checking the success condition

Success::
.. if an update can be made to the universal canister and queried back

end::catalog[] */

use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::pot_dsl::{PotSetupFn, SysTestFn};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, HasVm, IcNodeContainer, IcNodeSnapshot,
};
use ic_system_test_driver::util::{block_on, MetricsFetcher, UniversalCanister};
use ic_types::Height;
use slog::info;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::str::FromStr;
use std::time::Duration;

const DKG_INTERVAL: u64 = 14;
const NOTARY_DELAY: Duration = Duration::from_millis(100);

pub const SUCCESSFUL_STATE_SYNC_DURATION_SECONDS_SUM: &str =
    "state_sync_duration_seconds_sum{status=\"ok\"}";
pub const SUCCESSFUL_STATE_SYNC_DURATION_SECONDS_COUNT: &str =
    "state_sync_duration_seconds_count{status=\"ok\"}";
#[derive(Debug, Clone)]
pub struct Config {
    nodes_count: usize,
}

impl Config {
    pub fn new(nodes_count: usize) -> Config {
        Config { nodes_count }
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
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .add_nodes(config.nodes_count)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .with_initial_notary_delay(NOTARY_DELAY),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

fn test(env: TestEnv, config: Config) {
    block_on(test_async(env, config));
}

async fn test_async(env: TestEnv, config: Config) {
    let mut nodes = env.topology_snapshot().root_subnet().nodes();
    let agent_node = nodes.next().unwrap();
    let rejoin_node = nodes.next().unwrap();
    let allowed_failures = (config.nodes_count - 1) / 3;
    rejoin_test(
        &env,
        allowed_failures,
        DKG_INTERVAL,
        rejoin_node,
        agent_node,
        nodes.take(allowed_failures),
    )
    .await;
}
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
        store_and_read_stable(i.to_le_bytes().as_slice(), &universal_canister).await;
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

pub async fn store_and_read_stable(message: &[u8], universal_canister: &UniversalCanister<'_>) {
    universal_canister.store_to_stable(0, message).await;
    assert_eq!(
        universal_canister
            .try_read_stable(0, message.len() as u32)
            .await,
        message.to_vec()
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
