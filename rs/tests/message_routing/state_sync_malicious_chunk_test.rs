/* tag::catalog[]

Title:: Nodes can rejoin a subnet despite of malicious chunks

Runbook::
. setup the testnet of a root subnet and an app subnet
. each subnet has 3f + 1 nodes
. the root subnet has one special node which simulates malicious chunks by altering received chunks
. the node alters meta-manifest/manifest/state chunks based on the pre-defined allowance
. run rejoin_test with the special node as the rejoin_node
. check the state sync finishes successfully and the expected number of invalid chunks are detected
. the app subnet has f malicious nodes which always send malicious chunks
. run rejoin_test_large_state while some state sync peers are honest and others are malicious
. check the state sync finishes successfully and some invalid chunks are detected

Success::
.. all malicious chunks are rejected

end::catalog[] */

use anyhow::Result;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{
    AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, Subnet, VmResources,
};
use ic_system_test_driver::driver::pot_dsl::{PotSetupFn, SysTestFn};
use ic_system_test_driver::driver::prometheus_vm::PrometheusVm;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::block_on;
use ic_types::Height;
use ic_types::malicious_behavior::MaliciousBehavior;
use rejoin_test_lib::fetch_metrics;
use rejoin_test_lib::rejoin_test;
use rejoin_test_lib::rejoin_test_large_state;
use slog::info;
use std::collections::BTreeMap;
use std::time::Duration;

const PER_TASK_TIMEOUT: Duration = Duration::from_secs(3600 * 2);
const OVERALL_TIMEOUT: Duration = Duration::from_secs(3600 * 2);
const NUM_NODES: usize = 7;

const INVALID_META_MANIFEST_CHUNK: &str =
    "state_sync_corrupted_chunks{source=\"fetch_meta_manifest_chunk\"}";
const INVALID_MANIFEST_CHUNK: &str = "state_sync_corrupted_chunks{source=\"fetch_manifest_chunk\"}";
const INVALID_STATE_CHUNK: &str = "state_sync_corrupted_chunks{source=\"fetch_state_chunk\"}";

const DKG_INTERVAL_SMALL: u64 = 14;
const NOTARY_DELAY: Duration = Duration::from_millis(100);

const DKG_INTERVAL_LARGE: u64 = 199;
const NUM_CANISTERS: usize = 8;
const SIZE_LEVEL: usize = 8;

fn main() -> Result<()> {
    let config = Config::new(NUM_NODES);
    let test = config.clone().test();
    SystemTestGroup::new()
        .with_setup(config.build())
        .add_test(systest!(test))
        .with_timeout_per_test(PER_TASK_TIMEOUT)
        .with_overall_timeout(OVERALL_TIMEOUT)
        .execute_from_args()?;
    Ok(())
}

#[derive(Clone, Debug)]
pub struct Config {
    nodes_count: usize,
    allowed_failures: usize,
    meta_manifest_chunk_error_allowance: u32,
    manifest_chunk_error_allowance: u32,
    state_chunk_error_allowance: u32,
}

impl Config {
    pub fn new(nodes_count: usize) -> Config {
        let allowed_failures = (nodes_count - 1) / 3;
        let state_sync_peers = nodes_count - allowed_failures - 1;
        assert!(
            nodes_count >= 4,
            "at least 4 nodes are required for state sync"
        );

        // Assign the number of invalid chunks allowed for each phase.
        // Make sure that the number of state sync peers is greater than the total number of invalid chunks allowed.
        // Otherwise, the state sync will fail.
        let (
            meta_manifest_chunk_error_allowance,
            manifest_chunk_error_allowance,
            state_chunk_error_allowance,
        ) = match state_sync_peers {
            0..=1 => unreachable!(
                "there are at least 2 state sync peers because the subnet has at least 4 nodes"
            ),
            2 => (1, 0, 0),
            3 => (1, 1, 0),
            _ => (1, 1, state_sync_peers as u32 - 3),
        };
        Config {
            nodes_count,
            allowed_failures,
            meta_manifest_chunk_error_allowance,
            manifest_chunk_error_allowance,
            state_chunk_error_allowance,
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
fn setup(env: TestEnv, config: Config) {
    PrometheusVm::default()
        .start(&env)
        .expect("failed to start prometheus VM");

    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .add_nodes(config.nodes_count - 1)
                .add_malicious_nodes(
                    1,
                    MaliciousBehavior::new(true)
                        .set_maliciously_alter_state_sync_chunk_receiving_side(
                            config.meta_manifest_chunk_error_allowance,
                            config.manifest_chunk_error_allowance,
                            config.state_chunk_error_allowance,
                        ),
                )
                .with_dkg_interval_length(Height::from(DKG_INTERVAL_SMALL))
                .with_initial_notary_delay(NOTARY_DELAY),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_default_vm_resources(VmResources {
                    vcpus: None,
                    memory_kibibytes: Some(AmountOfMemoryKiB::new(
                        (24 + 2 * NUM_CANISTERS as u64) * 1024 * 1024,
                    )),
                    boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(
                        100 + 2 * NUM_CANISTERS as u64,
                    )),
                })
                .with_dkg_interval_length(Height::from(DKG_INTERVAL_LARGE))
                .add_nodes(config.nodes_count - config.allowed_failures)
                .add_malicious_nodes(
                    config.allowed_failures,
                    MaliciousBehavior::new(true)
                        .set_maliciously_alter_state_sync_chunk_sending_side(),
                ),
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
    let logger = env.logger();

    // Test 1: simulate malicious chunks by altering them in receiving side
    let root_subnet = env.topology_snapshot().root_subnet();
    // The special node is selected as the one to do state sync
    let rejoin_node = root_subnet
        .nodes()
        .find(|node| node.is_malicious())
        .unwrap();
    let mut nodes = root_subnet.nodes().filter(|node| !node.is_malicious());
    let agent_node = nodes.next().unwrap();

    rejoin_test(
        &env,
        config.allowed_failures,
        DKG_INTERVAL_SMALL,
        rejoin_node.clone(),
        agent_node,
        nodes.take(config.allowed_failures),
    )
    .await;

    info!(
        logger,
        "Collecting metrics of invalid chunks during state sync"
    );
    let results = fetch_metrics::<u64>(
        &logger,
        rejoin_node,
        vec![
            INVALID_META_MANIFEST_CHUNK,
            INVALID_MANIFEST_CHUNK,
            INVALID_STATE_CHUNK,
        ],
    )
    .await;
    // Assert the number of invalid chunks detected during state sync is the same as the pre-defined allowance
    assert_metrics(results, &config);

    // Test 2: some malicious nodes always send malicious chunks
    let app_subnet = env
        .topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_id != root_subnet.subnet_id)
        .expect("No app subnets found");

    let mut nodes = app_subnet.nodes().filter(|node| !node.is_malicious());
    let agent_node = nodes.next().unwrap();
    let rejoin_node = nodes.next().unwrap();
    // In this test, we run state sync with large state because it needs to download thousands of chunks and takes longer time to finish.
    // This gives all peers including the malicious ones chances to send chunks to the rejoin_node.
    rejoin_test_large_state(
        env,
        config.allowed_failures,
        SIZE_LEVEL,
        NUM_CANISTERS,
        DKG_INTERVAL_LARGE,
        rejoin_node.clone(),
        agent_node,
        nodes.take(config.allowed_failures),
    )
    .await;

    info!(
        logger,
        "Collecting metrics of invalid chunks during state sync"
    );
    let result = fetch_metrics::<u64>(
        &logger,
        rejoin_node,
        vec![
            INVALID_META_MANIFEST_CHUNK,
            INVALID_MANIFEST_CHUNK,
            INVALID_STATE_CHUNK,
        ],
    )
    .await;
    // Assert that there are some invalid chunks detected during state sync
    let total_invalid_chunks = result[INVALID_META_MANIFEST_CHUNK][0]
        + result[INVALID_MANIFEST_CHUNK][0]
        + result[INVALID_STATE_CHUNK][0];
    assert!(total_invalid_chunks > 0);
}

fn assert_metrics(result: BTreeMap<String, Vec<u64>>, config: &Config) {
    assert_eq!(
        result[INVALID_META_MANIFEST_CHUNK][0], config.meta_manifest_chunk_error_allowance as u64,
        "The number of invalid meta-manifest chunks detected: {} does not match the ones sent: {}.",
        result[INVALID_META_MANIFEST_CHUNK][0], config.meta_manifest_chunk_error_allowance,
    );

    assert_eq!(
        result[INVALID_MANIFEST_CHUNK][0], config.manifest_chunk_error_allowance as u64,
        "The number of invalid manifest chunks detected: {} does not match the ones sent: {}.",
        result[INVALID_MANIFEST_CHUNK][0], config.manifest_chunk_error_allowance,
    );

    assert_eq!(
        result[INVALID_STATE_CHUNK][0], config.state_chunk_error_allowance as u64,
        "The number of invalid other chunks detected: {} does not match the ones sent: {}.",
        result[INVALID_STATE_CHUNK][0], config.state_chunk_error_allowance,
    );
}
