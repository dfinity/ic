/* tag::catalog[]

Title:: Nodes can rejoin a subnet under load

Runbook::
. setup the testnet of 3f + 1 nodes
. pick a random node and install the universal canister through it
. install some state sync test canisters through it
. expand the heap of all canisters to `canister_size_gib` * 1 GiB
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

use anyhow::Result;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{
    AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, Subnet, VmResources,
};
use ic_system_test_driver::driver::pot_dsl::{PotSetupFn, SysTestFn};
use ic_system_test_driver::driver::prometheus_vm::{HasPrometheus, PrometheusVm};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::block_on;
use ic_types::Height;
use rejoin_test_lib::rejoin_test_large_state;
use std::time::Duration;

const PER_TASK_TIMEOUT: Duration = Duration::from_secs(3600 * 2);
const OVERALL_TIMEOUT: Duration = Duration::from_secs(3600 * 2);
const NUM_NODES: usize = 4;

// Increasing the total size of all canisters results in a more rigorous test, but will also increase state sync completion time.
// When adjusting canister size in manual test runs, it is recommended to also increase retry timeout and backoff values accordingly.
const CANISTER_SIZE_GIB: u64 = 2;
const NUM_CANISTERS: usize = 8;

fn main() -> Result<()> {
    let config = Config::new(NUM_NODES, CANISTER_SIZE_GIB, NUM_CANISTERS);
    let test = config.clone().test();
    SystemTestGroup::new()
        .with_setup(config.build())
        .add_test(systest!(test))
        .with_timeout_per_test(PER_TASK_TIMEOUT)
        .with_overall_timeout(OVERALL_TIMEOUT)
        .execute_from_args()?;
    Ok(())
}

const DKG_INTERVAL: u64 = 99;

#[derive(Clone, Debug)]
pub struct Config {
    nodes_count: usize,
    canister_size_gib: u64,
    num_canisters: usize,
}

impl Config {
    pub fn new(nodes_count: usize, canister_size_gib: u64, num_canisters: usize) -> Config {
        Config {
            nodes_count,
            canister_size_gib,
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
    PrometheusVm::default()
        .start(&env)
        .expect("failed to start prometheus VM");

    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_default_vm_resources(VmResources {
                    vcpus: None,
                    memory_kibibytes: Some(AmountOfMemoryKiB::new(
                        (24 + config.canister_size_gib * config.num_canisters as u64) * 1024 * 1024,
                    )),
                    boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(
                        100 + 2 * config.canister_size_gib * config.num_canisters as u64,
                    )),
                })
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .with_unit_delay(Duration::from_millis(200))
                .with_initial_notary_delay(Duration::from_millis(200))
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
        config.canister_size_gib,
        config.num_canisters,
        DKG_INTERVAL,
        rejoin_node.clone(),
        agent_node.clone(),
        nodes.take(allowed_failures),
    )
    .await;
}
