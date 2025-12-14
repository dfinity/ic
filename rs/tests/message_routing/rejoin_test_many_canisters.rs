/* tag::catalog[]

Title:: Nodes can rejoin a subnet with many canisters

Runbook::
. setup the testnet of 3f + 1 nodes with f = 4 (like on mainnet)
. pick a random node and install the state sync test canister through it
. create 100,000 canisters via the state sync test canister
. pick another random node rejoin_node and kill that node
. wait for the subnet producing a CUP
. start the rejoin_node

Success::
.. if the rejoin_node catches up w.r.t. its certified height until the next CUP

end::catalog[] */

use anyhow::Result;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::farm::HostFeature;
use ic_system_test_driver::driver::ic::{
    AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources,
};
use ic_system_test_driver::driver::pot_dsl::{PotSetupFn, SysTestFn};
use ic_system_test_driver::driver::simulate_network::{FixedNetworkSimulation, SimulateNetwork};
use ic_system_test_driver::driver::prometheus_vm::{HasPrometheus, PrometheusVm};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{get_app_subnet_and_node, block_on};
use ic_types::Height;
use rejoin_test_lib::rejoin_test_many_canisters;
use std::time::Duration;

const PER_TASK_TIMEOUT: Duration = Duration::from_secs(3600);
const OVERALL_TIMEOUT: Duration = Duration::from_secs(3600);
const NUM_CANISTERS: usize = 100_000;

const NUM_NODES: usize = 13; // mainnet value
const DKG_INTERVAL: u64 = 499; // mainnet value

// Network parameters
const BANDWIDTH_MBITS: u32 = 300; // artificial cap on bandwidth
const LATENCY: Duration = Duration::from_millis(150); // artificial added latency
const NETWORK_SIMULATION: FixedNetworkSimulation = FixedNetworkSimulation::new()
    .with_latency(LATENCY)
    .with_bandwidth(BANDWIDTH_MBITS);

fn main() -> Result<()> {
    let config = Config::new(NUM_NODES, NUM_CANISTERS);
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
    num_canisters: usize,
}

impl Config {
    pub fn new(nodes_count: usize, num_canisters: usize) -> Config {
        Config {
            nodes_count,
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

fn setup(env: TestEnv, config: Config) {
    PrometheusVm::default()
        .start(&env)
        .expect("failed to start prometheus VM");

    // VM resources are as for the "large" testnet.
    let vm_resources = VmResources {
        vcpus: Some(NrOfVCPUs::new(64)),
        memory_kibibytes: Some(AmountOfMemoryKiB::new(480 << 20)),
        boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(2000)),
    };
    InternetComputer::new()
        .with_required_host_features(vec![HostFeature::Performance])
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_default_vm_resources(vm_resources)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(1),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_default_vm_resources(vm_resources)
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
/*
    let root_subnet = env.topology_snapshot().root_subnet();
    root_subnet.apply_network_settings(NETWORK_SIMULATION);
*/
    let topology_snapshot = env.topology_snapshot();
    let (app_subnet, _) = get_app_subnet_and_node(&topology_snapshot);

    //app_subnet.apply_network_settings(NETWORK_SIMULATION);
}

fn test(env: TestEnv, config: Config) {
    block_on(test_async(env, config));
}

async fn test_async(env: TestEnv, config: Config) {
    let topology_snapshot = env.topology_snapshot();
    let (app_subnet, _) = get_app_subnet_and_node(&topology_snapshot);

    let mut nodes = app_subnet.nodes();
    let agent_node = nodes.next().unwrap();
    let rejoin_node = nodes.next().unwrap();
    rejoin_test_many_canisters(
        env,
        config.num_canisters,
        DKG_INTERVAL,
        rejoin_node.clone(),
        agent_node.clone(),
    )
    .await;
}
