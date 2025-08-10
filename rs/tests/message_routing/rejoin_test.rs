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

use anyhow::Result;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::pot_dsl::{PotSetupFn, SysTestFn};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::block_on;
use ic_types::Height;
use rejoin_test_lib::rejoin_test;
use std::fmt::Debug;
use std::time::Duration;

const NUM_NODES: usize = 4;

const DKG_INTERVAL: u64 = 14;
const NOTARY_DELAY: Duration = Duration::from_millis(100);

#[derive(Clone, Debug)]
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

fn main() -> Result<()> {
    let config = Config::new(NUM_NODES);
    let test = config.clone().test();
    SystemTestGroup::new()
        .with_setup(config.build())
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
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
