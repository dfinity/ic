/* tag::catalog[]
end::catalog[] */

use anyhow::Result;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        prometheus_vm::{HasPrometheus, PrometheusVm},
        simulate_network::{FixedNetworkSimulation, SimulateNetwork},
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer},
    },
    systest,
};
use ic_types::Height;
use std::time::Duration;

const INITIAL_NODES: usize = 1;
const TOTAL_NODES: usize = 13;

const BANDWIDTH_MBITS: u32 = 300; // artificial cap on bandwidth
const LATENCY: Duration = Duration::from_millis(150); // artificial added latency

const SIZE_LEVEL: usize = 8;
const NUM_CANISTERS: usize = 8;

fn setup(env: TestEnv) {
    PrometheusVm::default()
        .start(&env)
        .expect("failed to start prometheus VM");

    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(99))
                .with_unit_delay(Duration::from_millis(100))
                .with_initial_notary_delay(Duration::from_millis(100))
                .add_nodes(INITIAL_NODES),
        )
        .with_unassigned_nodes(TOTAL_NODES - INITIAL_NODES)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    let topology = env.topology_snapshot();
    topology.subnets().for_each(|subnet| {
        subnet.nodes().for_each(|node| {
            node.await_status_is_healthy()
                .expect("Nodes failed to come up healty")
        })
    });

    topology.unassigned_nodes().for_each(|node| {
        node.await_can_login_as_admin_via_ssh()
            .expect("Timeout while waiting for all unassigned nodes to be healthy");
    });

    topology
        .subnets()
        .next()
        .expect("Failed to retreive system subnet")
        .apply_network_settings(
            FixedNetworkSimulation::new()
                .with_latency(LATENCY)
                .with_bandwidth(BANDWIDTH_MBITS),
        );

    env.sync_with_prometheus();
}

fn test(env: TestEnv) {
    let logger = env.logger();

    todo!()
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}
