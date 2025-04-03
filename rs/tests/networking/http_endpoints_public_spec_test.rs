/* tag::catalog[]
Title:: Basic HTTP requests from canisters

Goal:: Ensure simple HTTP requests can be made from canisters.

Runbook::
0. Create an IC with two subnets with one node each
1. Instanciate two universal canisters, one on each subnet
2. Run the specific spec tests


Success::
1. Received expected http response code as per specification

end::catalog[] */

use anyhow::{bail, Result};
use ic_http_endpoints_test_agent::*;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer},
    },
    systest,
};
use slog::info;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    info!(&env.logger(), "Checking readiness of all nodes...");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

fn test(env: TestEnv) {
    let logger = env.logger();

    let sys_subnet = env
        .topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::System)
        .expect("Failed to find system subnet");
    let sys_agent = sys_subnet.nodes().next().unwrap().build_default_agent();

    let app_subnet = env
        .topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("Failed to find app subnet");
    let app_agent = app_subnet.nodes().next().unwrap().build_default_agent();

    block_on(async {
        // TODO
    });
    todo!()
}
