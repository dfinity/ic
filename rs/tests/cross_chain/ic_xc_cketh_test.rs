use anyhow::{anyhow, bail, Result};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{HasTopologySnapshot, IcNodeContainer, NnsCustomizations},
    },
    systest,
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup_with_system_and_application_subnets)
        .add_test(systest!(ic_xc_cketh_test))
        .execute_from_args()?;
    Ok(())
}

fn setup_with_system_and_application_subnets(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
        .setup_and_start(&env)
        .expect("Failed to setup IC under test");

    env.topology_snapshot()
        .subnets()
        .for_each(|subnet| subnet.await_all_nodes_healthy().unwrap());
}

fn ic_xc_cketh_test(env: TestEnv) {
    let logger = env.logger();
    let topology_snapshot = env.topology_snapshot();
}
