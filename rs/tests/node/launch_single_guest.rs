use anyhow::Result;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::InternetComputer,
        test_env::TestEnv,
        test_env_api::{HasTopologySnapshot, IcNodeContainer, SshSession},
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
        .add_fast_single_node_subnet(SubnetType::System)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

fn test(env: TestEnv) {
    let node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .expect("Unable to find GuestOS node.");

    info!(env.logger(), "Waiting for GuestOS to launch");
    node.await_can_login_as_admin_via_ssh().unwrap();
    info!(env.logger(), "GuestOS has launched!");
}
