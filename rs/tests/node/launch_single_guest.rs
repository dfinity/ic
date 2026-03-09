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
        .remove_all_metrics_to_check()
        .without_assert_no_replica_restarts()
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
    let log = env.logger();
    let node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .expect("Unable to find GuestOS node.");

    info!(log, "Waiting for GuestOS to launch");
    node.await_can_login_as_admin_via_ssh().unwrap();
    info!(log, "GuestOS has launched!");

    let failed_units = node
        .block_on_bash_script("systemctl list-units --failed --no-legend --no-pager")
        .expect("Failed to run systemctl list-units --failed on GuestOS");

    info!(log, "systemctl list-units --failed:\n{}", failed_units);

    assert!(
        failed_units.trim().is_empty(),
        "GuestOS has failed systemd units:\n{}",
        failed_units
    );

    info!(log, "No failed systemd units found.");
}
