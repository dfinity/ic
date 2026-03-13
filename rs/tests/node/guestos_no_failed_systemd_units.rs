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
use std::time::Duration;

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

/// Wait for GuestOS nodes to be SSH-accessible and then assert that no systemd
/// units have failed on any of them.
fn check_no_failed_systemd_units(env: TestEnv) {
    let logger = env.logger();
    let topology = env.topology_snapshot();

    for node in topology.subnets().flat_map(|s| s.nodes()) {
        node.await_can_login_as_admin_via_ssh()
            .expect("Failed to establish SSH session to GuestOS node");

        let failed_units = node
            .block_on_bash_script("systemctl list-units --failed --no-legend --no-pager")
            .expect("Failed to run systemctl list-units --failed on GuestOS node");
        info!(
            logger,
            "Node {}: systemctl list-units --failed:\n{}", node.node_id, failed_units
        );
        assert!(
            failed_units.trim().is_empty(),
            "Node {} has failed systemd units:\n{}",
            node.node_id,
            failed_units
        );
    }
    info!(logger, "No failed systemd units found on any GuestOS node.");
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(check_no_failed_systemd_units))
        .with_timeout_per_test(Duration::from_secs(10 * 60))
        .with_overall_timeout(Duration::from_secs(20 * 60))
        .execute_from_args()?;

    Ok(())
}
