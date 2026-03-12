use anyhow::Result;
use ic_system_test_driver::{
    driver::{group::SystemTestGroup, test_env::TestEnv, test_env_api::*},
    systest,
};
use slog::info;
use std::time::Duration;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(nested::setup)
        .with_teardown(nested::teardown)
        .add_test(systest!(check_no_failed_systemd_units))
        .with_timeout_per_test(Duration::from_secs(20 * 60))
        .with_overall_timeout(Duration::from_secs(30 * 60))
        .execute_from_args()?;

    Ok(())
}

/// Wait for GuestOS nodes to register and then assert that no systemd units
/// have failed on any of them.
fn check_no_failed_systemd_units(env: TestEnv) {
    let logger = env.logger();

    nested::registration(env.clone());

    let topology = env.topology_snapshot();
    for node in topology.unassigned_nodes() {
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
