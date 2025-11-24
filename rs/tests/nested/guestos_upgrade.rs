use anyhow::Result;
use reqwest::Client;
use slog::info;
use std::time::Duration;

use ic_system_test_driver::{
    driver::{group::SystemTestGroup, nested::HasNestedVms, test_env::TestEnv, test_env_api::*},
    systest,
    util::block_on,
};

use nested::{HOST_VM_NAME, registration};

use nested::util::{
    NODE_UPGRADE_BACKOFF, NODE_UPGRADE_TIMEOUT, elect_guestos_version,
    get_blessed_guestos_versions, get_unassigned_nodes_config, try_logging_guestos_diagnostics,
    update_unassigned_nodes, wait_for_expected_guest_version,
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(nested::setup)
        .add_test(systest!(upgrade_guestos))
        .with_timeout_per_test(Duration::from_secs(30 * 60))
        .with_overall_timeout(Duration::from_secs(40 * 60))
        .execute_from_args()?;

    Ok(())
}

/// Upgrade unassigned guestOS VMs to the target version, and verify that each one
/// is healthy before and after the upgrade.
pub fn upgrade_guestos(env: TestEnv) {
    let logger = env.logger();

    // The original GuestOS version is the deployed version (i.e., the SetupOS image version).
    let original_version = get_setupos_img_version();
    let target_version = get_guestos_update_img_version();
    let upgrade_url = get_guestos_update_img_url().to_string();
    let sha256 = get_guestos_update_img_sha256();
    let guest_launch_measurements = get_guestos_launch_measurements();

    info!(logger, "Image configuration:");
    info!(logger, "  Original GuestOS version: {original_version}");
    info!(logger, "  Target GuestOS version: {target_version}");
    info!(logger, "  Upgrade image URL: {upgrade_url}");
    info!(logger, "  Upgrade image SHA256: {sha256}");

    registration(env.clone());

    let host = env
        .get_nested_vm(HOST_VM_NAME)
        .expect("Unable to find HostOS node.");

    let guest_ipv6 = host
        .get_nested_network()
        .expect("Unable to get nested network")
        .guest_ip;

    // choose a node from the NNS subnet to submit the proposals to
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();
    nns_node.await_status_is_healthy().unwrap();

    block_on(async {
        info!(
            logger,
            "Initial blessed versions: {:?}",
            get_blessed_guestos_versions(&nns_node).await
        );

        info!(
            logger,
            "Unassigned nodes config: {:?}",
            get_unassigned_nodes_config(&nns_node).await
        );

        // check that GuestOS is on the expected version (initial version)
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .expect("Failed to build HTTP client");

        wait_for_expected_guest_version(
            &client,
            &guest_ipv6,
            &original_version,
            &logger,
            Duration::from_secs(60),
            Duration::from_secs(5),
        )
        .await
        .expect("guest didn't come up as expected");

        // elect the target GuestOS version
        elect_guestos_version(
            &nns_node,
            &target_version,
            sha256,
            vec![upgrade_url],
            Some(guest_launch_measurements),
        )
        .await;

        info!(
            logger,
            "Updated blessed versions: {:?}",
            get_blessed_guestos_versions(&nns_node).await
        );

        update_unassigned_nodes(&nns_node, &target_version).await;

        info!(
            logger,
            "Unassigned nodes config: {:?}",
            get_unassigned_nodes_config(&nns_node).await
        );

        wait_for_expected_guest_version(
            &client,
            &guest_ipv6,
            &target_version,
            &logger,
            NODE_UPGRADE_TIMEOUT,
            NODE_UPGRADE_BACKOFF,
        )
        .await
        .expect("guest failed to upgrade");

        info!(logger, "Waiting for Orchestrator dashboard...");
        if let Err(e) = host.await_orchestrator_dashboard_accessible() {
            try_logging_guestos_diagnostics(&host, &logger);
            panic!("Orchestrator dashboard is not accessible: {e}");
        }
    });
}
