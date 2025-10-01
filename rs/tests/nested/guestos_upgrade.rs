use anyhow::Result;
use reqwest::Client;
use slog::info;
use std::time::Duration;

use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_system_test_driver::{
    driver::{group::SystemTestGroup, nested::HasNestedVms, test_env::TestEnv, test_env_api::*},
    systest,
    util::block_on,
};

use nested::HOST_VM_NAME;

use nested::util::{
    NODE_REGISTRATION_BACKOFF, NODE_REGISTRATION_TIMEOUT, elect_guestos_version,
    get_blessed_guestos_versions, get_unassigned_nodes_config, update_unassigned_nodes,
    wait_for_expected_guest_version,
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

    let initial_topology = env.topology_snapshot();
    info!(logger, "Waiting for node to join ...");
    block_on(
        initial_topology.block_for_newer_registry_version_within_duration(
            NODE_REGISTRATION_TIMEOUT,
            NODE_REGISTRATION_BACKOFF,
        ),
    )
    .unwrap();
    info!(logger, "The node successfully came up and registered ...");

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
        // initial parameters
        let registry_canister = RegistryCanister::new(vec![nns_node.get_public_url()]);
        let reg_ver = registry_canister.get_latest_version().await.unwrap();
        info!(logger, "Registry is currently at version: {}", reg_ver);

        let blessed_versions = get_blessed_guestos_versions(&nns_node).await;
        info!(logger, "Initial blessed versions: {:?}", blessed_versions);

        let unassigned_nodes_config = get_unassigned_nodes_config(&nns_node).await;
        info!(
            logger,
            "Unassigned nodes config: {:?}", unassigned_nodes_config
        );

        let original_version = get_setupos_img_version();
        info!(logger, "Original GuestOS version: {}", original_version);

        // determine new GuestOS version
        let upgrade_url = get_guestos_update_img_url().to_string();
        info!(logger, "GuestOS upgrade image URL: {}", upgrade_url);

        let target_version = get_guestos_update_img_version();
        info!(logger, "Target replica version: {}", target_version);

        let sha256 = get_guestos_update_img_sha256();
        info!(logger, "Update image SHA256: {}", sha256);

        let guest_launch_measurements = get_guestos_launch_measurements();

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
            Duration::from_secs(5 * 60),
            Duration::from_secs(5),
        )
        .await
        .expect("guest didn't come up as expected");

        // elect the new GuestOS version (upgrade version)
        elect_guestos_version(
            &nns_node,
            &target_version,
            sha256,
            vec![upgrade_url],
            guest_launch_measurements,
        )
        .await;

        // check that the registry was updated after blessing the new guestos version
        let reg_ver2 = registry_canister.get_latest_version().await.unwrap();
        info!(
            logger,
            "Registry version after blessing the upgrade version: {}", reg_ver2
        );
        assert!(reg_ver < reg_ver2);

        // check that the new guestOS version is indeed part of the blessed versions
        let blessed_versions = get_blessed_guestos_versions(&nns_node).await;
        info!(logger, "Updated blessed versions: {:?}", blessed_versions);

        // proposal to upgrade the unassigned nodes
        update_unassigned_nodes(&nns_node, &target_version).await;

        // check that the registry was updated after updating the unassigned nodes
        let reg_ver3 = registry_canister.get_latest_version().await.unwrap();
        info!(
            logger,
            "Registry version after updating the unassigned nodes: {}", reg_ver3
        );
        assert!(reg_ver2 < reg_ver3);

        // check that the unassigned nodes config was indeed updated
        let unassigned_nodes_config = get_unassigned_nodes_config(&nns_node).await;
        info!(
            logger,
            "Unassigned nodes config: {:?}", unassigned_nodes_config
        );

        // Check that GuestOS is on the expected version (upgrade version)
        wait_for_expected_guest_version(
            &client,
            &guest_ipv6,
            &target_version,
            &logger,
            Duration::from_secs(7 * 60), // Long wait for GuestOS upgrade to apply and reboot
            Duration::from_secs(5),
        )
        .await
        .expect("guest failed to upgrade");
    });
}
