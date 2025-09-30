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

use nested::{HOST_VM_NAME, registration};

use nested::util::{
    NODE_UPGRADE_BACKOFF, NODE_UPGRADE_TIMEOUT, elect_guestos_version,
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
    registration(env.clone());

    let guest_ipv6 = env
        .get_nested_vm(HOST_VM_NAME)
        .expect("Unable to find HostOS node.")
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

        // The original GuestOS version is the deployed version (i.e., the SetupOS image version).
        let original_version = get_setupos_img_version();
        let target_version = get_guestos_update_img_version();
        let upgrade_url = get_guestos_update_img_url().to_string();
        let sha256 = get_guestos_update_img_sha256();
        let guest_launch_measurements = get_guestos_launch_measurements();

        // Log all image information together
        info!(logger, "Image configuration:");
        info!(logger, "  Original GuestOS version: {}", original_version);
        info!(logger, "  Target GuestOS version: {}", target_version);
        info!(logger, "  Upgrade image URL: {}", upgrade_url);
        info!(logger, "  Upgrade image SHA256: {}", sha256);

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
            guest_launch_measurements,
        )
        .await;

        // check that the registry was updated after blessing the target GuestOS version
        let reg_ver2 = registry_canister.get_latest_version().await.unwrap();
        info!(
            logger,
            "Registry version after blessing the upgrade version: {}", reg_ver2
        );
        assert!(reg_ver < reg_ver2);

        info!(
            logger,
            "Updated blessed versions: {:?}",
            get_blessed_guestos_versions(&nns_node).await
        );

        update_unassigned_nodes(&nns_node, &target_version).await;

        let reg_ver3 = registry_canister.get_latest_version().await.unwrap();
        info!(
            logger,
            "Registry version after updating the unassigned nodes: {}", reg_ver3
        );
        assert!(reg_ver2 < reg_ver3);

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
    });
}
