use anyhow::{Result, bail};
use slog::info;
use std::time::Duration;

use ic_system_test_driver::{
    driver::{group::SystemTestGroup, nested::HasNestedVms, test_env::TestEnv, test_env_api::*},
    retry_with_msg, systest,
    util::block_on,
};

use nested::HOST_VM_NAME;

use nested::util::{
    NODE_REGISTRATION_BACKOFF, NODE_REGISTRATION_TIMEOUT, NODE_UPGRADE_BACKOFF,
    NODE_UPGRADE_TIMEOUT, check_hostos_version, elect_hostos_version, get_host_boot_id,
    update_nodes_hostos_version,
};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(nested::setup)
        .add_test(systest!(upgrade_hostos))
        .with_timeout_per_test(Duration::from_secs(30 * 60))
        .with_overall_timeout(Duration::from_secs(40 * 60))
        .execute_from_args()?;

    Ok(())
}

/// Upgrade each HostOS VM to the target version, and verify that each is
/// healthy before and after the upgrade.
pub fn upgrade_hostos(env: TestEnv) {
    let logger = env.logger();

    // The original HostOS version is the deployed version (i.e., the SetupOS image version).
    let original_version = get_setupos_img_version();
    let target_version = get_hostos_update_img_version();
    let update_image_url = get_hostos_update_img_url();
    let update_image_sha256 = get_hostos_update_img_sha256();

    info!(logger, "Image configuration:");
    info!(logger, "  Original HostOS version: {}", original_version);
    info!(logger, "  Target HostOS version: {}", target_version);
    info!(logger, "  Update image URL: '{}'", update_image_url);
    info!(logger, "  Update image SHA256: {}", update_image_sha256);

    let initial_topology = env.topology_snapshot();
    info!(logger, "Waiting for node to join ...");
    let new_topology = block_on(
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

    // Check version
    info!(
        logger,
        "Checking version via SSH on HostOS: '{}'",
        host.get_vm().expect("Unable to get HostOS VM.").ipv6
    );
    assert_eq!(original_version, check_hostos_version(&host));

    let node_id = new_topology.unassigned_nodes().next().unwrap().node_id;

    // Elect target HostOS version
    info!(
        logger,
        "Electing target HostOS version '{target_version}' with sha256 '{update_image_sha256}' and upgrade url: '{update_image_url}'"
    );
    let nns_subnet = new_topology.root_subnet();
    let nns_node = nns_subnet.nodes().next().unwrap();
    block_on(elect_hostos_version(
        &nns_node,
        &target_version,
        &update_image_sha256,
        vec![update_image_url.to_string()],
    ));
    info!(logger, "Elected target HostOS version");

    info!(
        logger,
        "Retrieving the current boot ID from the host before we upgrade so we can determine when it rebooted post upgrade..."
    );
    let host_boot_id_pre_upgrade = get_host_boot_id(&host);
    info!(
        logger,
        "Host boot ID pre upgrade: '{}'", host_boot_id_pre_upgrade
    );

    info!(
        logger,
        "Upgrading node '{}' to '{}'", node_id, target_version
    );
    block_on(update_nodes_hostos_version(
        &nns_node,
        &target_version,
        vec![node_id],
    ));

    // The HostOS upgrade is applied with a reboot to the host machine.
    // Wait for the host to reboot before checking Orchestrator dashboard status
    info!(logger, "Waiting for the HostOS upgrade to apply...");

    retry_with_msg!(
        format!(
            "Waiting until the host's boot ID changes from its pre upgrade value of '{}'",
            host_boot_id_pre_upgrade
        ),
        logger.clone(),
        NODE_UPGRADE_TIMEOUT,
        NODE_UPGRADE_BACKOFF,
        || {
            let host_boot_id = get_host_boot_id(&host);
            if host_boot_id != host_boot_id_pre_upgrade {
                info!(
                    logger,
                    "Host boot ID changed from '{}' to '{}'",
                    host_boot_id_pre_upgrade,
                    host_boot_id
                );
                Ok(())
            } else {
                bail!("Host boot ID is still '{}'", host_boot_id_pre_upgrade)
            }
        }
    )
    .unwrap();

    info!(logger, "Waiting for Orchestrator dashboard...");
    host.await_orchestrator_dashboard_accessible().unwrap();

    // Check the HostOS version again after upgrade
    info!(
        logger,
        "Checking version via SSH on HostOS: '{}'",
        host.get_vm().expect("Unable to get HostOS VM.").ipv6
    );
    let new_version = check_hostos_version(&host);
    info!(logger, "Version found is: '{}'", new_version);

    assert!(new_version != original_version);
}
