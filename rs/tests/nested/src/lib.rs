use std::str::FromStr;
use std::time::Duration;

use url::Url;

use canister_test::PrincipalId;
use ic_consensus_system_test_utils::rw_message::install_nns_and_check_progress;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        ic::InternetComputer,
        ic_gateway_vm::{IcGatewayVm, IC_GATEWAY_VM_NAME},
        nested::NestedVms,
        test_env::TestEnv,
        test_env_api::*,
    },
    retry_with_msg, retry_with_msg_async,
    util::block_on,
};
use ic_types::{hostos_version::HostosVersion, ReplicaVersion};
use reqwest::Client;

use slog::info;

mod util;
use util::{
    check_guestos_version, check_guestos_version, check_hostos_version, elect_guestos_version,
    elect_hostos_version, get_blessed_guestos_versions, get_unassigned_nodes_config,
    setup_nested_vm, start_nested_vm, update_nodes_hostos_version, update_unassigned_nodes,
};

use anyhow::bail;

const HOST_VM_NAME: &str = "host-1";

const NODE_REGISTRATION_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const NODE_REGISTRATION_BACKOFF: Duration = Duration::from_secs(5);

/// Prepare the environment for nested tests.
/// SetupOS -> HostOS -> GuestOS
pub fn config(env: TestEnv, mainnet_config: bool) {
    let principal =
        PrincipalId::from_str("7532g-cd7sa-3eaay-weltl-purxe-qliyt-hfuto-364ru-b3dsz-kw5uz-kqe")
            .unwrap();

    // Setup "testnet"
    let mut ic = InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .with_api_boundary_nodes(1)
        .with_node_provider(principal)
        .with_node_operator(principal);

    if mainnet_config {
        ic = ic.with_mainnet_config();
    }

    ic.setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());

    IcGatewayVm::new(IC_GATEWAY_VM_NAME)
        .start(&env)
        .expect("failed to setup ic-gateway");

    setup_nested_vm(env, HOST_VM_NAME);
}

/// Allow the nested GuestOS to install and launch, and check that it can
/// successfully join the testnet.
pub fn registration(env: TestEnv) {
    let logger = env.logger();

    let initial_topology = block_on(
        env.topology_snapshot()
            .block_for_min_registry_version(ic_types::RegistryVersion::from(1)),
    )
    .unwrap();

    // Check that there are initially no unassigned nodes.
    let num_unassigned_nodes = initial_topology.unassigned_nodes().count();
    assert_eq!(num_unassigned_nodes, 0);

    start_nested_vm(env);

    // If the node is able to join successfully, the registry will be updated,
    // and the new node ID will enter the unassigned pool.
    info!(logger, "Waiting for node to join ...");
    let new_topology = block_on(
        initial_topology.block_for_newer_registry_version_within_duration(
            NODE_REGISTRATION_TIMEOUT,
            NODE_REGISTRATION_BACKOFF,
        ),
    )
    .unwrap();
    let num_unassigned_nodes = new_topology.unassigned_nodes().count();
    assert_eq!(num_unassigned_nodes, 1);
}

/// Upgrade each HostOS VM to the target version, and verify that each is
/// healthy before and after the upgrade.
pub fn upgrade_hostos(env: TestEnv) {
    let logger = env.logger();

    let target_version_str = std::env::var("ENV_DEPS__HOSTOS_UPDATE_IMG_VERSION").unwrap();
    let target_version =
        HostosVersion::try_from(target_version_str.trim()).expect("Invalid mainnet hostos version");

    let update_image_url_str = std::env::var("ENV_DEPS__HOSTOS_UPDATE_IMG_URL").unwrap();
    info!(
        logger,
        "HostOS update image URL: '{}'", update_image_url_str
    );
    let update_image_url =
        Url::parse(update_image_url_str.trim()).expect("Invalid mainnet hostos update image URL");
    let update_image_sha256 = std::env::var("ENV_DEPS__HOSTOS_UPDATE_IMG_SHA").unwrap();

    let initial_topology = env.topology_snapshot();
    start_nested_vm(env.clone());
    info!(logger, "Waiting for node to join ...");
    let new_topology = block_on(
        initial_topology.block_for_newer_registry_version_within_duration(
            NODE_REGISTRATION_TIMEOUT,
            NODE_REGISTRATION_BACKOFF,
        ),
    )
    .unwrap();

    let host = env
        .get_nested_vm(HOST_VM_NAME)
        .expect("Unable to find HostOS node.");

    // Check version
    info!(
        logger,
        "Checking version via SSH on HostOS: '{}'",
        host.get_vm().expect("Unable to get HostOS VM.").ipv6
    );
    let original_version = check_hostos_version(&host);
    info!(logger, "Version found is: '{}'", original_version);

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

    info!(logger, "Retrieving the current boot ID from the host before we upgrade so we can determine when it rebooted post upgrade...");
    let retrieve_host_boot_id = || {
        host.block_on_bash_script("journalctl -q --list-boots | tail -n1 | awk '{print $2}'")
            .unwrap()
            .trim()
            .to_string()
    };
    let host_boot_id_pre_upgrade = retrieve_host_boot_id();
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
        Duration::from_secs(5 * 60),
        Duration::from_secs(5),
        || {
            let host_boot_id = retrieve_host_boot_id();
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

/// Test the recovery upgrader functionality on nested VMs.
/// This test verifies that the recovery upgrader can successfully upgrade
/// the system components in a nested VM environment.
pub fn recovery_upgrader_test(env: TestEnv) {
    let logger = env.logger();

    let initial_topology = block_on(
        env.topology_snapshot()
            .block_for_min_registry_version(ic_types::RegistryVersion::from(1)),
    )
    .unwrap();

    info!(logger, "Starting recovery upgrader test...");

    start_nested_vm(env.clone());

    // Wait for node to join the testnet
    info!(logger, "Waiting for node to join ...");
    let new_topology = block_on(
        initial_topology.block_for_newer_registry_version_within_duration(
            NODE_REGISTRATION_TIMEOUT,
            NODE_REGISTRATION_BACKOFF,
        ),
    )
    .unwrap();

    let host = env
        .get_nested_vm(HOST_VM_NAME)
        .expect("Unable to find GuestOS node.");

    // Check version
    info!(
        logger,
        "Checking version via SSH on GuestOS: '{}'",
        host.get_vm().expect("Unable to get GuestOS VM.").ipv6
    );
    let original_version = check_guestos_version(&host);
    info!(logger, "Version found is: '{}'", original_version);

    // info!(logger, "Retrieving the current boot ID from the host before we upgrade so we can determine when it rebooted post upgrade...");
    // let retrieve_host_boot_id = || {
    //     host.block_on_bash_script("journalctl -q --list-boots | tail -n1 | awk '{print $2}'")
    //         .unwrap()
    //         .trim()
    //         .to_string()
    // };
    // let host_boot_id_pre_upgrade = retrieve_host_boot_id();
    // info!(
    //     logger,
    //     "Host boot ID pre upgrade: '{}'", host_boot_id_pre_upgrade
    // );

    info!(logger, "Sleeping for 30 minutes...");
    std::thread::sleep(Duration::from_secs(30 * 60));
    info!(logger, "Sleep completed");

    // TODO: Add recovery upgrader specific test logic here

    info!(logger, "Waiting for the GuestOS upgrade to apply...");

    // Check the GuestOS version again after upgrade
    info!(
        logger,
        "Checking version via SSH on GuestOS: '{}'",
        host.get_vm().expect("Unable to get GuestOS VM.").ipv6
    );
    let new_version = check_guestos_version(&host);
    info!(logger, "Version found is: '{}'", new_version);

    assert!(new_version != original_version);

    info!(
        logger,
        "Recovery upgrader test setup complete - implement test logic"
    );
}

/// Upgrade unassigned guestOS VMs to the target version, and verify that each one
/// is healthy before and after the upgrade.
pub fn upgrade_guestos(env: TestEnv) {
    let logger = env.logger();

    // start the nested VM and wait for it to join the network
    let initial_topology = env.topology_snapshot();
    start_nested_vm(env.clone());
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

        // determine new GuestOS version
        let original_version = unassigned_nodes_config.replica_version.clone();
        let upgrade_url = get_ic_os_update_img_test_url()
            .expect("no image URL")
            .to_string();
        info!(logger, "GuestOS upgrade image URL: {}", upgrade_url);

        let target_version = format!("{}-test", original_version);
        let new_replica_version = ReplicaVersion::try_from(target_version.clone()).unwrap();
        info!(logger, "Target replica version: {}", new_replica_version);

        let sha256 = get_ic_os_update_img_test_sha256().expect("no SHA256 hash");
        info!(logger, "Update image SHA256: {}", sha256);

        // check that GuestOS is on the expected version (initial version)
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .expect("Failed to build HTTP client");

        retry_with_msg_async!(
            format!(
                "Waiting until the guest is on the right version '{}'",
                original_version
            ),
            &logger,
            Duration::from_secs(5 * 60),
            Duration::from_secs(5),
            || async {
                let current_version = check_guestos_version(&client, &guest_ipv6)
                    .await
                    .unwrap_or("unavaiblable".to_string());
                if current_version == original_version {
                    info!(logger, "Guest upgraded to '{}'", current_version);
                    Ok(())
                } else {
                    bail!("Guest is still on version '{}'", current_version)
                }
            }
        )
        .await
        .expect("guest didn't come up as expected");

        // elect the new GuestOS version (upgrade version)
        elect_guestos_version(
            &nns_node,
            new_replica_version.clone(),
            sha256,
            vec![upgrade_url],
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
        update_unassigned_nodes(&nns_node, &new_replica_version).await;

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
        retry_with_msg_async!(
            format!(
                "Waiting until the guest is on the right version '{}'",
                target_version
            ),
            &logger,
            Duration::from_secs(5 * 60),
            Duration::from_secs(5),
            || async {
                let current_version = check_guestos_version(&client, &guest_ipv6)
                    .await
                    .unwrap_or("unavaiblable".to_string());
                if current_version == target_version {
                    info!(logger, "Guest upgraded to '{}'", current_version);
                    Ok(())
                } else {
                    bail!("Guest is still on version '{}'", current_version)
                }
            }
        )
        .await
        .expect("guest failed to upgrade");
    });
}
