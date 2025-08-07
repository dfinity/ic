use std::str::FromStr;
use std::time::Duration;

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
        vector_vm::HasVectorTargets,
    },
    retry_with_msg,
    util::block_on,
};
use ic_types::{hostos_version::HostosVersion, ReplicaVersion};
use reqwest::Client;

use slog::info;

mod util;
use util::{
    check_hostos_version, elect_guestos_version, elect_hostos_version,
    get_blessed_guestos_versions, get_host_boot_id, get_unassigned_nodes_config,
    setup_nested_vm_group, simple_setup_nested_vm_group, start_nested_vm_group,
    update_nodes_hostos_version, update_unassigned_nodes, wait_for_expected_guest_version,
    wait_for_guest_version,
};

use anyhow::bail;

const HOST_VM_NAME: &str = "host-1";
const FOUR_VM_NAMES: [&str; 4] = ["host-1", "host-2", "host-3", "host-4"];

const NODE_REGISTRATION_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const NODE_REGISTRATION_BACKOFF: Duration = Duration::from_secs(5);

/// Setup the basic IC infrastructure (testnet, NNS, gateway)
fn setup_ic_infrastructure(env: &TestEnv) {
    let principal =
        PrincipalId::from_str("7532g-cd7sa-3eaay-weltl-purxe-qliyt-hfuto-364ru-b3dsz-kw5uz-kqe")
            .unwrap();

    // Setup "testnet"
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .with_api_boundary_nodes(1)
        .with_node_provider(principal)
        .with_node_operator(principal)
        .setup_and_start(env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());

    IcGatewayVm::new(IC_GATEWAY_VM_NAME)
        .start(env)
        .expect("failed to setup ic-gateway");
}

/// Setup vector targets for a single VM
fn setup_vector_targets_for_vm(env: &TestEnv, vm_name: &str) {
    let vm = env
        .get_nested_vm(vm_name)
        .unwrap_or_else(|e| panic!("Expected nested vm {vm_name} to exist, but got error: {e:?}"));

    let network = vm.get_nested_network().unwrap();

    for (job, ip) in [
        ("node_exporter", network.guest_ip),
        ("host_node_exporter", network.host_ip),
    ] {
        env.add_custom_vector_target(
            format!("{vm_name}-{job}"),
            ip.into(),
            Some(
                [("job", job)]
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            ),
        )
        .unwrap();
    }
}

/// Prepare the environment for nested tests.
/// SetupOS -> HostOS -> GuestOS
pub fn config(env: TestEnv) {
    setup_ic_infrastructure(&env);
    setup_nested_vm_group(env.clone(), &[HOST_VM_NAME]);
    setup_vector_targets_for_vm(&env, HOST_VM_NAME);
}
/// Minimal setup that only creates a nested VM without any IC infrastructure.
/// This is much faster than the full config() setup.
pub fn simple_config(env: TestEnv) {
    simple_setup_nested_vm_group(env.clone(), &[HOST_VM_NAME]);
}

/// Prepare the environment for nested tests with four nested VMs.
/// SetupOS -> HostOS -> GuestOS (x4)
pub fn config_four_vms(env: TestEnv) {
    setup_ic_infrastructure(&env);
    setup_nested_vm_group(env.clone(), &FOUR_VM_NAMES);

    for vm_name in FOUR_VM_NAMES {
        setup_vector_targets_for_vm(&env, vm_name);
    }
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

    start_nested_vm_group(env.clone());

    // Assert that the GuestOS was started with direct kernel boot.
    let guest_kernel_cmdline = env
        .get_nested_vm(HOST_VM_NAME)
        .expect("Unable to find HostOS node.")
        .get_guest_ssh()
        .unwrap()
        .block_on_bash_script("cat /proc/cmdline")
        .expect("Could not read /proc/cmdline from GuestOS");
    assert!(
        guest_kernel_cmdline.contains("initrd=initrd"),
        "GuestOS kernel command line does not contain 'initrd=initrd'. This is likely caused by \
         the guest not being started with direct kernel boot but rather with the GRUB \
         bootloader. guest_kernel_cmdline: '{guest_kernel_cmdline}'"
    );

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

/// Test that all four VMs can register with the network successfully.
pub fn nns_recovery_test(env: TestEnv) {
    let logger = env.logger();

    let initial_topology = block_on(
        env.topology_snapshot()
            .block_for_min_registry_version(ic_types::RegistryVersion::from(1)),
    )
    .unwrap();

    // Check that there are initially no unassigned nodes.
    let num_unassigned_nodes = initial_topology.unassigned_nodes().count();
    assert_eq!(num_unassigned_nodes, 0);

    start_nested_vm_group(env.clone());

    info!(logger, "Waiting for all four nodes to join ...");

    // Wait for all four nodes to register by repeatedly waiting for registry updates
    // and checking if we have 4 unassigned nodes
    retry_with_msg!(
        "Waiting for all four nodes to register and appear as unassigned nodes",
        logger.clone(),
        NODE_REGISTRATION_TIMEOUT,
        NODE_REGISTRATION_BACKOFF,
        || {
            // Wait for a newer registry version to be available
            let new_topology = block_on(
                initial_topology.block_for_newer_registry_version_within_duration(
                    Duration::from_secs(60), // Shorter timeout for each individual check
                    Duration::from_secs(2),
                ),
            )?;

            let num_unassigned_nodes = new_topology.unassigned_nodes().count();
            if num_unassigned_nodes == 4 {
                info!(logger, "SUCCESS: All four nodes have registered");
                Ok(())
            } else {
                bail!(
                    "Expected 4 unassigned nodes, but found {}",
                    num_unassigned_nodes
                )
            }
        }
    )
    .unwrap();
}

/// Upgrade each HostOS VM to the target version, and verify that each is
/// healthy before and after the upgrade.
pub fn upgrade_hostos(env: TestEnv) {
    let logger = env.logger();

    let target_version_str = get_hostos_update_img_version().unwrap();
    let target_version =
        HostosVersion::try_from(target_version_str.trim()).expect("Invalid target hostos version");

    let update_image_url =
        get_hostos_update_img_url().expect("Invalid target hostos update image URL");
    info!(logger, "HostOS update image URL: '{}'", update_image_url);
    let update_image_sha256 = get_hostos_update_img_sha256().unwrap();

    let initial_topology = env.topology_snapshot();
    start_nested_vm_group(env.clone());
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
        Duration::from_secs(7 * 60), // long wait for hostos upgrade to apply and reboot
        Duration::from_secs(5),
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

/// Test the guestos-recovery-upgrader component: tests upgrading the GuestOS
/// from the HostOS based on injected version/hash boot parameters.
pub fn recovery_upgrader_test(env: TestEnv) {
    let logger = env.logger();

    start_nested_vm_group(env.clone());

    let host = env
        .get_nested_vm(HOST_VM_NAME)
        .expect("Unable to find HostOS node.");
    let guest_ipv6 = host
        .get_nested_network()
        .expect("Unable to get nested network")
        .guest_ip;

    block_on(async {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .expect("Failed to build HTTP client");

        let original_version = wait_for_guest_version(
            &client,
            &guest_ipv6,
            &logger,
            Duration::from_secs(10 * 60), // long wait for setupOS to install
            Duration::from_secs(5),
        )
        .await
        .expect("guest didn't come up as expected");

        info!(logger, "Retrieving the current boot ID from the host before we update boot_args so we can determine when it rebooted...");
        let host_boot_id_pre_reboot = get_host_boot_id(&host);
        info!(
            logger,
            "Host boot ID pre reboot: '{}'", host_boot_id_pre_reboot
        );

        info!(logger, "Checking current boot_args file content");
        let current_boot_args = host
            .block_on_bash_script("cat /boot/boot_args")
            .expect("Failed to read /boot/boot_args file");
        info!(logger, "Current boot_args content:\n{}", current_boot_args);

        let target_version =
            get_guestos_update_img_version().expect("Failed to get target guestos version");
        let target_short_hash =
            &get_guestos_update_img_sha256().expect("Failed to get target guestos hash")[..6]; // node providers only expected to input the first 6 characters of the hash

        info!(
            logger,
            "Using target version: {} and short hash: {}", target_version, target_short_hash
        );

        info!(
            logger,
            "Remounting /boot as read-write and updating boot_args file"
        );
        let boot_args_command = format!(
            "sudo mount -o remount,rw /boot && sudo sed -i 's/\\(BOOT_ARGS_A=\".*\\)enforcing=0\"/\\1enforcing=0 recovery=1 version={} hash={}\"/' /boot/boot_args && sudo mount -o remount,ro /boot",
            target_version, target_short_hash
        );
        host.block_on_bash_script(&boot_args_command)
            .expect("Failed to update boot_args file");
        info!(logger, "Boot_args file updated successfully.");

        info!(logger, "Verifying boot_args file contents");
        let updated_boot_args = host
            .block_on_bash_script("cat /boot/boot_args")
            .expect("Failed to read updated /boot/boot_args file");
        info!(logger, "Updated boot_args content:\n{}", updated_boot_args);

        info!(logger, "Rebooting the host");
        host.block_on_bash_script("sudo reboot")
            .expect("Failed to send reboot command (connection may be terminated by reboot)");

        info!(logger, "Waiting for host to reboot...");

        retry_with_msg!(
            format!(
                "Waiting until the host's boot ID changes from its pre reboot value of '{}'",
                host_boot_id_pre_reboot
            ),
            logger.clone(),
            Duration::from_secs(5 * 60),
            Duration::from_secs(5),
            || {
                let host_boot_id = get_host_boot_id(&host);
                if host_boot_id != host_boot_id_pre_reboot {
                    info!(
                        logger,
                        "Host boot ID changed from '{}' to '{}'",
                        host_boot_id_pre_reboot,
                        host_boot_id
                    );
                    Ok(())
                } else {
                    bail!("Host boot ID is still '{}'", host_boot_id_pre_reboot)
                }
            }
        )
        .unwrap();

        let new_version = wait_for_guest_version(
            &client,
            &guest_ipv6,
            &logger,
            Duration::from_secs(5 * 60),
            Duration::from_secs(5),
        )
        .await
        .expect("guest didn't come up as expected");

        assert!(new_version != original_version);
    });
}

/// Upgrade unassigned guestOS VMs to the target version, and verify that each one
/// is healthy before and after the upgrade.
pub fn upgrade_guestos(env: TestEnv) {
    let logger = env.logger();

    // start the nested VM and wait for it to join the network
    let initial_topology = env.topology_snapshot();
    start_nested_vm_group(env.clone());
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

        let original_version = get_setupos_img_version().expect("Failed to find initial version");
        info!(logger, "Original GuestOS version: {}", original_version);

        // determine new GuestOS version
        let upgrade_url = get_guestos_update_img_url()
            .expect("no image URL")
            .to_string();
        info!(logger, "GuestOS upgrade image URL: {}", upgrade_url);

        let target_version_str =
            get_guestos_update_img_version().expect("Failed to get target replica version");
        let target_version = ReplicaVersion::try_from(target_version_str.as_str()).unwrap();
        info!(logger, "Target replica version: {}", target_version);

        let sha256 = get_guestos_update_img_sha256().expect("no SHA256 hash");
        info!(logger, "Update image SHA256: {}", sha256);

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
        elect_guestos_version(&nns_node, target_version.clone(), sha256, vec![upgrade_url]).await;

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
            &target_version_str,
            &logger,
            Duration::from_secs(7 * 60), // Long wait for GuestOS upgrade to apply and reboot
            Duration::from_secs(5),
        )
        .await
        .expect("guest failed to upgrade");
    });
}
