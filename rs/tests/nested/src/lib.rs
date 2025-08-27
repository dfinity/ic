use std::str::FromStr;
use std::time::Duration;

use anyhow::Result;
use canister_test::PrincipalId;
use futures::future::join_all;
use ic_consensus_system_test_utils::{
    impersonate_upstreams,
    rw_message::{
        can_read_msg, cannot_store_msg, cert_state_makes_progress_with_retries,
        install_nns_and_check_progress, store_message,
    },
    set_sandbox_env_vars,
    ssh_access::{
        get_updatesubnetpayload_with_keys, update_subnet_record,
        wait_until_authentication_is_granted, AuthMean,
    },
    upgrade::assert_assigned_replica_version,
};
use ic_recovery::{
    get_node_metrics,
    nns_recovery_same_nodes::{NNSRecoverySameNodes, NNSRecoverySameNodesArgs},
    util::DataLocation,
    RecoveryArgs,
};
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        constants::SSH_USERNAME,
        driver_setup::{SSH_AUTHORIZED_PRIV_KEYS_DIR, SSH_AUTHORIZED_PUB_KEYS_DIR},
        ic::{InternetComputer, Subnet},
        ic_gateway_vm::{IcGatewayVm, IC_GATEWAY_VM_NAME},
        nested::NestedVms,
        test_env::TestEnv,
        test_env_api::*,
        vector_vm::HasVectorTargets,
    },
    nns::change_subnet_membership,
    retry_with_msg, retry_with_msg_async,
    util::block_on,
};
use ic_types::Height;
use rand::seq::SliceRandom;
use reqwest::Client;
use sha2::{Digest, Sha256};
use slog::{info, Logger};

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

fn get_host_vm_names(num_hosts: usize) -> Vec<String> {
    (1..=num_hosts).map(|i| format!("host-{}", i)).collect()
}

const NODE_REGISTRATION_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const NODE_REGISTRATION_BACKOFF: Duration = Duration::from_secs(5);

/// Setup the basic IC infrastructure (testnet, NNS, gateway)
fn setup_ic_infrastructure(env: &TestEnv, dkg_interval: Option<u64>) {
    let principal =
        PrincipalId::from_str("7532g-cd7sa-3eaay-weltl-purxe-qliyt-hfuto-364ru-b3dsz-kw5uz-kqe")
            .unwrap();

    // Setup "testnet"
    let mut subnet = Subnet::fast_single_node(SubnetType::System);
    if let Some(dkg_interval) = dkg_interval {
        subnet = subnet.with_dkg_interval_length(Height::from(dkg_interval));
    }
    InternetComputer::new()
        .add_subnet(subnet)
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

/// Asserts that SetupOS and initial NNS GuestOS image versions match.
/// Only checks if both functions return ReplicaVersion successfully.
/// NOTE: If you want to create a new test with conflicting versions, add a
/// field to override this check and, in your test, account for the fact that
/// after registration, the deployed node will upgrade to the NNS GuestOS version.
fn assert_version_compatibility() {
    let setupos_version = get_setupos_img_version();
    let guestos_version = get_guestos_img_version();

    if setupos_version != guestos_version {
        panic!(
            "Version mismatch detected: SetupOS version '{setupos_version}' does not match GuestOS version '{guestos_version}'. If you want to create a test with different versions, add a field to override this check."
        );
    }
}

/// Prepare the environment for nested tests.
/// SetupOS -> HostOS -> GuestOS (x num_hosts)
pub fn config(env: TestEnv, num_hosts: usize, dkg_interval: Option<u64>) {
    assert_version_compatibility();

    setup_ic_infrastructure(&env, dkg_interval);
    let host_vm_names = get_host_vm_names(num_hosts);
    let host_vm_names_refs: Vec<&str> = host_vm_names.iter().map(|s| s.as_str()).collect();
    setup_nested_vm_group(env.clone(), &host_vm_names_refs);

    for vm_name in &host_vm_names {
        setup_vector_targets_for_vm(&env, vm_name);
    }
}

/// Minimal setup that only creates a nested VM without any IC infrastructure.
/// This is much faster than the full config() setup.
pub fn simple_config(env: TestEnv) {
    simple_setup_nested_vm_group(env.clone(), &[HOST_VM_NAME]);
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
    info!(logger, "The node successfully came up and registered ...");

    let num_unassigned_nodes = new_topology.unassigned_nodes().count();
    assert_eq!(num_unassigned_nodes, 1);
}

/// nns_recovery_test uses four nodes, which is the minimum subnet size that satisfies 3f+1 for f=1
pub const SUBNET_SIZE: usize = 4;
/// nns_recovery_test uses a DKG interval of 9, which is large enough for a subnet of that size and
/// as small as possible to keep the test runtime low
pub const DKG_INTERVAL: u64 = 9;
/// nns_recovery_test's RECOVERY_GUESTOS_IMG_VERSION variable is a placeholder for the actual
/// version of the recovery GuestOS image, that Node Providers would use as input to
/// guestos-recovery-upgrader
pub const RECOVERY_GUESTOS_IMG_VERSION: &str = "RECOVERY_VERSION";

async fn overwrite_expected_recovery_hash<T>(node: &T, artifacts_hash: &str) -> Result<String>
where
    T: SshSession + Sync,
{
    let expected_recovery_hash_path = "/opt/ic/share/expected_recovery_hash";
    // File-system is read-only, so we write the hash in a temporary file and replace the
    // original with a bind mount.
    let command = format!(
        r#"
            echo {artifacts_hash} | sudo tee -a /tmp/expected_recovery_hash > /dev/null

            sudo chown --reference=/tmp/expected_recovery_hash {expected_recovery_hash_path}
            sudo chmod --reference=/tmp/expected_recovery_hash {expected_recovery_hash_path}

            sudo mount --bind /tmp/expected_recovery_hash {expected_recovery_hash_path}
        "#,
    );

    node.block_on_bash_script_async(&command).await
}

async fn simulate_node_provider_action(
    logger: &Logger,
    env: &TestEnv,
    vm_name: &str,
    img_version: &str,
    img_short_hash: &str,
    artifacts_hash: &str,
) {
    let host = env.get_nested_vm(vm_name).unwrap();
    let host_boot_id_pre_reboot = get_host_boot_id(&host);

    // Trigger HostOS reboot and run guestos-recovery-upgrader
    info!(
        logger,
        "Remounting /boot as read-write, updating boot_args file and rebooting host {}", vm_name,
    );
    let boot_args_command = format!(
        "sudo mount -o remount,rw /boot && sudo sed -i 's/\\(BOOT_ARGS_A=\".*\\)enforcing=0\"/\\1enforcing=0 recovery=1 version={} hash={}\"/' /boot/boot_args && sudo mount -o remount,ro /boot && sudo reboot",
        &img_version, &img_short_hash
    );
    host.block_on_bash_script_async(&boot_args_command)
        .await
        .expect("Failed to update boot_args file and reboot host");

    // Wait for HostOS to reboot by checking that its boot ID changes
    retry_with_msg_async!(
        format!(
            "Waiting until the host's boot ID changes from its pre reboot value of '{}'",
            host_boot_id_pre_reboot
        ),
        &logger,
        Duration::from_secs(5 * 60),
        Duration::from_secs(5),
        || async {
            let host_boot_id = get_host_boot_id(&host);
            if host_boot_id != host_boot_id_pre_reboot {
                info!(
                    logger,
                    "Host boot ID changed from '{}' to '{}'", host_boot_id_pre_reboot, host_boot_id
                );
                Ok(())
            } else {
                bail!("Host boot ID is still '{}'", host_boot_id_pre_reboot)
            }
        }
    )
    .await
    .unwrap();

    // Once HostOS is back up, spoof its DNS such that it downloads the GuestOS image from the UVM
    let server_ipv6 = impersonate_upstreams::get_upstreams_uvm_ipv6(env);
    info!(
        logger,
        "Spoofing HostOS {} DNS to point the upstreams to the UVM at {}", vm_name, server_ipv6
    );
    impersonate_upstreams::spoof_node_dns_async(&host, &server_ipv6)
        .await
        .expect("Failed to spoof HostOS DNS");

    // Once GuestOS is launched, we still need to overwrite the expected recovery hash with the
    // correct one and spoof its DNS for the same reason as HostOS
    let guest = host.get_guest_ssh().unwrap();
    info!(
        logger,
        "Manually overwriting recovery engine with artifacts expected hash {}", artifacts_hash
    );
    overwrite_expected_recovery_hash(&guest, artifacts_hash)
        .await
        .expect("Failed to overwrite expected recovery hash");
    info!(
        logger,
        "Spoofing GuestOS DNS to point the upstreams to the UVM at {}", server_ipv6
    );
    impersonate_upstreams::spoof_node_dns_async(&guest, &server_ipv6)
        .await
        .expect("Failed to spoof GuestOS DNS");
}

pub fn nns_recovery_test(env: TestEnv) {
    let logger = env.logger();

    let recovery_img = std::fs::read(get_dependency_path(
        std::env::var("RECOVERY_GUESTOS_IMG_PATH")
            .expect("RECOVERY_GUESTOS_IMG_PATH environment variable not found"),
    ))
    .expect("Failed to read recovery GuestOS image");
    let recovery_img_hash = Sha256::digest(&recovery_img)
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    let initial_topology = block_on(
        env.topology_snapshot()
            .block_for_min_registry_version(ic_types::RegistryVersion::from(1)),
    )
    .unwrap();

    // Check that there are initially no unassigned nodes.
    let num_unassigned_nodes = initial_topology.unassigned_nodes().count();
    assert_eq!(num_unassigned_nodes, 0);

    start_nested_vm_group(env.clone());

    info!(logger, "Waiting for all nodes to join ...");

    // Wait for all nodes to register by repeatedly waiting for registry updates
    // and checking if we have the expected number of unassigned nodes
    let new_topology = retry_with_msg!(
        "Waiting for all nodes to register and appear as unassigned nodes",
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
            if num_unassigned_nodes == SUBNET_SIZE {
                info!(logger, "Success: All nodes have registered");
                Ok(new_topology)
            } else {
                bail!(
                    "Expected {} unassigned nodes, but found {}",
                    SUBNET_SIZE,
                    num_unassigned_nodes
                )
            }
        }
    )
    .unwrap();

    info!(logger, "Adding all nodes to the NNS subnet...");
    let nns_subnet = new_topology.root_subnet();
    let original_node = nns_subnet.nodes().next().unwrap();

    let new_node_ids: Vec<_> = new_topology.unassigned_nodes().map(|n| n.node_id).collect();
    block_on(change_subnet_membership(
        original_node.get_public_url(),
        nns_subnet.subnet_id,
        &new_node_ids,
        &[original_node.node_id],
    ))
    .expect("Failed to change subnet membership");

    info!(
        logger,
        "Waiting for new nodes to take over the NNS subnet..."
    );
    let new_topology = block_on(
        new_topology.block_for_newer_registry_version_within_duration(
            Duration::from_secs(60),
            Duration::from_secs(2),
        ),
    )
    .unwrap();

    let nns_subnet = new_topology.root_subnet();
    let num_nns_nodes = nns_subnet.nodes().count();
    assert_eq!(
        num_nns_nodes, SUBNET_SIZE,
        "NNS subnet should have {} nodes after removing the original node, but found {} nodes",
        SUBNET_SIZE, num_nns_nodes
    );
    for node in nns_subnet.nodes() {
        node.await_status_is_healthy().unwrap();
    }
    info!(logger, "Success: New nodes have taken over the NNS subnet");

    // Define faulty and healthy nodes, pick a DFINITY-owned node that is healthy
    let mut nns_nodes = nns_subnet.nodes().collect::<Vec<_>>();
    nns_nodes.shuffle(&mut rand::thread_rng());
    let f = (SUBNET_SIZE - 1) / 3;
    let faulty_nodes = &nns_nodes[..(f + 1)];
    let healthy_nodes = &nns_nodes[(f + 1)..];
    let dfinity_owned_node = healthy_nodes.first().unwrap();

    // Readiness wait: ensure the NNS subnet is healthy and making progress before writing
    info!(
        logger,
        "Waiting for NNS subnet to become healthy and make progress after membership changes..."
    );
    info!(
        logger,
        "Selected DFINITY-owned NNS node: {} ({:?})",
        dfinity_owned_node.node_id,
        dfinity_owned_node.get_ip_addr()
    );
    cert_state_makes_progress_with_retries(
        &dfinity_owned_node.get_public_url(),
        dfinity_owned_node.effective_canister_id(),
        &logger,
        Duration::from_secs(300),
        Duration::from_secs(10),
    );

    // Mirror production setup by granting backup access to all NNS nodes to a specific SSH key.
    // This is necessary as part of the `DownloadCertifications` step of the recovery to determine
    // the latest certified height of the subnet.
    info!(logger, "Update the registry with the backup key");
    let ssh_priv_key_path = env
        .get_path(SSH_AUTHORIZED_PRIV_KEYS_DIR)
        .join(SSH_USERNAME);
    let ssh_priv_key =
        std::fs::read_to_string(&ssh_priv_key_path).expect("Failed to read SSH private key");
    let ssh_pub_key_path = env.get_path(SSH_AUTHORIZED_PUB_KEYS_DIR).join(SSH_USERNAME);
    let ssh_pub_key =
        std::fs::read_to_string(&ssh_pub_key_path).expect("Failed to read SSH public key");
    let payload =
        get_updatesubnetpayload_with_keys(nns_subnet.subnet_id, None, Some(vec![ssh_pub_key]));
    block_on(update_subnet_record(
        dfinity_owned_node.get_public_url(),
        payload,
    ));
    let backup_mean = AuthMean::PrivateKey(ssh_priv_key);
    for node in nns_subnet.nodes() {
        info!(
            logger,
            "Waiting for authentication to be granted on node {} ({:?})",
            node.node_id,
            node.get_ip_addr()
        );
        wait_until_authentication_is_granted(&node.get_ip_addr(), "backup", &backup_mean);
    }

    info!(logger, "Ensure NNS subnet is functional");
    let msg = "subnet recovery works!";
    let app_can_id = store_message(
        &dfinity_owned_node.get_public_url(),
        dfinity_owned_node.effective_canister_id(),
        msg,
        &logger,
    );
    assert!(can_read_msg(
        &logger,
        &dfinity_owned_node.get_public_url(),
        app_can_id,
        msg
    ));
    info!(
        logger,
        "NNS is healthy - message stored and read successfully"
    );

    let ic_version = get_guestos_img_version();
    info!(logger, "IC_VERSION_ID: {:?}", &ic_version);
    // identifies the version of the replica after the recovery
    let working_version = get_guestos_update_img_version();

    let recovery_dir = get_dependency_path("rs/tests");
    let output_dir = env.get_path("recovery_output");
    set_sandbox_env_vars(recovery_dir.join("recovery/binaries"));

    let recovery_args = RecoveryArgs {
        dir: recovery_dir,
        nns_url: dfinity_owned_node.get_public_url(),
        replica_version: Some(ic_version),
        key_file: Some(ssh_priv_key_path.clone()),
        test_mode: true,
        skip_prompts: true,
        use_local_binaries: false,
    };

    // unlike during a production recovery using the CLI, here we already know all of parameters
    // ahead of time.
    let subnet_args = NNSRecoverySameNodesArgs {
        subnet_id: nns_subnet.subnet_id,
        upgrade_version: Some(working_version.clone()),
        replay_until_height: None, // We will set this after breaking the subnet, see below
        upgrade_image_url: Some(get_guestos_update_img_url()),
        upgrade_image_hash: Some(get_guestos_update_img_sha256()),
        download_node: Some(dfinity_owned_node.get_ip_addr()),
        upload_method: Some(DataLocation::Remote(dfinity_owned_node.get_ip_addr())),
        backup_key_file: Some(ssh_priv_key_path),
        output_dir: Some(output_dir.clone()),
        next_step: None,
    };

    let mut subnet_recovery_tool =
        NNSRecoverySameNodes::new(logger.clone(), recovery_args, subnet_args);

    // Break f+1 nodes by SSHing into them and breaking the replica binary.
    info!(
        logger,
        "Breaking the NNS subnet by breaking the replica binary on f+1={} nodes",
        f + 1
    );
    let ssh_command =
        "sudo mount --bind /bin/false /opt/ic/bin/replica && sudo systemctl restart ic-replica";
    for node in faulty_nodes {
        info!(
            logger,
            "Breaking the replica on node {} ({:?})...",
            node.node_id,
            node.get_ip_addr()
        );

        node.block_on_bash_script(ssh_command).unwrap_or_else(|_| {
            panic!(
                "SSH command failed on node {} ({:?})",
                node.node_id,
                node.get_ip_addr()
            )
        });
    }

    if let Some(healthy) = healthy_nodes.first() {
        info!(logger, "Ensure a healthy node still works in read mode");
        assert!(can_read_msg(
            &logger,
            &healthy.get_public_url(),
            app_can_id,
            msg
        ));
    }
    info!(
        logger,
        "Ensure the subnet does not work in write mode anymore"
    );
    assert!(cannot_store_msg(
        logger.clone(),
        &dfinity_owned_node.get_public_url(),
        app_can_id,
        msg
    ));
    info!(
        logger,
        "Success: Subnet is broken - cannot store new messages"
    );

    // Replay until highest certification share height across all healthy nodes
    // In a real recovery, this will be determined by the recovery coordinator
    subnet_recovery_tool.params.replay_until_height = Some(
        healthy_nodes
            .iter()
            .map(|n| {
                block_on(get_node_metrics(&logger, &n.get_ip_addr()))
                    .expect("Missing metrics for node")
                    .certification_share_height
            })
            .max()
            .unwrap()
            .get(),
    );

    info!(logger, "Starting recovery tool",);

    // go over all steps of the NNS recovery
    for (step_type, step) in subnet_recovery_tool {
        info!(logger, "Next step: {:?}", step_type);

        info!(logger, "{}", step.descr());
        step.exec()
            .unwrap_or_else(|e| panic!("Execution of step {:?} failed: {}", step_type, e));
    }
    info!(
        logger,
        "Recovery coordinator successfully went through all steps of the recovery tool"
    );

    info!(logger, "Setup UVM to serve recovery artifacts");
    let artifacts = std::fs::read(output_dir.join("recovery.tar.zst")).unwrap();
    let artifacts_hash = std::fs::read_to_string(output_dir.join("recovery.tar.zst.sha256"))
        .unwrap()
        .trim()
        .to_string();
    impersonate_upstreams::uvm_serve_recovery_artifacts(&env, artifacts, &artifacts_hash)
        .expect("Failed to serve recovery artifacts from UVM");

    info!(logger, "Setup UVM to serve recovery-dev GuestOS image");
    impersonate_upstreams::uvm_serve_guestos_image(
        &env,
        recovery_img,
        RECOVERY_GUESTOS_IMG_VERSION,
    )
    .unwrap();

    info!(logger, "Simulate node provider action on 2f+1 nodes");
    block_on(join_all(
        get_host_vm_names(SUBNET_SIZE)
            .choose_multiple(&mut rand::thread_rng(), 2 * f + 1)
            .map(|vm_name| {
                simulate_node_provider_action(
                    &logger,
                    &env,
                    vm_name,
                    RECOVERY_GUESTOS_IMG_VERSION,
                    &recovery_img_hash[..6],
                    &artifacts_hash,
                )
            }),
    ));

    info!(logger, "Wait for state sync to complete");
    cert_state_makes_progress_with_retries(
        &dfinity_owned_node.get_public_url(),
        dfinity_owned_node.effective_canister_id(),
        &logger,
        secs(600),
        secs(10),
    );

    info!(logger, "Ensure the old message is still readable");
    assert!(can_read_msg(
        &logger,
        &dfinity_owned_node.get_public_url(),
        app_can_id,
        msg
    ));

    info!(logger, "Ensure the subnet uses the new replica version");
    let final_topology = block_on(new_topology.block_for_newer_registry_version())
        .expect("Could not obtain updated registry.");
    let dfinity_owned_node = final_topology
        .subnets()
        .flat_map(|s| s.nodes())
        .find(|n| n.node_id == dfinity_owned_node.node_id)
        .expect("Could not find upload_node in updated registry.");
    assert_assigned_replica_version(&dfinity_owned_node, &working_version, env.logger());

    info!(
        logger,
        "Ensure that the subnet is accepting updates after the recovery"
    );
    let new_msg = "subnet recovery still works!";
    let new_app_can_id = store_message(
        &dfinity_owned_node.get_public_url(),
        dfinity_owned_node.effective_canister_id(),
        new_msg,
        &logger,
    );
    assert!(can_read_msg(
        &logger,
        &dfinity_owned_node.get_public_url(),
        new_app_can_id,
        new_msg
    ));
}

/// Upgrade each HostOS VM to the target version, and verify that each is
/// healthy before and after the upgrade.
pub fn upgrade_hostos(env: TestEnv) {
    let logger = env.logger();

    let target_version = get_hostos_update_img_version();

    let update_image_url = get_hostos_update_img_url();
    info!(logger, "HostOS update image URL: '{}'", update_image_url);
    let update_image_sha256 = get_hostos_update_img_sha256();

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

        let target_version = get_guestos_update_img_version();
        let target_short_hash = &get_guestos_update_img_sha256()[..6]; // node providers only expected to input the first 6 characters of the hash

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
