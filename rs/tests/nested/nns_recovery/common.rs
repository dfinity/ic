use std::path::Path;

use anyhow::bail;
use ic_consensus_system_test_subnet_recovery::utils::{
    AdminAndUserKeys, BACKUP_USERNAME, assert_subnet_is_broken, break_nodes,
    get_admin_keys_and_generate_backup_keys,
    local::{NNS_RECOVERY_OUTPUT_DIR_REMOTE_PATH, nns_subnet_recovery_same_nodes_local_cli_args},
    node_with_highest_certification_share_height, remote_recovery,
};
use ic_consensus_system_test_utils::{
    impersonate_upstreams,
    node::await_subnet_earliest_topology_version_with_retries,
    rw_message::store_message,
    set_sandbox_env_vars,
    ssh_access::{
        AuthMean, disable_ssh_access_to_node, get_updatesubnetpayload_with_keys,
        update_subnet_record, wait_until_authentication_is_granted,
    },
    subnet::assert_subnet_is_healthy,
    upgrade::bless_replica_version,
};
use ic_recovery::{
    RecoveryArgs,
    nns_recovery_same_nodes::{NNSRecoverySameNodes, NNSRecoverySameNodesArgs, StepType},
    steps::CreateNNSRecoveryTarStep,
    util::DataLocation,
};
use ic_system_test_driver::{
    driver::{
        constants::SSH_USERNAME,
        ic::{AmountOfMemoryKiB, NrOfVCPUs, VmResources},
        nested::{HasNestedVms, NestedNodes, NestedVm},
        test_env::TestEnv,
        test_env_api::*,
    },
    nns::change_subnet_membership,
    retry_with_msg_async,
    util::block_on,
};
use ic_types::ReplicaVersion;
use manual_guestos_recovery::recovery_utils::build_recovery_upgrader_run_command;
use nested::util::setup_ic_infrastructure;
use rand::seq::SliceRandom;
use slog::{Logger, info};
use tokio::task::JoinSet;

pub const NNS_RECOVERY_VM_RESOURCES: VmResources = VmResources {
    vcpus: Some(NrOfVCPUs::new(8)),
    memory_kibibytes: Some(AmountOfMemoryKiB::new(25165824)), // 24GiB
    boot_image_minimal_size_gibibytes: None,
};

/// 4 nodes is the minimum subnet size that satisfies 3f+1 for f=1
pub const SUBNET_SIZE: usize = 4;
/// DKG interval of 9 is large enough for a subnet of that size and as small as possible to keep the
/// test runtime low
pub const DKG_INTERVAL: u64 = 9;

/// 40 nodes and DKG interval of 499 are the production values for the NNS but 49 was chosen for
/// the DKG interval to make the test faster
pub const LARGE_SUBNET_SIZE: usize = 40;
pub const LARGE_DKG_INTERVAL: u64 = 49;

/// RECOVERY_GUESTOS_IMG_VERSION variable is a placeholder for the actual version of the recovery
/// GuestOS image, that Node Providers would use as input to guestos-recovery-upgrader.
pub const RECOVERY_GUESTOS_IMG_VERSION: &str = "RECOVERY_VERSION";

pub struct SetupConfig {
    pub impersonate_upstreams: bool,
    pub subnet_size: usize,
    pub dkg_interval: u64,
}

#[derive(Debug)]
pub struct TestConfig {
    pub local_recovery: bool,
    pub break_dfinity_owned_node: bool,
    pub add_and_bless_upgrade_version: bool,
    pub fix_dfinity_owned_node_like_np: bool,
    pub sequential_np_actions: bool,
}

fn get_host_vm_names(num_hosts: usize) -> Vec<String> {
    (1..=num_hosts).map(|i| format!("host-{i}")).collect()
}

pub fn replace_nns_with_unassigned_nodes(env: &TestEnv) {
    let logger = env.logger();

    info!(logger, "Adding all unassigned nodes to the NNS subnet...");
    let topology = env.topology_snapshot();
    let nns_subnet = topology.root_subnet();
    let original_node = nns_subnet.nodes().next().unwrap();

    let new_node_ids: Vec<_> = topology.unassigned_nodes().map(|n| n.node_id).collect();
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
    let new_topology =
        block_on(topology.block_for_newer_registry_version_within_duration(secs(60), secs(2)))
            .unwrap();

    let nns_subnet = new_topology.root_subnet();
    let num_nns_nodes = nns_subnet.nodes().count();
    assert_eq!(
        num_nns_nodes,
        new_node_ids.len(),
        "NNS subnet should have {} nodes after removing the original node, but found {} nodes",
        new_node_ids.len(),
        num_nns_nodes
    );

    // Readiness wait: ensure the NNS subnet is healthy and making progress
    for node in nns_subnet.nodes() {
        node.await_status_is_healthy().unwrap();
    }
    await_subnet_earliest_topology_version_with_retries(
        &nns_subnet,
        new_topology.get_registry_version(),
        &logger,
        secs(15 * 60),
        secs(15),
    );
    info!(logger, "Success: New nodes have taken over the NNS subnet");
}

// Mirror production setup by granting backup access to all NNS nodes to a specific SSH key.
// This is necessary as part of the `DownloadCertifications` step of the recovery to determine
// the latest certified height of the subnet.
pub fn grant_backup_access_to_all_nns_nodes(
    env: &TestEnv,
    backup_auth: &AuthMean,
    ssh_backup_pub_key: &str,
) {
    let logger = env.logger();
    let topology = env.topology_snapshot();
    let nns_subnet = topology.root_subnet();
    let nns_node = nns_subnet.nodes().next().unwrap();

    info!(logger, "Update the registry with the backup key");
    let payload = get_updatesubnetpayload_with_keys(
        nns_subnet.subnet_id,
        None,
        Some(vec![ssh_backup_pub_key.to_string()]),
    );
    block_on(update_subnet_record(nns_node.get_public_url(), payload));

    for node in nns_subnet.nodes() {
        info!(
            logger,
            "Waiting for authentication to be granted on node {} ({:?})",
            node.node_id,
            node.get_ip_addr()
        );
        wait_until_authentication_is_granted(
            &logger,
            &node.get_ip_addr(),
            BACKUP_USERNAME,
            backup_auth,
        );
    }

    info!(logger, "Success: Backup access granted to all NNS nodes");
}

pub fn setup(env: TestEnv, cfg: SetupConfig) {
    if cfg.impersonate_upstreams {
        impersonate_upstreams::setup_upstreams_uvm(&env);
    }

    setup_ic_infrastructure(&env, Some(cfg.dkg_interval), /*is_fast=*/ false);

    let host_vm_names = get_host_vm_names(cfg.subnet_size);
    NestedNodes::new_with_resources(&host_vm_names, NNS_RECOVERY_VM_RESOURCES)
        .setup_and_start(&env)
        .unwrap();
}

pub fn test(env: TestEnv, cfg: TestConfig) {
    let logger = env.logger();

    let recovery_img_path = get_dependency_path_from_env("RECOVERY_GUESTOS_IMG_PATH");

    let AdminAndUserKeys {
        ssh_admin_priv_key_path,
        admin_auth,
        ssh_user_priv_key_path: ssh_backup_priv_key_path,
        user_auth: backup_auth,
        ssh_user_pub_key: ssh_backup_pub_key,
        ..
    } = get_admin_keys_and_generate_backup_keys(&env);

    nested::registration(env.clone());
    replace_nns_with_unassigned_nodes(&env);
    grant_backup_access_to_all_nns_nodes(&env, &backup_auth, &ssh_backup_pub_key);

    let current_version = get_guestos_img_version();
    info!(logger, "Current GuestOS version: {:?}", current_version);

    let topology = env.topology_snapshot();
    let nns_subnet = topology.root_subnet();
    let subnet_size = nns_subnet.nodes().count();
    let nns_node = nns_subnet.nodes().next().unwrap();

    info!(logger, "Ensure NNS subnet is functional");
    let init_msg = "subnet recovery works!";
    let app_can_id = store_message(
        &nns_node.get_public_url(),
        nns_node.effective_canister_id(),
        init_msg,
        &logger,
    );
    let msg = "subnet recovery works again!";
    assert_subnet_is_healthy(
        &nns_subnet.nodes().collect::<Vec<_>>(),
        &current_version,
        app_can_id,
        init_msg,
        msg,
        &logger,
    );

    // identifies the version of the replica after the recovery
    let upgrade_version = get_guestos_update_img_version();
    let upgrade_image_url = get_guestos_update_img_url();
    let upgrade_image_hash = get_guestos_update_img_sha256();
    let guest_launch_measurements = get_guestos_launch_measurements();
    if !cfg.add_and_bless_upgrade_version {
        // If ic-recovery does not add/bless the new version to the registry, then we must bless it now.
        block_on(bless_replica_version(
            &nns_node,
            &upgrade_version,
            &logger,
            upgrade_image_hash.clone(),
            Some(guest_launch_measurements),
            vec![upgrade_image_url.to_string()],
        ));
    }

    let recovery_dir = get_dependency_path("rs/tests");
    let output_dir = env.get_path("recovery_output");
    set_sandbox_env_vars(recovery_dir.join("recovery/binaries"));

    // Choose f+1 faulty nodes to break
    let nns_nodes = nns_subnet.nodes().collect::<Vec<_>>();
    let f = (subnet_size - 1) / 3;
    let faulty_nodes = &nns_nodes[..(f + 1)];
    let healthy_nodes = &nns_nodes[(f + 1)..];
    // TODO(CON-1587): Consider breaking all nodes.
    let healthy_node = healthy_nodes.first().unwrap();
    info!(
        logger,
        "Selected faulty nodes: {:?}. Selected healthy nodes: {:?}",
        faulty_nodes.iter().map(|n| n.node_id).collect::<Vec<_>>(),
        healthy_nodes.iter().map(|n| n.node_id).collect::<Vec<_>>(),
    );
    let dfinity_owned_node = if cfg.break_dfinity_owned_node {
        faulty_nodes.last().unwrap()
    } else {
        // TODO(CON-1587): Consider breaking all nodes.
        healthy_nodes.first().unwrap()
    };
    info!(
        logger,
        "Selected DFINITY-owned NNS node: {} ({:?})",
        dfinity_owned_node.node_id,
        dfinity_owned_node.get_ip_addr()
    );

    break_nodes(faulty_nodes, &logger);
    assert_subnet_is_broken(
        &healthy_node.get_public_url(),
        app_can_id,
        msg,
        true,
        &logger,
    );

    // Download pool from the node with the highest certification share height
    let (download_pool_node, highest_cert_share) =
        node_with_highest_certification_share_height(&nns_subnet, &logger);
    info!(
        logger,
        "Selected node {} ({:?}) as download pool with certification share height {}",
        download_pool_node.node_id,
        download_pool_node.get_ip_addr(),
        highest_cert_share,
    );

    // Mirror production setup by removing admin SSH access from all nodes except the DFINITY-owned node
    info!(
        logger,
        "Remove admin SSH access from all NNS nodes except the DFINITY-owned node"
    );
    let nodes_except_dfinity_owned = nns_subnet
        .nodes()
        .filter(|n| n.node_id != dfinity_owned_node.node_id)
        .collect::<Vec<_>>();
    for node in nodes_except_dfinity_owned {
        info!(
            logger,
            "Removing admin SSH access from node {} ({:?})",
            node.node_id,
            node.get_ip_addr()
        );

        let _ = disable_ssh_access_to_node(&logger, &node, SSH_USERNAME, &admin_auth).unwrap();
    }
    // Ensure we can still SSH into the DFINITY-owned node with the admin key
    wait_until_authentication_is_granted(
        &logger,
        &dfinity_owned_node.get_ip_addr(),
        SSH_USERNAME,
        &admin_auth,
    );

    let recovery_args = RecoveryArgs {
        dir: recovery_dir,
        nns_url: healthy_node.get_public_url(),
        replica_version: Some(current_version),
        admin_key_file: Some(ssh_admin_priv_key_path),
        test_mode: true,
        skip_prompts: true,
        use_local_binaries: false,
    };

    // Unlike during a production recovery using the CLI, here we already know all parameters ahead
    // of time.
    let subnet_args = NNSRecoverySameNodesArgs {
        subnet_id: nns_subnet.subnet_id,
        upgrade_version: Some(upgrade_version.clone()),
        upgrade_image_url: Some(upgrade_image_url),
        upgrade_image_hash: Some(upgrade_image_hash),
        add_and_bless_upgrade_version: Some(cfg.add_and_bless_upgrade_version),
        replay_until_height: Some(highest_cert_share),
        download_pool_node: Some(download_pool_node.get_ip_addr()),
        admin_access_location: Some(DataLocation::Remote(dfinity_owned_node.get_ip_addr())),
        keep_downloaded_state: Some(false),
        wait_for_cup_node: (!cfg.fix_dfinity_owned_node_like_np)
            .then_some(dfinity_owned_node.get_ip_addr()),
        backup_key_file: Some(ssh_backup_priv_key_path),
        output_dir: Some(output_dir.clone()),
        next_step: None,
        skip: Some(vec![StepType::Cleanup]), // Skip Cleanup to keep the output directory
    };

    info!(
        logger,
        "Starting recovery of NNS subnet {} with {:?}", nns_subnet.subnet_id, &subnet_args
    );

    let subnet_recovery = NNSRecoverySameNodes::new(logger.clone(), recovery_args, subnet_args);

    if cfg.local_recovery {
        info!(logger, "Performing a local recovery");
        local_recovery(dfinity_owned_node, subnet_recovery, &logger);
    } else {
        info!(logger, "Performing a remote recovery");
        remote_recovery(subnet_recovery, &logger);
    }
    info!(
        logger,
        "Recovery coordinator successfully went through all steps of the recovery tool"
    );

    info!(logger, "Setup UVM to serve recovery artifacts");
    let artifacts_path = output_dir.join(CreateNNSRecoveryTarStep::get_tar_name());
    let artifacts_hash =
        std::fs::read_to_string(output_dir.join(CreateNNSRecoveryTarStep::get_sha_name()))
            .unwrap()
            .trim()
            .to_string();
    let recovery_hash_prefix = &artifacts_hash[..6.min(artifacts_hash.len())];
    impersonate_upstreams::uvm_serve_recovery_artifacts(
        &env,
        &artifacts_path,
        recovery_hash_prefix,
    )
    .expect("Failed to serve recovery artifacts from UVM");

    info!(logger, "Setup UVM to serve recovery-dev GuestOS image");
    impersonate_upstreams::uvm_serve_recovery_image(
        &env,
        &recovery_img_path,
        RECOVERY_GUESTOS_IMG_VERSION,
    )
    .unwrap();

    // If we fix the DFINITY-owned node like the other NPs, we include it in the nodes to fix. If we
    // do not, it has already been fixed as part of the recovery tool. We thus fix 2f other nodes to
    // reach 2f+1 in total.
    let (dfinity_owned_host, other_hosts): (Vec<NestedVm>, Vec<NestedVm>) = env
        .get_all_nested_vms()
        .unwrap()
        .iter()
        .cloned()
        .partition(|vm| {
            vm.get_nested_network().unwrap().guest_ip == dfinity_owned_node.get_ip_addr()
        });
    let mut hosts_to_fix = other_hosts
        .choose_multiple(&mut rand::thread_rng(), 2 * f)
        .collect::<Vec<_>>();
    if cfg.fix_dfinity_owned_node_like_np {
        hosts_to_fix.push(dfinity_owned_host.first().unwrap());
    }

    info!(
        logger,
        "Simulate node provider action on {} nodes{}",
        hosts_to_fix.len(),
        if cfg.fix_dfinity_owned_node_like_np {
            ", including the DFINITY-owned node"
        } else {
            ""
        }
    );
    block_on(async {
        let mut handles = JoinSet::new();

        for vm in hosts_to_fix {
            let logger = logger.clone();
            let env = env.clone();
            let vm = vm.clone();
            let recovery_hash_prefix = recovery_hash_prefix.to_string();
            let upgrade_version = upgrade_version.clone();

            handles.spawn(async move {
                simulate_node_provider_action(
                    &logger,
                    &env,
                    &vm,
                    RECOVERY_GUESTOS_IMG_VERSION,
                    &recovery_hash_prefix,
                    &upgrade_version,
                )
                .await
            });

            if cfg.sequential_np_actions {
                handles
                    .join_next()
                    .await
                    .unwrap()
                    .expect("Node provider action failed");
            }
        }

        handles.join_all().await;
    });

    info!(logger, "Ensure the subnet is healthy after the recovery");
    let new_msg = "subnet recovery still works!";
    assert_subnet_is_healthy(
        &nns_subnet.nodes().collect::<Vec<_>>(),
        &upgrade_version,
        app_can_id,
        msg,
        new_msg,
        &logger,
    );
}

async fn simulate_node_provider_action(
    logger: &Logger,
    env: &TestEnv,
    host: &NestedVm,
    img_version: &str,
    recovery_hash_prefix: &str,
    upgrade_version: &ReplicaVersion,
) {
    // Spoof the HostOS DNS such that it downloads the GuestOS image from the UVM
    let server_ipv6 = impersonate_upstreams::get_upstreams_uvm_ipv6(env);
    info!(
        logger,
        "Spoofing HostOS {} DNS to point the upstreams to the UVM at {}",
        host.vm_name(),
        server_ipv6
    );
    impersonate_upstreams::spoof_node_dns_async(host, &server_ipv6)
        .await
        .expect("Failed to spoof HostOS DNS");

    // Run guestos-recovery-upgrader directly, bypassing the limited-console manual recovery TUI
    info!(
        logger,
        "Running guestos-recovery-upgrader on GuestOS {} with version={}, recovery-hash-prefix={}",
        host.vm_name(),
        img_version,
        recovery_hash_prefix,
    );
    let recovery_upgrader_command =
        build_recovery_upgrader_run_command(img_version, recovery_hash_prefix).to_shell_string();
    host.block_on_bash_script_async(&recovery_upgrader_command)
        .await
        .expect("Failed to run guestos-recovery-upgrader");

    // Spoof the GuestOS DNS such that it downloads the recovery artifacts from the UVM
    let guest = host.get_guest_ssh().unwrap();
    info!(
        logger,
        "Spoofing GuestOS {} DNS to point the upstreams to the UVM at {}",
        host.vm_name(),
        server_ipv6
    );
    impersonate_upstreams::spoof_node_dns_async(&guest, &server_ipv6)
        .await
        .expect("Failed to spoof GuestOS DNS");

    // Wait until the node has booted the expected GuestOS version
    retry_with_msg_async!(
        format!(
            "Waiting until GuestOS {} boots on the upgrade version {}",
            host.vm_name(),
            upgrade_version
        ),
        &logger,
        secs(600),
        secs(10),
        || async {
            match host.status_async().await {
                Ok(status) => {
                    if let Some(version_str) = &status.impl_version
                        && let Ok(version) = ReplicaVersion::try_from(version_str.as_str())
                        && version == *upgrade_version
                    {
                        return Ok(());
                    }

                    bail!(
                        "GuestOS is running version {:?}, expected {:?}",
                        status.impl_version,
                        upgrade_version
                    )
                }
                Err(err) => {
                    bail!("GuestOS is rebooting: {:?}", err)
                }
            }
        }
    )
    .await
    .expect("GuestOS did not reboot on the upgrade version");
}

fn local_recovery(node: &IcNodeSnapshot, subnet_recovery: NNSRecoverySameNodes, logger: &Logger) {
    let session = node.block_on_ssh_session().unwrap();
    let node_id = node.node_id;
    let node_ip = node.get_ip_addr();

    let command_args =
        nns_subnet_recovery_same_nodes_local_cli_args(node, &session, &subnet_recovery, logger);
    let command = format!(
        r#"/opt/ic/bin/ic-recovery \
        {command_args} \
        "#
    );

    // The command is expected to reboot the node as part of the recovery, so if it returns
    // successfully, it means something went wrong.
    info!(logger, "Executing local recovery command: \n{command}");
    node.block_on_bash_script_from_session(&session, &command)
        .expect_err("Local recovery command completed without rebooting");

    info!(logger, "Node rebooted as part of the recovery");

    // Resume the recovery by re-executing the command starting from WaitForCUP. The command should
    // succeed this time.
    let session = node.block_on_ssh_session().unwrap(); // New session after reboot
    let command = command + r#"--resume WaitForCUP \"#;
    info!(logger, "Resuming local recovery command: \n{command}");
    node.block_on_bash_script_from_session(&session, &command)
        .expect("Local recovery failed to complete");

    info!(logger, "Local recovery completed successfully");

    if let Some(local_output_dir) = &subnet_recovery.params.output_dir {
        info!(
            logger,
            "Copying output directory from node {node_id} with IP {node_ip} ..."
        );
        std::fs::create_dir_all(local_output_dir).unwrap();
        scp_recv_from(
            logger.clone(),
            &session,
            &Path::new(NNS_RECOVERY_OUTPUT_DIR_REMOTE_PATH)
                .join(CreateNNSRecoveryTarStep::get_tar_name()),
            &local_output_dir.join(CreateNNSRecoveryTarStep::get_tar_name()),
        );
        scp_recv_from(
            logger.clone(),
            &session,
            &Path::new(NNS_RECOVERY_OUTPUT_DIR_REMOTE_PATH)
                .join(CreateNNSRecoveryTarStep::get_sha_name()),
            &local_output_dir.join(CreateNNSRecoveryTarStep::get_sha_name()),
        );
    }
}
