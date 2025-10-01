use std::path::Path;
use std::time::Duration;

use anyhow::bail;
use ic_consensus_system_test_utils::{
    impersonate_upstreams,
    node::await_subnet_earliest_topology_version,
    rw_message::{
        can_read_msg, cannot_store_msg, cert_state_makes_progress_with_retries, store_message,
    },
    set_sandbox_env_vars,
    ssh_access::{
        AuthMean, get_updatesubnetpayload_with_keys, update_subnet_record,
        wait_until_authentication_is_granted,
    },
    upgrade::assert_assigned_replica_version,
};
use ic_recovery::{
    RecoveryArgs, get_node_metrics,
    nns_recovery_same_nodes::{NNSRecoverySameNodes, NNSRecoverySameNodesArgs},
    steps::CreateNNSRecoveryTarStep,
    util::DataLocation,
};
use ic_system_test_driver::{
    driver::{
        constants::SSH_USERNAME,
        driver_setup::{SSH_AUTHORIZED_PRIV_KEYS_DIR, SSH_AUTHORIZED_PUB_KEYS_DIR},
        nested::NestedVm,
        nested::{HasNestedVms, NestedNodes},
        test_env::TestEnv,
        test_env_api::*,
    },
    nns::change_subnet_membership,
    retry_with_msg_async,
    util::block_on,
};
use nested::util::{get_host_boot_id_async, setup_ic_infrastructure};
use rand::seq::SliceRandom;
use sha2::{Digest, Sha256};
use slog::{Logger, info};
use tokio::task::JoinSet;

/// 4 nodes is the minimum subnet size that satisfies 3f+1 for f=1
pub const SUBNET_SIZE: usize = 4;
/// DKG interval of 9 is large enough for a subnet of that size and as small as possible to keep the
/// test runtime low
pub const DKG_INTERVAL: u64 = 9;

/// 40 nodes and DKG interval of 199 are the production values for the NNS but 49 was chosen for
/// the DKG interval to make the test faster
pub const LARGE_SUBNET_SIZE: usize = 40;
pub const LARGE_DKG_INTERVAL: u64 = 49;

/// RECOVERY_GUESTOS_IMG_VERSION variable is a placeholder for the actual version of the recovery
/// GuestOS image, that Node Providers would use as input to guestos-recovery-upgrader.
pub const RECOVERY_GUESTOS_IMG_VERSION: &str = "RECOVERY_VERSION";

const ADMIN_KEY_FILE_REMOTE_PATH: &str = "/var/lib/admin/admin_key";
const BACKUP_KEY_FILE_REMOTE_PATH: &str = "/var/lib/admin/backup_key";
const OUTPUT_DIR_REMOTE_PATH: &str = "/var/lib/ic/data/recovery/output";

pub struct SetupConfig {
    pub impersonate_upstreams: bool,
    pub subnet_size: usize,
    pub dkg_interval: u64,
}

#[derive(Debug)]
pub struct TestConfig {
    pub local_recovery: bool,
    pub break_dfinity_owned_node: bool,
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
    let new_topology = block_on(topology.block_for_newer_registry_version_within_duration(
        Duration::from_secs(60),
        Duration::from_secs(2),
    ))
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
    await_subnet_earliest_topology_version(
        &nns_subnet,
        new_topology.get_registry_version(),
        &logger,
    );
    info!(logger, "Success: New nodes have taken over the NNS subnet");
}

pub fn setup(env: TestEnv, cfg: SetupConfig) {
    if cfg.impersonate_upstreams {
        impersonate_upstreams::setup_upstreams_uvm(&env);
    }

    setup_ic_infrastructure(&env, Some(cfg.dkg_interval), /*is_fast=*/ false);

    let host_vm_names = get_host_vm_names(cfg.subnet_size);
    NestedNodes::new(&host_vm_names)
        .setup_and_start(&env)
        .unwrap();
}

pub fn test(env: TestEnv, cfg: TestConfig) {
    let logger = env.logger();

    let recovery_img_path = get_dependency_path_from_env("RECOVERY_GUESTOS_IMG_PATH");
    let recovery_img =
        std::fs::read(&recovery_img_path).expect("Failed to read recovery GuestOS image");
    let recovery_img_hash = Sha256::digest(&recovery_img)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    nested::registration(env.clone());
    replace_nns_with_unassigned_nodes(&env);

    let topology = env.topology_snapshot();
    let nns_subnet = topology.root_subnet();
    let subnet_size = nns_subnet.nodes().count();
    let nns_node = nns_subnet.nodes().next().unwrap();

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
    block_on(update_subnet_record(nns_node.get_public_url(), payload));
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
        &nns_node.get_public_url(),
        nns_node.effective_canister_id(),
        msg,
        &logger,
    );
    assert!(can_read_msg(
        &logger,
        &nns_node.get_public_url(),
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
    // Break faulty nodes by SSHing into them and breaking the replica binary.
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

    info!(logger, "Ensure a healthy node still works in read mode");
    assert!(can_read_msg(
        &logger,
        &healthy_node.get_public_url(),
        app_can_id,
        msg
    ));
    info!(
        logger,
        "Ensure the subnet does not work in write mode anymore"
    );
    assert!(cannot_store_msg(
        logger.clone(),
        &nns_node.get_public_url(),
        app_can_id,
        msg
    ));
    info!(
        logger,
        "Success: Subnet is broken - cannot store new messages"
    );

    // Download pool from the node with the highest certification share height
    let (download_pool_node, highest_certification_share_height) = nns_subnet
        .nodes()
        .filter_map(|n| {
            block_on(get_node_metrics(&logger, &n.get_ip_addr()))
                .map(|m| (n, m.certification_share_height.get()))
        })
        .max_by_key(|&(_, cert_share_height)| cert_share_height)
        .expect("No download node found");

    let recovery_args = RecoveryArgs {
        dir: recovery_dir,
        nns_url: healthy_node.get_public_url(),
        replica_version: Some(ic_version),
        admin_key_file: Some(ssh_priv_key_path.clone()),
        test_mode: true,
        skip_prompts: true,
        use_local_binaries: false,
    };

    // unlike during a production recovery using the CLI, here we already know all of parameters
    // ahead of time.
    let subnet_args = NNSRecoverySameNodesArgs {
        subnet_id: nns_subnet.subnet_id,
        upgrade_version: Some(working_version.clone()),
        upgrade_image_url: Some(get_guestos_update_img_url()),
        upgrade_image_hash: Some(get_guestos_update_img_sha256()),
        add_and_bless_upgrade_version: Some(true),
        replay_until_height: Some(highest_certification_share_height),
        download_pool_node: Some(download_pool_node.get_ip_addr()),
        admin_access_location: Some(DataLocation::Remote(dfinity_owned_node.get_ip_addr())),
        keep_downloaded_state: Some(false),
        wait_for_cup_node: Some(dfinity_owned_node.get_ip_addr()),
        backup_key_file: Some(ssh_priv_key_path),
        output_dir: Some(output_dir.clone()),
        next_step: None,
        skip: None,
    };

    let subnet_recovery_tool =
        NNSRecoverySameNodes::new(logger.clone(), recovery_args, subnet_args);

    if cfg.local_recovery {
        info!(logger, "Performing a local recovery");
        local_recovery(dfinity_owned_node, subnet_recovery_tool, &logger);
    } else {
        info!(logger, "Performing a remote recovery");
        remote_recovery(subnet_recovery_tool, &logger);
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
    impersonate_upstreams::uvm_serve_recovery_artifacts(&env, &artifacts_path, &artifacts_hash)
        .expect("Failed to serve recovery artifacts from UVM");

    info!(logger, "Setup UVM to serve recovery-dev GuestOS image");
    impersonate_upstreams::uvm_serve_recovery_image(
        &env,
        &recovery_img_path,
        RECOVERY_GUESTOS_IMG_VERSION,
    )
    .unwrap();

    // The DFINITY-owned node is already recovered as part of the recovery tool, so we only need to
    // trigger the recovery on 2f other nodes.
    info!(logger, "Simulate node provider action on 2f nodes");
    block_on(async {
        let mut handles = JoinSet::new();

        for vm in env
            .get_all_nested_vms()
            .unwrap()
            .iter()
            .filter(|&vm| {
                vm.get_nested_network().unwrap().guest_ip != dfinity_owned_node.get_ip_addr()
            })
            .cloned()
            .collect::<Vec<_>>()
            .choose_multiple(&mut rand::thread_rng(), 2 * f)
        {
            let logger = logger.clone();
            let env = env.clone();
            let vm = vm.clone();
            let recovery_img_hash = recovery_img_hash.clone();
            let artifacts_hash = artifacts_hash.clone();

            handles.spawn(async move {
                simulate_node_provider_action(
                    &logger,
                    &env,
                    &vm,
                    RECOVERY_GUESTOS_IMG_VERSION,
                    &recovery_img_hash,
                    &artifacts_hash,
                )
                .await
            });
        }

        handles.join_all().await;
    });

    info!(
        logger,
        "Ensure every node uses the new replica version, is healthy and the subnet is making progress"
    );
    let nns_subnet =
        block_on(topology.block_for_newer_registry_version_within_duration(secs(600), secs(10)))
            .expect("Could not obtain updated registry.")
            .root_subnet();
    for node in nns_subnet.nodes() {
        assert_assigned_replica_version(&node, &working_version, env.logger());
        node.await_status_is_healthy().unwrap_or_else(|_| {
            panic!(
                "Node {} ({:?}) did not become healthy after the recovery",
                node.node_id,
                node.get_ip_addr()
            )
        });
    }
    cert_state_makes_progress_with_retries(
        &dfinity_owned_node.get_public_url(),
        dfinity_owned_node.effective_canister_id(),
        &logger,
        secs(600),
        secs(10),
    );

    let nns_node = nns_subnet.nodes().next().unwrap();

    info!(logger, "Ensure the old message is still readable");
    assert!(can_read_msg(
        &logger,
        &nns_node.get_public_url(),
        app_can_id,
        msg
    ));

    info!(
        logger,
        "Ensure that the subnet is accepting updates after the recovery"
    );
    let new_msg = "subnet recovery still works!";
    let new_app_can_id = store_message(
        &nns_node.get_public_url(),
        nns_node.effective_canister_id(),
        new_msg,
        &logger,
    );
    assert!(can_read_msg(
        &logger,
        &nns_node.get_public_url(),
        new_app_can_id,
        new_msg
    ));
}

async fn simulate_node_provider_action(
    logger: &Logger,
    env: &TestEnv,
    host: &NestedVm,
    img_version: &str,
    img_version_hash: &str,
    artifacts_hash: &str,
) {
    let host_boot_id_pre_reboot = get_host_boot_id_async(host).await;

    // Trigger HostOS reboot and run guestos-recovery-upgrader
    info!(
        logger,
        "Remounting /boot as read-write, updating boot_args file and rebooting host {}",
        host.vm_name(),
    );
    let boot_args_command = format!(
        "sudo mount -o remount,rw /boot && sudo sed -i 's/\\(BOOT_ARGS_A=\".*\\)enforcing=0\"/\\1enforcing=0 recovery=1 version={} version-hash={} recovery-hash={}\"/' /boot/boot_args && sudo mount -o remount,ro /boot && sudo reboot",
        &img_version, &img_version_hash, &artifacts_hash
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
            let host_boot_id = get_host_boot_id_async(host).await;
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
        "Spoofing HostOS {} DNS to point the upstreams to the UVM at {}",
        host.vm_name(),
        server_ipv6
    );
    impersonate_upstreams::spoof_node_dns_async(host, &server_ipv6)
        .await
        .expect("Failed to spoof HostOS DNS");

    // Once GuestOS is launched, we still need to spoof its DNS for the same reason as HostOS
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
}

fn remote_recovery(subnet_recovery_tool: NNSRecoverySameNodes, logger: &Logger) {
    for (step_type, step) in subnet_recovery_tool {
        info!(logger, "Next step: {:?}", step_type);

        info!(logger, "{}", step.descr());
        step.exec()
            .unwrap_or_else(|e| panic!("Execution of step {step_type:?} failed: {e}"));
    }
}

fn local_recovery(
    node: &IcNodeSnapshot,
    subnet_recovery_tool: NNSRecoverySameNodes,
    logger: &Logger,
) {
    let session = &node.block_on_ssh_session().unwrap();
    let node_id = node.node_id;
    let node_ip = node.get_ip_addr();

    let maybe_admin_key_file =
        if let Some(admin_key_file) = &subnet_recovery_tool.recovery_args.admin_key_file {
            info!(
                logger,
                "Copying the admin key file to node {node_id} with IP {node_ip} ..."
            );
            scp_send_to(
                logger.clone(),
                session,
                admin_key_file,
                Path::new(ADMIN_KEY_FILE_REMOTE_PATH),
                0o400,
            );

            format!("--admin-key-file {ADMIN_KEY_FILE_REMOTE_PATH} ")
        } else {
            String::default()
        };

    let maybe_backup_key_file =
        if let Some(backup_key_file) = &subnet_recovery_tool.params.backup_key_file {
            info!(
                logger,
                "Copying the backup key file to node {node_id} with IP {node_ip} ..."
            );
            scp_send_to(
                logger.clone(),
                session,
                backup_key_file,
                Path::new(BACKUP_KEY_FILE_REMOTE_PATH),
                0o400,
            );

            format!("--backup-key-file {BACKUP_KEY_FILE_REMOTE_PATH} ")
        } else {
            String::default()
        };

    let nns_url = subnet_recovery_tool.recovery_args.nns_url;
    let subnet_id = subnet_recovery_tool.params.subnet_id;
    let maybe_upgrade_version = subnet_recovery_tool
        .params
        .upgrade_version
        .map(|v| format!("--upgrade-version {v} "))
        .unwrap_or_default();
    let maybe_upgrade_image_url = subnet_recovery_tool
        .params
        .upgrade_image_url
        .map(|u| format!("--upgrade-image-url {u} "))
        .unwrap_or_default();
    let maybe_upgrade_image_hash = subnet_recovery_tool
        .params
        .upgrade_image_hash
        .map(|h| format!("--upgrade-image-hash {h} "))
        .unwrap_or_default();
    let maybe_add_and_bless_upgrade_version = subnet_recovery_tool
        .params
        .add_and_bless_upgrade_version
        .map(|b| format!("--add-and-bless-upgrade-version {b} "))
        .unwrap_or_default();
    let maybe_replay_until_height = subnet_recovery_tool
        .params
        .replay_until_height
        .map(|h| format!("--replay-until-height {h} "))
        .unwrap_or_default();
    let maybe_download_pool_node = subnet_recovery_tool
        .params
        .download_pool_node
        .map(|n| format!("--download-pool-node {n} "))
        .unwrap_or_default();
    let maybe_keep_downloaded_state = subnet_recovery_tool
        .params
        .keep_downloaded_state
        .map(|b| format!("--keep-downloaded-state {b} "))
        .unwrap_or_default();
    let maybe_skips = subnet_recovery_tool
        .params
        .skip
        .as_ref()
        .map(|skips| {
            skips
                .iter()
                .map(|s| format!("--skip {s:?} "))
                .collect::<String>()
        })
        .unwrap_or_default();

    let command = format!(
        r#"/opt/ic/bin/ic-recovery \
        --nns-url {nns_url} \
        {maybe_admin_key_file}\
        --test --skip-prompts \
        nns-recovery-same-nodes \
        --subnet-id {subnet_id} \
        {maybe_upgrade_version}\
        {maybe_upgrade_image_url}\
        {maybe_upgrade_image_hash}\
        {maybe_add_and_bless_upgrade_version}\
        {maybe_replay_until_height}\
        {maybe_download_pool_node}\
        --admin-access-location local \
        {maybe_keep_downloaded_state}\
        --wait-for-cup-node {node_ip} \
        {maybe_backup_key_file}\
        --output-dir {OUTPUT_DIR_REMOTE_PATH} \
        {maybe_skips}\
        --skip Cleanup \
        "#
    );

    // The command is expected to reboot the node as part of the recovery, so if it returns
    // successfully, it means something went wrong.
    info!(logger, "Executing local recovery command: \n{command}");
    node.block_on_bash_script_from_session(session, &command)
        .expect_err("Local recovery command completed without rebooting");

    info!(logger, "Node rebooted as part of the recovery");

    // Resume the recovery by re-executing the command starting from WaitForCUP. The command should
    // succeed this time.
    let session = &node.block_on_ssh_session().unwrap(); // New session after reboot
    let command = command + r#"--resume WaitForCUP \"#;
    info!(logger, "Resuming local recovery command: \n{command}");
    node.block_on_bash_script_from_session(session, &command)
        .expect("Local recovery failed to complete");

    info!(logger, "Local recovery completed successfully");

    if let Some(local_output_dir) = &subnet_recovery_tool.params.output_dir {
        info!(
            logger,
            "Copying output directory from node {node_id} with IP {node_ip} ..."
        );
        std::fs::create_dir_all(local_output_dir).unwrap();
        scp_recv_from(
            logger.clone(),
            session,
            &Path::new(OUTPUT_DIR_REMOTE_PATH).join(CreateNNSRecoveryTarStep::get_tar_name()),
            &local_output_dir.join(CreateNNSRecoveryTarStep::get_tar_name()),
        );
        scp_recv_from(
            logger.clone(),
            session,
            &Path::new(OUTPUT_DIR_REMOTE_PATH).join(CreateNNSRecoveryTarStep::get_sha_name()),
            &local_output_dir.join(CreateNNSRecoveryTarStep::get_sha_name()),
        );
    }
}
