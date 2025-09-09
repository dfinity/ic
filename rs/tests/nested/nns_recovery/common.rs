use std::time::Duration;

use anyhow::{bail, Result};
use futures::future::join_all;
use ic_consensus_system_test_utils::{
    impersonate_upstreams,
    node::await_subnet_earliest_topology_version,
    rw_message::{
        can_read_msg, cannot_store_msg, cert_state_makes_progress_with_retries, store_message,
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
use ic_system_test_driver::{
    driver::{
        constants::SSH_USERNAME,
        driver_setup::{SSH_AUTHORIZED_PRIV_KEYS_DIR, SSH_AUTHORIZED_PUB_KEYS_DIR},
        nested::NestedVms,
        test_env::TestEnv,
        test_env_api::*,
    },
    nns::change_subnet_membership,
    retry_with_msg, retry_with_msg_async,
    util::block_on,
};
use nested::util::{
    assert_version_compatibility, get_host_boot_id_async, setup_ic_infrastructure,
    setup_nested_vm_group, setup_vector_targets_for_vm, start_nested_vm_group,
    NODE_REGISTRATION_BACKOFF, NODE_REGISTRATION_TIMEOUT,
};
use rand::seq::SliceRandom;
use sha2::{Digest, Sha256};
use slog::{info, Logger};

/// 4 nodes is the minimum subnet size that satisfies 3f+1 for f=1
pub const SUBNET_SIZE: usize = 4;
/// DKG interval of 9 is large enough for a subnet of that size and as small as possible to keep the
/// test runtime low
pub const DKG_INTERVAL: u64 = 9;

/// 40 nodes and DKG interval of 199 are the production values for the NNS
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

pub struct TestConfig {
    pub subnet_size: usize,
}

fn get_host_vm_names(num_hosts: usize) -> Vec<String> {
    (1..=num_hosts).map(|i| format!("host-{}", i)).collect()
}

pub fn assign_unassigned_nodes_to_nns(
    logger: &Logger,
    topology: &TopologySnapshot,
) -> TopologySnapshot {
    info!(logger, "Adding all unassigned nodes to the NNS subnet...");
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

    new_topology
}

pub fn setup(env: TestEnv, cfg: SetupConfig) {
    assert_version_compatibility();

    if cfg.impersonate_upstreams {
        impersonate_upstreams::setup_upstreams_uvm(&env);
    }

    setup_ic_infrastructure(&env, Some(cfg.dkg_interval));

    let host_vm_names = get_host_vm_names(cfg.subnet_size);
    let host_vm_names_refs: Vec<&str> = host_vm_names.iter().map(|s| s.as_str()).collect();
    setup_nested_vm_group(env.clone(), &host_vm_names_refs);

    for vm_name in &host_vm_names {
        setup_vector_targets_for_vm(&env, vm_name);
    }
}

pub fn test(env: TestEnv, cfg: TestConfig) {
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
            if num_unassigned_nodes == cfg.subnet_size {
                info!(logger, "Success: All nodes have registered");
                Ok(new_topology)
            } else {
                bail!(
                    "Expected {} unassigned nodes, but found {}",
                    cfg.subnet_size,
                    num_unassigned_nodes
                )
            }
        }
    )
    .unwrap();

    let new_topology = assign_unassigned_nodes_to_nns(&logger, &new_topology);
    let nns_subnet = new_topology.root_subnet();
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
    let f = (cfg.subnet_size - 1) / 3;
    let faulty_nodes = &nns_nodes[..(f + 1)];
    let healthy_nodes = &nns_nodes[(f + 1)..];
    info!(
        logger,
        "Selected faulty nodes: {:?}. Selected healthy nodes: {:?}",
        faulty_nodes.iter().map(|n| n.node_id).collect::<Vec<_>>(),
        healthy_nodes.iter().map(|n| n.node_id).collect::<Vec<_>>(),
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
        &nns_node.get_public_url(),
        app_can_id,
        msg
    ));
    info!(
        logger,
        "Success: Subnet is broken - cannot store new messages"
    );

    // Choose the DFINITY-owned node to be the one with the highest certification share height
    let (dfinity_owned_node, highest_certification_share_height) = nns_subnet
        .nodes()
        .filter_map(|n| {
            block_on(get_node_metrics(&logger, &n.get_ip_addr()))
                .map(|m| (n, m.certification_share_height.get()))
        })
        .max_by_key(|&(_, cert_share_height)| cert_share_height)
        .expect("No download node found");

    info!(
        logger,
        "Selected DFINITY-owned NNS node: {} ({:?})",
        dfinity_owned_node.node_id,
        dfinity_owned_node.get_ip_addr()
    );

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
        replay_until_height: Some(highest_certification_share_height),
        upgrade_image_url: Some(get_guestos_update_img_url()),
        upgrade_image_hash: Some(get_guestos_update_img_sha256()),
        download_node: Some(dfinity_owned_node.get_ip_addr()),
        upload_method: Some(DataLocation::Remote(dfinity_owned_node.get_ip_addr())),
        backup_key_file: Some(ssh_priv_key_path),
        output_dir: Some(output_dir.clone()),
        next_step: None,
    };

    let subnet_recovery_tool =
        NNSRecoverySameNodes::new(logger.clone(), recovery_args, subnet_args);

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

    // The DFINITY-owned node is already recovered as part of the recovery tool, so we only need to
    // trigger the recovery on 2f other nodes.
    info!(logger, "Simulate node provider action on 2f nodes");
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(join_all(
            get_host_vm_names(cfg.subnet_size)
                .iter()
                .cloned()
                .filter(|vm_name| {
                    env.get_nested_vm(vm_name)
                        .unwrap()
                        .get_nested_network()
                        .unwrap()
                        .guest_ip
                        != dfinity_owned_node.get_ip_addr()
                })
                .collect::<Vec<_>>()
                .choose_multiple(&mut rand::thread_rng(), 2 * f)
                .cloned()
                .map(|vm_name| {
                    let logger = logger.clone();
                    let env = env.clone();
                    let recovery_img_hash = recovery_img_hash.clone();
                    let artifacts_hash = artifacts_hash.clone();

                    tokio::task::spawn(async move {
                        simulate_node_provider_action(
                            &logger,
                            &env,
                            &vm_name,
                            RECOVERY_GUESTOS_IMG_VERSION,
                            &recovery_img_hash[..6],
                            &artifacts_hash,
                        )
                        .await
                    })
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

    info!(logger, "Ensure the subnet uses the new replica version");
    let nns_subnet = block_on(new_topology.block_for_newer_registry_version())
        .expect("Could not obtain updated registry.")
        .root_subnet();
    for node in nns_subnet.nodes() {
        assert_assigned_replica_version(&node, &working_version, env.logger());
    }
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
    let host_boot_id_pre_reboot = get_host_boot_id_async(&host).await;

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
            let host_boot_id = get_host_boot_id_async(&host).await;
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
