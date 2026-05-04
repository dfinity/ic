use anyhow::bail;
use candid::Principal;
use ic_agent::Agent;
use ic_consensus_system_test_subnet_recovery::utils::{
    BACKUP_USERNAME, NodeHeights, SshKeys, assert_subnet_is_broken, break_nodes,
    get_ssh_keys_for_user,
    local::{NNS_RECOVERY_OUTPUT_DIR_REMOTE_PATH, nns_subnet_recovery_same_nodes_local_cli_args},
    node_with_highest_cup_and_cert_share_heights, remote_recovery,
};
use ic_consensus_system_test_utils::{
    impersonate_upstreams,
    node::await_subnet_earliest_topology_version_with_retries_async,
    rw_message::{cert_state_makes_progress_with_retries, store_message_with_retries},
    ssh_access::{
        AuthMean, disable_ssh_access_to_node, get_update_subnet_payload_with_keys,
        update_subnet_record, wait_until_authentication_is_granted,
    },
    subnet::assert_subnet_is_healthy,
    upgrade::{assert_assigned_replica_version, bless_replica_version},
};
use ic_nervous_system_root::change_canister::AddCanisterRequest;
use ic_recovery::{
    IC_DATA_PATH, IC_REGISTRY_LOCAL_STORE, RECOVERY_DIRECTORY_NAME, RecoveryArgs,
    nns_recovery_same_nodes::{NNSRecoverySameNodes, NNSRecoverySameNodesArgs, StepType},
    ssh_helper::SshHelper as RecoverySshHelper,
    steps::CreateNNSRecoveryTarStep,
    util::{DataLocation, SshUser as RecoverySshUser},
};
use ic_system_test_driver::{
    driver::{
        constants::SSH_USERNAME,
        ic::{AmountOfMemoryKiB, NrOfVCPUs, VmResourceOverrides},
        nested::{HasNestedVms, NestedNodes, NestedVm},
        test_env::TestEnv,
        test_env_api::*,
    },
    nns::change_subnet_membership,
    retry_with_msg_async,
    util::{MESSAGE_CANISTER_WASM, MessageCanister, assert_create_agent, block_on},
};
use ic_testnet_mainnet_nns::{
    MAINNET_NODE_VM_RESOURCE_OVERRIDES, proposals::ProposalWithMainnetState,
    setup as setup_with_mainnet_state,
};
use ic_types::ReplicaVersion;
use manual_guestos_recovery::recovery_utils::build_recovery_upgrader_run_command;
use nested::util::{NODE_REGISTRATION_TIMEOUT, setup_ic_infrastructure};
use rand::seq::SliceRandom;
use slog::{Logger, info};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
};
use tokio::task::JoinSet;

pub const NNS_RECOVERY_VM_RESOURCE_OVERRIDES: VmResourceOverrides = VmResourceOverrides {
    vcpus: Some(NrOfVCPUs::new(40)), // 36 GuestOS CPU + 4 HostOS
    memory_kibibytes: Some(AmountOfMemoryKiB::new(50331648)), // 48GiB
    ..VmResourceOverrides::const_default()
};

/// 4 nodes is the minimum subnet size that satisfies 3f+1 for f=1
pub const SUBNET_SIZE: usize = 4;
/// f is the maximum number of faulty nodes that can be tolerated in the subnet
pub const F: usize = (SUBNET_SIZE - 1) / 3;
/// DKG interval as small as possible to keep the test runtime low
pub const DKG_INTERVAL: u64 = 4 * SUBNET_SIZE as u64 + 13;

/// 40 nodes and DKG interval of 499 are the production values for the NNS but 49 was chosen for
/// the DKG interval to make the test faster
pub const LARGE_SUBNET_SIZE: usize = 40;
pub const LARGE_F: usize = (LARGE_SUBNET_SIZE - 1) / 3;
pub const LARGE_DKG_INTERVAL: u64 = 49;

/// RECOVERY_GUESTOS_IMG_VERSION variable is a placeholder for the actual version of the recovery
/// GuestOS image, that Node Providers would use as input to guestos-recovery-upgrader.
pub const RECOVERY_GUESTOS_IMG_VERSION: &str = "RECOVERY_VERSION";

const GUEST_LAUNCH_MEASUREMENTS_PATH: &str = "guest_launch_measurements.json";

pub struct SetupConfig {
    pub impersonate_upstreams: bool,
    pub use_mainnet_state: bool,
    pub subnet_size: usize,
    pub dkg_interval: u64,
    pub nested_nodes_vm_resource_overrides: VmResourceOverrides,
}

#[derive(Debug)]
pub struct TestConfig {
    pub use_mainnet_state: bool,
    pub local_recovery: bool,
    pub break_dfinity_owned_node: bool,
    pub num_broken_nodes: usize,
    pub add_upgrade_version: bool,
    pub fix_dfinity_owned_node_like_np: bool,
    pub sequential_np_actions: bool,
}

fn get_host_vm_names(num_hosts: usize) -> Vec<String> {
    (1..=num_hosts).map(|i| format!("host-{i}")).collect()
}

async fn replace_nns_with_nested_vms(env: &TestEnv, use_mainnet_state: bool) {
    let logger = env.logger();

    info!(logger, "Adding all nested VMs to the NNS subnet...");
    let topology = env.topology_snapshot();
    let nns_subnet = topology.root_subnet();
    let original_node = nns_subnet.nodes().next().unwrap();

    let nested_vm_ips: Vec<IpAddr> = env
        .get_all_nested_vms()
        .unwrap()
        .iter()
        .map(|vm| vm.get_nested_network().unwrap().guest_ip.into())
        .collect();
    let new_node_ids = topology
        .unassigned_nodes()
        .filter(|n| nested_vm_ips.contains(&n.get_ip_addr()))
        .map(|n| n.node_id)
        .collect::<Vec<_>>();
    assert_eq!(
        new_node_ids.len(),
        nested_vm_ips.len(),
        "Not all nested VMs have registered as IC nodes"
    );
    assert!(
        !new_node_ids.is_empty(),
        "No nested VMs found to add to the NNS subnet"
    );

    if use_mainnet_state {
        ProposalWithMainnetState::change_subnet_membership(
            original_node.get_public_url(),
            nns_subnet.subnet_id,
            &new_node_ids,
            &[original_node.node_id],
        )
        .await
    } else {
        change_subnet_membership(
            original_node.get_public_url(),
            nns_subnet.subnet_id,
            &new_node_ids,
            &[original_node.node_id],
        )
        .await
    }
    .expect("Failed to change subnet membership");

    info!(
        logger,
        "Waiting for new nodes to take over the NNS subnet..."
    );
    let new_topology = topology
        .block_for_newer_registry_version_within_duration(secs(60), secs(2))
        .await
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

    // Readiness wait: ensure the NNS subnet is driven by the new nodes
    let state_sync_timeout = if use_mainnet_state {
        // Large subnet with large state takes longer to sync
        secs(60 * 60)
    } else {
        secs(15 * 60)
    };
    await_subnet_earliest_topology_version_with_retries_async(
        &nns_subnet,
        new_topology.get_registry_version(),
        &logger,
        state_sync_timeout,
        secs(15),
    )
    .await;
    for node in nns_subnet.nodes() {
        node.await_status_is_healthy_async().await.unwrap();
    }
    info!(logger, "Success: New nodes have taken over the NNS subnet");
}

// Mirror production setup by granting backup access to all NNS nodes to a specific SSH key.
// This is necessary as part of the `DownloadCertifications` step of the recovery to determine
// the latest certified height of the subnet.
async fn grant_backup_access_to_all_nns_nodes(
    env: &TestEnv,
    backup_auth: &AuthMean,
    ssh_backup_pub_key: &str,
    use_mainnet_state: bool,
) {
    let logger = env.logger();
    let topology = env.topology_snapshot();
    let nns_subnet = topology.root_subnet();
    let nns_node = nns_subnet.nodes().next().unwrap();

    info!(logger, "Update the registry with the backup key");
    let payload = get_update_subnet_payload_with_keys(
        nns_subnet.subnet_id,
        None,
        Some(vec![ssh_backup_pub_key.to_string()]),
    );
    if use_mainnet_state {
        ProposalWithMainnetState::update_subnet_record(nns_node.get_public_url(), payload).await;
    } else {
        update_subnet_record(nns_node.get_public_url(), payload).await;
    }

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

    if cfg.use_mainnet_state {
        setup_with_mainnet_state(env.clone(), Some(cfg.dkg_interval));
    } else {
        setup_ic_infrastructure(&env, Some(cfg.dkg_interval), /*is_fast=*/ false);
    }

    if cfg.subnet_size > 0 {
        let host_vm_names = get_host_vm_names(cfg.subnet_size);
        let vm_resource_overrides = if cfg.use_mainnet_state {
            cfg.nested_nodes_vm_resource_overrides
                .layer(&MAINNET_NODE_VM_RESOURCE_OVERRIDES)
                .layer(&NNS_RECOVERY_VM_RESOURCE_OVERRIDES)
        } else {
            cfg.nested_nodes_vm_resource_overrides
                .layer(&NNS_RECOVERY_VM_RESOURCE_OVERRIDES)
        };
        NestedNodes::new_with_resource_overrides(&host_vm_names, vm_resource_overrides)
            .setup_and_start(&env)
            .unwrap();

        let registration_timeout = if cfg.use_mainnet_state {
            // Using mainnet state requires nodes to first sync their local store, which takes time
            NODE_REGISTRATION_TIMEOUT.saturating_add(secs(10 * 60))
        } else {
            NODE_REGISTRATION_TIMEOUT
        };
        nested::registration_with_timeout(env.clone(), registration_timeout);
        block_on(replace_nns_with_nested_vms(&env, cfg.use_mainnet_state));
    }

    let SshKeys {
        ssh_priv_key_path: _,
        auth: backup_auth,
        ssh_pub_key: ssh_backup_pub_key,
    } = get_ssh_keys_for_user(&env, BACKUP_USERNAME);
    block_on(grant_backup_access_to_all_nns_nodes(
        &env,
        &backup_auth,
        &ssh_backup_pub_key,
        cfg.use_mainnet_state,
    ));
}

pub fn test(env: TestEnv, cfg: TestConfig) {
    if cfg.use_mainnet_state {
        ProposalWithMainnetState::read_dictator_neuron_identity_from_env(&env);
    }

    let logger = env.logger();

    let recovery_img_path = get_dependency_path_from_env("RECOVERY_GUESTOS_IMG_PATH");

    let SshKeys {
        ssh_priv_key_path: ssh_admin_priv_key_path,
        auth: admin_auth,
        ssh_pub_key: _,
    } = get_ssh_keys_for_user(&env, SSH_USERNAME);
    let SshKeys {
        ssh_priv_key_path: ssh_backup_priv_key_path,
        auth: _,
        ssh_pub_key: _,
    } = get_ssh_keys_for_user(&env, BACKUP_USERNAME);

    let current_version = get_guestos_img_version();
    info!(logger, "Current GuestOS version: {:?}", current_version);

    let topology = env.topology_snapshot();
    let nns_subnet = topology.root_subnet();
    let subnet_size = nns_subnet.nodes().count();
    let nns_node = nns_subnet.nodes().next().unwrap();

    info!(logger, "Ensure NNS subnet is functional");
    let init_msg = "subnet recovery initially works!";
    let app_can_id = if cfg.use_mainnet_state {
        block_on(async {
            let nns_url = nns_node.get_public_url();
            let agent = assert_create_agent(nns_url.as_str()).await;

            let canister_principal = ProposalWithMainnetState::add_nns_canister(
                nns_url.clone(),
                AddCanisterRequest {
                    name: "message_canister".to_string(),
                    wasm_module: MESSAGE_CANISTER_WASM.to_vec(),
                    arg: vec![],
                    memory_allocation: None,
                    compute_allocation: None,
                    initial_cycles: 1 << 45,
                },
            )
            .await
            .into();

            let mcan = MessageCanister::from_canister_id(&agent, canister_principal);

            info!(
                logger,
                "Storing a message in canister with id {} at {}", canister_principal, nns_url
            );
            mcan.store_msg(init_msg.to_string()).await;

            canister_principal
        })
    } else {
        store_message_with_retries(
            &nns_node.get_public_url(),
            nns_node.effective_canister_id(),
            init_msg,
            &logger,
        )
    };

    let msg = "subnet recovery works!";
    if cfg.use_mainnet_state {
        assert_subnet_is_healthy_without_signature_verification(
            &nns_subnet.nodes().collect::<Vec<_>>(),
            &current_version,
            app_can_id,
            init_msg,
            msg,
            &logger,
        );
    } else {
        assert_subnet_is_healthy(
            &nns_subnet.nodes().collect::<Vec<_>>(),
            &current_version,
            app_can_id,
            init_msg,
            msg,
            &logger,
        );
    }

    // identifies the version of the replica after the recovery
    let upgrade_version = get_guestos_update_img_version();
    let upgrade_image_url = get_guestos_update_img_url();
    let upgrade_image_hash = get_guestos_update_img_sha256();
    let guest_launch_measurements = get_guestos_update_launch_measurements();
    std::fs::write(
        env.get_path(GUEST_LAUNCH_MEASUREMENTS_PATH),
        serde_json::to_string(&guest_launch_measurements).unwrap(),
    )
    .expect("Could not write guest launch measurements to file");
    if !cfg.add_upgrade_version {
        // If ic-recovery does not add the new version to the registry, then we must elect it now.
        if cfg.use_mainnet_state {
            block_on(ProposalWithMainnetState::bless_replica_version(
                &nns_node,
                &upgrade_version,
                &logger,
                upgrade_image_hash.clone(),
                Some(guest_launch_measurements),
                vec![upgrade_image_url.to_string()],
            ))
        } else {
            block_on(bless_replica_version(
                &nns_node,
                &upgrade_version,
                &logger,
                upgrade_image_hash.clone(),
                Some(guest_launch_measurements),
                vec![upgrade_image_url.to_string()],
            ))
        }
    }

    let output_dir = env.get_path("recovery_output");

    // Define faulty and healthy nodes
    let nns_nodes = nns_subnet.nodes().collect::<Vec<_>>();
    let f = (subnet_size - 1) / 3;
    assert!(
        f < cfg.num_broken_nodes && cfg.num_broken_nodes <= subnet_size,
        "Number of broken nodes must be between f+1 and the subnet size, but got {} broken nodes with f={}",
        cfg.num_broken_nodes,
        f
    );
    let faulty_nodes = &nns_nodes[..cfg.num_broken_nodes];
    let healthy_nodes = &nns_nodes[cfg.num_broken_nodes..];
    let maybe_healthy_node = healthy_nodes.first();
    info!(
        logger,
        "Selected faulty nodes: {:?}. Selected healthy nodes: {:?}",
        faulty_nodes.iter().map(|n| n.node_id).collect::<Vec<_>>(),
        healthy_nodes.iter().map(|n| n.node_id).collect::<Vec<_>>(),
    );
    assert!(
        cfg.break_dfinity_owned_node || cfg.num_broken_nodes < subnet_size,
        "Cannot break all nodes if the DFINITY-owned node is not broken"
    );
    let dfinity_owned_node = if cfg.break_dfinity_owned_node {
        faulty_nodes.last().unwrap()
    } else {
        healthy_nodes.first().unwrap()
    };
    info!(
        logger,
        "Selected DFINITY-owned NNS node: {} ({:?})",
        dfinity_owned_node.node_id,
        dfinity_owned_node.get_ip_addr()
    );

    // We could break all faulty nodes now. But if all nodes are broken, then the later call to
    // fetch nodes' metrics to determine which node to download the consensus pool from will fail,
    // since no nodes will answer.
    // To avoid that, in case all nodes are faulty, we break only `subnet_size - 1` nodes first,
    // effectively breaking the subnet, then fetch the metrics and determine the download pool, and
    // finally break the remaining node. Otherwise, we can break all faulty nodes at once.
    let (nodes_to_break_first, nodes_to_break_after) = if faulty_nodes.len() == subnet_size {
        faulty_nodes.split_at(subnet_size - 1)
    } else {
        (faulty_nodes, &[] as &[_])
    };
    break_nodes(nodes_to_break_first, &logger);

    if let Some(healthy_node) = maybe_healthy_node {
        assert_subnet_is_broken(
            &healthy_node.get_public_url(),
            app_can_id,
            msg,
            // When using mainnet state, queries (reading) will also fail because the root key has
            // changed. Thus, we do not check that the subnet works for reading in that case.
            /*can_read=*/
            !cfg.use_mainnet_state,
            &logger,
        );
    } else {
        // Special case if all nodes are broken: the subnet is broken even in read mode, see the
        // `false` parameter below.
        assert_subnet_is_broken(
            &dfinity_owned_node.get_public_url(), // This URL is not expected to be responsive
            app_can_id,
            msg,
            /*can_read=*/ false,
            &logger,
        );
    }

    // Download pool from the node with the highest certification share and CUP heights
    let NodeHeights {
        node: download_pool_node,
        cup: highest_cup,
        cert_share: highest_cert_share,
    } = node_with_highest_cup_and_cert_share_heights(&nns_subnet, &logger);
    info!(
        logger,
        "Selected node {} ({:?}) as download pool with certification share height {}",
        download_pool_node.node_id,
        download_pool_node.get_ip_addr(),
        highest_cert_share,
    );

    break_nodes(nodes_to_break_after, &logger);

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

    let recovery_dir = tempdir().unwrap().path().to_path_buf();
    let mut skipped_steps = vec![StepType::Cleanup]; // Skip Cleanup to keep the output directory
    if faulty_nodes.len() == subnet_size {
        // If all nodes are broken, the registry canister will not be able to respond to
        // `get_certified_changes_since` calls to initialize the local store of `ic-recovery`.
        // Thus, we need to manually download the local store of one of the nodes to pre-populate
        // the local store of `ic-recovery`.
        let local_store_path_src = PathBuf::from(IC_DATA_PATH)
            .join(IC_REGISTRY_LOCAL_STORE)
            .join("");
        let local_store_path_dest = recovery_dir
            .join(RECOVERY_DIRECTORY_NAME)
            .join("working_dir")
            .join("data")
            .join(IC_REGISTRY_LOCAL_STORE);

        std::fs::create_dir_all(&local_store_path_dest).unwrap();
        let ssh_helper = RecoverySshHelper::new(
            logger.clone(),
            RecoverySshUser::Backup,
            dfinity_owned_node.get_ip_addr(),
            false,
            Some(ssh_backup_priv_key_path.clone()),
        );

        info!(
            logger,
            "All nodes are broken, manually initialize the local store of ic-recovery by downloading it from node {}",
            dfinity_owned_node.node_id,
        );
        ssh_helper
            .rsync(
                ssh_helper.remote_path(&local_store_path_src),
                &local_store_path_dest,
            )
            .expect("Failed to initialize the local store of ic-recovery");

        // Skip validating the output if all nodes are broken, as in this case no replica will be
        // running to compare the heights to.
        skipped_steps.push(StepType::ValidateReplayOutput);
    }
    let recovery_args = RecoveryArgs {
        dir: recovery_dir,
        // If `maybe_healthy_node` is `None`, it means all nodes are broken, and the local store was
        // initialized above. In that case `ic-recovery` will not use `nns_url` and we can pass the
        // URL of whatever node.
        nns_url: maybe_healthy_node
            .unwrap_or(dfinity_owned_node)
            .get_public_url(),
        replica_version: None,
        admin_key_file: Some(ssh_admin_priv_key_path),
        test_mode: true,
        skip_prompts: true,
    };

    // Unlike during a production recovery using the CLI, here we already know all parameters ahead
    // of time.
    let subnet_args = NNSRecoverySameNodesArgs {
        subnet_id: nns_subnet.subnet_id,
        upgrade_version: Some(upgrade_version.clone()),
        upgrade_image_url: Some(upgrade_image_url),
        upgrade_image_hash: Some(upgrade_image_hash),
        upgrade_image_launch_measurements_path: Some(env.get_path(GUEST_LAUNCH_MEASUREMENTS_PATH)),
        add_and_bless_upgrade_version: Some(cfg.add_upgrade_version),
        replay_until_height: Some(highest_cert_share),
        download_pool_node: Some(download_pool_node.get_ip_addr()),
        admin_access_location: Some(DataLocation::Remote(dfinity_owned_node.get_ip_addr())),
        keep_downloaded_state: Some(false),
        // If the state height to download was computed to be 0 (i.e. the subnet stalled in its
        // first DKG interval), there is no checkpoint yet and we should actually not provide a
        // height to the recovery tool
        download_state_height: (highest_cup != 0).then_some(highest_cup),
        wait_for_cup_node: (!cfg.fix_dfinity_owned_node_like_np)
            .then_some(dfinity_owned_node.get_ip_addr()),
        backup_key_file: Some(ssh_backup_priv_key_path),
        output_dir: Some(output_dir.clone()),
        next_step: None,
        skip: Some(skipped_steps),
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
    if cfg.use_mainnet_state {
        assert_subnet_is_healthy_without_signature_verification(
            &nns_subnet.nodes().collect::<Vec<_>>(),
            &upgrade_version,
            app_can_id,
            msg,
            new_msg,
            &logger,
        );
    } else {
        assert_subnet_is_healthy(
            &nns_subnet.nodes().collect::<Vec<_>>(),
            &upgrade_version,
            app_can_id,
            msg,
            new_msg,
            &logger,
        );
    }
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

    // Run guestos-recovery-upgrader via limited-console's rbash-console
    // This tests the backup recovery path that node providers can use if the recovery TUI fails.
    //
    // Flow: SSH as admin → su to limited-console user → rbash-console → sudo recovery-launcher
    info!(
        logger,
        "Running guestos-recovery-upgrader via rbash-console on HostOS {} with version={}, recovery-hash-prefix={}",
        host.vm_name(),
        img_version,
        recovery_hash_prefix,
    );

    let recovery_upgrader_cmd =
        build_recovery_upgrader_run_command(img_version, recovery_hash_prefix).to_shell_string();

    // Note: keep in sync with the limited-console invocation in cpp/infogetty-cpp/infogetty.cc.
    // We need TWO "exit" commands: one to exit rbash, and one to exit limited-console's main loop.
    let script = format!(
        r#"echo -e "rbash-console\n{}\nexit\nexit" | sudo env -i TERM=linux su -s /opt/ic/bin/limited-console limited-console 2>&1"#,
        recovery_upgrader_cmd
    );

    host.block_on_bash_script_async(&script)
        .await
        .expect("Failed to run guestos-recovery-upgrader via rbash-console");

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
    // Set a 15-minute SSH timeout to detect when the node reboots and the TCP connection
    // hangs (e.g. abrupt reboot without clean TCP FIN). Without this, the SSH channel
    // can hang indefinitely waiting for data from the rebooted node.
    session.set_timeout(15 * 60 * 1000);
    info!(logger, "Executing local recovery command: \n{command}");
    node.block_on_bash_script_from_session(&session, &format!("{command} > /dev/null 2>&1"))
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

/// Code duplicate of rs/tests/consensus/utils/src/subnet.rs:assert_subnet_is_healthy
/// The difference is that we create an agent that does not verify query signatures.
/// To verify query response signatures from the root subnet, the agent requires the root subnet_id.
/// This is needed to retrieve the public keys of nodes within the root subnet.
/// Typically, the agent derives the root subnet_id from the root key. However, when using mainnet
/// state, the root key is different from the original one, but the subnet_id is reused.
/// So we create a new agent that does not verify the query response signatures for the time being.
/// A long-term solution involves modifying the agent to fetch the root subnet_id from the HTTP
/// status endpoint.
fn assert_subnet_is_healthy_without_signature_verification(
    subnet: &[IcNodeSnapshot],
    target_version: &ReplicaVersion,
    can_id: Principal,
    old_msg: &str,
    new_msg: &str,
    logger: &Logger,
) {
    info!(
        logger,
        "Confirm that ALL nodes are healthy and running on version {target_version}"
    );
    for node in subnet {
        assert_assigned_replica_version(node, target_version, logger.clone());
        info!(
            logger,
            "Healthy upgrade of assigned node {} to {}", node.node_id, target_version
        );
    }

    let node = &subnet[0];
    node.await_status_is_healthy().unwrap();
    // make sure that state sync is completed
    cert_state_makes_progress_with_retries(
        &node.get_public_url(),
        node.effective_canister_id(),
        logger,
        secs(600),
        secs(10),
    );

    let agent_bypass_signature = Agent::builder()
        .with_url(node.get_public_url())
        .with_verify_query_signatures(false)
        .build()
        .expect("Failed to create agent");
    block_on(agent_bypass_signature.fetch_root_key()).unwrap();

    let mcan = MessageCanister::from_canister_id(&agent_bypass_signature, can_id);

    info!(logger, "Ensure the old message is still readable");
    assert_eq!(
        block_on(mcan.read_msg()).expect("Received an empty message"),
        old_msg,
    );

    info!(logger, "Ensure that the subnet is accepting updates");
    block_on(mcan.store_msg(new_msg));

    // Wait until all nodes answer with the new message
    for node in subnet {
        let agent_bypass_signature = Agent::builder()
            .with_url(node.get_public_url())
            .with_verify_query_signatures(false)
            .build()
            .expect("Failed to create agent");
        let mcan = MessageCanister::from_canister_id(&agent_bypass_signature, can_id);

        block_on(retry_with_msg_async!(
            format!(
                "Waiting for node {} to have the new message readable",
                node.node_id
            ),
            &logger,
            secs(30),
            secs(5),
            || async {
                match mcan.try_read_msg().await {
                    Ok(Some(msg)) if msg == new_msg => Ok(()),
                    Ok(Some(msg)) => {
                        bail!(
                            "Received unexpected message: '{}', expected: '{}'",
                            msg,
                            new_msg
                        )
                    }
                    Ok(None) => {
                        bail!("Received an empty message")
                    }
                    Err(err) => {
                        bail!("Failed reading a message. Error: {}", err)
                    }
                }
            }
        ))
        .expect("Failed to read the new message from the node");
    }
}
