/* tag::catalog[]

Title:: Subnet Recovery Test (App subnet, same nodes + failover nodes, with and without chain keys, with and without version upgrade)

Goal::
Ensure that the subnet recovery of an app subnet works on the same nodes and on failover nodes.


Runbook::
. Deploy an IC with one "source" app subnet and one "app" app subnet (and some unassigned nodes
  in case of recovery on failover nodes).
. In case of chain keys: enable signing on the "source", create the "app" with the key, then disable
  signing on "source" and enable it on the "app" instead.
. Break (halt in case of no upgrade) the subnet.
. Make sure the subnet stalls.
. Propose readonly key and confirm ssh access.
. Download IC state of a node with max finalization height.
. Execute ic-replay to generate a recovery CUP.
. Optionally upgrade the subnet to a working replica.
. Submit a recovery CUP (using failover nodes and/or chain keys, if configured).
. Upload replayed state to a node.
. Unhalt the subnet.
. Ensure the subnet resumes.
. In case of chain keys: ensure that signing on the "app" is possible, and the key hasn't changed.

Success::
. "App" subnet is functional after the recovery.

end::catalog[] */

use crate::utils::{
    AdminAndUserKeys, Cursor, assert_subnet_is_broken, break_nodes,
    get_admin_keys_and_generate_readonly_keys, get_node_certification_share_height, halt_subnet,
    local::app_subnet_recovery_local_cli_args, node_with_highest_certification_share_height,
    remote_recovery, unhalt_subnet,
};
use anyhow::bail;
use canister_test::Canister;
use ic_base_types::NodeId;
use ic_consensus_system_test_utils::{
    node::assert_node_is_unassigned_with_ssh_session,
    rw_message::{install_nns_and_check_progress, store_message},
    set_sandbox_env_vars,
    ssh_access::{disable_ssh_access_to_node, wait_until_authentication_is_granted},
    subnet::{
        assert_subnet_is_healthy, disable_chain_key_on_subnet, enable_chain_key_signing_on_subnet,
    },
};
use ic_consensus_threshold_sig_system_test_utils::{
    await_pre_signature_stash_size, create_new_subnet_with_keys, make_key_ids_for_all_schemes,
    run_chain_key_signature_test, set_pre_signature_stash_size,
};
use ic_management_canister_types_private::MasterPublicKeyId;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_protobuf::types::v1 as pb;
use ic_recovery::{
    RecoveryArgs,
    admin_helper::AdminHelper,
    app_subnet_recovery::{AppSubnetRecovery, AppSubnetRecoveryArgs, StepType},
    get_node_metrics,
    util::DataLocation,
};
use ic_registry_subnet_features::{ChainKeyConfig, DEFAULT_ECDSA_MAX_QUEUE_SIZE, KeyConfig};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::constants::SSH_USERNAME;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env_api::scp_send_to;
use ic_system_test_driver::driver::{test_env::TestEnv, test_env_api::*};
use ic_system_test_driver::util::*;
use ic_types::{
    Height, ReplicaVersion, SubnetId,
    consensus::{CatchUpPackage, idkg::STORE_PRE_SIGNATURES_IN_STATE},
};
use prost::Message;
use slog::{Logger, info};
use std::{
    collections::{BTreeMap, HashMap},
    convert::TryFrom,
};
use std::{io::Read, time::Duration};
use std::{io::Write, path::Path};

const DKG_INTERVAL: u64 = 20;
const NNS_NODES: usize = 4;
const APP_NODES: usize = 4;
const UNASSIGNED_NODES: usize = 4;

const NNS_NODES_LARGE: usize = 40;
const APP_NODES_LARGE: usize = 37;
/// 40 dealings * 3 transcripts being reshared (high/local, high/remote, low/remote)
/// plus 4 to make checkpoint heights more predictable
const DKG_INTERVAL_LARGE: u64 = 124;

const IC_ADMIN_REMOTE_PATH: &str = "/var/lib/admin/ic-admin";

pub const CHAIN_KEY_SUBNET_RECOVERY_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const PRE_SIGNATURES_TO_CREATE_IN_ADVANCE: u32 = 5;

/// Setup an IC with the given number of unassigned nodes and
/// an app subnet with the given number of nodes
fn setup(env: TestEnv, cfg: SetupConfig) {
    let key_ids = make_key_ids_for_all_schemes();

    let key_configs = key_ids
        .into_iter()
        .map(|key_id| KeyConfig {
            max_queue_size: DEFAULT_ECDSA_MAX_QUEUE_SIZE,
            pre_signatures_to_create_in_advance: if key_id.requires_pre_signatures() {
                PRE_SIGNATURES_TO_CREATE_IN_ADVANCE
            } else {
                0
            },
            key_id,
        })
        .collect();

    let mut ic = InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(cfg.dkg_interval))
                .add_nodes(cfg.nns_nodes),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(cfg.dkg_interval))
                .add_nodes(cfg.source_nodes)
                .with_chain_key_config(ChainKeyConfig {
                    key_configs,
                    signature_request_timeout_ns: None,
                    idkg_key_rotation_period_ms: None,
                    max_parallel_pre_signature_transcripts_in_creation: None,
                }),
        )
        .with_unassigned_nodes(cfg.unassigned_nodes);
    if cfg.app_nodes > 0 {
        ic = ic.add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(cfg.dkg_interval))
                .add_nodes(cfg.app_nodes),
        );
    }

    ic.setup_and_start(&env)
        .expect("failed to setup IC under test");
    install_nns_and_check_progress(env.topology_snapshot());
}

struct SetupConfig {
    nns_nodes: usize,
    source_nodes: usize,
    app_nodes: usize,
    unassigned_nodes: usize,
    dkg_interval: u64,
}

pub fn setup_large_chain_keys(env: TestEnv) {
    setup(
        env,
        SetupConfig {
            nns_nodes: NNS_NODES_LARGE,
            source_nodes: APP_NODES_LARGE,
            app_nodes: 0,
            unassigned_nodes: APP_NODES_LARGE,
            dkg_interval: DKG_INTERVAL_LARGE,
        },
    );
}

pub fn setup_same_nodes_chain_keys(env: TestEnv) {
    setup(
        env,
        SetupConfig {
            nns_nodes: NNS_NODES,
            source_nodes: APP_NODES,
            app_nodes: 0,
            unassigned_nodes: APP_NODES,
            dkg_interval: DKG_INTERVAL,
        },
    );
}

pub fn setup_failover_nodes_chain_keys(env: TestEnv) {
    setup(
        env,
        SetupConfig {
            nns_nodes: NNS_NODES,
            source_nodes: APP_NODES,
            app_nodes: 0,
            unassigned_nodes: APP_NODES + UNASSIGNED_NODES,
            dkg_interval: DKG_INTERVAL,
        },
    );
}

pub fn setup_same_nodes(env: TestEnv) {
    setup(
        env,
        SetupConfig {
            nns_nodes: NNS_NODES,
            source_nodes: APP_NODES,
            app_nodes: APP_NODES,
            unassigned_nodes: 0,
            dkg_interval: DKG_INTERVAL,
        },
    );
}

pub fn setup_failover_nodes(env: TestEnv) {
    setup(
        env,
        SetupConfig {
            nns_nodes: NNS_NODES,
            source_nodes: APP_NODES,
            app_nodes: APP_NODES,
            unassigned_nodes: UNASSIGNED_NODES,
            dkg_interval: DKG_INTERVAL,
        },
    );
}

struct TestConfig {
    subnet_size: usize,
    upgrade: bool,
    chain_key: bool,
    corrupt_cup: bool,
    local_recovery: bool,
}

pub fn test_with_chain_keys(env: TestEnv) {
    app_subnet_recovery_test(
        env,
        TestConfig {
            subnet_size: APP_NODES,
            upgrade: true,
            chain_key: true,
            corrupt_cup: false,
            local_recovery: false,
        },
    );
}

pub fn test_without_chain_keys(env: TestEnv) {
    app_subnet_recovery_test(
        env,
        TestConfig {
            subnet_size: APP_NODES,
            upgrade: true,
            chain_key: false,
            corrupt_cup: false,
            local_recovery: false,
        },
    );
}

pub fn test_no_upgrade_with_chain_keys(env: TestEnv) {
    // Test the corrupt CUP case only when recovering an app subnet with chain keys without upgrade
    let corrupt_cup = env.topology_snapshot().unassigned_nodes().count() > 0;
    app_subnet_recovery_test(
        env,
        TestConfig {
            subnet_size: APP_NODES,
            upgrade: false,
            chain_key: true,
            corrupt_cup,
            local_recovery: false,
        },
    );
}

pub fn test_large_with_chain_keys(env: TestEnv) {
    app_subnet_recovery_test(
        env,
        TestConfig {
            subnet_size: APP_NODES_LARGE,
            upgrade: false,
            chain_key: true,
            corrupt_cup: false,
            local_recovery: false,
        },
    );
}

pub fn test_no_upgrade_without_chain_keys(env: TestEnv) {
    app_subnet_recovery_test(
        env,
        TestConfig {
            subnet_size: APP_NODES,
            upgrade: false,
            chain_key: false,
            corrupt_cup: false,
            local_recovery: false,
        },
    );
}

pub fn test_no_upgrade_without_chain_keys_local(env: TestEnv) {
    app_subnet_recovery_test(
        env,
        TestConfig {
            subnet_size: APP_NODES,
            upgrade: false,
            chain_key: false,
            corrupt_cup: false,
            local_recovery: true,
        },
    );
}

fn app_subnet_recovery_test(env: TestEnv, cfg: TestConfig) {
    let logger = env.logger();

    if cfg.local_recovery {
        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe {
            std::env::set_var(
                "IC_ADMIN_BIN",
                get_dependency_path_from_env("IC_ADMIN_PATH"),
            )
        };
    }

    let AdminAndUserKeys {
        ssh_admin_priv_key_path,
        admin_auth,
        ssh_user_priv_key_path: ssh_readonly_priv_key_path,
        ssh_user_pub_key: ssh_readonly_pub_key,
        ..
    } = get_admin_keys_and_generate_readonly_keys(&env);
    // If the latest CUP is corrupted we can't deploy read-only access
    let ssh_readonly_pub_key_deployed = (!cfg.corrupt_cup).then_some(ssh_readonly_pub_key);

    let current_version = get_guestos_img_version();
    info!(logger, "Current GuestOS version: {:?}", current_version);

    let topology_snapshot = env.topology_snapshot();

    // Choose a node from the nns subnet
    let nns_node = get_nns_node(&topology_snapshot);
    info!(
        logger,
        "Selected NNS node: {} ({:?})",
        nns_node.node_id,
        nns_node.get_ip_addr()
    );
    let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);

    let agent = nns_node.with_default_agent(|agent| async move { agent });
    let nns_canister = block_on(MessageCanister::new(
        &agent,
        nns_node.effective_canister_id(),
    ));

    // The first application subnet encountered during iteration is the source subnet because it was inserted first.
    let source_subnet_id = env
        .topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("there is no source subnet")
        .subnet_id;

    let create_new_subnet = !topology_snapshot
        .subnets()
        .any(|s| s.subnet_type() == SubnetType::Application && s.subnet_id != source_subnet_id);
    assert!(cfg.chain_key >= create_new_subnet);

    let key_ids = make_key_ids_for_all_schemes();
    let chain_key_pub_keys = cfg.chain_key.then(|| {
        info!(
            logger,
            "Chain key flag set, creating key on the source subnet."
        );
        if create_new_subnet {
            info!(
                logger,
                "No app subnet found, creating a new one with the Chain keys."
            );
            enable_chain_key_on_new_subnet(
                &env,
                &nns_node,
                &nns_canister,
                source_subnet_id,
                cfg.subnet_size,
                current_version.clone(),
                key_ids.clone(),
                &logger,
            )
        } else {
            enable_chain_key_signing_on_subnet(
                &nns_node,
                &nns_canister,
                source_subnet_id,
                key_ids.clone(),
                &logger,
            )
        }
    });

    let app_subnet = env
        .topology_snapshot()
        .subnets()
        .find(|subnet| {
            subnet.subnet_type() == SubnetType::Application && subnet.subnet_id != source_subnet_id
        })
        .expect("there is no application subnet");
    let mut app_nodes = app_subnet.nodes();
    let download_state_node = app_nodes.next().expect("there is no application node");
    info!(
        logger,
        "Selected random application subnet node to download the state from: {} ({:?})",
        download_state_node.node_id,
        download_state_node.get_ip_addr()
    );

    info!(logger, "Ensure app subnet is functional");
    let init_msg = "subnet recovery works!";
    let app_can_id = store_message(
        &download_state_node.get_public_url(),
        download_state_node.effective_canister_id(),
        init_msg,
        &logger,
    );
    let msg = "subnet recovery works again!";
    assert_subnet_is_healthy(
        &app_subnet.nodes().collect::<Vec<_>>(),
        &current_version,
        app_can_id,
        init_msg,
        msg,
        &logger,
    );

    print_source_and_app_and_unassigned_nodes(&env, &logger, source_subnet_id);

    // Only check that the pre-signature stash is purged in one test case (chain keys + corrupt CUP)
    let check_pre_signature_stash_is_purged =
        cfg.chain_key && cfg.corrupt_cup && STORE_PRE_SIGNATURES_IN_STATE;
    if check_pre_signature_stash_is_purged {
        let idkg_keys = key_ids
            .iter()
            .filter(|k| k.is_idkg_key())
            .cloned()
            .collect::<Vec<_>>();
        // The stash size should be 5 initially
        await_pre_signature_stash_size(
            &app_subnet,
            PRE_SIGNATURES_TO_CREATE_IN_ADVANCE as usize,
            idkg_keys.as_slice(),
            &logger,
        );
        // Turn off pre-signature generation on both subnets, so we can check that the stash is purged during recovery
        info!(logger, "Disabling pre-signature generation");
        block_on(set_pre_signature_stash_size(
            &governance,
            app_subnet.subnet_id,
            key_ids.as_slice(),
            /* max_parallel_pre_signatures */ 0,
            /* max_stash_size */ PRE_SIGNATURES_TO_CREATE_IN_ADVANCE,
            /* key_rotation_period */ None,
            &logger,
        ));
        block_on(set_pre_signature_stash_size(
            &governance,
            source_subnet_id,
            key_ids.as_slice(),
            /* max_parallel_pre_signatures */ 0,
            /* max_stash_size */ PRE_SIGNATURES_TO_CREATE_IN_ADVANCE,
            /* key_rotation_period */ None,
            &logger,
        ));
    };

    let unassigned_nodes_ids = env
        .topology_snapshot()
        .unassigned_nodes()
        .map(|n| n.node_id)
        .collect::<Vec<NodeId>>();

    let maybe_upgrade_version = (cfg.upgrade && unassigned_nodes_ids.is_empty())
        .then_some(get_guestos_update_img_version());

    let recovery_dir = get_dependency_path("rs/tests");
    let binaries_dir = recovery_dir.join("recovery/binaries");
    set_sandbox_env_vars(binaries_dir.clone());

    let app_subnet_id = app_subnet.subnet_id;
    let admin_helper = AdminHelper::new(
        match std::env::var("IC_ADMIN_PATH") {
            Ok(path) => get_dependency_path(path),
            Err(_) => binaries_dir.join("ic-admin"),
        },
        nns_node.get_public_url(),
        None,
    );
    if cfg.upgrade {
        // Break f+1 nodes
        let f = (cfg.subnet_size - 1) / 3;
        break_nodes(&app_nodes.take(f + 1).collect::<Vec<_>>(), &logger);
    } else {
        halt_subnet(
            &admin_helper,
            &download_state_node,
            app_subnet_id,
            &[],
            &logger,
        )
    }
    assert_subnet_is_broken(
        &download_state_node.get_public_url(),
        app_can_id,
        msg,
        true,
        &logger,
    );

    // If there are unassigned nodes, we are in a failover nodes scenario. Otherwise, just use the
    // same node that we downloaded the state from.
    let upload_node = env
        .topology_snapshot()
        .unassigned_nodes()
        .next()
        .unwrap_or_else(|| download_state_node.clone());

    let (download_pool_node, replay_height, admin_nodes) = if ssh_readonly_pub_key_deployed
        .is_some()
    {
        // If we can deploy read-only access to the subnet, then we can download the consensus
        // poll from the node with highest certification, and we only need admin access on the
        // upload node to upload the state

        let (download_pool_node, highest_cert_share) =
            node_with_highest_certification_share_height(&app_subnet, &logger);
        info!(
            logger,
            "Selected node {} ({:?}) as download pool with certification share height {}",
            download_pool_node.node_id,
            download_pool_node.get_ip_addr(),
            highest_cert_share,
        );
        let admins = vec![&upload_node];

        (download_pool_node, highest_cert_share, admins)
    } else {
        // If we cannot deploy read-only access to the subnet, this would mean that the CUP is
        // corrupted on enough nodes to stall the subnet which, in practice, should happen only
        // during upgrades. In that case, all nodes stalled at the same height (the upgrade height)
        // and the node with admin access (if not lagging behind) will have the highest
        // certification height (and thus state), which can be used to download both the consensus
        // pool and the state. Though, this means that this node requires admin access to read them
        // without a readonly key.
        //
        // Note: inside this system test, it is not the case that all nodes stalled at the same
        // height, and it is not the case that they stalled at an upgrade height. We would normally
        // not need to replay anything (because it would be an upgrade height), but we need here,
        // and since we do not break `download_state_node`, we know that it will have the highest
        // certification height available in the subnet.

        let download_pool_node = download_state_node.clone();
        info!(
            logger,
            "Using node {} ({:?}) both as download pool and download state node as read-only access cannot be deployed",
            download_pool_node.node_id,
            download_pool_node.get_ip_addr(),
        );
        let node_cert_share =
            get_node_certification_share_height(&download_state_node, &logger).unwrap();
        let admins = vec![&upload_node, &download_state_node];

        (download_pool_node, node_cert_share, admins)
    };

    if cfg.corrupt_cup {
        info!(logger, "Corrupting the latest CUP on all nodes");
        corrupt_latest_cup(&app_subnet, &admin_helper, &logger);
        assert_subnet_is_broken(
            &download_state_node.get_public_url(),
            app_can_id,
            msg,
            false,
            &logger,
        );
    }

    // Mirror production setup by removing admin SSH access from all nodes except the ones we need
    // for recovery.
    info!(
        logger,
        "Admin nodes: {:?}. Removing admin SSH access from all other nodes",
        admin_nodes.iter().map(|n| n.node_id).collect::<Vec<_>>()
    );
    let mut admin_ssh_sessions = HashMap::new();
    for node in app_subnet
        .nodes()
        .filter(|n| !admin_nodes.iter().any(|an| an.node_id == n.node_id))
    {
        info!(
            logger,
            "Removing admin SSH access from node {} ({:?})",
            node.node_id,
            node.get_ip_addr()
        );

        let session =
            disable_ssh_access_to_node(&logger, &node, SSH_USERNAME, &admin_auth).unwrap();

        admin_ssh_sessions.insert(node.node_id, session);
    }
    // Ensure we can still SSH into admin nodes
    for node in admin_nodes {
        wait_until_authentication_is_granted(
            &logger,
            &node.get_ip_addr(),
            SSH_USERNAME,
            &admin_auth,
        );
    }

    let recovery_args = RecoveryArgs {
        dir: recovery_dir,
        nns_url: nns_node.get_public_url(),
        replica_version: Some(current_version.clone()),
        admin_key_file: Some(ssh_admin_priv_key_path),
        test_mode: true,
        skip_prompts: true,
        use_local_binaries: cfg.local_recovery,
    };

    // Unlike during a production recovery using the CLI, here we already know all parameters ahead
    // of time.
    let subnet_args = AppSubnetRecoveryArgs {
        subnet_id: app_subnet_id,
        upgrade_version: maybe_upgrade_version.clone(),
        upgrade_image_url: Some(get_guestos_update_img_url()),
        upgrade_image_hash: Some(get_guestos_update_img_sha256()),
        replacement_nodes: Some(unassigned_nodes_ids.clone()),
        replay_until_height: Some(replay_height),
        readonly_pub_key: ssh_readonly_pub_key_deployed,
        readonly_key_file: Some(ssh_readonly_priv_key_path),
        download_pool_node: Some(download_pool_node.get_ip_addr()),
        download_state_method: Some(DataLocation::Remote(download_state_node.get_ip_addr())),
        keep_downloaded_state: Some(cfg.chain_key),
        upload_method: Some(DataLocation::Remote(upload_node.get_ip_addr())),
        wait_for_cup_node: Some(upload_node.get_ip_addr()),
        chain_key_subnet_id: cfg.chain_key.then_some(source_subnet_id),
        next_step: None,
        // Skip validating the output if the CUP is corrupted, as in this case no replica will be
        // running to compare the heights to.
        skip: cfg
            .corrupt_cup
            .then_some(vec![StepType::ValidateReplayOutput]),
    };

    info!(
        logger,
        "Starting recovery of subnet {} with {:?}",
        app_subnet_id.to_string(),
        &subnet_args
    );

    let subnet_recovery = AppSubnetRecovery::new(
        env.logger(),
        recovery_args,
        /*neuron_args=*/ None,
        subnet_args,
    );

    if cfg.local_recovery {
        info!(logger, "Performing a local node recovery");
        local_recovery(&download_state_node, subnet_recovery, &logger);
    } else {
        info!(logger, "Performing remote recovery");
        remote_recovery(subnet_recovery, &logger);
    }
    info!(
        logger,
        "Recovery coordinator successfully went through all steps of the recovery tool"
    );

    info!(logger, "Blocking for newer registry version");
    let topology_snapshot = block_on(env.topology_snapshot().block_for_newer_registry_version())
        .expect("Could not block for newer registry version");

    print_source_and_app_and_unassigned_nodes(&env, &logger, source_subnet_id);

    let all_app_nodes: Vec<IcNodeSnapshot> = topology_snapshot
        .subnets()
        .find(|subnet| {
            subnet.subnet_type() == SubnetType::Application && subnet.subnet_id != source_subnet_id
        })
        .expect("there is no application subnet")
        .nodes()
        .collect();

    let mut old_unassigned_ids = unassigned_nodes_ids;
    if !old_unassigned_ids.is_empty() {
        old_unassigned_ids.sort();
        let mut assigned_nodes_ids: Vec<NodeId> = all_app_nodes.iter().map(|n| n.node_id).collect();
        assigned_nodes_ids.sort();
        assert_eq!(
            old_unassigned_ids, assigned_nodes_ids,
            "Previously unassigned nodes should now be assigned"
        );
    }

    let new_msg = "subnet recovery still works!";
    assert_subnet_is_healthy(
        &all_app_nodes,
        &maybe_upgrade_version.unwrap_or(current_version),
        app_can_id,
        msg,
        new_msg,
        &logger,
    );

    for node in all_app_nodes {
        let height = block_on(get_node_metrics(&logger, &node.get_ip_addr()))
            .unwrap()
            .finalization_height;
        info!(
            logger,
            "Node {} finalization height: {:?}", node.node_id, height
        );
        assert!(height > Height::from(1000));
    }

    if check_pre_signature_stash_is_purged {
        info!(logger, "Checking that the pre-signature stash is purged");
        let idkg_keys = key_ids
            .iter()
            .filter(|k| k.is_idkg_key())
            .cloned()
            .collect::<Vec<_>>();
        // After recovery the stash should be purged
        await_pre_signature_stash_size(&app_subnet, 0, idkg_keys.as_slice(), &logger);
        // Re-enable pre-signature generation
        block_on(set_pre_signature_stash_size(
            &governance,
            app_subnet.subnet_id,
            key_ids.as_slice(),
            /* max_parallel_pre_signatures */ 10,
            /* max_stash_size */ PRE_SIGNATURES_TO_CREATE_IN_ADVANCE,
            /* key_rotation_period */ None,
            &logger,
        ));
    }

    if cfg.chain_key {
        if !create_new_subnet {
            disable_chain_key_on_subnet(
                &nns_node,
                source_subnet_id,
                &nns_canister,
                key_ids.clone(),
                &logger,
            );
            let app_keys = enable_chain_key_signing_on_subnet(
                &nns_node,
                &nns_canister,
                app_subnet_id,
                key_ids.clone(),
                &logger,
            );
            assert_eq!(chain_key_pub_keys.clone().unwrap(), app_keys)
        }

        for (key_id, chain_key_pub_key) in chain_key_pub_keys.unwrap() {
            run_chain_key_signature_test(&nns_canister, &logger, &key_id, chain_key_pub_key);
        }
    }

    info!(
        logger,
        "Making sure unassigned nodes deleted their state..."
    );
    topology_snapshot.unassigned_nodes().for_each(|n| {
        assert_node_is_unassigned_with_ssh_session(&n, admin_ssh_sessions.get(&n.node_id), &logger);
    });
}

fn local_recovery(node: &IcNodeSnapshot, subnet_recovery: AppSubnetRecovery, logger: &Logger) {
    let session = node.block_on_ssh_session().unwrap();
    let node_id = node.node_id;
    let node_ip = node.get_ip_addr();
    info!(
        logger,
        "Copying ic-admin to node {node_id} with IP {node_ip} such that ic-recovery can execute it ..."
    );
    scp_send_to(
        logger.clone(),
        &session,
        &get_dependency_path_from_env("IC_ADMIN_PATH"),
        Path::new(IC_ADMIN_REMOTE_PATH),
        0o755,
    );

    let command_args = app_subnet_recovery_local_cli_args(node, &session, &subnet_recovery, logger);
    let command = format!(
        r#"IC_ADMIN_BIN="{IC_ADMIN_REMOTE_PATH}" /opt/ic/bin/ic-recovery \
        {command_args}
        "#
    );

    info!(logger, "Executing local recovery command: \n{command}");
    match node.block_on_bash_script_from_session(&session, &command) {
        Ok(ret) => info!(logger, "Finished local recovery: \n{ret}"),
        Err(err) => panic!("Local recovery failed: \n{err}"),
    }
}

// Corrupt the latest cup of all subnet nodes by change the CUP's replica version field.
// This will change the hash of the block, thus making the CUP non-deserializable.
fn corrupt_latest_cup(subnet: &SubnetSnapshot, admin_helper: &AdminHelper, logger: &Logger) {
    const CUP_PATH: &str = "/var/lib/ic/data/cups/cup.types.v1.CatchUpPackage.pb";
    const NEW_CUP_PATH: &str = "/var/lib/ic/data/cups/new_cup.pb";

    let app_node = subnet.nodes().next().unwrap();
    let session = app_node.block_on_ssh_session().unwrap();

    info!(
        logger,
        "Setting journal cursor on node {:?}",
        app_node.get_ip_addr()
    );
    let message_str = app_node
        .block_on_bash_script_from_session(
            &session,
            "journalctl -n1 -o json --output-fields='__CURSOR'",
        )
        .expect("journal message");
    let message: Cursor = serde_json::from_str(&message_str).expect("JSON journal message");

    info!(logger, "Reading CUP from node {:?}", app_node.get_ip_addr());
    let (mut channel, _) = session.scp_recv(Path::new(CUP_PATH)).unwrap();
    let mut bytes = Vec::new();
    channel.read_to_end(&mut bytes).unwrap();

    info!(logger, "Modifying CUP replica version");
    let proto_cup = pb::CatchUpPackage::decode(bytes.as_slice()).unwrap();
    let mut cup = CatchUpPackage::try_from(&proto_cup).unwrap();
    cup.content.block.as_mut().version = ReplicaVersion::try_from("invalid_version").unwrap();
    let bytes = pb::CatchUpPackage::from(cup).encode_to_vec();

    for node in subnet.nodes() {
        info!(
            logger,
            "Uploading corrupted CUP of length {} to node {:?}",
            bytes.len(),
            node.get_ip_addr()
        );
        let session = node.block_on_ssh_session().unwrap();
        app_node
            .block_on_bash_script_from_session(
                &session,
                &format!("sudo touch {NEW_CUP_PATH}; sudo chmod a+rw {NEW_CUP_PATH}"),
            )
            .expect("touch");
        let mut channel = session
            .scp_send(Path::new(NEW_CUP_PATH), 0o666, bytes.len() as u64, None)
            .unwrap();
        channel.write_all(&bytes).unwrap();

        info!(logger, "Restarting node {:?}", node.get_ip_addr());
        app_node
            .block_on_bash_script_from_session(
                &session,
                &format!("sudo mv {NEW_CUP_PATH} {CUP_PATH}; sudo systemctl restart ic-replica"),
            )
            .expect("restart");
    }

    ic_system_test_driver::retry_with_msg!(
        "check if cup is corrupted",
        logger.clone(),
        secs(120),
        secs(10),
        || {
            let res = app_node.block_on_bash_script_from_session(
                &session,
                &format!(
                    "journalctl --after-cursor='{}' | grep -c 'Failed to deserialize CatchUpPackage'",
                    message.cursor
                ),
            );
            if res.is_ok_and( |r| r.trim().parse::<i32>().unwrap() > 0) {
                Ok(())
            } else {
                bail!("Did not find log entry that cup is corrupted.")
            }
        }
    )
    .expect("Failed to detect broken subnet.");

    unhalt_subnet(admin_helper, subnet.subnet_id, &[], logger);
}

/// Print ID and IP of the source subnet, the first app subnet found that is not the source, and all
/// unassigned nodes.
fn print_source_and_app_and_unassigned_nodes(
    env: &TestEnv,
    logger: &Logger,
    source_subnet_id: SubnetId,
) {
    let topology_snapshot = env.topology_snapshot();

    info!(logger, "Source nodes:");
    topology_snapshot
        .subnets()
        .find(|subnet| subnet.subnet_id == source_subnet_id)
        .unwrap()
        .nodes()
        .for_each(|n| {
            info!(logger, "S: {}, ip: {}", n.node_id, n.get_ip_addr());
        });

    info!(logger, "App nodes:");
    topology_snapshot
        .subnets()
        .find(|subnet| {
            subnet.subnet_type() == SubnetType::Application && subnet.subnet_id != source_subnet_id
        })
        .unwrap()
        .nodes()
        .for_each(|n| {
            info!(logger, "A: {}, ip: {}", n.node_id, n.get_ip_addr());
        });

    info!(logger, "Unassigned nodes:");
    topology_snapshot.unassigned_nodes().for_each(|n| {
        info!(logger, "U: {}, ip: {}", n.node_id, n.get_ip_addr());
    });
}

/// Create a chain key on the source subnet using the given NNS node, then
/// create a new subnet of the given size initialized with the chain key.
/// Disable signing on the source subnet and enable it on the new one.
/// Assert that the key stays the same regardless of whether signing
/// is enabled on the source subnet or the new one.
/// Return the public key for the given canister.
fn enable_chain_key_on_new_subnet(
    env: &TestEnv,
    nns_node: &IcNodeSnapshot,
    canister: &MessageCanister,
    source_subnet_id: SubnetId,
    subnet_size: usize,
    replica_version: ReplicaVersion,
    key_ids: Vec<MasterPublicKeyId>,
    logger: &Logger,
) -> BTreeMap<MasterPublicKeyId, Vec<u8>> {
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);
    let snapshot = env.topology_snapshot();
    let registry_version = snapshot.get_registry_version();

    info!(logger, "Enabling signing on the source subnet.");
    let source_keys = enable_chain_key_signing_on_subnet(
        nns_node,
        canister,
        source_subnet_id,
        key_ids.clone(),
        logger,
    );
    let snapshot =
        block_on(snapshot.block_for_min_registry_version(registry_version.increment())).unwrap();
    let registry_version = snapshot.get_registry_version();

    let unassigned_node_ids = snapshot
        .unassigned_nodes()
        .take(subnet_size)
        .map(|n| n.node_id)
        .collect();

    info!(logger, "Creating new subnet with keys.");
    block_on(create_new_subnet_with_keys(
        &governance,
        unassigned_node_ids,
        key_ids
            .iter()
            .cloned()
            .map(|key_id| (key_id, source_subnet_id.get()))
            .collect(),
        replica_version,
        logger,
    ));

    let snapshot =
        block_on(snapshot.block_for_min_registry_version(registry_version.increment())).unwrap();

    let app_subnet = snapshot
        .subnets()
        .find(|subnet| {
            subnet.subnet_type() == SubnetType::Application && subnet.subnet_id != source_subnet_id
        })
        .expect("there is no application subnet");

    app_subnet.nodes().for_each(|n| {
        n.await_status_is_healthy()
            .expect("Timeout while waiting for all nodes to be healthy");
    });

    info!(logger, "Disabling signing on the source subnet.");
    disable_chain_key_on_subnet(
        nns_node,
        source_subnet_id,
        canister,
        key_ids.clone(),
        logger,
    );
    let app_keys = enable_chain_key_signing_on_subnet(
        nns_node,
        canister,
        app_subnet.subnet_id,
        key_ids,
        logger,
    );

    assert_eq!(app_keys, source_keys);
    app_keys
}
