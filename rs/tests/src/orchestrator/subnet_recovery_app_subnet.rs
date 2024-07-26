/* tag::catalog[]

Title:: Subnet Recovery Test (App subnet, same nodes + failover nodes, with and without ECDSA, with and without version upgrade)

Goal::
Ensure that the subnet recovery of an app subnet works on the same nodes and on failover nodes.


Runbook::
. Deploy an IC with one app subnet (and some unassigned nodes in case of recovery on failover nodes).
. In case of ECDSA: enable signing on NNS, create the app subnet with the key, then disable signing
  on NNS and enable it on the app subnet instead.
. Break (halt in case of no upgrade) the subnet.
. Make sure the subnet stalls.
. Propose readonly key and confirm ssh access.
. Download IC state of a node with max finalization height.
. Execute ic-replay to generate a recovery CUP.
. Optionally upgrade the subnet to a working replica.
. Submit a recovery CUP (using failover nodes and/or ECDSA, if configured).
. Upload replayed state to a node.
. Unhalt the subnet.
. Ensure the subnet resumes.
. In case of ECDSA: ensure that signing on the app subnet is possible, and the key hasn't changed.

Success::
. App subnet is functional after the recovery.

end::catalog[] */

use anyhow::bail;
use candid::Principal;
use ic_base_types::NodeId;
use ic_consensus_system_test_utils::{
    rw_message::{
        can_read_msg, cannot_store_msg, cert_state_makes_progress_with_retries,
        install_nns_and_check_progress, store_message,
    },
    set_sandbox_env_vars,
    ssh_access::execute_bash_command,
    subnet::{
        assert_subnet_is_healthy, disable_chain_key_on_subnet, enable_chain_key_on_new_subnet,
        enable_chain_key_signing_on_subnet,
    },
};
use ic_consensus_threshold_sig_system_test_utils::{
    make_key_ids_for_all_schemes, run_chain_key_signature_test,
};
use ic_recovery::{
    app_subnet_recovery::{AppSubnetRecovery, AppSubnetRecoveryArgs},
    steps::Step,
    NodeMetrics, Recovery, RecoveryArgs,
};
use ic_recovery::{file_sync_helper, get_node_metrics};
use ic_registry_subnet_features::{ChainKeyConfig, KeyConfig, DEFAULT_ECDSA_MAX_QUEUE_SIZE};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::constants::SSH_USERNAME;
use ic_system_test_driver::driver::driver_setup::{
    SSH_AUTHORIZED_PRIV_KEYS_DIR, SSH_AUTHORIZED_PUB_KEYS_DIR,
};
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::{test_env::TestEnv, test_env_api::*};
use ic_system_test_driver::util::*;
use ic_types::{Height, ReplicaVersion, SubnetId};
use serde::{Deserialize, Serialize};
use slog::{info, Logger};
use std::convert::TryFrom;
use std::time::Duration;
use url::Url;

const DKG_INTERVAL: u64 = 9;
const APP_NODES: usize = 3;
const UNASSIGNED_NODES: usize = 3;

const DKG_INTERVAL_LARGE: u64 = 99;
const NNS_NODES_LARGE: usize = 40;
const APP_NODES_LARGE: usize = 37;

pub const CHAIN_KEY_SUBNET_RECOVERY_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Setup an IC with the given number of unassigned nodes and
/// an app subnet with the given number of nodes
pub fn setup(
    nns_nodes: Option<usize>,
    app_nodes: usize,
    unassigned_nodes: usize,
    dkg_interval: u64,
    env: TestEnv,
) {
    let mut nns = if let Some(nns_nodes) = nns_nodes {
        Subnet::new(SubnetType::System)
            .with_dkg_interval_length(Height::from(dkg_interval))
            .add_nodes(nns_nodes)
    } else {
        Subnet::fast_single_node(SubnetType::System)
            .with_dkg_interval_length(Height::from(dkg_interval))
    };
    let key_ids = make_key_ids_for_all_schemes();
    let key_configs = key_ids
        .into_iter()
        .map(|key_id| KeyConfig {
            key_id,
            max_queue_size: DEFAULT_ECDSA_MAX_QUEUE_SIZE,
            pre_signatures_to_create_in_advance: 3,
        })
        .collect();
    nns = nns.with_chain_key_config(ChainKeyConfig {
        key_configs,
        signature_request_timeout_ns: None,
        idkg_key_rotation_period_ms: None,
    });

    let mut ic = InternetComputer::new()
        .add_subnet(nns)
        .with_unassigned_nodes(unassigned_nodes);
    if app_nodes > 0 {
        ic = ic.add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(dkg_interval))
                .add_nodes(app_nodes),
        );
    }

    ic.setup_and_start(&env)
        .expect("failed to setup IC under test");
    install_nns_and_check_progress(env.topology_snapshot());
}

pub fn setup_large_tecdsa(env: TestEnv) {
    setup(
        Some(NNS_NODES_LARGE),
        0,
        APP_NODES_LARGE,
        DKG_INTERVAL_LARGE,
        env,
    );
}

pub fn setup_same_nodes_tecdsa(env: TestEnv) {
    setup(None, 0, APP_NODES, DKG_INTERVAL, env);
}

pub fn setup_failover_nodes_tecdsa(env: TestEnv) {
    setup(None, 0, APP_NODES + UNASSIGNED_NODES, DKG_INTERVAL, env);
}

pub fn setup_same_nodes(env: TestEnv) {
    setup(None, APP_NODES, 0, DKG_INTERVAL, env);
}

pub fn setup_failover_nodes(env: TestEnv) {
    setup(None, APP_NODES, UNASSIGNED_NODES, DKG_INTERVAL, env);
}

pub fn test_with_tecdsa(env: TestEnv) {
    app_subnet_recovery_test(env, APP_NODES, true, true);
}

pub fn test_without_tecdsa(env: TestEnv) {
    app_subnet_recovery_test(env, APP_NODES, true, false);
}

pub fn test_no_upgrade_with_tecdsa(env: TestEnv) {
    app_subnet_recovery_test(env, APP_NODES, false, true);
}

pub fn test_large_with_tecdsa(env: TestEnv) {
    app_subnet_recovery_test(env, APP_NODES_LARGE, false, true);
}

pub fn test_no_upgrade_without_tecdsa(env: TestEnv) {
    app_subnet_recovery_test(env, APP_NODES, false, false);
}

pub fn app_subnet_recovery_test(env: TestEnv, subnet_size: usize, upgrade: bool, chain_key: bool) {
    let logger = env.logger();

    let master_version = env.get_initial_replica_version().unwrap();
    info!(logger, "IC_VERSION_ID: {master_version:?}");
    let topology_snapshot = env.topology_snapshot();

    // choose a node from the nns subnet
    let nns_node = get_nns_node(&topology_snapshot);
    info!(
        logger,
        "Selected NNS node: {} ({:?})",
        nns_node.node_id,
        nns_node.get_ip_addr()
    );

    let agent = nns_node.with_default_agent(|agent| async move { agent });
    let nns_canister = block_on(MessageCanister::new(
        &agent,
        nns_node.effective_canister_id(),
    ));

    let root_subnet_id = topology_snapshot.root_subnet_id();

    let create_new_subnet = !topology_snapshot
        .subnets()
        .any(|s| s.subnet_type() == SubnetType::Application);
    assert!(chain_key >= create_new_subnet);

    let key_ids = make_key_ids_for_all_schemes();
    let chain_key_pub_keys = chain_key.then(|| {
        info!(logger, "Chain key flag set, creating key on NNS.");
        if create_new_subnet {
            info!(
                logger,
                "No app subnet found, creating a new one with the Chain keys."
            );
            enable_chain_key_on_new_subnet(
                &env,
                &nns_node,
                &nns_canister,
                subnet_size,
                master_version.clone(),
                key_ids.clone(),
                &logger,
            )
        } else {
            enable_chain_key_signing_on_subnet(
                &nns_node,
                &nns_canister,
                root_subnet_id,
                key_ids.clone(),
                &logger,
            )
        }
    });

    let app_subnet = env
        .topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("there is no application subnet");
    let mut app_nodes = app_subnet.nodes();
    let app_node = app_nodes.next().expect("there is no application node");
    info!(
        logger,
        "Selected random application subnet node: {} ({:?})",
        app_node.node_id,
        app_node.get_ip_addr()
    );
    info!(logger, "app node URL: {}", app_node.get_public_url());

    info!(logger, "Ensure app subnet is functional");
    cert_state_makes_progress_with_retries(
        &app_node.get_public_url(),
        app_node.effective_canister_id(),
        &logger,
        secs(600),
        secs(10),
    );
    let msg = "subnet recovery works!";
    let app_can_id = store_message(
        &app_node.get_public_url(),
        app_node.effective_canister_id(),
        msg,
        &logger,
    );
    assert!(can_read_msg(
        &logger,
        &app_node.get_public_url(),
        app_can_id,
        msg
    ));

    let subnet_id = app_subnet.subnet_id;

    let ssh_authorized_priv_keys_dir = env.get_path(SSH_AUTHORIZED_PRIV_KEYS_DIR);
    let ssh_authorized_pub_keys_dir = env.get_path(SSH_AUTHORIZED_PUB_KEYS_DIR);

    let pub_key = file_sync_helper::read_file(&ssh_authorized_pub_keys_dir.join(SSH_USERNAME))
        .expect("Couldn't read public key");

    let recovery_dir = env.get_dependency_path("rs/tests");
    set_sandbox_env_vars(recovery_dir.join("recovery/binaries"));

    let recovery_args = RecoveryArgs {
        dir: recovery_dir,
        nns_url: nns_node.get_public_url(),
        replica_version: Some(master_version.clone()),
        key_file: Some(ssh_authorized_priv_keys_dir.join(SSH_USERNAME)),
        test_mode: true,
        skip_prompts: true,
    };

    let mut unassigned_nodes = env.topology_snapshot().unassigned_nodes();

    let upload_node = if let Some(node) = unassigned_nodes.next() {
        node
    } else {
        app_nodes.next().unwrap()
    };

    print_app_and_unassigned_nodes(&env, &logger);

    let unassigned_nodes_ids = env
        .topology_snapshot()
        .unassigned_nodes()
        .map(|n| n.node_id)
        .collect::<Vec<NodeId>>();

    let version_is_broken = upgrade && unassigned_nodes_ids.is_empty();
    let working_version = if version_is_broken {
        format!("{}-test", master_version)
    } else {
        master_version.to_string()
    };

    let subnet_args = AppSubnetRecoveryArgs {
        keep_downloaded_state: Some(chain_key),
        subnet_id,
        upgrade_version: version_is_broken
            .then(|| ReplicaVersion::try_from(working_version.clone()).unwrap()),
        upgrade_image_url: env.get_ic_os_update_img_test_url().ok(),
        upgrade_image_hash: env.get_ic_os_update_img_test_sha256().ok(),
        replacement_nodes: Some(unassigned_nodes_ids.clone()),
        replay_until_height: None,
        pub_key: Some(pub_key),
        download_node: None,
        upload_node: Some(upload_node.get_ip_addr()),
        chain_key_subnet_id: chain_key.then_some(root_subnet_id),
        next_step: None,
    };

    info!(
        logger,
        "Starting recovery of subnet {} with {:?}",
        subnet_id.to_string(),
        &subnet_args
    );

    let mut subnet_recovery = AppSubnetRecovery::new(
        env.logger(),
        recovery_args,
        /*neuron_args=*/ None,
        subnet_args,
    );
    if upgrade {
        break_subnet(
            app_nodes,
            subnet_size,
            subnet_recovery.get_recovery_api(),
            &logger,
        );
    } else {
        halt_subnet(
            &app_node,
            subnet_id,
            subnet_recovery.get_recovery_api(),
            &logger,
        )
    }
    assert_subnet_is_broken(&app_node.get_public_url(), app_can_id, msg, &logger);

    let download_node = select_download_node(
        env.topology_snapshot()
            .subnets()
            .find(|subnet| subnet.subnet_type() == SubnetType::Application)
            .expect("there is no application subnet"),
        &logger,
    );

    subnet_recovery.params.download_node = Some(download_node.0.get_ip_addr());

    for (step_type, step) in subnet_recovery {
        info!(logger, "Next step: {:?}", step_type);

        info!(logger, "{}", step.descr());
        step.exec()
            .unwrap_or_else(|e| panic!("Execution of step {:?} failed: {}", step_type, e));
    }

    info!(logger, "Blocking for newer registry version");
    let topology_snapshot = block_on(env.topology_snapshot().block_for_newer_registry_version())
        .expect("Could not block for newer registry version");

    print_app_and_unassigned_nodes(&env, &logger);

    let all_app_nodes: Vec<IcNodeSnapshot> = topology_snapshot
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
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

    assert_subnet_is_healthy(&all_app_nodes, working_version, app_can_id, msg, &logger);

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

    if chain_key {
        if !create_new_subnet {
            disable_chain_key_on_subnet(
                &nns_node,
                root_subnet_id,
                &nns_canister,
                key_ids.clone(),
                &logger,
            );
            let app_keys = enable_chain_key_signing_on_subnet(
                &nns_node,
                &nns_canister,
                subnet_id,
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
    topology_snapshot
        .unassigned_nodes()
        .for_each(|n| assert_node_is_unassigned(&n, &logger));
}

/// break a subnet by breaking the replica binary on f+1 = (subnet_size - 1) / 3 +1
/// nodes taken from the given iterator.
fn break_subnet(
    subnet: Box<dyn Iterator<Item = IcNodeSnapshot>>,
    subnet_size: usize,
    recovery: &Recovery,
    logger: &Logger,
) {
    // Let's take f+1 nodes and break them.
    let f = (subnet_size - 1) / 3;
    info!(
        logger,
        "Breaking the subnet by breaking the replica binary on f+1={} nodes",
        f + 1
    );

    let faulty_nodes = subnet.take(f + 1).collect::<Vec<_>>();
    for node in faulty_nodes {
        // simulate subnet failure by breaking the replica process, but not the orchestrator
        recovery
            .execute_ssh_command(
                "admin",
                node.get_ip_addr(),
                "sudo mount --bind /bin/false /opt/ic/bin/replica && sudo systemctl restart ic-replica",
            )
            .expect("couldn't run ssh command");
    }
}

/// Halt the subnet and wait until the given app node reports consensus 'is halted'
fn halt_subnet(
    app_node: &IcNodeSnapshot,
    subnet_id: SubnetId,
    recovery: &Recovery,
    logger: &Logger,
) {
    #[derive(Debug, Deserialize, Serialize)]
    struct Cursor {
        #[serde(alias = "__CURSOR")]
        cursor: String,
    }

    info!(logger, "Breaking the app subnet by halting it",);
    let s = app_node.block_on_ssh_session().unwrap();
    let message_str = execute_bash_command(
        &s,
        "journalctl -n1 -o json --output-fields='__CURSOR'".to_string(),
    )
    .expect("journal message");
    let message: Cursor = serde_json::from_str(&message_str).expect("JSON journal message");
    recovery
        .halt_subnet(subnet_id, true, &[])
        .exec()
        .expect("Failed to halt subnet.");
    ic_system_test_driver::retry_with_msg!(
        "check if consensus is halted",
        logger.clone(),
        secs(120),
        secs(10),
        || {
            let res = execute_bash_command(
                &s,
                format!(
                    "journalctl --after-cursor='{}' | grep -c 'is halted'",
                    message.cursor
                ),
            );
            if res.map_or(false, |r| r.trim().parse::<i32>().unwrap() > 0) {
                Ok(())
            } else {
                bail!("Did not find log entry that consensus is halted.")
            }
        }
    )
    .expect("Failed to detect broken subnet.");
}

/// A subnet is considered to be broken if it still works in read mode,
/// but doesn't in write mode
fn assert_subnet_is_broken(node_url: &Url, can_id: Principal, msg: &str, logger: &Logger) {
    info!(logger, "Ensure the subnet works in read mode");
    assert!(
        can_read_msg(logger, node_url, can_id, msg),
        "Failed to read message on node: {}",
        node_url
    );
    info!(
        logger,
        "Ensure the subnet doesn't work in write mode anymore"
    );
    assert!(
        cannot_store_msg(logger.clone(), node_url, can_id, msg),
        "Writing messages still successful on: {}",
        node_url
    );
}

/// Assert that the given node has deleted its state within the next 5 minutes.
fn assert_node_is_unassigned(node: &IcNodeSnapshot, logger: &Logger) {
    info!(
        logger,
        "Asserting that node {} has deleted its state.",
        node.get_ip_addr()
    );
    // We need to exclude the page_deltas/ directory, which is not deleted on state deletion.
    // That is because deleting it would break SELinux assumptions.
    let check = r#"[ "$(ls -A /var/lib/ic/data/ic_state -I page_deltas)" ] && echo "assigned" || echo "unassigned""#;
    let s = node
        .block_on_ssh_session()
        .expect("Failed to establish SSH session");

    ic_system_test_driver::retry_with_msg!(
        format!("check if node {} is unassigned", node.node_id),
        logger.clone(),
        secs(300),
        secs(10),
        || match execute_bash_command(&s, check.to_string()) {
            Ok(s) if s.trim() == "unassigned" => Ok(()),
            Ok(s) if s.trim() == "assigned" => {
                bail!("Node {} is still assigned.", node.get_ip_addr())
            }
            Ok(s) => bail!("Received unexpected output: {}", s),
            Err(e) => bail!("Failed to read directory: {}", e),
        }
    )
    .expect("Failed to detect that node has deleted its state.");
}

/// Select a node with highest finalization height in the given subnet snapshot
fn select_download_node(subnet: SubnetSnapshot, logger: &Logger) -> (IcNodeSnapshot, NodeMetrics) {
    let node = subnet
        .nodes()
        .filter_map(|n| block_on(get_node_metrics(logger, &n.get_ip_addr())).map(|m| (n, m)))
        .max_by_key(|(_, metric)| metric.finalization_height)
        .expect("No download node found");
    info!(
        logger,
        "Selected download node: ({}, {})",
        node.0.get_ip_addr(),
        node.1.finalization_height
    );
    node
}

/// Print ID and IP of all unassigned nodes and the first app subnet found.
pub fn print_app_and_unassigned_nodes(env: &TestEnv, logger: &Logger) {
    let topology_snapshot = env.topology_snapshot();

    info!(logger, "App nodes:");
    topology_snapshot
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
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
