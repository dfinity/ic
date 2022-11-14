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

use super::utils::rw_message::install_nns_and_message_canisters;
use crate::driver::driver_setup::{SSH_AUTHORIZED_PRIV_KEYS_DIR, SSH_AUTHORIZED_PUB_KEYS_DIR};
use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::{test_env::TestEnv, test_env_api::*};
use crate::orchestrator::utils::rw_message::{
    can_read_msg, cert_state_makes_progress_with_retries, store_message,
};
use crate::orchestrator::utils::subnet_recovery::*;
use crate::util::*;
use ic_base_types::NodeId;
use ic_recovery::app_subnet_recovery::{AppSubnetRecovery, AppSubnetRecoveryArgs};
use ic_recovery::RecoveryArgs;
use ic_recovery::{file_sync_helper, get_node_metrics};
use ic_registry_subnet_type::SubnetType;
use ic_types::{Height, ReplicaVersion};
use slog::info;
use std::convert::TryFrom;
use std::env;

const DKG_INTERVAL: u64 = 9;
const APP_NODES: i32 = 3;
const UNASSIGNED_NODES: i32 = 3;

/// Setup an IC with the given number of unassigned nodes and
/// an app subnet with the given number of nodes
pub fn setup(app_nodes: i32, unassigned_nodes: i32, env: TestEnv) {
    let mut ic = InternetComputer::new()
        .add_subnet(
            Subnet::fast_single_node(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL)),
        )
        .with_unassigned_nodes(unassigned_nodes);
    if app_nodes > 0 {
        ic = ic.add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(app_nodes.try_into().unwrap()),
        );
    }

    ic.setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_message_canisters(env.topology_snapshot());
}

pub fn setup_same_nodes_tecdsa(env: TestEnv) {
    setup(0, APP_NODES, env);
}

pub fn setup_failover_nodes_tecdsa(env: TestEnv) {
    setup(0, APP_NODES + UNASSIGNED_NODES, env);
}

pub fn setup_same_nodes(env: TestEnv) {
    setup(APP_NODES, 0, env);
}

pub fn setup_failover_nodes(env: TestEnv) {
    setup(APP_NODES, UNASSIGNED_NODES, env);
}

pub fn test_with_tecdsa(env: TestEnv) {
    app_subnet_recovery_test(env, true, true);
}

pub fn test_without_tecdsa(env: TestEnv) {
    app_subnet_recovery_test(env, true, false);
}

pub fn test_no_upgrade_with_tecdsa(env: TestEnv) {
    app_subnet_recovery_test(env, false, true);
}

pub fn test_no_upgrade_without_tecdsa(env: TestEnv) {
    app_subnet_recovery_test(env, false, false);
}

pub fn app_subnet_recovery_test(env: TestEnv, upgrade: bool, ecdsa: bool) {
    let logger = env.logger();

    let master_version = match env::var("IC_VERSION_ID") {
        Ok(ver) => ver,
        Err(_) => panic!("Environment variable $IC_VERSION_ID is not set!"),
    };
    info!(logger, "IC_VERSION_ID: {}", master_version);
    let master_version = ReplicaVersion::try_from(master_version).unwrap();
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
    let subnet_size = APP_NODES.try_into().unwrap();

    let create_new_subnet = !topology_snapshot
        .subnets()
        .any(|s| s.subnet_type() == SubnetType::Application);

    let ecdsa_pub_key = ecdsa.then(|| {
        info!(logger, "ECDSA flag set, creating key on NNS.");
        if create_new_subnet {
            info!(
                logger,
                "No app subnet found, creating a new one with the ECDSA key."
            );
            enable_ecdsa_on_new_subnet(
                &env,
                &nns_node,
                &nns_canister,
                subnet_size,
                master_version.clone(),
                &logger,
            )
        } else {
            enable_ecdsa_on_nns(&nns_node, &nns_canister, root_subnet_id, &logger)
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

    let pub_key = file_sync_helper::read_file(&ssh_authorized_pub_keys_dir.join(ADMIN))
        .expect("Couldn't read public key");

    let recovery_args = RecoveryArgs {
        dir: tempfile::tempdir()
            .expect("Could not create a temp dir")
            .path()
            .to_path_buf(),
        nns_url: nns_node.get_public_url(),
        replica_version: Some(master_version.clone()),
        key_file: Some(ssh_authorized_priv_keys_dir.join(ADMIN)),
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
        subnet_id,
        upgrade_version: version_is_broken
            .then(|| ReplicaVersion::try_from(working_version.clone()).unwrap()),
        replacement_nodes: Some(unassigned_nodes_ids.clone()),
        pub_key: Some(pub_key),
        download_node: None,
        upload_node: Some(upload_node.get_ip_addr()),
        ecdsa_subnet_id: ecdsa.then(|| root_subnet_id),
    };

    let mut subnet_recovery =
        AppSubnetRecovery::new(env.logger(), recovery_args, None, subnet_args, false);
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

    info!(
        logger,
        "Starting recovery of subnet {}",
        subnet_id.to_string()
    );

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

    // Confirm that ALL nodes are now healthy and running on the new version
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

    if ecdsa {
        if !create_new_subnet {
            disable_ecdsa_on_subnet(&nns_node, root_subnet_id, &nns_canister, &logger);
            let app_key = enable_ecdsa_on_app_subnet(&nns_node, &nns_canister, subnet_id, &logger);
            assert_eq!(ecdsa_pub_key.unwrap(), app_key)
        }
        run_ecdsa_signature_test(&nns_canister, &logger, ecdsa_pub_key.unwrap());
    }
}
