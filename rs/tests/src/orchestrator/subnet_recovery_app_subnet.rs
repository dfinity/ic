/* tag::catalog[]

Title:: Subnet Recovery Test (App subnet, same nodes + failover nodes)

Goal::
Ensure that the subnet recovery of an app subnet works on the same nodes and on failover nodes.


Runbook::
. Deploy an IC with one app subnet (and some unassigned nodes in case of recovery on failover nodes).
. Upgrade the app subnet to a broken replica.
. Make sure the subnet stalls.
. Propose readonly key and confirm ssh access.
. Download IC state of a random node.
. Execute ic-replay to generate a recovery CUP.
. Upgrade the subnet to a working replica.
. Submit a recovery CUP (using failover nodes, if configured).
. Upload replayed state to a node.
. Unhalt the subnet.
. Ensure the subnet resumes.

Success::
. App subnet is functional after the recovery.

end::catalog[] */

use super::utils::rw_message::await_all_nodes_are_healthy;
use crate::driver::driver_setup::{SSH_AUTHORIZED_PRIV_KEYS_DIR, SSH_AUTHORIZED_PUB_KEYS_DIR};
use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::{test_env::TestEnv, test_env_api::*};
use crate::orchestrator::utils::rw_message::{
    can_install_canister, can_read_msg, cannot_store_msg, store_message,
};
use crate::orchestrator::utils::upgrade::assert_assigned_replica_version;
use crate::util::*;
use anyhow::bail;
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
const SUBNET_SIZE: usize = 3;

pub fn config_same_nodes() -> InternetComputer {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(SUBNET_SIZE),
        )
}

pub fn setup_same_nodes(env: TestEnv) {
    config_same_nodes()
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    await_all_nodes_are_healthy(env.topology_snapshot());
}

pub fn setup_failover_nodes(env: TestEnv) {
    config_same_nodes()
        .with_unassigned_nodes(3)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    await_all_nodes_are_healthy(env.topology_snapshot());
}

pub fn test(env: TestEnv) {
    let logger = env.logger();

    let master_version = match env::var("IC_VERSION_ID") {
        Ok(ver) => ver,
        Err(_) => panic!("Environment variable $IC_VERSION_ID is not set!"),
    };
    info!(logger, "IC_VERSION_ID: {}", master_version);

    let working_version = format!("{}-test", master_version);

    let ssh_authorized_priv_keys_dir = env.get_path(SSH_AUTHORIZED_PRIV_KEYS_DIR);
    let ssh_authorized_pub_keys_dir = env.get_path(SSH_AUTHORIZED_PUB_KEYS_DIR);

    info!(
        logger,
        "ssh_authorized_priv_keys_dir: {:?}", ssh_authorized_priv_keys_dir
    );
    info!(
        logger,
        "ssh_authorized_pub_keys_dir: {:?}", ssh_authorized_pub_keys_dir
    );

    // choose a node from the nns subnet
    let nns_node = get_nns_node(&env.topology_snapshot());

    nns_node
        .install_nns_canisters()
        .expect("NNS canisters not installed");
    info!(logger, "NNS canisters are installed.");

    info!(
        logger,
        "Selected NNS node: {} ({:?})",
        nns_node.node_id,
        nns_node.get_ip_addr()
    );

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
    let msg = "subnet recovery works!";
    let app_can_id = store_message(&app_node.get_public_url(), msg);
    assert!(can_read_msg(
        &logger,
        &app_node.get_public_url(),
        app_can_id,
        msg
    ));

    let subnet_id = app_subnet.subnet_id;

    let mut unassigned_nodes = env.topology_snapshot().unassigned_nodes();

    let upload_node = if let Some(node) = unassigned_nodes.next() {
        node
    } else {
        app_nodes.next().unwrap()
    };

    info!(logger, "App nodes:");
    env.topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .unwrap()
        .nodes()
        .for_each(|n| {
            info!(logger, "A: {}", n.node_id);
        });

    info!(logger, "Unassigned nodes:");
    env.topology_snapshot().unassigned_nodes().for_each(|n| {
        info!(logger, "U: {}", n.node_id);
    });

    let pub_key = file_sync_helper::read_file(&ssh_authorized_pub_keys_dir.join(ADMIN))
        .expect("Couldn't read public key");

    let tempdir = tempfile::tempdir().expect("Could not create a temp dir");

    let recovery_args = RecoveryArgs {
        dir: tempdir.path().to_path_buf(),
        nns_url: nns_node.get_public_url(),
        replica_version: Some(ReplicaVersion::try_from(master_version).unwrap()),
        key_file: Some(ssh_authorized_priv_keys_dir.join(ADMIN)),
    };

    let unassigned_nodes_ids = env
        .topology_snapshot()
        .unassigned_nodes()
        .map(|n| n.node_id)
        .collect::<Vec<NodeId>>();

    // Unlike during a production recovery using the CLI, here we already know all of parameters ahead of time.
    let subnet_args = AppSubnetRecoveryArgs {
        subnet_id,
        upgrade_version: Some(ReplicaVersion::try_from(working_version.clone()).unwrap()),
        replacement_nodes: Some(unassigned_nodes_ids),
        pub_key: Some(pub_key),
        download_node: Some(app_node.get_ip_addr()),
        upload_node: Some(upload_node.get_ip_addr()),
        ecdsa_subnet_id: None,
    };

    let mut subnet_recovery =
        AppSubnetRecovery::new(env.logger(), recovery_args, None, subnet_args);

    info!(logger, "Confirming admin ssh access to app node");
    assert!(subnet_recovery
        .get_recovery_api()
        .check_ssh_access("admin", app_node.get_ip_addr()));

    // Let's take f+1 nodes and break them.
    let f = (SUBNET_SIZE - 1) / 3;
    info!(
        logger,
        "Breaking the app subnet by breaking the replica binary on f+1={} nodes",
        f + 1
    );

    let faulty_nodes = app_nodes.take(f + 1).collect::<Vec<_>>();
    for node in faulty_nodes {
        // simulate subnet failure by breaking the replica process, but not the orchestrator
        subnet_recovery
            .get_recovery_api()
            .execute_ssh_command(
                "admin",
                node.get_ip_addr(),
                "sudo mount --bind /bin/false /opt/ic/bin/replica && sudo systemctl restart ic-replica",
            )
            .expect("couldn't run ssh command");
    }

    info!(logger, "Ensure the subnet works in read mode");
    assert!(can_read_msg(
        &logger,
        &app_node.get_public_url(),
        app_can_id,
        msg
    ));
    info!(
        logger,
        "Ensure the subnet doesn't work in write mode anymore"
    );
    assert!(cannot_store_msg(
        logger.clone(),
        &app_node.get_public_url(),
        app_can_id,
        msg
    ));

    let download_node = env
        .topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("there is no application subnet")
        .nodes()
        .filter_map(|n| get_node_metrics(&logger, &n.get_ip_addr()).map(|m| (n, m)))
        .max_by_key(|(_, metric)| metric.finalization_height)
        .unwrap();

    subnet_recovery.params.download_node = Some(download_node.0.get_ip_addr());
    info!(
        logger,
        "Chose as download node: {:?}", subnet_recovery.params.download_node
    );

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
    env.topology_snapshot()
        .block_for_newer_registry_version()
        .expect("Could not block for newer registry version");

    info!(logger, "App nodes:");
    env.topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .unwrap()
        .nodes()
        .for_each(|n| {
            info!(logger, "A: {}", n.node_id);
        });

    info!(logger, "Unassigned nodes:");
    env.topology_snapshot().unassigned_nodes().for_each(|n| {
        info!(logger, "U: {}", n.node_id);
    });

    // Confirm that ALL nodes are now healthy and running on the new version
    let all_app_nodes: Vec<IcNodeSnapshot> = env
        .topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("there is no application subnet")
        .nodes()
        .collect();
    for node in all_app_nodes {
        assert_assigned_replica_version(&node, &working_version, env.logger());
        info!(
            logger,
            "Healthy upgrade of assigned node {} to {}", node.node_id, working_version
        );
    }

    // make sure that state sync is completed
    retry(logger.clone(), secs(120), secs(5), || {
        info!(logger, "Try to install canister...");
        if can_install_canister(&upload_node.get_public_url()) {
            info!(logger, "Installing canister is possible.");
            Ok(())
        } else {
            bail!("retry...")
        }
    })
    .expect("Canister instalation should work!");

    info!(logger, "Ensure the old message is still readable");
    assert!(can_read_msg(
        &logger,
        &upload_node.get_public_url(),
        app_can_id,
        msg
    ));
    upload_node.await_status_is_healthy().unwrap();
    let new_msg = "subnet recovery still works!";
    info!(
        logger,
        "Ensure the the subnet is accepting updates after the recovery"
    );
    let new_app_can_id = store_message(&upload_node.get_public_url(), new_msg);
    assert!(can_read_msg(
        &logger,
        &upload_node.get_public_url(),
        new_app_can_id,
        new_msg
    ));
}
