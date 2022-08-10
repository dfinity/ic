/* tag::catalog[]

Title:: Subnet Recovery Test (App subnet, same nodes without replica version upgrade)

Goal::
Ensure that the subnet recovery of an app subnet works on the same nodes without replica version upgrade.


Runbook::
. Deploy an IC with one app subnet.
. Halt the subnet
. Make sure the subnet stalls.
. Propose readonly key and confirm ssh access.
. Download IC state of a node with maximum finalization height.
. Execute ic-replay to generate a recovery CUP.
. Submit a recovery CUP.
. Upload replayed state to a random node.
. Unhalt the subnet.
. Ensure the subnet resumes.

Success::
. App subnet is functional after the recovery.

end::catalog[] */

use super::utils::rw_message::await_all_nodes_are_healthy;
use crate::driver::driver_setup::{
    IcSetup, SSH_AUTHORIZED_PRIV_KEYS_DIR, SSH_AUTHORIZED_PUB_KEYS_DIR,
};
use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::test_env::TestEnvAttribute;
use crate::driver::{test_env::TestEnv, test_env_api::*};
use crate::orchestrator::utils::rw_message::{can_read_msg, cannot_store_msg, store_message};
use crate::orchestrator::utils::ssh_access::execute_bash_command;
use crate::orchestrator::utils::upgrade::assert_assigned_replica_version;
use crate::util::*;
use anyhow::bail;
use ic_recovery::app_subnet_recovery::{AppSubnetRecovery, AppSubnetRecoveryArgs};
use ic_recovery::steps::Step;
use ic_recovery::RecoveryArgs;
use ic_recovery::{file_sync_helper, get_node_metrics, NodeMetrics};
use ic_registry_subnet_type::SubnetType;
use ic_types::Height;
use rand::prelude::SliceRandom;
use slog::info;

const DKG_INTERVAL: u64 = 9;
const SUBNET_SIZE: usize = 3;

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(SUBNET_SIZE),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    await_all_nodes_are_healthy(env.topology_snapshot());
}

pub fn test(env: TestEnv) {
    let logger = env.logger();

    let master_version = IcSetup::read_attribute(&env).initial_replica_version;
    info!(logger, "IC_VERSION_ID: {}", master_version);

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

    let topology = env.topology_snapshot();
    let app_subnet = topology
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

    let pub_key = file_sync_helper::read_file(&ssh_authorized_pub_keys_dir.join(ADMIN))
        .expect("Couldn't read public key");

    let tempdir = tempfile::tempdir().expect("Could not create a temp dir");

    let recovery_args = RecoveryArgs {
        dir: tempdir.path().to_path_buf(),
        nns_url: nns_node.get_public_url(),
        replica_version: Some(master_version.clone()),
        key_file: Some(ssh_authorized_priv_keys_dir.join(ADMIN)),
    };

    let subnet_args = AppSubnetRecoveryArgs {
        subnet_id,
        upgrade_version: None,
        replacement_nodes: None,
        pub_key: Some(pub_key),
        download_node: None,
        upload_node: None,
        ecdsa_subnet_id: None,
    };

    let mut subnet_recovery =
        AppSubnetRecovery::new(env.logger(), recovery_args, None, subnet_args);

    info!(logger, "Confirming admin ssh access to app node");
    assert!(subnet_recovery
        .get_recovery_api()
        .check_ssh_access("admin", app_node.get_ip_addr()));

    info!(logger, "Breaking the app subnet by halting it",);

    subnet_recovery
        .get_recovery_api()
        .halt_subnet(subnet_id, true, &[])
        .exec()
        .expect("Failed to halt subnet.");

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

    let s = app_node.get_ssh_session(ADMIN).unwrap();
    retry(logger.clone(), secs(120), secs(10), || {
        let res = execute_bash_command(&s, "journalctl | grep -c 'is halted'".to_string());
        if res.trim().parse::<i32>().unwrap() > 0
            && cannot_store_msg(logger.clone(), &app_node.get_public_url(), app_can_id, msg)
        {
            Ok(())
        } else {
            bail!("retry...")
        }
    })
    .expect("Failed to detect broken subnet.");

    let nodes_with_metrics: Vec<(IcNodeSnapshot, NodeMetrics)> = app_subnet
        .nodes()
        .filter_map(|n| get_node_metrics(&logger, &n.get_ip_addr()).map(|m| (n, m)))
        .collect();

    // Pick node with highest finalization for download, random for upload.
    let download_node = nodes_with_metrics
        .iter()
        .max_by_key(|(_, metric)| metric.finalization_height)
        .unwrap();
    let upload_node = nodes_with_metrics
        .choose_multiple(&mut rand::thread_rng(), 1)
        .next()
        .unwrap();
    subnet_recovery.params.download_node = Some(download_node.0.get_ip_addr());
    subnet_recovery.params.upload_node = Some(upload_node.0.get_ip_addr());

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
    let topology = topology
        .block_for_newer_registry_version()
        .expect("Could not block for newer registry version");
    let app_subnet = topology
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("there is no application subnet");

    // Confirm that ALL nodes are now healthy and running on the new version
    let all_app_nodes: Vec<IcNodeSnapshot> = app_subnet.nodes().collect();
    all_app_nodes.iter().for_each(|node| {
        assert_assigned_replica_version(node, &master_version.to_string(), env.logger());
        info!(
            logger,
            "Healthy recovery of node {} on version {}", node.node_id, master_version,
        );
    });

    info!(logger, "Waiting until network proceeds after recovery CUP");
    retry(logger.clone(), secs(600), secs(10), || {
        let check = all_app_nodes.iter().all(|node| {
            let height = get_node_metrics(&logger, &node.get_ip_addr())
                .unwrap()
                .finalization_height;
            info!(
                logger,
                "Node {} finalization height: {:?}", node.node_id, height
            );
            height > Height::from(1000)
        });
        if check {
            Ok(())
        } else {
            bail!("Failed to detect finalization after recovery CUP.");
        }
    })
    .expect("Failed to detect finalization after recovery CUP.");

    let upload_node = &upload_node.0;

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
