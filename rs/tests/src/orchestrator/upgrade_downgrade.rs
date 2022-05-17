/* tag::catalog[]
Title:: Upgradability to/from oldest prod replica version.

Goal:: Ensure the upgradability of the branch version against the oldest used replica version

Runbook::
. Setup an IC with 4-nodes NNS and 4-nodes app subnet using the code from the branch.
. Downgrade each type of subnet to the mainnet version and back.
. During both upgrades simulate a disconnected node and make sure it catches up.

Success:: Upgrades work into both directions for all subnet types.

end::catalog[] */

use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::{test_env::TestEnv, test_env_api::*};
use crate::orchestrator::node_reassignment_test::{can_read_msg, store_message};
use crate::orchestrator::utils::upgrade::*;
use crate::util::block_on;
use anyhow::bail;
use ic_registry_subnet_type::SubnetType;
use ic_types::{Height, SubnetId};
use slog::{info, Logger};
use std::env;

const DKG_INTERVAL: u64 = 9;
const SUBNET_SIZE: usize = 4;

pub fn config(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .add_nodes(SUBNET_SIZE)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL)),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .add_nodes(SUBNET_SIZE)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL)),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test")
}

// Tests a downgrade of the nns subnet to the mainnet version and an upgrade back to the branch version
pub fn upgrade_downgrade_nns_subnet(env: TestEnv) {
    upgrade_downgrade(env, SubnetType::System);
}

// Tests a downgrade of the app subnet to the mainnet version and an upgrade back to the branch version
pub fn upgrade_downgrade_app_subnet(env: TestEnv) {
    upgrade_downgrade(env, SubnetType::Application);
}

// Downgrades a subnet to $TARGET_VERSION and back to branch version
fn upgrade_downgrade(env: TestEnv, subnet_type: SubnetType) {
    let logger = env.logger();
    let mainnet_version =
        env::var("TARGET_VERSION").expect("Environment variable $TARGET_VERSION is not set!");

    // choose a node from the nns subnet
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();
    nns_node.await_status_is_healthy().unwrap();

    nns_node
        .install_nns_canisters()
        .expect("NNS canisters not installed");
    info!(logger, "NNS canisters are installed.");

    let original_branch_version = get_assigned_replica_version_v2(&nns_node).unwrap();
    // We have to upgrade to `<VERSION>-test` because the original version is stored without the
    // download URL in the registry.
    let branch_version = format!("{}-test", original_branch_version);

    // Bless both replica versions
    block_on(bless_replica_version(
        &nns_node,
        &mainnet_version,
        UpdateImageType::Image,
        UpdateImageType::Image,
        &logger,
    ));
    block_on(bless_replica_version(
        &nns_node,
        &original_branch_version,
        UpdateImageType::ImageTest,
        UpdateImageType::ImageTest,
        &logger,
    ));
    info!(&logger, "Blessed all versions");

    downgrade_upgrade_roundtrip(
        env,
        &nns_node,
        &mainnet_version,
        &branch_version,
        subnet_type,
    );
}

// Downgrades and upgrades a subnet with one faulty node.
fn downgrade_upgrade_roundtrip(
    env: TestEnv,
    nns_node: &IcNodeSnapshot,
    target_version: &str,
    branch_version: &str,
    subnet_type: SubnetType,
) {
    let logger = env.logger();
    let (subnet_id, subnet_node, faulty_node) = if subnet_type == SubnetType::System {
        let subnet = env.topology_snapshot().root_subnet();
        let mut it = subnet.nodes();
        // We don't want to hit the node we're using for sending the proposals
        assert!(it.next().unwrap().node_id == nns_node.node_id);
        (subnet.subnet_id, it.next().unwrap(), it.next().unwrap())
    } else {
        let subnet = env
            .topology_snapshot()
            .subnets()
            .find(|subnet| subnet.subnet_type() == SubnetType::Application)
            .expect("there is no application subnet");
        let mut it = subnet.nodes();
        (subnet.subnet_id, it.next().unwrap(), it.next().unwrap())
    };
    subnet_node.await_status_is_healthy().unwrap();
    faulty_node.await_status_is_healthy().unwrap();

    let msg = "hello world!";
    let can_id = block_on(store_message(&subnet_node.get_public_url(), msg));
    assert!(block_on(can_read_msg(
        &logger,
        &subnet_node.get_public_url(),
        can_id,
        msg
    )));
    info!(logger, "Could store and read message '{}'", msg);

    stop_node(&logger, &faulty_node);

    upgrade_to(nns_node, subnet_id, &subnet_node, target_version, &logger);

    start_node(&logger, &faulty_node);
    assert_assigned_replica_version_v2(&faulty_node, target_version, env.logger());

    assert!(block_on(can_read_msg(
        &logger,
        &faulty_node.get_public_url(),
        can_id,
        msg
    )));
    info!(logger, "After upgrade could read message '{}'", msg);

    let msg_2 = "hello world after downgrade!";
    let can_id_2 = block_on(store_message(&faulty_node.get_public_url(), msg_2));
    assert!(block_on(can_read_msg(
        &logger,
        &faulty_node.get_public_url(),
        can_id_2,
        msg_2
    )));
    info!(logger, "Could store and read message '{}'", msg_2);

    stop_node(&logger, &faulty_node);
    upgrade_to(nns_node, subnet_id, &subnet_node, branch_version, &logger);

    let msg_3 = "hello world after upgrade!";
    let can_id_3 = block_on(store_message(&subnet_node.get_public_url(), msg_3));

    start_node(&logger, &faulty_node);
    assert_assigned_replica_version_v2(&faulty_node, branch_version, env.logger());

    for (c, m) in &[(can_id, msg), (can_id_2, msg_2), (can_id_3, msg_3)] {
        assert!(block_on(can_read_msg(
            &logger,
            &faulty_node.get_public_url(),
            *c,
            m
        )));
    }

    info!(logger, "Could read all previously stored messages!");
}

fn upgrade_to(
    nns_node: &IcNodeSnapshot,
    subnet_id: SubnetId,
    subnet_node: &IcNodeSnapshot,
    target_version: &str,
    logger: &Logger,
) {
    info!(
        logger,
        "Upgrading subnet {} to {}", subnet_id, target_version
    );
    use std::convert::TryFrom;
    block_on(update_subnet_replica_version(
        nns_node,
        &ic_types::ReplicaVersion::try_from(target_version).unwrap(),
        subnet_id,
    ));
    assert_assigned_replica_version_v2(subnet_node, target_version, logger.clone());
    info!(
        logger,
        "Successfully upgraded subnet {} to {}", subnet_id, target_version
    );
}

// Stops the node and makes sure it becomes unreachable
pub fn stop_node(logger: &Logger, app_node: &IcNodeSnapshot) {
    wait_node_healthy(logger, app_node);
    info!(logger, "Kill node: {}", app_node.get_ip_addr());
    app_node.vm().kill();
    wait_node_unreachable(logger, app_node);
    info!(logger, "Node killed: {}", app_node.get_ip_addr());
}

// Starts a node and makes sure it becomes reachable
pub fn start_node(logger: &Logger, app_node: &IcNodeSnapshot) {
    wait_node_unreachable(logger, app_node);
    info!(logger, "Starting node: {}", app_node.get_ip_addr());
    app_node.vm().start();
    wait_node_healthy(logger, app_node);
    info!(logger, "Node started: {}", app_node.get_ip_addr());
}

fn wait_node_healthy(logger: &Logger, node: &IcNodeSnapshot) {
    retry(logger.clone(), secs(600), secs(20), || {
        node.status_is_healthy()
            .and_then(|s| if !s { bail!("Not ready!") } else { Ok(()) })
    })
    .expect("Node not healty");
}

fn wait_node_unreachable(logger: &Logger, node: &IcNodeSnapshot) {
    retry(logger.clone(), secs(600), secs(20), || {
        match node.status_is_healthy() {
            Ok(true) => bail!("Still ready!"),
            _ => Ok(()),
        }
    })
    .expect("Node still healty");
}
