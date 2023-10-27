/* tag::catalog[]
Title:: Upgradability from/to the mainnet replica version.

Goal:: Ensure the upgradability of the branch version against the oldest used replica version

Runbook::
. Setup an IC with 4-nodes NNS and 4-nodes app subnet using the mainnet replica version.
. Upgrade each type of subnet to the branch version, and downgrade again.
. During both upgrades simulate a disconnected node and make sure it catches up.

Success:: Upgrades work into both directions for all subnet types.

end::catalog[] */

use super::utils::rw_message::install_nns_and_check_progress;
use crate::{
    driver::{
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::*,
    },
    orchestrator::utils::{
        rw_message::{can_read_msg, can_read_msg_with_retries, store_message},
        subnet_recovery::{enable_ecdsa_signing_on_subnet, run_ecdsa_signature_test},
        upgrade::*,
    },
    tecdsa::tecdsa_signature_test::{
        add_ecdsa_key_with_timeout_and_rotation_period, make_key, KEY_ID1,
    },
    util::{block_on, runtime_from_url, MessageCanister},
};
use canister_test::Canister;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_registry_subnet_type::SubnetType;
use ic_types::{Height, SubnetId};
use k256::ecdsa::VerifyingKey;
use slog::{info, Logger};
use std::time::Duration;

pub const MIN_HASH_LENGTH: usize = 8; // in bytes

const DKG_INTERVAL: u64 = 9;

const ALLOWED_FAILURES: usize = 1;
const SUBNET_SIZE: usize = 3 * ALLOWED_FAILURES + 1; // 4 nodes

// Pre-master tests should not run for more than 5..6 minutes. The Upgrade/Downgrade tests run on
// pre-master and are a known exception to this rule. The test itself takes around 10 minutes,
// while the setup takes a little more than one minute to complete.
pub const UP_DOWNGRADE_OVERALL_TIMEOUT: Duration = Duration::from_secs(18 * 60);
pub const UP_DOWNGRADE_PER_TEST_TIMEOUT: Duration = Duration::from_secs(15 * 60);

pub fn config(env: TestEnv) {
    InternetComputer::new()
        .with_mainnet_config()
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
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
}

// Tests an upgrade of the NNS subnet to the branch version and a downgrade back to the mainnet version
pub fn upgrade_downgrade_nns_subnet(env: TestEnv) {
    upgrade_downgrade(env, SubnetType::System);
}

// Tests an upgrade of the app subnet to the branch version and a downgrade back to the mainnet version
pub fn upgrade_downgrade_app_subnet(env: TestEnv) {
    upgrade_downgrade(env, SubnetType::Application);
}

// Upgrades to the branch version, and back to mainnet NNS version.
fn upgrade_downgrade(env: TestEnv, subnet_type: SubnetType) {
    let logger = env.logger();

    let mainnet_version = env
        .read_dependency_to_string("testnet/mainnet_nns_revision.txt")
        .unwrap();

    // we expect to get a hash value here, so checking that is a hash number of at least 64 bits size
    assert!(mainnet_version.len() >= 2 * MIN_HASH_LENGTH);
    assert!(hex::decode(&mainnet_version).is_ok());

    // choose a node from the nns subnet
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();

    let agent = nns_node.with_default_agent(|agent| async move { agent });
    let nns_canister = block_on(MessageCanister::new(
        &agent,
        nns_node.effective_canister_id(),
    ));

    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);
    let subnet_id = env
        .topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == subnet_type)
        .unwrap()
        .subnet_id;
    info!(logger, "Enabling ECDSA signatures on {subnet_id}.");
    block_on(add_ecdsa_key_with_timeout_and_rotation_period(
        &governance,
        subnet_id,
        make_key(KEY_ID1),
        None,
        None,
    ));
    let key = enable_ecdsa_signing_on_subnet(&nns_node, &nns_canister, subnet_id, &logger);
    run_ecdsa_signature_test(&nns_canister, &logger, key);

    let original_branch_version = "0000000000000000000000000000000000000000".to_string();
    let branch_version = format!("{}-test", original_branch_version);

    // Bless branch version (mainnet is already blessed)
    let sha256 = env.get_ic_os_update_img_test_sha256().unwrap();
    let upgrade_url = env.get_ic_os_update_img_test_url().unwrap();
    block_on(bless_replica_version(
        &nns_node,
        &original_branch_version,
        UpdateImageType::ImageTest,
        &logger,
        &sha256,
        vec![upgrade_url.to_string()],
    ));
    info!(&logger, "Blessed all versions");

    upgrade_downgrade_roundtrip(
        env,
        &nns_node,
        &branch_version,
        &mainnet_version,
        subnet_type,
        &nns_canister,
        key,
    );
}

// Upgrades and downgrades a subnet with one faulty node.
fn upgrade_downgrade_roundtrip(
    env: TestEnv,
    nns_node: &IcNodeSnapshot,
    upgrade_version: &str,
    downgrade_version: &str,
    subnet_type: SubnetType,
    nns_canister: &MessageCanister,
    key: VerifyingKey,
) {
    let logger = env.logger();
    let (subnet_id, subnet_node, faulty_node, redundant_nodes) =
        if subnet_type == SubnetType::System {
            let subnet = env.topology_snapshot().root_subnet();
            let mut it = subnet.nodes();
            // We don't want to hit the node we're using for sending the proposals
            assert!(it.next().unwrap().node_id == nns_node.node_id);
            let subnet_node = it.next().unwrap();
            let faulty_node = it.next().unwrap();
            let mut redundant_nodes = Vec::new();
            for _ in 0..ALLOWED_FAILURES {
                redundant_nodes.push(it.next().unwrap());
            }
            (subnet.subnet_id, subnet_node, faulty_node, redundant_nodes)
        } else {
            let subnet = env
                .topology_snapshot()
                .subnets()
                .find(|subnet| subnet.subnet_type() == SubnetType::Application)
                .expect("there is no application subnet");
            let mut it = subnet.nodes();
            let subnet_node = it.next().unwrap();
            let faulty_node = it.next().unwrap();
            let mut redundant_nodes = Vec::new();
            for _ in 0..ALLOWED_FAILURES {
                redundant_nodes.push(it.next().unwrap());
            }
            (subnet.subnet_id, subnet_node, faulty_node, redundant_nodes)
        };
    info!(
        logger,
        "downgrade_upgrade_roundtrip: subnet_node = {:?}", subnet_node.node_id
    );
    subnet_node.await_status_is_healthy().unwrap();
    faulty_node.await_status_is_healthy().unwrap();

    let msg = "hello world!";
    let can_id = store_message(
        &subnet_node.get_public_url(),
        subnet_node.effective_canister_id(),
        msg,
    );
    assert!(can_read_msg(
        &logger,
        &subnet_node.get_public_url(),
        can_id,
        msg
    ));
    info!(logger, "Could store and read message '{}'", msg);

    stop_node(&logger, &faulty_node);

    info!(logger, "Upgrade to version {}", upgrade_version);
    upgrade_to(nns_node, subnet_id, &subnet_node, upgrade_version, &logger);

    // Killing redundant nodes should not prevent the `faulty_node` downgrading to mainnet version and catching up after restarting.
    for redundant_node in &redundant_nodes {
        stop_node(&logger, redundant_node);
    }
    start_node(&logger, &faulty_node);
    assert_assigned_replica_version(&faulty_node, upgrade_version, env.logger());

    assert!(can_read_msg(
        &logger,
        &faulty_node.get_public_url(),
        can_id,
        msg
    ));
    info!(logger, "After upgrade could read message '{}'", msg);

    let msg_2 = "hello world after an upgrade!";
    let can_id_2 = store_message(
        &faulty_node.get_public_url(),
        faulty_node.effective_canister_id(),
        msg_2,
    );
    assert!(can_read_msg(
        &logger,
        &faulty_node.get_public_url(),
        can_id_2,
        msg_2
    ));
    info!(logger, "Could store and read message '{}'", msg_2);
    run_ecdsa_signature_test(nns_canister, &logger, key);

    // Start redundant nodes for upgrading to the branch version.
    for redundant_node in &redundant_nodes {
        start_node(&logger, redundant_node);
    }

    stop_node(&logger, &faulty_node);

    info!(logger, "Downgrade to version {}", downgrade_version);
    upgrade_to(
        nns_node,
        subnet_id,
        &subnet_node,
        downgrade_version,
        &logger,
    );

    let msg_3 = "hello world after upgrade!";
    let can_id_3 = store_message(
        &subnet_node.get_public_url(),
        subnet_node.effective_canister_id(),
        msg_3,
    );

    for redundant_node in &redundant_nodes {
        stop_node(&logger, redundant_node);
    }
    start_node(&logger, &faulty_node);
    assert_assigned_replica_version(&faulty_node, downgrade_version, env.logger());

    for (can_id, msg) in &[(can_id, msg), (can_id_2, msg_2), (can_id_3, msg_3)] {
        assert!(can_read_msg_with_retries(
            &logger,
            &faulty_node.get_public_url(),
            *can_id,
            msg,
            /*retries=*/ 3
        ));
    }

    info!(logger, "Could read all previously stored messages!");
    run_ecdsa_signature_test(nns_canister, &logger, key);
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
    block_on(update_subnet_replica_version(
        nns_node,
        &ic_types::ReplicaVersion::try_from(target_version).unwrap(),
        subnet_id,
    ));
    assert_assigned_replica_version(subnet_node, target_version, logger.clone());
    info!(
        logger,
        "Successfully upgraded subnet {} to {}", subnet_id, target_version
    );
}

// Stops the node and makes sure it becomes unreachable
pub fn stop_node(logger: &Logger, app_node: &IcNodeSnapshot) {
    app_node
        .await_status_is_healthy()
        .expect("Node not healthy");
    info!(logger, "Kill node: {}", app_node.get_ip_addr());
    app_node.vm().kill();
    app_node
        .await_status_is_unavailable()
        .expect("Node still healthy");
    info!(logger, "Node killed: {}", app_node.get_ip_addr());
}

// Starts a node and makes sure it becomes reachable
pub fn start_node(logger: &Logger, app_node: &IcNodeSnapshot) {
    app_node
        .await_status_is_unavailable()
        .expect("Node still healthy");
    info!(logger, "Starting node: {}", app_node.get_ip_addr());
    app_node.vm().start();
    app_node
        .await_status_is_healthy()
        .expect("Node not healthy");
    info!(logger, "Node started: {}", app_node.get_ip_addr());
}
