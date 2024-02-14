/* tag::catalog[]
Title:: Upgradability from/to the mainnet replica version.

Goal:: Ensure the upgradability of the branch version against the oldest used replica version

Runbook::
. Setup an IC with 4-nodes (App/NNS) subnet under test using the mainnet replica version.
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
        rw_message::{
            can_read_msg, can_read_msg_with_retries, cert_state_makes_progress_with_retries,
            store_message,
        },
        subnet_recovery::{enable_ecdsa_signing_on_subnet, run_ecdsa_signature_test},
        upgrade::*,
    },
    tecdsa::{make_key, KEY_ID1},
    util::{block_on, MessageCanister},
};
use candid::Principal;
use ic_agent::Agent;
use ic_registry_subnet_features::{EcdsaConfig, DEFAULT_ECDSA_MAX_QUEUE_SIZE};
use ic_registry_subnet_type::SubnetType;
use ic_types::{Height, SubnetId};
use k256::ecdsa::VerifyingKey;
use slog::{info, Logger};
use std::time::Duration;

const DKG_INTERVAL: u64 = 9;

const ALLOWED_FAILURES: usize = 1;
const SUBNET_SIZE: usize = 3 * ALLOWED_FAILURES + 1; // 4 nodes

pub const UP_DOWNGRADE_OVERALL_TIMEOUT: Duration = Duration::from_secs(18 * 60);
pub const UP_DOWNGRADE_PER_TEST_TIMEOUT: Duration = Duration::from_secs(15 * 60);

pub fn config(env: TestEnv, subnet_type: SubnetType, mainnet_version: bool) {
    let mut ic = InternetComputer::new();
    if mainnet_version {
        ic = ic.with_mainnet_config();

        // Due to a change in how default firewall rules are supplied, they are
        // not preserved across the transitional upgrade. We temporarily stash
        // the whitelist in the registry for the time being.
        // THIS PATH SHOULD BE REMOVED.
        ic = ic.with_forced_default_firewall();
    }

    let mut subnet_under_test = Subnet::new(subnet_type)
        .add_nodes(SUBNET_SIZE)
        .with_dkg_interval_length(Height::from(DKG_INTERVAL));

    // Activate ecdsa if we are testing the app subnet
    if subnet_type == SubnetType::Application {
        ic = ic.add_subnet(Subnet::fast_single_node(SubnetType::System));
        subnet_under_test = subnet_under_test.with_ecdsa_config(EcdsaConfig {
            quadruples_to_create_in_advance: 5,
            key_ids: vec![make_key(KEY_ID1)],
            max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
        });
    }

    ic.add_subnet(subnet_under_test)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
}

// Tests an upgrade of the NNS subnet to the branch version and a downgrade back to the mainnet version
pub fn upgrade_downgrade_nns_subnet(env: TestEnv) {
    let nns_node = env.get_first_healthy_system_node_snapshot();
    let branch_version = bless_branch_version(&env, &nns_node);
    let (faulty_node, can_id, msg) =
        upgrade(&env, &nns_node, &branch_version, SubnetType::System, None);
    let mainnet_version = env
        .read_dependency_to_string("testnet/mainnet_nns_revision.txt")
        .unwrap();
    upgrade(&env, &nns_node, &mainnet_version, SubnetType::System, None);
    // Make sure we can still read the message stored before the first upgrade
    assert!(can_read_msg_with_retries(
        &env.logger(),
        &faulty_node.get_public_url(),
        can_id,
        &msg,
        /*retries=*/ 3
    ));
}

// Tests an upgrade of the app subnet to the branch version and a downgrade back to the mainnet version
pub fn upgrade_downgrade_app_subnet(env: TestEnv) {
    let nns_node = env.get_first_healthy_system_node_snapshot();
    let branch_version = bless_branch_version(&env, &nns_node);
    let agent = nns_node.with_default_agent(|agent| async move { agent });
    let ecdsa_state = get_ecdsa_canister_and_key(&env, &nns_node, &agent, SubnetType::Application);
    let (faulty_node, can_id, msg) = upgrade(
        &env,
        &nns_node,
        &branch_version,
        SubnetType::Application,
        Some(&ecdsa_state),
    );
    let mainnet_version = env
        .read_dependency_to_string("testnet/mainnet_nns_revision.txt")
        .unwrap();
    upgrade(
        &env,
        &nns_node,
        &mainnet_version,
        SubnetType::Application,
        Some(&ecdsa_state),
    );
    // Make sure we can still read the message stored before the first upgrade
    assert!(can_read_msg_with_retries(
        &env.logger(),
        &faulty_node.get_public_url(),
        can_id,
        &msg,
        /*retries=*/ 3
    ));
}

// Tests a downgrade of the app subnet to the mainnet version
pub fn downgrade_app_subnet(env: TestEnv) {
    let nns_node = env.get_first_healthy_system_node_snapshot();
    let mainnet_version = bless_mainnet_version(&env, &nns_node);
    let agent = nns_node.with_default_agent(|agent| async move { agent });
    let ecdsa_state = get_ecdsa_canister_and_key(&env, &nns_node, &agent, SubnetType::Application);
    upgrade(
        &env,
        &nns_node,
        &mainnet_version,
        SubnetType::Application,
        Some(&ecdsa_state),
    );
}

// Tests an upgrade of the app subnet to the branch version
pub fn upgrade_app_subnet(env: TestEnv) {
    let nns_node = env.get_first_healthy_system_node_snapshot();
    let branch_version = bless_branch_version(&env, &nns_node);
    let agent = nns_node.with_default_agent(|agent| async move { agent });
    let ecdsa_state = get_ecdsa_canister_and_key(&env, &nns_node, &agent, SubnetType::Application);
    upgrade(
        &env,
        &nns_node,
        &branch_version,
        SubnetType::Application,
        Some(&ecdsa_state),
    );
}

fn bless_branch_version(env: &TestEnv, nns_node: &IcNodeSnapshot) -> String {
    let logger = env.logger();

    let original_branch_version = env
        .read_dependency_from_env_to_string("ENV_DEPS__IC_VERSION_FILE")
        .expect("tip-of-branch IC version");
    let branch_version = format!("{}-test", original_branch_version);

    // Bless branch version
    let sha256 = env.get_ic_os_update_img_test_sha256().unwrap();
    let upgrade_url = env.get_ic_os_update_img_test_url().unwrap();
    block_on(bless_replica_version(
        nns_node,
        &original_branch_version,
        UpdateImageType::ImageTest,
        &logger,
        &sha256,
        vec![upgrade_url.to_string()],
    ));
    info!(&logger, "Blessed branch version");
    branch_version
}

fn bless_mainnet_version(env: &TestEnv, nns_node: &IcNodeSnapshot) -> String {
    let logger = env.logger();

    let mainnet_version = env
        .read_dependency_to_string("testnet/mainnet_nns_revision.txt")
        .expect("mainnet IC version");

    // Bless mainnet version
    let sha256 = env.get_mainnet_ic_os_update_img_sha256().unwrap();
    let upgrade_url = env.get_mainnet_ic_os_update_img_url().unwrap();
    block_on(bless_replica_version(
        nns_node,
        &mainnet_version,
        UpdateImageType::Image,
        &logger,
        &sha256,
        vec![upgrade_url.to_string()],
    ));
    info!(&logger, "Blessed mainnet version");
    mainnet_version
}

// Enable ECDSA signing on the first subnet of the given type, and
// return a canister on that subnet together with its tECDSA public key
fn get_ecdsa_canister_and_key<'a>(
    env: &TestEnv,
    nns_node: &IcNodeSnapshot,
    agent: &'a Agent,
    subnet_type: SubnetType,
) -> (MessageCanister<'a>, VerifyingKey) {
    let logger = env.logger();
    let nns_canister = block_on(MessageCanister::new(
        agent,
        nns_node.effective_canister_id(),
    ));
    let subnet_id = env
        .topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == subnet_type)
        .unwrap()
        .subnet_id;
    info!(logger, "Enabling ECDSA signing on {subnet_id}.");
    let key = enable_ecdsa_signing_on_subnet(nns_node, &nns_canister, subnet_id, &logger);
    run_ecdsa_signature_test(&nns_canister, &logger, key);
    (nns_canister, key)
}

// Upgrades a subnet with one faulty node.
// Return the faulty node and the message (canister) stored before the upgrade.
fn upgrade(
    env: &TestEnv,
    nns_node: &IcNodeSnapshot,
    upgrade_version: &str,
    subnet_type: SubnetType,
    ecdsa_canister_key: Option<&(MessageCanister, VerifyingKey)>,
) -> (IcNodeSnapshot, Principal, String) {
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
    info!(logger, "upgrade: subnet_node = {:?}", subnet_node.node_id);
    subnet_node.await_status_is_healthy().unwrap();
    faulty_node.await_status_is_healthy().unwrap();

    let msg = &format!("hello before upgrade to {upgrade_version}");
    let can_id = store_message(
        &subnet_node.get_public_url(),
        subnet_node.effective_canister_id(),
        msg,
        &logger,
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

    // Killing redundant nodes should not prevent the `faulty_node` from upgrading
    // and catching up after restarting.
    for redundant_node in &redundant_nodes {
        stop_node(&logger, redundant_node);
    }
    start_node(&logger, &faulty_node);
    assert_assigned_replica_version(&faulty_node, upgrade_version, env.logger());

    // make sure that state sync is completed
    cert_state_makes_progress_with_retries(
        &faulty_node.get_public_url(),
        faulty_node.effective_canister_id(),
        &logger,
        secs(600),
        secs(10),
    );

    assert!(can_read_msg(
        &logger,
        &faulty_node.get_public_url(),
        can_id,
        msg
    ));
    info!(logger, "After upgrade could read message '{}'", msg);

    let msg_2 = &format!("hello after upgrade to {upgrade_version}");
    let can_id_2 = store_message(
        &faulty_node.get_public_url(),
        faulty_node.effective_canister_id(),
        msg_2,
        &logger,
    );
    assert!(can_read_msg(
        &logger,
        &faulty_node.get_public_url(),
        can_id_2,
        msg_2
    ));
    info!(logger, "Could store and read message '{}'", msg_2);

    if let Some((canister, key)) = ecdsa_canister_key {
        run_ecdsa_signature_test(canister, &logger, *key);
    }

    // Start redundant nodes.
    for redundant_node in &redundant_nodes {
        start_node(&logger, redundant_node);
    }

    (faulty_node.clone(), can_id, msg.into())
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
