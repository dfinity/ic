/* tag::catalog[]
Title:: Upgradability from/to the mainnet replica version.

Goal:: Ensure the upgradability of the branch version against the oldest used replica version

Runbook::
. Setup an IC with 4-nodes (App/NNS) subnet under test using the mainnet replica version.
. Upgrade each type of subnet to the branch version, and downgrade again.
. During both upgrades simulate a disconnected node and make sure it catches up.

Success:: Upgrades work into both directions for all subnet types.

end::catalog[] */

use candid::Principal;
use ic_agent::Agent;
use ic_consensus_system_test_utils::rw_message::{
    can_read_msg, cert_state_makes_progress_with_retries, store_message,
};
use ic_consensus_system_test_utils::subnet::enable_chain_key_signing_on_subnet;
use ic_consensus_system_test_utils::upgrade::{
    assert_assigned_replica_version, bless_replica_version, deploy_guestos_to_all_subnet_nodes,
    UpdateImageType,
};
use ic_consensus_threshold_sig_system_test_utils::run_chain_key_signature_test;
use ic_management_canister_types_private::MasterPublicKeyId;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::util::create_agent;
use ic_system_test_driver::{
    driver::{test_env::TestEnv, test_env_api::*},
    util::{block_on, MessageCanister},
};
use ic_types::SubnetId;
use ic_utils::interfaces::ManagementCanister;
use slog::{info, Logger};
use std::collections::BTreeMap;
use std::time::Duration;

const ALLOWED_FAILURES: usize = 1;

pub const UP_DOWNGRADE_OVERALL_TIMEOUT: Duration = Duration::from_secs(25 * 60);
pub const UP_DOWNGRADE_PER_TEST_TIMEOUT: Duration = Duration::from_secs(20 * 60);

pub fn bless_branch_version(env: &TestEnv, nns_node: &IcNodeSnapshot) -> String {
    let logger = env.logger();

    let original_branch_version = read_dependency_from_env_to_string("ENV_DEPS__IC_VERSION_FILE")
        .expect("tip-of-branch IC version");
    let branch_version = format!("{}-test", original_branch_version);

    // Bless branch version
    let sha256 = get_ic_os_update_img_test_sha256().unwrap();
    let upgrade_url = get_ic_os_update_img_test_url().unwrap();
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

pub fn bless_mainnet_version(env: &TestEnv, nns_node: &IcNodeSnapshot) -> String {
    let logger = env.logger();

    let mainnet_version = get_mainnet_nns_revision();

    // Bless mainnet version
    let sha256 = env.get_mainnet_ic_os_update_img_sha256().unwrap();
    let upgrade_url = get_mainnet_ic_os_update_img_url().unwrap();
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
pub fn get_chain_key_canister_and_public_key<'a>(
    env: &TestEnv,
    nns_node: &IcNodeSnapshot,
    agent: &'a Agent,
    subnet_type: SubnetType,
    key_ids: Vec<MasterPublicKeyId>,
) -> (MessageCanister<'a>, BTreeMap<MasterPublicKeyId, Vec<u8>>) {
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
    let public_keys =
        enable_chain_key_signing_on_subnet(nns_node, &nns_canister, subnet_id, key_ids, &logger);

    for (key_id, public_key) in &public_keys {
        run_chain_key_signature_test(&nns_canister, &logger, key_id, public_key.clone());
    }

    (nns_canister, public_keys)
}

// Upgrades a subnet with one faulty node.
// Return the faulty node and the message (canister) stored before the upgrade.
pub fn upgrade(
    env: &TestEnv,
    nns_node: &IcNodeSnapshot,
    upgrade_version: &str,
    subnet_type: SubnetType,
    ecdsa_canister_key: Option<&(MessageCanister, BTreeMap<MasterPublicKeyId, Vec<u8>>)>,
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

    // Create canister snapshot before upgrading.
    block_on(async {
        let agent = create_agent(subnet_node.get_public_url().as_str())
            .await
            .expect("Failed to create agent");
        let mgr = ManagementCanister::create(&agent);
        mgr.take_canister_snapshot(&can_id, None).await.unwrap();
    });

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

    if let Some((canister, public_keys)) = ecdsa_canister_key {
        for (key_id, public_key) in public_keys {
            run_chain_key_signature_test(canister, &logger, key_id, public_key.clone());
        }
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
    block_on(deploy_guestos_to_all_subnet_nodes(
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
