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
use ic_consensus_system_test_utils::ssh_access::execute_bash_command;
use ic_consensus_system_test_utils::subnet::enable_chain_key_signing_on_subnet;
use ic_consensus_system_test_utils::upgrade::{
    assert_assigned_replica_version, bless_replica_version, deploy_guestos_to_all_subnet_nodes,
};
use ic_consensus_threshold_sig_system_test_utils::run_chain_key_signature_test;
use ic_management_canister_types_private::MasterPublicKeyId;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::util::create_agent;
use ic_system_test_driver::{
    driver::{test_env::TestEnv, test_env_api::*},
    util::{MessageCanister, block_on},
};
use ic_types::{ReplicaVersion, SubnetId};
use ic_utils::interfaces::ManagementCanister;
use slog::{Logger, info};
use std::collections::BTreeMap;
use std::time::Duration;

const ALLOWED_FAILURES: usize = 1;

pub const UP_DOWNGRADE_OVERALL_TIMEOUT: Duration = Duration::from_secs(25 * 60);
pub const UP_DOWNGRADE_PER_TEST_TIMEOUT: Duration = Duration::from_secs(20 * 60);

pub fn bless_target_version(env: &TestEnv, nns_node: &IcNodeSnapshot) -> ReplicaVersion {
    let logger = env.logger();

    let target_version = get_guestos_update_img_version();

    // Bless target version
    let sha256 = get_guestos_update_img_sha256();
    let upgrade_url = get_guestos_update_img_url();
    let guest_launch_measurements = get_guestos_launch_measurements();
    block_on(bless_replica_version(
        nns_node,
        &target_version,
        &logger,
        sha256,
        Some(guest_launch_measurements),
        vec![upgrade_url.to_string()],
    ));
    info!(&logger, "Blessed target version");

    target_version
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
    upgrade_version: &ReplicaVersion,
    subnet_type: SubnetType,
    ecdsa_canister_key: Option<&(MessageCanister, BTreeMap<MasterPublicKeyId, Vec<u8>>)>,
    assert_graceful_orchestrator_tasks_exits: bool,
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
    info!(logger, "Storing message: '{}'", msg);
    let can_id = store_message(
        &subnet_node.get_public_url(),
        subnet_node.effective_canister_id(),
        msg,
        &logger,
    );
    info!(logger, "Reading message: '{}'", msg);
    assert!(can_read_msg(
        &logger,
        &subnet_node.get_public_url(),
        can_id,
        msg
    ));
    info!(logger, "Could store and read message '{}'", msg);

    info!(logger, "Creating canister snapshot before upgrading ...");
    block_on(async {
        let agent = create_agent(subnet_node.get_public_url().as_str())
            .await
            .expect("Failed to create agent");
        let mgr = ManagementCanister::create(&agent);
        mgr.take_canister_snapshot(&can_id, None).await.unwrap();
    });

    info!(logger, "Stopping faulty node {} ...", faulty_node.node_id);
    stop_node(&logger, &faulty_node);

    info!(logger, "Upgrade to version {}", upgrade_version);
    upgrade_to(
        nns_node,
        subnet_id,
        &subnet_node,
        upgrade_version,
        assert_graceful_orchestrator_tasks_exits,
        &logger,
    );

    info!(logger, "Stopping redundant nodes ...");
    // Killing redundant nodes should not prevent the `faulty_node` from upgrading
    // and catching up after restarting.
    for redundant_node in &redundant_nodes {
        info!(
            logger,
            "Stopping redundant node: {} ...", redundant_node.node_id
        );
        stop_node(&logger, redundant_node);
    }
    info!(logger, "Starting faulty node: {} ...", faulty_node.node_id);
    start_node(&logger, &faulty_node);

    info!(
        logger,
        "Asserting that the faulty node is running the expected version: {} ...", upgrade_version
    );
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

    info!(logger, "Starting redundant nodes ...");
    for redundant_node in &redundant_nodes {
        info!(
            logger,
            "Starting redundant node: {} ...", redundant_node.node_id
        );
        start_node(&logger, redundant_node);
    }

    (faulty_node.clone(), can_id, msg.into())
}

fn upgrade_to(
    nns_node: &IcNodeSnapshot,
    subnet_id: SubnetId,
    subnet_node: &IcNodeSnapshot,
    target_version: &ReplicaVersion,
    assert_graceful_orchestrator_tasks_exits: bool,
    logger: &Logger,
) {
    info!(
        logger,
        "Upgrading subnet {} to {}", subnet_id, target_version
    );
    block_on(deploy_guestos_to_all_subnet_nodes(
        nns_node,
        target_version,
        subnet_id,
    ));

    if assert_graceful_orchestrator_tasks_exits {
        info!(
            logger,
            "Checking if the node {} has produced a log \
            indicating that the orchestrator has gracefully shut down the tasks",
            subnet_node.get_ip_addr(),
        );
        block_on(assert_orchestrator_stopped_gracefully(subnet_node.clone()));
        info!(logger, "The orchestrator shut down the tasks gracefully");
    }

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

async fn assert_orchestrator_stopped_gracefully(node: IcNodeSnapshot) {
    const MESSAGE: &str = r"Orchestrator shut down gracefully";

    let script = format!("journalctl -f | grep -q \"{MESSAGE}\"");

    let ssh_session = node
        .block_on_ssh_session()
        .expect("Failed to establish SSH session");

    execute_bash_command(&ssh_session, script).expect("Didn't find the appropriate log entry");
}
