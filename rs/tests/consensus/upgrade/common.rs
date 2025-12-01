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
use futures::future::try_join_all;
use ic_agent::Agent;
use ic_consensus_system_test_utils::rw_message::{
    can_read_msg, cert_state_makes_progress_with_retries, store_message,
};
use ic_consensus_system_test_utils::subnet::enable_chain_key_signing_on_subnet;
use ic_consensus_system_test_utils::upgrade::{
    assert_assigned_replica_version, bless_replica_version, deploy_guestos_to_all_subnet_nodes,
};
use ic_consensus_threshold_sig_system_test_utils::run_chain_key_signature_test;
use ic_management_canister_types_private::MasterPublicKeyId;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::util::{LogStream, create_agent};
use ic_system_test_driver::{
    driver::{test_env::TestEnv, test_env_api::*},
    util::{MessageCanister, block_on},
};
use ic_types::{NodeId, ReplicaVersion, SubnetId};
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
) -> (IcNodeSnapshot, Principal, String) {
    let logger = env.logger();
    let (subnet_id, subnet_nodes, healthy_node, faulty_node, redundant_nodes) =
        if subnet_type == SubnetType::System {
            let subnet = env.topology_snapshot().root_subnet();
            let subnet_nodes = subnet.nodes().collect::<Vec<_>>();

            let mut it = subnet.nodes();
            // We don't want to hit the node we're using for sending the proposals
            assert!(it.next().unwrap().node_id == nns_node.node_id);
            let healthy_node = it.next().unwrap();
            let faulty_node = it.next().unwrap();
            let mut redundant_nodes = Vec::new();
            for _ in 0..ALLOWED_FAILURES {
                redundant_nodes.push(it.next().unwrap());
            }
            (
                subnet.subnet_id,
                subnet_nodes,
                healthy_node,
                faulty_node,
                redundant_nodes,
            )
        } else {
            let subnet = env
                .topology_snapshot()
                .subnets()
                .find(|subnet| subnet.subnet_type() == SubnetType::Application)
                .expect("there is no application subnet");
            let subnet_nodes = subnet.nodes().collect::<Vec<_>>();

            let mut it = subnet.nodes();
            let healthy_node = it.next().unwrap();
            let faulty_node = it.next().unwrap();
            let mut redundant_nodes = Vec::new();
            for _ in 0..ALLOWED_FAILURES {
                redundant_nodes.push(it.next().unwrap());
            }
            (
                subnet.subnet_id,
                subnet_nodes,
                healthy_node,
                faulty_node,
                redundant_nodes,
            )
        };
    info!(logger, "upgrade: healthy_node = {:?}", healthy_node.node_id);
    healthy_node.await_status_is_healthy().unwrap();
    faulty_node.await_status_is_healthy().unwrap();

    let msg = &format!("hello before upgrade to {upgrade_version}");
    info!(logger, "Storing message: '{}'", msg);
    let can_id = store_message(
        &healthy_node.get_public_url(),
        healthy_node.effective_canister_id(),
        msg,
        &logger,
    );
    info!(logger, "Reading message: '{}'", msg);
    assert!(can_read_msg(
        &logger,
        &healthy_node.get_public_url(),
        can_id,
        msg
    ));
    info!(logger, "Could store and read message '{}'", msg);

    info!(logger, "Creating canister snapshot before upgrading ...");
    block_on(async {
        let agent = create_agent(healthy_node.get_public_url().as_str())
            .await
            .expect("Failed to create agent");
        let mgr = ManagementCanister::create(&agent);
        mgr.take_canister_snapshot(&can_id, None).await.unwrap();
    });

    info!(logger, "Stopping faulty node {} ...", faulty_node.node_id);
    stop_node(&logger, &faulty_node);

    info!(logger, "Upgrade to version {}", upgrade_version);
    block_on(upgrade_to(
        nns_node,
        subnet_id,
        subnet_nodes.len(),
        subnet_nodes
            .into_iter()
            .filter(|n| n.node_id != faulty_node.node_id)
            .collect(),
        upgrade_version,
        &logger,
    ));

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

/// Deploys the target version to all nodes of the given subnet, and performs the necessary checks
/// to ensure that the upgrade was successful. Those include:
/// - Checking that all nodes produced a log indicating that the orchestrator has gracefully shut
///   down the tasks.
/// - Checking that at least n - f nodes produced a log displaying the latest computed root hash.
///   This is useful for recoveries, in case we need to know the latest state hash but it is
///   impossible to provision SSH keys.
/// - After reboot, checking that the state hash from the local CUP matches the one extracted from
///   the logs before reboot, for the nodes that logged that hash.
/// - Checking that all nodes have the target version assigned after the upgrade.
async fn upgrade_to(
    nns_node: &IcNodeSnapshot,
    subnet_id: SubnetId,
    num_nodes: usize,
    healthy_nodes: Vec<IcNodeSnapshot>,
    target_version: &ReplicaVersion,
    logger: &Logger,
) {
    let log_streams = LogStream::open(healthy_nodes.iter().cloned())
        .await
        .unwrap();

    info!(
        logger,
        "Upgrading subnet {} to {}", subnet_id, target_version
    );
    deploy_guestos_to_all_subnet_nodes(nns_node, target_version, subnet_id).await;

    info!(
        logger,
        "Checking that all nodes produced a log indicating that the orchestrator has gracefully shut \
        down the tasks, as well as at least n - f nodes producing a log displaying the latest computed \
        root hash.",
    );

    // Concurrently assert that all orchestrators shut down gracefully and fetch the latest computed
    // root hash from logs of each node
    let graceful_stops_handle = try_join_all(healthy_nodes.iter().map(|node| {
        let node_cl = node.clone();
        tokio::spawn(async move {
            assert_orchestrator_stopped_gracefully(&node_cl).await;
        })
    }));
    let fetch_hashes_handle = {
        let logger_cl = logger.clone();
        tokio::spawn(async move {
            fetch_latest_computed_root_hashes_from_logs(&logger_cl, log_streams).await
        })
    };

    let (graceful_stops_result, fetch_hashes_result) =
        tokio::join!(graceful_stops_handle, fetch_hashes_handle);

    // Ensure that all nodes gracefully stopped
    graceful_stops_result.unwrap();
    info!(logger, "All orchestrators shut down the tasks gracefully");

    let state_hashes_from_logs = fetch_hashes_result.unwrap();
    // Find all nodes that logged the same latest computed root hash and pick the most common one
    let mut state_hashes_counts = BTreeMap::new();
    for (node_id, hash) in state_hashes_from_logs.iter() {
        state_hashes_counts
            .entry(hash.clone())
            .or_insert_with(Vec::new)
            .push(*node_id);
    }
    let (most_common_hash, nodes_that_logged_hash) = state_hashes_counts
        .into_iter()
        .max_by_key(|(_, nodes)| nodes.len())
        .expect("No state hashes found in logs");

    let n = num_nodes;
    let f = (n - 1) / 3;
    assert!(
        nodes_that_logged_hash.len() >= n - f,
        "{} < n - f nodes produced the same latest computed root hash in logs",
        nodes_that_logged_hash.len()
    );

    info!(
        logger,
        "Extracted state hash from logs of {} nodes before they rebooted: {}",
        nodes_that_logged_hash.len(),
        most_common_hash
    );

    for node in healthy_nodes {
        assert_assigned_replica_version(&node, target_version, logger.clone());
    }
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

/// Fetches the latest computed state root hash from the node logs by continously searching for
/// matching log entries until the log stream ends (which indicates that all nodes rebooted).
/// Returns the last computed root hash found in the logs for every node.
///
/// This function will never return if an upgrade is not scheduled.
async fn fetch_latest_computed_root_hashes_from_logs(
    logger: &Logger,
    mut log_streams: LogStream,
) -> BTreeMap<NodeId, String> {
    let computed_root_hash_regex =
        regex::Regex::new(r#"Computed root hash CryptoHash\(0x([a-f0-9]{64})\) of state @(\d*)"#)
            .unwrap();

    let mut latest_root_hash_per_node = BTreeMap::new();
    while let Ok((node, entry)) = log_streams
        .find(|_, line| computed_root_hash_regex.is_match(line))
        .await
    {
        let (computed_root_hash, height) = computed_root_hash_regex
            .captures(&entry)
            .and_then(|caps| {
                let hash_group = caps.get(1)?.as_str().to_string();
                let height_group = caps.get(2)?.as_str().parse::<u64>().ok()?;
                Some((hash_group, height_group))
            })
            .expect("Failed to extract computed root hash from log entry");

        info!(
            logger,
            "Found computed root hash log entry for node {} @{}: {}",
            node.node_id,
            height,
            computed_root_hash
        );

        latest_root_hash_per_node.insert(node.node_id, computed_root_hash);
    }

    latest_root_hash_per_node
}

/// Asserts that the orchestrator has shut down gracefully by searching for a specific log entry.
/// Panics if the log entry is not found but the log stream ends (which indicates the node
/// rebooted).
///
/// We use a bash script instead of connecting to the log stream endpoint because as the
/// orchestrator is shutting down, the endpoint might close right away without letting us the
/// chance to read the relevant log entry. In constrast, the SSH connection remains open longer.
///
/// This function will never return if an upgrade is not scheduled.
async fn assert_orchestrator_stopped_gracefully(node: &IcNodeSnapshot) {
    const MESSAGE: &str = r"Orchestrator shut down gracefully";

    let script = format!("journalctl -f | grep -q \"{MESSAGE}\"");

    node.block_on_bash_script_async(&script)
        .await
        .expect("Orchestrator did not shut down gracefully");
}
