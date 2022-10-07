use crate::orchestrator::utils::rw_message::{can_install_canister_with_retries, can_store_msg};
use crate::orchestrator::utils::ssh_access::execute_bash_command;
use crate::orchestrator::utils::upgrade::assert_assigned_replica_version;
use crate::tecdsa::tecdsa_signature_test::{
    create_new_subnet_with_keys, enable_ecdsa_signing, get_public_key_with_logger,
    get_signature_with_logger, make_key, verify_signature, KEY_ID1,
};
use crate::util::*;
use crate::{
    driver::{test_env::TestEnv, test_env_api::*},
    orchestrator::utils::rw_message::{can_read_msg, cannot_store_msg},
    util::runtime_from_url,
};
use anyhow::bail;
use candid::Principal;
use canister_test::Canister;
use ic_base_types::SubnetId;
use ic_config::subnet_config::ECDSA_SIGNATURE_FEE;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_recovery::steps::Step;
use ic_recovery::{get_node_metrics, NodeMetrics, Recovery};
use ic_registry_subnet_type::SubnetType;
use ic_types::ReplicaVersion;
use registry_canister::mutations::do_create_subnet::EcdsaKeyRequest;
use secp256k1::PublicKey;
use slog::{info, Logger};
use url::Url;

/// break a subnet by breaking the replica binary on f+1 = (subnet_size - 1) / 3 +1
/// nodes taken from the given iterator.
pub(crate) fn break_subnet(
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
pub(crate) fn halt_subnet(
    app_node: &IcNodeSnapshot,
    subnet_id: SubnetId,
    recovery: &Recovery,
    logger: &Logger,
) {
    info!(logger, "Breaking the app subnet by halting it",);
    recovery
        .halt_subnet(subnet_id, true, &[])
        .exec()
        .expect("Failed to halt subnet.");
    let s = app_node.get_ssh_session(ADMIN).unwrap();
    retry(logger.clone(), secs(120), secs(10), || {
        let res = execute_bash_command(&s, "journalctl | grep -c 'is halted'".to_string());
        if res.map_or(false, |r| r.trim().parse::<i32>().unwrap() > 0) {
            Ok(())
        } else {
            bail!("retry...")
        }
    })
    .expect("Failed to detect broken subnet.");
}

/// A subnet is considered to be broken if it still works in read mode,
/// but doesn't in write mode
pub(crate) fn assert_subnet_is_broken(
    node_url: &Url,
    can_id: Principal,
    msg: &str,
    logger: &Logger,
) {
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

/// A subnet is considered to be healthy if all nodes in the given vector are healthy
/// and running the given version, canisters can be installed and messages can be written and read.
pub(crate) fn assert_subnet_is_healthy(
    subnet: &Vec<IcNodeSnapshot>,
    target_version: String,
    can_id: Principal,
    msg: &str,
    logger: &Logger,
) {
    // Confirm that ALL nodes are now healthy and running on the new version
    for node in subnet {
        assert_assigned_replica_version(node, &target_version, logger.clone());
        info!(
            logger,
            "Healthy upgrade of assigned node {} to {}", node.node_id, target_version
        );
    }

    let node = &subnet[0];
    node.await_status_is_healthy().unwrap();
    // make sure that state sync is completed
    can_install_canister_with_retries(&node.get_public_url(), logger, secs(600), secs(10));

    info!(logger, "Ensure the old message is still readable");
    assert!(
        can_read_msg(logger, &node.get_public_url(), can_id, msg),
        "Failed to read old message on {}",
        node.get_ip_addr()
    );
    let new_msg = "subnet recovery still works!";
    info!(
        logger,
        "Ensure that the subnet is accepting updates after the recovery"
    );
    assert!(
        can_store_msg(logger, &node.get_public_url(), can_id, new_msg),
        "Failed to store new message on {}",
        node.get_ip_addr()
    );
    assert!(
        can_read_msg(logger, &node.get_public_url(), can_id, new_msg),
        "Failed to read new message on {}",
        node.get_ip_addr()
    );
}

/// Select a node with highest finalization height in the given subnet snapshot
pub(crate) fn select_download_node(
    subnet: SubnetSnapshot,
    logger: &Logger,
) -> (IcNodeSnapshot, NodeMetrics) {
    let node = subnet
        .nodes()
        .filter_map(|n| get_node_metrics(logger, &n.get_ip_addr()).map(|m| (n, m)))
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
pub(crate) fn print_app_and_unassigned_nodes(env: &TestEnv, logger: &Logger) {
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

/// Enable ecdsa on the root subnet using the given NNS node, then
/// create a new subnet of the given size initialized with the ecdsa key.
/// Wait until nodes of the new subnet report healthy.
pub(crate) fn enable_ecdsa_and_create_subnet(
    env: &TestEnv,
    nns_node: &IcNodeSnapshot,
    subnet_size: usize,
    replica_version: ReplicaVersion,
    logger: &Logger,
) {
    info!(logger, "Enabling ECDSA signatures.");
    let nns_runtime = runtime_from_url(nns_node.get_public_url());
    let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);
    let root_subnet_id = env.topology_snapshot().root_subnet_id();
    block_on(async {
        enable_ecdsa_signing(&governance, root_subnet_id, make_key(KEY_ID1)).await;
    });

    get_canister_and_ecdsa_pub_key(nns_node, None, logger);

    let unassigned_node_ids = env
        .topology_snapshot()
        .unassigned_nodes()
        .take(subnet_size)
        .map(|n| n.node_id)
        .collect();

    block_on(async {
        create_new_subnet_with_keys(
            &governance,
            unassigned_node_ids,
            vec![EcdsaKeyRequest {
                key_id: make_key(KEY_ID1),
                subnet_id: Some(root_subnet_id.get()),
            }],
            replica_version,
        )
        .await;
    });

    let topology_snapshot = env
        .topology_snapshot()
        .block_for_newer_registry_version()
        .unwrap();

    let app_subnet = topology_snapshot
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("there is no application subnet");

    app_subnet.nodes().for_each(|n| {
        n.await_status_is_healthy()
            .expect("Timeout while waiting for all subnets to be healthy");
    });
}

pub(crate) fn get_canister_and_ecdsa_pub_key(
    node: &IcNodeSnapshot,
    existing_can_id: Option<Principal>,
    logger: &Logger,
) -> (Principal, PublicKey) {
    info!(logger, "Initial run to get app ecdsa public key.");
    let agent = node.with_default_agent(|agent| async move { agent });
    let (canister_id, public_key) = block_on(async {
        let uni_can = if let Some(can_id) = existing_can_id {
            UniversalCanister::from_canister_id(&agent, can_id)
        } else {
            UniversalCanister::new(&agent).await
        };
        let public_key = get_public_key_with_logger(make_key(KEY_ID1), &uni_can, logger)
            .await
            .unwrap();
        (uni_can.canister_id(), public_key)
    });
    info!(
        logger,
        "Got public key of canister {}: {}", canister_id, public_key
    );
    (canister_id, public_key)
}

pub(crate) fn run_ecdsa_signature_test(
    node: &IcNodeSnapshot,
    logger: &Logger,
    ecdsa_canister_and_key: (Principal, PublicKey),
) {
    let (canister_id, public_key) = ecdsa_canister_and_key;
    info!(logger, "Run through ecdsa signature test.");
    let message_hash = [0xabu8; 32];
    let agent = node.with_default_agent(|agent| async move { agent });
    block_on(async {
        let uni_can = UniversalCanister::from_canister_id(&agent, canister_id);
        let public_key_ = get_public_key_with_logger(make_key(KEY_ID1), &uni_can, logger)
            .await
            .unwrap();
        assert_eq!(public_key, public_key_);
        let signature = get_signature_with_logger(
            &message_hash,
            ECDSA_SIGNATURE_FEE,
            make_key(KEY_ID1),
            &uni_can,
            logger,
        )
        .await
        .unwrap();
        verify_signature(&message_hash, &public_key_, &signature);
    });
}
