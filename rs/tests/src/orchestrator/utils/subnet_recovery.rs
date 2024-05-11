use std::path::PathBuf;
use std::time::Duration;

use crate::orchestrator::utils::rw_message::{
    can_store_msg, cert_state_makes_progress_with_retries,
};
use crate::orchestrator::utils::ssh_access::execute_bash_command;
use crate::orchestrator::utils::upgrade::assert_assigned_replica_version;
use crate::tecdsa::{
    add_ecdsa_keys_with_timeout_and_rotation_period, create_new_subnet_with_keys,
    empty_subnet_update, execute_update_subnet_proposal, get_public_key_with_retries,
    get_signature_with_logger, make_key, verify_signature, KEY_ID1,
};
use crate::util::*;
use crate::{
    driver::{test_env::TestEnv, test_env_api::*},
    orchestrator::utils::rw_message::{can_read_msg, cannot_store_msg},
    retry_with_msg,
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
use k256::ecdsa::VerifyingKey;
use registry_canister::mutations::do_create_subnet::EcdsaKeyRequest;
use registry_canister::mutations::do_update_subnet::UpdateSubnetPayload;
use serde::{Deserialize, Serialize};
use slog::{info, Logger};
use url::Url;

pub fn set_sandbox_env_vars(dir: PathBuf) {
    set_var_to_path("SANDBOX_BINARY", dir.join("canister_sandbox"));
    set_var_to_path("LAUNCHER_BINARY", dir.join("sandbox_launcher"));
    set_var_to_path("COMPILER_BINARY", dir.join("compiler_sandbox"));
}

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
    #[derive(Debug, Deserialize, Serialize)]
    struct Cursor {
        #[serde(alias = "__CURSOR")]
        cursor: String,
    }

    info!(logger, "Breaking the app subnet by halting it",);
    let s = app_node.block_on_ssh_session().unwrap();
    let message_str = execute_bash_command(
        &s,
        "journalctl -n1 -o json --output-fields='__CURSOR'".to_string(),
    )
    .expect("journal message");
    let message: Cursor = serde_json::from_str(&message_str).expect("JSON journal message");
    recovery
        .halt_subnet(subnet_id, true, &[])
        .exec()
        .expect("Failed to halt subnet.");
    retry_with_msg!(
        "check if consensus is halted",
        logger.clone(),
        secs(120),
        secs(10),
        || {
            let res = execute_bash_command(
                &s,
                format!(
                    "journalctl --after-cursor='{}' | grep -c 'is halted'",
                    message.cursor
                ),
            );
            if res.map_or(false, |r| r.trim().parse::<i32>().unwrap() > 0) {
                Ok(())
            } else {
                bail!("Did not find log entry that consensus is halted.")
            }
        }
    )
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
    info!(
        logger,
        "Confirm that ALL nodes are now healthy and running on the new version {target_version}"
    );
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
    cert_state_makes_progress_with_retries(
        &node.get_public_url(),
        node.effective_canister_id(),
        logger,
        secs(600),
        secs(10),
    );

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

/// Assert that the given node has deleted its state within the next 5 minutes.
pub(crate) fn assert_node_is_unassigned(node: &IcNodeSnapshot, logger: &Logger) {
    info!(
        logger,
        "Asserting that node {} has deleted its state.",
        node.get_ip_addr()
    );
    // We need to exclude the page_deltas/ directory, which is not deleted on state deletion.
    // That is because deleting it would break SELinux assumptions.
    let check = r#"[ "$(ls -A /var/lib/ic/data/ic_state -I page_deltas)" ] && echo "assigned" || echo "unassigned""#;
    let s = node
        .block_on_ssh_session()
        .expect("Failed to establish SSH session");

    retry_with_msg!(
        format!("check if node {} is unassigned", node.node_id),
        logger.clone(),
        secs(300),
        secs(10),
        || match execute_bash_command(&s, check.to_string()) {
            Ok(s) if s.trim() == "unassigned" => Ok(()),
            Ok(s) if s.trim() == "assigned" => {
                bail!("Node {} is still assigned.", node.get_ip_addr())
            }
            Ok(s) => bail!("Received unexpected output: {}", s),
            Err(e) => bail!("Failed to read directory: {}", e),
        }
    )
    .expect("Failed to detect that node has deleted its state.");
}

/// Select a node with highest finalization height in the given subnet snapshot
pub(crate) fn select_download_node(
    subnet: SubnetSnapshot,
    logger: &Logger,
) -> (IcNodeSnapshot, NodeMetrics) {
    let node = subnet
        .nodes()
        .filter_map(|n| block_on(get_node_metrics(logger, &n.get_ip_addr())).map(|m| (n, m)))
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

/// Enable ECDSA key and signing on the subnet using the given NNS node.
pub fn enable_ecdsa_on_subnet(
    nns_node: &IcNodeSnapshot,
    canister: &MessageCanister,
    subnet_id: SubnetId,
    rotation_period: Option<Duration>,
    logger: &Logger,
) -> VerifyingKey {
    info!(logger, "Enabling ECDSA signatures.");
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);

    block_on(add_ecdsa_keys_with_timeout_and_rotation_period(
        &governance,
        subnet_id,
        vec![make_key(KEY_ID1)],
        None,
        rotation_period,
        logger,
    ));

    enable_ecdsa_signing_on_subnet(nns_node, canister, subnet_id, logger)
}

/// Pre-condition: subnet has the ECDSA key and no other subnet has signing enabled for that key.
/// Enables ECDSA signing on the given subnet and returns a public key for the given canister.
pub(crate) fn enable_ecdsa_signing_on_subnet(
    nns_node: &IcNodeSnapshot,
    canister: &MessageCanister,
    subnet_id: SubnetId,
    logger: &Logger,
) -> VerifyingKey {
    info!(logger, "Enabling signing on subnet {}.", subnet_id);
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);

    let enable_signing_payload = UpdateSubnetPayload {
        subnet_id,
        ecdsa_key_signing_enable: Some(vec![make_key(KEY_ID1)]),
        ..empty_subnet_update()
    };
    block_on(execute_update_subnet_proposal(
        &governance,
        enable_signing_payload,
        "Enable ECDSA signing",
        logger,
    ));

    get_ecdsa_pub_key(canister, logger)
}

/// Enable ecdsa on the root subnet using the given NNS node, then
/// create a new subnet of the given size initialized with the ecdsa key.
/// Disable signing on NNS and enable it on the new app subnet.
/// Assert that the key stays the same regardless of whether signing
/// is enabled on NNS or the app subnet. Return the public key for the given canister.
pub(crate) fn enable_ecdsa_on_new_subnet(
    env: &TestEnv,
    nns_node: &IcNodeSnapshot,
    canister: &MessageCanister,
    subnet_size: usize,
    replica_version: ReplicaVersion,
    logger: &Logger,
) -> VerifyingKey {
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);
    let snapshot = env.topology_snapshot();
    let root_subnet_id = snapshot.root_subnet_id();
    let registry_version = snapshot.get_registry_version();

    info!(logger, "Enabling signing on NNS.");
    let nns_key = enable_ecdsa_signing_on_subnet(nns_node, canister, root_subnet_id, logger);
    let snapshot =
        block_on(snapshot.block_for_min_registry_version(registry_version.increment())).unwrap();
    let registry_version = snapshot.get_registry_version();

    let unassigned_node_ids = snapshot
        .unassigned_nodes()
        .take(subnet_size)
        .map(|n| n.node_id)
        .collect();

    info!(logger, "Creating new subnet with keys.");
    block_on(create_new_subnet_with_keys(
        &governance,
        unassigned_node_ids,
        vec![EcdsaKeyRequest {
            key_id: make_key(KEY_ID1),
            subnet_id: Some(root_subnet_id.get()),
        }],
        replica_version,
        logger,
    ));

    let snapshot =
        block_on(snapshot.block_for_min_registry_version(registry_version.increment())).unwrap();

    let app_subnet = snapshot
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("there is no application subnet");

    app_subnet.nodes().for_each(|n| {
        n.await_status_is_healthy()
            .expect("Timeout while waiting for all nodes to be healthy");
    });

    info!(logger, "Disabling signing on NNS.");
    disable_ecdsa_on_subnet(nns_node, root_subnet_id, canister, logger);
    let app_key = enable_ecdsa_signing_on_subnet(nns_node, canister, app_subnet.subnet_id, logger);

    assert_eq!(app_key, nns_key);
    app_key
}

/// Disable ecdsa signing on the given subnet and wait until sign requests fail.
pub(crate) fn disable_ecdsa_on_subnet(
    nns_node: &IcNodeSnapshot,
    subnet_id: SubnetId,
    canister: &MessageCanister,
    logger: &Logger,
) {
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);

    let disable_signing_payload = UpdateSubnetPayload {
        subnet_id,
        ecdsa_key_signing_disable: Some(vec![make_key(KEY_ID1)]),
        ..empty_subnet_update()
    };
    block_on(execute_update_subnet_proposal(
        &governance,
        disable_signing_payload,
        "Disable ECDSA signing",
        logger,
    ));

    info!(logger, "Waiting until signing fails.");
    let message_hash = [0xabu8; 32];
    retry_with_msg!(
        "check if signing has failed",
        logger.clone(),
        secs(120),
        secs(2),
        || {
            let sig_result = block_on(get_signature_with_logger(
                &message_hash,
                ECDSA_SIGNATURE_FEE,
                make_key(KEY_ID1),
                canister,
                logger,
            ));
            if sig_result.is_ok() {
                bail!("Signing is still possible.")
            } else {
                Ok(())
            }
        }
    )
    .expect("Failed to detect disabled signing.");
}

/// Get the ECDSA public key of the given canister
pub(crate) fn get_ecdsa_pub_key(canister: &MessageCanister, logger: &Logger) -> VerifyingKey {
    info!(logger, "Getting ecdsa public key.");
    let public_key = block_on(get_public_key_with_retries(
        make_key(KEY_ID1),
        canister,
        logger,
        300,
    ))
    .unwrap();
    info!(logger, "Got public key {:?}", public_key);
    public_key
}

/// The signature test consists of getting the given canister's ECDSA key, comparing it to the existing key
/// to ensure it hasn't changed, sending a sign request, and verifying the signature
pub fn run_ecdsa_signature_test(
    canister: &MessageCanister,
    logger: &Logger,
    existing_key: VerifyingKey,
) {
    info!(logger, "Run through ecdsa signature test.");
    let message_hash = [0xabu8; 32];
    block_on(async {
        let public_key = get_public_key_with_retries(make_key(KEY_ID1), canister, logger, 300)
            .await
            .unwrap();
        assert_eq!(existing_key, public_key);
        let signature = get_signature_with_logger(
            &message_hash,
            ECDSA_SIGNATURE_FEE,
            make_key(KEY_ID1),
            canister,
            logger,
        )
        .await
        .unwrap();
        verify_signature(&message_hash, &public_key, &signature);
    });
}
