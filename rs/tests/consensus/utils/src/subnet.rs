use crate::rw_message::{
    can_read_msg, can_read_msg_with_retries, can_store_msg, cert_state_makes_progress_with_retries,
};
use crate::upgrade::assert_assigned_replica_version;
use anyhow::bail;
use candid::Principal;
use canister_test::Canister;
use ic_base_types::SubnetId;
use ic_config::subnet_config::ECDSA_SIGNATURE_FEE;
use ic_consensus_threshold_sig_system_test_utils::{
    add_chain_keys_with_timeout_and_rotation_period, empty_subnet_update,
    execute_update_subnet_proposal, get_master_public_key, get_signature_with_logger,
};
use ic_management_canister_types_private::MasterPublicKeyId;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_system_test_driver::util::*;
use ic_system_test_driver::{driver::test_env_api::*, util::runtime_from_url};
use ic_types::ReplicaVersion;
use registry_canister::mutations::do_update_subnet::UpdateSubnetPayload;
use slog::{Logger, info};
use std::collections::BTreeMap;
use std::time::Duration;

/// A subnet is considered to be healthy if all given nodes are healthy and running the given
/// version, the certified time advances, and messages can be written and read.
pub fn assert_subnet_is_healthy(
    subnet: &[IcNodeSnapshot],
    target_version: &ReplicaVersion,
    can_id: Principal,
    old_msg: &str,
    new_msg: &str,
    logger: &Logger,
) {
    info!(
        logger,
        "Confirm that ALL nodes are healthy and running on version {target_version}"
    );
    for node in subnet {
        assert_assigned_replica_version(node, target_version, logger.clone());
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
        can_read_msg(logger, &node.get_public_url(), can_id, old_msg),
        "Failed to read old message on {}",
        node.get_ip_addr()
    );
    info!(logger, "Ensure that the subnet is accepting updates");
    assert!(
        can_store_msg(logger, &node.get_public_url(), can_id, new_msg),
        "Failed to store new message on {}",
        node.get_ip_addr()
    );
    // Wait until all nodes answer with the new message
    for node in subnet {
        assert!(
            can_read_msg_with_retries(logger, &node.get_public_url(), can_id, new_msg, 5),
            "Failed to read new message on {}",
            node.get_ip_addr()
        );
    }
}

/// Enable Chain key and signing on the subnet using the given NNS node.
pub fn enable_chain_key_on_subnet(
    nns_node: &IcNodeSnapshot,
    canister: &MessageCanister,
    subnet_id: SubnetId,
    rotation_period: Option<Duration>,
    key_ids: Vec<MasterPublicKeyId>,
    logger: &Logger,
) -> BTreeMap<MasterPublicKeyId, Vec<u8>> {
    info!(logger, "Enabling Chain key signatures.");
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);

    block_on(add_chain_keys_with_timeout_and_rotation_period(
        &governance,
        subnet_id,
        key_ids.clone(),
        None,
        rotation_period,
        logger,
    ));

    enable_chain_key_signing_on_subnet(nns_node, canister, subnet_id, key_ids, logger)
}

/// Pre-condition: subnet has the Chain key and no other subnet has signing enabled for that key.
/// Enables Chain key signing on the given subnet and returns a public key for the given canister.
pub fn enable_chain_key_signing_on_subnet(
    nns_node: &IcNodeSnapshot,
    canister: &MessageCanister,
    subnet_id: SubnetId,
    key_ids: Vec<MasterPublicKeyId>,
    logger: &Logger,
) -> BTreeMap<MasterPublicKeyId, Vec<u8>> {
    info!(logger, "Enabling signing on subnet {}.", subnet_id);
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);

    let enable_signing_payload = UpdateSubnetPayload {
        subnet_id,
        chain_key_signing_enable: Some(key_ids.clone()),
        ..empty_subnet_update()
    };
    block_on(execute_update_subnet_proposal(
        &governance,
        enable_signing_payload,
        "Enable Chain key signing",
        logger,
    ));

    key_ids
        .iter()
        .map(|key_id| {
            (
                key_id.clone(),
                get_master_public_key(canister, key_id, logger),
            )
        })
        .collect()
}

/// Disable Chain key signing on the given subnet and wait until sign requests fail.
pub fn disable_chain_key_on_subnet(
    nns_node: &IcNodeSnapshot,
    subnet_id: SubnetId,
    canister: &MessageCanister,
    key_ids: Vec<MasterPublicKeyId>,
    logger: &Logger,
) {
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);
    let disable_signing_payload = UpdateSubnetPayload {
        subnet_id,
        chain_key_signing_disable: Some(key_ids.clone()),
        ..empty_subnet_update()
    };
    block_on(execute_update_subnet_proposal(
        &governance,
        disable_signing_payload,
        "Disable Chain key signing",
        logger,
    ));

    info!(logger, "Waiting until signing fails.");
    let message_hash = vec![0xabu8; 32];
    for key_id in key_ids {
        ic_system_test_driver::retry_with_msg!(
            "check if signing has failed",
            logger.clone(),
            secs(120),
            secs(2),
            || {
                let sig_result = block_on(get_signature_with_logger(
                    message_hash.clone(),
                    ECDSA_SIGNATURE_FEE,
                    &key_id,
                    canister,
                    logger,
                ));
                if sig_result.is_ok() {
                    bail!("Signing with key {} is still possible.", key_id)
                } else {
                    Ok(())
                }
            }
        )
        .expect("Failed to detect disabled signing.");
    }
}
