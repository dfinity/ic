use std::time::Duration;

use crate::{nns::vote_and_execute_proposal, util::MessageCanister};

use candid::{Encode, Principal};
use canister_test::{Canister, Cycles};
use ic_agent::AgentError;
use ic_base_types::{NodeId, SubnetId};
use ic_canister_client::Sender;
use ic_management_canister_types::{
    DerivationPath, ECDSAPublicKeyArgs, ECDSAPublicKeyResponse, EcdsaCurve, EcdsaKeyId, Payload,
    SignWithECDSAArgs, SignWithECDSAReply,
};
use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_KEYPAIR;
use ic_nns_common::types::NeuronId;
use ic_nns_governance::{
    init::TEST_NEURON_1_ID,
    pb::v1::{NnsFunction, ProposalStatus},
};
use ic_nns_test_utils::governance::submit_external_update_proposal;
use ic_registry_subnet_features::{EcdsaConfig, DEFAULT_ECDSA_MAX_QUEUE_SIZE};
use ic_registry_subnet_type::SubnetType;
use ic_types::{p2p, ReplicaVersion};
use ic_types_test_utils::ids::subnet_test_id;
use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use registry_canister::mutations::{
    do_create_subnet::{CreateSubnetPayload, EcdsaInitialConfig, EcdsaKeyRequest},
    do_update_subnet::UpdateSubnetPayload,
};
use slog::{debug, info, Logger};

pub mod tecdsa_add_nodes_test;
pub mod tecdsa_complaint_test;
pub mod tecdsa_remove_nodes_test;
pub mod tecdsa_signature_test;
pub mod tecdsa_two_signing_subnets_test;

pub(crate) const KEY_ID1: &str = "secp256k1";
pub(crate) const KEY_ID2: &str = "some_other_key";

/// The default DKG interval takes too long before the keys are created and
/// passed to execution.
pub(crate) const DKG_INTERVAL: u64 = 19;

pub(crate) fn make_key(name: &str) -> EcdsaKeyId {
    EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: name.to_string(),
    }
}

pub(crate) fn empty_subnet_update() -> UpdateSubnetPayload {
    UpdateSubnetPayload {
        subnet_id: subnet_test_id(0),
        max_ingress_bytes_per_message: None,
        max_ingress_messages_per_block: None,
        max_block_payload_size: None,
        unit_delay_millis: None,
        initial_notary_delay_millis: None,
        dkg_interval_length: None,
        dkg_dealings_per_block: None,
        max_artifact_streams_per_peer: None,
        max_chunk_wait_ms: None,
        max_duplicity: None,
        max_chunk_size: None,
        receive_check_cache_size: None,
        pfn_evaluation_period_ms: None,
        registry_poll_period_ms: None,
        retransmission_request_ms: None,
        set_gossip_config_to_default: false,
        start_as_nns: None,
        subnet_type: None,
        is_halted: None,
        halt_at_cup_height: None,
        max_instructions_per_message: None,
        max_instructions_per_round: None,
        max_instructions_per_install_code: None,
        features: None,
        ecdsa_config: None,
        ecdsa_key_signing_enable: None,
        ecdsa_key_signing_disable: None,
        max_number_of_canisters: None,
        ssh_readonly_access: None,
        ssh_backup_access: None,
    }
}

pub(crate) async fn get_public_key_with_retries(
    key_id: EcdsaKeyId,
    msg_can: &MessageCanister<'_>,
    logger: &Logger,
    retries: u64,
) -> Result<VerifyingKey, AgentError> {
    let public_key_request = ECDSAPublicKeyArgs {
        canister_id: None,
        derivation_path: DerivationPath::new(vec![]),
        key_id,
    };
    info!(
        logger,
        "Sending a 'get public key' request: {:?}", public_key_request
    );

    let mut count = 0;
    let public_key = loop {
        let res = msg_can
            .forward_to(
                &Principal::management_canister(),
                "ecdsa_public_key",
                Encode!(&public_key_request).unwrap(),
            )
            .await;
        match res {
            Ok(bytes) => {
                let key = ECDSAPublicKeyResponse::decode(&bytes)
                    .expect("failed to decode ECDSAPublicKeyResponse");
                break key.public_key;
            }
            Err(err) => {
                count += 1;
                if count < retries {
                    debug!(
                        logger,
                        "ecdsa_public_key returns `{}`. Trying again...", err
                    );
                    tokio::time::sleep(Duration::from_millis(1000)).await;
                } else {
                    return Err(err);
                }
            }
        }
    };
    info!(logger, "ecdsa_public_key returns {:?}", public_key);
    Ok(VerifyingKey::from_sec1_bytes(&public_key).expect("Response is not a valid public key"))
}

pub(crate) async fn get_public_key_with_logger(
    key_id: EcdsaKeyId,
    msg_can: &MessageCanister<'_>,
    logger: &Logger,
) -> Result<VerifyingKey, AgentError> {
    get_public_key_with_retries(key_id, msg_can, logger, /*retries=*/ 300).await
}

pub(crate) async fn execute_update_subnet_proposal(
    governance: &Canister<'_>,
    proposal_payload: UpdateSubnetPayload,
    title: &str,
    logger: &Logger,
) {
    info!(
        logger,
        "Executing Subnet Update proposal: {:?}", proposal_payload
    );

    let proposal_id = submit_external_update_proposal(
        governance,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::UpdateConfigOfSubnet,
        proposal_payload,
        format!(
            "<subnet update proposal created by threshold ecdsa test>: {}",
            title
        ),
        /*summary=*/ String::default(),
    )
    .await;

    let proposal_result = vote_and_execute_proposal(governance, proposal_id).await;
    info!(
        logger,
        "Subnet Update proposal result: {:?}", proposal_result
    );
    assert_eq!(proposal_result.status(), ProposalStatus::Executed);
}

pub(crate) async fn execute_create_subnet_proposal(
    governance: &Canister<'_>,
    proposal_payload: CreateSubnetPayload,
    logger: &Logger,
) {
    info!(
        logger,
        "Executing Subnet creation proposal: {:?}", proposal_payload
    );

    let proposal_id = submit_external_update_proposal(
        governance,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::CreateSubnet,
        proposal_payload,
        "<subnet creation proposal created by threshold ecdsa test>".to_string(),
        /*summary=*/ String::default(),
    )
    .await;

    let proposal_result = vote_and_execute_proposal(governance, proposal_id).await;
    info!(
        logger,
        "Subnet Creation proposal result: {:?}", proposal_result
    );
    assert_eq!(proposal_result.status(), ProposalStatus::Executed);
}

pub(crate) async fn get_signature_with_logger(
    message_hash: &[u8; 32],
    cycles: Cycles,
    key_id: EcdsaKeyId,
    msg_can: &MessageCanister<'_>,
    logger: &Logger,
) -> Result<Signature, AgentError> {
    let signature_request = SignWithECDSAArgs {
        message_hash: *message_hash,
        derivation_path: DerivationPath::new(Vec::new()),
        key_id,
    };
    info!(logger, "Sending a signing request: {:?}", signature_request);

    let mut count = 0;
    let signature = loop {
        // Ask for a signature.
        let res = msg_can
            .forward_with_cycles_to(
                &Principal::management_canister(),
                "sign_with_ecdsa",
                Encode!(&signature_request).unwrap(),
                cycles,
            )
            .await;
        match res {
            Ok(reply) => {
                let signature = SignWithECDSAReply::decode(&reply)
                    .expect("failed to decode SignWithECDSAReply")
                    .signature;
                break signature;
            }
            Err(err) => {
                count += 1;
                if count < 20 {
                    debug!(logger, "sign_with_ecdsa returns `{}`. Trying again...", err);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                } else {
                    return Err(err);
                }
            }
        }
    };
    info!(logger, "sign_with_ecdsa returns {:?}", signature);

    Ok(Signature::try_from(signature.as_ref()).expect("Response is not a valid signature"))
}

pub(crate) fn verify_signature(
    message_hash: &[u8],
    public_key: &VerifyingKey,
    signature: &Signature,
) {
    // Verify the signature:
    assert!(public_key.verify_prehash(message_hash, signature).is_ok());
}

pub(crate) async fn enable_ecdsa_signing(
    governance: &Canister<'_>,
    subnet_id: SubnetId,
    key_ids: Vec<EcdsaKeyId>,
    logger: &Logger,
) {
    enable_ecdsa_signing_with_timeout(
        governance, subnet_id, key_ids, /*timeout=*/ None, logger,
    )
    .await
}

pub(crate) async fn enable_ecdsa_signing_with_timeout(
    governance: &Canister<'_>,
    subnet_id: SubnetId,
    key_ids: Vec<EcdsaKeyId>,
    timeout: Option<Duration>,
    logger: &Logger,
) {
    enable_ecdsa_signing_with_timeout_and_rotation_period(
        governance, subnet_id, key_ids, timeout, /*period=*/ None, logger,
    )
    .await
}

pub(crate) async fn add_ecdsa_keys_with_timeout_and_rotation_period(
    governance: &Canister<'_>,
    subnet_id: SubnetId,
    key_ids: Vec<EcdsaKeyId>,
    timeout: Option<Duration>,
    period: Option<Duration>,
    logger: &Logger,
) {
    let proposal_payload = UpdateSubnetPayload {
        subnet_id,
        ecdsa_config: Some(EcdsaConfig {
            quadruples_to_create_in_advance: 5,
            key_ids,
            max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            signature_request_timeout_ns: timeout.map(|t| t.as_nanos() as u64),
            idkg_key_rotation_period_ms: period.map(|t| t.as_millis() as u64),
        }),
        ..empty_subnet_update()
    };
    execute_update_subnet_proposal(governance, proposal_payload, "Add ECDSA keys", logger).await;
}

pub(crate) async fn enable_ecdsa_signing_with_timeout_and_rotation_period(
    governance: &Canister<'_>,
    subnet_id: SubnetId,
    key_ids: Vec<EcdsaKeyId>,
    timeout: Option<Duration>,
    period: Option<Duration>,
    logger: &Logger,
) {
    // The ECDSA key sharing process requires that a key first be added to a
    // subnet, and then enabling signing with that key must happen in a separate
    // proposal.
    add_ecdsa_keys_with_timeout_and_rotation_period(
        governance,
        subnet_id,
        key_ids.clone(),
        timeout,
        period,
        logger,
    )
    .await;

    let proposal_payload = UpdateSubnetPayload {
        subnet_id,
        ecdsa_key_signing_enable: Some(key_ids),
        ..empty_subnet_update()
    };
    execute_update_subnet_proposal(governance, proposal_payload, "Enable ECDSA signing", logger)
        .await;
}

pub(crate) async fn create_new_subnet_with_keys(
    governance: &Canister<'_>,
    node_ids: Vec<NodeId>,
    keys: Vec<EcdsaKeyRequest>,
    replica_version: ReplicaVersion,
    logger: &Logger,
) {
    let config = ic_prep_lib::subnet_configuration::get_default_config_params(
        SubnetType::Application,
        node_ids.len(),
    );
    let gossip = p2p::build_default_gossip_config();
    let scheduler = ic_config::subnet_config::SchedulerConfig::application_subnet();
    let payload = CreateSubnetPayload {
        node_ids,
        subnet_id_override: None,
        ingress_bytes_per_block_soft_cap: Default::default(),
        max_ingress_bytes_per_message: config.max_ingress_bytes_per_message,
        max_ingress_messages_per_block: config.max_ingress_messages_per_block,
        max_block_payload_size: config.max_block_payload_size,
        replica_version_id: replica_version.to_string(),
        unit_delay_millis: ic_prep_lib::subnet_configuration::duration_to_millis(config.unit_delay),
        initial_notary_delay_millis: ic_prep_lib::subnet_configuration::duration_to_millis(
            config.initial_notary_delay,
        ),
        dkg_interval_length: DKG_INTERVAL,
        dkg_dealings_per_block: config.dkg_dealings_per_block as u64,
        gossip_max_artifact_streams_per_peer: gossip.max_artifact_streams_per_peer,
        gossip_max_chunk_wait_ms: gossip.max_chunk_wait_ms,
        gossip_max_duplicity: gossip.max_duplicity,
        gossip_max_chunk_size: gossip.max_chunk_size,
        gossip_receive_check_cache_size: gossip.receive_check_cache_size,
        gossip_pfn_evaluation_period_ms: gossip.pfn_evaluation_period_ms,
        gossip_registry_poll_period_ms: gossip.registry_poll_period_ms,
        gossip_retransmission_request_ms: gossip.retransmission_request_ms,
        start_as_nns: false,
        subnet_type: SubnetType::Application,
        is_halted: false,
        max_instructions_per_message: scheduler.max_instructions_per_message.get(),
        max_instructions_per_round: scheduler.max_instructions_per_round.get(),
        max_instructions_per_install_code: scheduler.max_instructions_per_install_code.get(),
        features: Default::default(),
        max_number_of_canisters: 4,
        ssh_readonly_access: vec![],
        ssh_backup_access: vec![],
        ecdsa_config: Some(EcdsaInitialConfig {
            quadruples_to_create_in_advance: 4,
            keys,
            max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
        }),
    };
    execute_create_subnet_proposal(governance, payload, logger).await;
}
