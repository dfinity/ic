use crate::tecdsa::{
    add_chain_keys_with_timeout_and_rotation_period, create_new_subnet_with_keys,
    empty_subnet_update, execute_update_subnet_proposal, get_public_key_with_retries,
    get_signature_with_logger, verify_signature,
};
use anyhow::bail;
use candid::{CandidType, Deserialize, Encode, Principal};
use canister_test::Canister;
use canister_test::{Canister, Cycles};
use ic_agent::AgentError;
use ic_base_types::SubnetId;
use ic_base_types::{NodeId, SubnetId};
use ic_canister_client::Sender;
use ic_config::subnet_config::ECDSA_SIGNATURE_FEE;
use ic_config::subnet_config::{ECDSA_SIGNATURE_FEE, SCHNORR_SIGNATURE_FEE};
use ic_constants::SMALL_APP_SUBNET_MAX_SIZE;
use ic_management_canister_types::MasterPublicKeyId;
use ic_management_canister_types::{
    DerivationPath, ECDSAPublicKeyArgs, ECDSAPublicKeyResponse, EcdsaCurve, EcdsaKeyId,
    MasterPublicKeyId, Payload, SchnorrAlgorithm, SchnorrKeyId, SchnorrPublicKeyArgs,
    SchnorrPublicKeyResponse, SignWithECDSAArgs, SignWithECDSAReply, SignWithSchnorrArgs,
    SignWithSchnorrReply,
};
use ic_message::ForwardParams;
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nns_common::types::NeuronId;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance::pb::v1::{NnsFunction, ProposalStatus};
use ic_nns_test_utils::governance::submit_external_update_proposal;
use ic_registry_subnet_features::DEFAULT_ECDSA_MAX_QUEUE_SIZE;
use ic_registry_subnet_type::SubnetType;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::util::{block_on, MessageCanister};
use ic_system_test_driver::{
    canister_api::{CallMode, Request},
    nns::vote_and_execute_proposal,
    util::MessageCanister,
};
use ic_types::ReplicaVersion;
use ic_types::{PrincipalId, ReplicaVersion};
use ic_types_test_utils::ids::subnet_test_id;
use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use registry_canister::mutations::do_update_subnet::UpdateSubnetPayload;
use registry_canister::mutations::{
    do_create_subnet::{
        CreateSubnetPayload, InitialChainKeyConfig, KeyConfig as KeyConfigCreate, KeyConfigRequest,
    },
    do_update_subnet::{ChainKeyConfig, KeyConfig as KeyConfigUpdate, UpdateSubnetPayload},
};
use slog::{debug, info, Logger};
use slog::{info, Logger};
use std::collections::BTreeMap;
use std::time::Duration;
use std::time::Duration;

/// The default DKG interval takes too long before the keys are created and
/// passed to execution.
pub(crate) const DKG_INTERVAL: u64 = 19;

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

/// Create a chain key on the root subnet using the given NNS node, then
/// create a new subnet of the given size initialized with the chain key.
/// Disable signing on NNS and enable it on the new app subnet.
/// Assert that the key stays the same regardless of whether signing
/// is enabled on NNS or the app subnet. Return the public key for the given canister.
pub(crate) fn enable_chain_key_on_new_subnet(
    env: &TestEnv,
    nns_node: &IcNodeSnapshot,
    canister: &MessageCanister,
    subnet_size: usize,
    replica_version: ReplicaVersion,
    key_ids: Vec<MasterPublicKeyId>,
    logger: &Logger,
) -> BTreeMap<MasterPublicKeyId, Vec<u8>> {
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);
    let snapshot = env.topology_snapshot();
    let root_subnet_id = snapshot.root_subnet_id();
    let registry_version = snapshot.get_registry_version();

    info!(logger, "Enabling signing on NNS.");
    let nns_keys = enable_chain_key_signing_on_subnet(
        nns_node,
        canister,
        root_subnet_id,
        key_ids.clone(),
        logger,
    );
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
        key_ids
            .iter()
            .cloned()
            .map(|key_id| (key_id, root_subnet_id.get()))
            .collect(),
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
    disable_chain_key_on_subnet(nns_node, root_subnet_id, canister, key_ids.clone(), logger);
    let app_keys = enable_chain_key_signing_on_subnet(
        nns_node,
        canister,
        app_subnet.subnet_id,
        key_ids,
        logger,
    );

    assert_eq!(app_keys, nns_keys);
    app_keys
}

/// Disable Chain key signing on the given subnet and wait until sign requests fail.
pub(crate) fn disable_chain_key_on_subnet(
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

pub(crate) async fn create_new_subnet_with_keys(
    governance: &Canister<'_>,
    node_ids: Vec<NodeId>,
    keys: Vec<(MasterPublicKeyId, PrincipalId)>,
    replica_version: ReplicaVersion,
    logger: &Logger,
) {
    let chain_key_config = InitialChainKeyConfig {
        key_configs: keys
            .into_iter()
            .map(|(key_id, subnet_id)| KeyConfigRequest {
                key_config: Some(KeyConfigCreate {
                    key_id: Some(key_id),
                    pre_signatures_to_create_in_advance: Some(4),
                    max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                }),
                subnet_id: Some(subnet_id),
            })
            .collect(),
        signature_request_timeout_ns: None,
        idkg_key_rotation_period_ms: None,
    };
    let config = ic_prep_lib::subnet_configuration::get_default_config_params(
        SubnetType::Application,
        node_ids.len(),
    );
    let scheduler = ic_config::subnet_config::SchedulerConfig::application_subnet();
    let payload = CreateSubnetPayload {
        node_ids,
        subnet_id_override: None,
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
        chain_key_config: Some(chain_key_config),
        // Unused section follows
        ecdsa_config: None,
        ingress_bytes_per_block_soft_cap: Default::default(),
        gossip_max_artifact_streams_per_peer: Default::default(),
        gossip_max_chunk_wait_ms: Default::default(),
        gossip_max_duplicity: Default::default(),
        gossip_max_chunk_size: Default::default(),
        gossip_receive_check_cache_size: Default::default(),
        gossip_pfn_evaluation_period_ms: Default::default(),
        gossip_registry_poll_period_ms: Default::default(),
        gossip_retransmission_request_ms: Default::default(),
    };
    execute_create_subnet_proposal(governance, payload, logger).await;
}

/// Get the threshold public key of the given canister
pub(crate) fn get_master_public_key(
    canister: &MessageCanister,
    key_id: &MasterPublicKeyId,
    logger: &Logger,
) -> Vec<u8> {
    info!(
        logger,
        "Getting threshold public key for key id: {}.", key_id
    );
    let public_key = block_on(get_public_key_with_retries(key_id, canister, logger, 100)).unwrap();
    info!(logger, "Got public key {:?}", public_key);
    public_key
}

pub(crate) fn make_key(name: &str) -> EcdsaKeyId {
    EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: name.to_string(),
    }
}

pub fn make_ecdsa_key_id() -> MasterPublicKeyId {
    MasterPublicKeyId::Ecdsa(EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: "some_ecdsa_key".to_string(),
    })
}

pub(crate) fn make_eddsa_key_id() -> MasterPublicKeyId {
    MasterPublicKeyId::Schnorr(SchnorrKeyId {
        algorithm: SchnorrAlgorithm::Ed25519,
        name: "some_eddsa_key".to_string(),
    })
}

pub(crate) fn make_bip340_key_id() -> MasterPublicKeyId {
    MasterPublicKeyId::Schnorr(SchnorrKeyId {
        algorithm: SchnorrAlgorithm::Bip340Secp256k1,
        name: "some_bip340_key".to_string(),
    })
}

pub(crate) fn make_key_ids_for_all_schemes() -> Vec<MasterPublicKeyId> {
    vec![
        make_ecdsa_key_id(),
        make_bip340_key_id(),
        make_eddsa_key_id(),
    ]
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
        chain_key_config: None,
        chain_key_signing_enable: None,
        chain_key_signing_disable: None,
        max_number_of_canisters: None,
        ssh_readonly_access: None,
        ssh_backup_access: None,
        // Deprecated/unused values follow
        max_artifact_streams_per_peer: None,
        max_chunk_wait_ms: None,
        max_duplicity: None,
        max_chunk_size: None,
        receive_check_cache_size: None,
        pfn_evaluation_period_ms: None,
        registry_poll_period_ms: None,
        retransmission_request_ms: None,
        set_gossip_config_to_default: Default::default(),
    }
}

// TODO(EXC-1168): cleanup after cost scaling is fully implemented.
pub(crate) fn scale_cycles(cycles: Cycles) -> Cycles {
    match USE_COST_SCALING_FLAG {
        false => cycles,
        true => {
            // Subnet is constructed with `NUMBER_OF_NODES`, see `config()` and `config_without_ecdsa_on_nns()`.
            (cycles * NUMBER_OF_NODES) / SMALL_APP_SUBNET_MAX_SIZE
        }
    }
}

pub(crate) async fn get_public_key_and_test_signature(
    key_id: &MasterPublicKeyId,
    message_canister: &MessageCanister<'_>,
    zero_cycles: bool,
    logger: &Logger,
) -> Result<Vec<u8>, AgentError> {
    let cycles = if zero_cycles {
        Cycles::zero()
    } else {
        scale_cycles(ECDSA_SIGNATURE_FEE)
    };

    let message_hash = vec![0xabu8; 32];

    info!(logger, "Getting the public key for {}", key_id);
    let public_key = get_public_key_with_logger(key_id, message_canister, logger).await?;

    info!(logger, "Getting signature for {}", key_id);
    let signature = get_signature_with_logger(
        message_hash.clone(),
        cycles,
        key_id,
        message_canister,
        logger,
    )
    .await?;

    info!(logger, "Verifying signature for {}", key_id);
    verify_signature(key_id, &message_hash, &public_key, &signature);

    Ok(public_key)
}

pub(crate) async fn get_public_key_with_retries(
    key_id: &MasterPublicKeyId,
    msg_can: &MessageCanister<'_>,
    logger: &Logger,
    retries: u64,
) -> Result<Vec<u8>, AgentError> {
    match key_id {
        MasterPublicKeyId::Ecdsa(key_id) => {
            get_ecdsa_public_key_with_retries(key_id, msg_can, logger, retries).await
        }
        MasterPublicKeyId::Schnorr(key_id) => {
            get_schnorr_public_key_with_retries(key_id, msg_can, logger, retries).await
        }
    }
}

pub(crate) async fn get_ecdsa_public_key_with_retries(
    key_id: &EcdsaKeyId,
    msg_can: &MessageCanister<'_>,
    logger: &Logger,
    retries: u64,
) -> Result<Vec<u8>, AgentError> {
    let public_key_request = ECDSAPublicKeyArgs {
        canister_id: None,
        derivation_path: DerivationPath::new(vec![]),
        key_id: key_id.clone(),
    };
    info!(
        logger,
        "Sending a 'get ecdsa public key' request: {:?}", public_key_request
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
                        "ecdsa_public_key returns `{}`. Trying again in 2 seconds...", err
                    );
                    tokio::time::sleep(Duration::from_secs(2)).await;
                } else {
                    return Err(err);
                }
            }
        }
    };
    let pk =
        VerifyingKey::from_sec1_bytes(&public_key[..]).expect("Bytes are not a valid public key");
    info!(logger, "ecdsa_public_key returns {:?}", pk);
    Ok(public_key)
}

pub(crate) async fn get_schnorr_public_key_with_retries(
    key_id: &SchnorrKeyId,
    msg_can: &MessageCanister<'_>,
    logger: &Logger,
    retries: u64,
) -> Result<Vec<u8>, AgentError> {
    let public_key_request = SchnorrPublicKeyArgs {
        canister_id: None,
        derivation_path: DerivationPath::new(vec![]),
        key_id: key_id.clone(),
    };
    info!(
        logger,
        "Sending a 'get schnorr public key' request: {:?}", public_key_request
    );

    let mut count = 0;
    let public_key = loop {
        let res = msg_can
            .forward_to(
                &Principal::management_canister(),
                "schnorr_public_key",
                Encode!(&public_key_request).unwrap(),
            )
            .await;
        match res {
            Ok(bytes) => {
                let key = SchnorrPublicKeyResponse::decode(&bytes)
                    .expect("failed to decode SchnorrPublicKeyResponse");
                break key.public_key;
            }
            Err(err) => {
                count += 1;
                if count < retries {
                    debug!(
                        logger,
                        "schnorr_public_key returns `{}`. Trying again in 2 seconds...", err
                    );
                    tokio::time::sleep(Duration::from_secs(2)).await;
                } else {
                    return Err(err);
                }
            }
        }
    };

    match key_id.algorithm {
        SchnorrAlgorithm::Bip340Secp256k1 => {
            use schnorr_fun::fun::{marker::*, Point};
            assert_eq!(public_key.len(), 33);
            let bip340_pk_array =
                <[u8; 32]>::try_from(&public_key[1..]).expect("public key is not 32 bytes");

            let vk = Point::<EvenY, Public>::from_xonly_bytes(bip340_pk_array)
                .expect("failed to parse public key");
            info!(logger, "schnorr_public_key returns {:?}", vk);
        }
        SchnorrAlgorithm::Ed25519 => {
            let pk: [u8; 32] = public_key[..].try_into().expect("Public key wrong size");
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap();
            info!(logger, "schnorr_public_key returns {:?}", vk);
        }
    }
    Ok(public_key)
}

pub(crate) async fn get_public_key_with_logger(
    key_id: &MasterPublicKeyId,
    msg_can: &MessageCanister<'_>,
    logger: &Logger,
) -> Result<Vec<u8>, AgentError> {
    get_public_key_with_retries(key_id, msg_can, logger, /*retries=*/ 100).await
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
    message: Vec<u8>,
    cycles: Cycles,
    key_id: &MasterPublicKeyId,
    msg_can: &MessageCanister<'_>,
    logger: &Logger,
) -> Result<Vec<u8>, AgentError> {
    match key_id {
        MasterPublicKeyId::Ecdsa(key_id) => {
            let message_hash =
                <[u8; 32]>::try_from(&message[..]).expect("message hash is not 32 bytes");
            get_ecdsa_signature_with_logger(&message_hash, cycles, key_id, msg_can, logger).await
        }
        MasterPublicKeyId::Schnorr(key_id) => {
            get_schnorr_signature_with_logger(message, cycles, key_id, msg_can, logger).await
        }
    }
}

pub(crate) async fn get_ecdsa_signature_with_logger(
    message_hash: &[u8; 32],
    cycles: Cycles,
    key_id: &EcdsaKeyId,
    msg_can: &MessageCanister<'_>,
    logger: &Logger,
) -> Result<Vec<u8>, AgentError> {
    let signature_request = SignWithECDSAArgs {
        message_hash: *message_hash,
        derivation_path: DerivationPath::new(Vec::new()),
        key_id: key_id.clone(),
    };
    info!(
        logger,
        "Sending an ECDSA signing request: {:?}", signature_request
    );

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
                if count < 5 {
                    debug!(
                        logger,
                        "sign_with_ecdsa returns `{}`. Trying again in 2 seconds...", err
                    );
                    tokio::time::sleep(Duration::from_secs(2)).await;
                } else {
                    return Err(err);
                }
            }
        }
    };
    info!(logger, "sign_with_ecdsa returns {:?}", signature);

    Ok(signature)
}

pub(crate) async fn get_schnorr_signature_with_logger(
    message: Vec<u8>,
    cycles: Cycles,
    key_id: &SchnorrKeyId,
    msg_can: &MessageCanister<'_>,
    logger: &Logger,
) -> Result<Vec<u8>, AgentError> {
    let signature_request = SignWithSchnorrArgs {
        message,
        derivation_path: DerivationPath::new(Vec::new()),
        key_id: key_id.clone(),
    };
    info!(
        logger,
        "Sending a {} signing request of size: {}",
        key_id,
        signature_request.message.len(),
    );

    let mut count = 0;
    let signature = loop {
        // Ask for a signature.
        let res = msg_can
            .forward_with_cycles_to(
                &Principal::management_canister(),
                "sign_with_schnorr",
                Encode!(&signature_request).unwrap(),
                cycles,
            )
            .await;
        match res {
            Ok(reply) => {
                let signature = SignWithSchnorrReply::decode(&reply)
                    .expect("failed to decode SignWithSchnorrReply")
                    .signature;
                break signature;
            }
            Err(err) => {
                count += 1;
                if count < 5 {
                    debug!(
                        logger,
                        "sign_with_schnorr returns `{}`. Trying again in 2 seconds...", err
                    );
                    tokio::time::sleep(Duration::from_secs(2)).await;
                } else {
                    return Err(err);
                }
            }
        }
    };
    info!(logger, "sign_with_schnorr returns {:?}", signature);

    Ok(signature)
}

pub(crate) async fn enable_chain_key_signing(
    governance: &Canister<'_>,
    subnet_id: SubnetId,
    key_ids: Vec<MasterPublicKeyId>,
    logger: &Logger,
) {
    enable_chain_key_signing_with_timeout(
        governance, subnet_id, key_ids, /*timeout=*/ None, logger,
    )
    .await
}

pub(crate) async fn enable_chain_key_signing_with_timeout(
    governance: &Canister<'_>,
    subnet_id: SubnetId,
    key_ids: Vec<MasterPublicKeyId>,
    timeout: Option<Duration>,
    logger: &Logger,
) {
    enable_chain_key_signing_with_timeout_and_rotation_period(
        governance, subnet_id, key_ids, timeout, /*period=*/ None, logger,
    )
    .await
}

pub(crate) async fn add_chain_keys_with_timeout_and_rotation_period(
    governance: &Canister<'_>,
    subnet_id: SubnetId,
    key_ids: Vec<MasterPublicKeyId>,
    timeout: Option<Duration>,
    period: Option<Duration>,
    logger: &Logger,
) {
    let proposal_payload = UpdateSubnetPayload {
        subnet_id,
        chain_key_config: Some(ChainKeyConfig {
            key_configs: key_ids
                .into_iter()
                .map(|key_id| KeyConfigUpdate {
                    key_id: Some(key_id.clone()),
                    pre_signatures_to_create_in_advance: Some(5),
                    max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                })
                .collect(),
            signature_request_timeout_ns: timeout.map(|t| t.as_nanos() as u64),
            idkg_key_rotation_period_ms: period.map(|t| t.as_millis() as u64),
        }),
        ..empty_subnet_update()
    };
    execute_update_subnet_proposal(governance, proposal_payload, "Add Chain keys", logger).await;
}

pub(crate) async fn enable_chain_key_signing_with_timeout_and_rotation_period(
    governance: &Canister<'_>,
    subnet_id: SubnetId,
    key_ids: Vec<MasterPublicKeyId>,
    timeout: Option<Duration>,
    period: Option<Duration>,
    logger: &Logger,
) {
    // The Chain key sharing process requires that a key first be added to a
    // subnet, and then enabling signing with that key must happen in a separate
    // proposal.
    add_chain_keys_with_timeout_and_rotation_period(
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
        chain_key_signing_enable: Some(key_ids),
        ..empty_subnet_update()
    };
    execute_update_subnet_proposal(
        governance,
        proposal_payload,
        "Enable Chain key signing",
        logger,
    )
    .await;
}

pub fn verify_bip340_signature(sec1_pk: &[u8], sig: &[u8], msg: &[u8]) -> bool {
    use schnorr_fun::{
        fun::{marker::*, Point},
        Message, Schnorr, Signature,
    };
    use sha2::Sha256;

    let sig_array = <[u8; 64]>::try_from(sig).expect("signature is not 64 bytes");
    assert_eq!(sec1_pk.len(), 33);
    // The public key is a BIP-340 public key, which is a 32-byte
    // compressed public key ignoring the y coordinate in the first byte of the
    // SEC1 encoding.
    let bip340_pk_array = <[u8; 32]>::try_from(&sec1_pk[1..]).expect("public key is not 32 bytes");

    let schnorr = Schnorr::<Sha256>::verify_only();
    let public_key = Point::<EvenY, Public>::from_xonly_bytes(bip340_pk_array)
        .expect("failed to parse public key");
    let signature = Signature::<Public>::from_bytes(sig_array).unwrap();
    schnorr.verify(&public_key, Message::<Secret>::raw(msg), &signature)
}

pub fn verify_ed25519_signature(pk: &[u8], sig: &[u8], msg: &[u8]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let pk: [u8; 32] = pk.try_into().expect("Public key wrong size");
    let vk = VerifyingKey::from_bytes(&pk).unwrap();

    let signature = Signature::from_slice(sig).expect("Signature incorrect length");

    vk.verify(msg, &signature).is_ok()
}

pub fn verify_ecdsa_signature(pk: &[u8], sig: &[u8], msg: &[u8]) -> bool {
    let pk = VerifyingKey::from_sec1_bytes(pk).expect("Bytes are not a valid public key");
    let signature = Signature::try_from(sig).expect("Bytes are not a valid signature");
    pk.verify_prehash(msg, &signature).is_ok()
}

pub fn verify_signature(key_id: &MasterPublicKeyId, msg: &[u8], pk: &[u8], sig: &[u8]) {
    let res = match key_id {
        MasterPublicKeyId::Ecdsa(key_id) => match key_id.curve {
            EcdsaCurve::Secp256k1 => verify_ecdsa_signature(pk, sig, msg),
        },
        MasterPublicKeyId::Schnorr(key_id) => match key_id.algorithm {
            SchnorrAlgorithm::Bip340Secp256k1 => verify_bip340_signature(pk, sig, msg),
            SchnorrAlgorithm::Ed25519 => verify_ed25519_signature(pk, sig, msg),
        },
    };
    assert!(res);
}

#[derive(CandidType, Deserialize, Debug)]
pub enum SignWithChainKeyReply {
    Ecdsa(SignWithECDSAReply),
    Schnorr(SignWithSchnorrReply),
}

#[derive(Clone)]
pub struct ChainSignatureRequest {
    pub key_id: MasterPublicKeyId,
    pub principal: Principal,
    pub payload: Vec<u8>,
}

impl ChainSignatureRequest {
    pub fn new(
        principal: Principal,
        key_id: MasterPublicKeyId,
        schnorr_message_size: usize,
    ) -> Self {
        let params = match key_id.clone() {
            MasterPublicKeyId::Ecdsa(ecdsa_key_id) => Self::ecdsa_params(ecdsa_key_id),
            MasterPublicKeyId::Schnorr(schnorr_key_id) => {
                Self::schnorr_params(schnorr_key_id, schnorr_message_size)
            }
        };
        let payload = Encode!(&params).unwrap();

        Self {
            key_id,
            principal,
            payload,
        }
    }

    fn ecdsa_params(ecdsa_key_id: EcdsaKeyId) -> ForwardParams {
        let signature_request = SignWithECDSAArgs {
            message_hash: [1; 32],
            derivation_path: DerivationPath::new(Vec::new()),
            key_id: ecdsa_key_id,
        };
        ForwardParams {
            receiver: Principal::management_canister(),
            method: "sign_with_ecdsa".to_string(),
            cycles: ECDSA_SIGNATURE_FEE.get() * 2,
            payload: Encode!(&signature_request).unwrap(),
        }
    }

    fn schnorr_params(schnorr_key_id: SchnorrKeyId, message_size: usize) -> ForwardParams {
        let signature_request = SignWithSchnorrArgs {
            message: vec![1; message_size],
            derivation_path: DerivationPath::new(Vec::new()),
            key_id: schnorr_key_id,
        };
        ForwardParams {
            receiver: Principal::management_canister(),
            method: "sign_with_schnorr".to_string(),
            cycles: SCHNORR_SIGNATURE_FEE.get() * 2,
            payload: Encode!(&signature_request).unwrap(),
        }
    }
}

impl Request<SignWithChainKeyReply> for ChainSignatureRequest {
    fn mode(&self) -> CallMode {
        CallMode::Update
    }

    fn canister_id(&self) -> Principal {
        self.principal
    }

    fn method_name(&self) -> String {
        "forward".to_string()
    }

    fn payload(&self) -> Vec<u8> {
        self.payload.clone()
    }

    fn parse_response(&self, raw_response: &[u8]) -> anyhow::Result<SignWithChainKeyReply> {
        Ok(match self.key_id {
            MasterPublicKeyId::Ecdsa(_) => {
                SignWithChainKeyReply::Ecdsa(SignWithECDSAReply::decode(raw_response)?)
            }
            MasterPublicKeyId::Schnorr(_) => {
                SignWithChainKeyReply::Schnorr(SignWithSchnorrReply::decode(raw_response)?)
            }
        })
    }
}
