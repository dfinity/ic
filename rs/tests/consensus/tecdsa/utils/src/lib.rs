use candid::{CandidType, Deserialize, Encode, Principal};
use canister_test::{Canister, Cycles};
use ic_agent::AgentError;
use ic_base_types::{NodeId, SubnetId};
use ic_canister_client::Sender;
use ic_config::subnet_config::{ECDSA_SIGNATURE_FEE, SCHNORR_SIGNATURE_FEE};
use ic_limits::SMALL_APP_SUBNET_MAX_SIZE;
use ic_management_canister_types::{
    DerivationPath, ECDSAPublicKeyArgs, ECDSAPublicKeyResponse, EcdsaCurve, EcdsaKeyId,
    MasterPublicKeyId, Payload, SchnorrAlgorithm, SchnorrKeyId, SchnorrPublicKeyArgs,
    SchnorrPublicKeyResponse, SignWithECDSAArgs, SignWithECDSAReply, SignWithSchnorrArgs,
    SignWithSchnorrReply,
};
use ic_message::ForwardParams;
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nns_common::types::NeuronId;
use ic_nns_governance_api::pb::v1::{NnsFunction, ProposalStatus};
use ic_nns_test_utils::governance::submit_external_update_proposal;
use ic_registry_subnet_features::DEFAULT_ECDSA_MAX_QUEUE_SIZE;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    canister_api::{CallMode, Request},
    driver::{
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder,
        },
    },
    nns::vote_and_execute_proposal,
    util::{block_on, MessageCanister},
};
use ic_types::{Height, PrincipalId, ReplicaVersion};
use ic_types_test_utils::ids::subnet_test_id;
use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use registry_canister::mutations::{
    do_create_subnet::{
        CreateSubnetPayload, InitialChainKeyConfig, KeyConfig as KeyConfigCreate, KeyConfigRequest,
    },
    do_update_subnet::{ChainKeyConfig, KeyConfig as KeyConfigUpdate, UpdateSubnetPayload},
};
use slog::{debug, info, Logger};
use std::time::Duration;

pub const KEY_ID1: &str = "secp256k1";

/// The default DKG interval takes too long before the keys are created and
/// passed to execution.
pub const DKG_INTERVAL: u64 = 19;

pub const NUMBER_OF_NODES: usize = 4;

pub fn make_key(name: &str) -> EcdsaKeyId {
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

pub fn make_eddsa_key_id() -> MasterPublicKeyId {
    MasterPublicKeyId::Schnorr(SchnorrKeyId {
        algorithm: SchnorrAlgorithm::Ed25519,
        name: "some_eddsa_key".to_string(),
    })
}

pub fn make_bip340_key_id() -> MasterPublicKeyId {
    MasterPublicKeyId::Schnorr(SchnorrKeyId {
        algorithm: SchnorrAlgorithm::Bip340Secp256k1,
        name: "some_bip340_key".to_string(),
    })
}

pub fn make_key_ids_for_all_schemes() -> Vec<MasterPublicKeyId> {
    vec![
        make_ecdsa_key_id(),
        make_bip340_key_id(),
        make_eddsa_key_id(),
    ]
}

/// Creates one system subnet without signing enabled and one application subnet
/// with signing enabled.
pub fn setup_without_ecdsa_on_nns(test_env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(19))
                .add_nodes(NUMBER_OF_NODES),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(NUMBER_OF_NODES),
        )
        .with_unassigned_nodes(NUMBER_OF_NODES)
        .setup_and_start(&test_env)
        .expect("Could not start IC!");
    test_env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    test_env
        .topology_snapshot()
        .unassigned_nodes()
        .for_each(|node| node.await_can_login_as_admin_via_ssh().unwrap());

    // Currently, we make the assumption that the first subnets is the root
    // subnet. This might not hold in the future.
    let nns_node = test_env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();
    NnsInstallationBuilder::new()
        .install(&nns_node, &test_env)
        .expect("Failed to install NNS canisters");
}

/// Creates one system subnet and two application subnets.
pub fn setup(test_env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(NUMBER_OF_NODES),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(NUMBER_OF_NODES),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(NUMBER_OF_NODES),
        )
        .with_unassigned_nodes(NUMBER_OF_NODES)
        .setup_and_start(&test_env)
        .expect("Could not start IC!");
    test_env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    test_env
        .topology_snapshot()
        .unassigned_nodes()
        .for_each(|node| node.await_can_login_as_admin_via_ssh().unwrap());

    // Currently, we make the assumption that the first subnets is the root
    // subnet. This might not hold in the future.
    let nns_node = test_env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();
    NnsInstallationBuilder::new()
        .install(&nns_node, &test_env)
        .expect("Failed to install NNS canisters");
}

pub fn empty_subnet_update() -> UpdateSubnetPayload {
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

pub fn scale_cycles(cycles: Cycles) -> Cycles {
    // Subnet is constructed with `NUMBER_OF_NODES`, see `config()` and `config_without_ecdsa_on_nns()`.
    (cycles * NUMBER_OF_NODES) / SMALL_APP_SUBNET_MAX_SIZE
}

/// The signature test consists of getting the given canister's Chain key, comparing it to the existing key
/// to ensure it hasn't changed, sending a sign request, and verifying the signature
pub fn run_chain_key_signature_test(
    canister: &MessageCanister,
    logger: &Logger,
    key_id: &MasterPublicKeyId,
    existing_key: Vec<u8>,
) {
    info!(logger, "Run through Chain key signature test.");
    let message_hash = vec![0xabu8; 32];
    block_on(async {
        let public_key = get_public_key_with_retries(key_id, canister, logger, 100)
            .await
            .unwrap();
        assert_eq!(existing_key, public_key);
        let signature = get_signature_with_logger(
            message_hash.clone(),
            ECDSA_SIGNATURE_FEE,
            key_id,
            canister,
            logger,
        )
        .await
        .unwrap();
        verify_signature(key_id, &message_hash, &public_key, &signature);
    });
}

/// Get the threshold public key of the given canister
pub fn get_master_public_key(
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

pub async fn get_public_key_and_test_signature(
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

pub async fn get_public_key_with_retries(
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

pub async fn get_ecdsa_public_key_with_retries(
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

pub async fn get_schnorr_public_key_with_retries(
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

pub async fn get_public_key_with_logger(
    key_id: &MasterPublicKeyId,
    msg_can: &MessageCanister<'_>,
    logger: &Logger,
) -> Result<Vec<u8>, AgentError> {
    get_public_key_with_retries(key_id, msg_can, logger, /*retries=*/ 100).await
}

pub async fn execute_update_subnet_proposal(
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

pub async fn execute_create_subnet_proposal(
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

pub async fn get_signature_with_logger(
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

pub async fn get_ecdsa_signature_with_logger(
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

pub async fn get_schnorr_signature_with_logger(
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

pub async fn enable_chain_key_signing(
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

pub async fn enable_chain_key_signing_with_timeout(
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

pub async fn add_chain_keys_with_timeout_and_rotation_period(
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

pub async fn enable_chain_key_signing_with_timeout_and_rotation_period(
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

pub async fn create_new_subnet_with_keys(
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

#[derive(Debug, CandidType, Deserialize)]
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
