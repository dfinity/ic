use anyhow::bail;
use candid::{CandidType, Deserialize, Encode, Principal};
use canister_test::{Canister, Cycles};
use ic_agent::AgentError;
use ic_base_types::{CanisterId, NodeId, SubnetId};
use ic_bls12_381::G1Affine;
use ic_canister_client::Sender;
use ic_cdk::management_canister::{
    SignWithEcdsaResult, SignWithSchnorrResult, VetKDDeriveKeyResult,
};
use ic_config::subnet_config::{ECDSA_SIGNATURE_FEE, SCHNORR_SIGNATURE_FEE, VETKD_FEE};
use ic_limits::SMALL_APP_SUBNET_MAX_SIZE;
use ic_management_canister_types_private::{
    DerivationPath, ECDSAPublicKeyArgs, ECDSAPublicKeyResponse, EcdsaCurve, EcdsaKeyId,
    MasterPublicKeyId, Payload, SchnorrAlgorithm, SchnorrKeyId, SchnorrPublicKeyArgs,
    SchnorrPublicKeyResponse, SignWithECDSAArgs, SignWithECDSAReply, SignWithSchnorrArgs,
    SignWithSchnorrAux, SignWithSchnorrReply, VetKdCurve, VetKdDeriveKeyArgs, VetKdDeriveKeyResult,
    VetKdKeyId, VetKdPublicKeyArgs, VetKdPublicKeyResult,
};
use ic_message::ForwardParams;
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nns_common::types::NeuronId;
use ic_nns_governance_api::{NnsFunction, ProposalStatus};
use ic_nns_test_utils::governance::submit_external_update_proposal;
use ic_registry_subnet_features::DEFAULT_ECDSA_MAX_QUEUE_SIZE;
use ic_registry_subnet_type::SubnetType;
use ic_signer::{GenEcdsaParams, GenSchnorrParams, GenVetkdParams};
use ic_system_test_driver::{
    canister_api::{CallMode, Request},
    driver::{
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder,
            READY_WAIT_TIMEOUT, RETRY_BACKOFF, SubnetSnapshot,
        },
    },
    nns::vote_and_execute_proposal,
    util::{MessageCanister, MetricsFetcher, SignerCanister, block_on},
};
use ic_types::{Height, PrincipalId, ReplicaVersion};
use ic_types_test_utils::ids::subnet_test_id;
use ic_vetkeys::{DerivedPublicKey, EncryptedVetKey, TransportSecretKey};
use k256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use registry_canister::mutations::{
    do_create_subnet::{
        CanisterCyclesCostSchedule, CreateSubnetPayload, InitialChainKeyConfig,
        KeyConfig as KeyConfigCreate, KeyConfigRequest,
    },
    do_recover_subnet::RecoverSubnetPayload,
    do_update_subnet::{ChainKeyConfig, KeyConfig as KeyConfigUpdate, UpdateSubnetPayload},
};
use slog::{Logger, debug, info};
use std::{fmt::Debug, time::Duration};

pub const KEY_ID1: &str = "secp256k1";

/// The default DKG interval takes too long before the keys are created and
/// passed to execution.
pub const DKG_INTERVAL: u64 = 19;

pub const NUMBER_OF_NODES: usize = 4;

const VETKD_TRANSPORT_SECRET_KEY_SEED: [u8; 32] = [13; 32];
const GET_SIGNATURE_RETRIES: i32 = 10;

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

pub fn make_vetkd_key_id() -> MasterPublicKeyId {
    MasterPublicKeyId::VetKd(VetKdKeyId {
        curve: VetKdCurve::Bls12_381_G2,
        name: "some_vetkd_key".to_string(),
    })
}

pub fn make_key_ids_for_all_schemes() -> Vec<MasterPublicKeyId> {
    vec![
        make_ecdsa_key_id(),
        make_bip340_key_id(),
        make_eddsa_key_id(),
        make_vetkd_key_id(),
    ]
}

pub fn make_key_ids_for_all_idkg_schemes() -> Vec<MasterPublicKeyId> {
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

pub fn scale_cycles_to(number_of_nodes: usize, cycles: Cycles) -> Cycles {
    (cycles * number_of_nodes) / SMALL_APP_SUBNET_MAX_SIZE
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
    get_public_key_with_retries_impl(/*canister_id=*/ None, key_id, msg_can, logger, retries).await
}

pub async fn get_public_key_for_canister_id_with_retries(
    canister_id: CanisterId,
    key_id: &MasterPublicKeyId,
    msg_can: &MessageCanister<'_>,
    logger: &Logger,
    retries: u64,
) -> Result<Vec<u8>, AgentError> {
    get_public_key_with_retries_impl(Some(canister_id), key_id, msg_can, logger, retries).await
}

async fn get_public_key_with_retries_impl(
    canister_id: Option<CanisterId>,
    key_id: &MasterPublicKeyId,
    msg_can: &MessageCanister<'_>,
    logger: &Logger,
    retries: u64,
) -> Result<Vec<u8>, AgentError> {
    match key_id {
        MasterPublicKeyId::Ecdsa(key_id) => {
            get_ecdsa_public_key_with_retries(canister_id, key_id, msg_can, logger, retries).await
        }
        MasterPublicKeyId::Schnorr(key_id) => {
            get_schnorr_public_key_with_retries(canister_id, key_id, msg_can, logger, retries).await
        }
        MasterPublicKeyId::VetKd(key_id) => {
            get_vetkd_public_key_with_retries(canister_id, key_id, msg_can, logger, retries).await
        }
    }
}

pub async fn get_ecdsa_public_key_with_retries(
    canister_id: Option<CanisterId>,
    key_id: &EcdsaKeyId,
    msg_can: &MessageCanister<'_>,
    logger: &Logger,
    retries: u64,
) -> Result<Vec<u8>, AgentError> {
    let public_key_request = ECDSAPublicKeyArgs {
        canister_id,
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
    canister_id: Option<CanisterId>,
    key_id: &SchnorrKeyId,
    msg_can: &MessageCanister<'_>,
    logger: &Logger,
    retries: u64,
) -> Result<Vec<u8>, AgentError> {
    let public_key_request = SchnorrPublicKeyArgs {
        canister_id,
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
            let pk_with_even_y = {
                let mut k = public_key.clone();
                k[0] = 0x02;
                k
            };

            let vk = k256::PublicKey::from_sec1_bytes(&pk_with_even_y);
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

pub async fn get_vetkd_public_key_with_retries(
    canister_id: Option<CanisterId>,
    key_id: &VetKdKeyId,
    msg_can: &MessageCanister<'_>,
    logger: &Logger,
    retries: u64,
) -> Result<Vec<u8>, AgentError> {
    let public_key_request = VetKdPublicKeyArgs {
        canister_id,
        context: vec![],
        key_id: key_id.clone(),
    };
    info!(
        logger,
        "Sending a 'get vetkd public key' request: {:?}", public_key_request
    );

    let mut count = 0;
    let public_key = loop {
        let res = msg_can
            .forward_to(
                &Principal::management_canister(),
                "vetkd_public_key",
                Encode!(&public_key_request).unwrap(),
            )
            .await;
        match res {
            Ok(bytes) => {
                let key = VetKdPublicKeyResult::decode(&bytes)
                    .expect("failed to decode VetKdPublicKeyResult");
                break key.public_key;
            }
            Err(err) => {
                count += 1;
                if count < retries {
                    debug!(
                        logger,
                        "vetkd_public_key returns `{}`. Trying again in 2 seconds...", err
                    );
                    tokio::time::sleep(Duration::from_secs(2)).await;
                } else {
                    return Err(err);
                }
            }
        }
    };
    let _key =
        DerivedPublicKey::deserialize(&public_key).expect("Failed to parse vetkd public key");

    info!(logger, "vetkd_public_key returns {:?}", public_key);
    Ok(public_key)
}

pub async fn get_public_key_with_logger(
    key_id: &MasterPublicKeyId,
    msg_can: &MessageCanister<'_>,
    logger: &Logger,
) -> Result<Vec<u8>, AgentError> {
    get_public_key_with_logger_impl(/*canister_id=*/ None, key_id, msg_can, logger).await
}

pub async fn get_public_key_for_canister_id_with_logger(
    canister_id: CanisterId,
    key_id: &MasterPublicKeyId,
    msg_can: &MessageCanister<'_>,
    logger: &Logger,
) -> Result<Vec<u8>, AgentError> {
    get_public_key_with_logger_impl(Some(canister_id), key_id, msg_can, logger).await
}

async fn get_public_key_with_logger_impl(
    canister_id: Option<CanisterId>,
    key_id: &MasterPublicKeyId,
    msg_can: &MessageCanister<'_>,
    logger: &Logger,
) -> Result<Vec<u8>, AgentError> {
    get_public_key_with_retries_impl(canister_id, key_id, msg_can, logger, /*retries=*/ 100).await
}

pub async fn execute_proposal(
    governance: &Canister<'_>,
    function: NnsFunction,
    proposal_payload: impl CandidType + Debug,
    title: &str,
    logger: &Logger,
) {
    info!(
        logger,
        "Executing {:?} proposal: {:?}", function, proposal_payload
    );

    let proposal_id = submit_external_update_proposal(
        governance,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        function,
        proposal_payload,
        title.to_string(),
        /*summary=*/ String::default(),
    )
    .await;

    let proposal_result = vote_and_execute_proposal(governance, proposal_id).await;
    info!(
        logger,
        "{:?} proposal result: {:?}", function, proposal_result
    );
    assert_eq!(proposal_result.status, ProposalStatus::Executed as i32);
}

pub async fn execute_update_subnet_proposal(
    governance: &Canister<'_>,
    proposal_payload: UpdateSubnetPayload,
    title: &str,
    logger: &Logger,
) {
    execute_proposal(
        governance,
        NnsFunction::UpdateConfigOfSubnet,
        proposal_payload,
        &format!("<subnet update proposal created by system test>: {title}"),
        logger,
    )
    .await;
}

pub async fn execute_create_subnet_proposal(
    governance: &Canister<'_>,
    proposal_payload: CreateSubnetPayload,
    logger: &Logger,
) {
    execute_proposal(
        governance,
        NnsFunction::CreateSubnet,
        proposal_payload,
        "<subnet creation proposal created by system test>",
        logger,
    )
    .await;
}

pub async fn execute_recover_subnet_proposal(
    governance: &Canister<'_>,
    proposal_payload: RecoverSubnetPayload,
    logger: &Logger,
) {
    execute_proposal(
        governance,
        NnsFunction::RecoverSubnet,
        proposal_payload,
        "<recover subnet proposal created by system test>",
        logger,
    )
    .await;
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
        MasterPublicKeyId::VetKd(key_id) => {
            get_vetkd_with_logger(message, vec![], cycles, key_id, msg_can, logger).await
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
                if count < GET_SIGNATURE_RETRIES {
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
        aux: None,
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
                if count < GET_SIGNATURE_RETRIES {
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

pub async fn get_vetkd_with_logger(
    input: Vec<u8>,
    context: Vec<u8>,
    cycles: Cycles,
    key_id: &VetKdKeyId,
    msg_can: &MessageCanister<'_>,
    logger: &Logger,
) -> Result<Vec<u8>, AgentError> {
    let transport_key = TransportSecretKey::from_seed(VETKD_TRANSPORT_SECRET_KEY_SEED.to_vec())
        .expect("Failed to generate transport secret key");
    let transport_public_key = transport_key.public_key().try_into().unwrap();

    info!(
        logger,
        "Sending a {} request of size: {}",
        key_id,
        input.len() + context.len(),
    );

    let mut count = 0;
    let result = loop {
        let res = vetkd_derive_key(
            transport_public_key,
            key_id.clone(),
            input.clone(),
            context.clone(),
            msg_can,
            cycles,
        )
        .await;
        match res {
            Ok(result) => {
                break result;
            }
            Err(err) => {
                count += 1;
                if count < GET_SIGNATURE_RETRIES {
                    debug!(
                        logger,
                        "vetkd_derive_key returns `{}`. Trying again in 2 seconds...", err
                    );
                    tokio::time::sleep(Duration::from_secs(2)).await;
                } else {
                    return Err(err);
                }
            }
        }
    };

    info!(logger, "vetkd_derive_key returns {:?}", result);
    Ok(result)
}

pub async fn generate_dummy_ecdsa_signature_with_logger(
    derivation_path_length: usize,
    derivation_path_element_size: usize,
    key_id: &EcdsaKeyId,
    sig_can: &SignerCanister<'_>,
    logger: &Logger,
) -> Result<SignWithEcdsaResult, AgentError> {
    let signature_request = GenEcdsaParams {
        derivation_path_length,
        derivation_path_element_size,
        key_id: cast_ecdsa_key_id(key_id.clone()),
    };
    info!(
        logger,
        "Sending a dummy ECDSA signing request: {:?}", signature_request
    );

    let mut count = 0;
    let signature = loop {
        // Ask for a signature.
        let res = sig_can.gen_ecdsa_sig(signature_request.clone()).await;
        match res {
            Ok(signature) => {
                break signature;
            }
            Err(err) => {
                count += 1;
                if count < GET_SIGNATURE_RETRIES {
                    debug!(
                        logger,
                        "gen_ecdsa_sig returns `{}`. Trying again in 2 seconds...", err
                    );
                    tokio::time::sleep(Duration::from_secs(2)).await;
                } else {
                    return Err(err);
                }
            }
        }
    };
    info!(logger, "gen_ecdsa_sig returns {:?}", signature);

    Ok(signature)
}

pub async fn generate_dummy_schnorr_signature_with_logger(
    message_size: usize,
    derivation_path_length: usize,
    derivation_path_element_size: usize,
    key_id: &SchnorrKeyId,
    aux: Option<SignWithSchnorrAux>,
    sig_can: &SignerCanister<'_>,
    logger: &Logger,
) -> Result<SignWithSchnorrResult, AgentError> {
    let signature_request = GenSchnorrParams {
        message_size,
        derivation_path_length,
        derivation_path_element_size,
        key_id: cast_schnorr_key_id(key_id.clone()),
        aux: aux.map(cast_schnorr_aux),
    };
    info!(
        logger,
        "Sending a dummy Schnorr signing request: {:?}", signature_request
    );

    let mut count = 0;
    let signature = loop {
        // Ask for a signature.
        let res = sig_can.gen_schnorr_sig(signature_request.clone()).await;
        match res {
            Ok(signature) => {
                break signature;
            }
            Err(err) => {
                count += 1;
                if count < GET_SIGNATURE_RETRIES {
                    debug!(
                        logger,
                        "gen_schnorr_sig returns `{}`. Trying again in 2 seconds...", err
                    );
                    tokio::time::sleep(Duration::from_secs(2)).await;
                } else {
                    return Err(err);
                }
            }
        }
    };
    info!(logger, "gen_schnorr_sig returns {:?}", signature);

    Ok(signature)
}

pub async fn generate_dummy_vetkd_key_with_logger(
    context_size: usize,
    input_size: usize,
    key_id: &VetKdKeyId,
    sig_can: &SignerCanister<'_>,
    logger: &Logger,
) -> Result<VetKDDeriveKeyResult, AgentError> {
    let key_request = GenVetkdParams {
        context_size,
        input_size,
        key_id: cast_vetkd_key_id(key_id.clone()),
    };

    info!(
        logger,
        "Sending a dummy VetKD key request: {:?}", key_request
    );

    let mut count = 0;
    let result = loop {
        let res = sig_can.gen_vetkd_key(key_request.clone()).await;
        match res {
            Ok(encrypted_key) => {
                break encrypted_key;
            }
            Err(err) => {
                count += 1;
                if count < GET_SIGNATURE_RETRIES {
                    debug!(
                        logger,
                        "gen_vetkd_key returns `{}`. Trying again in 2 seconds...", err
                    );
                    tokio::time::sleep(Duration::from_secs(2)).await;
                } else {
                    return Err(err);
                }
            }
        }
    };

    info!(logger, "gen_vetkd_key returns {:?}", result);
    Ok(result)
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
                    pre_signatures_to_create_in_advance: Some(
                        if key_id.requires_pre_signatures() {
                            5
                        } else {
                            0
                        },
                    ),
                    max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                })
                .collect(),
            signature_request_timeout_ns: timeout.map(|t| t.as_nanos() as u64),
            idkg_key_rotation_period_ms: period.map(|t| t.as_millis() as u64),
            max_parallel_pre_signature_transcripts_in_creation: None,
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
                    pre_signatures_to_create_in_advance: Some(
                        if key_id.requires_pre_signatures() {
                            5
                        } else {
                            0
                        },
                    ),
                    max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                    key_id: Some(key_id),
                }),
                subnet_id: Some(subnet_id),
            })
            .collect(),
        signature_request_timeout_ns: None,
        idkg_key_rotation_period_ms: None,
        max_parallel_pre_signature_transcripts_in_creation: None,
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
        canister_cycles_cost_schedule: Some(CanisterCyclesCostSchedule::Normal),

        // Unused section follows
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

pub fn await_pre_signature_stash_size(
    subnet: &SubnetSnapshot,
    expected_size: usize,
    key_ids: &[MasterPublicKeyId],
    log: &Logger,
) {
    let metric_vec = key_ids
        .iter()
        .map(|key_id| format!("execution_pre_signature_stash_size{{key_id=\"{key_id}\"}}"))
        .collect::<Vec<_>>();
    let metrics = MetricsFetcher::new(subnet.nodes(), metric_vec.clone());
    ic_system_test_driver::retry_with_msg!(
        format!(
            "Waiting until pre-signature stashes for key_ids {key_ids:?} are of size {expected_size}",
        ),
        log.clone(),
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || match block_on(metrics.fetch::<usize>()) {
            Ok(val) => {
                for metric in &metric_vec {
                    let Some(sizes) = val.get(metric) else {
                        bail!("Metric {metric} not found in {val:?}");
                    };
                    assert_eq!(sizes.len(), subnet.nodes().count());
                    for size in sizes {
                        if *size != expected_size {
                            bail!(
                                "Pre-signature stash for key_id {} is of size {}, but expected {}",
                                metric, size, expected_size
                            );
                        }
                    }
                }
                Ok(())
            }
            Err(err) => {
                bail!("Could not connect to metrics yet {:?}", err);
            }
        }
    )
    .expect("The subnet did not reach the required pre-signature stash size in time");
}

pub async fn set_pre_signature_stash_size(
    governance: &Canister<'_>,
    subnet_id: SubnetId,
    key_ids: &[MasterPublicKeyId],
    max_parallel_pre_signature_transcripts_in_creation: u32,
    pre_signatures_to_create_in_advance: u32,
    idkg_key_rotation_period_ms: Option<Duration>,
    log: &Logger,
) {
    let proposal_payload = UpdateSubnetPayload {
        subnet_id,
        chain_key_config: Some(ChainKeyConfig {
            key_configs: key_ids
                .iter()
                .map(|key_id| KeyConfigUpdate {
                    key_id: Some(key_id.clone()),
                    pre_signatures_to_create_in_advance: Some(pre_signatures_to_create_in_advance),
                    max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                })
                .collect(),
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: idkg_key_rotation_period_ms.map(|t| t.as_millis() as u64),
            max_parallel_pre_signature_transcripts_in_creation: Some(
                max_parallel_pre_signature_transcripts_in_creation,
            ),
        }),
        ..empty_subnet_update()
    };
    execute_update_subnet_proposal(governance, proposal_payload, "Update Chain key config", log)
        .await;
}

pub fn verify_bip340_signature(sec1_pk: &[u8], sig: &[u8], msg: &[u8]) -> bool {
    let signature = match k256::schnorr::Signature::try_from(sig) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    // from_bytes takes just the x coordinate encoding:
    match k256::schnorr::VerifyingKey::from_bytes(&sec1_pk[1..]) {
        Ok(bip340) => bip340.verify_raw(msg, &signature).is_ok(),
        _ => false,
    }
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

pub fn verify_vetkey(public_key: &[u8], encrypted_key: &[u8], input: &[u8]) -> bool {
    let dpk = DerivedPublicKey::deserialize(public_key).expect("Failed to deserialize public key");

    let transport_key = TransportSecretKey::from_seed(VETKD_TRANSPORT_SECRET_KEY_SEED.to_vec())
        .expect("Failed to generate transport secret key");

    let enc_key =
        EncryptedVetKey::deserialize(encrypted_key).expect("Failed to deserialize encrypted key");

    enc_key
        .decrypt_and_verify(&transport_key, &dpk, input)
        .is_ok()
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
        MasterPublicKeyId::VetKd(key_id) => match key_id.curve {
            VetKdCurve::Bls12_381_G2 => verify_vetkey(pk, sig, msg),
        },
    };
    assert!(res);
}

#[derive(Debug, CandidType, Deserialize)]
pub enum SignWithChainKeyReply {
    Ecdsa(SignWithECDSAReply),
    Schnorr(SignWithSchnorrReply),
    VetKd(VetKdDeriveKeyResult),
}

fn cast_ecdsa_key_id(key_id: EcdsaKeyId) -> ic_cdk::management_canister::EcdsaKeyId {
    ic_cdk::management_canister::EcdsaKeyId {
        curve: match key_id.curve {
            EcdsaCurve::Secp256k1 => ic_cdk::management_canister::EcdsaCurve::Secp256k1,
        },
        name: key_id.name,
    }
}

fn cast_schnorr_key_id(key_id: SchnorrKeyId) -> ic_cdk::management_canister::SchnorrKeyId {
    ic_cdk::management_canister::SchnorrKeyId {
        algorithm: match key_id.algorithm {
            SchnorrAlgorithm::Bip340Secp256k1 => {
                ic_cdk::management_canister::SchnorrAlgorithm::Bip340secp256k1
            }
            SchnorrAlgorithm::Ed25519 => ic_cdk::management_canister::SchnorrAlgorithm::Ed25519,
        },
        name: key_id.name,
    }
}

fn cast_vetkd_key_id(key_id: VetKdKeyId) -> ic_cdk::management_canister::VetKDKeyId {
    ic_cdk::management_canister::VetKDKeyId {
        curve: match key_id.curve {
            VetKdCurve::Bls12_381_G2 => ic_cdk::management_canister::VetKDCurve::Bls12_381_G2,
        },
        name: key_id.name,
    }
}

fn cast_schnorr_aux(aux: SignWithSchnorrAux) -> ic_cdk::management_canister::SchnorrAux {
    match aux {
        SignWithSchnorrAux::Bip341(aux) => {
            ic_cdk::management_canister::SchnorrAux::Bip341(ic_cdk::management_canister::Bip341 {
                merkle_root_hash: aux.merkle_root_hash.to_vec(),
            })
        }
    }
}

#[derive(Clone)]
pub struct ChainSignatureRequest {
    pub principal: Principal,
    pub method_name: String,
    pub key_id: MasterPublicKeyId,
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
            MasterPublicKeyId::VetKd(vetkd_key_id) => Self::vetkd_params(vetkd_key_id),
        };
        let payload = Encode!(&params).unwrap();

        Self {
            principal,
            method_name: String::from("forward"),
            key_id,
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
            aux: None,
        };
        ForwardParams {
            receiver: Principal::management_canister(),
            method: "sign_with_schnorr".to_string(),
            cycles: SCHNORR_SIGNATURE_FEE.get() * 2,
            payload: Encode!(&signature_request).unwrap(),
        }
    }

    fn vetkd_params(vetkd_key_id: VetKdKeyId) -> ForwardParams {
        let vetkd_request = VetKdDeriveKeyArgs {
            context: vec![1; 32],
            input: vec![],
            key_id: vetkd_key_id,
            transport_public_key: G1Affine::generator().to_compressed(),
        };
        ForwardParams {
            receiver: Principal::management_canister(),
            method: "vetkd_derive_key".to_string(),
            cycles: VETKD_FEE.get() * 2,
            payload: Encode!(&vetkd_request).unwrap(),
        }
    }

    pub fn large_ecdsa_method_and_payload(
        derivation_path_length: usize,
        derivation_path_element_size: usize,
        key_id: EcdsaKeyId,
    ) -> (String, Vec<u8>) {
        let params = GenEcdsaParams {
            derivation_path_length,
            derivation_path_element_size,
            key_id: cast_ecdsa_key_id(key_id),
        };

        (String::from("gen_ecdsa_sig"), Encode!(&params).unwrap())
    }

    pub fn large_schnorr_method_and_payload(
        message_size: usize,
        derivation_path_length: usize,
        derivation_path_element_size: usize,
        key_id: SchnorrKeyId,
        aux: Option<SignWithSchnorrAux>,
    ) -> (String, Vec<u8>) {
        let params = GenSchnorrParams {
            message_size,
            derivation_path_length,
            derivation_path_element_size,
            key_id: cast_schnorr_key_id(key_id),
            aux: aux.map(cast_schnorr_aux),
        };

        (String::from("gen_schnorr_sig"), Encode!(&params).unwrap())
    }

    pub fn large_vetkd_method_and_payload(
        context_size: usize,
        input_size: usize,
        key_id: VetKdKeyId,
    ) -> (String, Vec<u8>) {
        let params = GenVetkdParams {
            context_size,
            input_size,
            key_id: cast_vetkd_key_id(key_id),
        };

        (String::from("gen_vetkd_key"), Encode!(&params).unwrap())
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
        self.method_name.clone()
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
            MasterPublicKeyId::VetKd(_) => {
                SignWithChainKeyReply::VetKd(VetKdDeriveKeyResult::decode(raw_response)?)
            }
        })
    }
}

pub async fn vetkd_derive_key(
    transport_public_key: [u8; 48],
    key_id: VetKdKeyId,
    input: Vec<u8>,
    context: Vec<u8>,
    msg_can: &MessageCanister<'_>,
    cycles: Cycles,
) -> Result<Vec<u8>, AgentError> {
    let args = VetKdDeriveKeyArgs {
        context,
        input,
        key_id,
        transport_public_key,
    };

    let res = msg_can
        .forward_with_cycles_to(
            &Principal::management_canister(),
            "vetkd_derive_key",
            Encode!(&args).unwrap(),
            cycles,
        )
        .await?;

    let res = VetKdDeriveKeyResult::decode(&res).expect("Failed to decode VetKdDeriveKeyResult");

    Ok(res.encrypted_key)
}
