/* tag::catalog[]
Title:: Threshold ECDSA signature test

Goal:: Verify if the threshold ECDSA feature is working properly by exercising
the ECDSA public APIs.

Runbook::
. start a subnet with ecdsa feature enabled.
. get public key of a canister
. have the canister sign a message and get the signature
. verify if the signature is correct with respect to the public key

Success:: An agent can complete the signing process and result signature verifies.

end::catalog[] */

use std::collections::HashSet;
use std::time::Duration;

use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer};
use crate::nns::{get_subnet_list_from_registry, vote_and_execute_proposal};
use crate::util::*;
use candid::{Encode, Principal};
use canister_test::{Canister, Cycles};
use ic_agent::{
    agent::{RejectCode, RejectResponse},
    AgentError,
};
use ic_base_types::{NodeId, SubnetId};
use ic_canister_client::Sender;
use ic_config::subnet_config::ECDSA_SIGNATURE_FEE;
use ic_constants::SMALL_APP_SUBNET_MAX_SIZE;
use ic_ic00_types::{
    DerivationPath, ECDSAPublicKeyArgs, ECDSAPublicKeyResponse, EcdsaCurve, EcdsaKeyId, Payload,
    SignWithECDSAArgs, SignWithECDSAReply,
};
use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_KEYPAIR;
use ic_nns_common::types::{NeuronId, ProposalId};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance::pb::v1::{NnsFunction, ProposalStatus};
use ic_nns_test_utils::{governance::submit_external_update_proposal, ids::TEST_NEURON_1_ID};
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_subnet_features::{EcdsaConfig, SubnetFeatures, DEFAULT_ECDSA_MAX_QUEUE_SIZE};
use ic_registry_subnet_type::SubnetType;
use ic_types::{p2p, Height, ReplicaVersion};
use ic_types_test_utils::ids::subnet_test_id;
use itertools::Itertools;
use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use registry_canister::mutations::do_create_subnet::{
    CreateSubnetPayload, EcdsaInitialConfig, EcdsaKeyRequest,
};
use registry_canister::mutations::do_update_subnet::UpdateSubnetPayload;
use slog::{debug, info, Logger};

pub(crate) const KEY_ID1: &str = "secp256k1";
pub(crate) const KEY_ID2: &str = "some_other_key";
/// The default DKG interval takes too long before the keys are created and
/// passed to execution.
pub(crate) const DKG_INTERVAL: u64 = 19;

/// [EXC-1168] Flag to turn on cost scaling according to a subnet replication factor.
const USE_COST_SCALING_FLAG: bool = true;
const NUMBER_OF_NODES: usize = 4;

const ECDSA_KEY_TRANSCRIPT_CREATED: &str = "consensus_ecdsa_key_transcript_created";

/// Life cycle test requires more time
pub const LIFE_CYCLE_OVERALL_TIMEOUT: Duration = Duration::from_secs(14 * 60);
pub const LIFE_CYCLE_PER_TEST_TIMEOUT: Duration = Duration::from_secs(10 * 60);

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

/// Creates one system subnet without ECDSA enabled and one application subnet
/// with ECDSA enabled.
pub fn config_without_ecdsa_on_nns(test_env: TestEnv) {
    use crate::driver::test_env_api::*;
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
        .with_unassigned_nodes(NUMBER_OF_NODES as i32)
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
pub fn config(test_env: TestEnv) {
    use crate::driver::test_env_api::*;
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
        .with_unassigned_nodes(NUMBER_OF_NODES as i32)
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

// TODO(EXC-1168): cleanup after cost scaling is fully implemented.
fn scale_cycles(cycles: Cycles) -> Cycles {
    match USE_COST_SCALING_FLAG {
        false => cycles,
        true => {
            // Subnet is constructed with `NUMBER_OF_NODES`, see `config()` and `config_without_ecdsa_on_nns()`.
            (cycles * NUMBER_OF_NODES) / SMALL_APP_SUBNET_MAX_SIZE
        }
    }
}

pub(crate) async fn get_public_key_with_logger(
    key_id: EcdsaKeyId,
    msg_can: &MessageCanister<'_>,
    logger: &Logger,
) -> Result<VerifyingKey, AgentError> {
    let public_key_request = ECDSAPublicKeyArgs {
        canister_id: None,
        derivation_path: DerivationPath::new(vec![]),
        key_id,
    };

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
                if count < 20 {
                    debug!(logger, "ecdsa_public_key returns {}, try again...", err);
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                } else {
                    return Err(err);
                }
            }
        }
    };
    info!(logger, "ecdsa_public_key returns {:?}", public_key);
    Ok(VerifyingKey::from_sec1_bytes(&public_key).expect("Response is not a valid public key"))
}

pub(crate) async fn execute_update_subnet_proposal(
    governance: &Canister<'_>,
    proposal_payload: UpdateSubnetPayload,
) {
    let proposal_id: ProposalId = submit_external_update_proposal(
        governance,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::UpdateConfigOfSubnet,
        proposal_payload,
        "<proposal created by threshold ecdsa test>".to_string(),
        "".to_string(),
    )
    .await;

    let proposal_result = vote_and_execute_proposal(governance, proposal_id).await;
    println!("{:?}", proposal_result);
    assert_eq!(proposal_result.status(), ProposalStatus::Executed);
}

async fn execute_create_subnet_proposal(
    governance: &Canister<'_>,
    proposal_payload: CreateSubnetPayload,
) {
    let proposal_id: ProposalId = submit_external_update_proposal(
        governance,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::CreateSubnet,
        proposal_payload,
        "<proposal created by threshold ecdsa test>".to_string(),
        "".to_string(),
    )
    .await;

    let proposal_result = vote_and_execute_proposal(governance, proposal_id).await;
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
                    debug!(logger, "sign_with_ecdsa returns {}, try again...", err);
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
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
    key_id: EcdsaKeyId,
) {
    enable_ecdsa_signing_with_timeout(governance, subnet_id, key_id, None).await
}

pub(crate) async fn enable_ecdsa_signing_with_timeout(
    governance: &Canister<'_>,
    subnet_id: SubnetId,
    key_id: EcdsaKeyId,
    timeout: Option<Duration>,
) {
    enable_ecdsa_signing_with_timeout_and_rotation_period(
        governance, subnet_id, key_id, timeout, None,
    )
    .await
}

pub(crate) async fn add_ecdsa_key_with_timeout_and_rotation_period(
    governance: &Canister<'_>,
    subnet_id: SubnetId,
    key_id: EcdsaKeyId,
    timeout: Option<Duration>,
    period: Option<Duration>,
) {
    let proposal_payload = UpdateSubnetPayload {
        subnet_id,
        ecdsa_config: Some(EcdsaConfig {
            quadruples_to_create_in_advance: 10,
            key_ids: vec![key_id],
            max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            signature_request_timeout_ns: timeout.map(|t| t.as_nanos() as u64),
            idkg_key_rotation_period_ms: period.map(|t| t.as_millis() as u64),
        }),
        ..empty_subnet_update()
    };
    execute_update_subnet_proposal(governance, proposal_payload).await;
}

pub(crate) async fn enable_ecdsa_signing_with_timeout_and_rotation_period(
    governance: &Canister<'_>,
    subnet_id: SubnetId,
    key_id: EcdsaKeyId,
    timeout: Option<Duration>,
    period: Option<Duration>,
) {
    // The ECDSA key sharing process requires that a key first be added to a
    // subnet, and then enabling signing with that key must happen in a separate
    // proposal.
    add_ecdsa_key_with_timeout_and_rotation_period(
        governance,
        subnet_id,
        key_id.clone(),
        timeout,
        period,
    )
    .await;

    let proposal_payload = UpdateSubnetPayload {
        subnet_id,
        ecdsa_key_signing_enable: Some(vec![key_id]),
        ..empty_subnet_update()
    };
    execute_update_subnet_proposal(governance, proposal_payload).await;
}

pub(crate) async fn create_new_subnet_with_keys(
    governance: &Canister<'_>,
    node_ids: Vec<NodeId>,
    keys: Vec<EcdsaKeyRequest>,
    replica_version: ReplicaVersion,
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
        ingress_bytes_per_block_soft_cap: config.ingress_bytes_per_block_soft_cap,
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
        features: SubnetFeatures::default(),
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
    execute_create_subnet_proposal(governance, payload).await;
}

/// Tests whether a call to `sign_with_ecdsa` is responded with a signature
/// that is verifiable with the result from `ecdsa_public_key`.
pub fn test_threshold_ecdsa_signature_same_subnet(env: TestEnv) {
    let log = env.logger();
    let topology = env.topology_snapshot();
    let nns_subnet = topology.root_subnet();
    let app_subnet = topology
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap();
    let nns_node = nns_subnet.nodes().next().unwrap();
    let app_node = app_subnet.nodes().next().unwrap();
    let app_agent = app_node.build_default_agent();
    block_on(async move {
        let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        enable_ecdsa_signing(&governance, app_subnet.subnet_id, make_key(KEY_ID1)).await;
        let msg_can = MessageCanister::new(&app_agent, app_node.effective_canister_id()).await;
        let message_hash = [0xabu8; 32];
        let public_key = get_public_key_with_logger(make_key(KEY_ID1), &msg_can, &log)
            .await
            .unwrap();
        let signature = get_signature_with_logger(
            &message_hash,
            scale_cycles(ECDSA_SIGNATURE_FEE),
            make_key(KEY_ID1),
            &msg_can,
            &log,
        )
        .await
        .unwrap();
        verify_signature(&message_hash, &public_key, &signature);
    });
}

/// Tests whether a call to `sign_with_ecdsa` is responded with a signature that
/// is verifiable with the result from `get_ecdsa_public_key` when the subnet
/// sending the request is different than the subnet responsible for signing
/// with the key.
pub fn test_threshold_ecdsa_signature_from_other_subnet(env: TestEnv) {
    let log = env.logger();
    let topology = env.topology_snapshot();
    let nns_subnet = topology.root_subnet();
    let (app_subnet_1, app_subnet_2) = topology
        .subnets()
        .filter(|s| s.subnet_type() == SubnetType::Application)
        .tuples()
        .next()
        .unwrap();
    let nns_node = nns_subnet.nodes().next().unwrap();
    let node_from_app_subnet_1 = app_subnet_1.nodes().next().unwrap();
    let agent_for_app_subnet_1 = node_from_app_subnet_1.build_default_agent();
    block_on(async move {
        let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        enable_ecdsa_signing(&governance, app_subnet_2.subnet_id, make_key(KEY_ID2)).await;
        let msg_can = MessageCanister::new(
            &agent_for_app_subnet_1,
            node_from_app_subnet_1.effective_canister_id(),
        )
        .await;
        let message_hash = [0xabu8; 32];
        let public_key = get_public_key_with_logger(make_key(KEY_ID2), &msg_can, &log)
            .await
            .unwrap();
        let signature = get_signature_with_logger(
            &message_hash,
            scale_cycles(ECDSA_SIGNATURE_FEE),
            make_key(KEY_ID2),
            &msg_can,
            &log,
        )
        .await
        .unwrap();
        verify_signature(&message_hash, &public_key, &signature);
    });
}

/// Tests whether a call to `sign_with_ecdsa` fails when not enough cycles are
/// sent.
pub fn test_threshold_ecdsa_signature_fails_without_cycles(env: TestEnv) {
    let log = env.logger();
    let topology = env.topology_snapshot();
    let nns_subnet = topology.root_subnet();
    let app_subnet = topology
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap();
    let nns_node = nns_subnet.nodes().next().unwrap();
    let app_node = app_subnet.nodes().next().unwrap();
    let app_agent = app_node.build_default_agent();
    block_on(async move {
        let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        enable_ecdsa_signing(&governance, app_subnet.subnet_id, make_key(KEY_ID1)).await;

        // Cycles are only required for application subnets.
        let msg_can = MessageCanister::new(&app_agent, app_node.effective_canister_id()).await;
        let message_hash = [0xabu8; 32];

        info!(log, "Getting the public key to make sure the subnet has the latest registry changes and routing of ECDSA messages is working");
        let _public_key = get_public_key_with_logger(make_key(KEY_ID1), &msg_can, &log)
            .await
            .unwrap();

        info!(log, "Checking that signature request fails");
        let error = get_signature_with_logger(
            &message_hash,
            scale_cycles(ECDSA_SIGNATURE_FEE) - Cycles::from(1u64),
            make_key(KEY_ID1),
            &msg_can,
            &log,
        )
        .await
        .unwrap_err();
        assert_eq!(
            error,
            AgentError::ReplicaError(RejectResponse {
                reject_code: RejectCode::CanisterReject,
                reject_message: format!(
                    "sign_with_ecdsa request sent with {} cycles, but {} cycles are required.",
                    scale_cycles(ECDSA_SIGNATURE_FEE) - Cycles::from(1u64),
                    scale_cycles(ECDSA_SIGNATURE_FEE),
                ),
                error_code: None
            })
        )
    });
}

/// Tests that an ECDSA signature request coming from the NNS succeeds even when
/// there are no cycles sent with the request.
pub fn test_threshold_ecdsa_signature_from_nns_without_cycles(env: TestEnv) {
    let log = env.logger();
    let topology = env.topology_snapshot();
    let nns_subnet = topology.root_subnet();
    let app_subnet = topology
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap();
    let nns_node = nns_subnet.nodes().next().unwrap();
    let nns_agent = nns_node.build_default_agent();
    block_on(async move {
        let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        enable_ecdsa_signing(&governance, app_subnet.subnet_id, make_key(KEY_ID2)).await;
        let msg_can = MessageCanister::new(&nns_agent, nns_node.effective_canister_id()).await;
        let message_hash = [0xabu8; 32];
        let public_key = get_public_key_with_logger(make_key(KEY_ID2), &msg_can, &log)
            .await
            .unwrap();
        let signature = get_signature_with_logger(
            &message_hash,
            Cycles::zero(),
            make_key(KEY_ID2),
            &msg_can,
            &log,
        )
        .await
        .unwrap();
        verify_signature(&message_hash, &public_key, &signature);
    });
}

pub fn test_threshold_ecdsa_life_cycle(env: TestEnv) {
    let topology_snapshot = &env.topology_snapshot();
    let log = &env.logger();
    let app_subnet = topology_snapshot
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .expect("Could not find application subnet.");
    let nns_node = topology_snapshot.root_subnet().nodes().next().unwrap();
    let nns_agent = nns_node.build_default_agent();
    block_on(async move {
        let msg_can = MessageCanister::new(&nns_agent, nns_node.effective_canister_id()).await;

        info!(
            log,
            "1. Verifying that signature and public key requests fail before signing is enabled."
        );

        let message_hash = [0xabu8; 32];
        assert_eq!(
            get_public_key_with_logger(make_key(KEY_ID2), &msg_can, log)
                .await
                .unwrap_err(),
            AgentError::ReplicaError(RejectResponse {
                reject_code: RejectCode::CanisterReject,
                reject_message: "Unable to route management canister request ecdsa_public_key: EcdsaKeyError(\"Requested ECDSA key: Secp256k1:some_other_key, existing keys: []\")".to_string(),
                error_code: None,
            })
        );
        assert_eq!(
            get_signature_with_logger(
                &message_hash,
                scale_cycles(ECDSA_SIGNATURE_FEE),
                make_key(KEY_ID2),
                &msg_can,
                log,
            )
            .await
            .unwrap_err(),
            AgentError::ReplicaError(RejectResponse {
                reject_code: RejectCode::CanisterReject,
                reject_message: "Unable to route management canister request sign_with_ecdsa: EcdsaKeyError(\"Requested ECDSA key: Secp256k1:some_other_key, existing keys with signing enabled: []\")".to_string(),
                error_code: None,
            })
        );

        info!(log, "2. Enabling signing and verifying that it works.");

        let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        enable_ecdsa_signing(&governance, app_subnet.subnet_id, make_key(KEY_ID2)).await;

        let public_key = get_public_key_with_logger(make_key(KEY_ID2), &msg_can, log)
            .await
            .unwrap();
        let signature = get_signature_with_logger(
            &message_hash,
            scale_cycles(ECDSA_SIGNATURE_FEE),
            make_key(KEY_ID2),
            &msg_can,
            log,
        )
        .await
        .unwrap();
        verify_signature(&message_hash, &public_key, &signature);

        info!(
            log,
            "3. Sharing key with new app subnet, disabling signing on old app subnet, and then verifying signing no longer works."
        );

        let registry_client = RegistryCanister::new_with_query_timeout(
            vec![nns_node.get_public_url()],
            Duration::from_secs(10),
        );
        let original_subnets: HashSet<_> = get_subnet_list_from_registry(&registry_client)
            .await
            .into_iter()
            .collect();
        let unassigned_node_ids: Vec<_> = topology_snapshot
            .unassigned_nodes()
            .map(|n| n.node_id)
            .collect();

        let replica_version = crate::nns::get_software_version_from_snapshot(&nns_node)
            .await
            .expect("could not obtain replica software version");
        create_new_subnet_with_keys(
            &governance,
            unassigned_node_ids,
            vec![EcdsaKeyRequest {
                key_id: make_key(KEY_ID2),
                subnet_id: Some(app_subnet.subnet_id.get()),
            }],
            replica_version,
        )
        .await;
        let new_subnets: HashSet<_> = get_subnet_list_from_registry(&registry_client)
            .await
            .into_iter()
            .collect();
        let new_subnet_id = *new_subnets
            .symmetric_difference(&original_subnets)
            .next()
            .unwrap();

        let disable_signing_payload = UpdateSubnetPayload {
            subnet_id: app_subnet.subnet_id,
            ecdsa_key_signing_disable: Some(vec![make_key(KEY_ID2)]),
            ..empty_subnet_update()
        };
        execute_update_subnet_proposal(&governance, disable_signing_payload).await;

        // Try several times because signing won't fail until new registry data
        // is picked up.
        let mut sig_result;
        for _ in 0..20 {
            sig_result = get_signature_with_logger(
                &message_hash,
                scale_cycles(ECDSA_SIGNATURE_FEE),
                make_key(KEY_ID2),
                &msg_can,
                log,
            )
            .await;
            if sig_result.is_err() {
                break;
            } else {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
        assert_eq!(
            get_signature_with_logger(
                &message_hash,
                scale_cycles(ECDSA_SIGNATURE_FEE),
                make_key(KEY_ID2),
                &msg_can,
                log,
            )
            .await
            .unwrap_err(),
            AgentError::ReplicaError(RejectResponse {
                reject_code: RejectCode::CanisterReject,
                reject_message: "Unable to route management canister request sign_with_ecdsa: EcdsaKeyError(\"Requested ECDSA key: Secp256k1:some_other_key, existing keys with signing enabled: []\")".to_string(),
                error_code: None
            })
        );

        info!(log, "4. Enabling signing on new subnet then verifying that signing works and public key is unchanged.");

        let proposal_payload = UpdateSubnetPayload {
            subnet_id: new_subnet_id,
            ecdsa_key_signing_enable: Some(vec![make_key(KEY_ID2)]),
            ..empty_subnet_update()
        };
        execute_update_subnet_proposal(&governance, proposal_payload).await;

        let topology_snapshot = env
            .topology_snapshot()
            .block_for_newer_registry_version()
            .await
            .expect("Could not obtain updated registry.");
        let new_subnet = topology_snapshot
            .subnets()
            .find(|s| s.subnet_id == new_subnet_id)
            .expect("Could not find newly created subnet.");
        new_subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap());

        let new_public_key = get_public_key_with_logger(make_key(KEY_ID2), &msg_can, log)
            .await
            .unwrap();
        assert_eq!(public_key, new_public_key);
        let new_signature = get_signature_with_logger(
            &message_hash,
            scale_cycles(ECDSA_SIGNATURE_FEE),
            make_key(KEY_ID2),
            &msg_can,
            log,
        )
        .await
        .unwrap();
        verify_signature(&message_hash, &public_key, &new_signature);
    });
}

/// Tests whether a call to `sign_with_ecdsa` can be timed out when setting signature_request_timeout_ns.
pub fn test_threshold_ecdsa_signature_timeout(env: TestEnv) {
    let log = env.logger();
    let topology = env.topology_snapshot();
    let nns_subnet = topology.root_subnet();
    let app_subnet = topology
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap();
    let nns_node = nns_subnet.nodes().next().unwrap();
    let app_node = app_subnet.nodes().next().unwrap();
    let app_agent = app_node.build_default_agent();
    block_on(async move {
        let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        enable_ecdsa_signing_with_timeout(
            &governance,
            app_subnet.subnet_id,
            make_key(KEY_ID1),
            Some(Duration::from_secs(1)),
        )
        .await;
        let msg_can = MessageCanister::new(&app_agent, app_node.effective_canister_id()).await;
        let message_hash = [0xabu8; 32];
        // Get the public key first to make sure ECDSA is working
        let _public_key = get_public_key_with_logger(make_key(KEY_ID1), &msg_can, &log)
            .await
            .unwrap();
        let error = get_signature_with_logger(
            &message_hash,
            scale_cycles(ECDSA_SIGNATURE_FEE),
            make_key(KEY_ID1),
            &msg_can,
            &log,
        )
        .await
        .unwrap_err();
        assert_eq!(
            error,
            AgentError::ReplicaError(RejectResponse {
                reject_code: RejectCode::CanisterReject,
                reject_message: "Signature request expired".to_string(),
                error_code: None
            })
        )
    });
}

/// Tests whether ECDSA key transcript is correctly reshared when crypto keys are rotated
/// using the test settings below:
/// - DKG interval is set to 19, which roughly takes 20 or so seconds.
/// - Keys are rotated every 50 seconds, which should take more than 2 DKG intervals.
pub fn test_threshold_ecdsa_key_rotation(test_env: TestEnv) {
    let log = test_env.logger();
    let topology = test_env.topology_snapshot();
    let nns_subnet = topology.root_subnet();
    let app_subnet = topology
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap();
    let nns_node = nns_subnet.nodes().next().unwrap();
    let app_node = app_subnet.nodes().next().unwrap();
    let app_agent = app_node.build_default_agent();

    block_on(async move {
        let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        enable_ecdsa_signing_with_timeout_and_rotation_period(
            &governance,
            app_subnet.subnet_id,
            make_key(KEY_ID1),
            None,
            Some(Duration::from_secs(50)),
        )
        .await;
        let msg_can = MessageCanister::new(&app_agent, app_node.effective_canister_id()).await;
        // Get the public key first to make sure ECDSA is working
        let _public_key = get_public_key_with_logger(make_key(KEY_ID1), &msg_can, &log)
            .await
            .unwrap();

        let mut count = 0;
        let mut created = 0;
        let metrics = MetricsFetcher::new(
            app_subnet.nodes(),
            vec![ECDSA_KEY_TRANSCRIPT_CREATED.to_string()],
        );
        loop {
            match metrics.fetch().await {
                Ok(val) => {
                    created = val[ECDSA_KEY_TRANSCRIPT_CREATED][0];
                    if created > 1 {
                        break;
                    }
                }
                Err(err) => {
                    info!(log, "Could not connect to metrics yet {:?}", err);
                }
            }
            count += 1;
            // Break after 200 tries
            if count > 200 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        }
        if created <= 1 {
            panic!("Failed to observe key transcript being reshared more than once");
        }
    });
}
