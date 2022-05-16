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

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::test_env::TestEnv;
use crate::nns::{get_subnet_list_from_registry, vote_and_execute_proposal};
use crate::util::{self, *};
use candid::Encode;
use candid::Principal;
use canister_test::Canister;
use canister_test::Cycles;
use ic_agent::AgentError;
use ic_base_types::{NodeId, SubnetId};
use ic_canister_client::Sender;
use ic_config::subnet_config::ECDSA_SIGNATURE_FEE;
use ic_fondue::ic_manager::{IcEndpoint, IcHandle};
use ic_ic00_types::{
    ECDSAPublicKeyArgs, ECDSAPublicKeyResponse, EcdsaCurve, EcdsaKeyId, Payload, SignWithECDSAArgs,
    SignWithECDSAReply,
};
use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_KEYPAIR;
use ic_nns_common::types::{NeuronId, ProposalId};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance::pb::v1::{NnsFunction, ProposalStatus};
use ic_nns_test_utils::{governance::submit_external_update_proposal, ids::TEST_NEURON_1_ID};
use ic_registry_common::registry::RegistryCanister;
use ic_registry_subnet_features::{EcdsaConfig, SubnetFeatures};
use ic_registry_subnet_type::SubnetType;
use ic_types::p2p::{self};
use ic_types::{Height, ReplicaVersion};
use ic_types_test_utils::ids::subnet_test_id;
use registry_canister::mutations::do_create_subnet::{
    CreateSubnetPayload, EcdsaInitialConfig, EcdsaKeyRequest,
};
use registry_canister::mutations::do_update_subnet::UpdateSubnetPayload;
use secp256k1::{Message, PublicKey, Secp256k1, Signature};
use slog::{debug, info};

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

fn empty_subnet_update() -> UpdateSubnetPayload {
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
        advert_best_effort_percentage: None,
        set_gossip_config_to_default: false,
        start_as_nns: None,
        subnet_type: None,
        is_halted: None,
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
                .with_features(SubnetFeatures {
                    ecdsa_signatures: false,
                    ..SubnetFeatures::default()
                })
                .add_nodes(4),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .with_features(SubnetFeatures {
                    ecdsa_signatures: true,
                    ..SubnetFeatures::default()
                })
                .add_nodes(4),
        )
        .with_unassigned_nodes(4)
        .setup_and_start(&test_env)
        .expect("Could not start IC!");

    // Currently, we make the assumption that the first subnets is the root
    // subnet. This might not hold in the future.
    test_env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap()
        .install_nns_canisters()
        .expect("Failed to install NNS canisters");
}

/// Creates one system subnet and two application subnets.
pub fn config(test_env: TestEnv) {
    use crate::driver::test_env_api::*;
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .with_features(SubnetFeatures {
                    ecdsa_signatures: true,
                    ..SubnetFeatures::default()
                })
                .add_nodes(4),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .with_features(SubnetFeatures {
                    ecdsa_signatures: true,
                    ..SubnetFeatures::default()
                })
                .add_nodes(4),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .with_features(SubnetFeatures {
                    ecdsa_signatures: true,
                    ..SubnetFeatures::default()
                })
                .add_nodes(4),
        )
        .with_unassigned_nodes(4)
        .setup_and_start(&test_env)
        .expect("Could not start IC!");

    // Currently, we make the assumption that the first subnets is the root
    // subnet. This might not hold in the future.
    test_env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap()
        .install_nns_canisters()
        .expect("Failed to install NNS canisters");
}

struct Endpoints {
    nns_endpoint: IcEndpoint,
    app_endpoint_1: IcEndpoint,
    app_endpoint_2: IcEndpoint,
}

fn get_endpoints(handle: &IcHandle) -> Endpoints {
    let mut subnet_endpoints = BTreeMap::new();
    for endpoint in &handle.public_api_endpoints {
        if let Some(subnet) = endpoint.subnet.as_ref() {
            subnet_endpoints.entry(subnet.id).or_insert(endpoint);
        }
    }

    let mut ordered = subnet_endpoints.into_iter();
    let mut nns_endpoint = None;
    let mut app_endpoint_1 = None;
    let mut app_endpoint_2 = None;
    for _ in 0..3 {
        let endpoint = ordered.next().unwrap().1.clone();
        if endpoint.is_root_subnet {
            assert_eq!(
                endpoint.subnet.as_ref().unwrap().type_of,
                SubnetType::System
            );
            nns_endpoint = Some(endpoint);
        } else {
            assert_eq!(
                endpoint.subnet.as_ref().unwrap().type_of,
                SubnetType::Application
            );
            if app_endpoint_1.is_none() {
                app_endpoint_1 = Some(endpoint);
            } else {
                app_endpoint_2 = Some(endpoint);
            }
        }
    }

    Endpoints {
        nns_endpoint: nns_endpoint.unwrap(),
        app_endpoint_1: app_endpoint_1.unwrap(),
        app_endpoint_2: app_endpoint_2.unwrap(),
    }
}

pub(crate) async fn get_public_key(
    key_id: EcdsaKeyId,
    uni_can: &UniversalCanister<'_>,
    ctx: &ic_fondue::pot::Context,
) -> Result<PublicKey, AgentError> {
    let public_key_request = ECDSAPublicKeyArgs {
        canister_id: None,
        derivation_path: vec![],
        key_id,
    };

    let mut count = 0;
    let public_key = loop {
        let res = uni_can
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
                    debug!(ctx.logger, "ecdsa_public_key returns {}, try again...", err);
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                } else {
                    return Err(err);
                }
            }
        }
    };
    info!(ctx.logger, "ecdsa_public_key returns {:?}", public_key);
    Ok(PublicKey::from_slice(&public_key).expect("Response is not a valid public key"))
}

async fn execute_update_subnet_proposal(
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

pub(crate) async fn get_signature(
    message_hash: &[u8],
    cycles: Cycles,
    key_id: EcdsaKeyId,
    uni_can: &UniversalCanister<'_>,
    ctx: &ic_fondue::pot::Context,
) -> Result<Signature, AgentError> {
    let signature_request = SignWithECDSAArgs {
        message_hash: message_hash.to_vec(),
        derivation_path: Vec::new(),
        key_id,
    };

    // Ask for a signature.
    let reply = uni_can
        .forward_with_cycles_to(
            &Principal::management_canister(),
            "sign_with_ecdsa",
            Encode!(&signature_request).unwrap(),
            cycles,
        )
        .await?;

    let signature = SignWithECDSAReply::decode(&reply)
        .expect("failed to decode SignWithECDSAReply")
        .signature;
    info!(ctx.logger, "sign_with_ecdsa returns {:?}", signature);

    Ok(Signature::from_compact(&signature).expect("Response is not a valid signature"))
}

pub(crate) fn verify_signature(message_hash: &[u8], public_key: &PublicKey, signature: &Signature) {
    // Verify the signature:
    let secp = Secp256k1::new();
    let message = Message::from_slice(message_hash).expect("32 bytes");
    assert!(secp.verify(&message, signature, public_key).is_ok());
}

async fn enable_ecdsa_signing(governance: &Canister<'_>, subnet_id: SubnetId, key_id: EcdsaKeyId) {
    // The ECDSA key sharing process requires that a key first be added to a
    // subnet, and then enabling signing with that key must happen in a separate
    // proposal.
    let proposal_payload = UpdateSubnetPayload {
        subnet_id,
        ecdsa_config: Some(EcdsaConfig {
            quadruples_to_create_in_advance: 10,
            key_ids: vec![key_id.clone()],
        }),
        ..empty_subnet_update()
    };
    execute_update_subnet_proposal(governance, proposal_payload).await;

    let proposal_payload = UpdateSubnetPayload {
        subnet_id,
        ecdsa_key_signing_enable: Some(vec![key_id]),
        ..empty_subnet_update()
    };
    execute_update_subnet_proposal(governance, proposal_payload).await;
}

async fn create_new_subnet_with_keys(
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
        advert_best_effort_percentage: gossip.advert_config.map(|gac| gac.best_effort_percentage),
        start_as_nns: false,
        subnet_type: SubnetType::Application,
        is_halted: false,
        max_instructions_per_message: scheduler.max_instructions_per_message.get(),
        max_instructions_per_round: scheduler.max_instructions_per_round.get(),
        max_instructions_per_install_code: scheduler.max_instructions_per_install_code.get(),
        features: SubnetFeatures {
            ecdsa_signatures: true,
            ..SubnetFeatures::default()
        },
        max_number_of_canisters: 4,
        ssh_readonly_access: vec![],
        ssh_backup_access: vec![],
        ecdsa_config: Some(EcdsaInitialConfig {
            quadruples_to_create_in_advance: 4,
            keys,
        }),
    };
    execute_create_subnet_proposal(governance, payload).await;
}

/// Tests whether a call to `sign_with_ecdsa` is responded with a signature
/// that is verifiable with the result from `ecdsa_public_key`.
pub fn test_threshold_ecdsa_signature_same_subnet(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on(async move {
        let endpoints = get_endpoints(&handle);
        let nns_endpoint = endpoints.nns_endpoint;
        let app_endpoint = endpoints.app_endpoint_1;
        nns_endpoint.assert_ready(ctx).await;
        app_endpoint.assert_ready(ctx).await;

        let nns = runtime_from_url(nns_endpoint.url.clone());
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        enable_ecdsa_signing(
            &governance,
            app_endpoint.subnet.as_ref().unwrap().id,
            make_key(KEY_ID1),
        )
        .await;
        let agent = assert_create_agent(app_endpoint.url.as_str()).await;
        let uni_can = UniversalCanister::new(&agent).await;
        let message_hash = [0xabu8; 32];
        let public_key = get_public_key(make_key(KEY_ID1), &uni_can, ctx)
            .await
            .unwrap();
        let signature = get_signature(
            &message_hash,
            Cycles::from(7_000_000_000u64),
            make_key(KEY_ID1),
            &uni_can,
            ctx,
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
pub fn test_threshold_ecdsa_signature_from_other_subnet(
    handle: IcHandle,
    ctx: &ic_fondue::pot::Context,
) {
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on(async move {
        let endpoints = get_endpoints(&handle);
        let nns_endpoint = endpoints.nns_endpoint;
        let app_endpoint = endpoints.app_endpoint_1;
        nns_endpoint.assert_ready(ctx).await;
        app_endpoint.assert_ready(ctx).await;

        let nns = runtime_from_url(nns_endpoint.url.clone());
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        enable_ecdsa_signing(
            &governance,
            app_endpoint.subnet.as_ref().unwrap().id,
            make_key(KEY_ID2),
        )
        .await;

        let endpoint = endpoints.app_endpoint_2;
        endpoint.assert_ready(ctx).await;
        let agent = assert_create_agent(endpoint.url.as_str()).await;
        let uni_can = UniversalCanister::new(&agent).await;
        let message_hash = [0xabu8; 32];
        let public_key = get_public_key(make_key(KEY_ID2), &uni_can, ctx)
            .await
            .unwrap();
        let signature = get_signature(
            &message_hash,
            ECDSA_SIGNATURE_FEE,
            make_key(KEY_ID2),
            &uni_can,
            ctx,
        )
        .await
        .unwrap();
        verify_signature(&message_hash, &public_key, &signature);
    });
}

/// Tests whether a call to `sign_with_ecdsa` fails when not enough cycles are
/// sent.
pub fn test_threshold_ecdsa_signature_fails_without_cycles(
    handle: IcHandle,
    ctx: &ic_fondue::pot::Context,
) {
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on(async move {
        let endpoints = get_endpoints(&handle);
        let nns_endpoint = endpoints.nns_endpoint;
        let app_endpoint = endpoints.app_endpoint_1;
        nns_endpoint.assert_ready(ctx).await;
        app_endpoint.assert_ready(ctx).await;

        // Cycles are only required for application subnets.
        let endpoint = endpoints.app_endpoint_2;
        endpoint.assert_ready(ctx).await;
        let agent = assert_create_agent(endpoint.url.as_str()).await;
        let uni_can = UniversalCanister::new(&agent).await;
        let message_hash = [0xabu8; 32];
        let error = get_signature(
            &message_hash,
            ECDSA_SIGNATURE_FEE - Cycles::from(1u64),
            make_key(KEY_ID1),
            &uni_can,
            ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(
            error,
            AgentError::ReplicaError {
                reject_code: 4,
                reject_message: format!(
                    "sign_with_ecdsa request sent with {} cycles, but {} cycles are required.",
                    ECDSA_SIGNATURE_FEE.get() - 1,
                    ECDSA_SIGNATURE_FEE.get()
                )
            }
        )
    });
}

/// Tests that an ECDSA signature request coming from the NNS succeeds even when
/// there are no cycles sent with the request.
pub fn test_threshold_ecdsa_signature_from_nns_without_cycles(
    handle: IcHandle,
    ctx: &ic_fondue::pot::Context,
) {
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on(async move {
        let endpoints = get_endpoints(&handle);
        let nns_endpoint = endpoints.nns_endpoint;
        let app_endpoint = endpoints.app_endpoint_1;
        nns_endpoint.assert_ready(ctx).await;
        app_endpoint.assert_ready(ctx).await;

        let nns = runtime_from_url(nns_endpoint.url.clone());
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        enable_ecdsa_signing(
            &governance,
            app_endpoint.subnet.as_ref().unwrap().id,
            make_key(KEY_ID2),
        )
        .await;

        let agent = assert_create_agent(nns_endpoint.url.as_str()).await;
        let uni_can = UniversalCanister::new(&agent).await;
        let message_hash = [0xabu8; 32];
        let public_key = get_public_key(make_key(KEY_ID2), &uni_can, ctx)
            .await
            .unwrap();
        let signature = get_signature(
            &message_hash,
            Cycles::zero(),
            make_key(KEY_ID2),
            &uni_can,
            ctx,
        )
        .await
        .unwrap();
        verify_signature(&message_hash, &public_key, &signature);
    });
}

pub fn test_threshold_ecdsa_life_cycle(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let mut rng = ctx.rng.clone();
    rt.block_on(async move {
        let nns_endpoint = get_random_system_node_endpoint(&handle, &mut rng);
        let app_endpoint = get_random_application_node_endpoint(&handle, &mut rng);
        nns_endpoint.assert_ready(ctx).await;
        app_endpoint.assert_ready(ctx).await;
        let agent = assert_create_agent(nns_endpoint.url.as_str()).await;
        let uni_can = UniversalCanister::new(&agent).await;

        info!(
            ctx.logger,
            "1. Verifying that signature and public key requests fail before signing is enabled."
        );

        let message_hash = [0xabu8; 32];
        assert_eq!(
            get_public_key(make_key(KEY_ID2), &uni_can, ctx)
                .await
                .unwrap_err(),
            AgentError::ReplicaError {
                reject_code: 4,
                reject_message: "This API is not enabled on this subnet".to_string()
            }
        );
        assert_eq!(
            get_signature(
                &message_hash,
                ECDSA_SIGNATURE_FEE,
                make_key(KEY_ID2),
                &uni_can,
                ctx,
            )
            .await
            .unwrap_err(),
            AgentError::ReplicaError {
                reject_code: 4,
                reject_message: "This API is not enabled on this subnet".to_string()
            }
        );

        info!(ctx.logger, "2. Enabling signing and verifying that it works.");

        let nns = runtime_from_url(nns_endpoint.url.clone());
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        enable_ecdsa_signing(
            &governance,
            app_endpoint.subnet.as_ref().unwrap().id,
            make_key(KEY_ID2),
        )
        .await;

        let public_key = get_public_key(make_key(KEY_ID2), &uni_can, ctx)
            .await
            .unwrap();
        let signature = get_signature(
            &message_hash,
            ECDSA_SIGNATURE_FEE,
            make_key(KEY_ID2),
            &uni_can,
            ctx,
        )
        .await
        .unwrap();
        verify_signature(&message_hash, &public_key, &signature);

        info!(
            ctx.logger,
            "3. Sharing key with new app subnet, disabling signing on old app subnet, and then verifying signing no longer works."
        );

        let registry_client = RegistryCanister::new_with_query_timeout(
            vec![nns_endpoint.url.clone()],
            Duration::from_secs(10),
        );
        let original_subnets: HashSet<_> = get_subnet_list_from_registry(&registry_client)
            .await
            .into_iter()
            .collect();
        let unassigned_nodes_endpoints = util::get_unassinged_nodes_endpoints(&handle);
        let unassigned_node_ids: Vec<NodeId> = unassigned_nodes_endpoints
            .iter()
            .map(|ep| ep.node_id)
            .collect();
        util::assert_all_ready(unassigned_nodes_endpoints.as_slice(), ctx).await;

        let replica_version = crate::nns::get_software_version(nns_endpoint)
            .await
            .expect("could not obtain replica software version");
        create_new_subnet_with_keys(
            &governance,
            unassigned_node_ids,
            vec![EcdsaKeyRequest {
                key_id: make_key(KEY_ID2),
                subnet_id: Some(app_endpoint.subnet.as_ref().unwrap().id.get()),
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
            subnet_id: app_endpoint.subnet.as_ref().unwrap().id,
            ecdsa_key_signing_disable: Some(vec![make_key(KEY_ID2)]),
            ..empty_subnet_update()
        };
        execute_update_subnet_proposal(&governance, disable_signing_payload).await;

        // Try several times because signing won't fail until new registry data
        // is picked up.
        let mut sig_result;
        for _ in 0..20 {
            sig_result = get_signature(
                &message_hash,
                ECDSA_SIGNATURE_FEE,
                make_key(KEY_ID2),
                &uni_can,
                ctx,
            )
            .await;
            if sig_result.is_err() {
                break;
            } else {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
        assert_eq!(
            get_signature(
                &message_hash,
                ECDSA_SIGNATURE_FEE,
                make_key(KEY_ID2),
                &uni_can,
                ctx,
            )
            .await
            .unwrap_err(),
            AgentError::ReplicaError {
                reject_code: 4,
                reject_message: "This API is not enabled on this subnet".to_string()
            }
        );

        info!(ctx.logger, "4. Enabling signing on new subnet then verifying that signing works and public key is unchanged.");

        let proposal_payload = UpdateSubnetPayload {
            subnet_id: new_subnet_id,
            ecdsa_key_signing_enable: Some(vec![make_key(KEY_ID2)]),
            ..empty_subnet_update()
        };
        execute_update_subnet_proposal(&governance, proposal_payload).await;

        let newly_assigned_endpoint =
            unassigned_nodes_endpoints[0].recreate_with_subnet(ic_fondue::ic_manager::IcSubnet {
                id: new_subnet_id,
                type_of: SubnetType::Application,
            });

        newly_assigned_endpoint.assert_ready(ctx).await;

        let new_public_key = get_public_key(make_key(KEY_ID2), &uni_can, ctx)
            .await
            .unwrap();
        assert_eq!(public_key, new_public_key);
        let new_signature = get_signature(
            &message_hash,
            ECDSA_SIGNATURE_FEE,
            make_key(KEY_ID2),
            &uni_can,
            ctx,
        )
        .await
        .unwrap();
        verify_signature(&message_hash, &public_key, &new_signature);
    });
}
