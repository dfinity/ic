//! This module contains the batch delivery logic: crafting of batches from
//! selections of ingress and xnet messages, and DKGs computed for other
//! subnets.

use crate::consensus::{
    pool_reader::PoolReader,
    prelude::*,
    utils::{crypto_hashable_to_seed, get_block_hash_string, lookup_replica_version},
};
use ic_crypto::utils::ni_dkg::initial_ni_dkg_transcript_record_from_transcript;
use ic_interfaces::{
    messaging::{MessageRouting, MessageRoutingError},
    registry::RegistryClient,
    state_manager::StateManager,
};
use ic_logger::{debug, info, trace, warn, ReplicaLogger};
use ic_protobuf::log::consensus_log_entry::v1::ConsensusLogEntry;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_replicated_state::{metadata_state::subnet_call_context_manager::*, ReplicatedState};
use ic_types::{
    crypto::threshold_sig::ni_dkg::{
        NiDkgId, NiDkgTag, NiDkgTargetSubnet::Remote, NiDkgTranscript,
    },
    ic00::SetupInitialDKGResponse,
    messages::{CallbackId, Response},
    CountBytes, ReplicaVersion,
};
use secp256k1::{Message, Secp256k1, SecretKey};
use std::collections::BTreeMap;
use std::time::Duration;

/// Deliver all finalized blocks from
/// `message_routing.expected_batch_height` to `finalized_height` via
/// `MessageRouting` and return the last delivered batch height.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn deliver_batches(
    message_routing: &dyn MessageRouting,
    pool: &PoolReader<'_>,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    registry_client: &dyn RegistryClient,
    subnet_id: SubnetId,
    current_replica_version: ReplicaVersion,
    log: &ReplicaLogger,
    // This flag is used by the replay tool only.
    persist_the_last_batch: bool,
    // Deliver batches until this height or finalized height if set to `None`
    max_deliver_height: Option<u64>,
    result_processor: Option<
        &dyn Fn(
            &Result<(), MessageRoutingError>,
            u64,
            usize,
            usize,
            usize,
            Vec<ic_types::artifact::IngressMessageId>,
            &str,
            u64,
            u64,
        ),
    >,
) -> Result<Height, MessageRoutingError> {
    // If `max_deliver_height` is specified and smaller than `finalized_height`, we
    // use it, otherwise we use `finalized_height`.
    let target_height = max_deliver_height
        .map(Height::from)
        .unwrap_or_else(|| pool.get_finalized_height());

    let mut h = message_routing.expected_batch_height();
    if h == Height::from(0) {
        return Ok(Height::from(0));
    }
    let mut last_delivered_batch_height = h.decrement();
    while h <= target_height {
        match (pool.get_finalized_block(h), pool.get_random_tape(h)) {
            (Some(block), Some(tape)) => {
                debug!(
                    log,
                    "Finalized height";
                    consensus => ConsensusLogEntry { height: Some(h.get()), hash: Some(get_block_hash_string(&block)) }
                );
                let mut consensus_responses = Vec::<Response>::new();
                if block.payload.is_summary() {
                    let summary = block.payload.as_ref().as_summary();
                    info!(
                        log,
                        "New DKG summary with config ids created: {:?}",
                        summary.dkg.configs.keys().collect::<Vec<_>>()
                    );
                    // Compute consensus' responses to subnet calls.
                    consensus_responses = generate_responses_to_subnet_calls(
                        &*state_manager,
                        block.context.certified_height,
                        summary.dkg.transcripts_for_new_subnets(),
                        block.context.time,
                        &log,
                    );
                }
                // When we are not deliverying CUP block, we must check replica_version
                else {
                    match pool.registry_version(h).and_then(|registry_version| {
                        lookup_replica_version(registry_client, subnet_id, &log, registry_version)
                    }) {
                        Some(replica_version) if replica_version != current_replica_version => {
                            debug!(
                                log,
                                "Batch of height {} is not delivered before replica upgrades to new version {}",
                                h,
                                replica_version.as_ref()
                            );
                            return Ok(last_delivered_batch_height);
                        }
                        None => {
                            warn!(
                                log,
                                "Skipping batch delivery because replica version is unknown",
                            );
                            return Ok(last_delivered_batch_height);
                        }
                        _ => {}
                    }
                }

                let block_hash = get_block_hash_string(&block);
                let block_height = block.height().get();

                let randomness = Randomness::from(crypto_hashable_to_seed(&tape));
                let persist_batch = persist_the_last_batch && h == target_height;
                let batch = Batch {
                    batch_number: h,
                    requires_full_state_hash: block.payload.is_summary() || persist_batch,
                    payload: if block.payload.is_summary() {
                        BatchPayload::default()
                    } else {
                        BlockPayload::from(block.payload).into_data().batch
                    },
                    randomness,
                    registry_version: block.context.registry_version,
                    time: block.context.time,
                    consensus_responses,
                };
                let batch_height = batch.batch_number.get();
                let ingress_count = batch.payload.ingress.message_count();
                let ingress_bytes = batch.payload.ingress.count_bytes();
                let xnet_bytes = batch.payload.xnet.count_bytes();
                let ingress_ids = batch.payload.ingress.message_ids();
                let block_context_certified_height = block.context.certified_height.get();
                debug!(log, "deliver batch {:?}", batch_height);
                let result = message_routing.deliver_batch(batch);
                if let Some(f) = result_processor {
                    f(
                        &result,
                        batch_height,
                        ingress_count,
                        ingress_bytes,
                        xnet_bytes,
                        ingress_ids,
                        &block_hash,
                        block_height,
                        block_context_certified_height,
                    );
                }
                if let Err(err) = result {
                    warn!(log, "Batch delivery failed: {:?}", &err);
                    return Err(err);
                }
                last_delivered_batch_height = h;
                h = h.increment();
            }
            (None, _) => {
                trace!(
                        log,
                        "Do not deliver height {:?} because no finalized block was found. This should indicate we are waiting for state sync.",
                        h);
                break;
            }
            (_, None) => {
                // Do not deliver batch if we don't have random tape
                trace!(
                    log,
                    "Do not deliver height {:?} because RandomTape is not ready. Will re-try later",
                    h
                );
                break;
            }
        }
    }
    Ok(last_delivered_batch_height)
}

/// This function creates responses to the system calls that are redirected to
/// consensus.
pub fn generate_responses_to_subnet_calls(
    state_manager: &dyn StateManager<State = ReplicatedState>,
    certified_height: Height,
    transcripts_for_new_subnets: &BTreeMap<NiDkgId, Result<NiDkgTranscript, String>>,
    batch_time: Time,
    log: &ReplicaLogger,
) -> Vec<Response> {
    let mut consensus_responses = Vec::<Response>::new();
    if let Ok(state) = state_manager.get_state_at(certified_height) {
        let setup_initial_dkg_contexts = &state
            .get_ref()
            .metadata
            .subnet_call_context_manager
            .setup_initial_dkg_contexts;
        consensus_responses.append(&mut generate_responses_to_setup_initial_dkg_calls(
            setup_initial_dkg_contexts,
            transcripts_for_new_subnets,
            log,
        ));
        let sign_with_mock_ecdsa_contexts = &state
            .get_ref()
            .metadata
            .subnet_call_context_manager
            .sign_with_mock_ecdsa_contexts;
        consensus_responses.append(&mut generate_responses_to_sign_with_mock_ecdsa_calls(
            sign_with_mock_ecdsa_contexts,
            batch_time,
        ));
    }
    consensus_responses
}

/// This function creates responses to the SetupInitialDKG system calls with the
/// computed DKG key material for remote subnets.
pub fn generate_responses_to_setup_initial_dkg_calls(
    contexts: &BTreeMap<CallbackId, SetupInitialDkgContext>,
    transcripts_for_new_subnets: &BTreeMap<NiDkgId, Result<NiDkgTranscript, String>>,
    log: &ReplicaLogger,
) -> Vec<Response> {
    let mut consensus_responses = Vec::<Response>::new();
    for (callback_id, context) in contexts.iter() {
        let target_id = context.target_id;

        let transcript = |dkg_tag| {
            transcripts_for_new_subnets
                .iter()
                .filter_map(|(id, transcript)| {
                    if id.dkg_tag == dkg_tag && id.target_subnet == Remote(target_id) {
                        Some(transcript)
                    } else {
                        None
                    }
                })
                .last()
        };

        let payload = match (
            transcript(NiDkgTag::LowThreshold),
            transcript(NiDkgTag::HighThreshold),
        ) {
            (Some(Ok(low_threshold_transcript)), Some(Ok(high_threshold_transcript))) => {
                info!(
                    log,
                    "Found transcripts for another subnet with ids {:?} and {:?}",
                    low_threshold_transcript.dkg_id,
                    high_threshold_transcript.dkg_id
                );
                let low_threshold_transcript_record =
                    initial_ni_dkg_transcript_record_from_transcript(
                        low_threshold_transcript.clone(),
                    );
                let high_threshold_transcript_record =
                    initial_ni_dkg_transcript_record_from_transcript(
                        high_threshold_transcript.clone(),
                    );

                // This is what we expect consensus to reply with.
                let threshold_sig_pk = high_threshold_transcript.public_key();
                let subnet_threshold_public_key = PublicKeyProto::from(threshold_sig_pk);
                let key_der: Vec<u8> =
                    ic_crypto::threshold_sig_public_key_to_der(threshold_sig_pk).unwrap();
                let fresh_subnet_id =
                    SubnetId::new(PrincipalId::new_self_authenticating(key_der.as_slice()));

                let initial_transcript_records = SetupInitialDKGResponse {
                    low_threshold_transcript_record,
                    high_threshold_transcript_record,
                    fresh_subnet_id,
                    subnet_threshold_public_key,
                };

                Some(messages::Payload::Data(initial_transcript_records.encode()))
            }
            (Some(Err(err_str1)), Some(Err(err_str2))) => {
                Some(messages::Payload::Reject(messages::RejectContext {
                    code: ic_types::user_error::RejectCode::CanisterReject,
                    message: format!("{}{}", err_str1, err_str2),
                }))
            }
            (Some(Err(err_str)), _) => Some(messages::Payload::Reject(messages::RejectContext {
                code: ic_types::user_error::RejectCode::CanisterReject,
                message: err_str.to_string(),
            })),
            (_, Some(Err(err_str))) => Some(messages::Payload::Reject(messages::RejectContext {
                code: ic_types::user_error::RejectCode::CanisterReject,
                message: err_str.to_string(),
            })),
            _ => None,
        };

        if let Some(response_payload) = payload {
            consensus_responses.push(Response {
                originator: CanisterId::ic_00(),
                respondent: CanisterId::ic_00(),
                originator_reply_callback: *callback_id,
                refund: Cycles::zero(),
                response_payload,
            });
        }
    }
    consensus_responses
}

const MOCK_ECDSA_DELAY_MILLIS: u64 = 30000;
/// This function creates responses to the SignWithMockECDSA system calls with
/// the computed MOCK(!) signature.
pub fn generate_responses_to_sign_with_mock_ecdsa_calls(
    contexts: &BTreeMap<CallbackId, SignWithEcdsaContext>,
    batch_time: Time,
) -> Vec<Response> {
    let mut consensus_responses = Vec::<Response>::new();
    if contexts.is_empty() {
        return consensus_responses;
    }
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");

    for (callback_id, context) in contexts.iter() {
        if batch_time > context.batch_time + Duration::from_millis(MOCK_ECDSA_DELAY_MILLIS) {
            let hash = Message::from_slice(&context.message_hash).unwrap();
            let sig = secp.sign(&hash, &secret_key);
            let response_payload = messages::Payload::Data(sig.serialize_compact().to_vec());
            consensus_responses.push(Response {
                originator: CanisterId::ic_00(),
                respondent: CanisterId::ic_00(),
                originator_reply_callback: *callback_id,
                refund: Cycles::zero(),
                response_payload,
            });
        }
    }
    consensus_responses
}
