//! This module contains the batch delivery logic: crafting of batches from
//! selections of ingress and xnet messages, and DKGs computed for other
//! subnets.

use crate::consensus::{
    pool_reader::PoolReader,
    prelude::*,
    utils::{crypto_hashable_to_seed, get_block_hash_string, lookup_replica_version},
};
use crate::ecdsa::utils::EcdsaBlockReaderImpl;
use ic_artifact_pool::consensus_pool::build_consensus_block_chain;
use ic_crypto::get_tecdsa_master_public_key;
use ic_crypto::utils::ni_dkg::initial_ni_dkg_transcript_record_from_transcript;
use ic_ic00_types::SetupInitialDKGResponse;
use ic_interfaces::{
    messaging::{MessageRouting, MessageRoutingError},
    registry::RegistryClient,
};
use ic_interfaces_state_manager::StateManager;
use ic_logger::{debug, info, trace, warn, ReplicaLogger};
use ic_protobuf::log::consensus_log_entry::v1::ConsensusLogEntry;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_replicated_state::{metadata_state::subnet_call_context_manager::*, ReplicatedState};
use ic_types::{
    consensus::ecdsa::{CompletedSignature, EcdsaBlockReader},
    crypto::threshold_sig::ni_dkg::{
        NiDkgId, NiDkgTag, NiDkgTargetSubnet::Remote, NiDkgTranscript,
    },
    messages::{CallbackId, Response},
    CountBytes, ReplicaVersion,
};
use std::collections::BTreeMap;

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
    // This argument should only be used by the ic-replay tool. If it is set to `None`, we will
    // deliver all batches until the finalized height. If it is set to `Some(h)`, we will
    // deliver all bathes up to the height `min(h, finalized_height)`.
    max_batch_height_to_deliver: Option<Height>,
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
    let finalized_height = pool.get_finalized_height();
    // If `max_batch_height_to_deliver` is specified and smaller than
    // `finalized_height`, we use it, otherwise we use `finalized_height`.
    let target_height = max_batch_height_to_deliver
        .unwrap_or(finalized_height)
        .min(finalized_height);

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
                    consensus => ConsensusLogEntry {
                        height: Some(h.get()),
                        hash: Some(get_block_hash_string(&block)),
                        replica_version: Some(String::from(current_replica_version.clone()))
                    }
                );
                // Compute consensus' responses to subnet calls.
                let consensus_responses =
                    generate_responses_to_subnet_calls(&*state_manager, &block, log);

                if block.payload.is_summary() {
                    info!(log, "Delivering finalized batch at CUP height of {}", h);
                }
                // When we are not deliverying CUP block, we must check replica_version
                else {
                    match pool.registry_version(h).and_then(|registry_version| {
                        lookup_replica_version(registry_client, subnet_id, log, registry_version)
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
                let ecdsa_subnet_public_key = pool.dkg_summary_block(&block).and_then(|summary| {
                    let ecdsa_summary = summary.payload.as_ref().as_summary().ecdsa.as_ref();
                    ecdsa_summary.and_then(|ecdsa| {
                        let chain = build_consensus_block_chain(pool.pool(), &summary, &block);
                        let block_reader = EcdsaBlockReaderImpl::new(chain);
                        let transcript_ref = ecdsa.current_key_transcript.as_ref();
                        match block_reader.transcript(transcript_ref) {
                            Ok(transcript) =>  get_tecdsa_master_public_key(&transcript).ok(),
                            Err(err) => {
                                warn!(
                                    log,
                                    "deliver_batches(): failed to translate transcript ref {:?}: {:?}",
                                    transcript_ref, err
                                );
                                None
                            }
                        }
                    })
                });

                // This flag can only be true, if we've called deliver_batches with a height
                // limit.  In this case we also want to have a checkpoint for that last height.
                let persist_batch = Some(h) == max_batch_height_to_deliver;
                let batch = Batch {
                    batch_number: h,
                    requires_full_state_hash: block.payload.is_summary() || persist_batch,
                    payload: if block.payload.is_summary() {
                        BatchPayload::default()
                    } else {
                        BlockPayload::from(block.payload).into_data().batch
                    },
                    randomness,
                    ecdsa_subnet_public_key,
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
                debug!(
                    log,
                    "replica {:?} delivered batch {:?} for block_hash {:?}",
                    current_replica_version,
                    batch_height,
                    block_hash
                );
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
                    warn!(every_n_seconds => 5, log, "Batch delivery failed: {:?}", err);
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
/// consensus. There are two types of calls being handled here:
/// - Initial NiDKG transcript creation, where a response may come from summary payloads.
/// - Threshold ECDSA signature creation, where a response may from from data payloads.
pub fn generate_responses_to_subnet_calls(
    state_manager: &dyn StateManager<State = ReplicatedState>,
    block: &Block,
    log: &ReplicaLogger,
) -> Vec<Response> {
    let mut consensus_responses = Vec::<Response>::new();
    let block_payload = &block.payload;
    if let Ok(state) = state_manager.get_state_at(block.context.certified_height) {
        let setup_initial_dkg_contexts = &state
            .get_ref()
            .metadata
            .subnet_call_context_manager
            .setup_initial_dkg_contexts;
        if block_payload.is_summary() {
            let summary = block_payload.as_ref().as_summary();
            info!(
                log,
                "New DKG summary with config ids created: {:?}",
                summary.dkg.configs.keys().collect::<Vec<_>>()
            );

            consensus_responses.append(&mut generate_responses_to_setup_initial_dkg_calls(
                setup_initial_dkg_contexts,
                summary.dkg.transcripts_for_new_subnets(),
                log,
            ));
        } else if let Some(payload) = &block_payload.as_ref().as_data().ecdsa {
            let sign_with_ecdsa_contexts = &state
                .get_ref()
                .metadata
                .subnet_call_context_manager
                .sign_with_ecdsa_contexts;
            consensus_responses.append(&mut generate_responses_to_sign_with_ecdsa_calls(
                sign_with_ecdsa_contexts,
                &payload.ecdsa_payload,
            ));

            let ecdsa_dealings_contexts = &state
                .get_ref()
                .metadata
                .subnet_call_context_manager
                .ecdsa_dealings_contexts;
            consensus_responses.append(&mut generate_responses_to_initial_dealings_calls(
                ecdsa_dealings_contexts,
                &payload.ecdsa_payload,
            ));
        }
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
                    code: ic_error_types::RejectCode::CanisterReject,
                    message: format!("{}{}", err_str1, err_str2),
                }))
            }
            (Some(Err(err_str)), _) => Some(messages::Payload::Reject(messages::RejectContext {
                code: ic_error_types::RejectCode::CanisterReject,
                message: err_str.to_string(),
            })),
            (_, Some(Err(err_str))) => Some(messages::Payload::Reject(messages::RejectContext {
                code: ic_error_types::RejectCode::CanisterReject,
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

/// Creates responses to `SignWithECDSA` system calls with the computed
/// signature.
pub fn generate_responses_to_sign_with_ecdsa_calls(
    contexts: &BTreeMap<CallbackId, SignWithEcdsaContext>,
    ecdsa_payload: &ecdsa::EcdsaPayload,
) -> Vec<Response> {
    use ic_ic00_types::{Payload, SignWithECDSAReply};
    let mut consensus_responses = Vec::<Response>::new();
    let mut completed_set = ecdsa_payload
        .signature_agreements
        .iter()
        .map(|(request_id, sig)| (request_id.pseudo_random_id, sig))
        .collect::<BTreeMap<_, _>>();
    for (callback_id, context) in contexts.iter() {
        if let Some(CompletedSignature::Unreported(response)) =
            completed_set.remove(context.pseudo_random_id.as_slice())
        {
            consensus_responses.push(Response {
                originator: context.request.sender,
                respondent: CanisterId::ic_00(),
                originator_reply_callback: *callback_id,
                // Execution is responsible for burning the appropriate cycles
                // before pushing the new context, so any remaining cycles can
                // be refunded to the canister.
                refund: context.request.payment,
                response_payload: messages::Payload::Data(
                    SignWithECDSAReply {
                        signature: response.signature.clone(),
                    }
                    .encode(),
                ),
            });
        }
    }
    consensus_responses
}

/// Creates responses to `ComputeInitialEcdsaDealingsArgs` system calls with the initial
/// dealings.
fn generate_responses_to_initial_dealings_calls(
    contexts: &BTreeMap<CallbackId, EcdsaDealingsContext>,
    ecdsa_payload: &ecdsa::EcdsaPayload,
) -> Vec<Response> {
    use ic_ic00_types::ComputeInitialEcdsaDealingsResponse;
    let mut consensus_responses = Vec::<Response>::new();
    for (callback_id, context) in contexts.iter() {
        let request = ecdsa::EcdsaReshareRequest {
            key_id: context.key_id.clone(),
            receiving_node_ids: context.nodes.iter().cloned().collect(),
            registry_version: context.registry_version,
        };

        if let Some(ecdsa::CompletedReshareRequest::Unreported(initial_dealings)) =
            ecdsa_payload.xnet_reshare_agreements.get(&request)
        {
            consensus_responses.push(Response {
                originator: context.request.sender,
                respondent: CanisterId::ic_00(),
                originator_reply_callback: *callback_id,
                refund: context.request.payment,
                response_payload: messages::Payload::Data(
                    ComputeInitialEcdsaDealingsResponse {
                        initial_dkg_dealings: (initial_dealings.as_ref()).into(),
                    }
                    .encode(),
                ),
            });
        }
    }
    consensus_responses
}
