//! This module contains the batch delivery logic: crafting of batches from
//! selections of ingress and xnet messages, and DKGs computed for other
//! subnets.

use crate::{
    consensus::{
        metrics::{BatchStats, BlockStats},
        status::{self, Status},
        utils::get_block_hash_string,
    },
    idkg::utils::{get_idkg_subnet_public_keys, get_pre_signature_ids_to_deliver},
};
use ic_consensus_utils::{
    crypto_hashable_to_seed, membership::Membership, pool_reader::PoolReader,
};
use ic_https_outcalls_consensus::payload_builder::CanisterHttpPayloadBuilderImpl;
use ic_interfaces::{
    batch_payload::IntoMessages,
    messaging::{MessageRouting, MessageRoutingError},
};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{debug, error, info, warn, ReplicaLogger};
use ic_management_canister_types::SetupInitialDKGResponse;
use ic_protobuf::{
    log::consensus_log_entry::v1::ConsensusLogEntry,
    registry::{crypto::v1::PublicKey as PublicKeyProto, subnet::v1::InitialNiDkgTranscriptRecord},
};
use ic_types::{
    batch::{Batch, BatchMessages, BatchSummary, BlockmakerMetrics, ConsensusResponse},
    consensus::{
        idkg::{self, CompletedSignature},
        Block,
    },
    crypto::threshold_sig::{
        ni_dkg::{NiDkgId, NiDkgTag, NiDkgTranscript},
        ThresholdSigPublicKey,
    },
    messages::{CallbackId, Payload, RejectContext},
    Height, PrincipalId, Randomness, ReplicaVersion, SubnetId,
};
use std::collections::BTreeMap;

/// Deliver all finalized blocks from
/// `message_routing.expected_batch_height` to `finalized_height` via
/// `MessageRouting` and return the last delivered batch height.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn deliver_batches(
    message_routing: &dyn MessageRouting,
    membership: &Membership,
    pool: &PoolReader<'_>,
    registry_client: &dyn RegistryClient,
    subnet_id: SubnetId,
    current_replica_version: ReplicaVersion,
    log: &ReplicaLogger,
    // This argument should only be used by the ic-replay tool. If it is set to `None`, we will
    // deliver all batches until the finalized height. If it is set to `Some(h)`, we will
    // deliver all bathes up to the height `min(h, finalized_height)`.
    max_batch_height_to_deliver: Option<Height>,
    result_processor: Option<&dyn Fn(&Result<(), MessageRoutingError>, BlockStats, BatchStats)>,
) -> Result<Height, MessageRoutingError> {
    let finalized_height = pool.get_finalized_height();
    // If `max_batch_height_to_deliver` is specified and smaller than
    // `finalized_height`, we use it, otherwise we use `finalized_height`.
    let target_height = max_batch_height_to_deliver
        .unwrap_or(finalized_height)
        .min(finalized_height);

    let mut height = message_routing.expected_batch_height();
    if height == Height::from(0) {
        return Ok(Height::from(0));
    }
    let mut last_delivered_batch_height = height.decrement();
    while height <= target_height {
        let Some(block) = pool.get_finalized_block(height) else {
            warn!(
                every_n_seconds => 30,
                log,
                "Do not deliver height {} because no finalized block was found. \
                This should indicate we are waiting for state sync. \
                Finalized height: {}",
                height,
                finalized_height
            );
            break;
        };
        let Some(tape) = pool.get_random_tape(height) else {
            // Do not deliver batch if we don't have random tape
            warn!(
                every_n_seconds => 30,
                log,
                "Do not deliver height {} because RandomTape is not ready. Will re-try later",
                height
            );
            break;
        };
        debug!(
            every_n_seconds => 5,
            log,
            "Finalized height";
            consensus => ConsensusLogEntry {
                height: Some(height.get()),
                hash: Some(get_block_hash_string(&block)),
                replica_version: Some(String::from(current_replica_version.clone()))
            }
        );

        if block.payload.is_summary() {
            info!(
                log,
                "Delivering finalized batch at CUP height of {}", height
            );
        }
        // When we are not delivering CUP block, we must check if the subnet is halted.
        else {
            match status::get_status(height, registry_client, subnet_id, pool, log) {
                Some(Status::Halting | Status::Halted) => {
                    debug!(
                        every_n_seconds => 5,
                        log,
                        "Batch of height {} is not delivered because replica is halted",
                        height,
                    );
                    return Ok(last_delivered_batch_height);
                }
                Some(Status::Running) => {}
                None => {
                    warn!(
                        log,
                        "Skipping batch delivery because checking if replica is halted failed",
                    );
                    return Ok(last_delivered_batch_height);
                }
            }
        }

        let randomness = Randomness::from(crypto_hashable_to_seed(&tape));

        let idkg_subnet_public_keys = match get_idkg_subnet_public_keys(&block, pool, log) {
            Ok(keys) => keys,
            Err(e) => {
                // Do not deliver batch if we can't find a previous summary block,
                // this means we should continue with the latest CUP.
                warn!(
                    every_n_seconds => 5,
                    log,
                    "Do not deliver height {:?}: {}", height, e
                );
                return Ok(last_delivered_batch_height);
            }
        };

        let block_stats = BlockStats::from(&block);
        let mut batch_stats = BatchStats::new(height);

        // Compute consensus' responses to subnet calls.
        let consensus_responses = generate_responses_to_subnet_calls(&block, &mut batch_stats, log);

        // This flag can only be true, if we've called deliver_batches with a height
        // limit.  In this case we also want to have a checkpoint for that last height.
        let persist_batch = Some(height) == max_batch_height_to_deliver;
        let requires_full_state_hash = block.payload.is_summary() || persist_batch;
        let batch_messages = if block.payload.is_summary() {
            BatchMessages::default()
        } else {
            let batch_payload = &block.payload.as_ref().as_data().batch;
            batch_stats.add_from_payload(batch_payload);
            batch_payload
                .clone()
                .into_messages()
                .map_err(|err| {
                    error!(log, "batch payload deserialization failed: {:?}", err);
                    err
                })
                .unwrap_or_default()
        };

        let Some(previous_beacon) = pool.get_random_beacon(last_delivered_batch_height) else {
            warn!(
                every_n_seconds => 5,
                log,
                "No batch delivery at height {}: no random beacon found.",
                height
            );
            return Ok(last_delivered_batch_height);
        };
        let blockmaker_ranking = match membership.get_shuffled_nodes(
            block.height,
            &previous_beacon,
            &ic_crypto_prng::RandomnessPurpose::BlockmakerRanking,
        ) {
            Ok(nodes) => nodes,
            Err(e) => {
                warn!(
                    every_n_seconds => 5,
                    log,
                    "No batch delivery at height {}: membership error: {:?}",
                    height,
                    e
                );
                return Ok(last_delivered_batch_height);
            }
        };
        let blockmaker_metrics = BlockmakerMetrics {
            blockmaker: blockmaker_ranking[block.rank.0 as usize],
            failed_blockmakers: blockmaker_ranking[0..(block.rank.0 as usize)].to_vec(),
        };

        let Some(summary_block) = pool.dkg_summary_block_for_finalized_height(height) else {
            warn!(
                every_n_seconds => 30,
                log,
                "Do not deliver height {} because no summary block was found. \
                Finalized height: {}",
                height,
                finalized_height
            );
            break;
        };
        let dkg_summary = &summary_block.payload.as_ref().as_summary().dkg;
        let next_checkpoint_height = dkg_summary.get_next_start_height();
        let current_interval_length = dkg_summary.interval_length;
        let batch = Batch {
            batch_number: height,
            batch_summary: Some(BatchSummary {
                next_checkpoint_height,
                current_interval_length,
            }),
            requires_full_state_hash,
            messages: batch_messages,
            randomness,
            idkg_subnet_public_keys,
            idkg_pre_signature_ids: get_pre_signature_ids_to_deliver(&block),
            registry_version: block.context.registry_version,
            time: block.context.time,
            consensus_responses,
            blockmaker_metrics,
        };

        debug!(
            log,
            "replica {:?} delivered batch {:?} for block_hash {:?}",
            current_replica_version,
            batch_stats.batch_height,
            block_stats.block_hash
        );
        let result = message_routing.deliver_batch(batch);
        if let Some(f) = result_processor {
            f(&result, block_stats, batch_stats);
        }
        if let Err(err) = result {
            warn!(every_n_seconds => 5, log, "Batch delivery failed: {:?}", err);
            return Err(err);
        }
        last_delivered_batch_height = height;
        height = height.increment();
    }
    Ok(last_delivered_batch_height)
}

/// This function creates responses to the system calls that are redirected to
/// consensus. There are two types of calls being handled here:
/// - Initial NiDKG transcript creation, where a response may come from summary payloads.
/// - Canister threshold signature creation, where a response may come from from data payloads.
/// - CanisterHttpResponse handling, where a response to a canister http request may come from data payloads.
pub fn generate_responses_to_subnet_calls(
    block: &Block,
    stats: &mut BatchStats,
    log: &ReplicaLogger,
) -> Vec<ConsensusResponse> {
    let mut consensus_responses = Vec::new();
    let block_payload = &block.payload;
    if block_payload.is_summary() {
        let summary = block_payload.as_ref().as_summary();
        info!(
            log,
            "New DKG summary with config ids created: {:?}",
            summary.dkg.configs.keys().collect::<Vec<_>>()
        );
        consensus_responses.append(&mut generate_responses_to_setup_initial_dkg_calls(
            &summary.dkg.transcripts_for_new_subnets_with_callback_ids,
            log,
        ))
    } else {
        let block_payload = block_payload.as_ref().as_data();
        if let Some(payload) = &block_payload.idkg {
            consensus_responses.append(&mut generate_responses_to_signature_request_contexts(
                payload,
            ));
            consensus_responses.append(&mut generate_responses_to_initial_dealings_calls(payload));
        }

        let (mut http_responses, http_stats) =
            CanisterHttpPayloadBuilderImpl::into_messages(&block_payload.batch.canister_http);
        consensus_responses.append(&mut http_responses);
        stats.canister_http = http_stats;
    }
    consensus_responses
}

struct TranscriptResults {
    low_threshold: Option<Result<NiDkgTranscript, String>>,
    high_threshold: Option<Result<NiDkgTranscript, String>>,
}

/// This function creates responses to the SetupInitialDKG system calls with the
/// computed DKG key material for remote subnets, without needing values from the state.
pub fn generate_responses_to_setup_initial_dkg_calls(
    transcripts_for_new_subnets: &[(NiDkgId, CallbackId, Result<NiDkgTranscript, String>)],
    log: &ReplicaLogger,
) -> Vec<ConsensusResponse> {
    let mut consensus_responses = Vec::new();

    let mut transcripts: BTreeMap<CallbackId, TranscriptResults> = BTreeMap::new();

    for (id, callback_id, transcript) in transcripts_for_new_subnets.iter() {
        let add_transcript = |transcript_results: &mut TranscriptResults| {
            let value = Some(transcript.clone());
            match id.dkg_tag {
                NiDkgTag::LowThreshold => {
                    if transcript_results.low_threshold.is_some() {
                        error!(
                            log,
                            "Multiple low threshold transcripts for {}", callback_id
                        );
                    }
                    transcript_results.low_threshold = value;
                }
                NiDkgTag::HighThreshold => {
                    if transcript_results.high_threshold.is_some() {
                        error!(
                            log,
                            "Multiple high threshold transcripts for {}", callback_id
                        );
                    }
                    transcript_results.high_threshold = value;
                }
            }
        };
        match transcripts.get_mut(callback_id) {
            Some(existing) => add_transcript(existing),
            None => {
                let mut transcript_results = TranscriptResults {
                    low_threshold: None,
                    high_threshold: None,
                };
                add_transcript(&mut transcript_results);
                transcripts.insert(*callback_id, transcript_results);
            }
        };
    }

    for (callback, transcript_results) in transcripts.into_iter() {
        let payload = generate_dkg_response_payload(
            transcript_results.low_threshold.as_ref(),
            transcript_results.high_threshold.as_ref(),
            log,
        );
        if let Some(payload) = payload {
            consensus_responses.push(ConsensusResponse::new(callback, payload));
        }
    }
    consensus_responses
}

/// Generate a response payload given the low and high threshold transcripts
fn generate_dkg_response_payload(
    low_threshold: Option<&Result<NiDkgTranscript, String>>,
    high_threshold: Option<&Result<NiDkgTranscript, String>>,
    log: &ReplicaLogger,
) -> Option<Payload> {
    match (low_threshold, high_threshold) {
        (Some(Ok(low_threshold_transcript)), Some(Ok(high_threshold_transcript))) => {
            info!(
                log,
                "Found transcripts for another subnet with ids {:?} and {:?}",
                low_threshold_transcript.dkg_id,
                high_threshold_transcript.dkg_id
            );
            let low_threshold_transcript_record =
                InitialNiDkgTranscriptRecord::from(low_threshold_transcript.clone());
            let high_threshold_transcript_record =
                InitialNiDkgTranscriptRecord::from(high_threshold_transcript.clone());

            let threshold_sig_pk = match ThresholdSigPublicKey::try_from(high_threshold_transcript)
            {
                Ok(key) => key,
                Err(err) => {
                    return Some(Payload::Reject(RejectContext::new(
                        ic_error_types::RejectCode::CanisterReject,
                        format!(
                            "Failed to extract public key from high threshold transcript with id {:?}: {}",
                            high_threshold_transcript.dkg_id,
                            err,
                        ),
                    )))
                }
            };
            let subnet_threshold_public_key = PublicKeyProto::from(threshold_sig_pk);
            let key_der = match ic_crypto_utils_threshold_sig_der::threshold_sig_public_key_to_der(
                threshold_sig_pk,
            ) {
                Ok(key) => key,
                Err(err) => {
                    return Some(Payload::Reject(RejectContext::new(
                        ic_error_types::RejectCode::CanisterReject,
                        format!(
                            "Failed to encode threshold signature public key of transcript id {:?} into DER: {}",
                            high_threshold_transcript.dkg_id,
                            err,
                        ),
                    )))
                }
            };
            let fresh_subnet_id =
                SubnetId::new(PrincipalId::new_self_authenticating(key_der.as_slice()));

            let initial_transcript_records = SetupInitialDKGResponse {
                low_threshold_transcript_record,
                high_threshold_transcript_record,
                fresh_subnet_id,
                subnet_threshold_public_key,
            };

            Some(Payload::Data(initial_transcript_records.encode()))
        }
        (Some(Err(err_str1)), Some(Err(err_str2))) => Some(Payload::Reject(RejectContext::new(
            ic_error_types::RejectCode::CanisterReject,
            format!("{}{}", err_str1, err_str2),
        ))),
        (Some(Err(err_str)), _) | (_, Some(Err(err_str))) => Some(Payload::Reject(
            RejectContext::new(ic_error_types::RejectCode::CanisterReject, err_str),
        )),
        _ => None,
    }
}

/// Creates responses to `SignWithECDSA` and `SignWithSchnorr` system calls with the computed
/// signature.
pub fn generate_responses_to_signature_request_contexts(
    idkg_payload: &idkg::IDkgPayload,
) -> Vec<ConsensusResponse> {
    let mut consensus_responses = Vec::new();
    for completed in idkg_payload.signature_agreements.values() {
        if let CompletedSignature::Unreported(response) = completed {
            consensus_responses.push(response.clone());
        }
    }
    consensus_responses
}

/// Creates responses to `ComputeInitialIDkgDealingsArgs` system calls with the initial
/// dealings.
fn generate_responses_to_initial_dealings_calls(
    idkg_payload: &idkg::IDkgPayload,
) -> Vec<ConsensusResponse> {
    let mut consensus_responses = Vec::new();
    for agreement in idkg_payload.xnet_reshare_agreements.values() {
        if let idkg::CompletedReshareRequest::Unreported(response) = agreement {
            consensus_responses.push(response.clone());
        }
    }
    consensus_responses
}
