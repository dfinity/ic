//! This module contains the batch delivery logic: crafting of batches from
//! selections of ingress and xnet messages, and DKGs computed for other
//! subnets.

use crate::consensus::{
    metrics::{BatchStats, BlockStats},
    status::{self, Status},
};
use ic_consensus_dkg::get_vetkey_public_keys;
use ic_consensus_idkg::utils::{
    generate_responses_to_signature_request_contexts,
    get_idkg_subnet_public_keys_and_pre_signatures,
};
use ic_consensus_utils::{
    crypto_hashable_to_seed, membership::Membership, pool_reader::PoolReader,
};
use ic_consensus_vetkd::VetKdPayloadBuilderImpl;
use ic_error_types::RejectCode;
use ic_https_outcalls_consensus::payload_builder::CanisterHttpPayloadBuilderImpl;
use ic_interfaces::{
    batch_payload::IntoMessages,
    messaging::{MessageRouting, MessageRoutingError},
};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{ReplicaLogger, debug, error, info, warn};
use ic_management_canister_types_private::{ReshareChainKeyResponse, SetupInitialDKGResponse};
use ic_protobuf::{
    log::consensus_log_entry::v1::ConsensusLogEntry,
    registry::{crypto::v1::PublicKey as PublicKeyProto, subnet::v1::InitialNiDkgTranscriptRecord},
};
use ic_types::{
    Height, PrincipalId, Randomness, SubnetId,
    batch::{
        Batch, BatchContent, BatchMessages, BatchSummary, BlockmakerMetrics, ChainKeyData,
        ConsensusResponse,
    },
    consensus::{
        Block, BlockPayload, HasVersion,
        idkg::{self},
    },
    crypto::threshold_sig::{
        ThresholdSigPublicKey,
        ni_dkg::{NiDkgId, NiDkgTag, NiDkgTranscript},
    },
    messages::{CallbackId, Payload, RejectContext},
};
use std::collections::BTreeMap;

/// Deliver all finalized blocks from
/// `message_routing.expected_batch_height` to `finalized_height` via
/// `MessageRouting` and return the last delivered batch height.
pub fn deliver_batches(
    message_routing: &dyn MessageRouting,
    membership: &Membership,
    pool: &PoolReader<'_>,
    registry_client: &dyn RegistryClient,
    subnet_id: SubnetId,
    log: &ReplicaLogger,
    // This argument should only be used by the ic-replay tool. If it is set to `None`, we will
    // deliver all batches until the finalized height. If it is set to `Some(h)`, we will
    // deliver all bathes up to the height `min(h, finalized_height)`.
    max_batch_height_to_deliver: Option<Height>,
) -> Result<Height, MessageRoutingError> {
    deliver_batches_with_result_processor(
        message_routing,
        membership,
        pool,
        registry_client,
        subnet_id,
        log,
        max_batch_height_to_deliver,
        /*result_processor=*/ None,
    )
}

/// Deliver all finalized blocks from
/// `message_routing.expected_batch_height` to `finalized_height` via
/// `MessageRouting` and return the last delivered batch height.
#[allow(clippy::type_complexity)]
pub(crate) fn deliver_batches_with_result_processor(
    message_routing: &dyn MessageRouting,
    membership: &Membership,
    pool: &PoolReader<'_>,
    registry_client: &dyn RegistryClient,
    subnet_id: SubnetId,
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
        let replica_version = block.version().clone();
        let mut block_stats = BlockStats::from(&block);
        debug!(
            every_n_seconds => 5,
            log,
            "Finalized height";
            consensus => ConsensusLogEntry {
                height: Some(height.get()),
                hash: Some(block_stats.block_hash.clone()),
                replica_version: Some(String::from(&replica_version))
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

        // Retrieve the dkg summary block
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

        let mut chain_key_subnet_public_keys = BTreeMap::new();
        let (mut idkg_subnet_public_keys, idkg_pre_signatures) =
            get_idkg_subnet_public_keys_and_pre_signatures(
                &block,
                &summary_block,
                pool,
                log,
                block_stats.idkg_stats.as_mut(),
            );
        chain_key_subnet_public_keys.append(&mut idkg_subnet_public_keys);

        // Add vetKD keys to this map as well
        let (mut nidkg_subnet_public_keys, nidkg_ids) = get_vetkey_public_keys(dkg_summary, log);
        chain_key_subnet_public_keys.append(&mut nidkg_subnet_public_keys);

        // If the subnet contains chain keys, log them on every summary block
        if !chain_key_subnet_public_keys.is_empty() && block.payload.is_summary() {
            info!(
                log,
                "Subnet {} contains chain keys: {:?}", subnet_id, chain_key_subnet_public_keys
            );
        }

        let mut batch_stats = BatchStats::new(height);

        let chain_key_data = ChainKeyData {
            master_public_keys: chain_key_subnet_public_keys,
            idkg_pre_signatures,
            nidkg_ids,
        };
        let consensus_responses = generate_responses_to_subnet_calls(&block, &mut batch_stats, log);
        // This flag can only be true, if we've called deliver_batches with a height
        // limit.  In this case we also want to have a checkpoint for that last height.
        let persist_batch = Some(height) == max_batch_height_to_deliver;
        let requires_full_state_hash = block.payload.is_summary() || persist_batch;
        let batch_content = match block.payload.as_ref() {
            BlockPayload::Summary(_summary_payload) => BatchContent::Data {
                batch_messages: BatchMessages::default(),
                chain_key_data,
                consensus_responses,
                requires_full_state_hash,
            },
            BlockPayload::Data(data_payload) => {
                batch_stats.add_from_payload(&data_payload.batch);
                BatchContent::Data {
                    batch_messages: data_payload
                        .batch
                        .clone()
                        .into_messages()
                        .map_err(|err| {
                            error!(log, "batch payload deserialization failed: {:?}", err);
                            err
                        })
                        .unwrap_or_default(),
                    chain_key_data,
                    consensus_responses,
                    requires_full_state_hash,
                }
            }
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

        let next_checkpoint_height = dkg_summary.get_next_start_height();
        let current_interval_length = dkg_summary.interval_length;
        let batch = Batch {
            batch_number: height,
            batch_summary: Some(BatchSummary {
                next_checkpoint_height,
                current_interval_length,
            }),
            content: batch_content,
            randomness,

            registry_version: block.context.registry_version,
            time: block.context.time,
            blockmaker_metrics,
            replica_version,
        };

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
fn generate_responses_to_subnet_calls(
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
        consensus_responses.append(&mut generate_responses_to_remote_dkgs(
            &summary.dkg.transcripts_for_remote_subnets,
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

        let mut vetkd_responses =
            VetKdPayloadBuilderImpl::into_messages(&block_payload.batch.vetkd);
        consensus_responses.append(&mut vetkd_responses);
    }
    consensus_responses
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RemoteDkgResults {
    ReshareChainKey(Result<NiDkgTranscript, String>),
    SetupInitialDKG {
        low_threshold: Option<Result<NiDkgTranscript, String>>,
        high_threshold: Option<Result<NiDkgTranscript, String>>,
    },
}

impl RemoteDkgResults {
    fn new(id: &NiDkgId, transcript: Result<NiDkgTranscript, String>) -> Self {
        match id.dkg_tag {
            NiDkgTag::LowThreshold => Self::SetupInitialDKG {
                low_threshold: Some(transcript),
                high_threshold: None,
            },
            NiDkgTag::HighThreshold => Self::SetupInitialDKG {
                low_threshold: None,
                high_threshold: Some(transcript),
            },
            NiDkgTag::HighThresholdForKey(_) => Self::ReshareChainKey(transcript),
        }
    }

    fn add_transcript(
        &mut self,
        id: &NiDkgId,
        transcript: Result<NiDkgTranscript, String>,
        logger: &ReplicaLogger,
    ) {
        let Self::SetupInitialDKG {
            low_threshold,
            high_threshold,
        } = self
        else {
            error!(
                logger,
                "Cannot add a second transcript to a ReshareChainKey transcript: {id}"
            );
            return;
        };

        let old_val = match id.dkg_tag {
            NiDkgTag::LowThreshold => low_threshold.replace(transcript),
            NiDkgTag::HighThreshold => high_threshold.replace(transcript),
            NiDkgTag::HighThresholdForKey(_) => {
                error!(
                    logger,
                    "Cannot add a ReshareChainKey transcript to a SetupInitialDKG request: {id}"
                );
                return;
            }
        };

        if old_val.is_some() {
            error!(
                logger,
                "Received a duplicate transcript for SetupInitialDKG request: {id}"
            );
        }
    }
}

/// This function creates responses to finished remote DKGs
///
/// Responses can either be information about a failed DKG or contain the DKG transcript(s)
/// necessary to complete the request.
///
/// The responses generate by this function are:
/// - Responses to `setup_initial_dkg` system calls
/// - Responses to `reshare_chain_key`, if the requested key is a NiDkg key
fn generate_responses_to_remote_dkgs(
    transcripts_for_remote_subnets: &[(NiDkgId, CallbackId, Result<NiDkgTranscript, String>)],
    log: &ReplicaLogger,
) -> Vec<ConsensusResponse> {
    let mut dkg_results: BTreeMap<CallbackId, RemoteDkgResults> = BTreeMap::new();
    for (id, callback_id, transcript) in transcripts_for_remote_subnets.iter() {
        dkg_results
            .entry(*callback_id)
            .and_modify(|transcript_result| {
                transcript_result.add_transcript(id, transcript.clone(), log)
            })
            .or_insert_with(|| RemoteDkgResults::new(id, transcript.clone()));
    }

    dkg_results
        .into_iter()
        .filter_map(|(callback_id, transcript_result)| {
            match transcript_result {
                RemoteDkgResults::ReshareChainKey(key_transcript) => {
                    Some(generate_reshare_chain_key_response(key_transcript))
                }
                RemoteDkgResults::SetupInitialDKG {
                    low_threshold,
                    high_threshold,
                } => generate_dkg_response_payload(
                    low_threshold.as_ref(),
                    high_threshold.as_ref(),
                    log,
                ),
            }
            .map(|payload| ConsensusResponse::new(callback_id, payload))
        })
        .collect()
}

fn generate_reshare_chain_key_response(key_transcript: Result<NiDkgTranscript, String>) -> Payload {
    match key_transcript {
        Ok(transcript) => Payload::Data(ReshareChainKeyResponse::NiDkg(transcript.into()).encode()),
        Err(err) => Payload::Reject(RejectContext::new(RejectCode::CanisterReject, err)),
    }
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
                        RejectCode::CanisterReject,
                        format!(
                            "Failed to extract public key from high threshold transcript with id {:?}: {}",
                            high_threshold_transcript.dkg_id, err,
                        ),
                    )));
                }
            };
            let subnet_threshold_public_key = PublicKeyProto::from(threshold_sig_pk);
            let key_der = match ic_crypto_utils_threshold_sig_der::threshold_sig_public_key_to_der(
                threshold_sig_pk,
            ) {
                Ok(key) => key,
                Err(err) => {
                    return Some(Payload::Reject(RejectContext::new(
                        RejectCode::CanisterReject,
                        format!(
                            "Failed to encode threshold signature public key of transcript id {:?} into DER: {}",
                            high_threshold_transcript.dkg_id, err,
                        ),
                    )));
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
            RejectCode::CanisterReject,
            format!("{err_str1}{err_str2}"),
        ))),
        (Some(Err(err_str)), _) | (_, Some(Err(err_str))) => Some(Payload::Reject(
            RejectContext::new(RejectCode::CanisterReject, err_str),
        )),
        _ => None,
    }
}

/// Creates responses to `ReshareChainKeyArgs` system calls with the initial
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

#[cfg(test)]
mod tests {
    //! Finalizer unit tests
    use super::*;
    use crate::consensus::batch_delivery::generate_responses_to_remote_dkgs;
    use ic_crypto_test_utils_ni_dkg::dummy_transcript_for_tests;
    use ic_logger::replica_logger::no_op_logger;
    use ic_management_canister_types_private::{SetupInitialDKGResponse, VetKdCurve, VetKdKeyId};
    use ic_test_utilities_types::ids::subnet_test_id;
    use ic_types::{
        PrincipalId, SubnetId,
        crypto::threshold_sig::ni_dkg::{
            NiDkgId, NiDkgMasterPublicKeyId, NiDkgTag, NiDkgTargetId, NiDkgTargetSubnet,
        },
        messages::{CallbackId, Payload},
    };
    use std::str::FromStr;

    #[test]
    fn test_generate_setup_initial_dkg_response() {
        const TARGET_ID: NiDkgTargetId = NiDkgTargetId::new([8; 32]);

        // Build some transcipts with matching ids and tags
        let transcripts_for_remote_subnets = vec![
            (
                NiDkgId {
                    start_block_height: Height::from(0),
                    dealer_subnet: subnet_test_id(0),
                    dkg_tag: NiDkgTag::LowThreshold,
                    target_subnet: NiDkgTargetSubnet::Remote(TARGET_ID),
                },
                CallbackId::from(1),
                Ok(dummy_transcript_for_tests()),
            ),
            (
                NiDkgId {
                    start_block_height: Height::from(0),
                    dealer_subnet: subnet_test_id(0),
                    dkg_tag: NiDkgTag::HighThreshold,
                    target_subnet: NiDkgTargetSubnet::Remote(TARGET_ID),
                },
                CallbackId::from(1),
                Ok(dummy_transcript_for_tests()),
            ),
        ];

        let result =
            generate_responses_to_remote_dkgs(&transcripts_for_remote_subnets[..], &no_op_logger());
        assert_eq!(result.len(), 1);

        // Deserialize the `SetupInitialDKGResponse` and check the subnet id
        let payload = match &result[0].payload {
            Payload::Data(data) => data,
            Payload::Reject(_) => panic!("Payload was rejected unexpectedly"),
        };
        let initial_transcript_records = SetupInitialDKGResponse::decode(payload).unwrap();
        assert_eq!(
            initial_transcript_records.fresh_subnet_id,
            SubnetId::from(
                PrincipalId::from_str(
                    "icdrs-3sfmz-hm6r3-cdzf5-cfroa-3cddh-aght7-azz25-eo34b-4strl-wae"
                )
                .unwrap()
            )
        );
    }

    #[test]
    fn test_generate_request_chain_key_nidkg_response() {
        const TARGET_ID: NiDkgTargetId = NiDkgTargetId::new([8; 32]);

        let key_id: NiDkgMasterPublicKeyId = NiDkgMasterPublicKeyId::VetKd(VetKdKeyId {
            curve: VetKdCurve::Bls12_381_G2,
            name: String::from("test_vetkd_key"),
        });

        // Build some transcipts with matching ids and tags
        let transcripts_for_remote_subnets = vec![(
            NiDkgId {
                start_block_height: Height::from(0),
                dealer_subnet: subnet_test_id(0),
                dkg_tag: NiDkgTag::HighThresholdForKey(key_id.clone()),
                target_subnet: NiDkgTargetSubnet::Remote(TARGET_ID),
            },
            CallbackId::from(2),
            Ok(dummy_transcript_for_tests()),
        )];

        let result =
            generate_responses_to_remote_dkgs(&transcripts_for_remote_subnets[..], &no_op_logger());
        assert_eq!(result.len(), 1);

        // Deserialize the `ReshareChainKeyResponse`
        let payload = match &result[0].payload {
            Payload::Data(data) => data,
            Payload::Reject(_) => panic!("Payload was rejected unexpectedly"),
        };
        let response = ReshareChainKeyResponse::decode(payload).unwrap();
        let ReshareChainKeyResponse::NiDkg(_response) = response else {
            panic!("Expected a NiDkg response");
        };
    }
}
