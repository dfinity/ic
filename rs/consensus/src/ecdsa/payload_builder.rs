//! This module implements the ECDSA payload builder and verifier.
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::enum_variant_names)]

use crate::consensus::{crypto::ConsensusCrypto, pool_reader::PoolReader};
use ic_interfaces::{
    ecdsa::EcdsaPool,
    registry::RegistryClient,
    state_manager::{StateManager, StateManagerError},
};
use ic_logger::{warn, ReplicaLogger};
use ic_protobuf::registry::subnet::v1::EcdsaConfig;
use ic_registry_client::helper::subnet::SubnetRegistry;
use ic_replicated_state::{metadata_state::subnet_call_context_manager::*, ReplicatedState};
use ic_types::{
    batch::ValidationContext,
    consensus::{ecdsa, Block, HasHeight, SummaryPayload},
    crypto::{
        canister_threshold_sig::{
            error::{IDkgParamsValidationError, PresignatureQuadrupleCreationError},
            idkg::{
                IDkgDealers, IDkgReceivers, IDkgTranscriptId, IDkgTranscriptOperation,
                IDkgTranscriptParams,
            },
            PreSignatureQuadruple, ThresholdEcdsaSigInputs,
        },
        AlgorithmId,
    },
    registry::RegistryClientError,
    Height, NodeId, RegistryVersion, SubnetId,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub enum EcdsaPayloadError {
    RegistryClientError(RegistryClientError),
    StateManagerError(StateManagerError),
    PreSignatureError(PresignatureQuadrupleCreationError),
    IDkgParamsValidationError(IDkgParamsValidationError),
    OtherError(String),
}

impl From<RegistryClientError> for EcdsaPayloadError {
    fn from(err: RegistryClientError) -> Self {
        EcdsaPayloadError::RegistryClientError(err)
    }
}

impl From<StateManagerError> for EcdsaPayloadError {
    fn from(err: StateManagerError) -> Self {
        EcdsaPayloadError::StateManagerError(err)
    }
}

impl From<PresignatureQuadrupleCreationError> for EcdsaPayloadError {
    fn from(err: PresignatureQuadrupleCreationError) -> Self {
        EcdsaPayloadError::PreSignatureError(err)
    }
}

impl From<IDkgParamsValidationError> for EcdsaPayloadError {
    fn from(err: IDkgParamsValidationError) -> Self {
        EcdsaPayloadError::IDkgParamsValidationError(err)
    }
}

/// Creates a threshold ECDSA summary payload.
pub fn create_summary_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    crypto: &dyn ConsensusCrypto,
    pool_reader: &PoolReader<'_>,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    context: &ValidationContext,
    parent_block: &Block,
    log: ReplicaLogger,
) -> Result<ecdsa::Summary, EcdsaPayloadError> {
    let height = parent_block.height().increment();
    match &parent_block.payload.as_ref().as_data().ecdsa {
        None => Ok(None),
        Some(payload) => {
            // Produce summary payload from the previous batch payload and summary block.
            let previous_summary_block = pool_reader
                .dkg_summary_block(parent_block)
                .ok_or_else(|| {
                    warn!(
                        log,
                        "Fail to find the summary block that governs height {}. This should not happen!",
                        parent_block.height()
                    );
                    EcdsaPayloadError::OtherError("Fail to find summary block".to_string())
                })?;
            let previous_summary = previous_summary_block
                .payload
                .as_ref()
                .as_summary()
                .ecdsa
                .as_ref()
                .unwrap_or_else(|| {
                    panic!("ECDSA payload exists but previous summary is not found")
                });
            let summary = ecdsa::EcdsaSummaryPayload {
                current_ecdsa_transcript: previous_summary.next_ecdsa_transcript.clone(),
                next_ecdsa_transcript: get_ecdsa_transcript(payload),
                ongoing_signatures: payload.ongoing_signatures.clone(),
                // TODO: carrying over available_quadruples is assuming unchanged
                // membership. This problem has to be addressed when membership changes.
                available_quadruples: payload.available_quadruples.clone(),
                next_unused_transcript_id: payload.next_unused_transcript_id,
            };
            Ok(Some(summary))
        }
    }
}

fn get_registry_version_and_subnet_nodes_from_summary(
    summary: &SummaryPayload,
    registry_client: &dyn RegistryClient,
    subnet_id: SubnetId,
) -> Result<(RegistryVersion, Vec<NodeId>), EcdsaPayloadError> {
    let summary_registry_version = summary.dkg.registry_version;
    // TODO: shuffle the nodes using random beacon?
    let subnet_nodes = registry_client
        .get_node_ids_on_subnet(subnet_id, summary_registry_version)?
        .ok_or_else(|| {
            EcdsaPayloadError::OtherError(format!(
                "Subnet {} has empty node ids in registry version {}",
                subnet_id, summary_registry_version
            ))
        })?;
    Ok((summary_registry_version, subnet_nodes))
}

/// Creates a threshold ECDSA batch payload.
pub fn create_data_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    crypto: &dyn ConsensusCrypto,
    pool_reader: &PoolReader<'_>,
    ecdsa_pool: &dyn EcdsaPool,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    context: &ValidationContext,
    parent_block: &Block,
    log: ReplicaLogger,
) -> Result<ecdsa::Payload, EcdsaPayloadError> {
    let height = parent_block.height().increment();
    let block_payload = &parent_block.payload.as_ref();
    if block_payload.is_summary() {
        let summary = block_payload.as_summary();
        match &summary.ecdsa {
            None => Ok(None),
            Some(ecdsa_summary) => {
                let (summary_registry_version, node_ids) =
                    get_registry_version_and_subnet_nodes_from_summary(
                        summary,
                        registry_client,
                        subnet_id,
                    )?;
                let ecdsa_config = registry_client
                    .get_ecdsa_config(subnet_id, summary_registry_version)?
                    .unwrap_or_default();
                let mut next_unused_transcript_id = ecdsa_summary.next_unused_transcript_id;
                let quadruples_in_creation = next_quadruples_in_creation(
                    &node_ids,
                    summary_registry_version,
                    ecdsa_summary,
                    ecdsa_config.as_ref(),
                    &mut next_unused_transcript_id,
                )?;
                let payload = ecdsa::EcdsaDataPayload {
                    signature_agreements: BTreeMap::new(),
                    ongoing_signatures: ecdsa_summary.ongoing_signatures.clone(),
                    available_quadruples: ecdsa_summary.available_quadruples.clone(),
                    quadruples_in_creation,
                    next_unused_transcript_id,
                };
                Ok(Some(payload))
            }
        }
    } else {
        match &block_payload.as_data().ecdsa {
            None => Ok(None),
            Some(prev_payload) => {
                let summary_block =
                    pool_reader
                        .dkg_summary_block(parent_block)
                        .unwrap_or_else(|| {
                            panic!(
                                "Impossible: fail to the summary block that governs height {}",
                                parent_block.height()
                            )
                        });
                let summary = summary_block.payload.as_ref().as_summary();
                let ecdsa_summary = summary.ecdsa.as_ref().unwrap_or_else(|| {
                    panic!("ecdsa payload exists but previous summary is not found")
                });
                let (summary_registry_version, node_ids) =
                    get_registry_version_and_subnet_nodes_from_summary(
                        summary,
                        registry_client,
                        subnet_id,
                    )?;
                let mut payload = prev_payload.clone();
                let count =
                    update_signing_requests(log, ecdsa_pool, state_manager, context, &mut payload)?;
                // quadruples are consumed, need to produce more
                let quadruple_id = payload
                    .available_quadruples
                    .keys()
                    .last()
                    .cloned()
                    .unwrap_or_default();
                start_making_new_quadruples(
                    count,
                    &node_ids,
                    summary_registry_version,
                    &mut payload.next_unused_transcript_id,
                    &mut payload.quadruples_in_creation,
                    quadruple_id,
                )?;
                update_quadruples_in_creation(ecdsa_summary, &mut payload, ecdsa_pool)?;
                Ok(Some(payload))
            }
        }
    }
}

/// Look for the latest reshared ECDSA transcript in an EcdsaDataPayload.
fn get_ecdsa_transcript(payload: &ecdsa::EcdsaDataPayload) -> Option<ecdsa::UnmaskedTranscript> {
    todo!()
}

/// Create a new random transcript config and advance the
/// next_unused_transcript_id by one.
fn new_random_config(
    subnet_nodes: &[NodeId],
    summary_registry_version: RegistryVersion,
    next_unused_transcript_id: &mut IDkgTranscriptId,
) -> Result<ecdsa::RandomTranscriptParams, EcdsaPayloadError> {
    let transcript_id = *next_unused_transcript_id;
    *next_unused_transcript_id = transcript_id.increment();
    let dealers = IDkgDealers::new(subnet_nodes.iter().copied().collect::<BTreeSet<_>>())?;
    let receivers = IDkgReceivers::new(subnet_nodes.iter().copied().collect::<BTreeSet<_>>())?;
    Ok(ecdsa::RandomTranscriptParams::new(
        transcript_id,
        dealers,
        receivers,
        summary_registry_version,
        AlgorithmId::EcdsaP256,
        IDkgTranscriptOperation::Random,
    )?)
}

/// Initialize the next set of quadruples with random configs from the summary
/// block, and return it together with the next transcript id.
fn next_quadruples_in_creation(
    subnet_nodes: &[NodeId],
    summary_registry_version: RegistryVersion,
    summary: &ecdsa::EcdsaSummaryPayload,
    ecdsa_config: Option<&EcdsaConfig>,
    next_unused_transcript_id: &mut IDkgTranscriptId,
) -> Result<BTreeMap<ecdsa::QuadrupleId, ecdsa::QuadrupleInCreation>, EcdsaPayloadError> {
    let quadruple_id = summary
        .available_quadruples
        .keys()
        .last()
        .cloned()
        .unwrap_or_default();
    let mut quadruples = BTreeMap::new();
    let num_quadruples = summary.available_quadruples.len();
    let mut to_create = ecdsa_config
        .map(|config| config.quadruples_to_create_in_advance as usize)
        .unwrap_or_default();
    if to_create > num_quadruples {
        to_create -= num_quadruples;
    } else {
        to_create = 0;
    }
    start_making_new_quadruples(
        to_create,
        subnet_nodes,
        summary_registry_version,
        next_unused_transcript_id,
        &mut quadruples,
        quadruple_id,
    )?;
    Ok(quadruples)
}

/// Start making the given number of new quadruples by adding them to
/// quadruples_in_creation.
fn start_making_new_quadruples(
    num_quadruples_to_create: usize,
    subnet_nodes: &[NodeId],
    summary_registry_version: RegistryVersion,
    next_unused_transcript_id: &mut IDkgTranscriptId,
    quadruples_in_creation: &mut BTreeMap<ecdsa::QuadrupleId, ecdsa::QuadrupleInCreation>,
    mut quadruple_id: ecdsa::QuadrupleId,
) -> Result<(), EcdsaPayloadError> {
    for _ in 0..num_quadruples_to_create {
        let kappa_config = new_random_config(
            subnet_nodes,
            summary_registry_version,
            next_unused_transcript_id,
        )?;
        let lambda_config = new_random_config(
            subnet_nodes,
            summary_registry_version,
            next_unused_transcript_id,
        )?;
        quadruples_in_creation.insert(
            quadruple_id,
            ecdsa::QuadrupleInCreation::new(kappa_config, lambda_config),
        );
        quadruple_id = quadruple_id.increment();
    }
    Ok(())
}

// Try to comibine signature shares in the ECDSA pool and return
// an interator of new full signatures constructed.
// TODO: also pass in signatures we are looking for to avoid traversing
// everything.
fn combine_signatures(
    ecdsa_pool: &dyn EcdsaPool,
) -> Box<dyn Iterator<Item = (ecdsa::RequestId, ecdsa::EcdsaSignature)>> {
    todo!()
}

/// Update data fields related to signing requests in the ECDSA payload:
///
/// - Check if new signatures have been produced, and add them to
/// signature agreements.
/// - Check if there are new signing requests, and start to work on them.
///
/// Return the number of new signing requests that are worked on (or
/// equivalently, the number of quadruples that are consumed).
fn update_signing_requests(
    log: ReplicaLogger,
    ecdsa_pool: &dyn EcdsaPool,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    context: &ValidationContext,
    payload: &mut ecdsa::EcdsaDataPayload,
) -> Result<usize, StateManagerError> {
    // Check if new signatures have been produced
    for (request_id, signature) in combine_signatures(ecdsa_pool) {
        if payload.ongoing_signatures.remove(&request_id).is_none() {
            warn!(
                log,
                "ECDSA signing request {:?} is not found in payload but we have a signature for it",
                request_id
            );
        } else {
            payload.signature_agreements.insert(request_id, signature);
        }
    }
    // Get the set of new signing requests that we have not signed, and are
    // not already working on.
    let existing_requests: BTreeSet<&ecdsa::RequestId> = payload
        .signature_agreements
        .keys()
        .chain(payload.ongoing_signatures.keys())
        .collect::<BTreeSet<_>>();
    let new_requests = get_new_signing_requests(
        state_manager,
        existing_requests,
        &mut payload.available_quadruples,
        context.certified_height,
    )?;
    let mut count = 0;
    for (request_id, sign_inputs) in new_requests {
        payload.ongoing_signatures.insert(request_id, sign_inputs);
        count += 1;
    }
    Ok(count)
}

// Return new signing requests initiated from canisters.
fn get_new_signing_requests(
    state_manager: &dyn StateManager<State = ReplicatedState>,
    existing_requests: BTreeSet<&ecdsa::RequestId>,
    available_quadruples: &mut BTreeMap<ecdsa::QuadrupleId, PreSignatureQuadruple>,
    height: Height,
) -> Result<Vec<(ecdsa::RequestId, ThresholdEcdsaSigInputs)>, StateManagerError> {
    let state = state_manager.get_state_at(height)?;
    let contexts = &state
        .get_ref()
        .metadata
        .subnet_call_context_manager
        .sign_with_ecdsa_contexts;
    let new_requests = contexts
        .iter()
        .filter_map(|(callback_id, context)| {
            let SignWithEcdsaContext {
                request,
                pseudo_random_id,
                message_hash,
                derivation_path,
                batch_time,
            } = context;
            // request_id is just pseudo_random_id which is guaranteed to be always unique.
            let request_id = ecdsa::RequestId::from(pseudo_random_id.to_vec());
            if !existing_requests.contains(&request_id) {
                Some((request_id, context))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let mut ret = Vec::new();
    let mut consumed_quadruples = Vec::new();
    for ((request_id, context), (quadruple_id, quadruple)) in
        new_requests.iter().zip(available_quadruples.iter())
    {
        let sign_inputs = build_sign_inputs(context, quadruple);
        ret.push((request_id.clone(), sign_inputs));
        consumed_quadruples.push(*quadruple_id);
    }

    for quadruple_id in consumed_quadruples {
        available_quadruples.remove(&quadruple_id);
    }
    Ok(ret)
}

/// Update the quadruples in the payload by:
/// - making new configs when pre-conditions are met;
/// - gathering ready results (new transcripts) from ecdsa pool; (TODO)
/// - moving completed quadruples from "in creation" to "available".
fn update_quadruples_in_creation(
    summary: &ecdsa::EcdsaSummaryPayload,
    payload: &mut ecdsa::EcdsaDataPayload,
    ecdsa_pool: &dyn EcdsaPool,
) -> Result<(), EcdsaPayloadError> {
    let ecdsa_transcript = summary.current_ecdsa_transcript.as_ref();
    let mut newly_available = Vec::new();
    for (key, quadruple) in payload.quadruples_in_creation.iter_mut() {
        // TODO: update quadruple results fields if they are ready in ecdsa pool.
        if let (Some(kappa_masked), None) =
            (&quadruple.kappa_masked, &quadruple.unmask_kappa_config)
        {
            let unmask_kappa_config = IDkgTranscriptParams::new(
                payload.next_unused_transcript_id,
                quadruple.kappa_config.dealers().clone(),
                quadruple.kappa_config.receivers().clone(),
                quadruple.kappa_config.registry_version(),
                quadruple.kappa_config.algorithm_id(),
                IDkgTranscriptOperation::ReshareOfMasked(kappa_masked.clone().into_base_type()),
            )?;
            payload.next_unused_transcript_id = payload.next_unused_transcript_id.increment();
        }
        if let (Some(lambda_masked), None, Some(transcript)) = (
            &quadruple.lambda_masked,
            &quadruple.key_times_lambda_config,
            ecdsa_transcript,
        ) {
            let key_times_lambda_config = IDkgTranscriptParams::new(
                payload.next_unused_transcript_id,
                quadruple.lambda_config.dealers().clone(),
                quadruple.lambda_config.receivers().clone(),
                quadruple.lambda_config.registry_version(),
                quadruple.lambda_config.algorithm_id(),
                IDkgTranscriptOperation::UnmaskedTimesMasked(
                    transcript.clone().into_base_type(),
                    lambda_masked.clone().into_base_type(),
                ),
            )?;
            payload.next_unused_transcript_id = payload.next_unused_transcript_id.increment();
        }
        if let (Some(lambda_masked), Some(kappa_unmasked), None) = (
            &quadruple.lambda_masked,
            &quadruple.kappa_unmasked,
            &quadruple.kappa_times_lambda_config,
        ) {
            let kappa_times_lambda_config = IDkgTranscriptParams::new(
                payload.next_unused_transcript_id,
                quadruple.lambda_config.dealers().clone(),
                quadruple.lambda_config.receivers().clone(),
                quadruple.lambda_config.registry_version(),
                quadruple.lambda_config.algorithm_id(),
                IDkgTranscriptOperation::UnmaskedTimesMasked(
                    kappa_unmasked.clone().into_base_type(),
                    lambda_masked.clone().into_base_type(),
                ),
            )?;
            payload.next_unused_transcript_id = payload.next_unused_transcript_id.increment();
        }
        if let (
            Some(kappa_unmasked),
            Some(lambda_masked),
            Some(key_times_lambda),
            Some(kappa_times_lambda),
        ) = (
            &quadruple.kappa_unmasked,
            &quadruple.lambda_masked,
            &quadruple.key_times_lambda,
            &quadruple.kappa_times_lambda,
        ) {
            newly_available.push(*key);
        }
    }
    for key in newly_available.into_iter() {
        // the following unwraps are safe
        let quadruple = payload.quadruples_in_creation.remove(&key).unwrap();
        let lambda_masked = quadruple.lambda_masked.unwrap();
        let kappa_unmasked = quadruple.kappa_unmasked.unwrap();
        let key_times_lambda = quadruple.key_times_lambda.unwrap();
        let kappa_times_lambda = quadruple.kappa_times_lambda.unwrap();
        payload.available_quadruples.insert(
            key,
            PreSignatureQuadruple::new(
                kappa_unmasked.into_base_type(),
                lambda_masked.into_base_type(),
                kappa_times_lambda.into_base_type(),
                key_times_lambda.into_base_type(),
            )?,
        );
    }
    Ok(())
}

/// Validates a threshold ECDSA summary payload.
pub fn validate_summary_payload(
    payload: ecdsa::EcdsaSummaryPayload,
) -> Result<(), EcdsaPayloadError> {
    todo!()
}

/// Validates a threshold ECDSA data payload.
pub fn validate_data_payload(payload: ecdsa::EcdsaDataPayload) -> Result<(), EcdsaPayloadError> {
    todo!()
}

/// Helper to build threshold signature inputs from the context and
/// the pre-signature quadruple
/// TODO: PrincipalId, key transcript, etc need to figured out
fn build_sign_inputs(
    context: &SignWithEcdsaContext,
    quadruple: &PreSignatureQuadruple,
) -> ThresholdEcdsaSigInputs {
    unimplemented!()
}
