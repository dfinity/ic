//! This module implements the ECDSA payload verifier.
//!
//! 1. Data integrity:
//!   - if all referenced data is available (e.g. references have to resolve).
//!   - if all data that should be carried over are indeed carried over.
//!   - if newly included data is consistent with carried over data.
//!   - if new quadruples/transcripts being added have increasing ids.
//! 2. Data authenticity.
//!   - if carried over data is not tampered.
//!   - if cryptographically verifiable data can be verified.

#![allow(unused_imports)]
use super::payload_builder::{EcdsaPayloadError, InvalidChainCacheError, MembershipError};
use super::utils::EcdsaBlockReaderImpl;
use crate::consensus::{
    crypto::ConsensusCrypto, metrics::EcdsaPayloadMetrics, pool_reader::PoolReader,
};
use crate::ecdsa::payload_builder::{
    block_chain_cache, build_signature_inputs, create_summary_payload, ecdsa_feature_is_enabled,
    get_signing_requests, is_subnet_membership_changing,
};
use ic_artifact_pool::consensus_pool::build_consensus_block_chain;
use ic_interfaces::{
    consensus_pool::ConsensusBlockChain,
    ecdsa::EcdsaPool,
    registry::RegistryClient,
    validation::{ValidationError, ValidationResult},
};
use ic_interfaces_state_manager::{StateManager, StateManagerError};
use ic_logger::{debug, info, warn, ReplicaLogger};
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_registry_subnet_features::EcdsaConfig;
use ic_replicated_state::{metadata_state::subnet_call_context_manager::*, ReplicatedState};
use ic_types::{
    batch::ValidationContext,
    consensus::{ecdsa, ecdsa::EcdsaBlockReader, Block, BlockPayload, HasHeight, SummaryPayload},
    crypto::canister_threshold_sig::idkg::IDkgTranscriptId,
    messages::CallbackId,
    registry::RegistryClientError,
    Height, RegistryVersion, SubnetId,
};
use std::collections::{btree_map, BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};

#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
pub enum TransientError {
    RegistryClientError(RegistryClientError),
    EcdsaPayloadError(EcdsaPayloadError),
    StateManagerError(StateManagerError),
}

#[derive(Debug)]
pub enum PermanentError {
    EcdsaFeatureDisabled,
    SummaryPayloadMismatch,
    UnexpectedSummaryPayload(EcdsaPayloadError),
    SubnetWithNoNodes(SubnetId, RegistryVersion),
    MissingEcdsaDataPayload,
    MissingParentDataPayload,
    InvalidChainCacheError(InvalidChainCacheError),
    NewTranscriptNotFound(IDkgTranscriptId),
    NewTranscriptMiscount(u64),
    UnexpectedDataPayload,
}

impl From<PermanentError> for EcdsaValidationError {
    fn from(err: PermanentError) -> Self {
        ValidationError::Permanent(err)
    }
}

impl From<TransientError> for EcdsaValidationError {
    fn from(err: TransientError) -> Self {
        ValidationError::Transient(err)
    }
}

impl From<MembershipError> for EcdsaValidationError {
    fn from(err: MembershipError) -> Self {
        match err {
            MembershipError::RegistryClientError(err) => {
                TransientError::RegistryClientError(err).into()
            }
            MembershipError::SubnetWithNoNodes(subnet_id, err) => {
                PermanentError::SubnetWithNoNodes(subnet_id, err).into()
            }
        }
    }
}

impl From<InvalidChainCacheError> for PermanentError {
    fn from(err: InvalidChainCacheError) -> Self {
        PermanentError::InvalidChainCacheError(err)
    }
}

impl From<RegistryClientError> for TransientError {
    fn from(err: RegistryClientError) -> Self {
        TransientError::RegistryClientError(err)
    }
}

pub type EcdsaValidationError = ValidationError<PermanentError, TransientError>;

#[allow(clippy::too_many_arguments)]
pub fn validate_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    crypto: &dyn ConsensusCrypto,
    pool_reader: &PoolReader<'_>,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    context: &ValidationContext,
    parent_block: &Block,
    payload: &BlockPayload,
) -> ValidationResult<EcdsaValidationError> {
    if payload.is_summary() {
        validate_summary_payload(
            subnet_id,
            registry_client,
            pool_reader,
            parent_block,
            payload.as_summary().ecdsa.as_ref(),
        )
    } else {
        validate_data_payload(
            subnet_id,
            registry_client,
            crypto,
            pool_reader,
            state_manager,
            context,
            parent_block,
            payload.as_data().ecdsa.as_ref(),
        )
    }
}

/// Validates a threshold ECDSA summary payload.
/// This is an entirely deterministic operation, so we can just check if
/// the given summary payload matches what we would have created locally.
pub fn validate_summary_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    pool_reader: &PoolReader<'_>,
    parent_block: &Block,
    summary_payload: Option<&ecdsa::EcdsaPayload>,
) -> ValidationResult<EcdsaValidationError> {
    let height = parent_block.height().increment();
    if !ecdsa_feature_is_enabled(subnet_id, registry_client, pool_reader, height)
        .map_err(TransientError::from)?
    {
        if summary_payload.is_some() {
            return Err(PermanentError::EcdsaFeatureDisabled.into());
        } else {
            return Ok(());
        }
    };
    match create_summary_payload(
        subnet_id,
        registry_client,
        pool_reader,
        parent_block,
        None,
        ic_logger::replica_logger::no_op_logger(),
    ) {
        Ok(payload) => {
            if payload.as_ref() == summary_payload {
                Ok(())
            } else {
                Err(PermanentError::SummaryPayloadMismatch.into())
            }
        }
        Err(EcdsaPayloadError::RegistryClientError(err)) => {
            Err(TransientError::RegistryClientError(err).into())
        }
        Err(EcdsaPayloadError::StateManagerError(err)) => {
            Err(TransientError::StateManagerError(err).into())
        }
        Err(err) => Err(PermanentError::UnexpectedSummaryPayload(err).into()),
    }
}

#[allow(unused_variables, unused_assignments, clippy::too_many_arguments)]
/// Validates a threshold ECDSA data payload.
pub fn validate_data_payload(
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    crypto: &dyn ConsensusCrypto,
    pool_reader: &PoolReader<'_>,
    state_manager: &dyn StateManager<State = ReplicatedState>,
    context: &ValidationContext,
    parent_block: &Block,
    data_payload: Option<&ecdsa::EcdsaPayload>,
) -> ValidationResult<EcdsaValidationError> {
    let height = parent_block.height().increment();
    let ecdsa_enabled = ecdsa_feature_is_enabled(subnet_id, registry_client, pool_reader, height)
        .map_err(TransientError::from)?;
    if !ecdsa_enabled {
        if data_payload.is_some() {
            return Err(PermanentError::EcdsaFeatureDisabled.into());
        } else {
            return Ok(());
        }
    }

    let block_payload = &parent_block.payload.as_ref();
    let summary_block = pool_reader
        .dkg_summary_block(parent_block)
        .unwrap_or_else(|| {
            panic!(
                "Impossible: fail to the summary block that governs height {}",
                parent_block.height()
            )
        });
    let summary = summary_block.payload.as_ref().as_summary();
    let summary_registry_version = summary.dkg.registry_version;
    let next_summary_registry_version = summary_block.context.registry_version;
    let ecdsa_config = registry_client
        .get_ecdsa_config(subnet_id, summary_registry_version)
        .map_err(TransientError::from)?
        .unwrap_or(EcdsaConfig {
            quadruples_to_create_in_advance: 1, // default value
            ..EcdsaConfig::default()
        });
    let (prev_payload, cur_payload) = if block_payload.is_summary() {
        match &summary.ecdsa {
            None => {
                if data_payload.is_some() {
                    return Err(PermanentError::UnexpectedDataPayload.into());
                } else {
                    return Ok(());
                }
            }
            Some(ecdsa_summary) => {
                if data_payload.is_none() {
                    return Err(PermanentError::MissingEcdsaDataPayload.into());
                }
                (ecdsa_summary.clone(), data_payload.as_ref().unwrap())
            }
        }
    } else {
        match &block_payload.as_data().ecdsa {
            None => {
                if data_payload.is_some() {
                    return Err(PermanentError::UnexpectedDataPayload.into());
                } else {
                    return Ok(());
                }
            }
            Some(payload) => {
                if data_payload.is_none() {
                    return Err(PermanentError::MissingEcdsaDataPayload.into());
                }
                (payload.clone(), data_payload.as_ref().unwrap())
            }
        }
    };
    let parent_chain = block_chain_cache(pool_reader, &summary_block, parent_block)
        .map_err(PermanentError::from)?;
    let block_reader = EcdsaBlockReaderImpl::new(parent_chain);
    validate_transcript_refs(&block_reader, &prev_payload, cur_payload)?;
    Ok(())
}

// Validate transcript references
// - All references in the payload should resolve.
// - Newly added transcripts are referenced.
// - Newly added transcripts are valid (check in their referenced site, not here).
//
// Since this function is only called on data payload, we can assume all references
// in prev_payload resolve correctly. So only new references need to be checked.
fn validate_transcript_refs(
    block_reader: &dyn EcdsaBlockReader,
    prev_payload: &ecdsa::EcdsaPayload,
    curr_payload: &ecdsa::EcdsaPayload,
) -> ValidationResult<EcdsaValidationError> {
    use PermanentError::*;
    let mut count = 0;
    let idkg_transcripts = &curr_payload.idkg_transcripts;
    let prev_refs = prev_payload.active_transcripts();
    for transcript_ref in curr_payload.active_transcripts().iter() {
        if !prev_refs.contains(transcript_ref) && block_reader.transcript(transcript_ref).is_err() {
            let transcript_id = &transcript_ref.transcript_id;
            if idkg_transcripts.get(transcript_id).is_some() {
                count += 1;
            } else {
                return Err(NewTranscriptNotFound(*transcript_id).into());
            }
        }
    }
    if count as usize == idkg_transcripts.len() {
        Ok(())
    } else {
        Err(NewTranscriptMiscount(count).into())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ecdsa::utils::test_utils::*;
    use ic_crypto_test_utils_canister_threshold_sigs::{
        generate_key_transcript, CanisterThresholdSigTestEnvironment,
    };
    use ic_test_utilities::types::ids::subnet_test_id;
    use ic_types::crypto::AlgorithmId;
    use std::convert::TryFrom;

    #[test]
    fn test_validate_transcript_refs() {
        let num_of_nodes = 4;
        let subnet_id = subnet_test_id(1);
        let env = CanisterThresholdSigTestEnvironment::new(num_of_nodes);
        //let registry_version = env.newest_registry_version;
        //let subnet_nodes = env.receivers().into_iter().collect::<Vec<_>>();
        let algorithm = AlgorithmId::ThresholdEcdsaSecp256k1;
        let mut block_reader = TestEcdsaBlockReader::new();
        let prev_payload = empty_ecdsa_payload(subnet_id);
        let mut curr_payload = prev_payload.clone();
        // Empty payload verifies
        assert!(validate_transcript_refs(&block_reader, &prev_payload, &curr_payload).is_ok());

        // Add a transcript
        let transcript_0 = generate_key_transcript(&env, algorithm);
        let transcript_ref_0 =
            ecdsa::UnmaskedTranscript::try_from((Height::new(100), &transcript_0)).unwrap();
        curr_payload
            .idkg_transcripts
            .insert(transcript_0.transcript_id, transcript_0);
        // Error because transcript is not referenced
        assert!(matches!(
            validate_transcript_refs(&block_reader, &prev_payload, &curr_payload),
            Err(ValidationError::Permanent(
                PermanentError::NewTranscriptMiscount(_)
            ))
        ));

        // Add the reference
        curr_payload.key_transcript.next_in_creation =
            ecdsa::KeyTranscriptCreation::Created(transcript_ref_0);
        assert!(validate_transcript_refs(&block_reader, &prev_payload, &curr_payload).is_ok());

        // Add another reference
        let transcript_1 = generate_key_transcript(&env, algorithm);
        let transcript_ref_1 =
            ecdsa::UnmaskedTranscript::try_from((Height::new(100), &transcript_1)).unwrap();
        curr_payload.key_transcript.next_in_creation =
            ecdsa::KeyTranscriptCreation::Created(transcript_ref_1);
        assert!(matches!(
            validate_transcript_refs(&block_reader, &prev_payload, &curr_payload),
            Err(ValidationError::Permanent(
                PermanentError::NewTranscriptNotFound(_)
            ))
        ));

        curr_payload.idkg_transcripts = BTreeMap::new();
        block_reader.add_transcript(*transcript_ref_1.as_ref(), transcript_1);
        println!(
            "{:?}",
            validate_transcript_refs(&block_reader, &prev_payload, &curr_payload)
        );
        assert!(validate_transcript_refs(&block_reader, &prev_payload, &curr_payload).is_ok());
    }
}
