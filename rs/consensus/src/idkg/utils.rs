//! Common utils for the IDKG implementation.

use crate::idkg::complaints::{IDkgTranscriptLoader, TranscriptLoadStatus};
use crate::idkg::metrics::IDkgPayloadMetrics;
use ic_consensus_utils::pool_reader::PoolReader;
use ic_crypto::get_master_public_key_from_transcript;
use ic_interfaces::consensus_pool::ConsensusBlockChain;
use ic_interfaces::idkg::{IDkgChangeAction, IDkgChangeSet, IDkgPool};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{warn, ReplicaLogger};
use ic_management_canister_types::{EcdsaCurve, MasterPublicKeyId, SchnorrAlgorithm};
use ic_protobuf::registry::subnet::v1 as pb;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_registry_subnet_features::ChainKeyConfig;
use ic_replicated_state::metadata_state::subnet_call_context_manager::{
    SignWithThresholdContext, ThresholdArguments,
};
use ic_types::consensus::idkg::common::{PreSignatureRef, SignatureScheme, ThresholdSigInputsRef};
use ic_types::consensus::idkg::ecdsa::ThresholdEcdsaSigInputsRef;
use ic_types::consensus::idkg::schnorr::ThresholdSchnorrSigInputsRef;
use ic_types::consensus::idkg::HasMasterPublicKeyId;
use ic_types::consensus::Block;
use ic_types::consensus::{
    idkg::{
        IDkgBlockReader, IDkgMessage, IDkgTranscriptParamsRef, PreSigId, RequestId,
        TranscriptLookupError, TranscriptRef,
    },
    HasHeight,
};
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgTranscript, IDkgTranscriptOperation, InitialIDkgDealings,
};
use ic_types::crypto::canister_threshold_sig::{ExtendedDerivationPath, MasterPublicKey};
use ic_types::crypto::AlgorithmId;
use ic_types::registry::RegistryClientError;
use ic_types::{Height, RegistryVersion, SubnetId};
use phantom_newtype::Id;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    convert::TryInto,
    fmt::{self, Display, Formatter},
    sync::Arc,
};

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct InvalidChainCacheError(String);

impl Display for InvalidChainCacheError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub(super) struct IDkgBlockReaderImpl {
    chain: Arc<dyn ConsensusBlockChain>,
}

impl IDkgBlockReaderImpl {
    pub(crate) fn new(chain: Arc<dyn ConsensusBlockChain>) -> Self {
        Self { chain }
    }
}

impl IDkgBlockReader for IDkgBlockReaderImpl {
    fn tip_height(&self) -> Height {
        self.chain.tip().height()
    }

    fn requested_transcripts(&self) -> Box<dyn Iterator<Item = &IDkgTranscriptParamsRef> + '_> {
        self.chain
            .tip()
            .payload
            .as_ref()
            .as_idkg()
            .map_or(Box::new(std::iter::empty()), |idkg_payload| {
                Box::new(idkg_payload.iter_transcript_configs_in_creation())
            })
    }

    fn pre_signatures_in_creation(
        &self,
    ) -> Box<dyn Iterator<Item = (PreSigId, MasterPublicKeyId)> + '_> {
        self.chain.tip().payload.as_ref().as_idkg().map_or(
            Box::new(std::iter::empty()),
            |idkg_payload| {
                Box::new(
                    idkg_payload
                        .pre_signatures_in_creation
                        .iter()
                        .map(|(id, pre_sig)| (*id, pre_sig.key_id())),
                )
            },
        )
    }

    fn available_pre_signature(&self, id: &PreSigId) -> Option<&PreSignatureRef> {
        self.chain
            .tip()
            .payload
            .as_ref()
            .as_idkg()
            .and_then(|idkg_payload| idkg_payload.available_pre_signatures.get(id))
    }

    fn active_transcripts(&self) -> BTreeSet<TranscriptRef> {
        self.chain
            .tip()
            .payload
            .as_ref()
            .as_idkg()
            .map_or(BTreeSet::new(), |payload| payload.active_transcripts())
    }

    fn source_subnet_xnet_transcripts(
        &self,
    ) -> Box<dyn Iterator<Item = &IDkgTranscriptParamsRef> + '_> {
        self.chain
            .tip()
            .payload
            .as_ref()
            .as_idkg()
            .map_or(Box::new(std::iter::empty()), |idkg_payload| {
                Box::new(idkg_payload.iter_xnet_transcripts_source_subnet())
            })
    }

    fn target_subnet_xnet_transcripts(
        &self,
    ) -> Box<dyn Iterator<Item = &IDkgTranscriptParamsRef> + '_> {
        self.chain
            .tip()
            .payload
            .as_ref()
            .as_idkg()
            .map_or(Box::new(std::iter::empty()), |idkg_payload| {
                Box::new(idkg_payload.iter_xnet_transcripts_target_subnet())
            })
    }

    fn transcript(
        &self,
        transcript_ref: &TranscriptRef,
    ) -> Result<IDkgTranscript, TranscriptLookupError> {
        let idkg_payload = match self.chain.get_block_by_height(transcript_ref.height) {
            Ok(block) => {
                if let Some(idkg_payload) = block.payload.as_ref().as_idkg() {
                    idkg_payload
                } else {
                    return Err(format!(
                        "transcript(): chain look up failed {:?}: IDkgPayload not found",
                        transcript_ref
                    ));
                }
            }
            Err(err) => {
                return Err(format!(
                    "transcript(): chain look up failed {:?}: {:?}",
                    transcript_ref, err
                ))
            }
        };

        idkg_payload
            .idkg_transcripts
            .get(&transcript_ref.transcript_id)
            .ok_or(format!(
                "transcript(): missing idkg_transcript: {:?}",
                transcript_ref
            ))
            .cloned()
    }
}

pub(super) fn block_chain_reader(
    pool_reader: &PoolReader<'_>,
    summary_block: &Block,
    parent_block: &Block,
    idkg_payload_metrics: Option<&IDkgPayloadMetrics>,
    log: &ReplicaLogger,
) -> Result<IDkgBlockReaderImpl, InvalidChainCacheError> {
    // Resolve the transcript refs pointing into the parent chain,
    // copy the resolved transcripts into the summary block.
    block_chain_cache(pool_reader, summary_block, parent_block)
        .map(IDkgBlockReaderImpl::new)
        .map_err(|err| {
            warn!(
                log,
                "block_chain_reader(): failed to build chain cache: {}", err
            );
            if let Some(metrics) = idkg_payload_metrics {
                metrics.payload_errors_inc("summary_invalid_chain_cache");
            };
            err
        })
}

/// Wrapper to build the chain cache and perform sanity checks on the returned chain
pub(super) fn block_chain_cache(
    pool_reader: &PoolReader<'_>,
    start: &Block,
    end: &Block,
) -> Result<Arc<dyn ConsensusBlockChain>, InvalidChainCacheError> {
    let chain = pool_reader.pool().build_block_chain(start, end);
    let expected_len = (end.height().get() - start.height().get() + 1) as usize;
    let chain_len = chain.len();
    if chain_len == expected_len {
        Ok(chain)
    } else {
        Err(InvalidChainCacheError(format!(
            "Invalid chain cache length: expected = {:?}, actual = {:?}, \
             start = {:?}, end = {:?}, tip = {:?}, \
             notarized_height = {:?}, finalized_height = {:?}, CUP height = {:?}",
            expected_len,
            chain_len,
            start.height(),
            end.height(),
            chain.tip().height(),
            pool_reader.get_notarized_height(),
            pool_reader.get_finalized_height(),
            pool_reader.get_catch_up_height()
        )))
    }
}

/// Helper to build the [`RequestId`] if the context is already completed
pub(super) fn get_context_request_id(context: &SignWithThresholdContext) -> Option<RequestId> {
    context
        .matched_pre_signature
        .map(|(pre_signature_id, height)| RequestId {
            pre_signature_id,
            pseudo_random_id: context.pseudo_random_id,
            height,
        })
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum BuildSignatureInputsError {
    /// The context wasn't matched to a pre-signature yet, or is still missing its random nonce
    ContextIncomplete,
    /// The context was matched to a pre-signature which cannot be found in the latest block payload
    MissingPreSignature(RequestId),
    /// The context was matched to a pre-signature of the wrong signature scheme
    SignatureSchemeMismatch(RequestId, SignatureScheme),
}

impl BuildSignatureInputsError {
    /// Fatal errors indicate a problem in the construction of payloads,
    /// request contexts, or the match between both.
    pub(crate) fn is_fatal(&self) -> bool {
        matches!(
            self,
            BuildSignatureInputsError::SignatureSchemeMismatch(_, _)
        )
    }
}

/// Helper to build threshold signature inputs from the context and
/// the pre-signature
pub(super) fn build_signature_inputs(
    context: &SignWithThresholdContext,
    block_reader: &dyn IDkgBlockReader,
) -> Result<(RequestId, ThresholdSigInputsRef), BuildSignatureInputsError> {
    let request_id =
        get_context_request_id(context).ok_or(BuildSignatureInputsError::ContextIncomplete)?;
    let extended_derivation_path = ExtendedDerivationPath {
        caller: context.request.sender.into(),
        derivation_path: context.derivation_path.clone(),
    };
    let pre_signature = block_reader
        .available_pre_signature(&request_id.pre_signature_id)
        .ok_or_else(|| BuildSignatureInputsError::MissingPreSignature(request_id.clone()))?
        .clone();
    let nonce = Id::from(
        context
            .nonce
            .ok_or(BuildSignatureInputsError::ContextIncomplete)?,
    );
    let inputs = match (pre_signature, &context.args) {
        (PreSignatureRef::Ecdsa(pre_sig), ThresholdArguments::Ecdsa(args)) => {
            ThresholdSigInputsRef::Ecdsa(ThresholdEcdsaSigInputsRef::new(
                extended_derivation_path,
                args.message_hash,
                nonce,
                pre_sig,
            ))
        }
        (PreSignatureRef::Schnorr(pre_sig), ThresholdArguments::Schnorr(args)) => {
            ThresholdSigInputsRef::Schnorr(ThresholdSchnorrSigInputsRef::new(
                extended_derivation_path,
                args.message.clone(),
                nonce,
                pre_sig,
            ))
        }
        (PreSignatureRef::Ecdsa(_), _) => {
            return Err(BuildSignatureInputsError::SignatureSchemeMismatch(
                request_id,
                SignatureScheme::Ecdsa,
            ))
        }
        (PreSignatureRef::Schnorr(_), _) => {
            return Err(BuildSignatureInputsError::SignatureSchemeMismatch(
                request_id,
                SignatureScheme::Schnorr,
            ))
        }
    };

    Ok((request_id, inputs))
}

/// Load the given transcripts
/// Returns None if all the transcripts could be loaded successfully.
/// Otherwise, returns the complaint change set to be added to the pool
pub(super) fn load_transcripts(
    idkg_pool: &dyn IDkgPool,
    transcript_loader: &dyn IDkgTranscriptLoader,
    transcripts: &[&IDkgTranscript],
) -> Option<IDkgChangeSet> {
    let mut new_complaints = Vec::new();
    for transcript in transcripts {
        match transcript_loader.load_transcript(idkg_pool, transcript) {
            TranscriptLoadStatus::Success => (),
            TranscriptLoadStatus::Failure => return Some(Default::default()),
            TranscriptLoadStatus::Complaints(complaints) => {
                for complaint in complaints {
                    new_complaints.push(IDkgChangeAction::AddToValidated(IDkgMessage::Complaint(
                        complaint,
                    )));
                }
            }
        }
    }

    if new_complaints.is_empty() {
        None
    } else {
        Some(new_complaints)
    }
}

/// Brief summary of the IDkgTranscriptOperation
pub(super) fn transcript_op_summary(op: &IDkgTranscriptOperation) -> String {
    match op {
        IDkgTranscriptOperation::Random => "Random".to_string(),
        IDkgTranscriptOperation::RandomUnmasked => "RandomUnmasked".to_string(),
        IDkgTranscriptOperation::ReshareOfMasked(t) => {
            format!("ReshareOfMasked({:?})", t.transcript_id)
        }
        IDkgTranscriptOperation::ReshareOfUnmasked(t) => {
            format!("ReshareOfUnmasked({:?})", t.transcript_id)
        }
        IDkgTranscriptOperation::UnmaskedTimesMasked(t1, t2) => format!(
            "UnmaskedTimesMasked({:?}, {:?})",
            t1.transcript_id, t2.transcript_id
        ),
    }
}

/// Inspect chain_key_initializations field in the CUPContent.
/// Return key_id and dealings.
pub(crate) fn inspect_chain_key_initializations(
    ecdsa_initializations: &[pb::EcdsaInitialization],
    chain_key_initializations: &[pb::ChainKeyInitialization],
) -> Result<BTreeMap<MasterPublicKeyId, InitialIDkgDealings>, String> {
    let mut initial_dealings_per_key_id = BTreeMap::new();

    if !ecdsa_initializations.is_empty() && !chain_key_initializations.is_empty() {
        return Err("`chain_key_initialization` and `ecdsa_initializations` \
            cannot be present at the same time"
            .to_string());
    }

    // TODO(CON-1332): Do not panic if fields are missing
    for ecdsa_init in ecdsa_initializations {
        let ecdsa_key_id = ecdsa_init
            .key_id
            .clone()
            .expect("Error: Failed to find key_id in ecdsa_initializations")
            .try_into()
            .map_err(|err| {
                format!(
                    "Error reading ECDSA key_id: {:?}. Setting idkg_summary to None.",
                    err
                )
            })?;

        let dealings = ecdsa_init
            .dealings
            .as_ref()
            .expect("Error: Failed to find dealings in ecdsa_initializations")
            .try_into()
            .map_err(|err| {
                format!(
                    "Error reading ECDSA dealings: {:?}. Setting idkg_summary to None.",
                    err
                )
            })?;

        initial_dealings_per_key_id.insert(MasterPublicKeyId::Ecdsa(ecdsa_key_id), dealings);
    }

    // TODO(CON-1332): Do not panic if fields are missing
    for chain_key_init in chain_key_initializations {
        let key_id = chain_key_init
            .key_id
            .clone()
            .expect("Error: Failed to find key_id in chain_key_initializations")
            .try_into()
            .map_err(|err| {
                format!(
                    "Error reading Master public key_id: {:?}. Setting idkg_summary to None.",
                    err
                )
            })?;

        let dealings = chain_key_init
            .dealings
            .as_ref()
            .expect("Error: Failed to find dealings in chain_key_initializations")
            .try_into()
            .map_err(|err| {
                format!(
                    "Error reading initial IDkg dealings: {:?}. Setting idkg_summary to None.",
                    err
                )
            })?;

        initial_dealings_per_key_id.insert(key_id, dealings);
    }

    Ok(initial_dealings_per_key_id)
}

pub(crate) fn algorithm_for_key_id(key_id: &MasterPublicKeyId) -> AlgorithmId {
    match key_id {
        MasterPublicKeyId::Ecdsa(ecdsa_key_id) => match ecdsa_key_id.curve {
            EcdsaCurve::Secp256k1 => AlgorithmId::ThresholdEcdsaSecp256k1,
        },
        MasterPublicKeyId::Schnorr(schnorr_key_id) => match schnorr_key_id.algorithm {
            SchnorrAlgorithm::Bip340Secp256k1 => AlgorithmId::ThresholdSchnorrBip340,
            SchnorrAlgorithm::Ed25519 => AlgorithmId::ThresholdEd25519,
        },
    }
}

pub(crate) fn get_chain_key_config_if_enabled(
    subnet_id: SubnetId,
    registry_version: RegistryVersion,
    registry_client: &dyn RegistryClient,
) -> Result<Option<ChainKeyConfig>, RegistryClientError> {
    if let Some(chain_key_config) =
        registry_client.get_chain_key_config(subnet_id, registry_version)?
    {
        // A key that has `presignatures_to_create_in_advance` set to 0 is not active
        let num_active_key_ids = chain_key_config
            .key_configs
            .iter()
            .filter(|key_config| key_config.pre_signatures_to_create_in_advance != 0)
            .count();

        if num_active_key_ids == 0 {
            Ok(None)
        } else {
            Ok(Some(chain_key_config))
        }
    } else {
        Ok(None)
    }
}

/// Return the set of pre-signature IDs to be delivered in the batch of this block.
/// We deliver IDs of all available pre-signatures that were created using the current key transcript.
pub(crate) fn get_pre_signature_ids_to_deliver(
    block: &Block,
) -> BTreeMap<MasterPublicKeyId, BTreeSet<PreSigId>> {
    let Some(idkg) = block.payload.as_ref().as_idkg() else {
        return BTreeMap::new();
    };

    let mut pre_sig_ids: BTreeMap<MasterPublicKeyId, BTreeSet<PreSigId>> = BTreeMap::new();
    for key_id in idkg.key_transcripts.keys() {
        pre_sig_ids.insert(key_id.clone(), BTreeSet::default());
    }

    for (pre_sig_id, pre_signature) in &idkg.available_pre_signatures {
        let key_id = pre_signature.key_id();
        if idkg
            .current_key_transcript(&key_id)
            .is_some_and(|current_key_transcript| {
                current_key_transcript.transcript_id()
                    == pre_signature.key_unmasked().as_ref().transcript_id
            })
        {
            pre_sig_ids.entry(key_id).or_default().insert(*pre_sig_id);
        }
    }

    pre_sig_ids
}

/// This function returns the subnet master public keys to be added to the batch, if required.
/// We return `Ok(Some(key))`, if
/// - The block contains an IDKG payload with current key transcript ref, and
/// - the corresponding transcript exists in past blocks, and
/// - we can extract the threshold master public key from the transcript.
///
/// Otherwise `Ok(None)` is returned.
/// Additionally, we return `Err(string)` if we were unable to find a dkg summary block for the height
/// of the given block (as the lower bound for past blocks to lookup the transcript in). In that case
/// a newer CUP is already present in the pool and we should continue from there.
pub(crate) fn get_idkg_subnet_public_keys(
    block: &Block,
    pool: &PoolReader<'_>,
    log: &ReplicaLogger,
) -> Result<BTreeMap<MasterPublicKeyId, MasterPublicKey>, String> {
    let Some(idkg_payload) = block.payload.as_ref().as_idkg() else {
        return Ok(BTreeMap::new());
    };

    let Some(summary) = pool.dkg_summary_block_for_finalized_height(block.height) else {
        return Err(format!(
            "Failed to find dkg summary block for height {}",
            block.height
        ));
    };
    let chain = pool.pool().build_block_chain(&summary, block);
    let block_reader = IDkgBlockReaderImpl::new(chain);

    let mut public_keys = BTreeMap::new();

    for (key_id, key_transcript) in &idkg_payload.key_transcripts {
        let Some(transcript_ref) = key_transcript
            .current
            .as_ref()
            .map(|unmasked| *unmasked.as_ref())
        else {
            continue;
        };

        let ecdsa_subnet_public_key = match block_reader.transcript(&transcript_ref) {
            Ok(transcript) => get_subnet_master_public_key(&transcript, log),
            Err(err) => {
                warn!(
                    log,
                    "Failed to translate transcript ref {:?}: {:?}", transcript_ref, err
                );

                None
            }
        };

        if let Some(public_key) = ecdsa_subnet_public_key {
            public_keys.insert(key_id.clone(), public_key);
        }
    }

    Ok(public_keys)
}

fn get_subnet_master_public_key(
    transcript: &IDkgTranscript,
    log: &ReplicaLogger,
) -> Option<MasterPublicKey> {
    match get_master_public_key_from_transcript(transcript) {
        Ok(public_key) => Some(public_key),
        Err(err) => {
            warn!(
                log,
                "Failed to retrieve IDKg subnet master public key: {:?}", err
            );

            None
        }
    }
}

/// Updates the latest purge height, and returns true if
/// it increased. Otherwise returns false.
pub(crate) fn update_purge_height(cell: &RefCell<Height>, new_height: Height) -> bool {
    let prev_purge_height = cell.replace(new_height);
    new_height > prev_purge_height
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::idkg::test_utils::{
        create_available_pre_signature_with_key_transcript, fake_ecdsa_key_id,
        fake_ecdsa_master_public_key_id, fake_master_public_key_ids_for_all_algorithms,
        set_up_idkg_payload, IDkgPayloadTestHelper,
    };
    use ic_config::artifact_pool::ArtifactPoolConfig;
    use ic_consensus_mocks::{dependencies, Dependencies};
    use ic_crypto_test_utils_canister_threshold_sigs::{
        dummy_values::dummy_initial_idkg_dealing_for_tests, generate_key_transcript,
        IDkgParticipants,
    };
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_management_canister_types::{EcdsaKeyId, SchnorrKeyId};
    use ic_protobuf::registry::subnet::v1::EcdsaInitialization;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_subnet_features::KeyConfig;
    use ic_test_utilities_consensus::fake::Fake;
    use ic_test_utilities_registry::{add_subnet_record, SubnetRecordBuilder};
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{
        batch::ValidationContext,
        consensus::{
            idkg::{IDkgPayload, UnmaskedTranscript},
            BlockPayload, Payload, SummaryPayload,
        },
        crypto::CryptoHashOf,
        time::UNIX_EPOCH,
    };
    use pb::ChainKeyInitialization;
    use std::str::FromStr;

    #[test]
    fn test_inspect_chain_key_initializations_no_keys() {
        let init = inspect_chain_key_initializations(&[], &[])
            .expect("Should successfully get initializations");

        assert!(init.is_empty());
    }

    #[test]
    fn test_inspect_chain_key_initializations_one_ecdsa_key() {
        let mut rng = reproducible_rng();
        let initial_dealings = dummy_initial_idkg_dealing_for_tests(
            ic_types::crypto::AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let key_id = fake_ecdsa_key_id();
        let ecdsa_init = EcdsaInitialization {
            key_id: Some((&key_id).into()),
            dealings: Some((&initial_dealings).into()),
        };

        let init = inspect_chain_key_initializations(&[ecdsa_init], &[])
            .expect("Should successfully get initializations");

        assert_eq!(
            init,
            BTreeMap::from([(MasterPublicKeyId::Ecdsa(key_id), initial_dealings)])
        );
    }

    #[test]
    fn test_inspect_chain_key_initializations_one_master_public_key() {
        let mut rng = reproducible_rng();
        let initial_dealings = dummy_initial_idkg_dealing_for_tests(
            ic_types::crypto::AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let key_id = fake_ecdsa_master_public_key_id();
        let chain_key_init = ChainKeyInitialization {
            key_id: Some((&key_id).into()),
            dealings: Some((&initial_dealings).into()),
        };

        let init = inspect_chain_key_initializations(&[], &[chain_key_init])
            .expect("Should successfully get initializations");

        assert_eq!(init, BTreeMap::from([(key_id, initial_dealings)]));
    }

    #[test]
    fn test_inspect_chain_key_initializations_multiple_keys() {
        let mut rng = reproducible_rng();
        let initial_dealings = dummy_initial_idkg_dealing_for_tests(
            ic_types::crypto::AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let initial_dealings_2 = dummy_initial_idkg_dealing_for_tests(
            ic_types::crypto::AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let key_id = EcdsaKeyId::from_str("Secp256k1:some_key").unwrap();
        let master_key_id = MasterPublicKeyId::Ecdsa(key_id.clone());
        let key_id_2 = EcdsaKeyId::from_str("Secp256k1:some_key_2").unwrap();
        let master_key_id_2 = MasterPublicKeyId::Ecdsa(key_id_2.clone());

        let ecdsa_init = EcdsaInitialization {
            key_id: Some((&key_id).into()),
            dealings: Some((&initial_dealings).into()),
        };
        let ecdsa_init_2 = EcdsaInitialization {
            key_id: Some((&key_id_2).into()),
            dealings: Some((&initial_dealings_2).into()),
        };
        let chain_key_init = ChainKeyInitialization {
            key_id: Some((&master_key_id).into()),
            dealings: Some((&initial_dealings).into()),
        };
        let chain_key_init_2 = ChainKeyInitialization {
            key_id: Some((&master_key_id_2).into()),
            dealings: Some((&initial_dealings_2).into()),
        };

        let init =
            inspect_chain_key_initializations(&[ecdsa_init.clone(), ecdsa_init_2.clone()], &[])
                .expect("Should successfully inspect initializations");
        assert_eq!(
            init,
            BTreeMap::from([
                (master_key_id.clone(), initial_dealings.clone()),
                (master_key_id_2.clone(), initial_dealings_2.clone()),
            ])
        );

        let init = inspect_chain_key_initializations(
            &[],
            &[chain_key_init.clone(), chain_key_init_2.clone()],
        )
        .expect("Should successfully inspect initializations");
        assert_eq!(
            init,
            BTreeMap::from([
                (master_key_id.clone(), initial_dealings.clone()),
                (master_key_id_2.clone(), initial_dealings_2.clone()),
            ])
        );

        inspect_chain_key_initializations(&[ecdsa_init.clone()], &[chain_key_init_2.clone()])
            .expect_err("Should fail when both arguments are non-empty");
    }

    fn set_up_get_chain_key_config_test(
        config: &ChainKeyConfig,
        pool_config: ArtifactPoolConfig,
    ) -> (SubnetId, Arc<FakeRegistryClient>, RegistryVersion) {
        let Dependencies {
            registry,
            registry_data_provider,
            ..
        } = dependencies(pool_config, 1);
        let subnet_id = subnet_test_id(1);
        let registry_version = RegistryVersion::from(10);

        add_subnet_record(
            &registry_data_provider,
            registry_version.get(),
            subnet_id,
            SubnetRecordBuilder::from(&[node_test_id(0)])
                .with_chain_key_config(config.clone())
                .build(),
        );
        registry.update_to_latest_version();

        (subnet_id, registry, registry_version)
    }

    #[test]
    fn test_get_chain_key_config_if_enabled_no_keys() {
        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
                let chain_key_config_with_no_keys = ChainKeyConfig::default();
                let (subnet_id, registry, version) =
                    set_up_get_chain_key_config_test(&chain_key_config_with_no_keys, pool_config);

                let config = get_chain_key_config_if_enabled(subnet_id, version, registry.as_ref())
                    .expect("Should successfully get the config");

                assert!(config.is_none());
            },
        )
    }

    #[test]
    fn test_get_chain_key_config_if_enabled_one_key() {
        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
                let chain_key_config_with_one_key = ChainKeyConfig {
                    key_configs: vec![KeyConfig {
                        key_id: MasterPublicKeyId::Ecdsa(
                            EcdsaKeyId::from_str("Secp256k1:some_key").unwrap(),
                        ),
                        pre_signatures_to_create_in_advance: 1,
                        max_queue_size: 3,
                    }],
                    ..ChainKeyConfig::default()
                };

                let (subnet_id, registry, version) =
                    set_up_get_chain_key_config_test(&chain_key_config_with_one_key, pool_config);

                let config = get_chain_key_config_if_enabled(subnet_id, version, registry.as_ref())
                    .expect("Should successfully get the config");

                assert_eq!(config, Some(chain_key_config_with_one_key));
            },
        )
    }

    #[test]
    fn test_get_chain_key_config_if_enabled_multiple_keys() {
        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
                let key_config = KeyConfig {
                    key_id: MasterPublicKeyId::Ecdsa(
                        EcdsaKeyId::from_str("Secp256k1:some_key_1").unwrap(),
                    ),
                    pre_signatures_to_create_in_advance: 1,
                    max_queue_size: 3,
                };
                let key_config_2 = KeyConfig {
                    key_id: MasterPublicKeyId::Schnorr(
                        SchnorrKeyId::from_str("Ed25519:some_key_2").unwrap(),
                    ),
                    pre_signatures_to_create_in_advance: 1,
                    max_queue_size: 3,
                };

                let chain_key_config_with_two_keys = ChainKeyConfig {
                    key_configs: vec![key_config.clone(), key_config_2.clone()],
                    ..ChainKeyConfig::default()
                };

                let (subnet_id, registry, version) =
                    set_up_get_chain_key_config_test(&chain_key_config_with_two_keys, pool_config);

                let config = get_chain_key_config_if_enabled(subnet_id, version, registry.as_ref())
                    .expect("Should successfully get the config");

                assert_eq!(
                    config,
                    Some(ChainKeyConfig {
                        key_configs: vec![key_config, key_config_2],
                        ..chain_key_config_with_two_keys
                    })
                );
            },
        )
    }

    #[test]
    fn test_get_chain_key_config_if_enabled_malformed() {
        ic_test_utilities_artifact_pool::artifact_pool_config::with_test_pool_config(
            |pool_config| {
                let malformed_chain_key_config = ChainKeyConfig {
                    key_configs: vec![KeyConfig {
                        key_id: MasterPublicKeyId::Ecdsa(
                            EcdsaKeyId::from_str("Secp256k1:some_key").unwrap(),
                        ),
                        pre_signatures_to_create_in_advance: 0,
                        max_queue_size: 3,
                    }],
                    ..ChainKeyConfig::default()
                };
                let (subnet_id, registry, version) =
                    set_up_get_chain_key_config_test(&malformed_chain_key_config, pool_config);

                let config = get_chain_key_config_if_enabled(subnet_id, version, registry.as_ref())
                    .expect("Should successfully get the config");

                assert!(config.is_none());
            },
        )
    }

    fn add_available_pre_signatures_with_key_transcript(
        idkg_payload: &mut IDkgPayload,
        key_transcript: UnmaskedTranscript,
        key_id: &MasterPublicKeyId,
    ) -> Vec<PreSigId> {
        let mut pre_sig_ids = vec![];
        for i in 0..10 {
            let id = create_available_pre_signature_with_key_transcript(
                idkg_payload,
                i,
                key_id.clone(),
                Some(key_transcript),
            );
            pre_sig_ids.push(id);
        }
        pre_sig_ids
    }

    fn make_block(idkg_payload: Option<IDkgPayload>) -> Block {
        Block::new(
            CryptoHashOf::from(ic_types::crypto::CryptoHash(Vec::new())),
            Payload::new(
                ic_types::crypto::crypto_hash,
                BlockPayload::Summary(SummaryPayload {
                    dkg: ic_types::consensus::dkg::Summary::fake(),
                    idkg: idkg_payload,
                }),
            ),
            Height::from(123),
            ic_types::consensus::Rank(456),
            ValidationContext {
                registry_version: RegistryVersion::from(99),
                certified_height: Height::from(42),
                time: UNIX_EPOCH,
            },
        )
    }

    #[test]
    fn test_get_pre_signature_ids_to_deliver_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_get_pre_signature_ids_to_deliver(key_id);
        }
    }

    fn test_get_pre_signature_ids_to_deliver(key_id: MasterPublicKeyId) {
        let mut rng = reproducible_rng();
        let (mut idkg_payload, env, _) = set_up_idkg_payload(
            &mut rng,
            subnet_test_id(1),
            /*nodes_count=*/ 8,
            vec![key_id.clone()],
            /*should_create_key_transcript=*/ true,
        );
        let current_key_transcript = idkg_payload
            .single_key_transcript()
            .current
            .clone()
            .unwrap();

        let pre_signature_ids_to_be_delivered = add_available_pre_signatures_with_key_transcript(
            &mut idkg_payload,
            current_key_transcript.unmasked_transcript(),
            &key_id,
        );

        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::AllNodesAsDealersAndReceivers,
            &mut rng,
        );

        let key_transcript = generate_key_transcript(
            &env,
            &dealers,
            &receivers,
            algorithm_for_key_id(&key_id),
            &mut rng,
        );
        let old_key_transcript =
            UnmaskedTranscript::try_from((Height::from(0), &key_transcript)).unwrap();
        let pre_signature_ids_not_to_be_delivered =
            add_available_pre_signatures_with_key_transcript(
                &mut idkg_payload,
                old_key_transcript,
                &key_id,
            );

        let block = make_block(Some(idkg_payload));
        let mut delivered_map = get_pre_signature_ids_to_deliver(&block);
        assert_eq!(delivered_map.len(), 1);
        let delivered_ids = delivered_map.remove(&key_id).unwrap();

        assert!(!pre_signature_ids_not_to_be_delivered
            .into_iter()
            .any(|pid| delivered_ids.contains(&pid)));
        assert_eq!(
            pre_signature_ids_to_be_delivered,
            delivered_ids.into_iter().collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_block_without_idkg_should_not_deliver_quadruples() {
        let block = make_block(None);
        let delivered_ids = get_pre_signature_ids_to_deliver(&block);

        assert!(delivered_ids.is_empty());
    }

    #[test]
    fn test_block_without_key_should_not_deliver_pre_signatures_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_algorithms() {
            println!("Running test for key ID {key_id}");
            test_block_without_key_should_not_deliver_pre_signatures(key_id);
        }
    }

    fn test_block_without_key_should_not_deliver_pre_signatures(key_id: MasterPublicKeyId) {
        let mut rng = reproducible_rng();
        let (mut idkg_payload, env, _) = set_up_idkg_payload(
            &mut rng,
            subnet_test_id(1),
            /*nodes_count=*/ 8,
            vec![key_id.clone()],
            /*should_create_key_transcript=*/ false,
        );

        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::AllNodesAsDealersAndReceivers,
            &mut rng,
        );
        let key_transcript = generate_key_transcript(
            &env,
            &dealers,
            &receivers,
            algorithm_for_key_id(&key_id),
            &mut rng,
        );
        let key_transcript_ref =
            UnmaskedTranscript::try_from((Height::from(0), &key_transcript)).unwrap();
        add_available_pre_signatures_with_key_transcript(
            &mut idkg_payload,
            key_transcript_ref,
            &key_id,
        );

        let block = make_block(Some(idkg_payload));
        let delivered_ids = get_pre_signature_ids_to_deliver(&block);

        assert_eq!(delivered_ids.get(&key_id), Some(&BTreeSet::default()));
    }
}
