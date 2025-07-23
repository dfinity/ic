//! Common utils for the IDKG implementation.

use crate::{
    complaints::{IDkgTranscriptLoader, TranscriptLoadStatus},
    metrics::IDkgPayloadMetrics,
};
use ic_consensus_utils::pool_reader::PoolReader;
use ic_crypto::get_master_public_key_from_transcript;
use ic_interfaces::{
    consensus_pool::ConsensusBlockChain,
    idkg::{IDkgChangeAction, IDkgChangeSet, IDkgPool},
};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{warn, ReplicaLogger};
use ic_management_canister_types_private::MasterPublicKeyId;
use ic_protobuf::registry::subnet::v1 as pb;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_registry_subnet_features::ChainKeyConfig;
use ic_replicated_state::metadata_state::subnet_call_context_manager::{
    SignWithThresholdContext, ThresholdArguments,
};
use ic_types::{
    batch::{AvailablePreSignatures, ConsensusResponse},
    consensus::{
        idkg::{
            common::{PreSignatureRef, SignatureScheme, ThresholdSigInputsRef},
            ecdsa::ThresholdEcdsaSigInputsRef,
            schnorr::ThresholdSchnorrSigInputsRef,
            CompletedSignature, HasIDkgMasterPublicKeyId, IDkgBlockReader, IDkgMasterPublicKeyId,
            IDkgMessage, IDkgPayload, IDkgTranscriptParamsRef, PreSigId, RequestId,
            TranscriptLookupError, TranscriptRef,
        },
        Block, HasHeight,
    },
    crypto::{
        canister_threshold_sig::{
            idkg::{IDkgTranscript, IDkgTranscriptOperation, InitialIDkgDealings},
            MasterPublicKey,
        },
        vetkd::{VetKdArgs, VetKdDerivationContext},
        ExtendedDerivationPath,
    },
    messages::CallbackId,
    registry::RegistryClientError,
    Height, RegistryVersion, SubnetId,
};
use phantom_newtype::Id;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    convert::TryInto,
    fmt::{self, Display, Formatter},
    sync::Arc,
};

#[derive(Clone, PartialEq, Debug)]
pub struct InvalidChainCacheError(String);

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
    ) -> Box<dyn Iterator<Item = (PreSigId, IDkgMasterPublicKeyId)> + '_> {
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

#[derive(Debug)]
#[allow(dead_code)]
pub enum BuildSignatureInputsError {
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
    callback_id: CallbackId,
    context: &SignWithThresholdContext,
    block_reader: &dyn IDkgBlockReader,
) -> Result<(RequestId, ThresholdSigInputsRef), BuildSignatureInputsError> {
    match &context.args {
        ThresholdArguments::Ecdsa(args) => {
            let (pre_sig_id, height) = context
                .matched_pre_signature
                .ok_or(BuildSignatureInputsError::ContextIncomplete)?;
            let request_id = RequestId {
                callback_id,
                height,
            };
            let PreSignatureRef::Ecdsa(pre_sig) = block_reader
                .available_pre_signature(&pre_sig_id)
                .ok_or(BuildSignatureInputsError::MissingPreSignature(request_id))?
                .clone()
            else {
                return Err(BuildSignatureInputsError::SignatureSchemeMismatch(
                    request_id,
                    SignatureScheme::Schnorr,
                ));
            };
            let nonce = Id::from(
                context
                    .nonce
                    .ok_or(BuildSignatureInputsError::ContextIncomplete)?,
            );
            let inputs = ThresholdSigInputsRef::Ecdsa(ThresholdEcdsaSigInputsRef::new(
                ExtendedDerivationPath {
                    caller: context.request.sender.into(),
                    derivation_path: context.derivation_path.to_vec(),
                },
                args.message_hash,
                nonce,
                pre_sig,
            ));
            Ok((request_id, inputs))
        }
        ThresholdArguments::Schnorr(args) => {
            let (pre_sig_id, height) = context
                .matched_pre_signature
                .ok_or(BuildSignatureInputsError::ContextIncomplete)?;
            let request_id = RequestId {
                callback_id,
                height,
            };
            let PreSignatureRef::Schnorr(pre_sig) = block_reader
                .available_pre_signature(&pre_sig_id)
                .ok_or(BuildSignatureInputsError::MissingPreSignature(request_id))?
                .clone()
            else {
                return Err(BuildSignatureInputsError::SignatureSchemeMismatch(
                    request_id,
                    SignatureScheme::Ecdsa,
                ));
            };
            let nonce = Id::from(
                context
                    .nonce
                    .ok_or(BuildSignatureInputsError::ContextIncomplete)?,
            );
            let inputs = ThresholdSigInputsRef::Schnorr(ThresholdSchnorrSigInputsRef::new(
                ExtendedDerivationPath {
                    caller: context.request.sender.into(),
                    derivation_path: context.derivation_path.to_vec(),
                },
                args.message.clone(),
                nonce,
                pre_sig,
                args.taproot_tree_root.clone(),
            ));
            Ok((request_id, inputs))
        }
        ThresholdArguments::VetKd(args) => {
            let request_id = RequestId {
                callback_id,
                height: args.height,
            };
            let inputs = ThresholdSigInputsRef::VetKd(VetKdArgs {
                context: VetKdDerivationContext {
                    caller: context.request.sender.into(),
                    context: context.derivation_path.iter().flatten().cloned().collect(),
                },
                ni_dkg_id: args.ni_dkg_id.clone(),
                input: args.input.to_vec(),
                transport_public_key: args.transport_public_key.clone(),
            });
            Ok((request_id, inputs))
        }
    }
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
pub fn inspect_idkg_chain_key_initializations(
    ecdsa_initializations: &[pb::EcdsaInitialization],
    chain_key_initializations: &[pb::ChainKeyInitialization],
) -> Result<BTreeMap<IDkgMasterPublicKeyId, InitialIDkgDealings>, String> {
    let mut initial_dealings_per_key_id = BTreeMap::new();

    if !ecdsa_initializations.is_empty() && !chain_key_initializations.is_empty() {
        return Err("`chain_key_initialization` and `ecdsa_initializations` \
            cannot be present at the same time"
            .to_string());
    }

    for ecdsa_init in ecdsa_initializations {
        let ecdsa_key_id = ecdsa_init
            .key_id
            .clone()
            .ok_or("Failed to find key_id in ecdsa_initializations")?
            .try_into()
            .map_err(|err| format!("Error reading ECDSA key_id: {:?}", err))?;

        let dealings = ecdsa_init
            .dealings
            .as_ref()
            .ok_or("Failed to find dealings in ecdsa_initializations")?
            .try_into()
            .map_err(|err| format!("Error reading ECDSA dealings: {:?}", err))?;

        initial_dealings_per_key_id.insert(
            MasterPublicKeyId::Ecdsa(ecdsa_key_id).try_into().unwrap(),
            dealings,
        );
    }

    for chain_key_init in chain_key_initializations {
        let key_id: MasterPublicKeyId = chain_key_init
            .key_id
            .clone()
            .ok_or("Failed to find key_id in chain_key_initializations")?
            .try_into()
            .map_err(|err| format!("Error reading Master public key_id: {:?}", err))?;

        // Skip non-idkg keys
        let key_id = match key_id.try_into() {
            Ok(key_id) => key_id,
            Err(_) => continue,
        };

        let dealings = match &chain_key_init.initialization {
            Some(pb::chain_key_initialization::Initialization::Dealings(dealings)) => dealings,
            Some(pb::chain_key_initialization::Initialization::TranscriptRecord(_)) | None => {
                return Err(
                    "Error: Failed to find dealings in chain_key_initializations".to_string(),
                )
            }
        };

        let dealings = dealings
            .try_into()
            .map_err(|err| format!("Error reading initial IDkg dealings: {:?}", err))?;

        initial_dealings_per_key_id.insert(key_id, dealings);
    }

    Ok(initial_dealings_per_key_id)
}

pub fn get_idkg_chain_key_config_if_enabled(
    subnet_id: SubnetId,
    registry_version: RegistryVersion,
    registry_client: &dyn RegistryClient,
) -> Result<Option<ChainKeyConfig>, RegistryClientError> {
    if let Some(chain_key_config) =
        registry_client.get_chain_key_config(subnet_id, registry_version)?
    {
        let num_active_key_ids = chain_key_config
            .key_configs
            .iter()
            // Skip keys that don't need to run IDKG protocol
            .filter(|key_config| key_config.key_id.is_idkg_key())
            // A key that has `presignatures_to_create_in_advance` set to 0 is not active
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

/// Creates responses to `SignWithECDSA` and `SignWithSchnorr` system calls with the computed
/// signature.
pub fn generate_responses_to_signature_request_contexts(
    idkg_payload: &IDkgPayload,
) -> Vec<ConsensusResponse> {
    let mut consensus_responses = Vec::new();
    for completed in idkg_payload.signature_agreements.values() {
        if let CompletedSignature::Unreported(response) = completed {
            consensus_responses.push(response.clone());
        }
    }
    consensus_responses
}

/// This function returns the subnet master public keys to be added to the batch, if required.
/// We return the keys, if
/// - The block contains an IDKG payload with current key transcript ref, and
/// - the corresponding transcript exists in past blocks, and
/// - we can extract the threshold master public key from the transcript.
///
/// Otherwise no keys are returned.
///
/// Additionally, return the set of pre-signature IDs to be delivered in the batch of this block.
/// We deliver IDs of all available pre-signatures that were created using the current key transcripts.
pub fn get_idkg_subnet_public_keys_and_pre_signatures(
    current_block: &Block,
    last_dkg_summary_block: &Block,
    pool: &PoolReader<'_>,
    log: &ReplicaLogger,
) -> (
    BTreeMap<MasterPublicKeyId, MasterPublicKey>,
    BTreeMap<MasterPublicKeyId, AvailablePreSignatures>,
) {
    let Some(idkg_payload) = current_block.payload.as_ref().as_idkg() else {
        return (BTreeMap::new(), BTreeMap::new());
    };

    let chain = pool
        .pool()
        .build_block_chain(last_dkg_summary_block, current_block);
    let block_reader = IDkgBlockReaderImpl::new(chain);

    let mut public_keys = BTreeMap::new();
    let mut pre_signatures = BTreeMap::new();

    for (key_id, key_transcript) in &idkg_payload.key_transcripts {
        let Some(transcript_ref) = key_transcript
            .current
            .as_ref()
            .map(|unmasked| *unmasked.as_ref())
        else {
            continue;
        };

        match block_reader.transcript(&transcript_ref) {
            Ok(key_transcript) => {
                if let Some(public_key) = get_subnet_master_public_key(&key_transcript, log) {
                    public_keys.insert(key_id.clone().into(), public_key);
                }
                pre_signatures.insert(
                    key_id.clone().into(),
                    AvailablePreSignatures {
                        key_transcript,
                        pre_signatures: BTreeMap::new(),
                    },
                );
            }
            Err(err) => {
                warn!(
                    log,
                    "Failed to translate transcript ref {:?}: {:?}", transcript_ref, err
                );
            }
        }
    }

    for (pre_sig_id, pre_signature) in &idkg_payload.available_pre_signatures {
        let key_id = pre_signature.key_id();
        let Some(entry) = pre_signatures.get_mut(key_id.inner()) else {
            continue;
        };

        if entry.key_transcript.transcript_id == pre_signature.key_unmasked().as_ref().transcript_id
        {
            // TODO(CON-1545) Resolve and deliver full pre-signature
            entry.pre_signatures.insert(*pre_sig_id, None);
        }
    }

    (public_keys, pre_signatures)
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
    use crate::test_utils::{
        create_available_pre_signature_with_key_transcript, set_up_idkg_payload,
        IDkgPayloadTestHelper,
    };
    use ic_config::artifact_pool::ArtifactPoolConfig;
    use ic_consensus_mocks::{dependencies, Dependencies};
    use ic_crypto_test_utils_canister_threshold_sigs::{
        dummy_values::dummy_initial_idkg_dealing_for_tests, generate_key_transcript,
        IDkgParticipants,
    };
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_logger::no_op_logger;
    use ic_management_canister_types_private::{EcdsaKeyId, SchnorrKeyId};
    use ic_protobuf::registry::subnet::v1::EcdsaInitialization;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_subnet_features::KeyConfig;
    use ic_test_utilities_consensus::{fake::Fake, idkg::*};
    use ic_test_utilities_registry::{add_subnet_record, SubnetRecordBuilder};
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{
        batch::ValidationContext,
        consensus::{
            dkg::DkgSummary,
            idkg::{IDkgPayload, UnmaskedTranscript},
            BlockPayload, Payload, SummaryPayload,
        },
        crypto::{AlgorithmId, CryptoHashOf},
        time::UNIX_EPOCH,
    };
    use pb::ChainKeyInitialization;
    use std::str::FromStr;

    #[test]
    fn test_inspect_chain_key_initializations_no_keys() {
        let init = inspect_idkg_chain_key_initializations(&[], &[])
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

        let init = inspect_idkg_chain_key_initializations(&[ecdsa_init], &[])
            .expect("Should successfully get initializations");

        assert_eq!(
            init,
            BTreeMap::from([(
                MasterPublicKeyId::Ecdsa(key_id).try_into().unwrap(),
                initial_dealings
            )])
        );
    }

    #[test]
    fn test_inspect_chain_key_initializations_one_master_public_key() {
        let mut rng = reproducible_rng();
        let initial_dealings = dummy_initial_idkg_dealing_for_tests(
            ic_types::crypto::AlgorithmId::ThresholdEcdsaSecp256k1,
            &mut rng,
        );
        let key_id = fake_ecdsa_idkg_master_public_key_id();
        let chain_key_init = ChainKeyInitialization {
            key_id: Some((&MasterPublicKeyId::from(key_id.clone())).into()),
            initialization: Some(pb::chain_key_initialization::Initialization::Dealings(
                (&initial_dealings).into(),
            )),
        };

        let init = inspect_idkg_chain_key_initializations(&[], &[chain_key_init])
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
            initialization: Some(pb::chain_key_initialization::Initialization::Dealings(
                (&initial_dealings).into(),
            )),
        };
        let chain_key_init_2 = ChainKeyInitialization {
            key_id: Some((&master_key_id_2).into()),
            initialization: Some(pb::chain_key_initialization::Initialization::Dealings(
                (&initial_dealings_2).into(),
            )),
        };

        let init = inspect_idkg_chain_key_initializations(
            &[ecdsa_init.clone(), ecdsa_init_2.clone()],
            &[],
        )
        .expect("Should successfully inspect initializations");
        assert_eq!(
            init,
            BTreeMap::from([
                (
                    master_key_id.clone().try_into().unwrap(),
                    initial_dealings.clone()
                ),
                (
                    master_key_id_2.clone().try_into().unwrap(),
                    initial_dealings_2.clone()
                ),
            ])
        );

        let init = inspect_idkg_chain_key_initializations(
            &[],
            &[chain_key_init.clone(), chain_key_init_2.clone()],
        )
        .expect("Should successfully inspect initializations");
        assert_eq!(
            init,
            BTreeMap::from([
                (
                    master_key_id.clone().try_into().unwrap(),
                    initial_dealings.clone()
                ),
                (
                    master_key_id_2.clone().try_into().unwrap(),
                    initial_dealings_2.clone()
                ),
            ])
        );

        inspect_idkg_chain_key_initializations(&[ecdsa_init.clone()], &[chain_key_init_2.clone()])
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
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let chain_key_config_with_no_keys = ChainKeyConfig::default();
            let (subnet_id, registry, version) =
                set_up_get_chain_key_config_test(&chain_key_config_with_no_keys, pool_config);

            let config =
                get_idkg_chain_key_config_if_enabled(subnet_id, version, registry.as_ref())
                    .expect("Should successfully get the config");

            assert!(config.is_none());
        })
    }

    #[test]
    fn test_get_chain_key_config_if_enabled_one_key() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
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

            let config =
                get_idkg_chain_key_config_if_enabled(subnet_id, version, registry.as_ref())
                    .expect("Should successfully get the config");

            assert_eq!(config, Some(chain_key_config_with_one_key));
        })
    }

    #[test]
    fn test_get_chain_key_config_if_enabled_multiple_keys() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
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

            let config =
                get_idkg_chain_key_config_if_enabled(subnet_id, version, registry.as_ref())
                    .expect("Should successfully get the config");

            assert_eq!(
                config,
                Some(ChainKeyConfig {
                    key_configs: vec![key_config, key_config_2],
                    ..chain_key_config_with_two_keys
                })
            );
        })
    }

    #[test]
    fn test_get_chain_key_config_if_enabled_malformed() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
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

            let config =
                get_idkg_chain_key_config_if_enabled(subnet_id, version, registry.as_ref())
                    .expect("Should successfully get the config");

            assert!(config.is_none());
        })
    }

    fn add_available_pre_signatures_with_key_transcript(
        idkg_payload: &mut IDkgPayload,
        key_transcript: UnmaskedTranscript,
        key_id: &IDkgMasterPublicKeyId,
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
                    dkg: DkgSummary::fake(),
                    idkg: idkg_payload,
                }),
            ),
            Height::from(100),
            ic_types::consensus::Rank(456),
            ValidationContext {
                registry_version: RegistryVersion::from(99),
                certified_height: Height::from(42),
                time: UNIX_EPOCH,
            },
        )
    }

    #[test]
    fn test_get_idkg_subnet_public_keys_and_pre_signatures_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_idkg_algorithms() {
            println!("Running test for key ID {key_id}");
            test_get_idkg_subnet_public_keys_and_pre_signatures(key_id);
        }
    }

    fn test_get_idkg_subnet_public_keys_and_pre_signatures(key_id: IDkgMasterPublicKeyId) {
        let mut rng = reproducible_rng();
        let (mut idkg_payload, env, block_reader) = set_up_idkg_payload(
            &mut rng,
            subnet_test_id(1),
            /*nodes_count=*/ 8,
            vec![key_id.clone()],
            /*should_create_key_transcript=*/ true,
        );
        let current_key_transcript_ref = idkg_payload
            .single_key_transcript()
            .current
            .clone()
            .unwrap();
        let current_key_transcript = block_reader
            .transcript(current_key_transcript_ref.unmasked_transcript().as_ref())
            .unwrap();
        assert!(idkg_payload.idkg_transcripts.is_empty());
        idkg_payload.idkg_transcripts.insert(
            current_key_transcript.transcript_id,
            current_key_transcript.clone(),
        );
        assert_eq!(
            current_key_transcript.transcript_id,
            current_key_transcript_ref.transcript_id()
        );

        let pre_signature_ids_to_be_delivered = add_available_pre_signatures_with_key_transcript(
            &mut idkg_payload,
            current_key_transcript_ref.unmasked_transcript(),
            &key_id,
        );

        let (dealers, receivers) = env.choose_dealers_and_receivers(
            &IDkgParticipants::AllNodesAsDealersAndReceivers,
            &mut rng,
        );

        let old_key_transcript = generate_key_transcript(
            &env,
            &dealers,
            &receivers,
            AlgorithmId::from(key_id.inner()),
            &mut rng,
        );
        let old_key_transcript_ref =
            UnmaskedTranscript::try_from((Height::from(0), &old_key_transcript)).unwrap();
        let pre_signature_ids_not_to_be_delivered =
            add_available_pre_signatures_with_key_transcript(
                &mut idkg_payload,
                old_key_transcript_ref,
                &key_id,
            );

        let block = make_block(Some(idkg_payload));

        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies { pool, .. } = dependencies(pool_config, 1);
            let log = no_op_logger();
            let pool_reader = PoolReader::new(&pool);

            let (public_keys, pre_signatures) =
                get_idkg_subnet_public_keys_and_pre_signatures(&block, &block, &pool_reader, &log);

            assert_eq!(public_keys.len(), 1);
            assert!(public_keys.get(key_id.inner()).is_some());

            assert_eq!(pre_signatures.len(), 1);
            let delivered_pre_signatures = pre_signatures.get(key_id.inner()).unwrap();
            assert_eq!(
                delivered_pre_signatures.key_transcript,
                current_key_transcript
            );
            let delivered_ids: BTreeSet<_> = delivered_pre_signatures
                .pre_signatures
                .keys()
                .copied()
                .collect();
            assert!(!pre_signature_ids_not_to_be_delivered
                .into_iter()
                .any(|pid| delivered_ids.contains(&pid)));
            assert_eq!(
                BTreeSet::from_iter(pre_signature_ids_to_be_delivered),
                delivered_ids
            );
        });
    }

    #[test]
    fn test_block_without_idkg_should_not_deliver_data() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies { pool, .. } = dependencies(pool_config, 1);
            let log = no_op_logger();
            let pool_reader = PoolReader::new(&pool);
            let block = make_block(None);
            let (public_keys, pre_signatures) =
                get_idkg_subnet_public_keys_and_pre_signatures(&block, &block, &pool_reader, &log);

            assert!(public_keys.is_empty());
            assert!(pre_signatures.is_empty());
        })
    }

    #[test]
    fn test_block_without_key_should_not_deliver_data_all_algorithms() {
        for key_id in fake_master_public_key_ids_for_all_idkg_algorithms() {
            println!("Running test for key ID {key_id}");
            test_block_without_key_should_not_deliver_data(key_id);
        }
    }

    fn test_block_without_key_should_not_deliver_data(key_id: IDkgMasterPublicKeyId) {
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
            AlgorithmId::from(key_id.inner()),
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

        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies { pool, .. } = dependencies(pool_config, 1);
            let log = no_op_logger();
            let pool_reader = PoolReader::new(&pool);

            let (public_keys, pre_signatures) =
                get_idkg_subnet_public_keys_and_pre_signatures(&block, &block, &pool_reader, &log);

            assert!(public_keys.is_empty());
            assert!(pre_signatures.is_empty());
        })
    }
}
