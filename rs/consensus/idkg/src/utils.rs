//! Common utils for the IDKG implementation.

use crate::{
    complaints::{IDkgTranscriptLoader, TranscriptLoadStatus},
    metrics::{IDkgPayloadMetrics, IDkgPayloadStats},
};
use ic_consensus_utils::{RoundRobin, pool_reader::PoolReader, range_len};
use ic_crypto::get_master_public_key_from_transcript;
use ic_interfaces::{
    consensus_pool::ConsensusBlockChain,
    idkg::{IDkgChangeAction, IDkgChangeSet, IDkgPool},
};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{ReplicaLogger, error, warn};
use ic_management_canister_types_private::MasterPublicKeyId;
use ic_protobuf::registry::subnet::v1 as pb;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_registry_subnet_features::ChainKeyConfig;
use ic_replicated_state::metadata_state::subnet_call_context_manager::{
    SignWithThresholdContext, ThresholdArguments,
};
use ic_types::{
    Height, RegistryVersion, SubnetId,
    batch::{AvailablePreSignatures, ConsensusResponse},
    consensus::{
        Block, HasHeight,
        idkg::{
            CompletedSignature, HasIDkgMasterPublicKeyId, IDkgBlockReader, IDkgMasterPublicKeyId,
            IDkgMessage, IDkgPayload, IDkgTranscriptParamsRef, PreSigId, RequestId,
            TranscriptLookupError, TranscriptRef,
            common::{BuildSignatureInputsError, ThresholdSigInputs},
        },
    },
    crypto::{
        canister_threshold_sig::{
            MasterPublicKey, ThresholdEcdsaSigInputs, ThresholdSchnorrSigInputs,
            idkg::{IDkgTranscript, IDkgTranscriptOperation, InitialIDkgDealings},
        },
        vetkd::{VetKdArgs, VetKdDerivationContextRef},
    },
    messages::CallbackId,
    registry::RegistryClientError,
};
use rayon::{ThreadPool, ThreadPoolBuilder};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    convert::TryInto,
    fmt::{self, Display, Formatter},
    sync::Arc,
};

pub const CRITICAL_ERROR_IDKG_RESOLVE_TRANSCRIPT_REFS: &str = "idkg_resolve_transcript_refs_error";

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

    fn transcript_as_ref(
        &self,
        transcript_ref: &TranscriptRef,
    ) -> Result<&IDkgTranscript, TranscriptLookupError> {
        let idkg_payload = match self.chain.get_block_by_height(transcript_ref.height) {
            Ok(block) => {
                if let Some(idkg_payload) = block.payload.as_ref().as_idkg() {
                    idkg_payload
                } else {
                    return Err(format!(
                        "transcript(): chain look up failed {transcript_ref:?}: IDkgPayload not found"
                    ));
                }
            }
            Err(err) => {
                return Err(format!(
                    "transcript(): chain look up failed {transcript_ref:?}: {err:?}"
                ));
            }
        };

        idkg_payload
            .idkg_transcripts
            .get(&transcript_ref.transcript_id)
            .ok_or(format!(
                "transcript(): missing idkg_transcript: {transcript_ref:?}"
            ))
    }

    fn iter_above(&self, height: Height) -> Box<dyn Iterator<Item = &IDkgPayload> + '_> {
        Box::new(
            self.chain
                .iter_above(height)
                .flat_map(|block| block.payload.as_ref().as_idkg()),
        )
    }
}

pub(super) fn block_chain_reader(
    pool_reader: &PoolReader<'_>,
    start_height: Height,
    parent_block: Block,
    idkg_payload_metrics: Option<&IDkgPayloadMetrics>,
    log: &ReplicaLogger,
) -> Result<IDkgBlockReaderImpl, InvalidChainCacheError> {
    block_chain_cache(pool_reader, start_height, parent_block)
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
    start_height: Height,
    end: Block,
) -> Result<Arc<dyn ConsensusBlockChain>, InvalidChainCacheError> {
    let end_height = end.height();
    let expected_len = range_len(start_height, end_height);
    let chain = pool_reader.pool().build_block_chain(start_height, end);
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
            start_height,
            end_height,
            chain.tip().height(),
            pool_reader.get_notarized_height(),
            pool_reader.get_finalized_height(),
            pool_reader.get_catch_up_height()
        )))
    }
}

/// Helper to build threshold signature inputs from the context
pub(super) fn build_signature_inputs<'a>(
    callback_id: CallbackId,
    context: &'a SignWithThresholdContext,
) -> Result<(RequestId, ThresholdSigInputs<'a>), BuildSignatureInputsError> {
    match &context.args {
        ThresholdArguments::Ecdsa(args) => {
            let matched_data = args
                .pre_signature
                .as_ref()
                .ok_or(BuildSignatureInputsError::ContextIncomplete)?;
            let request_id = RequestId {
                callback_id,
                height: matched_data.height,
            };
            let nonce_ref = context
                .nonce
                .as_ref()
                .ok_or(BuildSignatureInputsError::ContextIncomplete)?;
            let inputs = ThresholdSigInputs::Ecdsa(
                ThresholdEcdsaSigInputs::new(
                    context.request.sender.get_ref(),
                    &context.derivation_path,
                    &args.message_hash,
                    nonce_ref,
                    matched_data.pre_signature.as_ref(),
                    matched_data.key_transcript.as_ref(),
                )
                .map_err(BuildSignatureInputsError::ThresholdEcdsaSigInputsCreationError)?,
            );
            Ok((request_id, inputs))
        }
        ThresholdArguments::Schnorr(args) => {
            let matched_data = args
                .pre_signature
                .as_ref()
                .ok_or(BuildSignatureInputsError::ContextIncomplete)?;
            let request_id = RequestId {
                callback_id,
                height: matched_data.height,
            };
            let nonce_ref = context
                .nonce
                .as_ref()
                .ok_or(BuildSignatureInputsError::ContextIncomplete)?;
            let inputs = ThresholdSigInputs::Schnorr(
                ThresholdSchnorrSigInputs::new(
                    context.request.sender.get_ref(),
                    &context.derivation_path,
                    &args.message,
                    args.taproot_tree_root.as_ref().map(|v| v.as_slice()),
                    nonce_ref,
                    matched_data.pre_signature.as_ref(),
                    matched_data.key_transcript.as_ref(),
                )
                .map_err(BuildSignatureInputsError::ThresholdSchnorrSigInputsCreationError)?,
            );
            Ok((request_id, inputs))
        }
        ThresholdArguments::VetKd(args) => {
            let request_id = RequestId {
                callback_id,
                height: args.height,
            };
            debug_assert_eq!(context.derivation_path.len(), 1);
            const EMPTY_VEC_REF: &Vec<u8> = &vec![];
            let inputs = ThresholdSigInputs::VetKd(VetKdArgs {
                context: VetKdDerivationContextRef {
                    caller: context.request.sender.get_ref(),
                    context: context.derivation_path.first().unwrap_or(EMPTY_VEC_REF),
                },
                ni_dkg_id: &args.ni_dkg_id,
                input: &args.input,
                transport_public_key: &args.transport_public_key,
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
            .map_err(|err| format!("Error reading ECDSA key_id: {err:?}"))?;

        let dealings = ecdsa_init
            .dealings
            .as_ref()
            .ok_or("Failed to find dealings in ecdsa_initializations")?
            .try_into()
            .map_err(|err| format!("Error reading ECDSA dealings: {err:?}"))?;

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
            .map_err(|err| format!("Error reading Master public key_id: {err:?}"))?;

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
                );
            }
        };

        let dealings = dealings
            .try_into()
            .map_err(|err| format!("Error reading initial IDkg dealings: {err:?}"))?;

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
            .filter(|key_config| {
                key_config
                    .pre_signatures_to_create_in_advance
                    .unwrap_or_default()
                    != 0
            })
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
    mut stats: Option<&mut IDkgPayloadStats>,
) -> (
    BTreeMap<MasterPublicKeyId, MasterPublicKey>,
    BTreeMap<IDkgMasterPublicKeyId, AvailablePreSignatures>,
) {
    let Some(idkg_payload) = current_block.payload.as_ref().as_idkg() else {
        return (BTreeMap::new(), BTreeMap::new());
    };

    let chain = pool
        .pool()
        .build_block_chain(last_dkg_summary_block.height(), current_block.clone());
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
                match get_master_public_key_from_transcript(&key_transcript) {
                    Ok(public_key) => {
                        public_keys.insert(key_id.clone().into(), public_key);
                    }
                    Err(err) => {
                        if let Some(ref mut stats) = stats {
                            stats.transcript_resolution_errors += 1;
                        }
                        error!(
                            log,
                            "{}: Failed to retrieve IDKg subnet master public key of key id {}: {:?}",
                            CRITICAL_ERROR_IDKG_RESOLVE_TRANSCRIPT_REFS,
                            key_id,
                            err
                        );
                    }
                }
                pre_signatures.insert(
                    key_id.clone(),
                    AvailablePreSignatures {
                        key_transcript,
                        pre_signatures: BTreeMap::new(),
                    },
                );
            }
            Err(err) => {
                if let Some(ref mut stats) = stats {
                    stats.transcript_resolution_errors += 1;
                }
                error!(
                    log,
                    "{}: Failed to translate key transcript ref {:?} of key {}: {:?}",
                    CRITICAL_ERROR_IDKG_RESOLVE_TRANSCRIPT_REFS,
                    transcript_ref,
                    key_id,
                    err
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
            match pre_signature.translate(&block_reader) {
                Ok(pre_sig) => {
                    entry.pre_signatures.insert(*pre_sig_id, pre_sig);
                }
                Err(err) => {
                    if let Some(ref mut stats) = stats {
                        stats.transcript_resolution_errors += 1;
                    }
                    error!(
                        log,
                        "{}: Failed to translate Pre-signature ref of key {}: {:?}",
                        CRITICAL_ERROR_IDKG_RESOLVE_TRANSCRIPT_REFS,
                        key_id,
                        err
                    );
                }
            }
        }
    }

    (public_keys, pre_signatures)
}

/// A struct that maintains a round-robin schedule of calls to be made,
/// and a watermark of the last purge.
pub(crate) struct IDkgSchedule<T: Ord + Copy> {
    schedule: RoundRobin,
    pub(crate) last_purge: RefCell<T>,
}

impl<T: Ord + Copy> IDkgSchedule<T> {
    pub(crate) fn new(init: T) -> Self {
        Self {
            schedule: RoundRobin::default(),
            last_purge: RefCell::new(init),
        }
    }

    /// Call the next function in the schedule.
    pub(crate) fn call_next<C>(&self, calls: &[&dyn Fn() -> Vec<C>]) -> Vec<C> {
        self.schedule.call_next(calls)
    }

    /// Updates the latest purge watermark, and returns true if
    /// it increased. Otherwise returns false.
    pub(crate) fn update_last_purge(&self, new: T) -> bool {
        let prev = self.last_purge.replace(new);
        new > prev
    }
}

/// Builds a rayon thread pool with the given number of threads.
pub(crate) fn build_thread_pool(num_threads: usize) -> Arc<ThreadPool> {
    Arc::new(
        ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .expect("Failed to create thread pool"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{
        IDkgPayloadTestHelper, create_available_pre_signature_with_key_transcript_and_height,
        set_up_idkg_payload,
    };
    use assert_matches::assert_matches;
    use ic_config::artifact_pool::ArtifactPoolConfig;
    use ic_consensus_mocks::{Dependencies, dependencies};
    use ic_crypto_test_utils_canister_threshold_sigs::{
        IDkgParticipants, dummy_values::dummy_initial_idkg_dealing_for_tests,
        generate_key_transcript,
    };
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_logger::no_op_logger;
    use ic_management_canister_types_private::{EcdsaKeyId, SchnorrKeyId, VetKdKeyId};
    use ic_protobuf::registry::subnet::v1::EcdsaInitialization;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_subnet_features::KeyConfig;
    use ic_test_utilities_consensus::{fake::Fake, idkg::*};
    use ic_test_utilities_registry::{SubnetRecordBuilder, add_subnet_record};
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::{
        batch::ValidationContext,
        consensus::{
            BlockPayload, Payload, SummaryPayload,
            dkg::DkgSummary,
            idkg::{IDkgPayload, UnmaskedTranscript},
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

        inspect_idkg_chain_key_initializations(
            std::slice::from_ref(&ecdsa_init),
            std::slice::from_ref(&chain_key_init_2),
        )
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
                    pre_signatures_to_create_in_advance: Some(1),
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
                pre_signatures_to_create_in_advance: Some(1),
                max_queue_size: 3,
            };
            let key_config_2 = KeyConfig {
                key_id: MasterPublicKeyId::Schnorr(
                    SchnorrKeyId::from_str("Ed25519:some_key_2").unwrap(),
                ),
                pre_signatures_to_create_in_advance: Some(1),
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
                    pre_signatures_to_create_in_advance: Some(0),
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

    #[test]
    fn test_get_chain_key_config_if_enabled_malformed_with_pre_sigs_to_create_for_ecdsa_being_none()
    {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let malformed_chain_key_config = ChainKeyConfig {
                key_configs: vec![KeyConfig {
                    key_id: MasterPublicKeyId::Ecdsa(
                        EcdsaKeyId::from_str("Secp256k1:some_key").unwrap(),
                    ),
                    pre_signatures_to_create_in_advance: None,
                    max_queue_size: 3,
                }],
                ..ChainKeyConfig::default()
            };
            let (subnet_id, registry, version) =
                set_up_get_chain_key_config_test(&malformed_chain_key_config, pool_config);

            let config =
                get_idkg_chain_key_config_if_enabled(subnet_id, version, registry.as_ref());

            assert_matches!(config, Err(RegistryClientError::DecodeError{ error })
              if error.contains("failed with Missing required struct field: KeyConfig::pre_signatures_to_create_in_advance")
            );
        })
    }

    #[test]
    fn test_get_chain_key_config_if_enabled_malformed_with_pre_sigs_to_create_for_vetkd_being_some()
    {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let malformed_chain_key_config = ChainKeyConfig {
                key_configs: vec![KeyConfig {
                    key_id: MasterPublicKeyId::VetKd(
                        VetKdKeyId::from_str("Bls12_381_G2:some_key").unwrap(),
                    ),
                    pre_signatures_to_create_in_advance: Some(1),
                    max_queue_size: 3,
                }],
                ..ChainKeyConfig::default()
            };
            let (subnet_id, registry, version) =
                set_up_get_chain_key_config_test(&malformed_chain_key_config, pool_config);

            let config =
                get_idkg_chain_key_config_if_enabled(subnet_id, version, registry.as_ref());

            assert_matches!(config, Ok(None));
        })
    }

    fn add_available_pre_signatures_with_key_transcript(
        idkg_payload: &mut IDkgPayload,
        key_transcript: UnmaskedTranscript,
        key_id: &IDkgMasterPublicKeyId,
        height: Height,
    ) -> Vec<PreSigId> {
        let mut pre_sig_ids = vec![];
        for i in 0..10 {
            let id = create_available_pre_signature_with_key_transcript_and_height(
                idkg_payload,
                i,
                key_id.clone(),
                Some(key_transcript),
                height,
            );
            pre_sig_ids.push(id);
        }
        pre_sig_ids
    }

    fn make_block(idkg_payload: Option<IDkgPayload>, height: Height) -> Block {
        Block::new(
            CryptoHashOf::from(ic_types::crypto::CryptoHash(Vec::new())),
            Payload::new(
                ic_types::crypto::crypto_hash,
                BlockPayload::Summary(SummaryPayload {
                    dkg: DkgSummary::fake(),
                    idkg: idkg_payload,
                }),
            ),
            height,
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
        let height = Height::from(100);
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
            height,
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
                height,
            );

        let block = make_block(Some(idkg_payload), height);

        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies { pool, .. } = dependencies(pool_config, 1);
            let log = no_op_logger();
            let pool_reader = PoolReader::new(&pool);
            let mut stats = IDkgPayloadStats::default();
            let (public_keys, pre_signatures) = get_idkg_subnet_public_keys_and_pre_signatures(
                &block,
                &block,
                &pool_reader,
                &log,
                Some(&mut stats),
            );
            assert_eq!(stats.transcript_resolution_errors, 0);
            assert_eq!(public_keys.len(), 1);
            assert!(public_keys.contains_key(key_id.inner()));

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
            assert!(
                !pre_signature_ids_not_to_be_delivered
                    .into_iter()
                    .any(|pid| delivered_ids.contains(&pid))
            );
            assert_eq!(
                BTreeSet::from_iter(pre_signature_ids_to_be_delivered),
                delivered_ids
            );
        });
    }

    #[test]
    fn test_failure_to_resolve_should_increase_error_counter() {
        let key_id = fake_ecdsa_idkg_master_public_key_id();
        let mut rng = reproducible_rng();
        let transcript_ref_height = Height::from(101);
        let block_height = Height::from(100);
        let (mut idkg_payload, _, _) = set_up_idkg_payload(
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
        add_available_pre_signatures_with_key_transcript(
            &mut idkg_payload,
            current_key_transcript_ref.unmasked_transcript(),
            &key_id,
            transcript_ref_height,
        );
        let block = make_block(Some(idkg_payload), block_height);

        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies { pool, .. } = dependencies(pool_config, 1);
            let log = no_op_logger();
            let pool_reader = PoolReader::new(&pool);
            let mut stats = IDkgPayloadStats::default();
            let (public_keys, pre_signatures) = get_idkg_subnet_public_keys_and_pre_signatures(
                &block,
                &block,
                &pool_reader,
                &log,
                Some(&mut stats),
            );
            assert_eq!(stats.transcript_resolution_errors, 1);
            assert!(public_keys.is_empty());
            assert!(pre_signatures.is_empty());
        });
    }

    #[test]
    fn test_block_without_idkg_should_not_deliver_data() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies { pool, .. } = dependencies(pool_config, 1);
            let log = no_op_logger();
            let pool_reader = PoolReader::new(&pool);
            let block = make_block(None, Height::from(100));
            let mut stats = IDkgPayloadStats::default();
            let (public_keys, pre_signatures) = get_idkg_subnet_public_keys_and_pre_signatures(
                &block,
                &block,
                &pool_reader,
                &log,
                Some(&mut stats),
            );
            assert_eq!(stats.transcript_resolution_errors, 0);
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
        let height = Height::from(100);
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
            height,
        );

        let block = make_block(Some(idkg_payload), height);

        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies { pool, .. } = dependencies(pool_config, 1);
            let log = no_op_logger();
            let pool_reader = PoolReader::new(&pool);
            let mut stats = IDkgPayloadStats::default();
            let (public_keys, pre_signatures) = get_idkg_subnet_public_keys_and_pre_signatures(
                &block,
                &block,
                &pool_reader,
                &log,
                Some(&mut stats),
            );
            assert_eq!(stats.transcript_resolution_errors, 0);
            assert!(public_keys.is_empty());
            assert!(pre_signatures.is_empty());
        })
    }
}
