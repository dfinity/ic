//! Common utils for the ECDSA implementation.

use crate::ecdsa::complaints::{EcdsaTranscriptLoader, TranscriptLoadStatus};
use ic_ic00_types::EcdsaKeyId;
use ic_interfaces::consensus_pool::ConsensusBlockChain;
use ic_interfaces::ecdsa::{EcdsaChangeAction, EcdsaChangeSet, EcdsaPool};
use ic_protobuf::registry::subnet::v1 as pb;
use ic_types::consensus::ecdsa::QuadrupleId;
use ic_types::consensus::{
    ecdsa::{
        EcdsaBlockReader, EcdsaMessage, IDkgTranscriptParamsRef, RequestId,
        ThresholdEcdsaSigInputsRef, TranscriptLookupError, TranscriptRef,
    },
    HasHeight,
};
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgTranscript, IDkgTranscriptOperation, InitialIDkgDealings,
};
use ic_types::Height;
use std::collections::BTreeSet;
use std::convert::TryInto;
use std::sync::Arc;

pub(crate) struct EcdsaBlockReaderImpl {
    chain: Arc<dyn ConsensusBlockChain>,
}

impl EcdsaBlockReaderImpl {
    pub(crate) fn new(chain: Arc<dyn ConsensusBlockChain>) -> Self {
        Self { chain }
    }
}

impl EcdsaBlockReader for EcdsaBlockReaderImpl {
    fn tip_height(&self) -> Height {
        self.chain.tip().height()
    }

    fn requested_transcripts(&self) -> Box<dyn Iterator<Item = &IDkgTranscriptParamsRef> + '_> {
        self.chain
            .tip()
            .payload
            .as_ref()
            .as_ecdsa()
            .map_or(Box::new(std::iter::empty()), |ecdsa_payload| {
                ecdsa_payload.iter_transcript_configs_in_creation()
            })
    }

    fn quadruples_in_creation(&self) -> Box<dyn Iterator<Item = &QuadrupleId> + '_> {
        self.chain
            .tip()
            .payload
            .as_ref()
            .as_ecdsa()
            .map_or(Box::new(std::iter::empty()), |ecdsa_payload| {
                Box::new(ecdsa_payload.quadruples_in_creation.keys())
            })
    }

    fn requested_signatures(
        &self,
    ) -> Box<dyn Iterator<Item = (&RequestId, &ThresholdEcdsaSigInputsRef)> + '_> {
        self.chain
            .tip()
            .payload
            .as_ref()
            .as_ecdsa()
            .map_or(Box::new(std::iter::empty()), |payload| {
                Box::new(payload.ongoing_signatures.iter())
            })
    }

    fn active_transcripts(&self) -> BTreeSet<TranscriptRef> {
        self.chain
            .tip()
            .payload
            .as_ref()
            .as_ecdsa()
            .map_or(BTreeSet::new(), |payload| payload.active_transcripts())
    }

    fn source_subnet_xnet_transcripts(
        &self,
    ) -> Box<dyn Iterator<Item = &IDkgTranscriptParamsRef> + '_> {
        // TODO: chain iters for multiple key_id support
        self.chain
            .tip()
            .payload
            .as_ref()
            .as_ecdsa()
            .map_or(Box::new(std::iter::empty()), |ecdsa_payload| {
                ecdsa_payload.iter_xnet_transcripts_source_subnet()
            })
    }

    fn target_subnet_xnet_transcripts(
        &self,
    ) -> Box<dyn Iterator<Item = &IDkgTranscriptParamsRef> + '_> {
        // TODO: chain iters for multiple key_id support
        self.chain
            .tip()
            .payload
            .as_ref()
            .as_ecdsa()
            .map_or(Box::new(std::iter::empty()), |ecdsa_payload| {
                ecdsa_payload.iter_xnet_transcripts_target_subnet()
            })
    }

    fn transcript(
        &self,
        transcript_ref: &TranscriptRef,
    ) -> Result<IDkgTranscript, TranscriptLookupError> {
        let ecdsa_payload = match self.chain.get_block_by_height(transcript_ref.height) {
            Ok(block) => {
                if let Some(ecdsa_payload) = block.payload.as_ref().as_ecdsa() {
                    ecdsa_payload
                } else {
                    return Err(format!(
                        "transcript(): chain look up failed {:?}: EcdsaPayload not found",
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

        ecdsa_payload
            .idkg_transcripts
            .get(&transcript_ref.transcript_id)
            .ok_or(format!(
                "transcript(): missing idkg_transcript: {:?}",
                transcript_ref
            ))
            .map(|entry| entry.clone())
    }
}

/// Load the given transcripts
/// Returns None if all the transcripts could be loaded successfully.
/// Otherwise, returns the complaint change set to be added to the pool
pub(crate) fn load_transcripts(
    ecdsa_pool: &dyn EcdsaPool,
    transcript_loader: &dyn EcdsaTranscriptLoader,
    transcripts: &[&IDkgTranscript],
) -> Option<EcdsaChangeSet> {
    let mut new_complaints = Vec::new();
    for transcript in transcripts {
        match transcript_loader.load_transcript(ecdsa_pool, transcript) {
            TranscriptLoadStatus::Success => (),
            TranscriptLoadStatus::Failure => return Some(Default::default()),
            TranscriptLoadStatus::Complaints(complaints) => {
                for complaint in complaints {
                    new_complaints.push(EcdsaChangeAction::AddToValidated(
                        EcdsaMessage::EcdsaComplaint(complaint),
                    ));
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
pub(crate) fn transcript_op_summary(op: &IDkgTranscriptOperation) -> String {
    match op {
        IDkgTranscriptOperation::Random => "Random".to_string(),
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

/// Inspect ecdsa_initializations field in the CUPContent.
/// Return key_id and dealings.
pub(crate) fn inspect_ecdsa_initializations(
    ecdsa_initializations: &[pb::EcdsaInitialization],
) -> Result<Option<(EcdsaKeyId, InitialIDkgDealings)>, String> {
    if !ecdsa_initializations.is_empty() {
        if ecdsa_initializations.len() > 1 {
            Err(
                "More than one ecdsa_initialization is not supported. Choose the first one."
                    .to_string(),
            )
        } else {
            let ecdsa_init = ecdsa_initializations
                .iter()
                .next()
                .expect("Error: Ecdsa Initialization is None")
                .clone();
            match (
                (ecdsa_init
                    .key_id
                    .expect("Error: Failed to find key_id in ecdsa_initializations"))
                .try_into(),
                (&ecdsa_init
                    .dealings
                    .expect("Error: Failed to find dealings in ecdsa_initializations"))
                    .try_into(),
            ) {
                (Ok(key_id), Ok(dealings)) => Ok(Some((key_id, dealings))),
                (Err(err), _) => Err(format!(
                    "Error reading ECDSA key_id: {:?}. Setting ecdsa_summary to None.",
                    err
                )),
                (_, Err(err)) => Err(format!(
                    "Error reading ECDSA dealings: {:?}. Setting ecdsa_summary to None.",
                    err
                )),
            }
        }
    } else {
        Ok(None)
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use crate::ecdsa::complaints::{
        EcdsaComplaintHandlerImpl, EcdsaTranscriptLoader, TranscriptLoadStatus,
    };
    use crate::ecdsa::pre_signer::{EcdsaPreSignerImpl, EcdsaTranscriptBuilder};
    use crate::ecdsa::signer::{EcdsaSignatureBuilder, EcdsaSignerImpl};
    use assert_matches::assert_matches;
    use ic_artifact_pool::ecdsa_pool::EcdsaPoolImpl;
    use ic_config::artifact_pool::ArtifactPoolConfig;
    use ic_consensus_mocks::{dependencies, Dependencies};
    use ic_consensus_utils::crypto::ConsensusCrypto;
    use ic_crypto_temp_crypto::TempCryptoComponent;
    use ic_crypto_test_utils_canister_threshold_sigs::dummy_values::dummy_idkg_dealing_for_tests;
    use ic_crypto_test_utils_canister_threshold_sigs::dummy_values::dummy_initial_idkg_dealing_for_tests;
    use ic_crypto_test_utils_canister_threshold_sigs::{
        CanisterThresholdSigTestEnvironment, IDkgParticipants, IntoBuilder,
    };
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_ic00_types::EcdsaKeyId;
    use ic_interfaces::ecdsa::{EcdsaChangeAction, EcdsaPool};
    use ic_logger::ReplicaLogger;
    use ic_metrics::MetricsRegistry;
    use ic_protobuf::registry::subnet::v1::EcdsaInitialization;
    use ic_test_utilities::consensus::fake::*;
    use ic_test_utilities::types::ids::{node_test_id, NODE_1, NODE_2};
    use ic_types::artifact::EcdsaMessageId;
    use ic_types::consensus::ecdsa::{
        ecdsa_msg_id, EcdsaBlockReader, EcdsaComplaint, EcdsaComplaintContent, EcdsaKeyTranscript,
        EcdsaMessage, EcdsaOpening, EcdsaOpeningContent, EcdsaPayload, EcdsaReshareRequest,
        EcdsaSigShare, EcdsaUIDGenerator, IDkgTranscriptAttributes, IDkgTranscriptOperationRef,
        IDkgTranscriptParamsRef, KeyTranscriptCreation, MaskedTranscript, PreSignatureQuadrupleRef,
        QuadrupleId, RequestId, ReshareOfMaskedParams, ThresholdEcdsaSigInputsRef,
        TranscriptLookupError, TranscriptRef, UnmaskedTranscript,
    };
    use ic_types::crypto::canister_threshold_sig::idkg::{
        IDkgComplaint, IDkgDealing, IDkgDealingSupport, IDkgMaskedTranscriptOrigin, IDkgOpening,
        IDkgReceivers, IDkgTranscript, IDkgTranscriptId, IDkgTranscriptOperation,
        IDkgTranscriptParams, IDkgTranscriptType, IDkgUnmaskedTranscriptOrigin, SignedIDkgDealing,
    };
    use ic_types::crypto::canister_threshold_sig::{
        ExtendedDerivationPath, ThresholdEcdsaCombinedSignature, ThresholdEcdsaSigInputs,
        ThresholdEcdsaSigShare,
    };
    use ic_types::crypto::AlgorithmId;
    use ic_types::malicious_behaviour::MaliciousBehaviour;
    use ic_types::signature::*;
    use ic_types::{Height, NodeId, PrincipalId, Randomness, RegistryVersion, SubnetId};
    use rand::{CryptoRng, Rng};
    use std::collections::{BTreeMap, BTreeSet};
    use std::convert::TryFrom;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};

    use super::inspect_ecdsa_initializations;

    pub(crate) fn empty_response() -> ic_types::messages::Response {
        ic_types::messages::Response {
            originator: ic_types::CanisterId::ic_00(),
            respondent: ic_types::CanisterId::ic_00(),
            originator_reply_callback: ic_types::messages::CallbackId::from(0),
            // Execution is responsible for burning the appropriate cycles
            // before pushing the new context, so any remaining cycles can
            // be refunded to the canister.
            refund: ic_types::Cycles::new(0),
            response_payload: ic_types::messages::Payload::Data(vec![]),
        }
    }

    #[derive(Clone)]
    pub(crate) struct TestTranscriptParams {
        pub(crate) idkg_transcripts: BTreeMap<TranscriptRef, IDkgTranscript>,
        pub(crate) transcript_params_ref: IDkgTranscriptParamsRef,
    }

    impl From<&IDkgTranscriptParams> for TestTranscriptParams {
        fn from(params: &IDkgTranscriptParams) -> Self {
            let h = params.transcript_id().source_height();
            TestTranscriptParams {
                idkg_transcripts: Default::default(),
                transcript_params_ref: IDkgTranscriptParamsRef {
                    transcript_id: params.transcript_id(),
                    dealers: params.dealers().get().clone(),
                    receivers: params.receivers().get().clone(),
                    registry_version: params.registry_version(),
                    algorithm_id: params.algorithm_id(),
                    operation_type_ref: match params.operation_type() {
                        IDkgTranscriptOperation::Random => IDkgTranscriptOperationRef::Random,
                        IDkgTranscriptOperation::ReshareOfMasked(t) => {
                            IDkgTranscriptOperationRef::ReshareOfMasked(
                                MaskedTranscript::try_from((h, t)).unwrap(),
                            )
                        }
                        IDkgTranscriptOperation::ReshareOfUnmasked(t) => {
                            IDkgTranscriptOperationRef::ReshareOfUnmasked(
                                UnmaskedTranscript::try_from((h, t)).unwrap(),
                            )
                        }
                        IDkgTranscriptOperation::UnmaskedTimesMasked(t1, t2) => {
                            IDkgTranscriptOperationRef::UnmaskedTimesMasked(
                                UnmaskedTranscript::try_from((h, t1)).unwrap(),
                                MaskedTranscript::try_from((h, t2)).unwrap(),
                            )
                        }
                    },
                },
            }
        }
    }

    pub(crate) struct TestSigInputs {
        pub(crate) idkg_transcripts: BTreeMap<TranscriptRef, IDkgTranscript>,
        pub(crate) sig_inputs_ref: ThresholdEcdsaSigInputsRef,
    }

    impl From<&ThresholdEcdsaSigInputs> for TestSigInputs {
        fn from(inputs: &ThresholdEcdsaSigInputs) -> TestSigInputs {
            let height = Height::from(0);
            let quad = inputs.presig_quadruple();
            let key = inputs.key_transcript();
            let transcripts = vec![
                quad.kappa_times_lambda().clone(),
                quad.kappa_unmasked().clone(),
                quad.key_times_lambda().clone(),
                quad.lambda_masked().clone(),
                key.clone(),
            ];
            let mut idkg_transcripts: BTreeMap<TranscriptRef, IDkgTranscript> = Default::default();
            for t in transcripts {
                idkg_transcripts.insert(TranscriptRef::new(height, t.transcript_id), t);
            }
            let sig_inputs_ref = ThresholdEcdsaSigInputsRef {
                derivation_path: inputs.derivation_path().clone(),
                hashed_message: inputs.hashed_message().try_into().unwrap(),
                nonce: *inputs.nonce(),
                presig_quadruple_ref: PreSignatureQuadrupleRef {
                    kappa_unmasked_ref: UnmaskedTranscript::try_from((
                        height,
                        quad.kappa_unmasked(),
                    ))
                    .unwrap(),
                    lambda_masked_ref: MaskedTranscript::try_from((height, quad.lambda_masked()))
                        .unwrap(),
                    kappa_times_lambda_ref: MaskedTranscript::try_from((
                        height,
                        quad.kappa_times_lambda(),
                    ))
                    .unwrap(),
                    key_times_lambda_ref: MaskedTranscript::try_from((
                        height,
                        quad.key_times_lambda(),
                    ))
                    .unwrap(),
                },
                key_transcript_ref: UnmaskedTranscript::try_from((height, key)).unwrap(),
            };
            TestSigInputs {
                idkg_transcripts,
                sig_inputs_ref,
            }
        }
    }

    // Test implementation of EcdsaBlockReader to inject the test transcript params
    #[derive(Clone, Default)]
    pub(crate) struct TestEcdsaBlockReader {
        height: Height,
        requested_transcripts: Vec<IDkgTranscriptParamsRef>,
        source_subnet_xnet_transcripts: Vec<IDkgTranscriptParamsRef>,
        target_subnet_xnet_transcripts: Vec<IDkgTranscriptParamsRef>,
        requested_signatures: Vec<(RequestId, ThresholdEcdsaSigInputsRef)>,
        idkg_transcripts: BTreeMap<TranscriptRef, IDkgTranscript>,
        fail_to_resolve: bool,
    }

    impl TestEcdsaBlockReader {
        pub(crate) fn new() -> Self {
            Default::default()
        }

        pub(crate) fn for_pre_signer_test(
            height: Height,
            transcript_params: Vec<TestTranscriptParams>,
        ) -> Self {
            let mut idkg_transcripts = BTreeMap::new();
            let mut requested_transcripts = Vec::new();
            for t in transcript_params {
                for (transcript_ref, transcript) in t.idkg_transcripts {
                    idkg_transcripts.insert(transcript_ref, transcript);
                }
                requested_transcripts.push(t.transcript_params_ref);
            }

            Self {
                height,
                requested_transcripts,
                idkg_transcripts,
                ..Default::default()
            }
        }

        pub(crate) fn for_signer_test(
            height: Height,
            sig_inputs: Vec<(RequestId, TestSigInputs)>,
        ) -> Self {
            let mut idkg_transcripts = BTreeMap::new();
            let mut requested_signatures = Vec::new();
            for (request_id, sig_inputs) in sig_inputs {
                for (transcript_ref, transcript) in sig_inputs.idkg_transcripts {
                    idkg_transcripts.insert(transcript_ref, transcript);
                }
                requested_signatures.push((request_id, sig_inputs.sig_inputs_ref));
            }

            Self {
                height,
                requested_signatures,
                idkg_transcripts,
                ..Default::default()
            }
        }

        pub(crate) fn for_complainer_test(height: Height, active_refs: Vec<TranscriptRef>) -> Self {
            let mut idkg_transcripts = BTreeMap::new();
            for transcript_ref in active_refs {
                idkg_transcripts.insert(
                    transcript_ref,
                    create_transcript(transcript_ref.transcript_id, &[NODE_2]),
                );
            }

            Self {
                height,
                idkg_transcripts,
                ..Default::default()
            }
        }

        pub(crate) fn with_source_subnet_xnet_transcripts(
            mut self,
            refs: Vec<IDkgTranscriptParamsRef>,
        ) -> Self {
            self.source_subnet_xnet_transcripts = refs;
            self
        }

        pub(crate) fn with_target_subnet_xnet_transcripts(
            mut self,
            refs: Vec<IDkgTranscriptParamsRef>,
        ) -> Self {
            self.target_subnet_xnet_transcripts = refs;
            self
        }

        pub(crate) fn with_fail_to_resolve(mut self) -> Self {
            self.fail_to_resolve = true;
            self
        }

        pub(crate) fn add_transcript(
            &mut self,
            transcript_ref: TranscriptRef,
            transcript: IDkgTranscript,
        ) {
            self.idkg_transcripts.insert(transcript_ref, transcript);
        }
    }

    impl EcdsaBlockReader for TestEcdsaBlockReader {
        fn tip_height(&self) -> Height {
            self.height
        }

        fn requested_transcripts(&self) -> Box<dyn Iterator<Item = &IDkgTranscriptParamsRef> + '_> {
            Box::new(self.requested_transcripts.iter())
        }

        fn quadruples_in_creation(&self) -> Box<dyn Iterator<Item = &QuadrupleId> + '_> {
            Box::new(std::iter::empty())
        }

        fn requested_signatures(
            &self,
        ) -> Box<dyn Iterator<Item = (&RequestId, &ThresholdEcdsaSigInputsRef)> + '_> {
            Box::new(
                self.requested_signatures
                    .iter()
                    .map(|(id, sig_inputs)| (id, sig_inputs)),
            )
        }

        fn source_subnet_xnet_transcripts(
            &self,
        ) -> Box<dyn Iterator<Item = &IDkgTranscriptParamsRef> + '_> {
            Box::new(self.source_subnet_xnet_transcripts.iter())
        }

        fn target_subnet_xnet_transcripts(
            &self,
        ) -> Box<dyn Iterator<Item = &IDkgTranscriptParamsRef> + '_> {
            Box::new(self.target_subnet_xnet_transcripts.iter())
        }

        fn transcript(
            &self,
            transcript_ref: &TranscriptRef,
        ) -> Result<IDkgTranscript, TranscriptLookupError> {
            if self.fail_to_resolve {
                return Err("Test transcript resolve failure".into());
            }
            self.idkg_transcripts
                .get(transcript_ref)
                .cloned()
                .ok_or(format!(
                    "transcript(): {:?} not found in idkg_transcripts",
                    transcript_ref
                ))
        }

        fn active_transcripts(&self) -> BTreeSet<TranscriptRef> {
            self.idkg_transcripts.keys().cloned().collect()
        }
    }

    pub(crate) enum TestTranscriptLoadStatus {
        Success,
        Failure,
        Complaints,
    }

    pub(crate) struct TestEcdsaTranscriptLoader {
        load_transcript_result: TestTranscriptLoadStatus,
        returned_complaints: Mutex<Vec<EcdsaComplaint>>,
    }

    impl TestEcdsaTranscriptLoader {
        pub(crate) fn new(load_transcript_result: TestTranscriptLoadStatus) -> Self {
            Self {
                load_transcript_result,
                returned_complaints: Mutex::new(Vec::new()),
            }
        }

        pub(crate) fn returned_complaints(&self) -> Vec<EcdsaComplaint> {
            let complaints = self.returned_complaints.lock().unwrap();
            let mut ret = Vec::new();
            for complaint in complaints.iter() {
                ret.push(complaint.clone());
            }
            ret
        }
    }

    impl EcdsaTranscriptLoader for TestEcdsaTranscriptLoader {
        fn load_transcript(
            &self,
            _ecdsa_pool: &dyn EcdsaPool,
            transcript: &IDkgTranscript,
        ) -> TranscriptLoadStatus {
            match self.load_transcript_result {
                TestTranscriptLoadStatus::Success => TranscriptLoadStatus::Success,
                TestTranscriptLoadStatus::Failure => TranscriptLoadStatus::Failure,
                TestTranscriptLoadStatus::Complaints => {
                    let complaint = create_complaint(transcript.transcript_id, NODE_1, NODE_1);
                    self.returned_complaints
                        .lock()
                        .unwrap()
                        .push(complaint.clone());
                    TranscriptLoadStatus::Complaints(vec![complaint])
                }
            }
        }
    }

    impl Default for TestEcdsaTranscriptLoader {
        fn default() -> Self {
            Self::new(TestTranscriptLoadStatus::Success)
        }
    }

    pub(crate) struct TestEcdsaTranscriptBuilder {
        transcripts: Mutex<BTreeMap<IDkgTranscriptId, IDkgTranscript>>,
        dealings: Mutex<BTreeMap<IDkgTranscriptId, Vec<SignedIDkgDealing>>>,
    }

    impl TestEcdsaTranscriptBuilder {
        pub(crate) fn new() -> Self {
            Self {
                transcripts: Mutex::new(BTreeMap::new()),
                dealings: Mutex::new(BTreeMap::new()),
            }
        }

        pub(crate) fn add_transcript(
            &self,
            transcript_id: IDkgTranscriptId,
            transcript: IDkgTranscript,
        ) {
            self.transcripts
                .lock()
                .unwrap()
                .insert(transcript_id, transcript);
        }

        pub(crate) fn add_dealings(
            &self,
            transcript_id: IDkgTranscriptId,
            dealings: Vec<SignedIDkgDealing>,
        ) {
            self.dealings
                .lock()
                .unwrap()
                .insert(transcript_id, dealings);
        }
    }

    impl EcdsaTranscriptBuilder for TestEcdsaTranscriptBuilder {
        fn get_completed_transcript(
            &self,
            transcript_id: IDkgTranscriptId,
        ) -> Option<IDkgTranscript> {
            self.transcripts
                .lock()
                .unwrap()
                .get(&transcript_id)
                .cloned()
        }

        fn get_validated_dealings(
            &self,
            transcript_id: IDkgTranscriptId,
        ) -> Vec<SignedIDkgDealing> {
            self.dealings
                .lock()
                .unwrap()
                .get(&transcript_id)
                .cloned()
                .unwrap_or_default()
        }
    }

    pub(crate) struct TestEcdsaSignatureBuilder {
        pub(crate) signatures: BTreeMap<RequestId, ThresholdEcdsaCombinedSignature>,
    }

    impl TestEcdsaSignatureBuilder {
        pub(crate) fn new() -> Self {
            Self {
                signatures: BTreeMap::new(),
            }
        }
    }

    impl EcdsaSignatureBuilder for TestEcdsaSignatureBuilder {
        fn get_completed_signature(
            &self,
            request_id: &RequestId,
        ) -> Option<ThresholdEcdsaCombinedSignature> {
            self.signatures.get(request_id).cloned()
        }
    }

    // Sets up the dependencies and creates the pre signer
    pub(crate) fn create_pre_signer_dependencies_with_crypto(
        pool_config: ArtifactPoolConfig,
        logger: ReplicaLogger,
        consensus_crypto: Option<Arc<dyn ConsensusCrypto>>,
    ) -> (EcdsaPoolImpl, EcdsaPreSignerImpl) {
        let metrics_registry = MetricsRegistry::new();
        let Dependencies {
            pool,
            replica_config: _,
            membership: _,
            registry: _,
            crypto,
            ..
        } = dependencies(pool_config.clone(), 1);

        // need to make sure subnet matches the transcript
        let dummy_id = create_transcript_id(0);
        let pre_signer = EcdsaPreSignerImpl::new(
            NODE_1,
            *dummy_id.source_subnet(),
            pool.get_block_cache(),
            consensus_crypto.unwrap_or(crypto),
            metrics_registry.clone(),
            logger.clone(),
            MaliciousBehaviour::new(false).malicious_flags,
        );
        let ecdsa_pool = EcdsaPoolImpl::new(pool_config, logger, metrics_registry);

        (ecdsa_pool, pre_signer)
    }

    // Sets up the dependencies and creates the pre signer
    pub(crate) fn create_pre_signer_dependencies(
        pool_config: ArtifactPoolConfig,
        logger: ReplicaLogger,
    ) -> (EcdsaPoolImpl, EcdsaPreSignerImpl) {
        create_pre_signer_dependencies_with_crypto(pool_config, logger, None)
    }

    // Sets up the dependencies and creates the signer
    pub(crate) fn create_signer_dependencies_with_crypto(
        pool_config: ArtifactPoolConfig,
        logger: ReplicaLogger,
        consensus_crypto: Option<Arc<dyn ConsensusCrypto>>,
    ) -> (EcdsaPoolImpl, EcdsaSignerImpl) {
        let metrics_registry = MetricsRegistry::new();
        let Dependencies {
            pool,
            replica_config: _,
            membership: _,
            registry: _,
            crypto,
            ..
        } = dependencies(pool_config.clone(), 1);

        let signer = EcdsaSignerImpl::new(
            NODE_1,
            pool.get_block_cache(),
            consensus_crypto.unwrap_or(crypto),
            metrics_registry.clone(),
            logger.clone(),
        );
        let ecdsa_pool = EcdsaPoolImpl::new(pool_config, logger, metrics_registry);

        (ecdsa_pool, signer)
    }

    // Sets up the dependencies and creates the signer
    pub(crate) fn create_signer_dependencies(
        pool_config: ArtifactPoolConfig,
        logger: ReplicaLogger,
    ) -> (EcdsaPoolImpl, EcdsaSignerImpl) {
        create_signer_dependencies_with_crypto(pool_config, logger, None)
    }

    // Sets up the dependencies and creates the complaint handler
    pub(crate) fn create_complaint_dependencies_with_crypto_and_node_id(
        pool_config: ArtifactPoolConfig,
        logger: ReplicaLogger,
        consensus_crypto: Option<Arc<dyn ConsensusCrypto>>,
        node_id: NodeId,
    ) -> (EcdsaPoolImpl, EcdsaComplaintHandlerImpl) {
        let metrics_registry = MetricsRegistry::new();
        let Dependencies {
            pool,
            replica_config: _,
            membership: _,
            registry: _,
            crypto,
            ..
        } = dependencies(pool_config.clone(), 1);

        let complaint_handler = EcdsaComplaintHandlerImpl::new(
            node_id,
            pool.get_block_cache(),
            consensus_crypto.unwrap_or(crypto),
            metrics_registry.clone(),
            logger.clone(),
        );
        let ecdsa_pool = EcdsaPoolImpl::new(pool_config, logger, metrics_registry);

        (ecdsa_pool, complaint_handler)
    }

    pub(crate) fn create_complaint_dependencies(
        pool_config: ArtifactPoolConfig,
        logger: ReplicaLogger,
    ) -> (EcdsaPoolImpl, EcdsaComplaintHandlerImpl) {
        create_complaint_dependencies_with_crypto(pool_config, logger, None)
    }

    pub(crate) fn create_complaint_dependencies_with_crypto(
        pool_config: ArtifactPoolConfig,
        logger: ReplicaLogger,
        crypto: Option<Arc<dyn ConsensusCrypto>>,
    ) -> (EcdsaPoolImpl, EcdsaComplaintHandlerImpl) {
        create_complaint_dependencies_with_crypto_and_node_id(pool_config, logger, crypto, NODE_1)
    }

    // Creates a TranscriptID for tests
    pub(crate) fn create_transcript_id(id: u64) -> IDkgTranscriptId {
        use ic_crypto_test_utils_canister_threshold_sigs::dummy_values::dummy_idkg_transcript_id_for_tests;
        dummy_idkg_transcript_id_for_tests(id)
    }

    // Creates a TranscriptID for tests
    pub(crate) fn create_transcript_id_with_height(id: u64, height: Height) -> IDkgTranscriptId {
        let subnet = SubnetId::from(PrincipalId::new_subnet_test_id(314159));
        IDkgTranscriptId::new(subnet, id, height)
    }

    // Creates a test transcript
    pub(crate) fn create_transcript(
        transcript_id: IDkgTranscriptId,
        receiver_list: &[NodeId],
    ) -> IDkgTranscript {
        let mut receivers = BTreeSet::new();
        receiver_list.iter().for_each(|val| {
            receivers.insert(*val);
        });
        IDkgTranscript {
            transcript_id,
            receivers: IDkgReceivers::new(receivers).unwrap(),
            registry_version: RegistryVersion::from(1),
            verified_dealings: BTreeMap::new(),
            transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            internal_transcript_raw: vec![],
        }
    }

    /// Creates a test transcript param with registry version 0
    pub(crate) fn create_transcript_param(
        transcript_id: IDkgTranscriptId,
        dealer_list: &[NodeId],
        receiver_list: &[NodeId],
    ) -> TestTranscriptParams {
        create_transcript_param_with_registry_version(
            transcript_id,
            dealer_list,
            receiver_list,
            RegistryVersion::from(0),
        )
    }

    /// Creates a test transcript param for a specific registry version
    pub(crate) fn create_transcript_param_with_registry_version(
        transcript_id: IDkgTranscriptId,
        dealer_list: &[NodeId],
        receiver_list: &[NodeId],
        registry_version: RegistryVersion,
    ) -> TestTranscriptParams {
        let mut dealers = BTreeSet::new();
        dealer_list.iter().for_each(|val| {
            dealers.insert(*val);
        });
        let mut receivers = BTreeSet::new();
        receiver_list.iter().for_each(|val| {
            receivers.insert(*val);
        });

        // The random transcript
        let random_transcript_id = create_transcript_id(transcript_id.id() * 214365 + 1);
        let random_transcript = create_transcript(random_transcript_id, dealer_list);
        let random_masked =
            MaskedTranscript::try_from((Height::new(0), &random_transcript)).unwrap();
        let mut idkg_transcripts = BTreeMap::new();
        idkg_transcripts.insert(*random_masked.as_ref(), random_transcript);

        let attrs = IDkgTranscriptAttributes::new(
            dealers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            registry_version,
        );

        // The transcript that points to the random transcript
        let transcript_params_ref = ReshareOfMaskedParams::new(
            transcript_id,
            receivers,
            registry_version,
            &attrs,
            random_masked,
        );

        TestTranscriptParams {
            idkg_transcripts,
            transcript_params_ref: transcript_params_ref.as_ref().clone(),
        }
    }

    // Creates a ReshareUnmasked transcript params to reshare the given transcript
    pub(crate) fn create_reshare_unmasked_transcript_param(
        unmasked_transcript: &IDkgTranscript,
        receiver_list: &[NodeId],
        registry_version: RegistryVersion,
    ) -> IDkgTranscriptParams {
        let reshare_unmasked_id = unmasked_transcript.transcript_id.increment();
        let dealers = unmasked_transcript.receivers.get().clone();
        let receivers = receiver_list.iter().fold(BTreeSet::new(), |mut acc, node| {
            acc.insert(*node);
            acc
        });

        IDkgTranscriptParams::new(
            reshare_unmasked_id,
            dealers,
            receivers,
            registry_version,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_transcript.clone()),
        )
        .unwrap()
    }

    /// Return a valid transcript for random sharing created by the first node of the environment
    pub(crate) fn create_valid_transcript<R: Rng + CryptoRng>(
        env: &CanisterThresholdSigTestEnvironment,
        rng: &mut R,
    ) -> (NodeId, IDkgTranscriptParams, IDkgTranscript) {
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            rng,
        );
        let dealings = env.nodes.create_and_verify_signed_dealings(&params);
        let dealings = env
            .nodes
            .support_dealings_from_all_receivers(dealings, &params);
        let dealer = env.nodes.dealers(&params).next().expect("Empty dealers");
        let idkg_transcript = dealer.create_transcript_or_panic(&params, &dealings);
        (dealer.id(), params, idkg_transcript)
    }

    /// Return a corrupt transcript for random sharing by changing ciphertexts intended
    /// for the first node of the environment
    pub(crate) fn create_corrupted_transcript<R: CryptoRng + Rng>(
        env: &CanisterThresholdSigTestEnvironment,
        rng: &mut R,
    ) -> (NodeId, IDkgTranscriptParams, IDkgTranscript) {
        let (node_id, params, mut transcript) = create_valid_transcript(env, rng);
        let to_corrupt = *transcript.verified_dealings.keys().next().unwrap();
        let complainer_index = params.receiver_index(node_id).unwrap();
        let signed_dealing = transcript.verified_dealings.get_mut(&to_corrupt).unwrap();
        let mut rng = rand::thread_rng();
        let builder = signed_dealing.content.clone().into_builder();
        signed_dealing.content = builder
            .corrupt_internal_dealing_raw_by_changing_ciphertexts(&[complainer_index], &mut rng)
            .build();
        (node_id, params, transcript)
    }

    pub(crate) fn get_dealings_and_support(
        env: &CanisterThresholdSigTestEnvironment,
        params: &IDkgTranscriptParams,
    ) -> (BTreeMap<NodeId, SignedIDkgDealing>, Vec<IDkgDealingSupport>) {
        let dealings = env.nodes.create_and_verify_signed_dealings(params);
        let supports = dealings
            .iter()
            .flat_map(|(_, dealing)| {
                env.nodes.receivers(&params).map(|signer| {
                    let c: Arc<dyn ConsensusCrypto> = signer.crypto();
                    let sig_share = c
                        .sign(dealing, signer.id(), params.registry_version())
                        .unwrap();

                    IDkgDealingSupport {
                        transcript_id: params.transcript_id(),
                        dealer_id: dealing.dealer_id(),
                        dealing_hash: ic_types::crypto::crypto_hash(dealing),
                        sig_share,
                    }
                })
            })
            .collect();

        (dealings, supports)
    }

    // Creates a test dealing
    fn create_dealing_content(transcript_id: IDkgTranscriptId) -> IDkgDealing {
        let mut idkg_dealing = dummy_idkg_dealing_for_tests();
        idkg_dealing.transcript_id = transcript_id;
        idkg_dealing
    }

    // Creates a test signed dealing
    pub(crate) fn create_dealing(
        transcript_id: IDkgTranscriptId,
        dealer_id: NodeId,
    ) -> SignedIDkgDealing {
        SignedIDkgDealing {
            content: create_dealing_content(transcript_id),
            signature: BasicSignature::fake(dealer_id),
        }
    }

    // Creates a test signed dealing with internal payload
    pub(crate) fn create_dealing_with_payload<R: Rng + CryptoRng>(
        transcript_id: IDkgTranscriptId,
        dealer_id: NodeId,
        rng: &mut R,
    ) -> SignedIDkgDealing {
        let env = CanisterThresholdSigTestEnvironment::new(2, rng);
        let (dealers, receivers) =
            env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
        let params = env.params_for_random_sharing(
            &dealers,
            &receivers,
            AlgorithmId::ThresholdEcdsaSecp256k1,
            rng,
        );
        let dealer = env.nodes.dealers(&params).next().unwrap();
        let dealing = dealer.create_dealing_or_panic(&params);
        let mut content = create_dealing_content(transcript_id);
        content.internal_dealing_raw = dealing.content.internal_dealing_raw;
        SignedIDkgDealing {
            content,
            signature: BasicSignature::fake(dealer_id),
        }
    }

    // Creates a test dealing and a support for the dealing
    pub(crate) fn create_support(
        transcript_id: IDkgTranscriptId,
        dealer_id: NodeId,
        signer: NodeId,
    ) -> (SignedIDkgDealing, IDkgDealingSupport) {
        let dealing = SignedIDkgDealing {
            content: create_dealing_content(transcript_id),
            signature: BasicSignature::fake(dealer_id),
        };
        let support = IDkgDealingSupport {
            transcript_id,
            dealer_id,
            dealing_hash: ic_types::crypto::crypto_hash(&dealing),
            sig_share: BasicSignature::fake(signer),
        };
        (dealing, support)
    }

    // Creates a test signature input
    pub(crate) fn create_sig_inputs_with_height(caller: u8, height: Height) -> TestSigInputs {
        let transcript_id = |offset| {
            let val = caller as u64;
            create_transcript_id(val * 214365 + offset)
        };
        let receivers: BTreeSet<_> = vec![node_test_id(1)].into_iter().collect();
        let key_unmasked_id = transcript_id(50);
        let key_masked_id = transcript_id(40);
        let key_unmasked = IDkgTranscript {
            transcript_id: key_unmasked_id,
            receivers: IDkgReceivers::new(receivers.clone()).unwrap(),
            registry_version: RegistryVersion::from(1),
            verified_dealings: BTreeMap::new(),
            transcript_type: IDkgTranscriptType::Unmasked(
                IDkgUnmaskedTranscriptOrigin::ReshareMasked(key_masked_id),
            ),
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            internal_transcript_raw: vec![],
        };
        create_sig_inputs_with_args(caller, &receivers, key_unmasked, height)
    }

    // Creates a test signature input
    pub(crate) fn create_sig_inputs_with_args(
        caller: u8,
        receivers: &BTreeSet<NodeId>,
        key_unmasked: IDkgTranscript,
        height: Height,
    ) -> TestSigInputs {
        let transcript_id = |offset| {
            let val = caller as u64;
            create_transcript_id(val * 214365 + offset)
        };

        let kappa_masked_id = transcript_id(10);
        let kappa_unmasked_id = transcript_id(20);
        let lambda_masked_id = transcript_id(30);
        let key_unmasked_id = key_unmasked.transcript_id;
        let kappa_unmasked_times_lambda_masked_id = transcript_id(60);
        let key_unmasked_times_lambda_masked_id = transcript_id(70);
        let mut idkg_transcripts = BTreeMap::new();

        let kappa_masked = IDkgTranscript {
            transcript_id: kappa_masked_id,
            receivers: IDkgReceivers::new(receivers.clone()).unwrap(),
            registry_version: RegistryVersion::from(1),
            verified_dealings: BTreeMap::new(),
            transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            internal_transcript_raw: vec![],
        };
        let kappa_masked_ref = MaskedTranscript::try_from((height, &kappa_masked)).unwrap();
        idkg_transcripts.insert(*kappa_masked_ref.as_ref(), kappa_masked);

        let kappa_unmasked = IDkgTranscript {
            transcript_id: kappa_unmasked_id,
            receivers: IDkgReceivers::new(receivers.clone()).unwrap(),
            registry_version: RegistryVersion::from(1),
            verified_dealings: BTreeMap::new(),
            transcript_type: IDkgTranscriptType::Unmasked(
                IDkgUnmaskedTranscriptOrigin::ReshareMasked(kappa_masked_id),
            ),
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            internal_transcript_raw: vec![],
        };
        let kappa_unmasked_ref = UnmaskedTranscript::try_from((height, &kappa_unmasked)).unwrap();
        idkg_transcripts.insert(*kappa_unmasked_ref.as_ref(), kappa_unmasked);

        let lambda_masked = IDkgTranscript {
            transcript_id: lambda_masked_id,
            receivers: IDkgReceivers::new(receivers.clone()).unwrap(),
            registry_version: RegistryVersion::from(1),
            verified_dealings: BTreeMap::new(),
            transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            internal_transcript_raw: vec![],
        };
        let lambda_masked_ref = MaskedTranscript::try_from((height, &lambda_masked)).unwrap();
        idkg_transcripts.insert(*lambda_masked_ref.as_ref(), lambda_masked);

        let key_unmasked_ref = UnmaskedTranscript::try_from((height, &key_unmasked)).unwrap();
        idkg_transcripts.insert(*key_unmasked_ref.as_ref(), key_unmasked);

        let kappa_unmasked_times_lambda_masked = IDkgTranscript {
            transcript_id: kappa_unmasked_times_lambda_masked_id,
            receivers: IDkgReceivers::new(receivers.clone()).unwrap(),
            registry_version: RegistryVersion::from(1),
            verified_dealings: BTreeMap::new(),
            transcript_type: IDkgTranscriptType::Masked(
                IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(
                    kappa_unmasked_id,
                    lambda_masked_id,
                ),
            ),
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            internal_transcript_raw: vec![],
        };
        let kappa_unmasked_times_lambda_masked_ref =
            MaskedTranscript::try_from((height, &kappa_unmasked_times_lambda_masked)).unwrap();
        idkg_transcripts.insert(
            *kappa_unmasked_times_lambda_masked_ref.as_ref(),
            kappa_unmasked_times_lambda_masked,
        );

        let key_unmasked_times_lambda_masked = IDkgTranscript {
            transcript_id: key_unmasked_times_lambda_masked_id,
            receivers: IDkgReceivers::new(receivers.clone()).unwrap(),
            registry_version: RegistryVersion::from(1),
            verified_dealings: BTreeMap::new(),
            transcript_type: IDkgTranscriptType::Masked(
                IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(key_unmasked_id, lambda_masked_id),
            ),
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            internal_transcript_raw: vec![],
        };
        let key_unmasked_times_lambda_masked_ref =
            MaskedTranscript::try_from((height, &key_unmasked_times_lambda_masked)).unwrap();
        idkg_transcripts.insert(
            *key_unmasked_times_lambda_masked_ref.as_ref(),
            key_unmasked_times_lambda_masked,
        );

        let presig_quadruple_ref = PreSignatureQuadrupleRef::new(
            kappa_unmasked_ref,
            lambda_masked_ref,
            kappa_unmasked_times_lambda_masked_ref,
            key_unmasked_times_lambda_masked_ref,
        );
        let sig_inputs_ref = ThresholdEcdsaSigInputsRef::new(
            ExtendedDerivationPath {
                caller: PrincipalId::try_from(&vec![caller]).unwrap(),
                derivation_path: vec![],
            },
            [0u8; 32],
            Randomness::from([0_u8; 32]),
            presig_quadruple_ref,
            key_unmasked_ref,
        );

        TestSigInputs {
            idkg_transcripts,
            sig_inputs_ref,
        }
    }

    // Creates a test signature input
    pub(crate) fn create_sig_inputs(caller: u8) -> TestSigInputs {
        create_sig_inputs_with_height(caller, Height::new(0))
    }

    // Creates a test signature share
    pub(crate) fn create_signature_share_with_nonce(
        signer_id: NodeId,
        request_id: RequestId,
        nonce: u8,
    ) -> EcdsaSigShare {
        EcdsaSigShare {
            signer_id,
            request_id,
            share: ThresholdEcdsaSigShare {
                sig_share_raw: vec![nonce],
            },
        }
    }

    // Creates a test signature share
    pub(crate) fn create_signature_share(
        signer_id: NodeId,
        request_id: RequestId,
    ) -> EcdsaSigShare {
        create_signature_share_with_nonce(signer_id, request_id, 0)
    }

    pub(crate) fn create_complaint_with_nonce(
        transcript_id: IDkgTranscriptId,
        dealer_id: NodeId,
        complainer_id: NodeId,
        nonce: u8,
    ) -> EcdsaComplaint {
        let content = EcdsaComplaintContent {
            idkg_complaint: IDkgComplaint {
                transcript_id,
                dealer_id,
                internal_complaint_raw: vec![nonce],
            },
        };
        EcdsaComplaint {
            content,
            signature: BasicSignature::fake(complainer_id),
        }
    }

    // Creates a test signed complaint
    pub(crate) fn create_complaint(
        transcript_id: IDkgTranscriptId,
        dealer_id: NodeId,
        complainer_id: NodeId,
    ) -> EcdsaComplaint {
        create_complaint_with_nonce(transcript_id, dealer_id, complainer_id, 0)
    }

    // Creates a test signed opening
    pub(crate) fn create_opening_with_nonce(
        transcript_id: IDkgTranscriptId,
        dealer_id: NodeId,
        _complainer_id: NodeId,
        opener_id: NodeId,
        nonce: u8,
    ) -> EcdsaOpening {
        let content = EcdsaOpeningContent {
            idkg_opening: IDkgOpening {
                transcript_id,
                dealer_id,
                internal_opening_raw: vec![nonce],
            },
        };
        EcdsaOpening {
            content,
            signature: BasicSignature::fake(opener_id),
        }
    }

    // Creates a test signed opening
    pub(crate) fn create_opening(
        transcript_id: IDkgTranscriptId,
        dealer_id: NodeId,
        complainer_id: NodeId,
        opener_id: NodeId,
    ) -> EcdsaOpening {
        create_opening_with_nonce(transcript_id, dealer_id, complainer_id, opener_id, 0)
    }
    // Checks that the dealing with the given id is being added to the validated
    // pool
    pub(crate) fn is_dealing_added_to_validated(
        change_set: &[EcdsaChangeAction],
        transcript_id: &IDkgTranscriptId,
    ) -> bool {
        for action in change_set {
            if let EcdsaChangeAction::AddToValidated(EcdsaMessage::EcdsaSignedDealing(
                signed_dealing,
            )) = action
            {
                let dealing = signed_dealing.idkg_dealing();
                if dealing.transcript_id == *transcript_id && signed_dealing.dealer_id() == NODE_1 {
                    return true;
                }
            }
        }
        false
    }

    // Checks that the dealing support for the given dealing is being added to the
    // validated pool
    pub(crate) fn is_dealing_support_added_to_validated(
        change_set: &[EcdsaChangeAction],
        transcript_id: &IDkgTranscriptId,
        dealer_id: &NodeId,
    ) -> bool {
        for action in change_set {
            if let EcdsaChangeAction::AddToValidated(EcdsaMessage::EcdsaDealingSupport(support)) =
                action
            {
                if support.transcript_id == *transcript_id
                    && support.dealer_id == *dealer_id
                    && support.sig_share.signer == NODE_1
                {
                    return true;
                }
            }
        }
        false
    }

    // Checks that the complaint is being added to the validated pool
    pub(crate) fn is_complaint_added_to_validated(
        change_set: &[EcdsaChangeAction],
        transcript_id: &IDkgTranscriptId,
        dealer_id: &NodeId,
        complainer_id: &NodeId,
    ) -> bool {
        for action in change_set {
            if let EcdsaChangeAction::AddToValidated(EcdsaMessage::EcdsaComplaint(
                signed_complaint,
            )) = action
            {
                let complaint = signed_complaint.get();
                if complaint.idkg_complaint.transcript_id == *transcript_id
                    && complaint.idkg_complaint.dealer_id == *dealer_id
                    && signed_complaint.signature.signer == *complainer_id
                {
                    return true;
                }
            }
        }
        false
    }

    // Checks that the opening is being added to the validated pool
    pub(crate) fn is_opening_added_to_validated(
        change_set: &[EcdsaChangeAction],
        transcript_id: &IDkgTranscriptId,
        dealer_id: &NodeId,
        opener_id: &NodeId,
    ) -> bool {
        for action in change_set {
            if let EcdsaChangeAction::AddToValidated(EcdsaMessage::EcdsaOpening(signed_opening)) =
                action
            {
                let opening = signed_opening.get();
                if opening.idkg_opening.transcript_id == *transcript_id
                    && opening.idkg_opening.dealer_id == *dealer_id
                    && signed_opening.signature.signer == *opener_id
                {
                    return true;
                }
            }
        }
        false
    }

    // Checks that the signature share with the given request is being added to the
    // validated pool
    pub(crate) fn is_signature_share_added_to_validated(
        change_set: &[EcdsaChangeAction],
        request_id: &RequestId,
        requested_height: Height,
    ) -> bool {
        for action in change_set {
            if let EcdsaChangeAction::AddToValidated(EcdsaMessage::EcdsaSigShare(share)) = action {
                if share.request_id.height == requested_height
                    && share.request_id == *request_id
                    && share.signer_id == NODE_1
                {
                    return true;
                }
            }
        }
        false
    }

    // Checks that artifact is being moved from unvalidated to validated pool
    pub(crate) fn is_moved_to_validated(
        change_set: &[EcdsaChangeAction],
        msg_id: &EcdsaMessageId,
    ) -> bool {
        for action in change_set {
            if let EcdsaChangeAction::MoveToValidated(msg) = action {
                if ecdsa_msg_id(msg) == *msg_id {
                    return true;
                }
            }
        }
        false
    }

    // Checks that artifact is being removed from validated pool
    pub(crate) fn is_removed_from_validated(
        change_set: &[EcdsaChangeAction],
        msg_id: &EcdsaMessageId,
    ) -> bool {
        for action in change_set {
            if let EcdsaChangeAction::RemoveValidated(id) = action {
                if *id == *msg_id {
                    return true;
                }
            }
        }
        false
    }

    // Checks that artifact is being removed from unvalidated pool
    pub(crate) fn is_removed_from_unvalidated(
        change_set: &[EcdsaChangeAction],
        msg_id: &EcdsaMessageId,
    ) -> bool {
        for action in change_set {
            if let EcdsaChangeAction::RemoveUnvalidated(id) = action {
                if *id == *msg_id {
                    return true;
                }
            }
        }
        false
    }

    // Checks that artifact is being dropped as invalid
    pub(crate) fn is_handle_invalid(
        change_set: &[EcdsaChangeAction],
        msg_id: &EcdsaMessageId,
    ) -> bool {
        for action in change_set {
            if let EcdsaChangeAction::HandleInvalid(id, _) = action {
                if *id == *msg_id {
                    return true;
                }
            }
        }
        false
    }

    pub(crate) fn empty_ecdsa_payload(subnet_id: SubnetId) -> EcdsaPayload {
        EcdsaPayload {
            signature_agreements: BTreeMap::new(),
            ongoing_signatures: BTreeMap::new(),
            available_quadruples: BTreeMap::new(),
            quadruples_in_creation: BTreeMap::new(),
            uid_generator: EcdsaUIDGenerator::new(subnet_id, Height::new(0)),
            idkg_transcripts: BTreeMap::new(),
            ongoing_xnet_reshares: BTreeMap::new(),
            xnet_reshare_agreements: BTreeMap::new(),
            key_transcript: EcdsaKeyTranscript {
                current: None,
                next_in_creation: KeyTranscriptCreation::Begin,
                key_id: EcdsaKeyId::from_str("Secp256k1:some_key").unwrap(),
            },
        }
    }

    pub(crate) fn create_reshare_request(
        num_nodes: u64,
        registry_version: u64,
    ) -> EcdsaReshareRequest {
        EcdsaReshareRequest {
            key_id: EcdsaKeyId::from_str("Secp256k1:some_key").unwrap(),
            receiving_node_ids: (0..num_nodes).map(node_test_id).collect::<Vec<_>>(),
            registry_version: RegistryVersion::from(registry_version),
        }
    }

    pub(crate) fn crypto_without_keys() -> Arc<dyn ConsensusCrypto> {
        TempCryptoComponent::builder().build_arc()
    }

    #[test]
    fn test_inspect_ecdsa_initializations() {
        let mut rng = reproducible_rng();
        let initial_dealings = dummy_initial_idkg_dealing_for_tests(&mut rng);
        let key_id = EcdsaKeyId::from_str("Secp256k1:some_key").unwrap();
        let ecdsa_init = EcdsaInitialization {
            key_id: Some((&key_id).into()),
            dealings: Some((&initial_dealings).into()),
        };

        let res = inspect_ecdsa_initializations(&[ecdsa_init.clone(), ecdsa_init.clone()]);
        assert_matches!(res, Err(_));

        let res = inspect_ecdsa_initializations(&[ecdsa_init]);
        assert_matches!(res, Ok(Some(_)));

        let res = inspect_ecdsa_initializations(&[]);
        assert_matches!(res, Ok(None));
    }
}
