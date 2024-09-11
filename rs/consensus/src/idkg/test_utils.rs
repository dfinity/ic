use crate::idkg::complaints::{
    IDkgComplaintHandlerImpl, IDkgTranscriptLoader, TranscriptLoadStatus,
};
use crate::idkg::pre_signer::{IDkgPreSignerImpl, IDkgTranscriptBuilder};
use crate::idkg::signer::{ThresholdSignatureBuilder, ThresholdSignerImpl};
use ic_artifact_pool::idkg_pool::IDkgPoolImpl;
use ic_config::artifact_pool::ArtifactPoolConfig;
use ic_consensus_mocks::{dependencies, Dependencies};
use ic_consensus_utils::crypto::ConsensusCrypto;
use ic_crypto_temp_crypto::TempCryptoComponent;
use ic_crypto_test_utils_canister_threshold_sigs::dummy_values::dummy_idkg_dealing_for_tests;
use ic_crypto_test_utils_canister_threshold_sigs::{
    setup_masked_random_params, CanisterThresholdSigTestEnvironment, IDkgParticipants, IntoBuilder,
};
use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
use ic_crypto_tree_hash::{LabeledTree, MixedHashTree};
use ic_interfaces::idkg::{IDkgChangeAction, IDkgPool};
use ic_interfaces_state_manager::{CertifiedStateSnapshot, Labeled};
use ic_logger::ReplicaLogger;
use ic_management_canister_types::{EcdsaKeyId, MasterPublicKeyId, SchnorrAlgorithm, SchnorrKeyId};
use ic_metrics::MetricsRegistry;
use ic_replicated_state::metadata_state::subnet_call_context_manager::{
    EcdsaArguments, IDkgDealingsContext, SchnorrArguments, SignWithThresholdContext,
    ThresholdArguments,
};
use ic_replicated_state::ReplicatedState;
use ic_test_artifact_pool::consensus_pool::TestConsensusPool;
use ic_test_utilities::state_manager::RefMockStateManager;
use ic_test_utilities_consensus::{fake::*, IDkgStatsNoOp};
use ic_test_utilities_state::ReplicatedStateBuilder;
use ic_test_utilities_types::ids::{node_test_id, NODE_1, NODE_2};
use ic_test_utilities_types::messages::RequestBuilder;
use ic_types::artifact::IDkgMessageId;
use ic_types::consensus::certification::Certification;
use ic_types::consensus::idkg::{
    self,
    common::{CombinedSignature, PreSignatureRef, ThresholdSigInputsRef},
    ecdsa::{PreSignatureQuadrupleRef, ThresholdEcdsaSigInputsRef},
    schnorr::{PreSignatureTranscriptRef, ThresholdSchnorrSigInputsRef},
    EcdsaSigShare, IDkgArtifactId, IDkgBlockReader, IDkgComplaintContent, IDkgMessage,
    IDkgOpeningContent, IDkgPayload, IDkgReshareRequest, IDkgTranscriptAttributes,
    IDkgTranscriptOperationRef, IDkgTranscriptParamsRef, KeyTranscriptCreation, MaskedTranscript,
    MasterKeyTranscript, PreSigId, RequestId, ReshareOfMaskedParams, SignedIDkgComplaint,
    SignedIDkgOpening, TranscriptAttributes, TranscriptLookupError, TranscriptRef,
    UnmaskedTranscript,
};
use ic_types::consensus::idkg::{HasMasterPublicKeyId, SchnorrSigShare};
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgComplaint, IDkgDealing, IDkgDealingSupport, IDkgMaskedTranscriptOrigin, IDkgOpening,
    IDkgReceivers, IDkgTranscript, IDkgTranscriptId, IDkgTranscriptOperation, IDkgTranscriptParams,
    IDkgTranscriptType, IDkgUnmaskedTranscriptOrigin, SignedIDkgDealing,
};
use ic_types::crypto::canister_threshold_sig::{
    ExtendedDerivationPath, ThresholdEcdsaSigInputs, ThresholdEcdsaSigShare,
    ThresholdSchnorrSigInputs, ThresholdSchnorrSigShare,
};
use ic_types::crypto::AlgorithmId;
use ic_types::messages::CallbackId;
use ic_types::time::UNIX_EPOCH;
use ic_types::{signature::*, time};
use ic_types::{Height, NodeId, PrincipalId, Randomness, RegistryVersion, SubnetId};
use rand::{CryptoRng, Rng};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use strum::IntoEnumIterator;

use super::utils::{algorithm_for_key_id, get_context_request_id};

pub(crate) fn dealings_context_from_reshare_request(
    request: idkg::IDkgReshareRequest,
) -> IDkgDealingsContext {
    IDkgDealingsContext {
        request: RequestBuilder::new().build(),
        key_id: request.key_id(),
        nodes: request.receiving_node_ids.into_iter().collect(),
        registry_version: request.registry_version,
        time: time::UNIX_EPOCH,
    }
}

pub(crate) fn empty_response() -> ic_types::batch::ConsensusResponse {
    ic_types::batch::ConsensusResponse::new(
        ic_types::messages::CallbackId::from(0),
        ic_types::messages::Payload::Data(vec![]),
    )
}

fn fake_signature_request_args(key_id: MasterPublicKeyId) -> ThresholdArguments {
    match key_id {
        MasterPublicKeyId::Ecdsa(key_id) => ThresholdArguments::Ecdsa(EcdsaArguments {
            key_id,
            message_hash: [0; 32],
        }),
        MasterPublicKeyId::Schnorr(key_id) => ThresholdArguments::Schnorr(SchnorrArguments {
            key_id,
            message: Arc::new(vec![1; 48]),
        }),
    }
}

pub fn fake_signature_request_context(
    key_id: MasterPublicKeyId,
    pseudo_random_id: [u8; 32],
) -> SignWithThresholdContext {
    SignWithThresholdContext {
        request: RequestBuilder::new().build(),
        args: fake_signature_request_args(key_id),
        derivation_path: vec![],
        batch_time: UNIX_EPOCH,
        pseudo_random_id,
        matched_pre_signature: None,
        nonce: None,
    }
}

pub fn fake_signature_request_context_with_pre_sig(
    id: u8,
    key_id: MasterPublicKeyId,
    pre_signature: Option<PreSigId>,
) -> (CallbackId, SignWithThresholdContext) {
    let context = SignWithThresholdContext {
        request: RequestBuilder::new().build(),
        args: fake_signature_request_args(key_id),
        derivation_path: vec![],
        batch_time: UNIX_EPOCH,
        pseudo_random_id: [id; 32],
        matched_pre_signature: pre_signature.map(|pid| (pid, Height::from(1))),
        nonce: None,
    };
    (CallbackId::from(id as u64), context)
}

pub fn fake_completed_signature_request_context(
    id: u8,
    key_id: MasterPublicKeyId,
    pre_signature_id: PreSigId,
) -> (CallbackId, SignWithThresholdContext) {
    let (_, context) = fake_signature_request_context_from_id(
        key_id,
        &RequestId {
            pre_signature_id,
            pseudo_random_id: [id; 32],
            height: Height::from(1),
        },
    );
    (CallbackId::from(id as u64), context)
}

pub fn fake_signature_request_context_from_id(
    key_id: MasterPublicKeyId,
    request_id: &RequestId,
) -> (CallbackId, SignWithThresholdContext) {
    let height = request_id.height;
    let pre_sig_id = request_id.pre_signature_id;
    let callback_id = CallbackId::from(pre_sig_id.id());
    let context = SignWithThresholdContext {
        request: RequestBuilder::new().build(),
        args: fake_signature_request_args(key_id),
        derivation_path: vec![],
        batch_time: UNIX_EPOCH,
        pseudo_random_id: request_id.pseudo_random_id,
        matched_pre_signature: Some((pre_sig_id, height)),
        nonce: Some([0; 32]),
    };
    (callback_id, context)
}

pub fn fake_state_with_signature_requests<T>(
    height: Height,
    contexts: T,
) -> FakeCertifiedStateSnapshot
where
    T: IntoIterator<Item = (CallbackId, SignWithThresholdContext)>,
{
    let mut state = ReplicatedStateBuilder::default().build();
    state
        .metadata
        .subnet_call_context_manager
        .sign_with_threshold_contexts = BTreeMap::from_iter(contexts);

    FakeCertifiedStateSnapshot {
        height,
        state: Arc::new(state),
    }
}

pub fn insert_test_sig_inputs<T>(
    block_reader: &mut TestIDkgBlockReader,
    idkg_payload: &mut IDkgPayload,
    inputs: T,
) where
    T: IntoIterator<Item = (PreSigId, TestSigInputs)>,
{
    for (pre_sig_id, inputs) in inputs {
        inputs
            .idkg_transcripts
            .iter()
            .for_each(|(transcript_ref, transcript)| {
                block_reader.add_transcript(*transcript_ref, transcript.clone())
            });
        idkg_payload
            .available_pre_signatures
            .insert(pre_sig_id, inputs.sig_inputs_ref.pre_signature());
        block_reader.add_available_pre_signature(pre_sig_id, inputs.sig_inputs_ref.pre_signature());
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
                    IDkgTranscriptOperation::RandomUnmasked => {
                        IDkgTranscriptOperationRef::RandomUnmasked
                    }
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

#[derive(Clone)]
pub(crate) struct TestSigInputs {
    pub(crate) idkg_transcripts: BTreeMap<TranscriptRef, IDkgTranscript>,
    pub(crate) sig_inputs_ref: ThresholdSigInputsRef,
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
                key_id: fake_ecdsa_key_id(),
                kappa_unmasked_ref: UnmaskedTranscript::try_from((height, quad.kappa_unmasked()))
                    .unwrap(),
                lambda_masked_ref: MaskedTranscript::try_from((height, quad.lambda_masked()))
                    .unwrap(),
                kappa_times_lambda_ref: MaskedTranscript::try_from((
                    height,
                    quad.kappa_times_lambda(),
                ))
                .unwrap(),
                key_times_lambda_ref: MaskedTranscript::try_from((height, quad.key_times_lambda()))
                    .unwrap(),
                key_unmasked_ref: UnmaskedTranscript::try_from((height, key)).unwrap(),
            },
        };
        TestSigInputs {
            idkg_transcripts,
            sig_inputs_ref: ThresholdSigInputsRef::Ecdsa(sig_inputs_ref),
        }
    }
}

impl From<&ThresholdSchnorrSigInputs> for TestSigInputs {
    fn from(inputs: &ThresholdSchnorrSigInputs) -> TestSigInputs {
        let height = Height::from(0);
        let pre_signature = inputs.presig_transcript();
        let key = inputs.key_transcript();
        let algorithm = schnorr_algorithm(key.algorithm_id);
        let transcripts = vec![pre_signature.blinder_unmasked().clone(), key.clone()];
        let mut idkg_transcripts: BTreeMap<TranscriptRef, IDkgTranscript> = Default::default();
        for t in transcripts {
            idkg_transcripts.insert(TranscriptRef::new(height, t.transcript_id), t);
        }
        let sig_inputs_ref = ThresholdSchnorrSigInputsRef {
            derivation_path: inputs.derivation_path().clone(),
            message: Arc::new(inputs.message().into()),
            nonce: *inputs.nonce(),
            presig_transcript_ref: PreSignatureTranscriptRef {
                key_id: fake_schnorr_key_id(algorithm),
                blinder_unmasked_ref: UnmaskedTranscript::try_from((
                    height,
                    pre_signature.blinder_unmasked(),
                ))
                .unwrap(),
                key_unmasked_ref: UnmaskedTranscript::try_from((height, key)).unwrap(),
            },
        };
        TestSigInputs {
            idkg_transcripts,
            sig_inputs_ref: ThresholdSigInputsRef::Schnorr(sig_inputs_ref),
        }
    }
}

// Test implementation of IDkgBlockReader to inject the test transcript params
#[derive(Clone, Default)]
pub(crate) struct TestIDkgBlockReader {
    height: Height,
    requested_transcripts: Vec<IDkgTranscriptParamsRef>,
    source_subnet_xnet_transcripts: Vec<IDkgTranscriptParamsRef>,
    target_subnet_xnet_transcripts: Vec<IDkgTranscriptParamsRef>,
    requested_signatures: Vec<(RequestId, ThresholdSigInputsRef)>,
    available_pre_signatures: BTreeMap<PreSigId, PreSignatureRef>,
    idkg_transcripts: BTreeMap<TranscriptRef, IDkgTranscript>,
    fail_to_resolve: bool,
}

impl TestIDkgBlockReader {
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
        let mut available_pre_signatures = BTreeMap::new();
        for (request_id, sig_inputs) in sig_inputs {
            for (transcript_ref, transcript) in sig_inputs.idkg_transcripts {
                idkg_transcripts.insert(transcript_ref, transcript);
            }
            available_pre_signatures.insert(
                request_id.pre_signature_id,
                sig_inputs.sig_inputs_ref.pre_signature(),
            );
            requested_signatures.push((request_id, sig_inputs.sig_inputs_ref));
        }

        Self {
            height,
            requested_signatures,
            available_pre_signatures,
            idkg_transcripts,
            ..Default::default()
        }
    }

    pub(crate) fn for_complainer_test(
        key_id: &MasterPublicKeyId,
        height: Height,
        active_refs: Vec<TranscriptRef>,
    ) -> Self {
        let mut idkg_transcripts = BTreeMap::new();
        for transcript_ref in active_refs {
            idkg_transcripts.insert(
                transcript_ref,
                create_transcript(key_id, transcript_ref.transcript_id, &[NODE_2]),
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

    pub(crate) fn add_available_pre_signature(
        &mut self,
        pre_signature_id: PreSigId,
        pre_signature: PreSignatureRef,
    ) {
        self.available_pre_signatures
            .insert(pre_signature_id, pre_signature);
    }

    pub(crate) fn requested_signatures(
        &self,
    ) -> Box<dyn Iterator<Item = (&RequestId, &ThresholdSigInputsRef)> + '_> {
        Box::new(
            self.requested_signatures
                .iter()
                .map(|(id, sig_inputs)| (id, sig_inputs)),
        )
    }
}

impl IDkgBlockReader for TestIDkgBlockReader {
    fn tip_height(&self) -> Height {
        self.height
    }

    fn requested_transcripts(&self) -> Box<dyn Iterator<Item = &IDkgTranscriptParamsRef> + '_> {
        Box::new(self.requested_transcripts.iter())
    }

    fn pre_signatures_in_creation(
        &self,
    ) -> Box<dyn Iterator<Item = (PreSigId, MasterPublicKeyId)> + '_> {
        Box::new(std::iter::empty())
    }

    fn available_pre_signature(&self, id: &PreSigId) -> Option<&PreSignatureRef> {
        self.available_pre_signatures.get(id)
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

pub(crate) struct TestIDkgTranscriptLoader {
    load_transcript_result: TestTranscriptLoadStatus,
    returned_complaints: Mutex<Vec<SignedIDkgComplaint>>,
}

impl TestIDkgTranscriptLoader {
    pub(crate) fn new(load_transcript_result: TestTranscriptLoadStatus) -> Self {
        Self {
            load_transcript_result,
            returned_complaints: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn returned_complaints(&self) -> Vec<SignedIDkgComplaint> {
        let complaints = self.returned_complaints.lock().unwrap();
        let mut ret = Vec::new();
        for complaint in complaints.iter() {
            ret.push(complaint.clone());
        }
        ret
    }
}

impl IDkgTranscriptLoader for TestIDkgTranscriptLoader {
    fn load_transcript(
        &self,
        _idkg_pool: &dyn IDkgPool,
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

impl Default for TestIDkgTranscriptLoader {
    fn default() -> Self {
        Self::new(TestTranscriptLoadStatus::Success)
    }
}

pub(crate) struct TestIDkgTranscriptBuilder {
    transcripts: Mutex<BTreeMap<IDkgTranscriptId, IDkgTranscript>>,
    dealings: Mutex<BTreeMap<IDkgTranscriptId, Vec<SignedIDkgDealing>>>,
}

impl TestIDkgTranscriptBuilder {
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

impl IDkgTranscriptBuilder for TestIDkgTranscriptBuilder {
    fn get_completed_transcript(&self, transcript_id: IDkgTranscriptId) -> Option<IDkgTranscript> {
        self.transcripts
            .lock()
            .unwrap()
            .get(&transcript_id)
            .cloned()
    }

    fn get_validated_dealings(&self, transcript_id: IDkgTranscriptId) -> Vec<SignedIDkgDealing> {
        self.dealings
            .lock()
            .unwrap()
            .get(&transcript_id)
            .cloned()
            .unwrap_or_default()
    }
}

pub(crate) struct TestThresholdSignatureBuilder {
    pub(crate) signatures: BTreeMap<RequestId, CombinedSignature>,
}

impl TestThresholdSignatureBuilder {
    pub(crate) fn new() -> Self {
        Self {
            signatures: BTreeMap::new(),
        }
    }
}

impl ThresholdSignatureBuilder for TestThresholdSignatureBuilder {
    fn get_completed_signature(
        &self,
        context: &SignWithThresholdContext,
    ) -> Option<CombinedSignature> {
        let request_id = get_context_request_id(context)?;
        self.signatures.get(&request_id).cloned()
    }
}

#[derive(Clone)]
pub(crate) struct FakeCertifiedStateSnapshot {
    pub(crate) height: Height,
    pub(crate) state: Arc<ReplicatedState>,
}

impl FakeCertifiedStateSnapshot {
    pub(crate) fn get_labeled_state(&self) -> Labeled<Arc<ReplicatedState>> {
        Labeled::new(self.height, self.state.clone())
    }

    pub(crate) fn inc_height_by(&mut self, height: u64) -> Height {
        self.height += Height::from(height);
        self.height
    }
}

impl CertifiedStateSnapshot for FakeCertifiedStateSnapshot {
    type State = ReplicatedState;

    fn get_state(&self) -> &Self::State {
        &self.state
    }

    fn get_height(&self) -> Height {
        self.height
    }

    fn read_certified_state(
        &self,
        _paths: &LabeledTree<()>,
    ) -> Option<(MixedHashTree, Certification)> {
        None
    }
}

pub(crate) fn create_idkg_pool(
    config: ArtifactPoolConfig,
    log: ReplicaLogger,
    metrics_registry: MetricsRegistry,
) -> IDkgPoolImpl {
    IDkgPoolImpl::new(config, log, metrics_registry, Box::new(IDkgStatsNoOp {}))
}

// Sets up the dependencies and creates the pre signer
pub(crate) fn create_pre_signer_dependencies_with_crypto(
    pool_config: ArtifactPoolConfig,
    logger: ReplicaLogger,
    consensus_crypto: Option<Arc<dyn ConsensusCrypto>>,
) -> (IDkgPoolImpl, IDkgPreSignerImpl) {
    let metrics_registry = MetricsRegistry::new();
    let Dependencies { pool, crypto, .. } = dependencies(pool_config.clone(), 1);

    // need to make sure subnet matches the transcript
    let pre_signer = IDkgPreSignerImpl::new(
        NODE_1,
        pool.get_block_cache(),
        consensus_crypto.unwrap_or(crypto),
        metrics_registry.clone(),
        logger.clone(),
    );
    let idkg_pool = create_idkg_pool(pool_config, logger, metrics_registry);

    (idkg_pool, pre_signer)
}

// Sets up the dependencies and creates the pre signer
pub(crate) fn create_pre_signer_dependencies_and_pool(
    pool_config: ArtifactPoolConfig,
    logger: ReplicaLogger,
) -> (IDkgPoolImpl, IDkgPreSignerImpl, TestConsensusPool) {
    let metrics_registry = MetricsRegistry::new();
    let Dependencies { pool, crypto, .. } = dependencies(pool_config.clone(), 1);

    let pre_signer = IDkgPreSignerImpl::new(
        NODE_1,
        pool.get_block_cache(),
        crypto,
        metrics_registry.clone(),
        logger.clone(),
    );
    let idkg_pool = create_idkg_pool(pool_config, logger, metrics_registry);

    (idkg_pool, pre_signer, pool)
}

// Sets up the dependencies and creates the pre signer
pub(crate) fn create_pre_signer_dependencies(
    pool_config: ArtifactPoolConfig,
    logger: ReplicaLogger,
) -> (IDkgPoolImpl, IDkgPreSignerImpl) {
    create_pre_signer_dependencies_with_crypto(pool_config, logger, None)
}

// Sets up the dependencies and creates the signer
pub(crate) fn create_signer_dependencies_with_crypto(
    pool_config: ArtifactPoolConfig,
    logger: ReplicaLogger,
    consensus_crypto: Option<Arc<dyn ConsensusCrypto>>,
) -> (IDkgPoolImpl, ThresholdSignerImpl) {
    let metrics_registry = MetricsRegistry::new();
    let Dependencies {
        pool,
        crypto,
        state_manager,
        ..
    } = dependencies(pool_config.clone(), 1);

    let signer = ThresholdSignerImpl::new(
        NODE_1,
        pool.get_block_cache(),
        consensus_crypto.unwrap_or(crypto),
        state_manager as Arc<_>,
        metrics_registry.clone(),
        logger.clone(),
    );
    let idkg_pool = create_idkg_pool(pool_config, logger, metrics_registry);

    (idkg_pool, signer)
}

// Sets up the dependencies and creates the signer
pub(crate) fn create_signer_dependencies(
    pool_config: ArtifactPoolConfig,
    logger: ReplicaLogger,
) -> (IDkgPoolImpl, ThresholdSignerImpl) {
    create_signer_dependencies_with_crypto(pool_config, logger, None)
}

pub(crate) fn create_signer_dependencies_and_state_manager(
    pool_config: ArtifactPoolConfig,
    logger: ReplicaLogger,
) -> (IDkgPoolImpl, ThresholdSignerImpl, Arc<RefMockStateManager>) {
    let metrics_registry = MetricsRegistry::new();
    let Dependencies {
        pool,
        crypto,
        state_manager,
        ..
    } = dependencies(pool_config.clone(), 1);

    let signer = ThresholdSignerImpl::new(
        NODE_1,
        pool.get_block_cache(),
        crypto,
        state_manager.clone(),
        metrics_registry.clone(),
        logger.clone(),
    );
    let idkg_pool = create_idkg_pool(pool_config, logger, metrics_registry);

    (idkg_pool, signer, state_manager)
}

// Sets up the dependencies and creates the complaint handler
pub(crate) fn create_complaint_dependencies_with_crypto_and_node_id(
    pool_config: ArtifactPoolConfig,
    logger: ReplicaLogger,
    consensus_crypto: Option<Arc<dyn ConsensusCrypto>>,
    node_id: NodeId,
) -> (IDkgPoolImpl, IDkgComplaintHandlerImpl) {
    let metrics_registry = MetricsRegistry::new();
    let Dependencies { pool, crypto, .. } = dependencies(pool_config.clone(), 1);

    let complaint_handler = IDkgComplaintHandlerImpl::new(
        node_id,
        pool.get_block_cache(),
        consensus_crypto.unwrap_or(crypto),
        metrics_registry.clone(),
        logger.clone(),
    );
    let idkg_pool = create_idkg_pool(pool_config, logger, metrics_registry);

    (idkg_pool, complaint_handler)
}

// Sets up the dependencies and creates the complaint handler
pub(crate) fn create_complaint_dependencies_and_pool(
    pool_config: ArtifactPoolConfig,
    logger: ReplicaLogger,
) -> (IDkgPoolImpl, IDkgComplaintHandlerImpl, TestConsensusPool) {
    let metrics_registry = MetricsRegistry::new();
    let Dependencies { pool, crypto, .. } = dependencies(pool_config.clone(), 1);

    let complaint_handler = IDkgComplaintHandlerImpl::new(
        NODE_1,
        pool.get_block_cache(),
        crypto,
        metrics_registry.clone(),
        logger.clone(),
    );
    let idkg_pool = create_idkg_pool(pool_config, logger, metrics_registry);

    (idkg_pool, complaint_handler, pool)
}

pub(crate) fn create_complaint_dependencies(
    pool_config: ArtifactPoolConfig,
    logger: ReplicaLogger,
) -> (IDkgPoolImpl, IDkgComplaintHandlerImpl) {
    create_complaint_dependencies_with_crypto(pool_config, logger, None)
}

pub(crate) fn create_complaint_dependencies_with_crypto(
    pool_config: ArtifactPoolConfig,
    logger: ReplicaLogger,
    crypto: Option<Arc<dyn ConsensusCrypto>>,
) -> (IDkgPoolImpl, IDkgComplaintHandlerImpl) {
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
    key_id: &MasterPublicKeyId,
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
        algorithm_id: algorithm_for_key_id(key_id),
        internal_transcript_raw: vec![],
    }
}

/// Creates a test transcript param with registry version 0
pub(crate) fn create_transcript_param(
    key_id: &MasterPublicKeyId,
    transcript_id: IDkgTranscriptId,
    dealer_list: &[NodeId],
    receiver_list: &[NodeId],
) -> TestTranscriptParams {
    create_transcript_param_with_registry_version(
        key_id,
        transcript_id,
        dealer_list,
        receiver_list,
        RegistryVersion::from(0),
    )
}

/// Creates a test transcript param for a specific registry version
pub(crate) fn create_transcript_param_with_registry_version(
    key_id: &MasterPublicKeyId,
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
    let random_transcript = create_transcript(key_id, random_transcript_id, dealer_list);
    let random_masked = MaskedTranscript::try_from((Height::new(0), &random_transcript)).unwrap();
    let mut idkg_transcripts = BTreeMap::new();
    idkg_transcripts.insert(*random_masked.as_ref(), random_transcript);

    let attrs =
        IDkgTranscriptAttributes::new(dealers, algorithm_for_key_id(key_id), registry_version);

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
    algorithm: AlgorithmId,
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
        algorithm,
        IDkgTranscriptOperation::ReshareOfUnmasked(unmasked_transcript.clone()),
    )
    .unwrap()
}

/// Return a valid transcript for random sharing created by the first node of the environment
pub(crate) fn create_valid_transcript<R: Rng + CryptoRng>(
    env: &CanisterThresholdSigTestEnvironment,
    rng: &mut R,
    algorithm: AlgorithmId,
) -> (NodeId, IDkgTranscriptParams, IDkgTranscript) {
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
    let params = setup_masked_random_params(env, algorithm, &dealers, &receivers, rng);
    let dealings = env.nodes.create_and_verify_signed_dealings(&params);
    let dealings = env
        .nodes
        .support_dealings_from_all_receivers(dealings, &params);
    let dealer = env
        .nodes
        .filter_by_dealers(&params)
        .next()
        .expect("Empty dealers");
    let idkg_transcript = dealer.create_transcript_or_panic(&params, &dealings);
    (dealer.id(), params, idkg_transcript)
}

/// Return a corrupt transcript for random sharing by changing ciphertexts intended
/// for the first node of the environment
pub(crate) fn create_corrupted_transcript<R: CryptoRng + Rng>(
    env: &CanisterThresholdSigTestEnvironment,
    rng: &mut R,
    algorithm: AlgorithmId,
) -> (NodeId, IDkgTranscriptParams, IDkgTranscript) {
    let (node_id, params, mut transcript) = create_valid_transcript(env, rng, algorithm);
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
            env.nodes.filter_by_receivers(&params).map(|signer| {
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
    key_id: &MasterPublicKeyId,
    transcript_id: IDkgTranscriptId,
    dealer_id: NodeId,
    rng: &mut R,
) -> SignedIDkgDealing {
    let env = CanisterThresholdSigTestEnvironment::new(2, rng);
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
    let params = setup_masked_random_params(
        &env,
        algorithm_for_key_id(key_id),
        &dealers,
        &receivers,
        rng,
    );
    let dealer = env.nodes.filter_by_dealers(&params).next().unwrap();
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
pub(crate) fn create_sig_inputs_with_height(
    caller: u8,
    height: Height,
    key_id: MasterPublicKeyId,
) -> TestSigInputs {
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
        transcript_type: IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(
            key_masked_id,
        )),
        algorithm_id: algorithm_for_key_id(&key_id),
        internal_transcript_raw: vec![],
    };
    create_sig_inputs_with_args(caller, &receivers, key_unmasked, height, &key_id)
}

pub(crate) fn create_sig_inputs_with_args(
    caller: u8,
    receivers: &BTreeSet<NodeId>,
    key_unmasked: IDkgTranscript,
    height: Height,
    key_id: &MasterPublicKeyId,
) -> TestSigInputs {
    match key_id {
        MasterPublicKeyId::Ecdsa(key_id) => {
            create_ecdsa_sig_inputs_with_args(caller, receivers, key_unmasked, height, key_id)
        }
        MasterPublicKeyId::Schnorr(key_id) => {
            create_schnorr_sig_inputs_with_args(caller, receivers, key_unmasked, height, key_id)
        }
    }
}

// Creates a test signature input
pub(crate) fn create_ecdsa_sig_inputs_with_args(
    caller: u8,
    receivers: &BTreeSet<NodeId>,
    key_unmasked: IDkgTranscript,
    height: Height,
    key_id: &EcdsaKeyId,
) -> TestSigInputs {
    let transcript_id = |offset| {
        let val = caller as u64;
        create_transcript_id(val * 214365 + offset)
    };

    let algorithm_id = key_unmasked.algorithm_id;
    assert!(
        algorithm_id.is_threshold_ecdsa(),
        "Expected tECDSA algorithm"
    );
    assert_eq!(
        algorithm_id,
        algorithm_for_key_id(&MasterPublicKeyId::Ecdsa(key_id.clone()))
    );
    let kappa_unmasked_id = transcript_id(20);
    let lambda_masked_id = transcript_id(30);
    let key_unmasked_id = key_unmasked.transcript_id;
    let kappa_unmasked_times_lambda_masked_id = transcript_id(60);
    let key_unmasked_times_lambda_masked_id = transcript_id(70);
    let mut idkg_transcripts = BTreeMap::new();

    let kappa_unmasked = IDkgTranscript {
        transcript_id: kappa_unmasked_id,
        receivers: IDkgReceivers::new(receivers.clone()).unwrap(),
        registry_version: RegistryVersion::from(1),
        verified_dealings: BTreeMap::new(),
        transcript_type: IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::Random),
        algorithm_id,
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
        algorithm_id,
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
            IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(kappa_unmasked_id, lambda_masked_id),
        ),
        algorithm_id,
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
        algorithm_id,
        internal_transcript_raw: vec![],
    };
    let key_unmasked_times_lambda_masked_ref =
        MaskedTranscript::try_from((height, &key_unmasked_times_lambda_masked)).unwrap();
    idkg_transcripts.insert(
        *key_unmasked_times_lambda_masked_ref.as_ref(),
        key_unmasked_times_lambda_masked,
    );

    let presig_quadruple_ref = PreSignatureQuadrupleRef::new(
        key_id.clone(),
        kappa_unmasked_ref,
        lambda_masked_ref,
        kappa_unmasked_times_lambda_masked_ref,
        key_unmasked_times_lambda_masked_ref,
        key_unmasked_ref,
    );
    let sig_inputs_ref = ThresholdEcdsaSigInputsRef::new(
        ExtendedDerivationPath {
            caller: PrincipalId::try_from(&vec![caller]).unwrap(),
            derivation_path: vec![],
        },
        [0u8; 32],
        Randomness::from([0_u8; 32]),
        presig_quadruple_ref,
    );

    TestSigInputs {
        idkg_transcripts,
        sig_inputs_ref: ThresholdSigInputsRef::Ecdsa(sig_inputs_ref),
    }
}

// Creates a test signature input
pub(crate) fn create_schnorr_sig_inputs_with_args(
    caller: u8,
    receivers: &BTreeSet<NodeId>,
    key_unmasked: IDkgTranscript,
    height: Height,
    key_id: &SchnorrKeyId,
) -> TestSigInputs {
    let transcript_id = |offset| {
        let val = caller as u64;
        create_transcript_id(val * 214365 + offset)
    };

    let algorithm_id = key_unmasked.algorithm_id;
    assert!(
        algorithm_id.is_threshold_schnorr(),
        "Expected tSchnorr algorithm"
    );
    assert_eq!(
        algorithm_id,
        algorithm_for_key_id(&MasterPublicKeyId::Schnorr(key_id.clone()))
    );
    let blinder_unmasked_id = transcript_id(10);
    let mut idkg_transcripts = BTreeMap::new();

    let blinder_unmasked = IDkgTranscript {
        transcript_id: blinder_unmasked_id,
        receivers: IDkgReceivers::new(receivers.clone()).unwrap(),
        registry_version: RegistryVersion::from(1),
        verified_dealings: BTreeMap::new(),
        transcript_type: IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::Random),
        algorithm_id,
        internal_transcript_raw: vec![],
    };
    let blinder_unmasked_ref = UnmaskedTranscript::try_from((height, &blinder_unmasked)).unwrap();
    idkg_transcripts.insert(*blinder_unmasked_ref.as_ref(), blinder_unmasked);

    let key_unmasked_ref = UnmaskedTranscript::try_from((height, &key_unmasked)).unwrap();
    idkg_transcripts.insert(*key_unmasked_ref.as_ref(), key_unmasked);

    let presig_transcript_ref =
        PreSignatureTranscriptRef::new(key_id.clone(), blinder_unmasked_ref, key_unmasked_ref);
    let sig_inputs_ref = ThresholdSchnorrSigInputsRef::new(
        ExtendedDerivationPath {
            caller: PrincipalId::try_from(&vec![caller]).unwrap(),
            derivation_path: vec![],
        },
        Arc::new(vec![0; 128]),
        Randomness::from([0_u8; 32]),
        presig_transcript_ref,
    );

    TestSigInputs {
        idkg_transcripts,
        sig_inputs_ref: ThresholdSigInputsRef::Schnorr(sig_inputs_ref),
    }
}

// Creates a test signature input
pub(crate) fn create_sig_inputs(caller: u8, key_id: &MasterPublicKeyId) -> TestSigInputs {
    create_sig_inputs_with_height(caller, Height::new(0), key_id.clone())
}

// Creates a test signature share
pub(crate) fn create_signature_share_with_nonce(
    key_id: &MasterPublicKeyId,
    signer_id: NodeId,
    request_id: RequestId,
    nonce: u8,
) -> IDkgMessage {
    match key_id {
        MasterPublicKeyId::Ecdsa(_) => IDkgMessage::EcdsaSigShare(EcdsaSigShare {
            signer_id,
            request_id,
            share: ThresholdEcdsaSigShare {
                sig_share_raw: vec![nonce],
            },
        }),
        MasterPublicKeyId::Schnorr(_) => IDkgMessage::SchnorrSigShare(SchnorrSigShare {
            signer_id,
            request_id,
            share: ThresholdSchnorrSigShare {
                sig_share_raw: vec![nonce],
            },
        }),
    }
}

// Creates a test signature share
pub(crate) fn create_signature_share(
    key_id: &MasterPublicKeyId,
    signer_id: NodeId,
    request_id: RequestId,
) -> IDkgMessage {
    create_signature_share_with_nonce(key_id, signer_id, request_id, 0)
}

pub(crate) fn create_complaint_with_nonce(
    transcript_id: IDkgTranscriptId,
    dealer_id: NodeId,
    complainer_id: NodeId,
    nonce: u8,
) -> SignedIDkgComplaint {
    let content = IDkgComplaintContent {
        idkg_complaint: IDkgComplaint {
            transcript_id,
            dealer_id,
            internal_complaint_raw: vec![nonce],
        },
    };
    SignedIDkgComplaint {
        content,
        signature: BasicSignature::fake(complainer_id),
    }
}

// Creates a test signed complaint
pub(crate) fn create_complaint(
    transcript_id: IDkgTranscriptId,
    dealer_id: NodeId,
    complainer_id: NodeId,
) -> SignedIDkgComplaint {
    create_complaint_with_nonce(transcript_id, dealer_id, complainer_id, 0)
}

// Creates a test signed opening
pub(crate) fn create_opening_with_nonce(
    transcript_id: IDkgTranscriptId,
    dealer_id: NodeId,
    _complainer_id: NodeId,
    opener_id: NodeId,
    nonce: u8,
) -> SignedIDkgOpening {
    let content = IDkgOpeningContent {
        idkg_opening: IDkgOpening {
            transcript_id,
            dealer_id,
            internal_opening_raw: vec![nonce],
        },
    };
    SignedIDkgOpening {
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
) -> SignedIDkgOpening {
    create_opening_with_nonce(transcript_id, dealer_id, complainer_id, opener_id, 0)
}
// Checks that the dealing with the given id is being added to the validated
// pool
pub(crate) fn is_dealing_added_to_validated(
    change_set: &[IDkgChangeAction],
    transcript_id: &IDkgTranscriptId,
) -> bool {
    for action in change_set {
        if let IDkgChangeAction::AddToValidated(IDkgMessage::Dealing(signed_dealing)) = action {
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
    change_set: &[IDkgChangeAction],
    transcript_id: &IDkgTranscriptId,
    dealer_id: &NodeId,
) -> bool {
    for action in change_set {
        if let IDkgChangeAction::AddToValidated(IDkgMessage::DealingSupport(support)) = action {
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
    change_set: &[IDkgChangeAction],
    transcript_id: &IDkgTranscriptId,
    dealer_id: &NodeId,
    complainer_id: &NodeId,
) -> bool {
    for action in change_set {
        if let IDkgChangeAction::AddToValidated(IDkgMessage::Complaint(signed_complaint)) = action {
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
    change_set: &[IDkgChangeAction],
    transcript_id: &IDkgTranscriptId,
    dealer_id: &NodeId,
    opener_id: &NodeId,
) -> bool {
    for action in change_set {
        if let IDkgChangeAction::AddToValidated(IDkgMessage::Opening(signed_opening)) = action {
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
    change_set: &[IDkgChangeAction],
    request_id: &RequestId,
    requested_height: Height,
) -> bool {
    for action in change_set {
        if let IDkgChangeAction::AddToValidated(IDkgMessage::EcdsaSigShare(share)) = action {
            if share.request_id.height == requested_height
                && share.request_id == *request_id
                && share.signer_id == NODE_1
            {
                return true;
            }
        }
        if let IDkgChangeAction::AddToValidated(IDkgMessage::SchnorrSigShare(share)) = action {
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
    change_set: &[IDkgChangeAction],
    msg_id: &IDkgMessageId,
) -> bool {
    for action in change_set {
        if let IDkgChangeAction::MoveToValidated(msg) = action {
            if IDkgArtifactId::from(msg) == *msg_id {
                return true;
            }
        }
    }
    false
}

// Checks that artifact is being removed from validated pool
pub(crate) fn is_removed_from_validated(
    change_set: &[IDkgChangeAction],
    msg_id: &IDkgMessageId,
) -> bool {
    for action in change_set {
        if let IDkgChangeAction::RemoveValidated(id) = action {
            if *id == *msg_id {
                return true;
            }
        }
    }
    false
}

// Checks that artifact is being removed from unvalidated pool
pub(crate) fn is_removed_from_unvalidated(
    change_set: &[IDkgChangeAction],
    msg_id: &IDkgMessageId,
) -> bool {
    for action in change_set {
        if let IDkgChangeAction::RemoveUnvalidated(id) = action {
            if *id == *msg_id {
                return true;
            }
        }
    }
    false
}

// Checks that artifact is being dropped as invalid
pub(crate) fn is_handle_invalid(change_set: &[IDkgChangeAction], msg_id: &IDkgMessageId) -> bool {
    for action in change_set {
        if let IDkgChangeAction::HandleInvalid(id, _) = action {
            if *id == *msg_id {
                return true;
            }
        }
    }
    false
}

pub(crate) fn empty_idkg_payload(subnet_id: SubnetId) -> IDkgPayload {
    empty_idkg_payload_with_key_ids(subnet_id, vec![fake_ecdsa_master_public_key_id()])
}

pub(crate) fn empty_idkg_payload_with_key_ids(
    subnet_id: SubnetId,
    key_ids: Vec<MasterPublicKeyId>,
) -> IDkgPayload {
    IDkgPayload::empty(
        Height::new(0),
        subnet_id,
        key_ids
            .into_iter()
            .map(|key_id| MasterKeyTranscript {
                current: None,
                next_in_creation: KeyTranscriptCreation::Begin,
                master_key_id: key_id.clone(),
            })
            .collect(),
    )
}

pub(crate) fn key_id_with_name(key_id: &MasterPublicKeyId, name: &str) -> MasterPublicKeyId {
    let mut key_id = key_id.clone();
    match key_id {
        MasterPublicKeyId::Ecdsa(ref mut key_id) => key_id.name = name.into(),
        MasterPublicKeyId::Schnorr(ref mut key_id) => key_id.name = name.into(),
    }
    key_id
}

pub(crate) fn fake_ecdsa_key_id() -> EcdsaKeyId {
    EcdsaKeyId::from_str("Secp256k1:some_key").unwrap()
}

pub(crate) fn fake_ecdsa_master_public_key_id() -> MasterPublicKeyId {
    MasterPublicKeyId::Ecdsa(fake_ecdsa_key_id())
}

pub(crate) fn fake_schnorr_key_id(algorithm: SchnorrAlgorithm) -> SchnorrKeyId {
    SchnorrKeyId {
        algorithm,
        name: String::from("some_schnorr_key"),
    }
}

pub(crate) fn fake_schnorr_master_public_key_id(algorithm: SchnorrAlgorithm) -> MasterPublicKeyId {
    MasterPublicKeyId::Schnorr(fake_schnorr_key_id(algorithm))
}

pub(crate) fn schnorr_algorithm(algorithm: AlgorithmId) -> SchnorrAlgorithm {
    match algorithm {
        AlgorithmId::ThresholdSchnorrBip340 => SchnorrAlgorithm::Bip340Secp256k1,
        AlgorithmId::ThresholdEd25519 => SchnorrAlgorithm::Ed25519,
        other => panic!("Unexpected algorithm: {other:?}"),
    }
}

pub(crate) fn fake_master_public_key_ids_for_all_algorithms() -> Vec<MasterPublicKeyId> {
    AlgorithmId::iter()
        .flat_map(|alg| match alg {
            AlgorithmId::ThresholdEcdsaSecp256k1 => Some(fake_ecdsa_master_public_key_id()),
            AlgorithmId::ThresholdSchnorrBip340 => Some(fake_schnorr_master_public_key_id(
                SchnorrAlgorithm::Bip340Secp256k1,
            )),
            AlgorithmId::ThresholdEd25519 => {
                Some(fake_schnorr_master_public_key_id(SchnorrAlgorithm::Ed25519))
            }
            _ => None,
        })
        .collect()
}

pub(crate) fn create_reshare_request(
    key_id: MasterPublicKeyId,
    num_nodes: u64,
    registry_version: u64,
) -> IDkgReshareRequest {
    IDkgReshareRequest {
        master_key_id: key_id,
        receiving_node_ids: (0..num_nodes).map(node_test_id).collect::<Vec<_>>(),
        registry_version: RegistryVersion::from(registry_version),
    }
}

pub(crate) fn crypto_without_keys() -> Arc<dyn ConsensusCrypto> {
    TempCryptoComponent::builder().build_arc()
}

pub(crate) fn add_available_quadruple_to_payload(
    idkg_payload: &mut IDkgPayload,
    pre_signature_id: PreSigId,
    registry_version: RegistryVersion,
) {
    let sig_inputs = create_sig_inputs(
        pre_signature_id.id() as u8,
        &fake_ecdsa_master_public_key_id(),
    );
    idkg_payload
        .available_pre_signatures
        .insert(pre_signature_id, sig_inputs.sig_inputs_ref.pre_signature());
    for (t_ref, mut transcript) in sig_inputs.idkg_transcripts {
        transcript.registry_version = registry_version;
        idkg_payload
            .idkg_transcripts
            .insert(t_ref.transcript_id, transcript);
    }
}

pub fn create_available_pre_signature(
    idkg_payload: &mut IDkgPayload,
    key_id: MasterPublicKeyId,
    caller: u8,
) -> PreSigId {
    create_available_pre_signature_with_key_transcript(
        idkg_payload,
        caller,
        key_id,
        /*key_transcript=*/ None,
    )
}

pub fn create_available_pre_signature_with_key_transcript(
    idkg_payload: &mut IDkgPayload,
    caller: u8,
    key_id: MasterPublicKeyId,
    key_transcript: Option<UnmaskedTranscript>,
) -> PreSigId {
    let sig_inputs = create_sig_inputs(caller, &key_id);
    let pre_sig_id = idkg_payload.uid_generator.next_pre_signature_id();
    let mut pre_signature_ref = sig_inputs.sig_inputs_ref.pre_signature();
    if let Some(transcript) = key_transcript {
        match pre_signature_ref {
            PreSignatureRef::Ecdsa(ref mut pre_sig) => {
                pre_sig.key_unmasked_ref = transcript;
            }
            PreSignatureRef::Schnorr(ref mut pre_sig) => {
                pre_sig.key_unmasked_ref = transcript;
            }
        }
    }
    idkg_payload
        .available_pre_signatures
        .insert(pre_sig_id, pre_signature_ref);

    for (t_ref, transcript) in sig_inputs.idkg_transcripts {
        idkg_payload
            .idkg_transcripts
            .insert(t_ref.transcript_id, transcript);
    }

    pre_sig_id
}

pub(crate) fn set_up_idkg_payload(
    rng: &mut ReproducibleRng,
    subnet_id: SubnetId,
    nodes_count: usize,
    key_ids: Vec<MasterPublicKeyId>,
    should_create_key_transcript: bool,
) -> (
    IDkgPayload,
    CanisterThresholdSigTestEnvironment,
    TestIDkgBlockReader,
) {
    let env = CanisterThresholdSigTestEnvironment::new(nodes_count, rng);

    let mut idkg_payload = empty_idkg_payload_with_key_ids(subnet_id, key_ids.clone());
    let mut block_reader = TestIDkgBlockReader::new();

    if should_create_key_transcript {
        for key_id in key_ids {
            let (key_transcript, key_transcript_ref) =
                idkg_payload.generate_current_key(&key_id, &env, rng);

            block_reader.add_transcript(*key_transcript_ref.as_ref(), key_transcript.clone());
        }
    }

    (idkg_payload, env, block_reader)
}

pub(crate) fn generate_key_transcript(
    key_id: &MasterPublicKeyId,
    env: &CanisterThresholdSigTestEnvironment,
    rng: &mut ReproducibleRng,
    height: Height,
) -> (
    IDkgTranscript,
    idkg::UnmaskedTranscript,
    idkg::UnmaskedTranscriptWithAttributes,
) {
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);

    let key_transcript = ic_crypto_test_utils_canister_threshold_sigs::generate_key_transcript(
        env,
        &dealers,
        &receivers,
        algorithm_for_key_id(key_id),
        rng,
    );
    let key_transcript_ref = idkg::UnmaskedTranscript::try_from((height, &key_transcript)).unwrap();

    let with_attributes = idkg::UnmaskedTranscriptWithAttributes::new(
        key_transcript.to_attributes(),
        key_transcript_ref,
    );

    (key_transcript, key_transcript_ref, with_attributes)
}

pub(crate) trait IDkgPayloadTestHelper {
    fn peek_next_transcript_id(&self) -> IDkgTranscriptId;

    #[allow(dead_code)]
    fn peek_next_pre_signature_id(&self) -> PreSigId;

    fn generate_current_key(
        &mut self,
        key_id: &MasterPublicKeyId,
        env: &CanisterThresholdSigTestEnvironment,
        rng: &mut ReproducibleRng,
    ) -> (IDkgTranscript, idkg::UnmaskedTranscript);

    /// Retrieves the only key transcript in the idkg payload.
    ///
    /// Panics if there are multiple or no keys.
    fn single_key_transcript(&self) -> &MasterKeyTranscript;

    /// Retrieves the only key transcript in the idkg payload.
    ///
    /// Panics if there are multiple or no keys.
    fn single_key_transcript_mut(&mut self) -> &mut MasterKeyTranscript;
}

impl IDkgPayloadTestHelper for IDkgPayload {
    fn peek_next_transcript_id(&self) -> IDkgTranscriptId {
        self.uid_generator.clone().next_transcript_id()
    }

    fn peek_next_pre_signature_id(&self) -> PreSigId {
        self.uid_generator.clone().next_pre_signature_id()
    }

    fn single_key_transcript(&self) -> &MasterKeyTranscript {
        match self.key_transcripts.len() {
            0 => panic!("There are no key transcripts in the payload"),
            1 => self.key_transcripts.values().next().unwrap(),
            n => panic!("There are multiple ({}) key transcripts in the payload", n),
        }
    }

    fn single_key_transcript_mut(&mut self) -> &mut MasterKeyTranscript {
        match self.key_transcripts.len() {
            0 => panic!("There are no key transcripts in the payload"),
            1 => self.key_transcripts.values_mut().next().unwrap(),
            n => panic!("There are multiple ({}) key transcripts in the payload", n),
        }
    }

    fn generate_current_key(
        &mut self,
        key_id: &MasterPublicKeyId,
        env: &CanisterThresholdSigTestEnvironment,
        rng: &mut ReproducibleRng,
    ) -> (IDkgTranscript, idkg::UnmaskedTranscript) {
        let (key_transcript, key_transcript_ref, current) =
            generate_key_transcript(key_id, env, rng, Height::new(100));

        self.key_transcripts.get_mut(key_id).unwrap().current = Some(current);

        (key_transcript, key_transcript_ref)
    }
}
