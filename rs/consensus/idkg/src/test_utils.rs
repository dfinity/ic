use crate::{
    MAX_IDKG_THREADS,
    complaints::{IDkgComplaintHandlerImpl, IDkgTranscriptLoader, TranscriptLoadStatus},
    pre_signer::{IDkgPreSignerImpl, IDkgTranscriptBuilder},
    signer::{ThresholdSignatureBuilder, ThresholdSignerImpl},
    utils::build_thread_pool,
};
use ic_artifact_pool::idkg_pool::IDkgPoolImpl;
use ic_config::artifact_pool::ArtifactPoolConfig;
use ic_consensus_mocks::{Dependencies, dependencies};
use ic_consensus_utils::crypto::ConsensusCrypto;
use ic_crypto_temp_crypto::TempCryptoComponent;
use ic_crypto_test_utils_canister_threshold_sigs::{
    CanisterThresholdSigTestEnvironment, IDkgParticipants, IntoBuilder,
    dummy_values::dummy_idkg_dealing_for_tests, setup_masked_random_params,
};
use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
use ic_interfaces::idkg::{IDkgChangeAction, IDkgPool};
use ic_logger::ReplicaLogger;
use ic_management_canister_types_private::MasterPublicKeyId;
use ic_metrics::MetricsRegistry;
use ic_replicated_state::metadata_state::subnet_call_context_manager::{
    IDkgSignWithThresholdContext, SignWithThresholdContext,
};
use ic_test_artifact_pool::consensus_pool::TestConsensusPool;
use ic_test_utilities::state_manager::RefMockStateManager;
use ic_test_utilities_consensus::{IDkgStatsNoOp, fake::*, idkg::*};
use ic_test_utilities_types::ids::{NODE_1, NODE_2, node_test_id};
use ic_types::{
    Height, NodeId, RegistryVersion, SubnetId,
    artifact::IDkgMessageId,
    consensus::idkg::{
        self, EcdsaSigShare, IDkgArtifactId, IDkgBlockReader, IDkgComplaintContent,
        IDkgMasterPublicKeyId, IDkgMessage, IDkgOpeningContent, IDkgPayload, IDkgReshareRequest,
        IDkgTranscriptAttributes, IDkgTranscriptOperationRef, IDkgTranscriptParamsRef,
        MaskedTranscript, MasterKeyTranscript, PreSigId, RequestId, ReshareOfMaskedParams,
        SchnorrSigShare, SignedIDkgComplaint, SignedIDkgOpening, TranscriptAttributes,
        TranscriptLookupError, TranscriptRef, UnmaskedTranscript, VetKdKeyShare,
        common::{CombinedSignature, PreSignatureRef},
    },
    crypto::{
        AlgorithmId,
        canister_threshold_sig::{
            ThresholdEcdsaSigShare, ThresholdSchnorrSigShare,
            idkg::{
                IDkgComplaint, IDkgDealing, IDkgDealingSupport, IDkgMaskedTranscriptOrigin,
                IDkgOpening, IDkgReceivers, IDkgTranscript, IDkgTranscriptId,
                IDkgTranscriptOperation, IDkgTranscriptParams, IDkgTranscriptType,
                SignedIDkgDealing,
            },
        },
        vetkd::{VetKdEncryptedKeyShare, VetKdEncryptedKeyShareContent},
    },
    messages::CallbackId,
    signature::*,
};
use rand::{CryptoRng, Rng};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
    sync::{Arc, Mutex},
};

pub fn into_idkg_contexts(
    contexts: &BTreeMap<CallbackId, SignWithThresholdContext>,
) -> BTreeMap<CallbackId, IDkgSignWithThresholdContext<'_>> {
    contexts
        .iter()
        .flat_map(|(id, ctxt)| IDkgSignWithThresholdContext::try_from(ctxt).map(|ctxt| (*id, ctxt)))
        .collect()
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

// Test implementation of IDkgBlockReader to inject the test transcript params
#[derive(Clone, Default)]
pub(crate) struct TestIDkgBlockReader {
    height: Height,
    requested_transcripts: Vec<IDkgTranscriptParamsRef>,
    source_subnet_xnet_transcripts: Vec<IDkgTranscriptParamsRef>,
    target_subnet_xnet_transcripts: Vec<IDkgTranscriptParamsRef>,
    idkg_transcripts: BTreeMap<TranscriptRef, IDkgTranscript>,
    idkg_payloads: BTreeMap<Height, IDkgPayload>,
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

    pub(crate) fn for_complainer_test(
        key_id: &IDkgMasterPublicKeyId,
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

    pub(crate) fn add_payload(&mut self, height: Height, payload: IDkgPayload) {
        self.idkg_payloads.insert(height, payload);
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
    ) -> Box<dyn Iterator<Item = (PreSigId, IDkgMasterPublicKeyId)> + '_> {
        Box::new(std::iter::empty())
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

    fn transcript_as_ref(
        &self,
        transcript_ref: &TranscriptRef,
    ) -> Result<&IDkgTranscript, TranscriptLookupError> {
        if self.fail_to_resolve {
            return Err("Test transcript resolve failure".into());
        }

        if let Some(transcript) = self.idkg_transcripts.get(transcript_ref) {
            return Ok(transcript);
        }

        self.idkg_payloads
            .get(&transcript_ref.height)
            .and_then(|payload| payload.idkg_transcripts.get(&transcript_ref.transcript_id))
            .ok_or(format!("transcript(): {transcript_ref:?} not found"))
    }

    fn active_transcripts(&self) -> BTreeSet<TranscriptRef> {
        self.idkg_transcripts.keys().cloned().collect()
    }

    fn iter_above(&self, height: Height) -> Box<dyn Iterator<Item = &IDkgPayload> + '_> {
        Box::new(
            self.idkg_payloads
                .range(height.increment()..)
                .map(|(_, v)| v),
        )
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
        callback_id: CallbackId,
        context: &SignWithThresholdContext,
    ) -> Option<CombinedSignature> {
        let height = context.matched_pre_signature.map(|(_, h)| h)?;
        self.signatures
            .get(&RequestId {
                callback_id,
                height,
            })
            .cloned()
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
    create_pre_signer_dependencies_with_crypto_and_threads(
        pool_config,
        logger,
        consensus_crypto,
        MAX_IDKG_THREADS,
    )
}

// Sets up the dependencies and creates the pre signer
pub(crate) fn create_pre_signer_dependencies_with_crypto_and_threads(
    pool_config: ArtifactPoolConfig,
    logger: ReplicaLogger,
    consensus_crypto: Option<Arc<dyn ConsensusCrypto>>,
    threads: usize,
) -> (IDkgPoolImpl, IDkgPreSignerImpl) {
    let metrics_registry = MetricsRegistry::new();
    let Dependencies { pool, crypto, .. } = dependencies(pool_config.clone(), 1);

    // need to make sure subnet matches the transcript
    let pre_signer = IDkgPreSignerImpl::new(
        NODE_1,
        pool.get_block_cache(),
        consensus_crypto.unwrap_or(crypto),
        build_thread_pool(threads),
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
        build_thread_pool(MAX_IDKG_THREADS),
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

// Sets up the dependencies and creates the pre signer
pub(crate) fn create_pre_signer_dependencies_with_threads(
    pool_config: ArtifactPoolConfig,
    logger: ReplicaLogger,
    threads: usize,
) -> (IDkgPoolImpl, IDkgPreSignerImpl) {
    create_pre_signer_dependencies_with_crypto_and_threads(pool_config, logger, None, threads)
}

// Sets up the dependencies and creates the signer
pub(crate) fn create_signer_dependencies_with_crypto(
    pool_config: ArtifactPoolConfig,
    logger: ReplicaLogger,
    consensus_crypto: Option<Arc<dyn ConsensusCrypto>>,
) -> (IDkgPoolImpl, ThresholdSignerImpl) {
    let metrics_registry = MetricsRegistry::new();
    let Dependencies {
        crypto,
        state_manager,
        ..
    } = dependencies(pool_config.clone(), 1);

    let signer = ThresholdSignerImpl::new(
        NODE_1,
        consensus_crypto.unwrap_or(crypto),
        build_thread_pool(MAX_IDKG_THREADS),
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
        crypto,
        state_manager,
        ..
    } = dependencies(pool_config.clone(), 1);

    let signer = ThresholdSignerImpl::new(
        NODE_1,
        crypto,
        build_thread_pool(MAX_IDKG_THREADS),
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
    let Dependencies {
        pool,
        crypto,
        state_manager,
        ..
    } = dependencies(pool_config.clone(), 1);

    let complaint_handler = IDkgComplaintHandlerImpl::new(
        node_id,
        pool.get_block_cache(),
        consensus_crypto.unwrap_or(crypto),
        state_manager,
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
    let Dependencies {
        pool,
        crypto,
        state_manager,
        ..
    } = dependencies(pool_config.clone(), 1);

    state_manager
        .get_mut()
        .expect_get_certified_state_snapshot()
        .returning(|| {
            Some(Box::new(fake_state_with_signature_requests(
                Height::from(0),
                [],
            )))
        });

    let complaint_handler = IDkgComplaintHandlerImpl::new(
        NODE_1,
        pool.get_block_cache(),
        crypto,
        state_manager,
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

// Creates a test transcript
pub(crate) fn create_transcript(
    key_id: &IDkgMasterPublicKeyId,
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
        verified_dealings: Arc::new(BTreeMap::new()),
        transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
        algorithm_id: AlgorithmId::from(key_id.inner()),
        internal_transcript_raw: vec![],
    }
}

/// Creates a test transcript param with registry version 0
pub(crate) fn create_transcript_param(
    key_id: &IDkgMasterPublicKeyId,
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
    key_id: &IDkgMasterPublicKeyId,
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
        IDkgTranscriptAttributes::new(dealers, AlgorithmId::from(key_id.inner()), registry_version);

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
    let signed_dealing = Arc::get_mut(&mut transcript.verified_dealings)
        .unwrap()
        .get_mut(&to_corrupt)
        .unwrap();
    let mut rng = rand::rng();
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
    key_id: &IDkgMasterPublicKeyId,
    transcript_id: IDkgTranscriptId,
    dealer_id: NodeId,
    rng: &mut R,
) -> SignedIDkgDealing {
    let env = CanisterThresholdSigTestEnvironment::new(2, rng);
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
    let params = setup_masked_random_params(
        &env,
        AlgorithmId::from(key_id.inner()),
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
        MasterPublicKeyId::VetKd(_) => IDkgMessage::VetKdKeyShare(VetKdKeyShare {
            signer_id,
            request_id,
            share: VetKdEncryptedKeyShare {
                encrypted_key_share: VetKdEncryptedKeyShareContent(vec![nonce]),
                node_signature: vec![nonce],
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
        if let IDkgChangeAction::AddToValidated(IDkgMessage::DealingSupport(support)) = action
            && support.transcript_id == *transcript_id
            && support.dealer_id == *dealer_id
            && support.sig_share.signer == NODE_1
        {
            return true;
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
    expected_request_id: &RequestId,
    requested_height: Height,
) -> bool {
    for action in change_set {
        let (request_id, signer) = match action {
            IDkgChangeAction::AddToValidated(IDkgMessage::EcdsaSigShare(share)) => {
                (share.request_id, share.signer_id)
            }
            IDkgChangeAction::AddToValidated(IDkgMessage::SchnorrSigShare(share)) => {
                (share.request_id, share.signer_id)
            }
            IDkgChangeAction::AddToValidated(IDkgMessage::VetKdKeyShare(share)) => {
                (share.request_id, share.signer_id)
            }
            _ => continue,
        };
        if request_id.height == requested_height
            && request_id == *expected_request_id
            && signer == NODE_1
        {
            return true;
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
        if let IDkgChangeAction::MoveToValidated(msg) = action
            && IDkgArtifactId::from(msg) == *msg_id
        {
            return true;
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
        if let IDkgChangeAction::RemoveValidated(id) = action
            && *id == *msg_id
        {
            return true;
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
        if let IDkgChangeAction::RemoveUnvalidated(id) = action
            && *id == *msg_id
        {
            return true;
        }
    }
    false
}

// Checks that artifact is being dropped as invalid
pub(crate) fn is_handle_invalid(change_set: &[IDkgChangeAction], msg_id: &IDkgMessageId) -> bool {
    for action in change_set {
        if let IDkgChangeAction::HandleInvalid(id, _) = action
            && *id == *msg_id
        {
            return true;
        }
    }
    false
}

pub(crate) fn create_reshare_request(
    key_id: IDkgMasterPublicKeyId,
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

pub fn create_available_pre_signature(
    idkg_payload: &mut IDkgPayload,
    key_id: IDkgMasterPublicKeyId,
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
    key_id: IDkgMasterPublicKeyId,
    key_transcript: Option<UnmaskedTranscript>,
) -> PreSigId {
    create_available_pre_signature_with_key_transcript_and_height(
        idkg_payload,
        caller,
        key_id,
        key_transcript,
        Height::new(0),
    )
}

pub fn create_available_pre_signature_with_key_transcript_and_height(
    idkg_payload: &mut IDkgPayload,
    caller: u8,
    key_id: IDkgMasterPublicKeyId,
    key_transcript: Option<UnmaskedTranscript>,
    height: Height,
) -> PreSigId {
    let inputs = create_pre_sig_ref_with_height(caller, height, &key_id);
    let pre_sig_id = idkg_payload.uid_generator.next_pre_signature_id();
    let mut pre_signature_ref = inputs.pre_signature_ref;
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

    for (t_ref, transcript) in inputs.idkg_transcripts {
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
    key_ids: Vec<IDkgMasterPublicKeyId>,
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
    key_id: &IDkgMasterPublicKeyId,
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
        AlgorithmId::from(key_id.inner()),
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
        key_id: &IDkgMasterPublicKeyId,
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
            n => panic!("There are multiple ({n}) key transcripts in the payload"),
        }
    }

    fn single_key_transcript_mut(&mut self) -> &mut MasterKeyTranscript {
        match self.key_transcripts.len() {
            0 => panic!("There are no key transcripts in the payload"),
            1 => self.key_transcripts.values_mut().next().unwrap(),
            n => panic!("There are multiple ({n}) key transcripts in the payload"),
        }
    }

    fn generate_current_key(
        &mut self,
        key_id: &IDkgMasterPublicKeyId,
        env: &CanisterThresholdSigTestEnvironment,
        rng: &mut ReproducibleRng,
    ) -> (IDkgTranscript, idkg::UnmaskedTranscript) {
        let (key_transcript, key_transcript_ref, current) =
            generate_key_transcript(key_id, env, rng, Height::new(100));

        self.key_transcripts.get_mut(key_id).unwrap().current = Some(current);

        (key_transcript, key_transcript_ref)
    }
}
