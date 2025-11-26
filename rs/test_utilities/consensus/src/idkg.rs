use ic_crypto_test_utils_canister_threshold_sigs::{
    CanisterThresholdSigTestEnvironment, IDkgParticipants, ThresholdEcdsaSigInputsOwned,
    ThresholdSchnorrSigInputsOwned, generate_ecdsa_presig_quadruple, generate_key_transcript,
    setup_unmasked_random_params,
};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_crypto_tree_hash::{LabeledTree, MatchPatternPath, MixedHashTree};
use ic_interfaces_state_manager::{CertifiedStateSnapshot, Labeled};
use ic_management_canister_types_private::{
    EcdsaKeyId, MasterPublicKeyId, SchnorrAlgorithm, SchnorrKeyId, VetKdKeyId,
};
use ic_replicated_state::{
    ReplicatedState,
    metadata_state::subnet_call_context_manager::{
        EcdsaArguments, EcdsaMatchedPreSignature, PreSignatureStash, ReshareChainKeyContext,
        SchnorrArguments, SchnorrMatchedPreSignature, SignWithThresholdContext, ThresholdArguments,
        VetKdArguments,
    },
};
use ic_test_utilities_state::ReplicatedStateBuilder;
use ic_test_utilities_types::{
    ids::{node_test_id, subnet_test_id},
    messages::RequestBuilder,
};
use ic_types::{
    Height, NodeId, PrincipalId, Randomness, RegistryVersion, SubnetId,
    batch::ConsensusResponse,
    consensus::{
        certification::Certification,
        idkg::{
            HasIDkgMasterPublicKeyId, IDkgMasterPublicKeyId, IDkgPayload, IDkgReshareRequest,
            KeyTranscriptCreation, MaskedTranscript, MasterKeyTranscript, PreSigId, RequestId,
            TranscriptRef, UnmaskedTranscript,
            common::{PreSignature, PreSignatureRef, ThresholdSigInputs},
            ecdsa::PreSignatureQuadrupleRef,
            schnorr::PreSignatureTranscriptRef,
        },
    },
    crypto::{
        AlgorithmId, ExtendedDerivationPath,
        canister_threshold_sig::{
            SchnorrPreSignatureTranscript,
            idkg::{
                IDkgMaskedTranscriptOrigin, IDkgReceivers, IDkgTranscript, IDkgTranscriptId,
                IDkgTranscriptType, IDkgUnmaskedTranscriptOrigin,
            },
        },
        threshold_sig::ni_dkg::{
            NiDkgId, NiDkgMasterPublicKeyId, NiDkgTag, NiDkgTargetId, NiDkgTargetSubnet,
        },
        vetkd::VetKdArgs,
    },
    messages::{CallbackId, Payload},
    time::UNIX_EPOCH,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::Arc,
};
use strum::IntoEnumIterator;

pub fn request_id(id: u64, height: Height) -> RequestId {
    RequestId {
        callback_id: CallbackId::from(id),
        height,
    }
}

pub fn dealings_context_from_reshare_request(
    request: IDkgReshareRequest,
) -> ReshareChainKeyContext {
    ReshareChainKeyContext {
        request: RequestBuilder::new().build(),
        key_id: request.key_id().into(),
        nodes: request.receiving_node_ids.into_iter().collect(),
        registry_version: request.registry_version,
        time: UNIX_EPOCH,
        target_id: NiDkgTargetId::new([0; 32]),
    }
}

pub fn empty_response() -> ConsensusResponse {
    ConsensusResponse::new(CallbackId::from(0), Payload::Data(vec![]))
}

pub fn key_transcript_for_tests(key_id: &IDkgMasterPublicKeyId) -> IDkgTranscript {
    let rng = &mut reproducible_rng();
    let env = CanisterThresholdSigTestEnvironment::new(4, rng);
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
    let alg = AlgorithmId::from(key_id.inner());
    generate_key_transcript(&env, &dealers, &receivers, alg, rng)
}

pub fn pre_signature_for_tests(key_id: &IDkgMasterPublicKeyId) -> PreSignature {
    let rng = &mut reproducible_rng();
    let env = CanisterThresholdSigTestEnvironment::new(4, rng);
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
    let alg = AlgorithmId::from(key_id.inner());
    match key_id.inner() {
        MasterPublicKeyId::Ecdsa(_) => {
            let key = generate_key_transcript(&env, &dealers, &receivers, alg, rng);
            let pre_sig =
                generate_ecdsa_presig_quadruple(&env, &dealers, &receivers, alg, &key, rng);
            PreSignature::Ecdsa(Arc::new(pre_sig))
        }
        MasterPublicKeyId::Schnorr(_) => {
            let blinder_params = setup_unmasked_random_params(&env, alg, &dealers, &receivers, rng);
            let blinder_transcript = env
                .nodes
                .run_idkg_and_create_and_verify_transcript(&blinder_params, rng);
            PreSignature::Schnorr(Arc::new(
                SchnorrPreSignatureTranscript::new(blinder_transcript).unwrap(),
            ))
        }
        MasterPublicKeyId::VetKd(_) => panic!("No pre-signatures for vetKD"),
    }
}

pub fn fake_pre_signature_stash(key_id: &IDkgMasterPublicKeyId, size: u64) -> PreSignatureStash {
    let rng = &mut reproducible_rng();
    let env = CanisterThresholdSigTestEnvironment::new(4, rng);
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
    let alg = AlgorithmId::from(key_id.inner());
    let key = generate_key_transcript(&env, &dealers, &receivers, alg, rng);
    let mut pre_signatures = BTreeMap::new();
    for i in 0..size {
        let pre_signature = match key_id.inner() {
            MasterPublicKeyId::Ecdsa(_) => {
                let pre_sig =
                    generate_ecdsa_presig_quadruple(&env, &dealers, &receivers, alg, &key, rng);
                PreSignature::Ecdsa(Arc::new(pre_sig))
            }
            MasterPublicKeyId::Schnorr(_) => {
                let blinder_params =
                    setup_unmasked_random_params(&env, alg, &dealers, &receivers, rng);
                let blinder_transcript = env
                    .nodes
                    .run_idkg_and_create_and_verify_transcript(&blinder_params, rng);
                PreSignature::Schnorr(Arc::new(
                    SchnorrPreSignatureTranscript::new(blinder_transcript).unwrap(),
                ))
            }
            MasterPublicKeyId::VetKd(_) => panic!("Not an IDkgMasterPublicKeyId"),
        };
        pre_signatures.insert(PreSigId(i), pre_signature);
    }
    PreSignatureStash {
        key_transcript: Arc::new(key),
        pre_signatures,
    }
}

fn fake_ecdsa_matched_pre_signature(
    key_id: &EcdsaKeyId,
    height: Height,
    id: PreSigId,
    rv: RegistryVersion,
) -> EcdsaMatchedPreSignature {
    let rng = &mut reproducible_rng();
    let env = CanisterThresholdSigTestEnvironment::new_with_registry_version(4, rv, rng);
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
    let alg = AlgorithmId::from(key_id.curve);
    let key_transcript = generate_key_transcript(&env, &dealers, &receivers, alg, rng);
    let pre_sig =
        generate_ecdsa_presig_quadruple(&env, &dealers, &receivers, alg, &key_transcript, rng);
    EcdsaMatchedPreSignature {
        id,
        height,
        pre_signature: Arc::new(pre_sig),
        key_transcript: Arc::new(key_transcript),
    }
}

fn fake_schnorr_matched_pre_signature(
    key_id: &SchnorrKeyId,
    height: Height,
    id: PreSigId,
    rv: RegistryVersion,
) -> SchnorrMatchedPreSignature {
    let rng = &mut reproducible_rng();
    let env = CanisterThresholdSigTestEnvironment::new_with_registry_version(4, rv, rng);
    let (dealers, receivers) =
        env.choose_dealers_and_receivers(&IDkgParticipants::AllNodesAsDealersAndReceivers, rng);
    let alg = AlgorithmId::from(key_id.algorithm);
    let key_transcript = generate_key_transcript(&env, &dealers, &receivers, alg, rng);
    let blinder_unmasked_params =
        setup_unmasked_random_params(&env, alg, &dealers, &receivers, rng);
    let blinder_transcript = env
        .nodes
        .run_idkg_and_create_and_verify_transcript(&blinder_unmasked_params, rng);
    let pre_sig = SchnorrPreSignatureTranscript::new(blinder_transcript).unwrap();
    SchnorrMatchedPreSignature {
        id,
        height,
        pre_signature: Arc::new(pre_sig),
        key_transcript: Arc::new(key_transcript),
    }
}

fn fake_signature_request_args(
    key_id: MasterPublicKeyId,
    height: Height,
    pre_sig_id: Option<PreSigId>,
    rv: RegistryVersion,
) -> ThresholdArguments {
    match key_id {
        MasterPublicKeyId::Ecdsa(key_id) => ThresholdArguments::Ecdsa(EcdsaArguments {
            message_hash: [0; 32],
            pre_signature: pre_sig_id
                .map(|id| fake_ecdsa_matched_pre_signature(&key_id, height, id, rv)),
            key_id,
        }),
        MasterPublicKeyId::Schnorr(key_id) => ThresholdArguments::Schnorr(SchnorrArguments {
            message: Arc::new(vec![1; 48]),
            taproot_tree_root: None,
            pre_signature: pre_sig_id
                .map(|id| fake_schnorr_matched_pre_signature(&key_id, height, id, rv)),
            key_id,
        }),
        MasterPublicKeyId::VetKd(key_id) => ThresholdArguments::VetKd(VetKdArguments {
            key_id: key_id.clone(),
            input: Arc::new(vec![1; 32]),
            transport_public_key: vec![1; 32],
            ni_dkg_id: fake_dkg_id(key_id),
            height,
        }),
    }
}

pub fn fake_signature_request_context(
    key_id: MasterPublicKeyId,
    pseudo_random_id: [u8; 32],
) -> SignWithThresholdContext {
    let rv = RegistryVersion::from(10);
    SignWithThresholdContext {
        request: RequestBuilder::new().build(),
        args: fake_signature_request_args(key_id, Height::from(0), None, rv),
        derivation_path: Arc::new(vec![]),
        batch_time: UNIX_EPOCH,
        pseudo_random_id,
        matched_pre_signature: None,
        nonce: None,
    }
}

pub fn fake_signature_request_context_with_pre_sig(
    request_id: RequestId,
    key_id: IDkgMasterPublicKeyId,
    pre_signature: Option<PreSigId>,
) -> (CallbackId, SignWithThresholdContext) {
    let rv = RegistryVersion::from(10);
    let height = Height::from(1);
    let context = SignWithThresholdContext {
        request: RequestBuilder::new().build(),
        args: fake_signature_request_args(key_id.into(), height, pre_signature, rv),
        derivation_path: Arc::new(vec![]),
        batch_time: UNIX_EPOCH,
        pseudo_random_id: [request_id.callback_id.get() as u8; 32],
        matched_pre_signature: pre_signature.map(|pid| (pid, height)),
        nonce: None,
    };
    (request_id.callback_id, context)
}

pub fn fake_signature_request_context_from_id(
    key_id: MasterPublicKeyId,
    pre_sig_id: PreSigId,
    request_id: RequestId,
) -> (CallbackId, SignWithThresholdContext) {
    let rv = RegistryVersion::from(10);
    let height = request_id.height;
    let context = SignWithThresholdContext {
        request: RequestBuilder::new().build(),
        args: fake_signature_request_args(key_id, height, Some(pre_sig_id), rv),
        derivation_path: Arc::new(vec![]),
        batch_time: UNIX_EPOCH,
        pseudo_random_id: [request_id.callback_id.get() as u8; 32],
        matched_pre_signature: Some((pre_sig_id, height)),
        nonce: Some([0; 32]),
    };
    (request_id.callback_id, context)
}

pub fn fake_malformed_signature_request_context_from_id(
    key_id: MasterPublicKeyId,
    pre_sig_id: PreSigId,
    request_id: RequestId,
) -> (CallbackId, SignWithThresholdContext) {
    let (callback_id, mut context) =
        fake_signature_request_context_from_id(key_id, pre_sig_id, request_id);

    // Change the algorithm ID of the key transcript to make it invalid.
    match &mut context.args {
        ThresholdArguments::Ecdsa(ecdsa) => {
            let mut key_transcript = ecdsa
                .pre_signature
                .as_ref()
                .unwrap()
                .key_transcript
                .as_ref()
                .clone();
            key_transcript.algorithm_id = AlgorithmId::Tls;
            ecdsa.pre_signature.as_mut().unwrap().key_transcript = Arc::new(key_transcript);
        }
        ThresholdArguments::Schnorr(schnorr) => {
            let mut key_transcript = schnorr
                .pre_signature
                .as_ref()
                .unwrap()
                .key_transcript
                .as_ref()
                .clone();
            key_transcript.algorithm_id = AlgorithmId::Tls;
            schnorr.pre_signature.as_mut().unwrap().key_transcript = Arc::new(key_transcript);
        }
        // VetKd contexts cannot be malformed in this way.
        ThresholdArguments::VetKd(_) => {}
    };

    (callback_id, context)
}

pub fn fake_signature_request_context_with_registry_version(
    pre_sig_id: Option<PreSigId>,
    key_id: &MasterPublicKeyId,
    rv: RegistryVersion,
) -> SignWithThresholdContext {
    let height = Height::from(1);
    SignWithThresholdContext {
        request: RequestBuilder::new().build(),
        args: fake_signature_request_args(key_id.clone(), height, pre_sig_id, rv),
        derivation_path: Arc::new(vec![]),
        batch_time: UNIX_EPOCH,
        pseudo_random_id: [1; 32],
        matched_pre_signature: pre_sig_id.map(|pid| (pid, height)),
        nonce: Some([0; 32]),
    }
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

#[derive(Clone)]
pub struct FakeCertifiedStateSnapshot {
    pub height: Height,
    pub state: Arc<ReplicatedState>,
}

impl FakeCertifiedStateSnapshot {
    pub fn get_labeled_state(&self) -> Labeled<Arc<ReplicatedState>> {
        Labeled::new(self.height, self.state.clone())
    }

    pub fn inc_height_by(&mut self, height: u64) -> Height {
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

    fn read_certified_state_with_exclusion(
        &self,
        _paths: &LabeledTree<()>,
        _exclusion: Option<&MatchPatternPath>,
    ) -> Option<(MixedHashTree, Certification)> {
        None
    }
}

#[derive(Clone)]
/// A test struct that contains a pre-signature ref, and all of the IDkgTranscripts
/// referenced by it.
pub struct TestPreSigRef {
    pub idkg_transcripts: BTreeMap<TranscriptRef, IDkgTranscript>,
    pub pre_signature_ref: PreSignatureRef,
}

impl From<&ThresholdEcdsaSigInputsOwned> for TestPreSigRef {
    fn from(inputs: &ThresholdEcdsaSigInputsOwned) -> TestPreSigRef {
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
        let pre_signature_ref = PreSignatureQuadrupleRef {
            key_id: fake_ecdsa_key_id(),
            kappa_unmasked_ref: UnmaskedTranscript::try_from((height, quad.kappa_unmasked()))
                .unwrap(),
            lambda_masked_ref: MaskedTranscript::try_from((height, quad.lambda_masked())).unwrap(),
            kappa_times_lambda_ref: MaskedTranscript::try_from((height, quad.kappa_times_lambda()))
                .unwrap(),
            key_times_lambda_ref: MaskedTranscript::try_from((height, quad.key_times_lambda()))
                .unwrap(),
            key_unmasked_ref: UnmaskedTranscript::try_from((height, key)).unwrap(),
        };
        TestPreSigRef {
            idkg_transcripts,
            pre_signature_ref: PreSignatureRef::Ecdsa(pre_signature_ref),
        }
    }
}

impl From<&ThresholdSchnorrSigInputsOwned> for TestPreSigRef {
    fn from(inputs: &ThresholdSchnorrSigInputsOwned) -> TestPreSigRef {
        let height = Height::from(0);
        let pre_signature = inputs.presig_transcript();
        let key = inputs.key_transcript();
        let algorithm = schnorr_algorithm(key.algorithm_id);
        let transcripts = vec![pre_signature.blinder_unmasked().clone(), key.clone()];
        let mut idkg_transcripts: BTreeMap<TranscriptRef, IDkgTranscript> = Default::default();
        for t in transcripts {
            idkg_transcripts.insert(TranscriptRef::new(height, t.transcript_id), t);
        }
        let pre_signature_ref = PreSignatureTranscriptRef {
            key_id: fake_schnorr_key_id(algorithm),
            blinder_unmasked_ref: UnmaskedTranscript::try_from((
                height,
                pre_signature.blinder_unmasked(),
            ))
            .unwrap(),
            key_unmasked_ref: UnmaskedTranscript::try_from((height, key)).unwrap(),
        };
        TestPreSigRef {
            idkg_transcripts,
            pre_signature_ref: PreSignatureRef::Schnorr(pre_signature_ref),
        }
    }
}

pub fn empty_idkg_payload(subnet_id: SubnetId) -> IDkgPayload {
    empty_idkg_payload_with_key_ids(subnet_id, vec![fake_ecdsa_idkg_master_public_key_id()])
}

pub fn empty_idkg_payload_with_key_ids(
    subnet_id: SubnetId,
    key_ids: Vec<IDkgMasterPublicKeyId>,
) -> IDkgPayload {
    IDkgPayload::empty(
        Height::new(0),
        subnet_id,
        key_ids
            .into_iter()
            .map(|key_id| MasterKeyTranscript::new(key_id.clone(), KeyTranscriptCreation::Begin))
            .collect(),
    )
}

pub fn key_id_with_name(key_id: &MasterPublicKeyId, name: &str) -> MasterPublicKeyId {
    let mut key_id = key_id.clone();
    match key_id {
        MasterPublicKeyId::Ecdsa(ref mut key_id) => key_id.name = name.into(),
        MasterPublicKeyId::Schnorr(ref mut key_id) => key_id.name = name.into(),
        MasterPublicKeyId::VetKd(ref mut key_id) => key_id.name = name.into(),
    }
    key_id
}

pub fn fake_ecdsa_key_id() -> EcdsaKeyId {
    EcdsaKeyId::from_str("Secp256k1:some_key").unwrap()
}

pub fn fake_ecdsa_idkg_master_public_key_id() -> IDkgMasterPublicKeyId {
    MasterPublicKeyId::Ecdsa(fake_ecdsa_key_id())
        .try_into()
        .unwrap()
}

pub fn fake_schnorr_key_id(algorithm: SchnorrAlgorithm) -> SchnorrKeyId {
    SchnorrKeyId {
        algorithm,
        name: String::from("some_schnorr_key"),
    }
}

pub fn fake_schnorr_idkg_master_public_key_id(
    algorithm: SchnorrAlgorithm,
) -> IDkgMasterPublicKeyId {
    MasterPublicKeyId::Schnorr(fake_schnorr_key_id(algorithm))
        .try_into()
        .unwrap()
}

pub fn schnorr_algorithm(algorithm: AlgorithmId) -> SchnorrAlgorithm {
    match algorithm {
        AlgorithmId::ThresholdSchnorrBip340 => SchnorrAlgorithm::Bip340Secp256k1,
        AlgorithmId::ThresholdEd25519 => SchnorrAlgorithm::Ed25519,
        other => panic!("Unexpected algorithm: {other:?}"),
    }
}

pub fn fake_vetkd_key_id() -> VetKdKeyId {
    VetKdKeyId::from_str("bls12_381_g2:some_key").unwrap()
}

pub fn fake_vetkd_master_public_key_id() -> MasterPublicKeyId {
    MasterPublicKeyId::VetKd(fake_vetkd_key_id())
}

pub fn fake_dkg_id(key_id: VetKdKeyId) -> NiDkgId {
    NiDkgId {
        start_block_height: Height::from(0),
        dealer_subnet: subnet_test_id(0),
        dkg_tag: NiDkgTag::HighThresholdForKey(NiDkgMasterPublicKeyId::VetKd(key_id)),
        target_subnet: NiDkgTargetSubnet::Local,
    }
}

pub fn fake_master_public_key_ids_for_all_idkg_algorithms() -> Vec<IDkgMasterPublicKeyId> {
    AlgorithmId::iter()
        .flat_map(|alg| match alg {
            AlgorithmId::ThresholdEcdsaSecp256k1 => Some(fake_ecdsa_idkg_master_public_key_id()),
            AlgorithmId::ThresholdSchnorrBip340 => Some(fake_schnorr_idkg_master_public_key_id(
                SchnorrAlgorithm::Bip340Secp256k1,
            )),
            AlgorithmId::ThresholdEd25519 => Some(fake_schnorr_idkg_master_public_key_id(
                SchnorrAlgorithm::Ed25519,
            )),
            _ => None,
        })
        .collect()
}

pub fn fake_master_public_key_ids_for_all_algorithms() -> Vec<MasterPublicKeyId> {
    std::iter::once(fake_vetkd_master_public_key_id())
        .chain(
            fake_master_public_key_ids_for_all_idkg_algorithms()
                .into_iter()
                .map(MasterPublicKeyId::from),
        )
        .collect()
}

/// Creates a TranscriptID for tests
pub fn create_transcript_id(id: u64) -> IDkgTranscriptId {
    let subnet = SubnetId::from(PrincipalId::new_subnet_test_id(314159));
    let height = Height::new(42);
    IDkgTranscriptId::new(subnet, id, height)
}

/// Creates a TranscriptID for tests
pub fn create_transcript_id_with_height(id: u64, height: Height) -> IDkgTranscriptId {
    let subnet = SubnetId::from(PrincipalId::new_subnet_test_id(314159));
    IDkgTranscriptId::new(subnet, id, height)
}

/// Creates a pre-signature ref and all of its transcripts at the given height for tests.
pub fn create_pre_sig_ref_with_height(
    caller: u8,
    height: Height,
    key_id: &IDkgMasterPublicKeyId,
) -> TestPreSigRef {
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
        verified_dealings: Arc::new(BTreeMap::new()),
        transcript_type: IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(
            key_masked_id,
        )),
        algorithm_id: AlgorithmId::from(key_id.inner()),
        internal_transcript_raw: vec![],
    };
    create_pre_sig_ref_with_args(caller, &receivers, key_unmasked, height, key_id)
}

pub fn create_pre_sig_ref_with_args(
    caller: u8,
    receivers: &BTreeSet<NodeId>,
    key_unmasked: IDkgTranscript,
    height: Height,
    key_id: &IDkgMasterPublicKeyId,
) -> TestPreSigRef {
    match key_id.inner() {
        MasterPublicKeyId::Ecdsa(key_id) => {
            create_ecdsa_pre_sig_ref_with_args(caller, receivers, key_unmasked, height, key_id)
        }
        MasterPublicKeyId::Schnorr(key_id) => {
            create_schnorr_pre_sig_ref_with_args(caller, receivers, key_unmasked, height, key_id)
        }
        MasterPublicKeyId::VetKd(_) => panic!("not applicable to vetKD"),
    }
}

/// Creates an ECDSA pre-signature ref and all of its transcripts for tests.
pub fn create_ecdsa_pre_sig_ref_with_args(
    caller: u8,
    receivers: &BTreeSet<NodeId>,
    key_unmasked: IDkgTranscript,
    height: Height,
    key_id: &EcdsaKeyId,
) -> TestPreSigRef {
    let transcript_id = |offset| {
        let val = caller as u64;
        create_transcript_id(val * 214365 + offset)
    };

    let algorithm_id = key_unmasked.algorithm_id;
    assert!(
        algorithm_id.is_threshold_ecdsa(),
        "Expected tECDSA algorithm"
    );
    assert_eq!(algorithm_id, AlgorithmId::from(key_id.curve));
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
        verified_dealings: Arc::new(BTreeMap::new()),
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
        verified_dealings: Arc::new(BTreeMap::new()),
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
        verified_dealings: Arc::new(BTreeMap::new()),
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
        verified_dealings: Arc::new(BTreeMap::new()),
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

    TestPreSigRef {
        idkg_transcripts,
        pre_signature_ref: PreSignatureRef::Ecdsa(presig_quadruple_ref),
    }
}

/// Creates a schnorr pre-signature ref and all of its transcripts for tests.
pub fn create_schnorr_pre_sig_ref_with_args(
    caller: u8,
    receivers: &BTreeSet<NodeId>,
    key_unmasked: IDkgTranscript,
    height: Height,
    key_id: &SchnorrKeyId,
) -> TestPreSigRef {
    let transcript_id = |offset| {
        let val = caller as u64;
        create_transcript_id(val * 214365 + offset)
    };

    let algorithm_id = key_unmasked.algorithm_id;
    assert!(
        algorithm_id.is_threshold_schnorr(),
        "Expected tSchnorr algorithm"
    );
    assert_eq!(algorithm_id, AlgorithmId::from(key_id.algorithm));
    let blinder_unmasked_id = transcript_id(10);
    let mut idkg_transcripts = BTreeMap::new();

    let blinder_unmasked = IDkgTranscript {
        transcript_id: blinder_unmasked_id,
        receivers: IDkgReceivers::new(receivers.clone()).unwrap(),
        registry_version: RegistryVersion::from(1),
        verified_dealings: Arc::new(BTreeMap::new()),
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

    TestPreSigRef {
        idkg_transcripts,
        pre_signature_ref: PreSignatureRef::Schnorr(presig_transcript_ref),
    }
}

/// Creates a pre-signature ref and all of its transcripts for tests.
pub fn create_pre_sig_ref(caller: u8, key_id: &IDkgMasterPublicKeyId) -> TestPreSigRef {
    create_pre_sig_ref_with_height(caller, Height::new(100), key_id)
}

#[allow(clippy::large_enum_variant)]
pub enum ThresholdSigInputsOwned {
    Ecdsa(ThresholdEcdsaSigInputsOwned),
    Schnorr(ThresholdSchnorrSigInputsOwned),
    VetKd(VetKdArgs),
}

impl ThresholdSigInputsOwned {
    pub fn as_ref<'a>(&'a self) -> ThresholdSigInputs<'a> {
        match self {
            ThresholdSigInputsOwned::Ecdsa(i) => ThresholdSigInputs::Ecdsa(i.as_ref()),
            ThresholdSigInputsOwned::Schnorr(i) => ThresholdSigInputs::Schnorr(i.as_ref()),
            ThresholdSigInputsOwned::VetKd(i) => ThresholdSigInputs::VetKd(i.clone()),
        }
    }
}

pub fn create_threshold_sig_inputs(
    caller: u8,
    key_id: &IDkgMasterPublicKeyId,
) -> ThresholdSigInputsOwned {
    let path = ExtendedDerivationPath {
        caller: PrincipalId::try_from(&vec![caller]).unwrap(),
        derivation_path: vec![],
    };
    let rnd = Randomness::from([0_u8; 32]);
    match key_id.inner() {
        MasterPublicKeyId::Ecdsa(key_id) => {
            let pre_sig = fake_ecdsa_matched_pre_signature(
                key_id,
                Height::from(0),
                PreSigId(1),
                RegistryVersion::from(1),
            );
            ThresholdSigInputsOwned::Ecdsa(ThresholdEcdsaSigInputsOwned::new(
                path.caller,
                path.derivation_path,
                [1; 32].to_vec(),
                rnd.get(),
                pre_sig.pre_signature.as_ref().clone(),
                pre_sig.key_transcript.as_ref().clone(),
            ))
        }
        MasterPublicKeyId::Schnorr(key_id) => {
            let pre_sig = fake_schnorr_matched_pre_signature(
                key_id,
                Height::from(0),
                PreSigId(1),
                RegistryVersion::from(1),
            );
            ThresholdSigInputsOwned::Schnorr(ThresholdSchnorrSigInputsOwned::new(
                path.caller,
                path.derivation_path,
                vec![1; 64],
                None,
                rnd.get(),
                pre_sig.pre_signature.as_ref().clone(),
                pre_sig.key_transcript.as_ref().clone(),
            ))
        }
        MasterPublicKeyId::VetKd(_) => panic!("not applicable to vetKD"),
    }
}
