use ic_crypto_tree_hash::{LabeledTree, MixedHashTree};
use ic_interfaces_state_manager::{CertifiedStateSnapshot, Labeled};
use ic_management_canister_types_private::{
    EcdsaCurve, EcdsaKeyId, MasterPublicKeyId, SchnorrAlgorithm, SchnorrKeyId, VetKdCurve,
    VetKdKeyId,
};
use ic_replicated_state::{
    metadata_state::subnet_call_context_manager::{
        EcdsaArguments, ReshareChainKeyContext, SchnorrArguments, SignWithThresholdContext,
        ThresholdArguments, VetKdArguments,
    },
    ReplicatedState,
};
use ic_test_utilities_state::ReplicatedStateBuilder;
use ic_test_utilities_types::{
    ids::{node_test_id, subnet_test_id},
    messages::RequestBuilder,
};
use ic_types::{
    batch::ConsensusResponse,
    consensus::{
        certification::Certification,
        idkg::{
            common::{PreSignatureRef, ThresholdSigInputsRef},
            ecdsa::{PreSignatureQuadrupleRef, ThresholdEcdsaSigInputsRef},
            schnorr::{PreSignatureTranscriptRef, ThresholdSchnorrSigInputsRef},
            HasIDkgMasterPublicKeyId, IDkgMasterPublicKeyId, IDkgPayload, IDkgReshareRequest,
            KeyTranscriptCreation, MaskedTranscript, MasterKeyTranscript, PreSigId, RequestId,
            TranscriptRef, UnmaskedTranscript,
        },
    },
    crypto::{
        canister_threshold_sig::{
            idkg::{
                IDkgMaskedTranscriptOrigin, IDkgReceivers, IDkgTranscript, IDkgTranscriptId,
                IDkgTranscriptType, IDkgUnmaskedTranscriptOrigin,
            },
            ThresholdEcdsaSigInputs, ThresholdSchnorrSigInputs,
        },
        threshold_sig::ni_dkg::{
            NiDkgId, NiDkgMasterPublicKeyId, NiDkgTag, NiDkgTargetId, NiDkgTargetSubnet,
        },
        vetkd::{VetKdArgs, VetKdDerivationContext},
        AlgorithmId, ExtendedDerivationPath,
    },
    messages::{CallbackId, Payload},
    time::UNIX_EPOCH,
    Height, NodeId, PrincipalId, Randomness, RegistryVersion, SubnetId,
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

fn fake_signature_request_args(key_id: MasterPublicKeyId, height: Height) -> ThresholdArguments {
    match key_id {
        MasterPublicKeyId::Ecdsa(key_id) => ThresholdArguments::Ecdsa(EcdsaArguments {
            key_id,
            message_hash: [0; 32],
        }),
        MasterPublicKeyId::Schnorr(key_id) => ThresholdArguments::Schnorr(SchnorrArguments {
            key_id,
            message: Arc::new(vec![1; 48]),
            taproot_tree_root: None,
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
    SignWithThresholdContext {
        request: RequestBuilder::new().build(),
        args: fake_signature_request_args(key_id, Height::from(0)),
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
    let height = Height::from(1);
    let context = SignWithThresholdContext {
        request: RequestBuilder::new().build(),
        args: fake_signature_request_args(key_id.into(), height),
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
    let height = request_id.height;
    let context = SignWithThresholdContext {
        request: RequestBuilder::new().build(),
        args: fake_signature_request_args(key_id, height),
        derivation_path: Arc::new(vec![]),
        batch_time: UNIX_EPOCH,
        pseudo_random_id: [request_id.callback_id.get() as u8; 32],
        matched_pre_signature: Some((pre_sig_id, height)),
        nonce: Some([0; 32]),
    };
    (request_id.callback_id, context)
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

    fn read_certified_state(
        &self,
        _paths: &LabeledTree<()>,
    ) -> Option<(MixedHashTree, Certification)> {
        None
    }
}

pub trait HasPreSignature {
    fn pre_signature(&self) -> Option<PreSignatureRef>;
}

impl HasPreSignature for ThresholdSigInputsRef {
    fn pre_signature(&self) -> Option<PreSignatureRef> {
        match self {
            ThresholdSigInputsRef::Ecdsa(inputs) => {
                Some(PreSignatureRef::Ecdsa(inputs.presig_quadruple_ref.clone()))
            }
            ThresholdSigInputsRef::Schnorr(inputs) => Some(PreSignatureRef::Schnorr(
                inputs.presig_transcript_ref.clone(),
            )),
            ThresholdSigInputsRef::VetKd(_) => None,
        }
    }
}

#[derive(Clone)]
pub struct TestSigInputs {
    pub idkg_transcripts: BTreeMap<TranscriptRef, IDkgTranscript>,
    pub sig_inputs_ref: ThresholdSigInputsRef,
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
            taproot_tree_root: None,
        };
        TestSigInputs {
            idkg_transcripts,
            sig_inputs_ref: ThresholdSigInputsRef::Schnorr(sig_inputs_ref),
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

pub fn algorithm_for_key_id(key_id: &IDkgMasterPublicKeyId) -> AlgorithmId {
    match key_id.inner() {
        MasterPublicKeyId::Ecdsa(ecdsa_key_id) => match ecdsa_key_id.curve {
            EcdsaCurve::Secp256k1 => AlgorithmId::ThresholdEcdsaSecp256k1,
        },
        MasterPublicKeyId::Schnorr(schnorr_key_id) => match schnorr_key_id.algorithm {
            SchnorrAlgorithm::Bip340Secp256k1 => AlgorithmId::ThresholdSchnorrBip340,
            SchnorrAlgorithm::Ed25519 => AlgorithmId::ThresholdEd25519,
        },
        MasterPublicKeyId::VetKd(vetkd_key_id) => match vetkd_key_id.curve {
            VetKdCurve::Bls12_381_G2 => AlgorithmId::Placeholder,
        },
    }
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

/// Creates a test signature input
pub fn create_sig_inputs_with_height(
    caller: u8,
    height: Height,
    key_id: MasterPublicKeyId,
) -> TestSigInputs {
    if let MasterPublicKeyId::VetKd(key_id) = &key_id {
        return create_vetkd_inputs_with_args(caller, key_id);
    }
    let transcript_id = |offset| {
        let val = caller as u64;
        create_transcript_id(val * 214365 + offset)
    };
    let receivers: BTreeSet<_> = vec![node_test_id(1)].into_iter().collect();
    let key_unmasked_id = transcript_id(50);
    let key_masked_id = transcript_id(40);
    let idkg_key_id = IDkgMasterPublicKeyId::try_from(key_id).unwrap();
    let key_unmasked = IDkgTranscript {
        transcript_id: key_unmasked_id,
        receivers: IDkgReceivers::new(receivers.clone()).unwrap(),
        registry_version: RegistryVersion::from(1),
        verified_dealings: BTreeMap::new(),
        transcript_type: IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(
            key_masked_id,
        )),
        algorithm_id: algorithm_for_key_id(&idkg_key_id),
        internal_transcript_raw: vec![],
    };
    create_sig_inputs_with_args(caller, &receivers, key_unmasked, height, &idkg_key_id)
}

pub fn create_sig_inputs_with_args(
    caller: u8,
    receivers: &BTreeSet<NodeId>,
    key_unmasked: IDkgTranscript,
    height: Height,
    key_id: &IDkgMasterPublicKeyId,
) -> TestSigInputs {
    match key_id.inner() {
        MasterPublicKeyId::Ecdsa(key_id) => {
            create_ecdsa_sig_inputs_with_args(caller, receivers, key_unmasked, height, key_id)
        }
        MasterPublicKeyId::Schnorr(key_id) => {
            create_schnorr_sig_inputs_with_args(caller, receivers, key_unmasked, height, key_id)
        }
        MasterPublicKeyId::VetKd(_) => panic!("not applicable to vetKD"),
    }
}

/// Creates a test signature input
pub fn create_ecdsa_sig_inputs_with_args(
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
        algorithm_for_key_id(&MasterPublicKeyId::Ecdsa(key_id.clone()).try_into().unwrap())
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

/// Creates a test signature input
pub fn create_schnorr_sig_inputs_with_args(
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
        algorithm_for_key_id(
            &MasterPublicKeyId::Schnorr(key_id.clone())
                .try_into()
                .unwrap()
        )
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
        None,
    );

    TestSigInputs {
        idkg_transcripts,
        sig_inputs_ref: ThresholdSigInputsRef::Schnorr(sig_inputs_ref),
    }
}

/// Creates a test vetkd input
pub fn create_vetkd_inputs_with_args(caller: u8, key_id: &VetKdKeyId) -> TestSigInputs {
    let inputs = VetKdArgs {
        ni_dkg_id: fake_dkg_id(key_id.clone()),
        context: VetKdDerivationContext {
            caller: PrincipalId::try_from(&vec![caller]).unwrap(),
            context: vec![],
        },
        input: vec![],
        transport_public_key: vec![1; 32],
    };

    TestSigInputs {
        idkg_transcripts: BTreeMap::new(),
        sig_inputs_ref: ThresholdSigInputsRef::VetKd(inputs),
    }
}

// Creates a test signature input
pub fn create_sig_inputs(caller: u8, key_id: &MasterPublicKeyId) -> TestSigInputs {
    create_sig_inputs_with_height(caller, Height::new(0), key_id.clone())
}

pub fn add_available_quadruple_to_payload(
    idkg_payload: &mut IDkgPayload,
    pre_signature_id: PreSigId,
    registry_version: RegistryVersion,
) {
    let sig_inputs = create_sig_inputs(
        pre_signature_id.id() as u8,
        &fake_ecdsa_idkg_master_public_key_id(),
    );
    idkg_payload.available_pre_signatures.insert(
        pre_signature_id,
        sig_inputs.sig_inputs_ref.pre_signature().unwrap(),
    );
    for (t_ref, mut transcript) in sig_inputs.idkg_transcripts {
        transcript.registry_version = registry_version;
        idkg_payload
            .idkg_transcripts
            .insert(t_ref.transcript_id, transcript);
    }
}
