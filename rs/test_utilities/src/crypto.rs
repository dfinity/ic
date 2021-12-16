pub mod basic_utilities;
pub mod fake_tls_handshake;

pub use ic_crypto_test_utils::files as temp_dir;

use crate::types::ids::node_test_id;
use ic_crypto::utils::TempCryptoComponent;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::PublicCoefficientsBytes;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    ni_dkg_groth20_bls12_381, CspNiDkgDealing, CspNiDkgTranscript,
};
use ic_interfaces::crypto::{
    BasicSigVerifier, BasicSigVerifierByPublicKey, BasicSigner, CanisterSigVerifier, IDkgProtocol,
    KeyManager, LoadTranscriptResult, NiDkgAlgorithm, ThresholdEcdsaSigVerifier,
    ThresholdEcdsaSigner, ThresholdSigVerifier, ThresholdSigVerifierByPublicKey, ThresholdSigner,
};
use ic_interfaces::crypto::{MultiSigVerifier, MultiSigner, Signable};
use ic_interfaces::registry::RegistryClient;
use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_client::fake::FakeRegistryClient;
use ic_registry_common::proto_registry_data_provider::ProtoRegistryDataProvider;
use ic_types::crypto::canister_threshold_sig::error::*;
use ic_types::crypto::canister_threshold_sig::idkg::*;
use ic_types::crypto::canister_threshold_sig::*;
use ic_types::crypto::threshold_sig::ni_dkg::errors::create_dealing_error::DkgCreateDealingError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::create_transcript_error::DkgCreateTranscriptError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::key_removal_error::DkgKeyRemovalError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::load_transcript_error::DkgLoadTranscriptError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::verify_dealing_error::DkgVerifyDealingError;
use ic_types::crypto::threshold_sig::ni_dkg::{
    config::NiDkgConfig, DkgId, NiDkgDealing, NiDkgId, NiDkgTag, NiDkgTranscript,
};
use ic_types::crypto::{
    AlgorithmId, BasicSig, BasicSigOf, CanisterSigOf, CombinedMultiSig, CombinedMultiSigOf,
    CombinedThresholdSig, CombinedThresholdSigOf, CryptoResult, IndividualMultiSig,
    IndividualMultiSigOf, ThresholdSigShare, ThresholdSigShareOf, UserPublicKey,
};
use ic_types::*;
use ic_types::{NodeId, RegistryVersion};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

pub fn empty_fake_registry() -> Arc<dyn RegistryClient> {
    Arc::new(FakeRegistryClient::new(Arc::new(
        ProtoRegistryDataProvider::new(),
    )))
}

pub fn temp_crypto_components_for(nodes: &[NodeId]) -> BTreeMap<NodeId, TempCryptoComponent> {
    let registry = RegistryClientImpl::new(Arc::new(ProtoRegistryDataProvider::new()), None);
    TempCryptoComponent::multiple_new(nodes, Arc::new(registry))
}

pub fn temp_crypto_component_with_fake_registry(node_id: NodeId) -> TempCryptoComponent {
    TempCryptoComponent::new(empty_fake_registry(), node_id)
}

pub fn crypto_for<T>(node_id: NodeId, crypto_components: &BTreeMap<NodeId, T>) -> &T {
    crypto_components
        .get(&node_id)
        .unwrap_or_else(|| panic!("missing crypto component for {:?}", node_id))
}

pub fn empty_ni_dkg_csp_dealing() -> CspNiDkgDealing {
    ni_dkg_csp_dealing(0)
}

pub fn ni_dkg_csp_dealing(seed: u8) -> CspNiDkgDealing {
    use ni_dkg_groth20_bls12_381 as scheme;
    fn fr(seed: u8) -> scheme::Fr {
        scheme::Fr([seed; scheme::Fr::SIZE])
    }
    fn g1(seed: u8) -> scheme::G1 {
        scheme::G1([seed; scheme::G1::SIZE])
    }
    fn g2(seed: u8) -> scheme::G2 {
        scheme::G2([seed; scheme::G2::SIZE])
    }
    const NUM_RECEIVERS: usize = 1;
    CspNiDkgDealing::Groth20_Bls12_381(scheme::Dealing {
        public_coefficients: scheme::PublicCoefficientsBytes {
            coefficients: Vec::new(),
        },
        ciphertexts: scheme::EncryptedShares {
            rand_r: [g1(seed); scheme::NUM_CHUNKS],
            rand_s: [g1(seed); scheme::NUM_CHUNKS],
            rand_z: [g2(seed); scheme::NUM_CHUNKS],
            ciphertext_chunks: (0..NUM_RECEIVERS)
                .map(|i| [g1(seed ^ (i as u8)); scheme::NUM_CHUNKS])
                .collect(),
        },
        zk_proof_decryptability: ni_dkg_groth20_bls12_381::ZKProofDec {
            // TODO(CRP-530): Populate this when it has been defined in the spec.
            first_move_y0: g1(seed),
            first_move_b: [g1(seed); scheme::NUM_ZK_REPETITIONS],
            first_move_c: [g1(seed); scheme::NUM_ZK_REPETITIONS],
            second_move_d: (0..NUM_RECEIVERS + 1)
                .map(|i| g1(seed ^ (i as u8)))
                .collect(),
            second_move_y: g1(seed),
            response_z_r: (0..NUM_RECEIVERS).map(|i| fr(seed | (i as u8))).collect(),
            response_z_s: [fr(seed); scheme::NUM_ZK_REPETITIONS],
            response_z_b: fr(seed),
        },
        zk_proof_correct_sharing: ni_dkg_groth20_bls12_381::ZKProofShare {
            first_move_f: g1(seed),
            first_move_a: g2(seed),
            first_move_y: g1(seed),
            response_z_r: fr(seed),
            response_z_a: fr(seed),
        },
    })
}

pub fn empty_ni_csp_dkg_transcript() -> CspNiDkgTranscript {
    CspNiDkgTranscript::Groth20_Bls12_381(ni_dkg_groth20_bls12_381::Transcript {
        public_coefficients: PublicCoefficientsBytes {
            coefficients: vec![],
        },
        receiver_data: Default::default(),
    })
}

pub fn empty_ni_dkg_dealing() -> NiDkgDealing {
    NiDkgDealing {
        internal_dealing: empty_ni_dkg_csp_dealing(),
    }
}

pub fn empty_ni_dkg_transcripts_with_committee(
    committee: Vec<NodeId>,
    registry_version: u64,
) -> std::collections::BTreeMap<NiDkgTag, NiDkgTranscript> {
    vec![
        (
            NiDkgTag::LowThreshold,
            NiDkgTranscript::dummy_transcript_for_tests_with_params(
                committee.clone(),
                NiDkgTag::LowThreshold,
                NiDkgTag::LowThreshold.threshold_for_subnet_of_size(committee.len()) as u32,
                registry_version,
            ),
        ),
        (
            NiDkgTag::HighThreshold,
            NiDkgTranscript::dummy_transcript_for_tests_with_params(
                committee.clone(),
                NiDkgTag::HighThreshold,
                NiDkgTag::HighThreshold.threshold_for_subnet_of_size(committee.len()) as u32,
                registry_version,
            ),
        ),
    ]
    .into_iter()
    .collect()
}

pub fn empty_ni_dkg_transcripts() -> std::collections::BTreeMap<NiDkgTag, NiDkgTranscript> {
    empty_ni_dkg_transcripts_with_committee(vec![node_test_id(0)], 0)
}

pub fn dummy_idkg_transcript_id_for_tests(id: usize) -> IDkgTranscriptId {
    let subnet = SubnetId::from(PrincipalId::new_subnet_test_id(314159));
    IDkgTranscriptId::new(subnet, id)
}

pub fn dummy_idkg_dealing_for_tests() -> IDkgDealing {
    IDkgDealing {
        transcript_id: IDkgTranscriptId::new(SubnetId::from(PrincipalId::new_subnet_test_id(1)), 1),
        dealer_id: NodeId::from(PrincipalId::new_node_test_id(0)),
        internal_dealing_raw: vec![],
    }
}

pub fn dummy_idkg_complaint_for_tests() -> IDkgComplaint {
    IDkgComplaint {
        transcript_id: IDkgTranscriptId::new(SubnetId::from(PrincipalId::new_subnet_test_id(1)), 1),
        dealer_id: NodeId::from(PrincipalId::new_node_test_id(0)),
        internal_complaint_raw: vec![],
    }
}

pub fn dummy_idkg_opening_for_tests() -> IDkgOpening {
    IDkgOpening {
        transcript_id: IDkgTranscriptId::new(SubnetId::from(PrincipalId::new_subnet_test_id(1)), 1),
        dealer_id: NodeId::from(PrincipalId::new_node_test_id(0)),
        internal_opening_raw: vec![],
    }
}

pub fn dummy_sig_inputs_for_tests(caller: PrincipalId) -> ThresholdEcdsaSigInputs {
    let (fake_key, fake_presig_quadruple) = {
        let mut nodes = BTreeSet::new();
        nodes.insert(node_test_id(1));

        let original_kappa_id = dummy_idkg_transcript_id_for_tests(1);
        let kappa_id = dummy_idkg_transcript_id_for_tests(2);
        let lambda_id = dummy_idkg_transcript_id_for_tests(3);
        let key_id = dummy_idkg_transcript_id_for_tests(4);

        let fake_kappa = IDkgTranscript {
            transcript_id: kappa_id,
            receivers: IDkgReceivers::new(nodes.clone()).unwrap(),
            registry_version: RegistryVersion::from(1),
            verified_dealings: BTreeMap::new(),
            transcript_type: IDkgTranscriptType::Unmasked(
                IDkgUnmaskedTranscriptOrigin::ReshareMasked(original_kappa_id),
            ),
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            internal_transcript_raw: vec![],
        };

        let fake_lambda = IDkgTranscript {
            transcript_id: lambda_id,
            receivers: IDkgReceivers::new(nodes.clone()).unwrap(),
            registry_version: RegistryVersion::from(1),
            verified_dealings: BTreeMap::new(),
            transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            internal_transcript_raw: vec![],
        };

        let fake_kappa_times_lambda = IDkgTranscript {
            transcript_id: dummy_idkg_transcript_id_for_tests(40),
            receivers: IDkgReceivers::new(nodes.clone()).unwrap(),
            registry_version: RegistryVersion::from(1),
            verified_dealings: BTreeMap::new(),
            transcript_type: IDkgTranscriptType::Masked(
                IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(kappa_id, lambda_id),
            ),
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            internal_transcript_raw: vec![],
        };

        let fake_key = IDkgTranscript {
            transcript_id: key_id,
            receivers: IDkgReceivers::new(nodes.clone()).unwrap(),
            registry_version: RegistryVersion::from(1),
            verified_dealings: BTreeMap::new(),
            transcript_type: IDkgTranscriptType::Unmasked(
                IDkgUnmaskedTranscriptOrigin::ReshareMasked(dummy_idkg_transcript_id_for_tests(50)),
            ),
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            internal_transcript_raw: vec![],
        };

        let fake_key_times_lambda = IDkgTranscript {
            transcript_id: dummy_idkg_transcript_id_for_tests(50),
            receivers: IDkgReceivers::new(nodes).unwrap(),
            registry_version: RegistryVersion::from(1),
            verified_dealings: BTreeMap::new(),
            transcript_type: IDkgTranscriptType::Masked(
                IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(key_id, lambda_id),
            ),
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            internal_transcript_raw: vec![],
        };

        let presig_quadruple = PreSignatureQuadruple::new(
            fake_kappa,
            fake_lambda,
            fake_kappa_times_lambda,
            fake_key_times_lambda,
        )
        .unwrap();

        (fake_key, presig_quadruple)
    };

    let derivation_path = ExtendedDerivationPath {
        caller,
        bip32_derivation_path: vec![],
    };
    ThresholdEcdsaSigInputs::new(
        &derivation_path,
        &[],
        Randomness::from([0_u8; 32]),
        fake_presig_quadruple,
        fake_key,
    )
    .expect("failed to create signature inputs")
}

#[derive(Default)]
pub struct CryptoReturningOk {
    // Here we store the ids of all transcripts, which were loaded by the crypto components.
    pub loaded_transcripts: std::sync::RwLock<BTreeSet<NiDkgId>>,
    // Here we keep track of all transcripts ids asked to be retained.
    pub retained_transcripts: std::sync::RwLock<Vec<HashSet<NiDkgId>>>,
}

impl<T: Signable> BasicSigner<T> for CryptoReturningOk {
    fn sign_basic(
        &self,
        _message: &T,
        _signer: NodeId,
        _registry_version: RegistryVersion,
    ) -> CryptoResult<BasicSigOf<T>> {
        Ok(BasicSigOf::new(BasicSig(vec![])))
    }
}

impl<T: Signable> BasicSigVerifier<T> for CryptoReturningOk {
    fn verify_basic_sig(
        &self,
        _signature: &BasicSigOf<T>,
        _message: &T,
        _signer: NodeId,
        _registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        Ok(())
    }
}

impl<T: Signable> BasicSigVerifierByPublicKey<T> for CryptoReturningOk {
    fn verify_basic_sig_by_public_key(
        &self,
        _signature: &BasicSigOf<T>,
        _signed_bytes: &T,
        _public_key: &UserPublicKey,
    ) -> CryptoResult<()> {
        Ok(())
    }
}

impl<T: Signable> MultiSigner<T> for CryptoReturningOk {
    fn sign_multi(
        &self,
        _message: &T,
        _signer: NodeId,
        _registry_version: RegistryVersion,
    ) -> CryptoResult<IndividualMultiSigOf<T>> {
        Ok(IndividualMultiSigOf::new(IndividualMultiSig(vec![])))
    }
}

impl<T: Signable> MultiSigVerifier<T> for CryptoReturningOk {
    fn verify_multi_sig_individual(
        &self,
        _signature: &IndividualMultiSigOf<T>,
        _message: &T,
        _signer: NodeId,
        _registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        Ok(())
    }

    fn combine_multi_sig_individuals(
        &self,
        _signatures: BTreeMap<NodeId, IndividualMultiSigOf<T>>,
        _registry_version: RegistryVersion,
    ) -> CryptoResult<CombinedMultiSigOf<T>> {
        Ok(CombinedMultiSigOf::new(CombinedMultiSig(vec![])))
    }

    fn verify_multi_sig_combined(
        &self,
        _signature: &CombinedMultiSigOf<T>,
        _message: &T,
        _signers: BTreeSet<NodeId>,
        _registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        Ok(())
    }
}

impl<T: Signable> ThresholdSigner<T> for CryptoReturningOk {
    fn sign_threshold(&self, _message: &T, _dkg_id: DkgId) -> CryptoResult<ThresholdSigShareOf<T>> {
        Ok(ThresholdSigShareOf::new(ThresholdSigShare(vec![])))
    }
}

impl<T: Signable> ThresholdSigVerifier<T> for CryptoReturningOk {
    fn verify_threshold_sig_share(
        &self,
        _signature: &ThresholdSigShareOf<T>,
        _message: &T,
        _dkg_id: DkgId,
        _signer: NodeId,
    ) -> CryptoResult<()> {
        Ok(())
    }

    fn combine_threshold_sig_shares(
        &self,
        _shares: BTreeMap<NodeId, ThresholdSigShareOf<T>>,
        _dkg_id: DkgId,
    ) -> CryptoResult<CombinedThresholdSigOf<T>> {
        Ok(CombinedThresholdSigOf::new(CombinedThresholdSig(vec![])))
    }

    fn verify_threshold_sig_combined(
        &self,
        _signature: &CombinedThresholdSigOf<T>,
        _message: &T,
        _dkg_id: DkgId,
    ) -> CryptoResult<()> {
        Ok(())
    }
}

impl<T: Signable> ThresholdSigVerifierByPublicKey<T> for CryptoReturningOk {
    fn verify_combined_threshold_sig_by_public_key(
        &self,
        _signature: &CombinedThresholdSigOf<T>,
        _message: &T,
        _subnet_id: SubnetId,
        _registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        Ok(())
    }
}

impl<T: Signable> CanisterSigVerifier<T> for CryptoReturningOk {
    fn verify_canister_sig(
        &self,
        _signature: &CanisterSigOf<T>,
        _signed_bytes: &T,
        _public_key: &UserPublicKey,
        _registry_version: RegistryVersion,
    ) -> CryptoResult<()> {
        Ok(())
    }
}

impl NiDkgAlgorithm for CryptoReturningOk {
    fn create_dealing(&self, _config: &NiDkgConfig) -> Result<NiDkgDealing, DkgCreateDealingError> {
        Ok(empty_ni_dkg_dealing())
    }

    fn verify_dealing(
        &self,
        _config: &NiDkgConfig,
        _dealer: NodeId,
        _dealing: &NiDkgDealing,
    ) -> Result<(), DkgVerifyDealingError> {
        Ok(())
    }

    fn create_transcript(
        &self,
        config: &NiDkgConfig,
        _verified_dealings: &BTreeMap<NodeId, NiDkgDealing>,
    ) -> Result<NiDkgTranscript, DkgCreateTranscriptError> {
        let mut transcript = NiDkgTranscript::dummy_transcript_for_tests_with_params(
            config.receivers().get().clone().into_iter().collect(),
            config.dkg_id().dkg_tag,
            config.threshold().get().get() as u32,
            config.registry_version().get(),
        );
        transcript.dkg_id = config.dkg_id();
        Ok(transcript)
    }

    fn load_transcript(
        &self,
        transcript: &NiDkgTranscript,
    ) -> Result<LoadTranscriptResult, DkgLoadTranscriptError> {
        self.loaded_transcripts
            .write()
            .unwrap()
            .insert(transcript.dkg_id);
        Ok(LoadTranscriptResult::SigningKeyAvailable)
    }

    fn retain_only_active_keys(
        &self,
        transcripts: HashSet<NiDkgTranscript>,
    ) -> Result<(), DkgKeyRemovalError> {
        self.retained_transcripts
            .write()
            .unwrap()
            .push(transcripts.iter().map(|t| t.dkg_id).collect());
        Ok(())
    }
}

impl KeyManager for CryptoReturningOk {
    fn check_keys_with_registry(&self, _registry_version: RegistryVersion) -> CryptoResult<()> {
        Ok(())
    }

    fn node_public_keys(&self) -> NodePublicKeys {
        unimplemented!()
    }
}

impl IDkgProtocol for CryptoReturningOk {
    fn create_dealing(
        &self,
        _params: &IDkgTranscriptParams,
    ) -> Result<IDkgDealing, IDkgCreateDealingError> {
        Ok(dummy_idkg_dealing_for_tests())
    }

    fn verify_dealing_public(
        &self,
        _params: &IDkgTranscriptParams,
        _dealing: &IDkgDealing,
    ) -> Result<(), IDkgVerifyDealingPublicError> {
        Ok(())
    }

    fn verify_dealing_private(
        &self,
        _params: &IDkgTranscriptParams,
        _dealing: &IDkgDealing,
    ) -> Result<(), IDkgVerifyDealingPrivateError> {
        Ok(())
    }

    fn create_transcript(
        &self,
        params: &IDkgTranscriptParams,
        verified_dealings: &BTreeMap<NodeId, IDkgMultiSignedDealing>,
    ) -> Result<IDkgTranscript, IDkgCreateTranscriptError> {
        let mut receivers = BTreeSet::new();
        receivers.insert(node_test_id(0));

        let dealings_by_index = verified_dealings
            .iter()
            .map(|(id, d)| (params.dealers().position(*id).expect("mock"), d.clone()))
            .collect();

        Ok(IDkgTranscript {
            transcript_id: dummy_idkg_transcript_id_for_tests(0),
            receivers: IDkgReceivers::new(receivers).unwrap(),
            registry_version: RegistryVersion::from(1),
            verified_dealings: dealings_by_index,
            transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
            algorithm_id: AlgorithmId::Placeholder,
            internal_transcript_raw: vec![],
        })
    }

    // Verification all multi-sig on the various dealings in the transcript.
    fn verify_transcript(
        &self,
        _params: &IDkgTranscriptParams,
        _transcript: &IDkgTranscript,
    ) -> Result<(), IDkgVerifyTranscriptError> {
        Ok(())
    }

    fn load_transcript(
        &self,
        _transcript: &IDkgTranscript,
    ) -> Result<Vec<IDkgComplaint>, IDkgLoadTranscriptError> {
        Ok(vec![])
    }

    fn verify_complaint(
        &self,
        _transcript: &IDkgTranscript,
        _complainer: NodeId,
        _complaint: &IDkgComplaint,
    ) -> Result<(), IDkgVerifyComplaintError> {
        Ok(())
    }

    fn open_transcript(
        &self,
        _transcript: &IDkgTranscript,
        _complaint: &IDkgComplaint,
    ) -> Result<IDkgOpening, IDkgOpenTranscriptError> {
        Ok(dummy_idkg_opening_for_tests())
    }

    fn verify_opening(
        &self,
        _transcript: &IDkgTranscript,
        _opener: NodeId,
        _opening: &IDkgOpening,
        _complaint: &IDkgComplaint,
    ) -> Result<(), IDkgVerifyOpeningError> {
        Ok(())
    }

    fn load_transcript_with_openings(
        &self,
        _transcript: IDkgTranscript,
        _openings: BTreeMap<IDkgComplaint, BTreeMap<NodeId, IDkgOpening>>,
    ) -> Result<(), IDkgLoadTranscriptWithOpeningsError> {
        Ok(())
    }

    fn retain_active_transcripts(&self, _active_transcripts: &[IDkgTranscript]) {}
}

impl ThresholdEcdsaSigner for CryptoReturningOk {
    fn sign_share(
        &self,
        _inputs: &ThresholdEcdsaSigInputs,
    ) -> Result<ThresholdEcdsaSigShare, ThresholdEcdsaSignShareError> {
        Ok(ThresholdEcdsaSigShare {
            sig_share_raw: vec![],
        })
    }
}

impl ThresholdEcdsaSigVerifier for CryptoReturningOk {
    fn verify_sig_share(
        &self,
        _signer: NodeId,
        _inputs: &ThresholdEcdsaSigInputs,
        _share: &ThresholdEcdsaSigShare,
    ) -> Result<(), ThresholdEcdsaVerifySigShareError> {
        Ok(())
    }

    fn combine_sig_shares(
        &self,
        _inputs: &ThresholdEcdsaSigInputs,
        _shares: &BTreeMap<NodeId, ThresholdEcdsaSigShare>,
    ) -> Result<ThresholdEcdsaCombinedSignature, ThresholdEcdsaCombineSigSharesError> {
        Ok(ThresholdEcdsaCombinedSignature { signature: vec![] })
    }

    fn verify_combined_sig(
        &self,
        _inputs: &ThresholdEcdsaSigInputs,
        _signature: &ThresholdEcdsaCombinedSignature,
    ) -> Result<(), ThresholdEcdsaVerifyCombinedSignatureError> {
        Ok(())
    }

    fn get_public_key(
        &self,
        _canister_id: PrincipalId,
        _key_transcript: IDkgTranscript,
    ) -> Result<EcdsaPublicKey, ThresholdEcdsaGetPublicKeyError> {
        Ok(EcdsaPublicKey {
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            public_key: vec![],
        })
    }
}

pub fn mock_random_number_generator() -> Box<dyn RngCore> {
    Box::new(StdRng::from_seed([0u8; 32]))
}
