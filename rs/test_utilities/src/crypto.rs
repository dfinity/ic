pub mod basic_utilities;
pub mod fake_tls_handshake;

pub use ic_crypto_test_utils::files as temp_dir;

use crate::types::ids::{node_test_id, subnet_test_id};
use ic_crypto::utils::TempCryptoComponent;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::PublicCoefficientsBytes;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    ni_dkg_groth20_bls12_381, CspNiDkgDealing, CspNiDkgTranscript,
};
use ic_interfaces::crypto::{
    BasicSigVerifier, BasicSigVerifierByPublicKey, BasicSigner, CanisterSigVerifier, DkgAlgorithm,
    KeyManager, LoadTranscriptResult, NiDkgAlgorithm, ThresholdSigVerifier,
    ThresholdSigVerifierByPublicKey, ThresholdSigner,
};
use ic_interfaces::crypto::{MultiSigVerifier, MultiSigner, Signable};
use ic_interfaces::registry::RegistryClient;
use ic_protobuf::crypto::v1::NodePublicKeys;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_client::fake::FakeRegistryClient;
use ic_registry_common::proto_registry_data_provider::ProtoRegistryDataProvider;
use ic_types::crypto::dkg::{
    Config, Dealing, EncryptionPublicKeyWithPop, Response, Transcript, TranscriptBytes,
};
use ic_types::crypto::threshold_sig::ni_dkg::errors::create_dealing_error::DkgCreateDealingError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::create_transcript_error::DkgCreateTranscriptError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::key_removal_error::DkgKeyRemovalError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::load_transcript_error::DkgLoadTranscriptError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::verify_dealing_error::DkgVerifyDealingError;
use ic_types::crypto::threshold_sig::ni_dkg::{
    config::NiDkgConfig, DkgId, NiDkgDealing, NiDkgId, NiDkgTag, NiDkgTranscript,
};
use ic_types::crypto::{
    BasicSig, BasicSigOf, CanisterSigOf, CombinedMultiSig, CombinedMultiSigOf,
    CombinedThresholdSig, CombinedThresholdSigOf, CryptoResult, IndividualMultiSig,
    IndividualMultiSigOf, ThresholdSigShare, ThresholdSigShareOf, UserPublicKey,
};
use ic_types::*;
use ic_types::{IDkgId, NodeId, RegistryVersion};
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

pub fn empty_dkg_transcript() -> crypto::dkg::Transcript {
    crypto::dkg::Transcript {
        dkg_id: IDkgId {
            instance_id: Height::from(0),
            subnet_id: subnet_test_id(0),
        },
        committee: vec![],
        transcript_bytes: TranscriptBytes(Default::default()),
    }
}

pub fn empty_ni_dkg_transcripts_with_committee(
    committee: Vec<NodeId>,
) -> std::collections::BTreeMap<NiDkgTag, NiDkgTranscript> {
    vec![
        (
            NiDkgTag::LowThreshold,
            NiDkgTranscript::dummy_transcript_for_tests_with_params(
                committee.clone(),
                NiDkgTag::LowThreshold,
                NiDkgTag::LowThreshold.threshold_for_subnet_of_size(committee.len()) as u32,
            ),
        ),
        (
            NiDkgTag::HighThreshold,
            NiDkgTranscript::dummy_transcript_for_tests_with_params(
                committee.clone(),
                NiDkgTag::HighThreshold,
                NiDkgTag::HighThreshold.threshold_for_subnet_of_size(committee.len()) as u32,
            ),
        ),
    ]
    .into_iter()
    .collect()
}

pub fn empty_ni_dkg_transcripts() -> std::collections::BTreeMap<NiDkgTag, NiDkgTranscript> {
    empty_ni_dkg_transcripts_with_committee(vec![node_test_id(0)])
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

impl DkgAlgorithm for CryptoReturningOk {
    fn generate_encryption_keys(
        &self,
        _dkg_config: &Config,
        _node_id: NodeId,
    ) -> CryptoResult<EncryptionPublicKeyWithPop> {
        Ok(EncryptionPublicKeyWithPop::default())
    }

    fn verify_encryption_public_key(
        &self,
        _dkg_config: &Config,
        _sender: NodeId,
        _key: &EncryptionPublicKeyWithPop,
    ) -> CryptoResult<()> {
        Ok(())
    }

    fn create_dealing(
        &self,
        _config: &Config,
        _verified_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        _node_id: NodeId,
    ) -> CryptoResult<Dealing> {
        Ok(Dealing(Default::default()))
    }

    fn verify_dealing(
        &self,
        _config: &Config,
        _verified_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        _dealer: NodeId,
        _dealing: &Dealing,
    ) -> CryptoResult<()> {
        Ok(())
    }

    fn create_response(
        &self,
        _config: &Config,
        _verified_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        _verified_dealings: &BTreeMap<NodeId, Dealing>,
        _node_id: NodeId,
    ) -> CryptoResult<Response> {
        Ok(Response(Default::default()))
    }

    fn verify_response(
        &self,
        _config: &Config,
        _verified_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        _verified_dealings: &BTreeMap<NodeId, Dealing>,
        _receiver: NodeId,
        _response: &Response,
    ) -> CryptoResult<()> {
        Ok(())
    }

    fn create_transcript(
        &self,
        config: &Config,
        _verified_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        _verified_dealings: &BTreeMap<NodeId, Dealing>,
        _verified_responses: &BTreeMap<NodeId, Response>,
    ) -> CryptoResult<Transcript> {
        Ok(Transcript {
            dkg_id: config.dkg_id,
            committee: config.receivers.iter().cloned().map(Some).collect(),
            transcript_bytes: TranscriptBytes(Default::default()),
        })
    }

    fn load_transcript(&self, _transcript: &Transcript, _receiver: NodeId) -> CryptoResult<()> {
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

pub fn mock_random_number_generator() -> Box<dyn RngCore> {
    Box::new(StdRng::from_seed([0u8; 32]))
}
