use ic_crypto_interfaces_sig_verification::{BasicSigVerifierByPublicKey, CanisterSigVerifier};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::CspNiDkgDealing;
use ic_crypto_test_utils_canister_threshold_sigs::dummy_values;
use ic_crypto_test_utils_ni_dkg::dummy_transcript_for_tests_with_params;
use ic_interfaces::crypto::{
    BasicSigVerifier, BasicSigner, CheckKeysWithRegistryError, CurrentNodePublicKeysError,
    IDkgDealingEncryptionKeyRotationError, IDkgKeyRotationResult, IDkgProtocol, KeyManager,
    LoadTranscriptResult, NiDkgAlgorithm, ThresholdEcdsaSigVerifier, ThresholdEcdsaSigner,
    ThresholdSchnorrSigVerifier, ThresholdSchnorrSigner, ThresholdSigVerifier,
    ThresholdSigVerifierByPublicKey, ThresholdSigner, VetKdProtocol,
};
use ic_interfaces::crypto::{MultiSigVerifier, MultiSigner};
use ic_test_utilities_types::ids::node_test_id;
use ic_types::crypto::canister_threshold_sig::error::*;
use ic_types::crypto::canister_threshold_sig::idkg::*;
use ic_types::crypto::canister_threshold_sig::*;
use ic_types::crypto::threshold_sig::ni_dkg::errors::create_dealing_error::DkgCreateDealingError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::create_transcript_error::DkgCreateTranscriptError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::key_removal_error::DkgKeyRemovalError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::load_transcript_error::DkgLoadTranscriptError;
use ic_types::crypto::threshold_sig::ni_dkg::errors::verify_dealing_error::DkgVerifyDealingError;
use ic_types::crypto::threshold_sig::ni_dkg::{
    NiDkgDealing, NiDkgId, NiDkgTranscript, config::NiDkgConfig,
};
use ic_types::crypto::{
    AlgorithmId, BasicSig, BasicSigOf, CanisterSigOf, CombinedMultiSig, CombinedMultiSigOf,
    CombinedThresholdSig, CombinedThresholdSigOf, CryptoResult, CurrentNodePublicKeys,
    IndividualMultiSig, IndividualMultiSigOf, Signable, ThresholdSigShare, ThresholdSigShareOf,
    UserPublicKey,
};
use ic_types::signature::{BasicSignature, BasicSignatureBatch};
use ic_types::*;
use ic_types::{NodeId, RegistryVersion};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

pub use ic_crypto_test_utils_ni_dkg::empty_ni_dkg_transcripts_with_committee;
use ic_types::crypto::threshold_sig::IcRootOfTrust;
use ic_types_test_utils::ids::NODE_1;

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

    fn combine_basic_sig(
        &self,
        signatures: BTreeMap<NodeId, &BasicSigOf<T>>,
        _registry_version: RegistryVersion,
    ) -> CryptoResult<BasicSignatureBatch<T>> {
        Ok(BasicSignatureBatch {
            signatures_map: signatures
                .iter()
                .map(|(key, value)| (*key, (*value).clone()))
                .collect(),
        })
    }

    fn verify_basic_sig_batch(
        &self,
        _signature: &BasicSignatureBatch<T>,
        _message: &T,
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
    fn sign_threshold(
        &self,
        _message: &T,
        _dkg_id: &NiDkgId,
    ) -> CryptoResult<ThresholdSigShareOf<T>> {
        Ok(ThresholdSigShareOf::new(ThresholdSigShare(vec![])))
    }
}

impl<T: Signable> ThresholdSigVerifier<T> for CryptoReturningOk {
    fn verify_threshold_sig_share(
        &self,
        _signature: &ThresholdSigShareOf<T>,
        _message: &T,
        _dkg_id: &NiDkgId,
        _signer: NodeId,
    ) -> CryptoResult<()> {
        Ok(())
    }

    fn combine_threshold_sig_shares(
        &self,
        _shares: BTreeMap<NodeId, ThresholdSigShareOf<T>>,
        _dkg_id: &NiDkgId,
    ) -> CryptoResult<CombinedThresholdSigOf<T>> {
        Ok(CombinedThresholdSigOf::new(CombinedThresholdSig(vec![])))
    }

    fn verify_threshold_sig_combined(
        &self,
        _signature: &CombinedThresholdSigOf<T>,
        _message: &T,
        _dkg_id: &NiDkgId,
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
        _root_of_trust: &IcRootOfTrust,
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
        let mut transcript = dummy_transcript_for_tests_with_params(
            config.receivers().get().clone().into_iter().collect(),
            config.dkg_id().dkg_tag.clone(),
            config.threshold().get().get(),
            config.registry_version().get(),
        );
        transcript.dkg_id = config.dkg_id().clone();
        Ok(transcript)
    }

    fn load_transcript(
        &self,
        transcript: &NiDkgTranscript,
    ) -> Result<LoadTranscriptResult, DkgLoadTranscriptError> {
        self.loaded_transcripts
            .write()
            .unwrap()
            .insert(transcript.dkg_id.clone());
        Ok(LoadTranscriptResult::SigningKeyAvailable)
    }

    fn retain_only_active_keys(
        &self,
        transcripts: HashSet<NiDkgTranscript>,
    ) -> Result<(), DkgKeyRemovalError> {
        self.retained_transcripts
            .write()
            .unwrap()
            .push(transcripts.into_iter().map(|t| t.dkg_id).collect());
        Ok(())
    }
}

impl KeyManager for CryptoReturningOk {
    fn check_keys_with_registry(
        &self,
        _registry_version: RegistryVersion,
    ) -> Result<(), CheckKeysWithRegistryError> {
        Ok(())
    }

    fn current_node_public_keys(
        &self,
    ) -> Result<CurrentNodePublicKeys, CurrentNodePublicKeysError> {
        unimplemented!()
    }

    fn rotate_idkg_dealing_encryption_keys(
        &self,
        _registry_version: RegistryVersion,
    ) -> Result<IDkgKeyRotationResult, IDkgDealingEncryptionKeyRotationError> {
        unimplemented!()
    }
}

impl IDkgProtocol for CryptoReturningOk {
    fn create_dealing(
        &self,
        params: &IDkgTranscriptParams,
    ) -> Result<SignedIDkgDealing, IDkgCreateDealingError> {
        let signed_dealing = SignedIDkgDealing {
            signature: BasicSignature {
                signature: BasicSigOf::new(BasicSig(vec![])),
                signer: NODE_1,
            },
            content: IDkgDealing {
                transcript_id: params.transcript_id(),
                internal_dealing_raw: vec![],
            },
        };
        Ok(signed_dealing)
    }

    fn verify_dealing_public(
        &self,
        _params: &IDkgTranscriptParams,
        _signed_dealing: &SignedIDkgDealing,
    ) -> Result<(), IDkgVerifyDealingPublicError> {
        Ok(())
    }

    fn verify_dealing_private(
        &self,
        _params: &IDkgTranscriptParams,
        _signed_dealing: &SignedIDkgDealing,
    ) -> Result<(), IDkgVerifyDealingPrivateError> {
        Ok(())
    }

    fn verify_initial_dealings(
        &self,
        _params: &IDkgTranscriptParams,
        _initial_dealings: &InitialIDkgDealings,
    ) -> Result<(), IDkgVerifyInitialDealingsError> {
        Ok(())
    }

    fn create_transcript(
        &self,
        params: &IDkgTranscriptParams,
        dealings: &BatchSignedIDkgDealings,
    ) -> Result<IDkgTranscript, IDkgCreateTranscriptError> {
        let mut receivers = BTreeSet::new();
        receivers.insert(node_test_id(0));

        let dealings_by_index = dealings
            .iter()
            .map(|dealing| {
                (
                    params.dealer_index(dealing.dealer_id()).expect(
                        "dealer from BatchSignedIDkgDealing should be in IDkgTranscriptParams",
                    ),
                    dealing.clone(),
                )
            })
            .collect();

        Ok(IDkgTranscript {
            transcript_id: dummy_values::dummy_idkg_transcript_id_for_tests(0),
            receivers: IDkgReceivers::new(receivers).unwrap(),
            registry_version: RegistryVersion::from(1),
            verified_dealings: Arc::new(dealings_by_index),
            transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
            algorithm_id: AlgorithmId::Unspecified,
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
        _complainer_id: NodeId,
        _complaint: &IDkgComplaint,
    ) -> Result<(), IDkgVerifyComplaintError> {
        Ok(())
    }

    fn open_transcript(
        &self,
        _transcript: &IDkgTranscript,
        _complainer_id: NodeId,
        complaint: &IDkgComplaint,
    ) -> Result<IDkgOpening, IDkgOpenTranscriptError> {
        Ok(dummy_values::dummy_idkg_opening_for_tests(complaint))
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
        _transcript: &IDkgTranscript,
        _openings: &BTreeMap<IDkgComplaint, BTreeMap<NodeId, IDkgOpening>>,
    ) -> Result<(), IDkgLoadTranscriptError> {
        Ok(())
    }

    fn retain_active_transcripts(
        &self,
        _active_transcripts: &HashSet<IDkgTranscript>,
    ) -> Result<(), IDkgRetainKeysError> {
        Ok(())
    }
}

impl ThresholdEcdsaSigner for CryptoReturningOk {
    fn create_sig_share(
        &self,
        _inputs: &ThresholdEcdsaSigInputs,
    ) -> Result<ThresholdEcdsaSigShare, ThresholdEcdsaCreateSigShareError> {
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
}

impl ThresholdSchnorrSigner for CryptoReturningOk {
    fn create_sig_share(
        &self,
        _inputs: &ThresholdSchnorrSigInputs,
    ) -> Result<ThresholdSchnorrSigShare, ThresholdSchnorrCreateSigShareError> {
        Ok(ThresholdSchnorrSigShare {
            sig_share_raw: vec![],
        })
    }
}

impl ThresholdSchnorrSigVerifier for CryptoReturningOk {
    fn verify_sig_share(
        &self,
        _signer: NodeId,
        _inputs: &ThresholdSchnorrSigInputs,
        _share: &ThresholdSchnorrSigShare,
    ) -> Result<(), ThresholdSchnorrVerifySigShareError> {
        Ok(())
    }

    fn combine_sig_shares(
        &self,
        _inputs: &ThresholdSchnorrSigInputs,
        _shares: &BTreeMap<NodeId, ThresholdSchnorrSigShare>,
    ) -> Result<ThresholdSchnorrCombinedSignature, ThresholdSchnorrCombineSigSharesError> {
        Ok(ThresholdSchnorrCombinedSignature { signature: vec![] })
    }

    fn verify_combined_sig(
        &self,
        _inputs: &ThresholdSchnorrSigInputs,
        _signature: &ThresholdSchnorrCombinedSignature,
    ) -> Result<(), ThresholdSchnorrVerifyCombinedSigError> {
        Ok(())
    }
}

use ic_types::crypto::vetkd::{
    VetKdArgs, VetKdEncryptedKey, VetKdEncryptedKeyShare, VetKdEncryptedKeyShareContent,
    VetKdKeyShareCombinationError, VetKdKeyShareCreationError, VetKdKeyShareVerificationError,
    VetKdKeyVerificationError,
};

impl VetKdProtocol for CryptoReturningOk {
    fn create_encrypted_key_share(
        &self,
        _args: VetKdArgs,
    ) -> Result<VetKdEncryptedKeyShare, VetKdKeyShareCreationError> {
        Ok(VetKdEncryptedKeyShare {
            encrypted_key_share: VetKdEncryptedKeyShareContent(vec![]),
            node_signature: vec![],
        })
    }

    fn verify_encrypted_key_share(
        &self,
        _signer: NodeId,
        _key_share: &VetKdEncryptedKeyShare,
        _args: &VetKdArgs,
    ) -> Result<(), VetKdKeyShareVerificationError> {
        Ok(())
    }

    fn combine_encrypted_key_shares(
        &self,
        _shares: &BTreeMap<NodeId, VetKdEncryptedKeyShare>,
        _args: &VetKdArgs,
    ) -> Result<VetKdEncryptedKey, VetKdKeyShareCombinationError> {
        Ok(VetKdEncryptedKey {
            encrypted_key: vec![],
        })
    }

    fn verify_encrypted_key(
        &self,
        _key: &VetKdEncryptedKey,
        _args: &VetKdArgs,
    ) -> Result<(), VetKdKeyVerificationError> {
        Ok(())
    }
}

fn empty_ni_dkg_csp_dealing() -> CspNiDkgDealing {
    ic_crypto_test_utils_ni_dkg::ni_dkg_csp_dealing(0)
}

fn empty_ni_dkg_dealing() -> NiDkgDealing {
    NiDkgDealing {
        internal_dealing: empty_ni_dkg_csp_dealing(),
    }
}
