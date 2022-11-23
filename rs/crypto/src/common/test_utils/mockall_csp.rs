// Including this clippy allow to circumvent clippy errors spawned by MockAll
// internal expansion.  Should be removed when DFN-860 is resolved.
// Specifically relevant to the Vec<> parameter.
#![allow(clippy::ptr_arg)]
#![allow(clippy::too_many_arguments)]

use ic_crypto_internal_csp::api::{
    CspCreateMEGaKeyError, CspIDkgProtocol, CspKeyGenerator, CspSecretKeyStoreChecker,
    CspSigVerifier, CspSigner, CspThresholdEcdsaSigVerifier, CspThresholdEcdsaSigner,
    CspThresholdSignError, CspTlsHandshakeSignerProvider, NiDkgCspClient, NodePublicKeyData,
    ThresholdSignatureCspClient,
};
use ic_crypto_internal_csp::key_id::KeyId;
use ic_crypto_internal_csp::types::{CspPop, CspPublicCoefficients, CspPublicKey, CspSignature};
use ic_crypto_internal_csp::TlsHandshakeCspVault;
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::{
    CspDkgCreateDealingError, CspDkgCreateFsKeyError, CspDkgCreateReshareDealingError,
    CspDkgCreateReshareTranscriptError, CspDkgCreateTranscriptError, CspDkgLoadPrivateKeyError,
    CspDkgRetainThresholdKeysError, CspDkgUpdateFsEpochError, CspDkgVerifyDealingError,
    CspDkgVerifyReshareDealingError,
};
use ic_crypto_internal_threshold_sig_ecdsa::{
    CommitmentOpening, IDkgComplaintInternal, IDkgDealingInternal, IDkgTranscriptInternal,
    IDkgTranscriptOperationInternal, MEGaPublicKey, ThresholdEcdsaCombinedSigInternal,
    ThresholdEcdsaSigShareInternal,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    CspFsEncryptionPop, CspFsEncryptionPublicKey, CspNiDkgDealing, CspNiDkgTranscript, Epoch,
};
use ic_crypto_internal_types::sign::threshold_sig::public_key::CspThresholdSigPublicKey;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgCreateTranscriptError, IDkgLoadTranscriptError,
    IDkgOpenTranscriptError, IDkgRetainThresholdKeysError, IDkgVerifyComplaintError,
    IDkgVerifyDealingPrivateError, IDkgVerifyDealingPublicError, IDkgVerifyOpeningError,
    IDkgVerifyTranscriptError, ThresholdEcdsaCombineSigSharesError, ThresholdEcdsaSignShareError,
    ThresholdEcdsaVerifyCombinedSignatureError, ThresholdEcdsaVerifySigShareError,
};
use ic_types::crypto::canister_threshold_sig::ExtendedDerivationPath;
use ic_types::crypto::threshold_sig::ni_dkg::NiDkgId;
use ic_types::crypto::CurrentNodePublicKeys;
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult};
use ic_types::{NodeId, NodeIndex, NumberOfNodes, Randomness};
use mockall::predicate::*;
use mockall::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

mock! {
    pub AllCryptoServiceProvider {}

    pub trait CspSigner {
        fn sign(
            &self,
            algorithm_id: AlgorithmId,
            msg: &[u8],
            key_id: KeyId,
        ) -> CryptoResult<CspSignature>;

        fn verify(
            &self,
            sig: &CspSignature,
            msg: &[u8],
            algorithm_id: AlgorithmId,
            signer: CspPublicKey,
        ) -> CryptoResult<()>;

        fn verify_pop(
            &self,
            pop: &CspPop,
            algorithm_id: AlgorithmId,
            public_key: CspPublicKey,
        ) -> CryptoResult<()>;

        fn combine_sigs(
            &self,
            signatures: Vec<(CspPublicKey, CspSignature)>,
            algorithm_id: AlgorithmId,
        ) -> CryptoResult<CspSignature>;

        fn verify_multisig(
            &self,
            signers: Vec<CspPublicKey>,
            signature: CspSignature,
            msg: &[u8],
            algorithm_id: AlgorithmId,
        ) -> CryptoResult<()>;
    }

    pub trait CspSigVerifier{
        fn verify_batch_vartime(
            &self,
            key_signature_pairs: &[(CspPublicKey, CspSignature)],
            msg: &[u8],
            algorithm_id: AlgorithmId,
        ) -> CryptoResult<()>;
    }

    pub trait CspKeyGenerator {
        fn gen_node_signing_key_pair(&self) -> Result<CspPublicKey, CryptoError>;

        fn gen_committee_signing_key_pair(
            &self,
        ) -> Result<(CspPublicKey, CspPop), CryptoError>;

        fn gen_tls_key_pair(
            &self,
            node: NodeId,
            not_after: &str,
        ) -> Result<TlsPublicKeyCert, CryptoError>;
    }

    pub trait ThresholdSignatureCspClient {

        fn threshold_sign(
            &self,
            _algorithm_id: AlgorithmId,
            _message: &[u8],
            _public_coefficients: CspPublicCoefficients,
        ) -> Result<CspSignature, CspThresholdSignError>;

        fn threshold_combine_signatures(
            &self,
            algorithm_id: AlgorithmId,
            signatures: &[Option<CspSignature>],
            public_coefficients: CspPublicCoefficients,
        ) -> CryptoResult<CspSignature>;

        fn threshold_individual_public_key(
            &self,
            algorithm_id: AlgorithmId,
            node_index: NodeIndex,
            public_coefficients: CspPublicCoefficients,
        ) -> CryptoResult<CspThresholdSigPublicKey>;

        fn threshold_verify_individual_signature(
            &self,
            algorithm_id: AlgorithmId,
            message: &[u8],
            signature: CspSignature,
            public_key: CspThresholdSigPublicKey,
        ) -> CryptoResult<()>;

        fn threshold_verify_combined_signature(
            &self,
            algorithm_id: AlgorithmId,
            message: &[u8],
            signature: CspSignature,
            public_coefficients: CspPublicCoefficients,
        ) -> CryptoResult<()>;
    }

    pub trait NiDkgCspClient {
        fn gen_dealing_encryption_key_pair(
            &self,
            _node_id: NodeId,
        ) -> Result<(CspFsEncryptionPublicKey, CspFsEncryptionPop), CspDkgCreateFsKeyError>;

        /// Erases forward secure secret keys at and before a given epoch
        fn update_forward_secure_epoch(
          &self,
         _algorithm_id: AlgorithmId,
         _epoch: Epoch,
        ) -> Result<(), CspDkgUpdateFsEpochError>;

        fn create_dealing(
            &self,
            algorithm_id: AlgorithmId,
            dkg_id: NiDkgId,
            dealer_index: NodeIndex,
            threshold: NumberOfNodes,
            epoch: Epoch,
            receiver_keys: BTreeMap<u32, CspFsEncryptionPublicKey>,
        ) -> Result<CspNiDkgDealing, CspDkgCreateDealingError>;

        fn create_resharing_dealing(
            &self,
            algorithm_id: AlgorithmId,
            dealer_resharing_index: NodeIndex,
            threshold: NumberOfNodes,
            epoch: Epoch,
            receiver_keys: BTreeMap<u32, CspFsEncryptionPublicKey>,
            resharing_public_coefficients: CspPublicCoefficients,
        ) -> Result<CspNiDkgDealing, CspDkgCreateReshareDealingError>;

        fn verify_dealing(
            &self,
            algorithm_id: AlgorithmId,
            dkg_id: NiDkgId,
            dealer_index: NodeIndex,
            threshold: NumberOfNodes,
            epoch: Epoch,
            receiver_keys: BTreeMap<u32, CspFsEncryptionPublicKey>,
            dealing: CspNiDkgDealing,
        ) -> Result<(), CspDkgVerifyDealingError>;

        fn verify_resharing_dealing(
            &self,
            algorithm_id: AlgorithmId,
            dkg_id: NiDkgId,
            dealer_resharing_index: u32,
            threshold: NumberOfNodes,
            epoch: Epoch,
            receiver_keys: BTreeMap<u32, CspFsEncryptionPublicKey>,
            dealing: CspNiDkgDealing,
            resharing_public_coefficients: CspPublicCoefficients,
        ) -> Result<(), CspDkgVerifyReshareDealingError>;

        fn create_transcript(
            &self,
            algorithm_id: AlgorithmId,
            threshold: NumberOfNodes,
            number_of_receivers: NumberOfNodes,
            csp_dealings: BTreeMap<u32, CspNiDkgDealing>,
            collection_threshold: NumberOfNodes,
        ) -> Result<CspNiDkgTranscript, CspDkgCreateTranscriptError>;

        fn create_resharing_transcript(
            &self,
            algorithm_id: AlgorithmId,
            threshold: NumberOfNodes,
            number_of_receivers: NumberOfNodes,
            csp_dealings: BTreeMap<u32, CspNiDkgDealing>,
            resharing_public_coefficients: CspPublicCoefficients,
        ) -> Result<CspNiDkgTranscript, CspDkgCreateReshareTranscriptError>;

        fn load_threshold_signing_key(
            &self,
            algorithm_id: AlgorithmId,
            dkg_id: NiDkgId,
            epoch: Epoch,
            csp_transcript: CspNiDkgTranscript,
            receiver_index: u32,
        ) -> Result<(), CspDkgLoadPrivateKeyError>;

        fn retain_threshold_keys_if_present(
            &self,
            active_keys: BTreeSet<CspPublicCoefficients>
        ) -> Result<(), CspDkgRetainThresholdKeysError>;
    }

    pub trait CspSecretKeyStoreChecker {
        fn sks_contains(&self, id: &KeyId) -> Result<bool, CryptoError>;
        fn sks_contains_tls_key(&self, cert: &TlsPublicKeyCert) -> Result<bool, CryptoError>;
    }

    pub trait NodePublicKeyData {
        fn pks_contains(&self, public_keys: CurrentNodePublicKeys) -> Result<bool, CryptoError>;
        fn current_node_public_keys(&self) -> CurrentNodePublicKeys;
        fn dkg_dealing_encryption_key_id(&self) -> KeyId;
    }

    pub trait CspTlsHandshakeSignerProvider: Send + Sync {
        fn handshake_signer(&self) -> Arc<dyn TlsHandshakeCspVault>;
    }

    pub trait CspIDkgProtocol {
        fn idkg_create_dealing(
            &self,
            algorithm_id: AlgorithmId,
            context_data: &[u8],
            dealer_index: NodeIndex,
            reconstruction_threshold: NumberOfNodes,
            receiver_keys: &[MEGaPublicKey],
            transcript_operation: &IDkgTranscriptOperationInternal,
        ) -> Result<IDkgDealingInternal, IDkgCreateDealingError>;

        fn idkg_verify_dealing_private(
            &self,
            algorithm_id: AlgorithmId,
            dealing: &IDkgDealingInternal,
            dealer_index: NodeIndex,
            receiver_index: NodeIndex,
            receiver_public_key: &MEGaPublicKey,
            context_data: &[u8],
        ) -> Result<(), IDkgVerifyDealingPrivateError>;

        fn idkg_verify_dealing_public(
            &self,
            algorithm_id: AlgorithmId,
            dealing: &IDkgDealingInternal,
            operation_mode: &IDkgTranscriptOperationInternal,
            reconstruction_threshold: NumberOfNodes,
            dealer_index: NodeIndex,
            number_of_receivers: NumberOfNodes,
            context_data: &[u8],
        ) -> Result<(), IDkgVerifyDealingPublicError>;

        fn idkg_create_transcript(
            &self,
            algorithm_id: AlgorithmId,
            reconstruction_threshold: NumberOfNodes,
            verified_dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
            operation_mode: &IDkgTranscriptOperationInternal,
        ) -> Result<IDkgTranscriptInternal, IDkgCreateTranscriptError>;

        fn idkg_verify_transcript(
            &self,
            transcript: &IDkgTranscriptInternal,
            algorithm_id: AlgorithmId,
            reconstruction_threshold: NumberOfNodes,
            verified_dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
            operation_mode: &IDkgTranscriptOperationInternal,
        ) -> Result<(), IDkgVerifyTranscriptError>;

        fn idkg_load_transcript(
            &self,
            dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
            context_data: &[u8],
            receiver_index: NodeIndex,
            public_key: &MEGaPublicKey,
            transcript: &IDkgTranscriptInternal,
        ) -> Result<BTreeMap<NodeIndex, IDkgComplaintInternal>, IDkgLoadTranscriptError>;

        fn idkg_load_transcript_with_openings(
            &self,
            dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
            openings: &BTreeMap<NodeIndex, BTreeMap<NodeIndex, CommitmentOpening>>,
            context_data: &[u8],
            receiver_index: NodeIndex,
            public_key: &MEGaPublicKey,
            transcript: &IDkgTranscriptInternal,
        ) -> Result<(), IDkgLoadTranscriptError>;

        fn idkg_retain_active_keys(
            &self,
            active_transcripts: &std::collections::BTreeSet<IDkgTranscriptInternal>,
            oldest_public_key: MEGaPublicKey,
        ) -> Result<(), IDkgRetainThresholdKeysError>;

        fn idkg_gen_dealing_encryption_key_pair(&self) -> Result<MEGaPublicKey, CspCreateMEGaKeyError>;

        fn idkg_verify_complaint(
            &self,
            complaint: &IDkgComplaintInternal,
            complainer_index: NodeIndex,
            complainer_key: &MEGaPublicKey,
            dealing: &IDkgDealingInternal,
            dealer_index: NodeIndex,
            context_data: &[u8],
        ) -> Result<(), IDkgVerifyComplaintError>;

        fn idkg_open_dealing(
            &self,
            dealing: IDkgDealingInternal,
            dealer_index: NodeIndex,
            context_data: &[u8],
            opener_index: NodeIndex,
            opener_public_key: &MEGaPublicKey,
        ) -> Result<CommitmentOpening, IDkgOpenTranscriptError>;

        fn idkg_verify_dealing_opening(
            &self,
            dealing: IDkgDealingInternal,
            opener_index: NodeIndex,
            opening: CommitmentOpening,
        ) -> Result<(), IDkgVerifyOpeningError>;
    }

    pub trait CspThresholdEcdsaSigner {
        fn ecdsa_sign_share(
            &self,
            derivation_path: &ExtendedDerivationPath,
            hashed_message: &[u8],
            nonce: &Randomness,
            key: &IDkgTranscriptInternal,
            kappa_unmasked: &IDkgTranscriptInternal,
            lambda_masked: &IDkgTranscriptInternal,
            kappa_times_lambda: &IDkgTranscriptInternal,
            key_times_lambda: &IDkgTranscriptInternal,
            algorithm_id: AlgorithmId,
        ) -> Result<ThresholdEcdsaSigShareInternal, ThresholdEcdsaSignShareError>;
    }

    pub trait CspThresholdEcdsaSigVerifier {
        fn ecdsa_combine_sig_shares(
            &self,
            derivation_path: &ExtendedDerivationPath,
            hashed_message: &[u8],
            nonce: &Randomness,
            key: &IDkgTranscriptInternal,
            kappa_unmasked: &IDkgTranscriptInternal,
            reconstruction_threshold: NumberOfNodes,
            sig_shares: &BTreeMap<NodeIndex, ThresholdEcdsaSigShareInternal>,
            algorithm_id: AlgorithmId,
        ) -> Result<ThresholdEcdsaCombinedSigInternal, ThresholdEcdsaCombineSigSharesError>;

        fn ecdsa_verify_sig_share(
            &self,
            share: &ThresholdEcdsaSigShareInternal,
            signer_index: NodeIndex,
            derivation_path: &ExtendedDerivationPath,
            hashed_message: &[u8],
            nonce: &Randomness,
            key: &IDkgTranscriptInternal,
            kappa_unmasked: &IDkgTranscriptInternal,
            lambda_masked: &IDkgTranscriptInternal,
            kappa_times_lambda: &IDkgTranscriptInternal,
            key_times_lambda: &IDkgTranscriptInternal,
            algorithm_id: AlgorithmId,
        ) -> Result<(), ThresholdEcdsaVerifySigShareError>;

        fn ecdsa_verify_combined_signature(
            &self,
            signature: &ThresholdEcdsaCombinedSigInternal,
            derivation_path: &ExtendedDerivationPath,
            hashed_message: &[u8],
            nonce: &Randomness,
            key: &IDkgTranscriptInternal,
            kappa_unmasked: &IDkgTranscriptInternal,
            algorithm_id: AlgorithmId,
        ) -> Result<(), ThresholdEcdsaVerifyCombinedSignatureError>;
    }
}
