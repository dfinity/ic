use ic_crypto_internal_csp::api::{
    CspCreateMEGaKeyError, CspIDkgProtocol, CspKeyGenerator, CspPublicAndSecretKeyStoreChecker,
    CspPublicKeyStore, CspSigVerifier, CspSigner, CspThresholdEcdsaSigVerifier,
    CspThresholdEcdsaSigner, CspThresholdSignError, CspTlsHandshakeSignerProvider, NiDkgCspClient,
    ThresholdSignatureCspClient,
};
use ic_crypto_internal_csp::key_id::KeyId;
use ic_crypto_internal_csp::types::ExternalPublicKeys;
use ic_crypto_internal_csp::types::{CspPop, CspPublicCoefficients, CspPublicKey, CspSignature};
use ic_crypto_internal_csp::vault::api::CspBasicSignatureKeygenError;
use ic_crypto_internal_csp::vault::api::CspMultiSignatureKeygenError;
use ic_crypto_internal_csp::vault::api::CspPublicKeyStoreError;
use ic_crypto_internal_csp::vault::api::CspTlsKeygenError;
use ic_crypto_internal_csp::vault::api::PksAndSksContainsErrors;
use ic_crypto_internal_csp::vault::api::ValidatePksAndSksError;
use ic_crypto_internal_csp::TlsHandshakeCspVault;
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::{
    CspDkgCreateDealingError, CspDkgCreateFsKeyError, CspDkgCreateReshareDealingError,
    CspDkgCreateReshareTranscriptError, CspDkgCreateTranscriptError, CspDkgLoadPrivateKeyError,
    CspDkgRetainThresholdKeysError, CspDkgUpdateFsEpochError, CspDkgVerifyDealingError,
    CspDkgVerifyReshareDealingError,
};
use ic_crypto_internal_threshold_sig_ecdsa::{
    IDkgTranscriptInternal, MEGaPublicKey, ThresholdEcdsaCombinedSigInternal,
    ThresholdEcdsaSigShareInternal,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    CspFsEncryptionPop, CspFsEncryptionPublicKey, CspNiDkgDealing, CspNiDkgTranscript, Epoch,
};
use ic_crypto_internal_types::sign::threshold_sig::public_key::CspThresholdSigPublicKey;
use ic_crypto_node_key_validation::ValidNodePublicKeys;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_types::crypto::canister_threshold_sig::error::{
    ThresholdEcdsaCombineSigSharesError, ThresholdEcdsaSignShareError,
    ThresholdEcdsaVerifyCombinedSignatureError, ThresholdEcdsaVerifySigShareError,
};
use ic_types::crypto::canister_threshold_sig::{ExtendedDerivationPath, ThresholdEcdsaSigInputs};
use ic_types::crypto::threshold_sig::ni_dkg::NiDkgId;
use ic_types::crypto::{AlgorithmId, CryptoResult, CurrentNodePublicKeys};
use ic_types::{NodeId, NodeIndex, NumberOfNodes, Randomness};
use mockall::predicate::*;
use mockall::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

mock! {
    pub AllCryptoServiceProvider {}

    impl CspSigner for AllCryptoServiceProvider {
        fn sign(
            &self,
            algorithm_id: AlgorithmId,
            msg: Vec<u8>,
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

    impl CspSigVerifier for AllCryptoServiceProvider {
        fn verify_batch(
            &self,
            key_signature_pairs: &[(CspPublicKey, CspSignature)],
            msg: &[u8],
            algorithm_id: AlgorithmId,
        ) -> CryptoResult<()>;
    }

    impl CspKeyGenerator for AllCryptoServiceProvider {
        fn gen_node_signing_key_pair(&self) -> Result<CspPublicKey, CspBasicSignatureKeygenError>;

        fn gen_committee_signing_key_pair(
            &self,
        ) -> Result<(CspPublicKey, CspPop), CspMultiSignatureKeygenError>;

        fn gen_tls_key_pair(
            &self,
            node_id: NodeId,
        ) -> Result<TlsPublicKeyCert, CspTlsKeygenError>;
    }

    impl ThresholdSignatureCspClient for AllCryptoServiceProvider {
        fn threshold_sign(
            &self,
            _algorithm_id: AlgorithmId,
            _message: Vec<u8>,
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

    impl NiDkgCspClient for AllCryptoServiceProvider {
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

        fn observe_minimum_epoch_in_active_transcripts(&self, epoch: Epoch);

        fn observe_epoch_in_loaded_transcript(&self, epoch: Epoch);
    }

    impl CspPublicAndSecretKeyStoreChecker for AllCryptoServiceProvider {
        fn pks_and_sks_contains(
            &self,
            registry_public_keys: ExternalPublicKeys,
        ) -> Result<(), PksAndSksContainsErrors>;

        fn validate_pks_and_sks(&self) -> Result<ValidNodePublicKeys, ValidatePksAndSksError>;
    }

    impl CspPublicKeyStore for AllCryptoServiceProvider {
        fn current_node_public_keys(&self) -> Result<CurrentNodePublicKeys, CspPublicKeyStoreError>;
        fn current_node_public_keys_with_timestamps(&self) -> Result<CurrentNodePublicKeys, CspPublicKeyStoreError>;
        fn idkg_dealing_encryption_pubkeys_count(&self) -> Result<usize, CspPublicKeyStoreError>;
    }

    impl CspTlsHandshakeSignerProvider for AllCryptoServiceProvider {
        fn handshake_signer(&self) -> Arc<dyn TlsHandshakeCspVault>;
    }

    impl CspIDkgProtocol for AllCryptoServiceProvider {
        fn idkg_gen_dealing_encryption_key_pair(&self) -> Result<MEGaPublicKey, CspCreateMEGaKeyError>;
    }

    impl CspThresholdEcdsaSigner for AllCryptoServiceProvider {
        fn ecdsa_sign_share(
            &self,
            inputs: &ThresholdEcdsaSigInputs,
        ) -> Result<ThresholdEcdsaSigShareInternal, ThresholdEcdsaSignShareError>;
    }

    impl CspThresholdEcdsaSigVerifier for AllCryptoServiceProvider {
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
