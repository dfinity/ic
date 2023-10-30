use ic_crypto_internal_csp::api::{CspCreateMEGaKeyError, CspThresholdSignError};
use ic_crypto_internal_csp::key_id::KeyId;
use ic_crypto_internal_csp::types::{CspPop, CspPublicKey, CspSignature, ExternalPublicKeys};
use ic_crypto_internal_csp::vault::api::BasicSignatureCspVault;
use ic_crypto_internal_csp::vault::api::CspBasicSignatureError;
use ic_crypto_internal_csp::vault::api::CspBasicSignatureKeygenError;
use ic_crypto_internal_csp::vault::api::CspMultiSignatureError;
use ic_crypto_internal_csp::vault::api::CspMultiSignatureKeygenError;
use ic_crypto_internal_csp::vault::api::CspPublicKeyStoreError;
use ic_crypto_internal_csp::vault::api::CspSecretKeyStoreContainsError;
use ic_crypto_internal_csp::vault::api::CspTlsKeygenError;
use ic_crypto_internal_csp::vault::api::CspTlsSignError;
use ic_crypto_internal_csp::vault::api::IDkgProtocolCspVault;
use ic_crypto_internal_csp::vault::api::MultiSignatureCspVault;
use ic_crypto_internal_csp::vault::api::NiDkgCspVault;
use ic_crypto_internal_csp::vault::api::PksAndSksContainsErrors;
use ic_crypto_internal_csp::vault::api::PublicAndSecretKeyStoreCspVault;
use ic_crypto_internal_csp::vault::api::PublicKeyStoreCspVault;
use ic_crypto_internal_csp::vault::api::PublicRandomSeedGenerator;
use ic_crypto_internal_csp::vault::api::PublicRandomSeedGeneratorError;
use ic_crypto_internal_csp::vault::api::SecretKeyStoreCspVault;
use ic_crypto_internal_csp::vault::api::ThresholdEcdsaSignerCspVault;
use ic_crypto_internal_csp::vault::api::ThresholdSignatureCspVault;
use ic_crypto_internal_csp::vault::api::TlsHandshakeCspVault;
use ic_crypto_internal_csp::vault::api::ValidatePksAndSksError;
use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors;
use ic_crypto_internal_threshold_sig_ecdsa::{
    CommitmentOpening, IDkgComplaintInternal, IDkgDealingInternal, IDkgTranscriptInternalBytes,
    IDkgTranscriptOperationInternal, MEGaPublicKey, ThresholdEcdsaSigShareInternal,
};
use ic_crypto_internal_types::encrypt::forward_secure::{
    CspFsEncryptionPop, CspFsEncryptionPublicKey,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    CspNiDkgDealing, CspNiDkgTranscript, Epoch,
};
use ic_crypto_node_key_validation::ValidNodePublicKeys;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgLoadTranscriptError, IDkgOpenTranscriptError, IDkgRetainKeysError,
    IDkgVerifyDealingPrivateError, ThresholdEcdsaSignShareError,
};
use ic_types::crypto::canister_threshold_sig::ExtendedDerivationPath;
use ic_types::crypto::{AlgorithmId, CurrentNodePublicKeys};
use ic_types::{NodeId, NodeIndex, NumberOfNodes, Randomness};
use mockall::mock;
use std::collections::{BTreeMap, BTreeSet};

mock! {
    pub LocalCspVault {}

    pub trait BasicSignatureCspVault {
        fn sign(
            &self,
            algorithm_id: AlgorithmId,
            message: &[u8],
            key_id: KeyId,
        ) -> Result<CspSignature, CspBasicSignatureError>;

        fn gen_node_signing_key_pair(&self) -> Result<CspPublicKey, CspBasicSignatureKeygenError>;
    }

    pub trait MultiSignatureCspVault {
        fn multi_sign(
            &self,
            algorithm_id: AlgorithmId,
            message: &[u8],
            key_id: KeyId,
        ) -> Result<CspSignature, CspMultiSignatureError>;

        fn gen_committee_signing_key_pair(
            &self,
        ) -> Result<(CspPublicKey, CspPop), CspMultiSignatureKeygenError>;
    }

    pub trait ThresholdSignatureCspVault {
        fn threshold_sign(
            &self,
            algorithm_id: AlgorithmId,
            message: &[u8],
            key_id: KeyId,
        ) -> Result<CspSignature, CspThresholdSignError>;
    }

    pub trait NiDkgCspVault {
        fn gen_dealing_encryption_key_pair(
            &self,
            node_id: NodeId,
        ) -> Result<(CspFsEncryptionPublicKey, CspFsEncryptionPop), ni_dkg_errors::CspDkgCreateFsKeyError>;

        fn update_forward_secure_epoch(
            &self,
            algorithm_id: AlgorithmId,
            key_id: KeyId,
            epoch: Epoch,
        ) -> Result<(), ni_dkg_errors::CspDkgUpdateFsEpochError>;

        fn create_dealing(
            &self,
            algorithm_id: AlgorithmId,
            dealer_index: NodeIndex,
            threshold: NumberOfNodes,
            epoch: Epoch,
            receiver_keys: &BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
            maybe_resharing_secret: Option<KeyId>,
        ) -> Result<CspNiDkgDealing, ni_dkg_errors::CspDkgCreateReshareDealingError>;

        fn load_threshold_signing_key(
            &self,
            algorithm_id: AlgorithmId,
            epoch: Epoch,
            csp_transcript: CspNiDkgTranscript,
            fs_key_id: KeyId,
            receiver_index: NodeIndex,
        ) -> Result<(), ni_dkg_errors::CspDkgLoadPrivateKeyError>;

        fn retain_threshold_keys_if_present(
            &self,
            active_key_ids: BTreeSet<KeyId>,
        ) -> Result<(), ni_dkg_errors::CspDkgRetainThresholdKeysError>;
    }

    pub trait IDkgProtocolCspVault {
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
            receiver_key_id: KeyId,
            context_data: &[u8],
        ) -> Result<(), IDkgVerifyDealingPrivateError>;

        fn idkg_load_transcript(
            &self,
            dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
            context_data: &[u8],
            receiver_index: NodeIndex,
            key_id: &KeyId,
            transcript: IDkgTranscriptInternalBytes,
        ) -> Result<BTreeMap<NodeIndex, IDkgComplaintInternal>, IDkgLoadTranscriptError>;

        fn idkg_load_transcript_with_openings(
            &self,
            dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
            openings: &BTreeMap<NodeIndex, BTreeMap<NodeIndex, CommitmentOpening>>,
            context_data: &[u8],
            receiver_index: NodeIndex,
            key_id: &KeyId,
            transcript: IDkgTranscriptInternalBytes,
        ) -> Result<(), IDkgLoadTranscriptError>;

        fn idkg_gen_dealing_encryption_key_pair(&self) -> Result<MEGaPublicKey, CspCreateMEGaKeyError>;

        fn idkg_open_dealing(
            &self,
            dealing: IDkgDealingInternal,
            dealer_index: NodeIndex,
            context_data: &[u8],
            opener_index: NodeIndex,
            opener_key_id: &KeyId,
        ) -> Result<CommitmentOpening, IDkgOpenTranscriptError>;

        fn idkg_retain_active_keys(
            &self,
            active_key_ids: BTreeSet<KeyId>,
            oldest_public_key: MEGaPublicKey,
        ) -> Result<(), IDkgRetainKeysError>;
    }

    pub trait ThresholdEcdsaSignerCspVault {
        fn ecdsa_sign_share(
            &self,
            derivation_path: &ExtendedDerivationPath,
            hashed_message: &[u8],
            nonce: &Randomness,
            key_raw: IDkgTranscriptInternalBytes,
            kappa_unmasked_raw: IDkgTranscriptInternalBytes,
            lambda_masked_raw: IDkgTranscriptInternalBytes,
            kappa_times_lambda_raw: IDkgTranscriptInternalBytes,
            key_times_lambda_raw: IDkgTranscriptInternalBytes,
            algorithm_id: AlgorithmId,
        ) -> Result<ThresholdEcdsaSigShareInternal, ThresholdEcdsaSignShareError>;
    }

    pub trait SecretKeyStoreCspVault {
        fn sks_contains(&self, key_id: &KeyId) -> Result<bool, CspSecretKeyStoreContainsError>;
    }

    pub trait PublicAndSecretKeyStoreCspVault {
        fn pks_and_sks_contains(
            &self,
            external_public_keys: ExternalPublicKeys,
        ) -> Result<(), PksAndSksContainsErrors>;

        fn validate_pks_and_sks(&self) -> Result<ValidNodePublicKeys, ValidatePksAndSksError>;
    }

    pub trait TlsHandshakeCspVault: Send + Sync {
        fn gen_tls_key_pair(
            &self,
            node: NodeId,
            not_after: &str,
        ) -> Result<TlsPublicKeyCert, CspTlsKeygenError>;

        fn tls_sign(&self, message: &[u8], key_id: &KeyId) -> Result<CspSignature, CspTlsSignError>;
    }

    pub trait PublicRandomSeedGenerator {
        fn new_public_seed(&self) -> Result<Seed, PublicRandomSeedGeneratorError>;
    }

    pub trait PublicKeyStoreCspVault {
        fn current_node_public_keys(&self) -> Result<CurrentNodePublicKeys, CspPublicKeyStoreError>;

        fn current_node_public_keys_with_timestamps(
            &self,
        ) -> Result<CurrentNodePublicKeys, CspPublicKeyStoreError>;

        fn idkg_dealing_encryption_pubkeys_count(&self) -> Result<usize, CspPublicKeyStoreError>;
    }
}
