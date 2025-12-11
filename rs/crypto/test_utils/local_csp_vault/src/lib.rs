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
use ic_crypto_internal_csp::vault::api::IDkgCreateDealingVaultError;
use ic_crypto_internal_csp::vault::api::IDkgDealingInternalBytes;
use ic_crypto_internal_csp::vault::api::IDkgProtocolCspVault;
use ic_crypto_internal_csp::vault::api::IDkgTranscriptInternalBytes;
use ic_crypto_internal_csp::vault::api::IDkgTranscriptOperationInternalBytes;
use ic_crypto_internal_csp::vault::api::MultiSignatureCspVault;
use ic_crypto_internal_csp::vault::api::NiDkgCspVault;
use ic_crypto_internal_csp::vault::api::PksAndSksContainsErrors;
use ic_crypto_internal_csp::vault::api::PublicAndSecretKeyStoreCspVault;
use ic_crypto_internal_csp::vault::api::PublicKeyStoreCspVault;
use ic_crypto_internal_csp::vault::api::PublicRandomSeedGenerator;
use ic_crypto_internal_csp::vault::api::PublicRandomSeedGeneratorError;
use ic_crypto_internal_csp::vault::api::SecretKeyStoreCspVault;
use ic_crypto_internal_csp::vault::api::ThresholdEcdsaSignerCspVault;
use ic_crypto_internal_csp::vault::api::ThresholdSchnorrCreateSigShareVaultError;
use ic_crypto_internal_csp::vault::api::ThresholdSchnorrSigShareBytes;
use ic_crypto_internal_csp::vault::api::ThresholdSchnorrSignerCspVault;
use ic_crypto_internal_csp::vault::api::ThresholdSignatureCspVault;
use ic_crypto_internal_csp::vault::api::TlsHandshakeCspVault;
use ic_crypto_internal_csp::vault::api::ValidatePksAndSksError;
use ic_crypto_internal_csp::vault::api::VetKdCspVault;
use ic_crypto_internal_csp::vault::api::VetKdEncryptedKeyShareCreationVaultError;
use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors;
use ic_crypto_internal_threshold_sig_canister_threshold_sig::{
    CommitmentOpening, IDkgComplaintInternal, MEGaPublicKey, ThresholdEcdsaSigShareInternal,
};
use ic_crypto_internal_types::encrypt::forward_secure::{
    CspFsEncryptionPop, CspFsEncryptionPublicKey,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    CspNiDkgDealing, CspNiDkgTranscript, Epoch,
};
use ic_crypto_node_key_validation::ValidNodePublicKeys;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_types::crypto::ExtendedDerivationPath;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgLoadTranscriptError, IDkgOpenTranscriptError, IDkgRetainKeysError,
    IDkgVerifyDealingPrivateError, ThresholdEcdsaCreateSigShareError,
};
use ic_types::crypto::canister_threshold_sig::idkg::BatchSignedIDkgDealing;
use ic_types::crypto::vetkd::VetKdDerivationContext;
use ic_types::crypto::vetkd::VetKdEncryptedKeyShareContent;
use ic_types::crypto::{AlgorithmId, CurrentNodePublicKeys};
use ic_types::{NodeId, NodeIndex, NumberOfNodes, Randomness};
use mockall::mock;
use std::collections::{BTreeMap, BTreeSet};

mock! {
    pub LocalCspVault {}

    impl BasicSignatureCspVault for LocalCspVault {
        fn sign(&self, message: Vec<u8>) -> Result<CspSignature, CspBasicSignatureError>;

        fn gen_node_signing_key_pair(&self) -> Result<CspPublicKey, CspBasicSignatureKeygenError>;
    }

    impl MultiSignatureCspVault for LocalCspVault {
        fn multi_sign(
            &self,
            algorithm_id: AlgorithmId,
            message: Vec<u8>,
            key_id: KeyId,
        ) -> Result<CspSignature, CspMultiSignatureError>;

        fn gen_committee_signing_key_pair(
            &self,
        ) -> Result<(CspPublicKey, CspPop), CspMultiSignatureKeygenError>;
    }

    impl ThresholdSignatureCspVault for LocalCspVault{
        fn threshold_sign(
            &self,
            algorithm_id: AlgorithmId,
            message: Vec<u8>,
            key_id: KeyId,
        ) -> Result<CspSignature, CspThresholdSignError>;
    }

    impl NiDkgCspVault for LocalCspVault {
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
            receiver_keys: BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
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

    impl IDkgProtocolCspVault for LocalCspVault{
        fn idkg_create_dealing(
            &self,
            algorithm_id: AlgorithmId,
            context_data: Vec<u8>,
            dealer_index: NodeIndex,
            reconstruction_threshold: NumberOfNodes,
            receiver_keys: Vec<PublicKey>,
            transcript_operation: IDkgTranscriptOperationInternalBytes,
        ) -> Result<IDkgDealingInternalBytes, IDkgCreateDealingVaultError>;

        fn idkg_verify_dealing_private(
            &self,
            algorithm_id: AlgorithmId,
            dealing: IDkgDealingInternalBytes,
            dealer_index: NodeIndex,
            receiver_index: NodeIndex,
            receiver_key_id: KeyId,
            context_data: Vec<u8>,
        ) -> Result<(), IDkgVerifyDealingPrivateError>;

        fn idkg_load_transcript(
            &self,
            algorithm_id: AlgorithmId,
            dealings: BTreeMap<NodeIndex, IDkgDealingInternalBytes>,
            context_data: Vec<u8>,
            receiver_index: NodeIndex,
            key_id: KeyId,
            transcript: IDkgTranscriptInternalBytes,
        ) -> Result<BTreeMap<NodeIndex, IDkgComplaintInternal>, IDkgLoadTranscriptError>;

        fn idkg_load_transcript_with_openings(
            &self,
            algorithm_id: AlgorithmId,
            dealings: BTreeMap<NodeIndex, BatchSignedIDkgDealing>,
            openings: BTreeMap<NodeIndex, BTreeMap<NodeIndex, CommitmentOpening>>,
            context_data: Vec<u8>,
            receiver_index: NodeIndex,
            key_id: KeyId,
            transcript: IDkgTranscriptInternalBytes,
        ) -> Result<(), IDkgLoadTranscriptError>;

        fn idkg_gen_dealing_encryption_key_pair(&self) -> Result<MEGaPublicKey, CspCreateMEGaKeyError>;

        fn idkg_open_dealing(
            &self,
            algorithm_id: AlgorithmId,
            dealing: BatchSignedIDkgDealing,
            dealer_index: NodeIndex,
            context_data: Vec<u8>,
            opener_index: NodeIndex,
            opener_key_id: KeyId,
        ) -> Result<CommitmentOpening, IDkgOpenTranscriptError>;

        fn idkg_retain_active_keys(
            &self,
            active_key_ids: BTreeSet<KeyId>,
            oldest_public_key: MEGaPublicKey,
        ) -> Result<(), IDkgRetainKeysError>;
    }

    impl ThresholdEcdsaSignerCspVault for LocalCspVault {
        fn create_ecdsa_sig_share(
            &self,
            derivation_path: ExtendedDerivationPath,
            hashed_message: Vec<u8>,
            nonce: Randomness,
            key_raw: IDkgTranscriptInternalBytes,
            kappa_unmasked_raw: IDkgTranscriptInternalBytes,
            lambda_masked_raw: IDkgTranscriptInternalBytes,
            kappa_times_lambda_raw: IDkgTranscriptInternalBytes,
            key_times_lambda_raw: IDkgTranscriptInternalBytes,
            algorithm_id: AlgorithmId,
        ) -> Result<ThresholdEcdsaSigShareInternal, ThresholdEcdsaCreateSigShareError>;
    }

    impl ThresholdSchnorrSignerCspVault for LocalCspVault {
        fn create_schnorr_sig_share(
            &self,
            derivation_path: ExtendedDerivationPath,
            message: Vec<u8>,
            taproot_tree_root: Option<Vec<u8>>,
            nonce: Randomness,
            key_raw: IDkgTranscriptInternalBytes,
            presig_raw: IDkgTranscriptInternalBytes,
            algorithm_id: AlgorithmId,
        ) -> Result<ThresholdSchnorrSigShareBytes, ThresholdSchnorrCreateSigShareVaultError>;
    }

    impl VetKdCspVault for LocalCspVault {
        fn create_encrypted_vetkd_key_share(
            &self,
            key_id: KeyId,
            master_public_key: Vec<u8>,
            transport_public_key: Vec<u8>,
            context: VetKdDerivationContext,
            input: Vec<u8>,
        ) -> Result<VetKdEncryptedKeyShareContent, VetKdEncryptedKeyShareCreationVaultError>;
    }

    impl SecretKeyStoreCspVault for LocalCspVault{
        fn sks_contains(&self, key_id: KeyId) -> Result<bool, CspSecretKeyStoreContainsError>;
    }

    impl PublicAndSecretKeyStoreCspVault for LocalCspVault{
        fn pks_and_sks_contains(
            &self,
            external_public_keys: ExternalPublicKeys,
        ) -> Result<(), PksAndSksContainsErrors>;

        fn validate_pks_and_sks(&self) -> Result<ValidNodePublicKeys, ValidatePksAndSksError>;
    }

    impl TlsHandshakeCspVault for LocalCspVault {
        fn gen_tls_key_pair(
            &self,
            node: NodeId,
        ) -> Result<TlsPublicKeyCert, CspTlsKeygenError>;

        fn tls_sign(&self, message: Vec<u8>, key_id: KeyId) -> Result<CspSignature, CspTlsSignError>;
    }

    impl PublicRandomSeedGenerator for LocalCspVault {
        fn new_public_seed(&self) -> Result<Seed, PublicRandomSeedGeneratorError>;
    }

    impl PublicKeyStoreCspVault for LocalCspVault {
        fn current_node_public_keys(&self) -> Result<CurrentNodePublicKeys, CspPublicKeyStoreError>;

        fn current_node_public_keys_with_timestamps(
            &self,
        ) -> Result<CurrentNodePublicKeys, CspPublicKeyStoreError>;

        fn idkg_dealing_encryption_pubkeys_count(&self) -> Result<usize, CspPublicKeyStoreError>;
    }
}
