use crate::api::{CspCreateMEGaKeyError, CspThresholdSignError};
use crate::key_id::KeyId;
use crate::types::CspPublicCoefficients;
use crate::types::{CspPop, CspPublicKey, CspSignature};
use crate::vault::api::BasicSignatureCspVault;
use crate::vault::api::CspThresholdSignatureKeygenError;
use crate::vault::api::CspTlsSignError;
use crate::vault::api::IDkgProtocolCspVault;
use crate::vault::api::MultiSignatureCspVault;
use crate::vault::api::NiDkgCspVault;
use crate::vault::api::PksAndSksContainsErrors;
use crate::vault::api::PublicAndSecretKeyStoreCspVault;
use crate::vault::api::PublicKeyStoreCspVault;
use crate::vault::api::PublicRandomSeedGenerator;
use crate::vault::api::PublicRandomSeedGeneratorError;
use crate::vault::api::SecretKeyStoreCspVault;
use crate::vault::api::ThresholdEcdsaSignerCspVault;
use crate::vault::api::ThresholdSignatureCspVault;
use crate::vault::CspBasicSignatureError;
use crate::vault::CspBasicSignatureKeygenError;
use crate::vault::CspMultiSignatureError;
use crate::vault::CspMultiSignatureKeygenError;
use crate::vault::CspSecretKeyStoreContainsError;
use crate::vault::CspTlsKeygenError;
use crate::CspPublicKeyStoreError;
use crate::ExternalPublicKeys;
use crate::TlsHandshakeCspVault;
use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors;
use ic_crypto_internal_threshold_sig_ecdsa::{
    CommitmentOpening, IDkgComplaintInternal, IDkgDealingInternal, IDkgTranscriptInternal,
    IDkgTranscriptOperationInternal, MEGaPublicKey, ThresholdEcdsaSigShareInternal,
};
use ic_crypto_internal_types::encrypt::forward_secure::{
    CspFsEncryptionPop, CspFsEncryptionPublicKey,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    CspNiDkgDealing, CspNiDkgTranscript, Epoch,
};
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
        fn threshold_keygen_for_test(
            &self,
            algorithm_id: AlgorithmId,
            threshold: NumberOfNodes,
            receivers: NumberOfNodes,
        ) -> Result<(CspPublicCoefficients, Vec<KeyId>), CspThresholdSignatureKeygenError>;

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
            transcript: &IDkgTranscriptInternal,
        ) -> Result<BTreeMap<NodeIndex, IDkgComplaintInternal>, IDkgLoadTranscriptError>;

        fn idkg_load_transcript_with_openings(
            &self,
            dealings: &BTreeMap<NodeIndex, IDkgDealingInternal>,
            openings: &BTreeMap<NodeIndex, BTreeMap<NodeIndex, CommitmentOpening>>,
            context_data: &[u8],
            receiver_index: NodeIndex,
            key_id: &KeyId,
            transcript: &IDkgTranscriptInternal,
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
            key: &IDkgTranscriptInternal,
            kappa_unmasked: &IDkgTranscriptInternal,
            lambda_masked: &IDkgTranscriptInternal,
            kappa_times_lambda: &IDkgTranscriptInternal,
            key_times_lambda: &IDkgTranscriptInternal,
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
        fn pks_contains(
            &self,
            public_keys: CurrentNodePublicKeys,
        ) -> Result<bool, CspPublicKeyStoreError>;

        fn current_node_public_keys(&self) -> Result<CurrentNodePublicKeys, CspPublicKeyStoreError>;

        fn current_node_public_keys_with_timestamps(
            &self,
        ) -> Result<CurrentNodePublicKeys, CspPublicKeyStoreError>;

        fn idkg_dealing_encryption_pubkeys_count(&self) -> Result<usize, CspPublicKeyStoreError>;
    }
}
