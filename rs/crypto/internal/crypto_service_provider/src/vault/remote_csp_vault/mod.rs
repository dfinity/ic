use crate::api::{CspCreateMEGaKeyError, CspThresholdSignError};
use crate::types::{CspPop, CspPublicKey, CspSignature};
use crate::vault::api::{
    CspBasicSignatureError, CspBasicSignatureKeygenError, CspMultiSignatureError,
    CspMultiSignatureKeygenError, CspPublicKeyStoreError, CspSecretKeyStoreContainsError,
    CspTlsKeygenError, CspTlsSignError, IDkgCreateDealingVaultError, IDkgDealingInternalBytes,
    IDkgTranscriptInternalBytes, PksAndSksContainsErrors, ThresholdSchnorrCreateSigShareVaultError,
    ThresholdSchnorrSigShareBytes, ValidatePksAndSksError,
};
use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors;
use ic_crypto_internal_threshold_sig_ecdsa::{
    CommitmentOpening, IDkgComplaintInternal, MEGaPublicKey, ThresholdEcdsaSigShareInternal,
};
use ic_crypto_internal_types::encrypt::forward_secure::{
    CspFsEncryptionPop, CspFsEncryptionPublicKey,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    CspNiDkgDealing, CspNiDkgTranscript, Epoch,
};
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_logger::ReplicaLogger;
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgLoadTranscriptError, IDkgOpenTranscriptError, IDkgRetainKeysError,
    IDkgVerifyDealingPrivateError, ThresholdEcdsaCreateSigShareError,
};
use ic_types::crypto::canister_threshold_sig::{
    idkg::{BatchSignedIDkgDealing, IDkgTranscriptOperation},
    ExtendedDerivationPath,
};
use ic_types::crypto::{AlgorithmId, CurrentNodePublicKeys};
use ic_types::{NodeId, NodeIndex, NumberOfNodes, Randomness};
use serde_bytes::ByteBuf;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use tokio::net::UnixListener;

const FOUR_GIGA_BYTES: usize = 4 * 1024 * 1024 * 1024;
mod codec;
mod robust_unix_socket;
mod tarpc_csp_vault_client;
mod tarpc_csp_vault_server;

use crate::key_id::KeyId;
pub use crate::vault::local_csp_vault::ProdLocalCspVault;
use crate::ExternalPublicKeys;
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_crypto_node_key_validation::ValidNodePublicKeys;
use std::sync::Arc;
pub use tarpc_csp_vault_client::{RemoteCspVault, RemoteCspVaultBuilder};
pub use tarpc_csp_vault_server::{TarpcCspVaultServerImpl, TarpcCspVaultServerImplBuilder};
use tokio_util::codec::length_delimited::Builder;
use tokio_util::codec::LengthDelimitedCodec;

use super::api::PublicRandomSeedGeneratorError;

#[cfg(test)]
mod tests;

// The actual `tarpc`-based CspVault trait.
// As `tarpc` does not support composed traits (i.e. we cannot just write
// that this trait implements e.g. BasicSignatureCspVault-trait)
// we "compose" it manually, by copying the methods from
// the relevant traits that define the required functionalities.
#[tarpc::service]
pub trait TarpcCspVault {
    // Corresponds to `BasicSignatureCspVault.sign()`.
    async fn sign(
        algorithm_id: AlgorithmId,
        message: ByteBuf,
        key_id: KeyId,
    ) -> Result<CspSignature, CspBasicSignatureError>;

    // Corresponds to `BasicSignatureCspVault.gen_node_signing_key_pair()`.
    async fn gen_node_signing_key_pair() -> Result<CspPublicKey, CspBasicSignatureKeygenError>;

    // Corresponds to `MultiSignatureCspVault.multi_sign()`.
    async fn multi_sign(
        algorithm_id: AlgorithmId,
        message: ByteBuf,
        key_id: KeyId,
    ) -> Result<CspSignature, CspMultiSignatureError>;

    // Corresponds to `MultiSignatureCspVault.gen_committee_signing_key_pair()`.
    async fn gen_committee_signing_key_pair(
    ) -> Result<(CspPublicKey, CspPop), CspMultiSignatureKeygenError>;

    // Corresponds to `ThresholdSignatureCspVault.threshold_sign()`.
    async fn threshold_sign(
        algorithm_id: AlgorithmId,
        message: ByteBuf,
        key_id: KeyId,
    ) -> Result<CspSignature, CspThresholdSignError>;

    // Corresponds to `NiDkgCspVault.gen_dealing_encryption_key_pair()`.
    async fn gen_dealing_encryption_key_pair(
        node_id: NodeId,
    ) -> Result<(CspFsEncryptionPublicKey, CspFsEncryptionPop), ni_dkg_errors::CspDkgCreateFsKeyError>;

    // Corresponds to `NiDkgCspVault.update_forward_secure_epoch()`.
    async fn update_forward_secure_epoch(
        algorithm_id: AlgorithmId,
        key_id: KeyId,
        epoch: Epoch,
    ) -> Result<(), ni_dkg_errors::CspDkgUpdateFsEpochError>;

    // Corresponds to `NiDkgCspVault.create_dealing()`.
    #[allow(clippy::too_many_arguments)]
    async fn create_dealing(
        algorithm_id: AlgorithmId,
        dealer_index: NodeIndex,
        threshold: NumberOfNodes,
        epoch: Epoch,
        receiver_keys: BTreeMap<NodeIndex, CspFsEncryptionPublicKey>,
        maybe_resharing_secret: Option<KeyId>,
    ) -> Result<CspNiDkgDealing, ni_dkg_errors::CspDkgCreateReshareDealingError>;

    // Corresponds to `NiDkgCspVault.load_threshold_signing_key()`.
    async fn load_threshold_signing_key(
        algorithm_id: AlgorithmId,
        epoch: Epoch,
        csp_transcript: CspNiDkgTranscript,
        fs_key_id: KeyId,
        receiver_index: NodeIndex,
    ) -> Result<(), ni_dkg_errors::CspDkgLoadPrivateKeyError>;

    // Corresponds to `NiDkgCspVault.retain_threshold_keys_if_present()`.
    async fn retain_threshold_keys_if_present(
        active_key_ids: BTreeSet<KeyId>,
    ) -> Result<(), ni_dkg_errors::CspDkgRetainThresholdKeysError>;

    // Corresponds to `SecretKeyStoreCspVault.sks_contains()`.
    async fn sks_contains(key_id: KeyId) -> Result<bool, CspSecretKeyStoreContainsError>;

    // Corresponds to `PublicKeyStoreCspVault.current_node_public_keys()`.
    async fn current_node_public_keys() -> Result<CurrentNodePublicKeys, CspPublicKeyStoreError>;

    // Corresponds to `PublicKeyStoreCspVault.current_node_public_keys_with_timestamps()`.
    async fn current_node_public_keys_with_timestamps(
    ) -> Result<CurrentNodePublicKeys, CspPublicKeyStoreError>;

    // Corresponds to `PublicKeyStoreCspVault.idkg_key_count()`.
    async fn idkg_key_count() -> Result<usize, CspPublicKeyStoreError>;

    // Corresponds to `PublicAndSecretKeyStoreCspVault.pks_and_sks_contains()`.
    async fn pks_and_sks_contains(
        external_public_keys: ExternalPublicKeys,
    ) -> Result<(), PksAndSksContainsErrors>;

    // Corresponds to `PublicAndSecretKeyStoreCspVault.validate_pks_and_sks()`.
    async fn validate_pks_and_sks() -> Result<ValidNodePublicKeys, ValidatePksAndSksError>;

    // Corresponds to `TlsHandshakeCspVault.gen_tls_key_pair()`.
    async fn gen_tls_key_pair(node: NodeId) -> Result<TlsPublicKeyCert, CspTlsKeygenError>;

    // Corresponds to `TlsHandshakeCspVault.tls_sign()`.
    async fn tls_sign(message: ByteBuf, key_id: KeyId) -> Result<CspSignature, CspTlsSignError>;

    // Corresponds to `IDkgProtocolCspVault.idkg_create_dealing`
    #[allow(clippy::too_many_arguments)]
    async fn idkg_create_dealing(
        algorithm_id: AlgorithmId,
        context_data: ByteBuf,
        dealer_index: NodeIndex,
        reconstruction_threshold: NumberOfNodes,
        receiver_keys: Vec<PublicKey>,
        transcript_operation: IDkgTranscriptOperation,
    ) -> Result<IDkgDealingInternalBytes, IDkgCreateDealingVaultError>;

    // Corresponds to `IDkgProtocolCspVault.idkg_verify_dealing_private`
    async fn idkg_verify_dealing_private(
        algorithm_id: AlgorithmId,
        dealing: IDkgDealingInternalBytes,
        dealer_index: NodeIndex,
        receiver_index: NodeIndex,
        receiver_key_id: KeyId,
        context_data: ByteBuf,
    ) -> Result<(), IDkgVerifyDealingPrivateError>;

    // Corresponds to `IDkgProtocolCspVault.idkg_load_transcript`
    async fn idkg_load_transcript(
        algorithm_id: AlgorithmId,
        dealings: BTreeMap<NodeIndex, BatchSignedIDkgDealing>,
        context_data: ByteBuf,
        receiver_index: NodeIndex,
        key_id: KeyId,
        transcript: IDkgTranscriptInternalBytes,
    ) -> Result<BTreeMap<NodeIndex, IDkgComplaintInternal>, IDkgLoadTranscriptError>;

    // Corresponds to `IDkgProtocolCspVault.idkg_load_transcript_with_openings`
    #[allow(clippy::too_many_arguments)]
    async fn idkg_load_transcript_with_openings(
        alg: AlgorithmId,
        dealings: BTreeMap<NodeIndex, BatchSignedIDkgDealing>,
        openings: BTreeMap<NodeIndex, BTreeMap<NodeIndex, CommitmentOpening>>,
        context_data: ByteBuf,
        receiver_index: NodeIndex,
        key_id: KeyId,
        transcript: IDkgTranscriptInternalBytes,
    ) -> Result<(), IDkgLoadTranscriptError>;

    // Corresponds to `IDkgProtocolCspVault.idkg_retain_active_keys`
    async fn idkg_retain_active_keys(
        active_key_ids: BTreeSet<KeyId>,
        oldest_public_key: MEGaPublicKey,
    ) -> Result<(), IDkgRetainKeysError>;

    // Corresponds to `IDkgProtocolCspVault.idkg_gen_dealing_encryption_key_pair`
    async fn idkg_gen_dealing_encryption_key_pair() -> Result<MEGaPublicKey, CspCreateMEGaKeyError>;

    // Corresponds to `IDkgProtocolCspVault.idkg_open_dealing`
    async fn idkg_open_dealing(
        alg: AlgorithmId,
        dealing: BatchSignedIDkgDealing,
        dealer_index: NodeIndex,
        context_data: ByteBuf,
        opener_index: NodeIndex,
        opener_key_id: KeyId,
    ) -> Result<CommitmentOpening, IDkgOpenTranscriptError>;

    // Corresponds to `ThresholdEcdsaSignerCspVault.create_ecdsa_sig_share`
    #[allow(clippy::too_many_arguments)]
    async fn create_ecdsa_sig_share(
        derivation_path: ExtendedDerivationPath,
        hashed_message: ByteBuf,
        nonce: Randomness,
        key_raw: IDkgTranscriptInternalBytes,
        kappa_unmasked_raw: IDkgTranscriptInternalBytes,
        lambda_masked_raw: IDkgTranscriptInternalBytes,
        kappa_times_lambda_raw: IDkgTranscriptInternalBytes,
        key_times_lambda_raw: IDkgTranscriptInternalBytes,
        algorithm_id: AlgorithmId,
    ) -> Result<ThresholdEcdsaSigShareInternal, ThresholdEcdsaCreateSigShareError>;

    // Corresponds to `ThresholdSchnorrSignerCspVault.create_schnorr_sig_share`
    async fn create_schnorr_sig_share(
        derivation_path: ExtendedDerivationPath,
        message: ByteBuf,
        nonce: Randomness,
        key_raw: IDkgTranscriptInternalBytes,
        presig_raw: IDkgTranscriptInternalBytes,
        algorithm_id: AlgorithmId,
    ) -> Result<ThresholdSchnorrSigShareBytes, ThresholdSchnorrCreateSigShareVaultError>;

    async fn new_public_seed() -> Result<Seed, PublicRandomSeedGeneratorError>;
}

pub async fn run_csp_vault_server(
    sks_dir: &Path,
    listener: UnixListener,
    logger: ReplicaLogger,
    metrics: CryptoMetrics,
) {
    let server = TarpcCspVaultServerImpl::builder(sks_dir)
        .with_logger(logger)
        .with_metrics(Arc::new(metrics))
        .build(listener);
    server.run().await
}

pub fn remote_vault_codec_builder() -> Builder {
    let mut codec_builder = LengthDelimitedCodec::builder();
    codec_builder
        .length_field_type::<u32>()
        .max_frame_length(FOUR_GIGA_BYTES);
    codec_builder
}
