use crate::api::{CspCreateMEGaKeyError, CspThresholdSignError};
use crate::types::{CspPop, CspPublicCoefficients, CspPublicKey, CspSignature};
use crate::vault::api::{
    CspBasicSignatureError, CspBasicSignatureKeygenError, CspMultiSignatureError,
    CspMultiSignatureKeygenError, CspThresholdSignatureKeygenError, CspTlsKeygenError,
    CspTlsSignError,
};
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
    IDkgCreateDealingError, IDkgLoadTranscriptError, IDkgOpenTranscriptError,
    IDkgVerifyDealingPrivateError, ThresholdEcdsaSignShareError,
};
use ic_types::crypto::canister_threshold_sig::ExtendedDerivationPath;
use ic_types::crypto::{AlgorithmId, KeyId};
use ic_types::{NodeId, NodeIndex, NumberOfNodes, Randomness};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use tokio::net::UnixListener;

mod tarpc_csp_vault_client;
mod tarpc_csp_vault_server;

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
        message: Vec<u8>,
        key_id: KeyId,
    ) -> Result<CspSignature, CspBasicSignatureError>;

    // Corresponds to `BasicSignatureCspVault.gen_key_pair()`.
    async fn gen_key_pair(
        algorithm_id: AlgorithmId,
    ) -> Result<(KeyId, CspPublicKey), CspBasicSignatureKeygenError>;

    // Corresponds to `MultiSignatureCspVault.multi_sign()`.
    async fn multi_sign(
        algorithm_id: AlgorithmId,
        message: Vec<u8>,
        key_id: KeyId,
    ) -> Result<CspSignature, CspMultiSignatureError>;

    // Corresponds to `MultiSignatureCspVault.gen_key_pair_with_pop()`.
    async fn gen_key_pair_with_pop(
        algorithm_id: AlgorithmId,
    ) -> Result<(KeyId, CspPublicKey, CspPop), CspMultiSignatureKeygenError>;

    // Corresponds to `ThresholdSignatureCspVault.threshold_sign()`.
    async fn threshold_sign(
        algorithm_id: AlgorithmId,
        message: Vec<u8>,
        key_id: KeyId,
    ) -> Result<CspSignature, CspThresholdSignError>;

    // Corresponds to `ThresholdSignatureCspVault.threshold_keygen_for_test()`.
    async fn threshold_keygen_for_test(
        algorithm_id: AlgorithmId,
        threshold: NumberOfNodes,
        signatory_eligibility: Vec<bool>,
    ) -> Result<(CspPublicCoefficients, Vec<Option<KeyId>>), CspThresholdSignatureKeygenError>;

    // Corresponds to `NiDkgCspVault.gen_forward_secure_key_pair()`.
    async fn gen_forward_secure_key_pair(
        node_id: NodeId,
        algorithm_id: AlgorithmId,
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
    async fn retain_threshold_keys_if_present(active_key_ids: BTreeSet<KeyId>);

    // Corresponds to `SecretKeyStoreCspVault.sks_contains()`.
    async fn sks_contains(key_id: KeyId) -> bool;

    // Corresponds to `TlsHandshakeCspVault.gen_tls_key_pair()`.
    async fn gen_tls_key_pair(
        node: NodeId,
        not_after: String,
    ) -> Result<(KeyId, TlsPublicKeyCert), CspTlsKeygenError>;

    // Corresponds to `TlsHandshakeCspVault.tls_sign()`.
    async fn tls_sign(message: Vec<u8>, key_id: KeyId) -> Result<CspSignature, CspTlsSignError>;

    // Corresponds to `IDkgProtocolCspVault.idkg_create_dealing`
    #[allow(clippy::too_many_arguments)]
    async fn idkg_create_dealing(
        algorithm_id: AlgorithmId,
        context_data: Vec<u8>,
        dealer_index: NodeIndex,
        reconstruction_threshold: NumberOfNodes,
        receiver_keys: Vec<MEGaPublicKey>,
        transcript_operation: IDkgTranscriptOperationInternal,
    ) -> Result<IDkgDealingInternal, IDkgCreateDealingError>;

    // Corresponds to `IDkgProtocolCspVault.idkg_verify_dealing_private`
    async fn idkg_verify_dealing_private(
        algorithm_id: AlgorithmId,
        dealing: IDkgDealingInternal,
        dealer_index: NodeIndex,
        receiver_index: NodeIndex,
        receiver_key_id: KeyId,
        context_data: Vec<u8>,
    ) -> Result<(), IDkgVerifyDealingPrivateError>;

    // Corresponds to `IDkgProtocolCspVault.idkg_load_transcript`
    async fn idkg_load_transcript(
        dealings: BTreeMap<NodeIndex, IDkgDealingInternal>,
        context_data: Vec<u8>,
        receiver_index: NodeIndex,
        key_id: KeyId,
        transcript: IDkgTranscriptInternal,
    ) -> Result<BTreeMap<NodeIndex, IDkgComplaintInternal>, IDkgLoadTranscriptError>;

    // Corresponds to `IDkgProtocolCspVault.idkg_load_transcript_with_openings`
    #[allow(clippy::too_many_arguments)]
    async fn idkg_load_transcript_with_openings(
        dealings: BTreeMap<NodeIndex, IDkgDealingInternal>,
        openings: BTreeMap<NodeIndex, BTreeMap<NodeIndex, CommitmentOpening>>,
        context_data: Vec<u8>,
        receiver_index: NodeIndex,
        key_id: KeyId,
        transcript: IDkgTranscriptInternal,
    ) -> Result<(), IDkgLoadTranscriptError>;

    // Corresponds to `IDkgProtocolCspVault.idkg_gen_mega_key_pair`
    async fn idkg_gen_mega_key_pair(
        algorithm_id: AlgorithmId,
    ) -> Result<MEGaPublicKey, CspCreateMEGaKeyError>;

    // Corresponds to `IDkgProtocolCspVault.idkg_open_dealing`
    async fn idkg_open_dealing(
        dealing: IDkgDealingInternal,
        dealer_index: NodeIndex,
        context_data: Vec<u8>,
        opener_index: NodeIndex,
        opener_key_id: KeyId,
    ) -> Result<CommitmentOpening, IDkgOpenTranscriptError>;

    // Corresponds to `ThresholdEcdsaSignerCspVault.ecdsa_sign_share`
    #[allow(clippy::too_many_arguments)]
    async fn ecdsa_sign_share(
        derivation_path: ExtendedDerivationPath,
        hashed_message: Vec<u8>,
        nonce: Randomness,
        key: IDkgTranscriptInternal,
        kappa_unmasked: IDkgTranscriptInternal,
        lambda_masked: IDkgTranscriptInternal,
        kappa_times_lambda: IDkgTranscriptInternal,
        key_times_lambda: IDkgTranscriptInternal,
        algorithm_id: AlgorithmId,
    ) -> Result<ThresholdEcdsaSigShareInternal, ThresholdEcdsaSignShareError>;
}

pub async fn run_csp_vault_server(sks_dir: &Path, listener: UnixListener) {
    let server = tarpc_csp_vault_server::TarpcCspVaultServerImpl::new(sks_dir, listener);
    server.run().await
}
