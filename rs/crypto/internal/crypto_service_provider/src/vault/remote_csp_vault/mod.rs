use crate::api::CspThresholdSignError;
use crate::types::{CspPop, CspPublicCoefficients, CspPublicKey, CspSignature};
use crate::vault::api::{
    CspBasicSignatureError, CspBasicSignatureKeygenError, CspMultiSignatureError,
    CspMultiSignatureKeygenError, CspThresholdSignatureKeygenError,
};
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors;
use ic_crypto_internal_types::encrypt::forward_secure::{
    CspFsEncryptionPop, CspFsEncryptionPublicKey,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    CspNiDkgDealing, CspNiDkgTranscript, Epoch,
};
use ic_types::crypto::{AlgorithmId, KeyId};
use ic_types::{NodeId, NodeIndex, NumberOfNodes};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

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
}

pub async fn run_csp_vault_server(sks_dir: &Path, socket_path: &Path) {
    let server = tarpc_csp_vault_server::TarpcCspVaultServerImpl::new(sks_dir, socket_path);
    server.run().await
}
