use ic_crypto_internal_threshold_sig_ecdsa::DeriveThresholdPublicKeyError;
use ic_types::crypto::canister_threshold_sig::error::CanisterThresholdGetPublicKeyError;
use ic_types::crypto::canister_threshold_sig::{
    ExtendedDerivationPath, MasterPublicKey, PublicKey,
};

/// Derives the threshold public key from the specified `master_public_key` for
/// the given `extended_derivation_path`.
pub fn derive_threshold_public_key(
    master_public_key: &MasterPublicKey,
    extended_derivation_path: &ExtendedDerivationPath,
) -> Result<PublicKey, CanisterThresholdGetPublicKeyError> {
    ic_crypto_internal_threshold_sig_ecdsa::derive_threshold_public_key(
        master_public_key,
        &extended_derivation_path.into(),
    )
    .map_err(|e| match e {
        DeriveThresholdPublicKeyError::InvalidArgument(s) => {
            CanisterThresholdGetPublicKeyError::InvalidArgument(s)
        }
        DeriveThresholdPublicKeyError::InternalError(e) => {
            CanisterThresholdGetPublicKeyError::InternalError(format!("{:?}", e))
        }
    })
}
