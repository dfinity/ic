use ic_crypto_internal_threshold_sig_ecdsa::ThresholdEcdsaDerivePublicKeyError;
use ic_types::crypto::canister_threshold_sig::error::ThresholdEcdsaGetPublicKeyError;
use ic_types::crypto::canister_threshold_sig::{
    EcdsaPublicKey, ExtendedDerivationPath, MasterEcdsaPublicKey,
};

/// Derives the ECDSA public key from the specified `master_public_key` for
/// the given `extended_derivation_path`.
pub fn derive_tecdsa_public_key(
    master_public_key: &MasterEcdsaPublicKey,
    extended_derivation_path: &ExtendedDerivationPath,
) -> Result<EcdsaPublicKey, ThresholdEcdsaGetPublicKeyError> {
    ic_crypto_internal_threshold_sig_ecdsa::derive_ecdsa_public_key(
        master_public_key,
        &extended_derivation_path.into(),
    )
    .map_err(|e| match e {
        ThresholdEcdsaDerivePublicKeyError::InvalidArgument(s) => {
            ThresholdEcdsaGetPublicKeyError::InvalidArgument(s)
        }
        ThresholdEcdsaDerivePublicKeyError::InternalError(e) => {
            ThresholdEcdsaGetPublicKeyError::InternalError(format!("{:?}", e))
        }
    })
}
