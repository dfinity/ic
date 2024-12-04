use ic_crypto_internal_bls12_381_vetkd::{DerivationPath, DerivedPublicKey, G2Affine};
use ic_crypto_internal_threshold_sig_canister_threshold_sig::DeriveThresholdPublicKeyError;
use ic_types::crypto::canister_threshold_sig::error::CanisterThresholdGetPublicKeyError;
use ic_types::crypto::canister_threshold_sig::{MasterPublicKey, PublicKey};
use ic_types::crypto::AlgorithmId;
use ic_types::crypto::ExtendedDerivationPath;
use std::fmt;

/// Derives the threshold public key from the specified `master_public_key` for
/// the given `extended_derivation_path`.
pub fn derive_threshold_public_key(
    master_public_key: &MasterPublicKey,
    extended_derivation_path: &ExtendedDerivationPath,
) -> Result<PublicKey, CanisterThresholdGetPublicKeyError> {
    ic_crypto_internal_threshold_sig_canister_threshold_sig::derive_threshold_public_key(
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

/// Derives the vetKD public key from the specified `master_public_key` for
/// the given `extended_derivation_path`.
pub fn derive_vetkd_public_key(
    master_public_key: &MasterPublicKey,
    extended_derivation_path: &ExtendedDerivationPath,
) -> Result<Vec<u8>, VetKdPublicKeyDeriveError> {
    match master_public_key.algorithm_id {
        AlgorithmId::ThresBls12_381 => (),
        _ => return Err(VetKdPublicKeyDeriveError::InvalidAlgorithmId),
    };

    let key = G2Affine::deserialize(&master_public_key.public_key)
        .map_err(|_| VetKdPublicKeyDeriveError::InvalidPublicKey)?;

    let derivation_path = DerivationPath::new(
        extended_derivation_path.caller.as_slice(),
        &extended_derivation_path.derivation_path,
    );

    let derived_key = DerivedPublicKey::compute_derived_key(&key, &derivation_path);
    Ok(derived_key.serialize().to_vec())
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum VetKdPublicKeyDeriveError {
    InvalidAlgorithmId,
    InvalidPublicKey,
}

impl fmt::Display for VetKdPublicKeyDeriveError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}
