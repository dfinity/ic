use ic_crypto_internal_bls12_381_vetkd::{DerivationDomain, DerivedPublicKey, G2Affine};
use ic_crypto_internal_threshold_sig_canister_threshold_sig::DeriveThresholdPublicKeyError;
use ic_types::crypto::canister_threshold_sig::error::CanisterThresholdGetPublicKeyError;
use ic_types::crypto::canister_threshold_sig::{MasterPublicKey, PublicKey};
use ic_types::crypto::vetkd::VetKdDerivationDomain;
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
    derivation_domain: &VetKdDerivationDomain,
) -> Result<Vec<u8>, VetKdPublicKeyDeriveError> {
    match master_public_key.algorithm_id {
        AlgorithmId::VetKD => (),
        _ => return Err(VetKdPublicKeyDeriveError::InvalidAlgorithmId),
    };

    let key = G2Affine::deserialize(&master_public_key.public_key)
        .map_err(|_| VetKdPublicKeyDeriveError::InvalidPublicKey)?;

    let derivation_domain = DerivationDomain::new(
        derivation_domain.caller.as_slice(),
        &derivation_domain.domain,
    );

    let derived_key = DerivedPublicKey::compute_derived_key(&key, &derivation_domain);
    Ok(derived_key.serialize().to_vec())
}

/// Checks if the given bytes deserialize into a correct public key
pub fn is_valid_transport_public_key(transport_public_key: &[u8; 48]) -> bool {
    G2Affine::deserialize(transport_public_key).is_ok()
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
