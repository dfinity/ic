#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

//! Static IDKM-compatible functions for threshold signatures
use ic_crypto_internal_threshold_sig_bls12381 as bls12_381;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes as BlsPublicKeyBytes;
use ic_interfaces::crypto::Signable;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use ic_types::crypto::{CombinedThresholdSigOf, CryptoResult};
use std::convert::TryFrom;

mod conversions;
pub use conversions::*;

#[cfg(test)]
mod tests;

/// Verify a combined threshold signature.
///
/// # Arguments
/// * `msg` is the [Signable] object associated with the signature
/// * `sig` is the combined threshold signature to be verified
/// * `pk` is the public key
/// # Returns
/// `Ok(())` if the signature is accepted, or an `Err` otherwise
/// # Error
/// Returns an error if the signature could not be verified
#[allow(dead_code)]
pub fn verify_combined<T: Signable>(
    msg: &T,
    sig: &CombinedThresholdSigOf<T>,
    pk: &ThresholdSigPublicKey,
) -> CryptoResult<()> {
    let bls_pk = BlsPublicKeyBytes(pk.into_bytes());
    let bls_sig = bls12_381::types::CombinedSignatureBytes::try_from(&sig.get_ref().0)?;
    bls12_381::api::verify_combined_signature(&msg.as_signed_bytes(), bls_sig, bls_pk)
}
