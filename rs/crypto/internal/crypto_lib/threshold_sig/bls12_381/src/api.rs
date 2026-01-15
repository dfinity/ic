//! External API for Threshold Signatures
//!
//! The threshold signature scheme has the following participants:
//! * Signatories are actors who hold a threshold key and can sign with that
//!   key.
//! * Dealers are actors who generate keys that are then distributed to
//!   signatories.
//! * Verifiers are actors who can verify that signatures are valid.
//!
//! The key properties of this threshold signature scheme:
//! * The public output of key generation is a set of `PublicCoefficients`.
//! * Individual signatures can be verified against the public coefficients.
//! * Individual signatures can be combined.  If there are enough individual
//!   signatures, and they are all valid, the combined signature is guaranteed
//!   to be valid and can be validated against the `PublicCoefficients`.
//! * The minimum number of individual signatures needed to make a valid
//!   combined signature is called the `threshold`.
//! * A valid combined signature is unique and the same, regardless of which
//!   threshold signatures were combined.
//! * The combined signature has constant size, regardless of the number of
//!   signatures or the threshold.  In this implementation that constant size is
//!   the same as a single individual signature.
//! * If some individual signatures are invalid, the combined signature is
//!   likely to be invalid.  Individual signatures SHOULD be checked before
//!   combining.
//!
//! Implementation notes:
//! * Potential signatories are stored in a list.  It is important to preserve
//!   the order of signatories, especially in the case of distributed key
//!   generation where multiple keys may be dealt for each signatory.
//! * The standard form for storing signatory information is `Vec<T>`,
//!   where: the index in the vector corresponds to the signatory index
//! * The external API methods are equivalent to internal methods but use opaque
//!   data types. The external API parses requests to the internal types, calls
//!   the corresponding internal methods and serialises the responses.
use super::crypto;
use super::types::{
    CombinedSignatureBytes, IndividualSignature, IndividualSignatureBytes, PublicCoefficients,
    SecretKeyBytes,
};
use crate::api::threshold_sign_error::ClibThresholdSignError;
use crate::types::PublicKey;
use crate::types::public_coefficients::pub_key_bytes_from_pub_coeff_bytes;
use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::PublicCoefficientsBytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_types::{
    NodeIndex, NumberOfNodes,
    crypto::{CryptoError, CryptoResult},
};
use std::convert::TryInto;

pub mod dkg_errors;
pub mod ni_dkg_errors;
#[cfg(test)]
mod tests;
pub mod threshold_sign_error;

/// Generates keys for threshold signatories.
///
/// # Arguments
/// * `seed` is a random input.  It must be treated as a secret.
/// * `threshold` is the minimum number of signatures that can be combined to
///   make a valid threshold signature.
/// * `receivers` is the total number of nodes that will receive a share of
///   the key.
/// # Returns
/// * `PublicCoefficients` can be used by the caller to verify signatures.
/// * `Vec<SecretKeyBytes>` contains secret keys.  The vector is of length
///   `receivers`
/// # Panics
/// This method is not expected to panic.
/// # Errors
/// * If `threshold > receivers` then it is impossible for the signatories to
///   create a valid combined signature, so this is treated as an error.
pub fn generate_threshold_key(
    seed: Seed,
    threshold: NumberOfNodes,
    receivers: NumberOfNodes,
) -> CryptoResult<(PublicCoefficientsBytes, Vec<SecretKeyBytes>)> {
    crypto::generate_threshold_key(seed, threshold, receivers)
        .map(|(public_coefficients, shares)| {
            let shares = shares.iter().cloned().map(SecretKeyBytes::from).collect();
            (PublicCoefficientsBytes::from(&public_coefficients), shares)
        })
        .map_err(CryptoError::from)
}

/// Derives the public key of one signatory from the `public_coefficients`.
///
/// # Arguments
/// * `public_coefficients` is the public output of a key generation.
/// * `index` is the position of the signatory in the list of signatories.
/// # Panics
/// This method is not expected to panic.
/// # Errors
/// If the `public_coefficients` cannot be parsed, this will return an error.
pub fn individual_public_key(
    public_coefficients: &PublicCoefficientsBytes,
    index: NodeIndex,
) -> CryptoResult<PublicKeyBytes> {
    let public_coefficients = PublicCoefficients::deserialize_cached(public_coefficients)?;
    let public_key: PublicKey = crypto::individual_public_key(&public_coefficients, index);
    Ok(PublicKeyBytes::from(public_key))
}

/// Extracts the combined public key from the PublicCoefficients.
///
/// The combined public key is used to verify combined threshold signatures.
///
/// # Arguments
/// * `public_coefficients` is the public output of a key generation.
/// # Panics
/// This method is not expected to panic.
/// # Errors
/// This method is not expected to return an error.
pub fn combined_public_key(
    public_coefficients: &PublicCoefficientsBytes,
) -> CryptoResult<PublicKeyBytes> {
    Ok(pub_key_bytes_from_pub_coeff_bytes(public_coefficients))
}

/// Creates an individual signature.
///
/// # Arguments
/// * `message` is the bytes to be signed.  Note: This may be changed to a
///   `[u8;32]` and renamed to hash pending discussion.  See TODO: DFN-1430
/// * `secret_key` is the individual signing key.
/// # Panics
/// This method is not expected to panic.
/// # Errors
/// If `secret_key` cannot be parsed, this will return an error.
pub fn sign_message(
    message: &[u8],
    secret_key: &SecretKeyBytes,
) -> Result<IndividualSignatureBytes, ClibThresholdSignError> {
    let signature = crypto::sign_message(message, &secret_key.try_into()?);
    Ok(IndividualSignatureBytes::from(&signature))
}

/// Combines individual signatures.
///
/// Note: Individual signatures SHOULD be checked for validity before being
/// combined.
///
/// # Arguments
/// * `signatures` is an array that contains the signature of the `i`th
///   signatory in `signatures[i]`.  Missing signatures are represented by
///   `signatures[i]=None`.  It is important that the signatures have the same
///   indices as the corresponding signatories had during key generation.
/// * `threshold` is the minimum number of signatures needed.
/// # Panics
/// This method is not expected to panic.
/// # Errors
/// * If `signatures` cannot be parsed, this will return an error.  Given that
///   the caller SHOULD verify individual signatures before combining them this
///   SHOULD never occur.
/// * If there are fewer than `threshold` signatures, this will return an error.
pub fn combine_signatures(
    signatures: &[Option<IndividualSignatureBytes>],
    threshold: NumberOfNodes,
) -> CryptoResult<CombinedSignatureBytes> {
    let signatures: CryptoResult<Vec<Option<IndividualSignature>>> = signatures
        .iter()
        .map(|option| {
            option
                .map(|signature: IndividualSignatureBytes| (&signature).try_into())
                .transpose()
        })
        .collect();
    Ok(CombinedSignatureBytes::from(&crypto::combine_signatures(
        &signatures?,
        threshold,
    )?))
}

/// Verifies that an individual signature is valid.
///
/// Usage note: Key generation by any compatible method generates
/// `PublicCoefficients` and fixes an index for each signatory.  An individual
/// signatory's public key can be derived from the `PublicCoefficients` and the
/// signatory's index with `individual_public_key(..)`.
///
/// # Arguments:
/// * `message` is the bytes that have been signed.  Note: This may be changed
///   to a `[u8;32]` and renamed to hash pending discussion.  See TODO: DFN-1430
/// * `signature` is the individual signature to be verified.
/// * `public_key` is the individual public key of the signatory.
/// # Panics
/// This method is not expected to panic.
/// # Errors
/// * If `signature` or `public_key` cannot be parsed, this will return an
///   error.
pub fn verify_individual_signature(
    message: &[u8],
    signature: IndividualSignatureBytes,
    public_key: PublicKeyBytes,
) -> CryptoResult<()> {
    let signature = (&signature).try_into()?;
    let pk = PublicKey::deserialize_cached(&public_key)?;
    crypto::verify_individual_sig(message, &signature, &pk)
}

/// Verifies that a combined signature is valid.
///
/// # Arguments
/// * `message` is the bytes that have been signed.
/// * `signature` is the combined signature to be verified.
/// * `public_key` is the combined public key for the threshold signature.
/// # Panics
/// This method is not expected to panic.
/// # Errors
/// * If `signature` or `public_key` cannot be parsed, or if the signature
///   is not valid for this `public_key` and `message`, this will return an
///   error.
pub fn verify_combined_signature(
    message: &[u8],
    signature: CombinedSignatureBytes,
    public_key: PublicKeyBytes,
) -> CryptoResult<()> {
    let signature = (&signature).try_into()?;
    let pk = PublicKey::deserialize_cached(&public_key)?;
    crypto::verify_combined_sig(message, &signature, &pk)
}

/// Verifies that a combined signature is valid, making use of a cache
///
/// The cache is a global shared signature cache defined in `cache.rs`
/// that caches a fixed number of signatures with an LRU eviction
/// policy.  Cache hits are significantly (~1000x) faster than
/// verifying the BLS signature directly. Using this function can be
/// beneficial in cases where the same BLS signature is repeatedly verified.
///
/// # Arguments
/// * `message` is the bytes that have been signed.
/// * `signature` is the combined signature to be verified.
/// * `public_key` is the combined public key for the threshold signature.
/// # Panics
/// This method is not expected to panic.
/// # Errors
/// * If `signature` or `public_key` cannot be parsed, or if the signature
///   is not valid for this `public_key` and `message`, this will return an
///   error.
pub fn verify_combined_signature_with_cache(
    message: &[u8],
    signature: CombinedSignatureBytes,
    public_key: PublicKeyBytes,
) -> CryptoResult<()> {
    let entry = crate::cache::SignatureCacheEntry::new(&public_key.0, &signature.0, message);

    if crate::cache::SignatureCache::global().contains(&entry) {
        return Ok(());
    }

    let result = verify_combined_signature(message, signature, public_key);

    if result.is_ok() {
        crate::cache::SignatureCache::global().insert(&entry);
    }

    result
}

/// Return statistics related to the verify_combined_signature_with_cache cache
pub fn bls_signature_cache_statistics() -> crate::cache::SignatureCacheStatistics {
    crate::cache::SignatureCache::global().cache_statistics()
}
