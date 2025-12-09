//! External API for the multisignature library
use super::crypto;
use super::types::{
    CombinedSignature, CombinedSignatureBytes, IndividualSignature, IndividualSignatureBytes, Pop,
    PopBytes, PublicKey, PublicKeyBytes, SecretKey, SecretKeyBytes,
};
use ic_types::crypto::{AlgorithmId, CryptoError};
use rand::{CryptoRng, Rng};
use std::convert::TryFrom;

#[cfg(test)]
mod tests;

/// Generates a keypair using the given `rng`.
pub fn keypair_from_rng<R: Rng + CryptoRng>(rng: &mut R) -> (SecretKeyBytes, PublicKeyBytes) {
    let (secret_key, public_key) = crypto::keypair_from_rng(rng);
    (
        SecretKeyBytes::from(&secret_key),
        PublicKeyBytes::from(&public_key),
    )
}

/// Generates a multisignature on the given `message` using the given
/// `secret_key`.
///
/// Note: This hashes the message to be signed.  If we pre-hash, the hashing
/// can be skipped. https://docs.rs/threshold_crypto/0.3.2/threshold_crypto/struct.SecretKey.html#method.sign
pub fn sign(message: &[u8], secret_key: &SecretKeyBytes) -> IndividualSignatureBytes {
    let signature = crypto::sign_message(message, &SecretKey::from(secret_key));
    IndividualSignatureBytes::from(&signature)
}

/// Creates a proof of possession (PoP) of `secret_key_bytes`.
///
/// The PoP is a (domain-separated) signature on `public_key_bytes`.
///
/// # Errors
/// * `CryptoError::MalformedPublicKey` if `public_key_bytes` cannot be parsed
///   as a valid G2 point.
pub fn create_pop(
    public_key_bytes: &PublicKeyBytes,
    secret_key_bytes: &SecretKeyBytes,
) -> Result<PopBytes, CryptoError> {
    let public_key = PublicKey::try_from(public_key_bytes)?;
    let pop = crypto::create_pop(&public_key, &SecretKey::from(secret_key_bytes));
    Ok(PopBytes::from(&pop))
}

/// Verifies a public key's proof of possession (PoP).
///
/// As part of the PoP verification, it is also verified that the
/// public key is a point on the curve and in the right subgroup.
///
/// # Errors
/// * `CryptoError::MalformedPop` if `pop_bytes` cannot be parsed as a valid G1
///   point.
/// * `CryptoError::MalformedPublicKey` if `public_key_bytes` cannot be parsed
///   as a valid G2 point.
/// * `CryptoError::PopVerification` if the given PoP fails to verify.
pub fn verify_pop(
    pop_bytes: &PopBytes,
    public_key_bytes: &PublicKeyBytes,
) -> Result<(), CryptoError> {
    let pop = Pop::try_from(pop_bytes)?;
    let public_key = PublicKey::try_from(public_key_bytes)?;
    if crypto::verify_pop(&pop, &public_key) {
        Ok(())
    } else {
        Err(CryptoError::PopVerification {
            algorithm: AlgorithmId::MultiBls12_381,
            public_key_bytes: public_key_bytes.0.to_vec(),
            pop_bytes: pop_bytes.0.to_vec(),
            internal_error: "PoP verification failed".to_string(),
        })
    }
}

/// Combines individual signatures into a multisignature.
///
/// # Errors
/// * `CryptoError::MalformedSignature` if any of the `signatures` cannot be
///   parsed as a G1 point.
pub fn combine(
    signatures: &[IndividualSignatureBytes],
) -> Result<CombinedSignatureBytes, CryptoError> {
    let signatures: Result<Vec<IndividualSignature>, CryptoError> = signatures
        .iter()
        .map(IndividualSignature::try_from)
        .collect();
    let signature = crypto::combine_signatures(&signatures?);
    Ok(CombinedSignatureBytes::from(&signature))
}

fn key_from_bytes_with_cache(public_key_bytes: &PublicKeyBytes) -> Result<PublicKey, CryptoError> {
    // This can't be defined on PublicKey because it is just a typedef for G2Projective at the moment
    ic_crypto_internal_bls12_381_type::G2Affine::deserialize_cached(&public_key_bytes.0)
        .map_err(|_| CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::MultiBls12_381,
            key_bytes: Some(public_key_bytes.0.to_vec()),
            internal_error: "Point decoding failed".to_string(),
        })
}

/// Verifies an individual signature over the given `message` using the given
/// `public_key_bytes`.
///
/// # Errors
/// * `CryptoError::MalformedSignature` if `signature_bytes` cannot be parsed as
///   a G1 point.
/// * `CryptoError::MalformedPublicKey` if `public_key_bytes` cannot be parsed
///   as a valid G2 point.
/// * `CryptoError::SignatureVerification` if verification of the signature
///   fails.
pub fn verify_individual(
    message: &[u8],
    signature_bytes: &IndividualSignatureBytes,
    public_key_bytes: &PublicKeyBytes,
) -> Result<(), CryptoError> {
    let signature = IndividualSignature::try_from(signature_bytes)?;
    let public_key = key_from_bytes_with_cache(public_key_bytes)?;

    if crypto::verify_individual_message_signature(message, &signature, &public_key) {
        Ok(())
    } else {
        Err(CryptoError::SignatureVerification {
            algorithm: AlgorithmId::MultiBls12_381,
            public_key_bytes: public_key_bytes.0.to_vec(),
            sig_bytes: signature_bytes.0.to_vec(),
            internal_error: "Verification of individual contribution to multisignature failed"
                .to_string(),
        })
    }
}

/// Verifies a combined multisignature over the given `message` using the given
/// array of `public_keys`.
///
/// # Errors
/// * `CryptoError::MalformedSignature` if the `signature` cannot be parsed as a
///   G1 point.
/// * `CryptoError::MalformedPublicKey` if any of the `public_keys` cannot be
///   parsed as a valid G2 point.
/// * `CryptoError::SignatureVerification` if verification of the signature
///   fails.
pub fn verify_combined(
    message: &[u8],
    signature: &CombinedSignatureBytes,
    public_keys: &[PublicKeyBytes],
) -> Result<(), CryptoError> {
    let public_keys: Result<Vec<PublicKey>, CryptoError> =
        public_keys.iter().map(key_from_bytes_with_cache).collect();
    if crypto::verify_combined_message_signature(
        message,
        &CombinedSignature::try_from(signature)?,
        &public_keys?[..],
    ) {
        Ok(())
    } else {
        Err(CryptoError::SignatureVerification {
            algorithm: AlgorithmId::MultiBls12_381,
            public_key_bytes: Vec::new(),
            sig_bytes: signature.0.to_vec(),
            internal_error: "Verification of multisignature failed".to_string(),
        })
    }
}
