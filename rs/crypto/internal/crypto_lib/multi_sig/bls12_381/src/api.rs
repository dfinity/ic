//! External API for the multisignature library
use super::crypto;
use super::types::{
    CombinedSignatureBytes, IndividualSignature, IndividualSignatureBytes, Pop, PopBytes,
    PublicKey, PublicKeyBytes, SecretKeyBytes,
};
use ic_types::crypto::{AlgorithmId, CryptoError};
use rand::{CryptoRng, Rng};
use std::convert::TryFrom;
use std::convert::TryInto;

#[cfg(test)]
mod tests;

/// Generates a keypair using the given `rng`.
pub fn keypair_from_rng<R: Rng + CryptoRng>(rng: &mut R) -> (SecretKeyBytes, PublicKeyBytes) {
    let (secret_key, public_key) = crypto::keypair_from_rng(rng);
    (secret_key.into(), public_key.into())
}

/// Generates a multisignature on the given `message` using the given
/// `secret_key`.
///
/// Note: This hashes the message to be signed.  If we pre-hash, the hashing
/// can be skipped. https://docs.rs/threshold_crypto/0.3.2/threshold_crypto/struct.SecretKey.html#method.sign
///
/// # Errors
/// This function is not expected to return an error.
pub fn sign(
    message: &[u8],
    secret_key: SecretKeyBytes,
) -> Result<IndividualSignatureBytes, CryptoError> {
    Ok(crypto::sign_message(message, secret_key.into()).into())
}

/// Creates a proof of possession (PoP) of `secret_key_bytes`.
///
/// The PoP is a (domain-separated) signature on `public_key_bytes`.
///
/// # Errors
/// * `CryptoError::MalformedPublicKey` if `public_key_bytes` cannot be parsed
///   as a valid G2 point.
pub fn create_pop(
    public_key_bytes: PublicKeyBytes,
    secret_key_bytes: SecretKeyBytes,
) -> Result<PopBytes, CryptoError> {
    let public_key = public_key_bytes.try_into()?;
    Ok(crypto::create_pop(public_key, secret_key_bytes.into()).into())
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
    pop_bytes: PopBytes,
    public_key_bytes: PublicKeyBytes,
) -> Result<(), CryptoError> {
    let pop = Pop::try_from(pop_bytes)?;
    let public_key = PublicKey::try_from(public_key_bytes)?;
    if crypto::verify_pop(pop, public_key) {
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
        .cloned()
        .map(|signature_bytes| signature_bytes.try_into())
        .collect();
    let signature = crypto::combine_signatures(&signatures?);
    Ok(signature.into())
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
    signature_bytes: IndividualSignatureBytes,
    public_key_bytes: PublicKeyBytes,
) -> Result<(), CryptoError> {
    let signature = signature_bytes.try_into()?;
    let public_key = public_key_bytes.try_into()?;
    if crypto::verify_individual_message_signature(message, signature, public_key) {
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
    signature: CombinedSignatureBytes,
    public_keys: &[PublicKeyBytes],
) -> Result<(), CryptoError> {
    let public_keys: Result<Vec<PublicKey>, CryptoError> =
        public_keys.iter().cloned().map(|x| x.try_into()).collect();
    if crypto::verify_combined_message_signature(message, signature.try_into()?, &public_keys?[..])
    {
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
