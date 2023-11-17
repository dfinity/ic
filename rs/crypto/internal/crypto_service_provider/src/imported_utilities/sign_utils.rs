//! Signature utilities
use ic_crypto_internal_threshold_sig_bls12381 as bls12_381;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes as BlsPublicKeyBytes;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use ic_types::crypto::CryptoResult;

/// Encodes a threshold signature public key into DER.
///
/// # Errors
/// * `CryptoError::MalformedPublicKey`: if the public cannot be DER encoded.
pub fn threshold_sig_public_key_to_der(pk: ThresholdSigPublicKey) -> CryptoResult<Vec<u8>> {
    // TODO(CRP-641): add a check that the key is indeed a BLS key.
    let pk = BlsPublicKeyBytes(pk.into_bytes());
    bls12_381::api::public_key_to_der(pk)
}

/// Decodes a threshold signature public key from DER.
///
/// # Errors
/// * `CryptoError::MalformedPublicKey`: if the public cannot be DER decoded.
pub fn threshold_sig_public_key_from_der(bytes: &[u8]) -> CryptoResult<ThresholdSigPublicKey> {
    let pk = bls12_381::api::public_key_from_der(bytes)?;
    Ok(pk.into())
}
