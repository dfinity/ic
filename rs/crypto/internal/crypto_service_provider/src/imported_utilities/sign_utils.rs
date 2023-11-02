//! Signature utilities
use crate::types::CspSignature;
use ic_crypto_internal_threshold_sig_bls12381 as bls12_381;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes as BlsPublicKeyBytes;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use ic_types::crypto::{AlgorithmId, CombinedThresholdSigOf, CryptoError, CryptoResult, Signable};
use std::convert::TryFrom;

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

/// Verifies a combined threshold signature.
// TODO(CRP-622): remove this helper once crypto has NNS-verification built in.
#[allow(dead_code)]
pub fn verify_combined_threshold_sig<T: Signable>(
    msg: &T,
    sig: &CombinedThresholdSigOf<T>,
    pk: &ThresholdSigPublicKey,
) -> CryptoResult<()> {
    let bls_pk = BlsPublicKeyBytes(pk.into_bytes());
    let csp_sig = CspSignature::try_from(sig)?;
    if csp_sig.algorithm() != AlgorithmId::ThresBls12_381 {
        return Err(CryptoError::MalformedSignature {
            algorithm: AlgorithmId::ThresBls12_381,
            sig_bytes: vec![],
            internal_error: "Not a ThresBls12_381-signature".to_string(),
        });
    }
    let bls_sig = bls12_381::types::CombinedSignatureBytes::try_from(csp_sig)?;
    bls12_381::api::verify_combined_signature(&msg.as_signed_bytes(), bls_sig, bls_pk)
}
