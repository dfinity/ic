//! ECDSA signature methods
use super::types;
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult};

/// Parse a secp256r1 public key from the DER enncoding
///
/// # Arguments
/// * `pk_der` is the binary DER encoding of the public key
/// # Errors
/// * `MalformedPublicKey` if the public key could not be parsed or is not canonical
/// # Returns
/// The decoded public key
pub fn public_key_from_der(pk_der: &[u8]) -> CryptoResult<types::PublicKeyBytes> {
    let pkey = ic_secp256r1::PublicKey::deserialize_canonical_der(pk_der).map_err(|e| {
        CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::EcdsaP256,
            key_bytes: Some(pk_der.to_vec()),
            internal_error: format!("{e:?}"),
        }
    })?;

    let pk_bytes = pkey.serialize_sec1(false);
    Ok(types::PublicKeyBytes::from(pk_bytes))
}

/// Sign a message using a secp256r1 private key
///
/// # Arguments
/// * `msg` is the message to be signed
/// * `sk` is the private key
/// # Errors
/// * `InvalidArgument` if signature generation failed
/// * `MalformedSecretKey` if the private key seems to be invalid
/// # Returns
/// The generated signature
pub fn sign(msg: &[u8], sk: &types::SecretKeyBytes) -> CryptoResult<types::SignatureBytes> {
    let signing_key = ic_secp256r1::PrivateKey::deserialize_rfc5915_der(sk.0.expose_secret())
        .map_err(|_| {
            CryptoError::MalformedSecretKey {
                algorithm: AlgorithmId::EcdsaP256,
                internal_error: "Error deserializing key".to_string(), // don't leak sensitive information
            }
        })?;

    if let Some(sig_bytes) = signing_key.sign_digest(msg) {
        Ok(types::SignatureBytes(sig_bytes))
    } else {
        Err(CryptoError::InvalidArgument {
            message: format!("Cannot ECDSA sign a digest of {} bytes", msg.len()),
        })
    }
}

/// Verify a signature using a secp256r1 public key
///
/// # Arguments
/// * `sig` is the signature to be verified
/// * `msg` is the message
/// * `pk` is the public key
/// # Errors
/// * `MalformedSignature` if the signature could not be parsed
/// * `MalformedPublicKey` if the public key could not be parsed
/// * `SignatureVerification` if the signature could not be verified
/// # Returns
/// `Ok(())` if the signature validated, or an error otherwise
pub fn verify(
    sig: &types::SignatureBytes,
    msg: &[u8],
    pk: &types::PublicKeyBytes,
) -> CryptoResult<()> {
    let pubkey = ic_secp256r1::PublicKey::deserialize_sec1(&pk.0).map_err(|e| {
        CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::EcdsaP256,
            key_bytes: Some(pk.0.to_vec()),
            internal_error: format!("{e:?}"),
        }
    })?;

    match pubkey.verify_signature_prehashed(msg, &sig.0) {
        true => Ok(()),
        false => Err(CryptoError::SignatureVerification {
            algorithm: AlgorithmId::EcdsaP256,
            public_key_bytes: pk.0.to_vec(),
            sig_bytes: sig.0.to_vec(),
            internal_error: "verification failed".to_string(),
        }),
    }
}
