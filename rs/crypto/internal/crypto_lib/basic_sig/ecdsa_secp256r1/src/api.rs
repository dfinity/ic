//! ECDSA signature methods
use super::types;
use ic_crypto_internal_basic_sig_der_utils::PkixAlgorithmIdentifier;
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult};
use simple_asn1::oid;

/// Return the algorithm identifier associated with ECDSA P-256
pub fn algorithm_identifier() -> PkixAlgorithmIdentifier {
    PkixAlgorithmIdentifier::new_with_oid_param(
        oid!(1, 2, 840, 10045, 2, 1),
        oid!(1, 2, 840, 10045, 3, 1, 7),
    )
}

/// Parse a secp256r1 public key from the DER enncoding
///
/// # Arguments
/// * `pk_der` is the binary DER encoding of the public key
/// # Errors
/// * `MalformedPublicKey` if the public key could not be parsed or is not canonical
/// # Returns
/// The decoded public key
pub fn public_key_from_der(pk_der: &[u8]) -> CryptoResult<types::PublicKeyBytes> {
    let pkey = ic_secp256r1::PublicKey::deserialize_der(pk_der).map_err(|e| {
        CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::EcdsaP256,
            key_bytes: Some(pk_der.to_vec()),
            internal_error: format!("{e:?}"),
        }
    })?;

    // Check pk_der is in canonical form (uncompressed).
    if pkey.serialize_der() != pk_der {
        return Err(CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::EcdsaP256,
            key_bytes: Some(pk_der.to_vec()),
            internal_error: "non-canonical encoding".to_string(),
        });
    }

    let pk_bytes = pkey.serialize_sec1(false);
    Ok(types::PublicKeyBytes::from(pk_bytes))
}

/// Parse a secp256r1 public key from the x/y affine coordinates
///
/// # Arguments
/// * `x` the x coordinate of the public point
/// * `y` the y coordinate of the public point
/// # Errors
/// * `MalformedPublicKey` if the public key could not be parsed
/// # Returns
/// The DER encoding of the public key
pub fn der_encoding_from_xy_coordinates(x: &[u8], y: &[u8]) -> CryptoResult<Vec<u8>> {
    if x.len() > types::FIELD_SIZE {
        return Err(CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::EcdsaP256,
            key_bytes: Some(x.to_vec()),
            internal_error: "ECDSA x coordinate is too large".to_string(),
        });
    }

    if y.len() > types::FIELD_SIZE {
        return Err(CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::EcdsaP256,
            key_bytes: Some(y.to_vec()),
            internal_error: "ECDSA y coordinate is too large".to_string(),
        });
    }

    let mut bytes = Vec::with_capacity(1 + 2 * types::FIELD_SIZE);
    bytes.extend_from_slice(&[0x04]); // uncompressed

    // apply zero padding for x if necessary
    for _i in x.len()..types::FIELD_SIZE {
        bytes.push(0x00);
    }
    bytes.extend_from_slice(x);

    // apply zero padding for y if necessary
    for _i in y.len()..types::FIELD_SIZE {
        bytes.push(0x00);
    }
    bytes.extend_from_slice(y);
    let bytes = types::PublicKeyBytes(bytes);
    public_key_to_der(&bytes)
}

fn public_key_to_der(pk: &types::PublicKeyBytes) -> CryptoResult<Vec<u8>> {
    let pkey = ic_secp256r1::PublicKey::deserialize_sec1(&pk.0).map_err(|e| {
        CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::EcdsaP256,
            key_bytes: Some(pk.0.to_vec()),
            internal_error: format!("{e:?}"),
        }
    })?;

    Ok(pkey.serialize_der())
}

/// Decode an ECDSA signature from the DER encoding
///
/// # Arguments
/// `sig_der` the DER encoded signature, as a pair of integers (r,s)
/// # Errors
/// * `MalformedSignature` if the data could not be decoded as a DER ECDSA
///   signature
pub fn signature_from_der(sig_der: &[u8]) -> CryptoResult<types::SignatureBytes> {
    let sig =
        p256::ecdsa::Signature::from_der(sig_der).map_err(|e| CryptoError::MalformedSignature {
            algorithm: AlgorithmId::EcdsaP256,
            sig_bytes: sig_der.to_vec(),
            internal_error: format!("Error parsing DER signature: {e}"),
        })?;

    let sig_bytes: [u8; 64] = sig.to_bytes().into();
    Ok(types::SignatureBytes(sig_bytes))
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
