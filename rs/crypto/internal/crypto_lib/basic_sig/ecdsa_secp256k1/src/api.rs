//! ECDSA signature methods
use super::types;
use ic_crypto_internal_basic_sig_der_utils::PkixAlgorithmIdentifier;
use ic_crypto_secrets_containers::SecretVec;
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult};
use simple_asn1::oid;

/// Return the algorithm identifier associated with ECDSA secp256k1
pub fn algorithm_identifier() -> PkixAlgorithmIdentifier {
    PkixAlgorithmIdentifier::new_with_oid_param(
        oid!(1, 2, 840, 10045, 2, 1),
        oid!(1, 3, 132, 0, 10),
    )
}

/// Create a secp256k1 secret key from raw bytes
///
/// # Arguments
/// * `sk_raw_bytes` is the big-endian encoding of unsigned integer
/// * `pk` is the public key associated with this secret key
/// # Errors
/// * `MalformedPublicKey` if the public key could not be parsed
/// * `MalformedSecretKey` if the secret key does not correspond with the public
///   key
pub fn secret_key_from_components(
    sk_raw_bytes: &[u8],
    pk: &types::PublicKeyBytes,
) -> CryptoResult<types::SecretKeyBytes> {
    let sk = ic_secp256k1::PrivateKey::deserialize_sec1(sk_raw_bytes).map_err(|e| {
        CryptoError::MalformedSecretKey {
            algorithm: AlgorithmId::EcdsaSecp256k1,
            internal_error: format!("{e:?}"),
        }
    })?;

    if pk.0 != sk.public_key().serialize_sec1(false) {
        return Err(CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::EcdsaSecp256k1,
            key_bytes: Some(pk.0.to_vec()),
            internal_error: "Public key does not match secret key".to_string(),
        });
    }

    let mut sk_rfc5915 = sk.serialize_rfc5915_der();

    Ok(types::SecretKeyBytes(SecretVec::new_and_zeroize_argument(
        &mut sk_rfc5915,
    )))
}

/// Parse a secp256k1 public key from the DER enncoding
///
/// # Arguments
/// * `pk_der` is the binary DER encoding of the public key
/// # Errors
/// * `MalformedPublicKey` if the public key could not be parsed
/// # Returns
/// The decoded public key
pub fn public_key_from_der(pk_der: &[u8]) -> CryptoResult<types::PublicKeyBytes> {
    let pkey = ic_secp256k1::PublicKey::deserialize_der(pk_der).map_err(|e| {
        CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::EcdsaSecp256k1,
            key_bytes: Some(pk_der.to_vec()),
            internal_error: format!("{e:?}"),
        }
    })?;

    let pk_bytes = pkey.serialize_sec1(false);

    // Check pk_der is in canonical form (uncompressed).

    if pkey.serialize_der() != pk_der {
        return Err(CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::EcdsaSecp256k1,
            key_bytes: Some(pk_der.to_vec()),
            internal_error: "non-canonical encoding".to_string(),
        });
    }
    Ok(types::PublicKeyBytes::from(pk_bytes))
}

/// Encode a secp256k1 public key to the DER encoding
///
/// # Arguments
/// * `pk` is the public key
/// # Errors
/// * `MalformedPublicKey` if the public key seems to be invalid
/// # Returns
/// The encoded public key
pub fn public_key_to_der(pk: &types::PublicKeyBytes) -> CryptoResult<Vec<u8>> {
    let pkey = ic_secp256k1::PublicKey::deserialize_sec1(&pk.0).map_err(|e| {
        CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::EcdsaSecp256k1,
            key_bytes: Some(pk.0.to_vec()),
            internal_error: format!("{e:?}"),
        }
    })?;

    Ok(pkey.serialize_der())
}

/// Sign a message using a secp256k1 private key
///
/// # Arguments
/// * `msg` is the message digest to be signed
/// * `sk` is the private key
/// # Errors
/// * `InvalidArgument` if the digest is too small
/// * `MalformedSecretKey` if the private key seems to be invalid
/// # Returns
/// The generated signature
pub fn sign(msg: &[u8], sk: &types::SecretKeyBytes) -> CryptoResult<types::SignatureBytes> {
    let signing_key = ic_secp256k1::PrivateKey::deserialize_rfc5915_der(sk.0.expose_secret())
        .map_err(|_| {
            CryptoError::MalformedSecretKey {
                algorithm: AlgorithmId::EcdsaSecp256k1,
                internal_error: "Error deserializing key".to_string(), // don't leak sensitive information
            }
        })?;

    let sig_bytes = signing_key.sign_digest_with_ecdsa(msg);
    Ok(types::SignatureBytes(sig_bytes))
}

/// Verify a signature using a secp256k1 public key
///
/// # Arguments
/// * `sig` is the signature to be verified
/// * `msg` is the message digest
/// * `pk` is the public key
/// # Errors
/// * `MalformedPublicKey` if the public key seems to be invalid
/// * `SignatureVerification` if the signature could not be verified
/// # Returns
/// `Ok(())` if the signature validated, or an error otherwise
pub fn verify(
    sig: &types::SignatureBytes,
    msg: &[u8],
    pk: &types::PublicKeyBytes,
) -> CryptoResult<()> {
    let pubkey = ic_secp256k1::PublicKey::deserialize_sec1(&pk.0).map_err(|e| {
        CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::EcdsaSecp256k1,
            key_bytes: Some(pk.0.to_vec()),
            internal_error: format!("{e:?}"),
        }
    })?;

    // Previously this crate was implemented using OpenSSL, which does not
    // check s-normalization, so we use the malleable verification here
    match pubkey.verify_ecdsa_signature_prehashed_with_malleability(msg, &sig.0) {
        true => Ok(()),
        false => Err(CryptoError::SignatureVerification {
            algorithm: AlgorithmId::EcdsaSecp256k1,
            public_key_bytes: pk.0.to_vec(),
            sig_bytes: sig.0.to_vec(),
            internal_error: "verification failed".to_string(),
        }),
    }
}
