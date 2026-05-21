//! API for Ed25519 basic signature
use super::types;
use ic_crypto_internal_seed::Seed;
use ic_crypto_secrets_containers::SecretArray;
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult};

#[cfg(test)]
mod tests;

/// Generates an Ed25519 keypair from a seed.
pub fn keypair_from_seed(seed: Seed) -> (types::SecretKeyBytes, types::PublicKeyBytes) {
    let signing_key = ic_ed25519::PrivateKey::generate_using_rng(&mut seed.into_rng());
    let sk = types::SecretKeyBytes(SecretArray::new_and_dont_zeroize_argument(
        &signing_key.serialize_raw(),
    ));
    let pk = types::PublicKeyBytes(signing_key.public_key().serialize_raw());
    (sk, pk)
}

/// Decodes an Ed25519 public key from a DER-encoding according to
/// [RFC 8410, Section 4](https://tools.ietf.org/html/rfc8410#section-4).
///
/// Uses the Ed25519 object identifier (OID) 1.3.101.112 (see [RFC 8410](https://tools.ietf.org/html/rfc8410)).
///
/// # Errors
/// * `MalformedPublicKey` if the input is not a valid DER-encoding according to
///   RFC 8410, or the OID in incorrect, or the key length is incorrect.
pub fn public_key_from_der(pk_der: &[u8]) -> CryptoResult<types::PublicKeyBytes> {
    match ic_ed25519::PublicKey::deserialize_rfc8410_der(pk_der) {
        Ok(pk) => Ok(types::PublicKeyBytes(pk.serialize_raw())),
        Err(e) => Err(CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::Ed25519,
            key_bytes: Some(pk_der.to_vec()),
            internal_error: format!("{:?}", e),
        }),
    }
}

/// Encodes the given `key` as DER-encoded Ed25519 public key according to
/// [RFC 8410, Section 4](https://tools.ietf.org/html/rfc8410#section-4).
///
/// Uses the Ed25519 object identifier (OID) 1.3.101.112 (see [RFC 8410](https://tools.ietf.org/html/rfc8410)).
pub fn public_key_to_der(key: types::PublicKeyBytes) -> Vec<u8> {
    ic_ed25519::PublicKey::convert_raw32_to_der(key.0)
}

/// An error indicating that decoding of a key failed
#[derive(Clone, Debug)]
pub enum KeyDecodingError {
    InvalidEncoding(String),
    InternalError(String),
}

/// Signs a message with an Ed25519 secret key.
///
/// # Errors
/// * `MalformedSecretKey` if the secret key is malformed
pub fn sign(msg: &[u8], sk: &types::SecretKeyBytes) -> types::SignatureBytes {
    let signing_key = ic_ed25519::PrivateKey::deserialize_raw_32(sk.0.expose_secret());
    let signature = signing_key.sign_message(msg);
    types::SignatureBytes(signature)
}

/// Verifies a signature using an Ed25519 public key.
///
/// # Errors
/// * `MalformedPublicKey` if the public key is malformed
/// * `SignatureVerification` if the signature is invalid
/// * `MalformedSignature` if the signature is malformed
pub fn verify(
    sig: &types::SignatureBytes,
    msg: &[u8],
    pk: &types::PublicKeyBytes,
) -> CryptoResult<()> {
    let public_key = ic_ed25519::PublicKey::deserialize_raw(&pk.0).map_err(|e| {
        CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::Ed25519,
            key_bytes: Some(pk.0.to_vec()),
            internal_error: e.to_string(),
        }
    })?;

    public_key
        .verify_signature(msg, &sig.0)
        .map_err(|e| CryptoError::SignatureVerification {
            algorithm: AlgorithmId::Ed25519,
            public_key_bytes: public_key.serialize_raw().to_vec(),
            sig_bytes: sig.0.to_vec(),
            internal_error: e.to_string(),
        })
}

/// Verifies whether the given key is a valid Ed25519 public key.
///
/// This includes checking that the key is a point on the curve and
/// in the right subgroup.
pub fn verify_public_key(pk: &types::PublicKeyBytes) -> bool {
    if let Ok(pk) = ic_ed25519::PublicKey::deserialize_raw(&pk.0) {
        pk.is_torsion_free()
    } else {
        false
    }
}
