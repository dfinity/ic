//! API for Ed25519 basic signature
use super::types;
use ic_crypto_internal_basic_sig_der_utils as der_utils;
use ic_crypto_secrets_containers::SecretArray;
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult};
use rand::{CryptoRng, Rng};
use std::convert::TryFrom;

#[cfg(test)]
mod tests;

/// Generates an Ed25519 keypair.
pub fn keypair_from_rng<R: Rng + CryptoRng>(
    csprng: &mut R,
) -> (types::SecretKeyBytes, types::PublicKeyBytes) {
    let keypair = ed25519_dalek::Keypair::generate(csprng);
    let sk = types::SecretKeyBytes(SecretArray::new_and_dont_zeroize_argument(
        keypair.secret.as_bytes(),
    ));
    let pk = types::PublicKeyBytes(keypair.public.to_bytes());
    (sk, pk)
}

/// The object identifier for Ed25519 public keys
///
/// See [RFC 8410](https://tools.ietf.org/html/rfc8410).
pub fn algorithm_identifier() -> der_utils::PkixAlgorithmIdentifier {
    der_utils::PkixAlgorithmIdentifier::new_with_empty_param(simple_asn1::oid!(1, 3, 101, 112))
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
    let expected_pk_len = 32;
    let pk_bytes = der_utils::parse_public_key(
        pk_der,
        AlgorithmId::Ed25519,
        algorithm_identifier(),
        Some(expected_pk_len),
    )?;
    types::PublicKeyBytes::try_from(&pk_bytes)
}

/// Encodes the given `key` as DER-encoded Ed25519 public key according to
/// [RFC 8410, Section 4](https://tools.ietf.org/html/rfc8410#section-4).
///
/// Uses the Ed25519 object identifier (OID) 1.3.101.112 (see [RFC 8410](https://tools.ietf.org/html/rfc8410)).
pub fn public_key_to_der(key: types::PublicKeyBytes) -> Vec<u8> {
    // Prefixing the following bytes to the key is sufficient to DER-encode it.
    let mut der_pk = vec![
        48, 42, // A sequence of 42 bytes follows.
        48, 5, // An element of 5 bytes follows.
        6, 3, 43, 101, 112, // The OID
        3, 33, // A bitstring of 33 bytes follows.
        0,  // The bitstring (32 bytes) is divisible by 8
    ];
    der_pk.extend_from_slice(&key.0);
    der_pk
}

/// Signs a message with an Ed25519 secret key.
///
/// # Errors
/// * `MalformedSecretKey` if the secret key is malformed
pub fn sign(msg: &[u8], sk: &types::SecretKeyBytes) -> CryptoResult<types::SignatureBytes> {
    use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer};

    let secret = SecretKey::from_bytes(sk.0.expose_secret()).map_err(|_e| {
        CryptoError::MalformedSecretKey {
            algorithm: AlgorithmId::Ed25519,
            internal_error: "dalek_ed25519::SecretKey::from_bytes failed".to_string(),
        }
    })?;
    // TODO (DFN-845): Consider storing pubkey in key store to improve performance
    let public = PublicKey::from(&secret);

    Ok(types::SignatureBytes(
        Keypair { secret, public }.sign(msg).to_bytes(),
    ))
}

/// Verifies a signature using an Ed25519 public key.
///
/// # Errors
/// * `MalformedPublicKey` if the public key is malformed
/// * `SignatureVerification` if the signature is invalid
pub fn verify(
    sig: &types::SignatureBytes,
    msg: &[u8],
    pk: &types::PublicKeyBytes,
) -> CryptoResult<()> {
    use ed25519_dalek::{PublicKey, Signature, Verifier};

    let pk = PublicKey::from_bytes(&pk.0).map_err(|e| CryptoError::MalformedPublicKey {
        algorithm: AlgorithmId::Ed25519,
        key_bytes: Some(pk.0.to_vec()),
        internal_error: e.to_string(),
    })?;
    let sig = Signature::new(sig.0);

    pk.verify(msg, &sig)
        .map_err(|e| CryptoError::SignatureVerification {
            algorithm: AlgorithmId::Ed25519,
            public_key_bytes: pk.as_bytes().to_vec(),
            sig_bytes: sig.to_bytes().to_vec(),
            internal_error: e.to_string(),
        })
}

/// Verifies whether the given key is a valid Ed25519 public key.
///
/// This includes checking that the key is a point on the curve and
/// in the right subgroup.
pub fn verify_public_key(pk: &types::PublicKeyBytes) -> bool {
    match curve25519_dalek::edwards::CompressedEdwardsY(pk.0).decompress() {
        None => false,
        Some(edwards_point) => edwards_point.is_torsion_free(),
    }
}
