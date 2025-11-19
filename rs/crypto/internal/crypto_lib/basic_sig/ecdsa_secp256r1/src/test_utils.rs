use super::types;
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult};

// NOTE: both `new_keypair()` and `sign()` are exposed as public but
// are not used in production. They are exposed due to requirements on
// how the tests are structured. This should be resolved.
//
// For the same reason the majority of tests is using signature verification
// test vectors (addition of test vectors for signature creation is more
// involved as Rust OpenSSL API doesn't seem to provide a way for
// "de-randomization" of signing operation).

/// Create a new secp256r1 keypair. This function should only be used for
/// testing.
///
/// # Errors
/// * `AlgorithmNotSupported` if an error occurs while generating the key
/// * `MalformedPublicKey` if the public key could not be parsed
/// * `MalformedSecretKey` if the secret key does not correspond with the public
///   key
/// # Returns
/// A tuple of the secret key bytes and public key bytes
pub fn new_keypair(
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> CryptoResult<(types::SecretKeyBytes, types::PublicKeyBytes)> {
    let (sk, pk) = {
        let sk = ic_secp256r1::PrivateKey::generate_using_rng(rng);
        let encoded_pk = sk.public_key().serialize_sec1(false);
        let serialized_pk: [u8; 65] = encoded_pk
            .try_into()
            .expect("public key with incorrect length");
        (sk.serialize_sec1(), serialized_pk)
    };

    let pk_bytes = crate::types::PublicKeyBytes::from(pk.to_vec());
    let sk_bytes = secret_key_from_components(&sk, &pk_bytes)?;

    Ok((sk_bytes, pk_bytes))
}

/// Create a secp256r1 secret key from raw bytes
///
/// # Arguments
/// * `sk_raw_bytes` is the big-endian encoding of unsigned integer
/// * `pk` is the public key associated with this secret key
/// # Errors
/// * `MalformedPublicKey` if the public key could not be parsed
/// * `MalformedSecretKey` if the secret key does not correspond with the public
///   key
fn secret_key_from_components(
    sk_raw_bytes: &[u8],
    pk: &types::PublicKeyBytes,
) -> CryptoResult<types::SecretKeyBytes> {
    use ic_crypto_secrets_containers::SecretVec;

    let sk = ic_secp256r1::PrivateKey::deserialize_sec1(sk_raw_bytes).map_err(|e| {
        CryptoError::MalformedSecretKey {
            algorithm: AlgorithmId::EcdsaP256,
            internal_error: format!("{e:?}"),
        }
    })?;

    if pk.0 != sk.public_key().serialize_sec1(false) {
        return Err(CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::EcdsaP256,
            key_bytes: Some(pk.0.to_vec()),
            internal_error: "Public key does not match secret key".to_string(),
        });
    }

    let mut sk_rfc5915 = sk.serialize_rfc5915_der();

    Ok(types::SecretKeyBytes(SecretVec::new_and_zeroize_argument(
        &mut sk_rfc5915,
    )))
}
