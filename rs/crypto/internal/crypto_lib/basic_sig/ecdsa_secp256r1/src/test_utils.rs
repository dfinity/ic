use super::types;
use crate::wrap_openssl_err;
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};

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
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let (sk, pk) = {
        let sk = p256::ecdsa::SigningKey::random(rng);
        let encoded_pk = p256::PublicKey::from(&sk.verifying_key()).to_encoded_point(false);
        let serialized_pk: [u8; 65] = encoded_pk
            .as_bytes()
            .try_into()
            .expect("public key with incorrect length");
        (sk.to_bytes(), serialized_pk)
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
/// * `AlgorithmNotSupported` if an error occurred while invoking OpenSSL
/// * `MalformedPublicKey` if the public key could not be parsed
/// * `MalformedSecretKey` if the secret key does not correspond with the public
///   key
fn secret_key_from_components(
    sk_raw_bytes: &[u8],
    pk: &types::PublicKeyBytes,
) -> CryptoResult<types::SecretKeyBytes> {
    use ic_crypto_secrets_containers::SecretVec;
    let group = EcGroup::from_curve_name(crate::CURVE_NAME)
        .map_err(|e| wrap_openssl_err(e, "unable to create EC group"))?;
    let private_number = BigNum::from_slice(sk_raw_bytes)
        .map_err(|e| wrap_openssl_err(e, "unable to parse big integer"))?;
    let mut ctx = BigNumContext::new()
        .map_err(|e| crate::wrap_openssl_err(e, "unable to create BigNumContext"))?;
    let public_point = EcPoint::from_bytes(&group, &pk.0, &mut ctx).map_err(|e| {
        CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::EcdsaP256,
            key_bytes: Some(pk.0.to_vec()),
            internal_error: e.to_string(),
        }
    })?;
    let ec_key =
        EcKey::from_private_components(&group, &private_number, &public_point).map_err(|_| {
            CryptoError::MalformedSecretKey {
                algorithm: AlgorithmId::EcdsaP256,
                internal_error: "OpenSSL error".to_string(), // don't leak sensitive information
            }
        })?;
    let mut sk_der =
        ec_key
            .private_key_to_der()
            .map_err(|e| CryptoError::AlgorithmNotSupported {
                algorithm: AlgorithmId::EcdsaP256,
                reason: format!("OpenSSL failed with error {}", e),
            })?;
    Ok(types::SecretKeyBytes(SecretVec::new_and_zeroize_argument(
        &mut sk_der,
    )))
}
