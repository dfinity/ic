//! ECDSA signature methods
use super::types;
use ic_crypto_internal_basic_sig_der_utils::PkixAlgorithmIdentifier;
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use simple_asn1::oid;

#[cfg(test)]
mod tests;

/// Return the algorithm identifier associated with ECDSA P-256
pub fn algorithm_identifier() -> PkixAlgorithmIdentifier {
    PkixAlgorithmIdentifier::new_with_oid_param(
        oid!(1, 2, 840, 10045, 2, 1),
        oid!(1, 2, 840, 10045, 3, 1, 7),
    )
}

// NOTE: prime256v1 is a yet another name for secp256r1 (aka. NIST P-256),
// cf. https://tools.ietf.org/html/rfc5480
const CURVE_NAME: Nid = Nid::X9_62_PRIME256V1;

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
/// # Returns
/// A tuple of the secret key bytes and public key bytes
pub fn new_keypair() -> CryptoResult<(types::SecretKeyBytes, types::PublicKeyBytes)> {
    let group = EcGroup::from_curve_name(CURVE_NAME)
        .map_err(|e| wrap_openssl_err(e, "unable to create EC group"))?;
    let ec_key =
        EcKey::generate(&group).map_err(|e| wrap_openssl_err(e, "unable to generate EC key"))?;
    let mut ctx =
        BigNumContext::new().map_err(|e| wrap_openssl_err(e, "unable to create BigNumContext"))?;
    let sk_der = ec_key
        .private_key_to_der()
        .map_err(|e| CryptoError::AlgorithmNotSupported {
            algorithm: AlgorithmId::EcdsaP256,
            reason: format!("OpenSSL failed with error {}", e.to_string()),
        })?;
    let sk = types::SecretKeyBytes::from(sk_der);
    let pk_bytes = ec_key
        .public_key()
        .to_bytes(
            &group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )
        .map_err(|e| wrap_openssl_err(e, "unable to serialize EC public key"))?;
    let pk = types::PublicKeyBytes::from(pk_bytes);
    Ok((sk, pk))
}

/// Parse a secp256r1 public key from the DER enncoding
///
/// # Arguments
/// * `pk_der` is the binary DER encoding of the public key
/// # Errors
/// * `AlgorithmNotSupported` if an error occured while invoking OpenSSL
/// * `MalformedPublicKey` if the public key could not be parsed
/// # Returns
/// The decoded public key
pub fn public_key_from_der(pk_der: &[u8]) -> CryptoResult<types::PublicKeyBytes> {
    let pkey = PKey::public_key_from_der(pk_der).map_err(|e| CryptoError::MalformedPublicKey {
        algorithm: AlgorithmId::EcdsaP256,
        key_bytes: Some(Vec::from(pk_der)),
        internal_error: e.to_string(),
    })?;
    let ec_key = pkey.ec_key().map_err(|e| CryptoError::MalformedPublicKey {
        algorithm: AlgorithmId::EcdsaP256,
        key_bytes: Some(Vec::from(pk_der)),
        internal_error: e.to_string(),
    })?;
    let mut ctx =
        BigNumContext::new().map_err(|e| wrap_openssl_err(e, "unable to create BigNumContext"))?;
    let group = EcGroup::from_curve_name(CURVE_NAME)
        .map_err(|e| wrap_openssl_err(e, "unable to create EC group"))?;
    let pk_bytes = ec_key
        .public_key()
        .to_bytes(
            &group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )
        .map_err(|e| CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::EcdsaP256,
            key_bytes: Some(Vec::from(pk_der)),
            internal_error: e.to_string(),
        })?;
    // Check pk_der is in canonical form (uncompressed).
    let canon =
        public_key_to_der(&types::PublicKeyBytes::from(pk_bytes.clone())).map_err(|_e| {
            CryptoError::MalformedPublicKey {
                algorithm: AlgorithmId::EcdsaP256,
                key_bytes: Some(Vec::from(pk_der)),
                internal_error: "cannot encode decoded key".to_string(),
            }
        })?;
    if canon != pk_der {
        return Err(CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::EcdsaP256,
            key_bytes: Some(Vec::from(pk_der)),
            internal_error: "non-canonical encoding".to_string(),
        });
    }
    Ok(types::PublicKeyBytes::from(pk_bytes))
}

/// Parse a secp256r1 public key from the x/y affine coordinates
///
/// # Arguments
/// * `x` the x coordinate of the public point
/// * `y` the y coordinate of the public point
/// # Errors
/// * `AlgorithmNotSupported` if an error occured while invoking OpenSSL
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
    let group = EcGroup::from_curve_name(CURVE_NAME)
        .map_err(|e| wrap_openssl_err(e, "unable to create EC group"))?;
    let mut ctx =
        BigNumContext::new().map_err(|e| wrap_openssl_err(e, "unable to create BigNumContext"))?;
    let point = EcPoint::from_bytes(&group, &pk.0, &mut ctx).map_err(|e| {
        CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::EcdsaP256,
            key_bytes: Some(pk.0.to_vec()),
            internal_error: e.to_string(),
        }
    })?;
    let ec_pk =
        EcKey::from_public_key(&group, &point).map_err(|e| CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::EcdsaP256,
            key_bytes: Some(pk.0.to_vec()),
            internal_error: e.to_string(),
        })?;
    ec_pk
        .public_key_to_der()
        .map_err(|e| CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::EcdsaP256,
            key_bytes: Some(pk.0.to_vec()),
            internal_error: e.to_string(),
        })
}

/// Decode an ECDSA signature from the DER encoding
///
/// # Arguments
/// `sig_der` the DER encoded signature, as a pair of integers (r,s)
/// # Errors
/// * `MalformedSignature` if the data could not be decoded as a DER ECDSA
///   signature
pub fn signature_from_der(sig_der: &[u8]) -> CryptoResult<types::SignatureBytes> {
    let ecdsa_sig = EcdsaSig::from_der(sig_der).map_err(|e| CryptoError::MalformedSignature {
        algorithm: AlgorithmId::EcdsaP256,
        sig_bytes: sig_der.to_vec(),
        internal_error: format!("Error parsing DER signature: {}", e.to_string()),
    })?;
    let sig_bytes = ecdsa_sig_to_bytes(ecdsa_sig)?;
    Ok(types::SignatureBytes(sig_bytes))
}

// Returns `ecdsa_sig` as an array of exactly types::SignatureBytes::SIZE bytes.
fn ecdsa_sig_to_bytes(ecdsa_sig: EcdsaSig) -> CryptoResult<[u8; types::SignatureBytes::SIZE]> {
    let r = ecdsa_sig.r().to_vec();
    let s = ecdsa_sig.s().to_vec();
    if r.len() > types::FIELD_SIZE || s.len() > types::FIELD_SIZE {
        return Err(CryptoError::MalformedSignature {
            algorithm: AlgorithmId::EcdsaP256,
            sig_bytes: ecdsa_sig
                .to_der()
                .map_err(|e| wrap_openssl_err(e, "unable to export ECDSA sig to DER format"))?,
            internal_error: "r or s is too long".to_string(),
        });
    }

    let mut bytes = [0; types::SignatureBytes::SIZE];
    // Account for leading zeros.
    bytes[(types::FIELD_SIZE - r.len())..types::FIELD_SIZE].clone_from_slice(&r);
    bytes[(types::SignatureBytes::SIZE - s.len())..types::SignatureBytes::SIZE]
        .clone_from_slice(&s);
    Ok(bytes)
}

/// Sign a message using a secp256r1 private key
///
/// # Arguments
/// * `msg` is the message to be signed
/// * `sk` is the private key
/// # Errors
/// * `InvalidArgument` if signature generation failed
/// * `MalformedSecretKey` if the private key seems to be invalid
/// * `MalformedSignature` if OpenSSL generates an invalid signature
/// # Returns
/// The generated signature
pub fn sign(msg: &[u8], sk: &types::SecretKeyBytes) -> CryptoResult<types::SignatureBytes> {
    let signing_key =
        EcKey::private_key_from_der(&sk.0).map_err(|_| CryptoError::MalformedSecretKey {
            algorithm: AlgorithmId::EcdsaP256,
            internal_error: "OpenSSL error".to_string(), // don't leak sensitive information
        })?;
    let ecdsa_sig =
        EcdsaSig::sign(msg, &signing_key).map_err(|e| CryptoError::InvalidArgument {
            message: format!("ECDSA signing failed with error {}", e),
        })?;
    let sig_bytes = ecdsa_sig_to_bytes(ecdsa_sig)?;
    Ok(types::SignatureBytes(sig_bytes))
}

// Extracts 'r' and 's' parts of a signature from `SignatureBytes'
fn r_s_from_sig_bytes(sig_bytes: &types::SignatureBytes) -> CryptoResult<(BigNum, BigNum)> {
    if sig_bytes.0.len() != types::SignatureBytes::SIZE {
        return Err(CryptoError::MalformedSignature {
            algorithm: AlgorithmId::EcdsaP256,
            sig_bytes: sig_bytes.0.to_vec(),
            internal_error: format!(
                "Expected {} bytes, got {}",
                types::SignatureBytes::SIZE,
                sig_bytes.0.len()
            ),
        });
    }
    let r = BigNum::from_slice(&sig_bytes.0[0..types::FIELD_SIZE]).map_err(|e| {
        CryptoError::MalformedSignature {
            algorithm: AlgorithmId::EcdsaP256,
            sig_bytes: sig_bytes.0.to_vec(),
            internal_error: format!("Error parsing r: {}", e.to_string()),
        }
    })?;
    let s = BigNum::from_slice(&sig_bytes.0[types::FIELD_SIZE..]).map_err(|e| {
        CryptoError::MalformedSignature {
            algorithm: AlgorithmId::EcdsaP256,
            sig_bytes: sig_bytes.0.to_vec(),
            internal_error: format!("Error parsing s: {}", e.to_string()),
        }
    })?;
    Ok((r, s))
}

/// Verify a signature using a secp256r1 public key
///
/// # Arguments
/// * `sig` is the signature to be verified
/// * `msg` is the message
/// * `pk` is the public key
/// # Errors
/// * `MalformedSignature` if the signature could not be parsed
/// * `AlgorithmNotSupported` if an error occurred while invoking OpenSSL
/// * `MalformedPublicKey` if the public key could not be parsed
/// * `SignatureVerification` if the signature could not be verified
/// # Returns
/// `Ok(())` if the signature validated, or an error otherwise
pub fn verify(
    sig: &types::SignatureBytes,
    msg: &[u8],
    pk: &types::PublicKeyBytes,
) -> CryptoResult<()> {
    let (r, s) = r_s_from_sig_bytes(sig)?;
    let ecdsa_sig =
        EcdsaSig::from_private_components(r, s).map_err(|e| CryptoError::MalformedSignature {
            algorithm: AlgorithmId::EcdsaP256,
            sig_bytes: sig.0.to_vec(),
            internal_error: e.to_string(),
        })?;
    let group = EcGroup::from_curve_name(CURVE_NAME)
        .map_err(|e| wrap_openssl_err(e, "unable to create EC group"))?;
    let mut ctx =
        BigNumContext::new().map_err(|e| wrap_openssl_err(e, "unable to create BigNumContext"))?;
    let point = EcPoint::from_bytes(&group, &pk.0, &mut ctx).map_err(|e| {
        CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::EcdsaP256,
            key_bytes: Some(pk.0.to_vec()),
            internal_error: e.to_string(),
        }
    })?;
    let ec_pk =
        EcKey::from_public_key(&group, &point).map_err(|e| CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::EcdsaP256,
            key_bytes: Some(pk.0.to_vec()),
            internal_error: e.to_string(),
        })?;
    let verified =
        ecdsa_sig
            .verify(msg, &ec_pk)
            .map_err(|e| CryptoError::SignatureVerification {
                algorithm: AlgorithmId::EcdsaP256,
                public_key_bytes: pk.0.to_vec(),
                sig_bytes: sig.0.to_vec(),
                internal_error: e.to_string(),
            })?;
    if verified {
        Ok(())
    } else {
        Err(CryptoError::SignatureVerification {
            algorithm: AlgorithmId::EcdsaP256,
            public_key_bytes: pk.0.to_vec(),
            sig_bytes: sig.0.to_vec(),
            internal_error: "verification failed".to_string(),
        })
    }
}

fn wrap_openssl_err(e: openssl::error::ErrorStack, err_msg: &str) -> CryptoError {
    CryptoError::AlgorithmNotSupported {
        algorithm: AlgorithmId::EcdsaP256,
        reason: format!("{}: OpenSSL failed with error {}", err_msg, e.to_string()),
    }
}
