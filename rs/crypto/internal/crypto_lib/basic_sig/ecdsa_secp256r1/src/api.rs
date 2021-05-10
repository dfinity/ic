//! ECDSA signature methods
use super::types;
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::pkey::PKey;

#[cfg(test)]
mod tests;

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
    Ok(types::PublicKeyBytes::from(pk_bytes))
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

mod cose {
    use super::*;
    use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    pub enum SignatureAlgorithm {
        ES256,
        ES384,
        ES512,
        PS256,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct PublicKey {
        pub signature_algorithm: SignatureAlgorithm,
        #[serde(with = "serde_bytes")]
        pub key_bytes: Vec<u8>,
    }

    // see https://tools.ietf.org/html/rfc8152 section 8.1
    pub const COSE_PARAM_KTY: serde_cbor::Value = serde_cbor::Value::Integer(1);
    pub const COSE_PARAM_ALG: serde_cbor::Value = serde_cbor::Value::Integer(3);
    pub const COSE_PARAM_KEY_OPS: serde_cbor::Value = serde_cbor::Value::Integer(4);
    pub const COSE_PARAM_EC2_CRV: serde_cbor::Value = serde_cbor::Value::Integer(-1);
    pub const COSE_PARAM_EC2_X: serde_cbor::Value = serde_cbor::Value::Integer(-2);
    pub const COSE_PARAM_EC2_Y: serde_cbor::Value = serde_cbor::Value::Integer(-3);

    pub const COSE_ALG_ES256: serde_cbor::Value = serde_cbor::Value::Integer(-7);
    pub const COSE_KTY_EC2: serde_cbor::Value = serde_cbor::Value::Integer(2);
    pub const COSE_EC2_CRV_P256: serde_cbor::Value = serde_cbor::Value::Integer(1);

    #[derive(Debug)]
    pub struct CoseKeyParts {
        kty: serde_cbor::value::Value,
        alg: serde_cbor::value::Value,
        crv: serde_cbor::value::Value,
        x: serde_cbor::value::Value,
        y: serde_cbor::value::Value,
        maybe_key_ops: Option<serde_cbor::value::Value>,
    }

    pub fn cose_key_parts(
        cbor_value: serde_cbor::value::Value,
        pk_cose: &[u8],
    ) -> CryptoResult<CoseKeyParts> {
        if let serde_cbor::Value::Map(mut cbor_map) = cbor_value {
            let maybe_kty = cbor_map.remove(&COSE_PARAM_KTY);
            let maybe_alg = cbor_map.remove(&COSE_PARAM_ALG);
            let maybe_crv = cbor_map.remove(&COSE_PARAM_EC2_CRV);
            let maybe_x = cbor_map.remove(&COSE_PARAM_EC2_X);
            let maybe_y = cbor_map.remove(&COSE_PARAM_EC2_Y);
            let maybe_key_ops = cbor_map.remove(&COSE_PARAM_KEY_OPS);
            if maybe_kty.is_none()
                || maybe_alg.is_none()
                || maybe_crv.is_none()
                || maybe_x.is_none()
                || maybe_y.is_none()
            {
                return Err(CryptoError::MalformedPublicKey {
                    algorithm: AlgorithmId::EcdsaP256,
                    key_bytes: Some(pk_cose.to_vec()),
                    internal_error: "Missing fields in COSE encoding".to_string(),
                });
            };
            Ok(CoseKeyParts {
                kty: maybe_kty.expect("unexpected None"),
                alg: maybe_alg.expect("unexpected None"),
                crv: maybe_crv.expect("unexpected None"),
                x: maybe_x.expect("unexpected None"),
                y: maybe_y.expect("unexpected None"),
                maybe_key_ops,
            })
        } else {
            Err(CryptoError::MalformedPublicKey {
                algorithm: AlgorithmId::EcdsaP256,
                key_bytes: Some(pk_cose.to_vec()),
                internal_error: "Incorrect COSE encoding".to_string(),
            })
        }
    }

    pub fn verify_parts_and_get_x_y_bytes(
        cose_parts: CoseKeyParts,
        pk_cose: &[u8],
    ) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        if cose_parts.kty != COSE_KTY_EC2
            || cose_parts.alg != COSE_ALG_ES256
            || cose_parts.crv != COSE_EC2_CRV_P256
        {
            return Err(CryptoError::AlgorithmNotSupported {
                algorithm: AlgorithmId::Placeholder,
                reason: format!("Expected COSE ECDSA-P256 public key, got {:?}", cose_parts),
            });
        };
        if let Some(key_ops) = &cose_parts.maybe_key_ops {
            if *key_ops != serde_cbor::Value::Text("verify".to_string()) {
                return Err(CryptoError::AlgorithmNotSupported {
                    algorithm: AlgorithmId::EcdsaP256,
                    reason: format!("Expected key_ops = 'verify', got {:?}", cose_parts),
                });
            }
        }
        match (cose_parts.x, cose_parts.y) {
            (serde_cbor::Value::Bytes(x_bytes), serde_cbor::Value::Bytes(y_bytes)) => {
                Ok((x_bytes, y_bytes))
            }
            _ => Err(CryptoError::MalformedPublicKey {
                algorithm: AlgorithmId::EcdsaP256,
                key_bytes: Some(pk_cose.to_vec()),
                internal_error: "Could not extract x, y coordinates".to_string(),
            }),
        }
    }

    pub fn public_key_bytes(
        x_bytes: &[u8],
        y_bytes: &[u8],
        pk_cose: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let group = EcGroup::from_curve_name(CURVE_NAME)
            .map_err(|e| wrap_openssl_err(e, "unable to create EC group"))?;
        let x_num = BigNum::from_slice(x_bytes).map_err(|e| CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::EcdsaP256,
            key_bytes: Some(pk_cose.to_vec()),
            internal_error: format!("Error parsing x: {}", e.to_string()),
        })?;
        let y_num = BigNum::from_slice(y_bytes).map_err(|e| CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::EcdsaP256,
            key_bytes: Some(pk_cose.to_vec()),
            internal_error: format!("Error parsing y: {}", e.to_string()),
        })?;
        let ec_key =
            EcKey::from_public_key_affine_coordinates(&group, &x_num, &y_num).map_err(|e| {
                CryptoError::MalformedPublicKey {
                    algorithm: AlgorithmId::EcdsaP256,
                    key_bytes: Some(pk_cose.to_vec()),
                    internal_error: format!("Incorrect affine coordinates: {}", e.to_string()),
                }
            })?;
        let mut ctx = BigNumContext::new()
            .map_err(|e| wrap_openssl_err(e, "unable to create BigNumContext"))?;
        ec_key
            .public_key()
            .to_bytes(
                &group,
                openssl::ec::PointConversionForm::UNCOMPRESSED,
                &mut ctx,
            )
            .map_err(|e| CryptoError::MalformedPublicKey {
                algorithm: AlgorithmId::EcdsaP256,
                key_bytes: Some(pk_cose.to_vec()),
                internal_error: e.to_string(),
            })
    }
}

/// Parse a CBOR-encoded ECDSA P-256 key in the COSE (RFC 8152) format
///
/// # Arguments
/// * `pk_cose` the CBOR-encoded COSE key
/// # Errors
/// * `MalformedPublicKey` if the data could not be CBOR-decoded
/// * `AlgorithmNotSupported` if the key was decoded but found to be something
///   other than an ECDSA P-256 key
/// # Returns
/// The decoded key
pub fn public_key_from_cose(pk_cose: &[u8]) -> CryptoResult<types::PublicKeyBytes> {
    let parsed_value: serde_cbor::value::Value =
        serde_cbor::from_slice(pk_cose).map_err(|e| CryptoError::MalformedPublicKey {
            algorithm: AlgorithmId::EcdsaP256,
            key_bytes: Some(Vec::from(pk_cose)),
            internal_error: e.to_string(),
        })?;

    let cose_parts = cose::cose_key_parts(parsed_value, pk_cose)?;
    let (x_bytes, y_bytes) = cose::verify_parts_and_get_x_y_bytes(cose_parts, pk_cose)?;
    let pk_bytes = cose::public_key_bytes(&x_bytes, &y_bytes, pk_cose)?;
    Ok(types::PublicKeyBytes::from(pk_bytes))
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
