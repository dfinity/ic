use ic_crypto_internal_basic_sig_der_utils::PkixAlgorithmIdentifier;
use ic_crypto_internal_basic_sig_ecdsa_secp256r1::der_encoding_from_xy_coordinates as p256_from_coordinates;
use ic_crypto_internal_basic_sig_rsa_pkcs1::RsaPublicKey;
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult};
use simple_asn1::oid;

/// Return the algorithm identifier associated with COSE encoded keys
pub fn algorithm_identifier() -> PkixAlgorithmIdentifier {
    PkixAlgorithmIdentifier::new_with_empty_param(oid!(1, 3, 6, 1, 4, 1, 56387, 1, 1))
}

type CborMap = std::collections::BTreeMap<serde_cbor::Value, serde_cbor::Value>;

/// A public key that was parsed from COSE format
///
/// Each variant wraps the standard DER encoding of a key for that
/// algorithm
#[derive(Debug, Eq, PartialEq)]
enum CosePublicKey {
    EcdsaP256Sha256(Vec<u8>),
    RsaPkcs1v15Sha256(Vec<u8>),
}

// see https://tools.ietf.org/html/rfc8152 section 8.1
const COSE_PARAM_KTY: serde_cbor::Value = serde_cbor::Value::Integer(1);
const COSE_PARAM_ALG: serde_cbor::Value = serde_cbor::Value::Integer(3);
const COSE_PARAM_KEY_OPS: serde_cbor::Value = serde_cbor::Value::Integer(4);

// see https://datatracker.ietf.org/doc/html/rfc8152#section-13
const COSE_KTY_EC2: serde_cbor::Value = serde_cbor::Value::Integer(2);
const COSE_PARAM_EC2_CRV: serde_cbor::Value = serde_cbor::Value::Integer(-1);
const COSE_PARAM_EC2_X: serde_cbor::Value = serde_cbor::Value::Integer(-2);
const COSE_PARAM_EC2_Y: serde_cbor::Value = serde_cbor::Value::Integer(-3);

// see https://datatracker.ietf.org/doc/html/rfc8152#section-8.1 and
// https://datatracker.ietf.org/doc/html/rfc8152#section-13.1
const COSE_ALG_ES256: serde_cbor::Value = serde_cbor::Value::Integer(-7);
const COSE_EC2_CRV_P256: serde_cbor::Value = serde_cbor::Value::Integer(1);

// https://datatracker.ietf.org/doc/html/rfc8812#section-2
const COSE_ALG_RS256: serde_cbor::Value = serde_cbor::Value::Integer(-257);

// https://datatracker.ietf.org/doc/html/rfc8230#section-4
const COSE_KTY_RSA: serde_cbor::Value = serde_cbor::Value::Integer(3);
const COSE_PARAM_RSA_N: serde_cbor::Value = serde_cbor::Value::Integer(-1);
const COSE_PARAM_RSA_E: serde_cbor::Value = serde_cbor::Value::Integer(-2);

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
/// An error that occured while parsing the COSE key
enum CosePublicKeyParseError {
    /// The key is malformed (not valid CBOR with COSE formatting)
    MalformedPublicKey(AlgorithmId),
    /// The key seems valid, but is for an algorithm that is not supported
    AlgorithmNotSupported,
}

impl CosePublicKey {
    /// Parse a COSE public key (RFC 8152) in CBOR encoding
    ///
    /// # Arguments
    /// * `pk_cose` the CBOR-encoded COSE public key
    /// # Errors
    /// * `AlgorithmNotSupported` if some unsupported algorithm is used
    /// * `MalformedPublicKey` if the public key could not be parsed
    /// # Returns
    /// The decoded public key
    pub fn from_cbor(pk_cose: &[u8]) -> Result<Self, CosePublicKeyParseError> {
        let parsed_value: serde_cbor::value::Value = serde_cbor::from_slice(pk_cose)
            .map_err(|_| CosePublicKeyParseError::MalformedPublicKey(AlgorithmId::Placeholder))?;

        if let serde_cbor::Value::Map(fields) = parsed_value {
            let kty =
                fields
                    .get(&COSE_PARAM_KTY)
                    .ok_or(CosePublicKeyParseError::MalformedPublicKey(
                        AlgorithmId::Placeholder,
                    ))?;
            let alg =
                fields
                    .get(&COSE_PARAM_ALG)
                    .ok_or(CosePublicKeyParseError::MalformedPublicKey(
                        AlgorithmId::Placeholder,
                    ))?;

            if *kty == COSE_KTY_EC2 && *alg == COSE_ALG_ES256 {
                Self::parse_ecdsa_p256(&fields)
            } else if *kty == COSE_KTY_RSA && *alg == COSE_ALG_RS256 {
                Self::parse_rsa_pkcs1_sha256(&fields)
            } else {
                // Some other algorithm
                Err(CosePublicKeyParseError::AlgorithmNotSupported)
            }
        } else {
            Err(CosePublicKeyParseError::MalformedPublicKey(
                AlgorithmId::Placeholder,
            )) // not a map!
        }
    }

    fn verify_key_ops(fields: &CborMap) -> Result<(), CosePublicKeyParseError> {
        if let Some(key_ops) = fields.get(&COSE_PARAM_KEY_OPS) {
            if *key_ops != serde_cbor::Value::Text("verify".to_string()) {
                return Err(CosePublicKeyParseError::AlgorithmNotSupported);
            }
        }

        Ok(())
    }

    /// Parse a COSE ECDSA key
    fn parse_ecdsa_p256(fields: &CborMap) -> Result<Self, CosePublicKeyParseError> {
        Self::verify_key_ops(fields)?;

        let crv =
            fields
                .get(&COSE_PARAM_EC2_CRV)
                .ok_or(CosePublicKeyParseError::MalformedPublicKey(
                    AlgorithmId::EcdsaP256,
                ))?;

        if *crv != COSE_EC2_CRV_P256 {
            // Some ECDSA we don't support
            return Err(CosePublicKeyParseError::AlgorithmNotSupported);
        }

        let x =
            fields
                .get(&COSE_PARAM_EC2_X)
                .ok_or(CosePublicKeyParseError::MalformedPublicKey(
                    AlgorithmId::EcdsaP256,
                ))?;
        let y =
            fields
                .get(&COSE_PARAM_EC2_Y)
                .ok_or(CosePublicKeyParseError::MalformedPublicKey(
                    AlgorithmId::EcdsaP256,
                ))?;

        match (x, y) {
            (serde_cbor::Value::Bytes(x), serde_cbor::Value::Bytes(y)) => {
                // RFC 8152 section 13.1.1 requires leading zeros are included
                if x.len() != 32 || y.len() != 32 {
                    return Err(CosePublicKeyParseError::MalformedPublicKey(
                        AlgorithmId::EcdsaP256,
                    ));
                }

                let der = p256_from_coordinates(x, y).map_err(|_| {
                    CosePublicKeyParseError::MalformedPublicKey(AlgorithmId::EcdsaP256)
                })?;
                Ok(Self::EcdsaP256Sha256(der))
            }
            (_, _) => Err(CosePublicKeyParseError::MalformedPublicKey(
                AlgorithmId::EcdsaP256,
            )),
        }
    }

    fn parse_rsa_pkcs1_sha256(fields: &CborMap) -> Result<Self, CosePublicKeyParseError> {
        Self::verify_key_ops(fields)?;

        let e =
            fields
                .get(&COSE_PARAM_RSA_E)
                .ok_or(CosePublicKeyParseError::MalformedPublicKey(
                    AlgorithmId::RsaSha256,
                ))?;
        let n =
            fields
                .get(&COSE_PARAM_RSA_N)
                .ok_or(CosePublicKeyParseError::MalformedPublicKey(
                    AlgorithmId::RsaSha256,
                ))?;

        match (e, n) {
            (serde_cbor::Value::Bytes(e), serde_cbor::Value::Bytes(n)) => {
                let key = RsaPublicKey::from_components(&e, &n).map_err(|_| {
                    CosePublicKeyParseError::MalformedPublicKey(AlgorithmId::RsaSha256)
                })?;
                let der = key.as_der().to_vec();
                Ok(Self::RsaPkcs1v15Sha256(der))
            }
            (_, _) => Err(CosePublicKeyParseError::MalformedPublicKey(
                AlgorithmId::RsaSha256,
            )),
        }
    }

    /// Return the algorithm ID associated with this public key
    fn algorithm_id(&self) -> AlgorithmId {
        match self {
            Self::EcdsaP256Sha256(_) => AlgorithmId::EcdsaP256,
            Self::RsaPkcs1v15Sha256(_) => AlgorithmId::RsaSha256,
        }
    }

    /// Return the standard DER encoding of this public key
    fn encoded_key(&self) -> Vec<u8> {
        match self {
            Self::EcdsaP256Sha256(der) => der.to_vec(),
            Self::RsaPkcs1v15Sha256(der) => der.to_vec(),
        }
    }
}

/// Parse a CBOR-encoded key in the COSE (RFC 8152) format
///
/// # Arguments
/// * `pk_cose` the CBOR-encoded COSE key
/// # Errors
/// * `MalformedPublicKey` if the data could not be CBOR-decoded
/// * `AlgorithmNotSupported` if the key was decoded but is some unsupported
///   algorithm
///
/// # Returns
/// The decoded key as an SPKI
pub fn parse_cose_public_key(pk_cose: &[u8]) -> CryptoResult<(AlgorithmId, Vec<u8>)> {
    match CosePublicKey::from_cbor(pk_cose) {
        Ok(key) => Ok((key.algorithm_id(), key.encoded_key())),
        Err(CosePublicKeyParseError::MalformedPublicKey(algorithm)) => {
            Err(CryptoError::MalformedPublicKey {
                algorithm,
                key_bytes: Some(pk_cose.to_vec()),
                internal_error: "Failed to parse COSE public key".to_string(),
            })
        }
        Err(CosePublicKeyParseError::AlgorithmNotSupported) => {
            Err(CryptoError::AlgorithmNotSupported {
                algorithm: AlgorithmId::Placeholder,
                reason: "Algorithm not supported in COSE parser".to_string(),
            })
        }
    }
}
