//! Verify RSA signatures
//!
//! See RFC 5280 (https://www.rfc-editor.org/rfc/rfc5280.txt)
//! and RFC 3279 (https://www.rfc-editor.org/rfc/rfc3279.txt)
//! for information about the SubjectPublicKeyInfo key encoding
//!
//! See RFC 8017 (https://www.rfc-editor.org/rfc/rfc8017.txt)
//! for information about the signature format
use ic_crypto_internal_basic_sig_der_utils as der_utils;
use ic_crypto_sha2::Sha256;
use ic_types::crypto::{AlgorithmId, CryptoError, CryptoResult};
use num_traits::{FromPrimitive, Zero};
use rsa::traits::PublicKeyParts;
use rsa::{pkcs8, Pkcs1v15Sign};
use serde::{Deserialize, Deserializer, Serialize};

/// The object identifier for RSA public keys
///
/// See [RFC 8017](https://tools.ietf.org/html/rfc8017).
pub fn algorithm_identifier() -> der_utils::PkixAlgorithmIdentifier {
    der_utils::PkixAlgorithmIdentifier::new_with_null_param(simple_asn1::oid!(
        1, 2, 840, 113549, 1, 1, 1
    ))
}

/// A RSA public key usable for signature verification
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct RsaPublicKey {
    der: Vec<u8>,
    #[serde(skip_serializing)]
    key: rsa::RsaPublicKey,
}

impl<'de> Deserialize<'de> for RsaPublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct RsaPublicKeyDeserializationHelper {
            der: Vec<u8>,
        }

        let helper: RsaPublicKeyDeserializationHelper = Deserialize::deserialize(deserializer)?;
        RsaPublicKey::from_der_spki(&helper.der).map_err(serde::de::Error::custom)
    }
}

impl RsaPublicKey {
    pub const MINIMUM_RSA_KEY_SIZE: usize = 2048;
    pub const MAXIMUM_RSA_KEY_SIZE: usize = 8192;

    /// Create the SPKI encoding of an RSA public key from the public parameters
    ///
    /// # Arguments
    /// * `e` the public exponent, encoded in big-endian bytes
    /// * `n` the public modulus, encoded in big-endian bytes
    fn spki_from_components(e: &[u8], n: &[u8]) -> CryptoResult<Vec<u8>> {
        use num_bigint::Sign;
        use simple_asn1::*;

        let n = ASN1Block::Integer(0, BigInt::from_bytes_be(Sign::Plus, n));
        let e = ASN1Block::Integer(0, BigInt::from_bytes_be(Sign::Plus, e));
        let blocks = vec![n, e];

        let pkcs1 =
            to_der(&ASN1Block::Sequence(0, blocks)).map_err(|e| CryptoError::InvalidArgument {
                message: format!("{:?}", e),
            })?;

        let oid = ASN1Block::ObjectIdentifier(0, oid!(1, 2, 840, 113549, 1, 1, 1));
        let alg = ASN1Block::Sequence(0, vec![oid, ASN1Block::Null(0)]);
        let octet_string = ASN1Block::BitString(0, pkcs1.len() * 8, pkcs1);
        let blocks = vec![alg, octet_string];

        to_der(&ASN1Block::Sequence(0, blocks)).map_err(|e| CryptoError::InvalidArgument {
            message: format!("{:?}", e),
        })
    }

    /// Create a RSA public key from the public parameters
    ///
    /// # Arguments
    /// * `e` the public exponent, encoded in big-endian bytes
    /// * `n` the public modulus, encoded in big-endian bytes
    pub fn from_components(e: &[u8], n: &[u8]) -> CryptoResult<Self> {
        let der = Self::spki_from_components(e, n)?;
        Self::from_der_spki(&der)
    }

    /// Create a RSA public key from the encoded X.509 SubjectPublicKeyInfo
    ///
    /// See https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
    /// for the definition of SubjectPublicKeyInfo and
    /// https://datatracker.ietf.org/doc/html/rfc3279#section-2.3.1 for the
    /// RSA specific definitions
    ///
    /// # Arguments
    /// * `bytes` the DER encoded data
    pub fn from_der_spki(bytes: &[u8]) -> CryptoResult<Self> {
        use rsa::BigUint;

        let parsed: rsa::RsaPublicKey = pkcs8::DecodePublicKey::from_public_key_der(bytes)
            .map_err(|e| CryptoError::MalformedPublicKey {
                algorithm: AlgorithmId::RsaSha256,
                key_bytes: Some(bytes.to_vec()),
                internal_error: format!("Parsing RSA key failed {:?}", e),
            })?;

        let two = BigUint::from_i8(2).expect("Unable to create 2 BigUint");

        // RustCrypto/rsa does not verify that the public exponent is odd
        if parsed.e() % &two == BigUint::zero() {
            return Err(CryptoError::MalformedPublicKey {
                algorithm: AlgorithmId::RsaSha256,
                key_bytes: Some(bytes.to_vec()),
                internal_error: "RSA public exponent is invalid".to_string(),
            });
        }

        // RustCrypto/rsa does not verify that the public modulus is odd
        if parsed.n() % &two == BigUint::zero() {
            return Err(CryptoError::MalformedPublicKey {
                algorithm: AlgorithmId::RsaSha256,
                key_bytes: Some(bytes.to_vec()),
                internal_error: "RSA public modulus is invalid".to_string(),
            });
        }

        // RustCrypto/rsa does not check if the modulus is valid size
        let modulus_bits = parsed.n().bits();

        if modulus_bits < Self::MINIMUM_RSA_KEY_SIZE {
            return Err(CryptoError::MalformedPublicKey {
                algorithm: AlgorithmId::RsaSha256,
                key_bytes: Some(bytes.to_vec()),
                internal_error: "RSA public key too small to accept".to_string(),
            });
        }

        if modulus_bits > Self::MAXIMUM_RSA_KEY_SIZE {
            return Err(CryptoError::MalformedPublicKey {
                algorithm: AlgorithmId::RsaSha256,
                key_bytes: Some(bytes.to_vec()),
                internal_error: "RSA public key too large to accept".to_string(),
            });
        }

        Ok(Self {
            der: bytes.to_vec(),
            key: parsed,
        })
    }

    /// Return the DER encoding of the key
    pub fn as_der(&self) -> &[u8] {
        self.der.as_ref()
    }

    /// Verify a PKCS#1 v1.5 SHA-256 RSA signature
    ///
    /// As specified in RFC 8017
    /// (https://datatracker.ietf.org/doc/html/rfc8017#section-8.2) and used by
    /// the IC for webauthn (https://docs.dfinity.systems/spec/public/#webauthn)
    pub fn verify_pkcs1_sha256(&self, message: &[u8], signature: &[u8]) -> CryptoResult<()> {
        // The version of rsa crate that we use has a signature malleability bug
        // https://github.com/RustCrypto/RSA/issues/272 which does not seem
        // directly to be any real problem, but worth avoiding.
        //
        // There is an updated version of the crate but upgrading
        // requires significant changes, see CRP-2038
        let modulus_bytes = (self.key.n().bits() + 7) / 8; // rounding up

        if signature.len() > modulus_bytes {
            return Err(CryptoError::SignatureVerification {
                algorithm: AlgorithmId::RsaSha256,
                public_key_bytes: self.as_der().to_vec(),
                sig_bytes: signature.to_vec(),
                internal_error: format!(
                    "Signature is {} bytes but public modulus only {}",
                    signature.len(),
                    modulus_bytes
                ),
            });
        }
        let sig = rsa::BigUint::from_bytes_be(signature);

        if &sig > self.key.n() {
            return Err(CryptoError::SignatureVerification {
                algorithm: AlgorithmId::RsaSha256,
                public_key_bytes: self.as_der().to_vec(),
                sig_bytes: signature.to_vec(),
                internal_error: "Signature is larger than public modulus".to_string(),
            });
        }

        let digest = Sha256::hash(message);

        match &self
            .key
            .verify(Pkcs1v15Sign::new::<sha2::Sha256>(), &digest, signature)
        {
            Ok(_) => Ok(()),
            Err(e) => Err(CryptoError::SignatureVerification {
                algorithm: AlgorithmId::RsaSha256,
                public_key_bytes: self.as_der().to_vec(),
                sig_bytes: signature.to_vec(),
                internal_error: format!("{:?}", e),
            }),
        }
    }
}
