//! Conversion of keys into various formats
use ic_crypto_internal_basic_sig_der_utils as der_utils;
use ic_crypto_internal_types::sign::eddsa::ed25519 as internal_types;
use simple_asn1::{BigUint, OID};
use std::convert::TryFrom;
pub mod pem;

#[cfg(test)]
#[allow(unused)]
mod test_data;

#[cfg(test)]
mod tests;

/// Usage:
/// * Import type - has no dependencies
/// * or import type + trait - has library dependencies
///
/// Convenience methods for DER/PEM encoding and decoding of Ed25519 public
/// keys. See https://tools.ietf.org/html/rfc8410 for the spec.
pub trait Ed25519Conversions {
    /// Encodes this key into a DER-encoded Ed25519 key.
    fn to_der(&self) -> Vec<u8>;

    /// Tries to parse `bytes` as a DER-encoded Ed25519 key
    fn from_der(bytes: &[u8]) -> Result<Self, Ed25519DerParseError>
    where
        Self: Sized;

    /// Encodes this key into a PEM-encoded Ed25519 key.
    fn to_pem(&self) -> String;

    /// Tries to parse `bytes` as a PEM-encoded Ed25519 key
    fn from_pem(bytes: &str) -> Result<Self, Ed25519PemParseError>
    where
        Self: Sized;
}

/// Convenience methods for DER/PEM encoding and decoding of Ed25519 secret keys
/// with the corresponding public keys.
/// See https://tools.ietf.org/html/rfc5958 for the spec.
pub trait Ed25519SecretKeyConversions {
    type PublicKeyType;

    /// Encodes this key into a DER-encoded Ed25519 key.
    fn to_der(&self, pk: &Self::PublicKeyType) -> Vec<u8>;

    /// Tries to parse `bytes` as a DER-encoded Ed25519 key
    fn from_der(bytes: &[u8]) -> Result<(Self, Self::PublicKeyType), Ed25519DerParseError>
    where
        Self: Sized;

    /// Encodes this key into a PEM-encoded Ed25519 key.
    fn to_pem(&self, pk: &Self::PublicKeyType) -> String;

    /// Tries to parse `bytes` as a PEM-encoded Ed25519 key
    fn from_pem(bytes: &str) -> Result<(Self, Self::PublicKeyType), Ed25519PemParseError>
    where
        Self: Sized;
}

#[derive(Debug)]
pub enum Ed25519DerParseError {
    IncorrectPublicKeyLength(internal_types::PublicKeyByteConversionError),
    IncorrectSecretKeyLength(internal_types::SecretKeyByteConversionError),
    OidExtractionError(String),
    OidValueError(simple_asn1::OID),
    MissingPublicKey(),
}

#[derive(Debug)]
pub enum Ed25519PemParseError {
    InvalidPem(std::io::Error),
    InvalidDer(Ed25519DerParseError),
}

impl Ed25519Conversions for internal_types::PublicKey {
    fn to_der(&self) -> Vec<u8> {
        // Prefixing the following bytes to the key is sufficient to DER-encode it.
        let mut der_pk = vec![
            48, 42, // A sequence of 42 bytes follows.
            48, 5, // An element of 5 bytes follows.
            6, 3, 43, 101, 112, // The OID
            3, 33, // A bitstring of 33 bytes follows.
            0,  // The bitstring (32 bytes) is divisible by 8
        ];
        der_pk.extend_from_slice(&self.0);
        der_pk
    }

    fn from_der(pk_der: &[u8]) -> Result<Self, Ed25519DerParseError>
    where
        Self: Sized,
    {
        let (oid, pk_bytes) = der_utils::oid_and_public_key_bytes_from_der(pk_der)
            .map_err(|e| Ed25519DerParseError::OidExtractionError(e.internal_error))?;
        if correct_oid() != oid {
            return Err(Ed25519DerParseError::OidValueError(oid));
        }
        internal_types::PublicKey::try_from(&pk_bytes[..])
            .map_err(Ed25519DerParseError::IncorrectPublicKeyLength)
    }

    fn to_pem(&self) -> String {
        let der = self.to_der();
        pem::der_to_pem(&der, pem::PUBLIC_KEY)
    }
    fn from_pem(pem: &str) -> Result<Self, Ed25519PemParseError>
    where
        Self: Sized,
    {
        let der =
            pem::pem_to_der(pem, pem::PUBLIC_KEY).map_err(Ed25519PemParseError::InvalidPem)?;
        Self::from_der(&der[..]).map_err(Ed25519PemParseError::InvalidDer)
    }
}

impl Ed25519SecretKeyConversions for internal_types::SecretKey {
    type PublicKeyType = internal_types::PublicKey;

    fn to_der(&self, pk: &Self::PublicKeyType) -> Vec<u8> {
        // Prefixing the following bytes to the secret key.
        let mut der_sk = vec![
            48, 83, // A sequence of 83 bytes follows.
            2, 1, // An integer denoting version
            1, // 0 if secret key only, 1 if public key is also present
            48, 5, // An element of 5 bytes follows
            6, 3, 43, 101, 112, // The OID
            4, 34, // An octet string of 34 bytes follows.
            4, 32, // An octet string of 32 bytes follows.
        ];
        der_sk.extend_from_slice(&self.0);

        // Prefixing the following bytes to the public key.
        der_sk.extend_from_slice(&[
            161, 35, // An explicitly tagged with 35 bytes.
            3, 33, // A bitstring of 33 bytes follows.
            0,  // The bitstring (32 bytes) is divisible by 8
        ]);
        der_sk.extend_from_slice(&pk.0);
        der_sk
    }

    fn from_der(sk_der: &[u8]) -> Result<(Self, Self::PublicKeyType), Ed25519DerParseError>
    where
        Self: Sized,
    {
        let key_data = der_utils::oid_and_key_pair_bytes_from_der(sk_der)
            .map_err(|e| Ed25519DerParseError::OidExtractionError(e.internal_error))?;
        if correct_oid() != key_data.oid {
            return Err(Ed25519DerParseError::OidValueError(key_data.oid));
        }

        let pk_bytes = key_data
            .pk_bytes
            .ok_or_else(Ed25519DerParseError::MissingPublicKey)?;

        let sk = internal_types::SecretKey::try_from(&*key_data.sk_bytes)
            .map_err(Ed25519DerParseError::IncorrectSecretKeyLength)?;
        let pk = internal_types::PublicKey::try_from(pk_bytes.as_ref())
            .map_err(Ed25519DerParseError::IncorrectPublicKeyLength)?;
        Ok((sk, pk))
    }

    fn to_pem(&self, pk: &Self::PublicKeyType) -> String {
        let der = self.to_der(pk);
        pem::der_to_pem(&der, pem::SECRET_KEY)
    }

    fn from_pem(pem: &str) -> Result<(Self, Self::PublicKeyType), Ed25519PemParseError>
    where
        Self: Sized,
    {
        let der =
            pem::pem_to_der(pem, pem::SECRET_KEY).map_err(Ed25519PemParseError::InvalidPem)?;
        Self::from_der(&der[..]).map_err(Ed25519PemParseError::InvalidDer)
    }
}

/// The correct DER OID for Ed25519
///
/// OID for Ed25519 is 1.3.101.112, see https://tools.ietf.org/html/rfc8410
fn correct_oid() -> simple_asn1::OID {
    simple_asn1::oid!(1, 3, 101, 112)
}
