//! Library crate that provides low-level functionality needed to establish TLS
//! connections.
//!
//! In particular, the crate provides functionality to
//! * generate TLS key material and wrap the public part in an X.509 certificate
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![warn(rust_2018_idioms)]
#![warn(future_incompatible)]

use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
use ic_crypto_internal_basic_sig_ed25519::{
    secret_key_to_pkcs8_v1_der, secret_key_to_pkcs8_v2_der,
};
use ic_crypto_secrets_containers::SecretBytes;
use rand::{CryptoRng, Rng};
use rcgen::{
    Certificate, CertificateParams, DistinguishedName, DnType, DnValue, KeyPair, SerialNumber,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use time::OffsetDateTime;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A DER-encoded X.509 v3 certificate with an Ed25519 public key.
#[derive(Debug)]
pub struct TlsEd25519CertificateDerBytes {
    pub bytes: Vec<u8>,
}

/// The generation of a TLS key pair and X.509 certificate failed.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum TlsKeyPairAndCertGenerationError {
    InvalidArguments(String),
    InternalError(String),
}

/// A DER-encoded Ed25519 secret key in PKCS#8 v1 format (RFC 5208).
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct TlsEd25519SecretKeyDerBytes {
    pub bytes: SecretBytes,
}

impl TlsEd25519SecretKeyDerBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        let bytes = SecretBytes::new(bytes);
        Self { bytes }
    }
}

impl From<SecretBytes> for TlsEd25519SecretKeyDerBytes {
    fn from(bytes: SecretBytes) -> Self {
        Self { bytes }
    }
}

impl fmt::Debug for TlsEd25519SecretKeyDerBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "REDACTED")
    }
}

/// Generates a TLS key pair.
///
/// The notBefore and notAfter dates are interpreted as Unix time, i.e., seconds since Unix epoch.
pub fn generate_tls_key_pair_der<R: Rng + CryptoRng>(
    csprng: &mut R,
    common_name: &str,
    not_before_secs_since_unix_epoch: u64,
    not_after_secs_since_unix_epoch: u64,
) -> Result<
    (TlsEd25519CertificateDerBytes, TlsEd25519SecretKeyDerBytes),
    TlsKeyPairAndCertGenerationError,
> {
    let serial: [u8; 19] = csprng.gen();
    let (secret_key, public_key) = ic_crypto_internal_basic_sig_ed25519::keypair_from_rng(csprng);
    let x509_cert = x509_v3_certificate(
        &public_key,
        common_name,
        serial,
        not_before_secs_since_unix_epoch,
        not_after_secs_since_unix_epoch,
        &secret_key,
    )?;
    der_encode_cert_and_secret_key(x509_cert, &secret_key)
}

/// Generates an X.509 v3 certificate.
///
/// The notBefore and notAfter dates are interpreted as Unix time, i.e., seconds since Unix epoch.
///
/// Note that the certificate serial number must be at most 20 octets according
/// to https://tools.ietf.org/html/rfc5280 Section 4.1.2.2. The 19 bytes serial
/// number argument is interpreted as an unsigned integer and thus fits in 20
/// bytes, encoded as a signed ASN1 integer.
fn x509_v3_certificate(
    public_key: &ed25519_types::PublicKeyBytes,
    common_name: &str,
    serial: [u8; 19],
    not_before_secs_since_unix_epoch: u64,
    not_after_secs_since_unix_epoch: u64,
    secret_key: &ed25519_types::SecretKeyBytes,
) -> Result<rcgen::Certificate, TlsKeyPairAndCertGenerationError> {
    let not_before_i64 = i64::try_from(not_before_secs_since_unix_epoch).map_err(|_e| {
        TlsKeyPairAndCertGenerationError::InvalidArguments(
            "invalid notBefore date: failed to convert to i64".to_string(),
        )
    })?;
    let not_before = OffsetDateTime::from_unix_timestamp(not_before_i64).map_err(|e| {
        TlsKeyPairAndCertGenerationError::InvalidArguments(format!(
            "invalid notBefore date: failed to convert to OffsetDateTime: {}",
            e
        ))
    })?;
    let not_after_i64 = i64::try_from(not_after_secs_since_unix_epoch).map_err(|_e| {
        TlsKeyPairAndCertGenerationError::InvalidArguments(
            "invalid notAfter date: failed to convert to i64".to_string(),
        )
    })?;
    let not_after = OffsetDateTime::from_unix_timestamp(not_after_i64).map_err(|e| {
        TlsKeyPairAndCertGenerationError::InvalidArguments(format!(
            "invalid notAfter date: failed to convert to OffsetDateTime: {}",
            e
        ))
    })?;
    if not_before >= not_after {
        return Err(TlsKeyPairAndCertGenerationError::InvalidArguments(format!(
            "notBefore date ({}) must be before notAfter date ({})",
            not_before, not_after,
        )));
    }
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(
        DnType::CommonName,
        DnValue::Utf8String(common_name.to_string()),
    );
    let mut key_pair = rcgen_keypair_from_ed25519_keypair(secret_key, public_key)?;

    let mut cert_params = CertificateParams::default();
    cert_params.not_before = not_before;
    cert_params.not_after = not_after;
    cert_params.serial_number = Some(SerialNumber::from_slice(&serial));
    cert_params.distinguished_name = distinguished_name;

    let cert_result = cert_params.self_signed(&key_pair).map_err(|e| {
        TlsKeyPairAndCertGenerationError::InternalError(format!(
            "failed to create X509 certificate: {}",
            e
        ))
    });
    key_pair.zeroize();
    cert_result
}

fn rcgen_keypair_from_ed25519_keypair(
    secret_key: &ed25519_types::SecretKeyBytes,
    public_key: &ed25519_types::PublicKeyBytes,
) -> Result<KeyPair, TlsKeyPairAndCertGenerationError> {
    let keypair_der = secret_key_to_pkcs8_v2_der(secret_key, public_key);
    KeyPair::try_from(keypair_der.expose_secret()).map_err(|e| {
        TlsKeyPairAndCertGenerationError::InternalError(format!(
            "failed to create Ed25519 key pair from raw private key: {}",
            e
        ))
    })
}

fn der_encode_cert_and_secret_key(
    x509_cert: Certificate,
    secret_key: &ed25519_types::SecretKeyBytes,
) -> Result<
    (TlsEd25519CertificateDerBytes, TlsEd25519SecretKeyDerBytes),
    TlsKeyPairAndCertGenerationError,
> {
    let cert_der = x509_cert.der().as_ref().to_vec();
    let private_key_pkcs8_v1_der = secret_key_to_pkcs8_v1_der(secret_key);
    Ok((
        TlsEd25519CertificateDerBytes { bytes: cert_der },
        TlsEd25519SecretKeyDerBytes::from(private_key_pkcs8_v1_der),
    ))
}
