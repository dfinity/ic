//! Functionality to generate key material to be used for TLS connections.
use ic_crypto_secrets_containers::SecretBytes;
use openssl::asn1::Asn1Integer;
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{X509Name, X509},
};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(test)]
mod tests;

/// The raw bytes of a DER-encoded X.509 certificate containing an Ed25519
/// public key.
pub struct TlsEd25519CertificateDerBytes {
    pub bytes: Vec<u8>,
}

impl TryFrom<&TlsEd25519CertificateDerBytes> for X509 {
    type Error = TlsEd25519CertificateDerBytesParseError;

    fn try_from(der_bytes: &TlsEd25519CertificateDerBytes) -> Result<Self, Self::Error> {
        X509::from_der(&der_bytes.bytes)
            .map_err(|_| TlsEd25519CertificateDerBytesParseError::CertificateParsingError)
    }
}

/// The parsing of the DER representation of an X.509 certificate with an
/// Ed25519 key failed.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum TlsEd25519CertificateDerBytesParseError {
    CertificateParsingError,
}

/// The generation of a TLS key pair and X.509 certificate failed.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum TlsKeyPairAndCertGenerationError {
    InvalidNotAfterDate { message: String },
}

/// The raw bytes of a DER-encoded Ed25519 secret key.
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

impl fmt::Debug for TlsEd25519SecretKeyDerBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "REDACTED")
    }
}

/// Generate a key pair and return the certificate and private key in DER
/// format.
pub fn generate_tls_key_pair_der<R: Rng + CryptoRng>(
    csprng: &mut R,
    common_name: &str,
    not_before: &Asn1Time,
    not_after: &Asn1Time,
) -> Result<
    (TlsEd25519CertificateDerBytes, TlsEd25519SecretKeyDerBytes),
    TlsKeyPairAndCertGenerationError,
> {
    let (x509_cert, key_pair) = generate_tls_key_pair(csprng, common_name, not_before, not_after)?;
    Ok(der_encode_cert_and_secret_key(&key_pair, x509_cert))
}

/// Generate a key pair and return the certificate and private key.
pub fn generate_tls_key_pair<R: Rng + CryptoRng>(
    csprng: &mut R,
    common_name: &str,
    not_before: &Asn1Time,
    not_after: &Asn1Time,
) -> Result<(X509, PKey<Private>), TlsKeyPairAndCertGenerationError> {
    let serial: [u8; 19] = csprng.gen();
    let key_pair = ed25519_key_pair(csprng);
    let x509_certificate = x509_v3_certificate(
        common_name,
        serial,
        &key_pair,
        not_before,
        not_after,
        // Digest must be null for Ed25519 (see https://www.openssl.org/docs/man1.1.1/man7/Ed25519.html)
        MessageDigest::null(),
    )?;
    Ok((x509_certificate, key_pair))
}

fn ed25519_key_pair<R: Rng + CryptoRng>(csprng: &mut R) -> PKey<Private> {
    let (secret_key, _public_key_ignored_because_regenerated_by_openssl) =
        ic_crypto_internal_basic_sig_ed25519::keypair_from_rng(csprng);
    PKey::private_key_from_raw_bytes(secret_key.0.expose_secret(), openssl::pkey::Id::ED25519)
        .expect("failed to create Ed25519 key pair from raw private key")
}

/// Generates a certificate.
///
/// Note that the certificate serial number must be at most 20 octets according
/// to https://tools.ietf.org/html/rfc5280 Section 4.1.2.2. The 19 bytes serial
/// number argument is interpreted as an unsigned integer and thus fits in 20
/// bytes, encoded as a signed ASN1 integer.
fn x509_v3_certificate(
    common_name: &str,
    serial: [u8; 19],
    key_pair: &PKey<Private>,
    not_before: &Asn1Time,
    not_after: &Asn1Time,
    message_digest: MessageDigest,
) -> Result<X509, TlsKeyPairAndCertGenerationError> {
    if not_after <= not_before {
        return Err(TlsKeyPairAndCertGenerationError::InvalidNotAfterDate {
            message: format!(
                "'not after' date ({}) must be after 'not before' date ({})",
                **not_after, **not_before,
            ),
        });
    }

    let mut builder = X509::builder().expect("unable to create builder");
    // note that this sets the version to 3 (zero indexed):
    builder.set_version(2).expect("unable to set version");
    builder
        .set_serial_number(&serial_number(serial))
        .expect("unable to set serial number");
    let cn = x509_name_with_cn(common_name);
    builder
        .set_subject_name(&cn)
        .expect("unable to set subject cn");
    builder
        .set_issuer_name(&cn)
        .expect("unable to set issuer cn");
    builder
        .set_pubkey(key_pair)
        .expect("unable to set public key");
    builder
        .set_not_before(not_before)
        .expect("unable to set 'not before'");
    builder
        .set_not_after(not_after)
        .expect("unable to set 'not after'");
    builder
        .sign(key_pair, message_digest)
        .expect("unable to sign");
    Ok(builder.build())
}

fn der_encode_cert_and_secret_key(
    key_pair: &PKey<Private>,
    x509_cert: X509,
) -> (TlsEd25519CertificateDerBytes, TlsEd25519SecretKeyDerBytes) {
    (
        TlsEd25519CertificateDerBytes {
            bytes: x509_cert
                .to_der()
                .expect("unable to DER encode certificate"),
        },
        TlsEd25519SecretKeyDerBytes::new(
            key_pair
                .private_key_to_der()
                .expect("private key could not be DER encoded"),
        ),
    )
}

fn x509_name_with_cn(common_name: &str) -> X509Name {
    let mut name = X509Name::builder().expect("unable to create name builder");
    name.append_entry_by_nid(Nid::COMMONNAME, common_name)
        .expect("unable to append common name");
    name.build()
}

fn serial_number(serial: [u8; 19]) -> Asn1Integer {
    BigNum::from_slice(&serial)
        .expect("unable to create the serial number big num")
        .to_asn1_integer()
        .expect("unable to create ASN1 integer for serial number")
}
