//! This module performs TLS keypair generation. It allows to generate an X.509
//! public key certificate together with its private key.
use super::*;
use ic_crypto_internal_tls::keygen::generate_tls_key_pair;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use openssl::asn1::Asn1Time;
use rand::rngs::OsRng;

/// Generates and returns a private key and a self-signed X509 public key
/// certificate.
///
/// Properties of the key and certificate:
/// * The certificate's subject and issuer CN are set to the `common_name`
/// * The certificate's serial number is generated randomly
/// * The private key is an ed25519 key
/// * The certificate's notAfter date defines the certificate's expiration
///   time and is set to `not_after`. This must be an appropriate time
///   format that RFC 5280 requires, which means it only allows
///   YYMMDDHHMMSSZ and YYYYMMDDHHMMSSZ (leap second is rejected), all
///   other ASN.1 time formats are not allowed. To set no well-defined
///   expiration date, pass "99991231235959Z" according to
///   https://tools.ietf.org/html/rfc5280#section-4.1.2.5
///
/// # Arguments
/// * `common_name` is the Common Name (and Issuer Name, since the cert is
///   self-signed)
/// * `not_after` is a string representation of the Not After field (cf. above)
///
/// # Returns
/// `(TlsPublicKeyCert, TlsPrivateKey)`
///
/// # Panics
/// * if `not_after` cannot be parsed or lies in the past
/// * if the generated X509 certificate is malformed
pub fn generate_tls_keys(common_name: &str, not_after: &str) -> (TlsPublicKeyCert, TlsPrivateKey) {
    let csprng = &mut OsRng;
    let not_after =
        Asn1Time::from_str_x509(not_after).expect("unable to parse not after as ASN1Time");
    let (cert, secret_key) = generate_tls_key_pair(csprng, common_name, &not_after);
    (
        // We panic here, because we *shouldn't* generate a malformed cert.
        TlsPublicKeyCert::new_from_x509(cert).expect("Generated X509 certificate is malformed"),
        TlsPrivateKey::new_from_pkey(secret_key),
    )
}
