//! Library crate for verifying the validity of a node's TLS certificate.

use chrono::{DateTime, Duration, Utc};
use core::fmt;
use ic_crypto_internal_basic_sig_ed25519::types::PublicKeyBytes as BasicSigEd25519PublicKeyBytes;
use ic_crypto_internal_basic_sig_ed25519::types::SignatureBytes as BasicSigEd25519SignatureBytes;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_types::crypto::CryptoResult;
use ic_types::NodeId;
use std::convert::TryFrom;
use x509_parser::certificate::X509Certificate;
use x509_parser::time::ASN1Time;
use x509_parser::x509::{X509Name, X509Version};

#[cfg(test)]
mod tests;

/// Validates a node's TLS certificate.
///
/// Validation of a *node's TLS certificate* includes verifying that
/// * the certificate is well-formed, i.e., formatted in X.509 version 3 and
///   DER-encoded
/// * the certificate has a single subject common name (CN) that matches the
///   `node_id`
/// * the certificate has a single issuer common name (CN) that matches the
///   subject CN (indicating that the certificate is self-signed)
/// * the certificate is NOT for a certificate authority. This means either 1)
///   there are no BasicConstraints extensions, or 2) if there are
///   BasicConstraints then one is `CA` and it's set to `False`.
/// * the certificate's notBefore date is latest in two minutes from now. This
///   is to ensure that the certificate is already valid or becomes valid
///   shortly. The grace period is to account for potential clock differences.
/// * the certificate's notAfter date indicates according to [RFC 5280 (section
///   4.1.2.5)] that the certificate has no well-defined expiration date.
/// * the certificate's signature algorithm is Ed25519 (OID 1.3.101.112)
/// * the certificate's public key is valid, which includes checking that the
///   key is a point on the curve and in the right subgroup
/// * the certificate's signature is valid w.r.t. the certificate's public key,
///   that is, the certificate is correctly self-signed
///
/// [RFC 5280 (section 4.1.2.5)]: https://tools.ietf.org/html/rfc5280#section-4.1.2.5
pub fn validate_tls_certificate(
    tls_certificate: &X509PublicKeyCert,
    node_id: NodeId,
) -> Result<(), TlsCertValidationError> {
    let x509_cert = parse_x509_v3_certificate(&tls_certificate.certificate_der)?;
    let subject_cn = single_subject_cn_as_str(&x509_cert)?;
    ensure_subject_cn_equals_node_id(subject_cn, node_id)?;
    ensure_single_issuer_cn_equals_subject_cn(&x509_cert, subject_cn)?;
    ensure_not_ca(&x509_cert)?;
    ensure_notbefore_date_is_latest_in_two_minutes_from_now(&x509_cert)?;
    ensure_notafter_date_equals_99991231235959z(&x509_cert)?;
    ensure_signature_algorithm_is_ed25519(&x509_cert)?;

    let public_key = ed25519_pubkey_from_x509_cert(&x509_cert)?;
    verify_ed25519_public_key(&public_key)?;
    verify_ed25519_signature(&x509_cert, &public_key).map_err(|e| {
        invalid_tls_certificate_error(format!("signature verification failed: {}", e))
    })?;
    Ok(())
}

fn single_subject_cn_as_str<'a>(
    x509_cert: &'a X509Certificate,
) -> Result<&'a str, TlsCertValidationError> {
    single_cn_as_str(x509_cert.subject()).map_err(|e| {
        invalid_tls_certificate_error(format!("invalid subject common name (CN): {}", e))
    })
}

fn parse_x509_v3_certificate(
    certificate_der: &[u8],
) -> Result<X509Certificate, TlsCertValidationError> {
    let (remainder, x509_cert) = x509_parser::parse_x509_certificate(certificate_der)
        .map_err(|e| invalid_tls_certificate_error(format!("failed to parse DER: {:?}", e)))?;
    if !remainder.is_empty() {
        return Err(invalid_tls_certificate_error(format!(
            "DER not fully consumed when parsing. Remainder: 0x{}",
            hex::encode(&remainder)
        )));
    }
    if x509_cert.version() != X509Version::V3 {
        return Err(invalid_tls_certificate_error("X509 version is not 3"));
    }
    Ok(x509_cert)
}

fn ensure_subject_cn_equals_node_id(
    subject_cn: &str,
    node_id: NodeId,
) -> Result<&str, TlsCertValidationError> {
    if subject_cn != node_id.get().to_string().as_str() {
        return Err(invalid_tls_certificate_error(
            "subject common name (CN) does not match node ID",
        ));
    }
    Ok(subject_cn)
}

fn ensure_single_issuer_cn_equals_subject_cn(
    x509_cert: &X509Certificate,
    subject_cn: &str,
) -> Result<(), TlsCertValidationError> {
    let issuer_cn = single_cn_as_str(x509_cert.issuer()).map_err(|e| {
        invalid_tls_certificate_error(format!("invalid issuer common name (CN): {}", e))
    })?;
    if issuer_cn != subject_cn {
        return Err(invalid_tls_certificate_error(
            "issuer common name (CN) does not match subject common name (CN)",
        ));
    }
    Ok(())
}

fn ensure_not_ca(x509_cert: &X509Certificate) -> Result<(), TlsCertValidationError> {
    if x509_cert.tbs_certificate.is_ca() {
        Err(invalid_tls_certificate_error("BasicConstraints:CA is True"))
    } else {
        Ok(())
    }
}

#[cfg(target_arch = "wasm32")]
fn utc_now() -> DateTime<Utc> {
    DateTime::<Utc>::from(dfn_core::api::now())
}

#[cfg(not(target_arch = "wasm32"))]
fn utc_now() -> DateTime<Utc> {
    Utc::now()
}

fn ensure_notbefore_date_is_latest_in_two_minutes_from_now(
    x509_cert: &X509Certificate,
) -> Result<(), TlsCertValidationError> {
    let now = utc_now();
    let two_min_from_now = now + Duration::minutes(2);
    let two_min_from_now_asn1 = ASN1Time::from_timestamp(two_min_from_now.timestamp());

    if x509_cert.validity().not_before > two_min_from_now_asn1 {
        return Err(invalid_tls_certificate_error(format!(
            "notBefore date(={:?}) is later than two minutes from now(={})",
            x509_cert.validity().not_before,
            now
        )));
    }
    Ok(())
}

fn ensure_notafter_date_equals_99991231235959z(
    x509_cert: &X509Certificate,
) -> Result<(), TlsCertValidationError> {
    if x509_cert.validity().not_after.to_rfc2822() != "Fri, 31 Dec 9999 23:59:59 +0000" {
        println!("{}", x509_cert.validity().not_after.to_rfc2822());
        return Err(invalid_tls_certificate_error(
            "notAfter date is not RFC 5280 value 99991231235959Z",
        ));
    }
    Ok(())
}

fn ensure_signature_algorithm_is_ed25519(
    x509_cert: &X509Certificate,
) -> Result<(), TlsCertValidationError> {
    if x509_cert.signature_algorithm.algorithm.to_id_string() != "1.3.101.112" {
        return Err(invalid_tls_certificate_error(
            "signature algorithm is not Ed25519 (OID 1.3.101.112)",
        ));
    }
    Ok(())
}

fn single_cn_as_str<'a>(name: &'a X509Name<'_>) -> Result<&'a str, String> {
    let mut cn_iter = name.iter_common_name();
    let first_cn_str = cn_iter
        .next()
        .ok_or("missing common name (CN)")?
        .as_str()
        .map_err(|e| format!("common name (CN) not a string: {:?}", e))?;
    if cn_iter.next() != None {
        return Err("found second common name (CN) entry, but expected a single one".to_string());
    }
    Ok(first_cn_str)
}

fn ed25519_pubkey_from_x509_cert(
    x509_cert: &X509Certificate,
) -> Result<BasicSigEd25519PublicKeyBytes, TlsCertValidationError> {
    BasicSigEd25519PublicKeyBytes::try_from(
        &x509_cert
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .to_vec(),
    )
    .map_err(|e| {
        invalid_tls_certificate_error(format!("conversion to Ed25519 public key failed: {}", e))
    })
}

fn verify_ed25519_public_key(
    public_key: &BasicSigEd25519PublicKeyBytes,
) -> Result<(), TlsCertValidationError> {
    if !ic_crypto_internal_basic_sig_ed25519::verify_public_key(public_key) {
        return Err(invalid_tls_certificate_error(
            "public key verification failed",
        ));
    }
    Ok(())
}

/// Verifies the signature of the given X509 certificate w.r.t. the
/// given `public_key`.
///
/// We use our own crypto library rather than
/// `x509_parser::certificate::X509Certificate::verify_signature` because the
/// `x509_parser` currently does not support Ed25519 signature verification.
///
/// See https://docs.rs/x509-parser/0.9.1/src/x509_parser/certificate.rs.html#153-183
/// to compare which fields the `x509_parser` crate uses from the `x509_cert`
/// for verifying the signature.
/// Additionally, see https://tools.ietf.org/html/rfc3280#section-4.1.1.3 for the
/// specification on how to verify the signature.
fn verify_ed25519_signature(
    x509_cert: &X509Certificate,
    public_key: &BasicSigEd25519PublicKeyBytes,
) -> CryptoResult<()> {
    let sig = BasicSigEd25519SignatureBytes::try_from(&x509_cert.signature_value.data.to_vec())?;
    let msg = x509_cert.tbs_certificate.as_ref();
    ic_crypto_internal_basic_sig_ed25519::verify(&sig, msg, public_key)
}

fn invalid_tls_certificate_error<S: Into<String>>(internal_error: S) -> TlsCertValidationError {
    TlsCertValidationError {
        error: format!("invalid TLS certificate: {}", internal_error.into()),
    }
}

/// A TLS cert validation error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsCertValidationError {
    pub error: String,
}

impl fmt::Display for TlsCertValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
