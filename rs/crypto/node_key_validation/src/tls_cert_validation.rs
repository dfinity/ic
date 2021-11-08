use super::*;
use chrono::{DateTime, Duration, Utc};
use ic_crypto_internal_basic_sig_ed25519::types::PublicKeyBytes as BasicSigEd25519PublicKeyBytes;
use ic_crypto_internal_basic_sig_ed25519::types::SignatureBytes as BasicSigEd25519SignatureBytes;
use ic_types::crypto::CryptoResult;
use x509_parser::certificate::X509Certificate;
use x509_parser::time::ASN1Time;
use x509_parser::x509::{X509Name, X509Version};

/// Validates a node's TLS certificate.
///
/// See the crate documentation for the exact checks that are performed.
pub fn validate_tls_certificate(
    tls_certificate: &Option<X509PublicKeyCert>,
    node_id: NodeId,
) -> Result<(), KeyValidationError> {
    let cert = tls_certificate
        .as_ref()
        .ok_or_else(|| invalid_tls_certificate_error("certificate is missing"))?;

    let x509_cert = parse_x509_v3_certificate(&cert.certificate_der)?;
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
) -> Result<&'a str, KeyValidationError> {
    single_cn_as_str(x509_cert.subject()).map_err(|e| {
        invalid_tls_certificate_error(format!("invalid subject common name (CN): {}", e))
    })
}

fn parse_x509_v3_certificate(
    certificate_der: &[u8],
) -> Result<X509Certificate, KeyValidationError> {
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
) -> Result<&str, KeyValidationError> {
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
) -> Result<(), KeyValidationError> {
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

fn ensure_not_ca(x509_cert: &X509Certificate) -> Result<(), KeyValidationError> {
    if x509_cert.tbs_certificate.is_ca() {
        Err(invalid_tls_certificate_error("BasicConstraints:CA is True"))
    } else {
        Ok(())
    }
}

fn ensure_notbefore_date_is_latest_in_two_minutes_from_now(
    x509_cert: &X509Certificate,
) -> Result<(), KeyValidationError> {
    let now = DateTime::<Utc>::from(dfn_core::api::now());
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
) -> Result<(), KeyValidationError> {
    if x509_cert.validity().not_after.to_rfc2822() != "Fri, 31 Dec 9999 23:59:59 +0000" {
        return Err(invalid_tls_certificate_error(
            "notAfter date is not RFC 5280's 99991231235959Z",
        ));
    }
    Ok(())
}

fn ensure_signature_algorithm_is_ed25519(
    x509_cert: &X509Certificate,
) -> Result<(), KeyValidationError> {
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
) -> Result<BasicSigEd25519PublicKeyBytes, KeyValidationError> {
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
) -> Result<(), KeyValidationError> {
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

fn invalid_tls_certificate_error<S: Into<String>>(internal_error: S) -> KeyValidationError {
    KeyValidationError {
        error: format!("invalid TLS certificate: {}", internal_error.into()),
    }
}
