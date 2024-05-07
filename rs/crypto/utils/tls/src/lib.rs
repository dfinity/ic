#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

use std::str::FromStr;

use ic_base_types::{NodeId, PrincipalId};
use ic_crypto_tls_interfaces::{MalformedPeerCertificateError, TlsPublicKeyCert};
use rustls::{Certificate, CertificateError, Error};
use x509_parser::certificate::X509Certificate;
use x509_parser::x509::X509Name;

/// Parses rustls Certificates to `TlsPublicKeyCert`.
/// Certificate is considered well encoded iff:
///     - It contains exactly one cert.
///     - The certificate is X509 DER formatted.
pub fn tls_pubkey_cert_from_rustls_certs(certs: &[Certificate]) -> Result<TlsPublicKeyCert, Error> {
    if certs.len() > 1 {
        return Err(Error::General(
            "peer sent more than one certificate, but expected only a single one".to_string(),
        ));
    }
    let end_entity = certs.first().ok_or(Error::NoCertificatesPresented)?;
    let tls_cert = TlsPublicKeyCert::new_from_der(end_entity.0.clone())
        .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
    Ok(tls_cert)
}

/// Extracts the NodeId from a tls certificate iff:
///     - There is exactly one name entry.
///     - The name entry is parsable into a principal id.
pub fn node_id_from_cert_subject_common_name(
    cert: &TlsPublicKeyCert,
) -> Result<NodeId, MalformedPeerCertificateError> {
    let x509_cert = parse_x509_certificate(cert.as_der())?;
    let subject_cn = single_subject_cn_as_str(&x509_cert)?;
    let principal_id = parse_principal_id(subject_cn)?;
    Ok(NodeId::from(principal_id))
}

fn parse_x509_certificate(
    certificate_der: &[u8],
) -> Result<X509Certificate, MalformedPeerCertificateError> {
    let (remainder, x509_cert) =
        x509_parser::parse_x509_certificate(certificate_der).map_err(|e| {
            MalformedPeerCertificateError::new(&format!("failed to parse DER: {:?}", e))
        })?;
    if !remainder.is_empty() {
        return Err(MalformedPeerCertificateError::new(&format!(
            "DER not fully consumed when parsing. Remainder: {remainder:?}",
        )));
    }
    Ok(x509_cert)
}

fn single_subject_cn_as_str<'a>(
    x509_cert: &'a X509Certificate,
) -> Result<&'a str, MalformedPeerCertificateError> {
    single_cn_as_str(x509_cert.subject()).map_err(|e| {
        MalformedPeerCertificateError::new(&format!("invalid subject common name (CN): {}", e))
    })
}

fn single_cn_as_str<'a>(name: &'a X509Name<'_>) -> Result<&'a str, String> {
    let mut cn_iter = name.iter_common_name();
    let first_cn_str = cn_iter
        .next()
        .ok_or("missing common name (CN)")?
        .as_str()
        .map_err(|e| format!("common name (CN) not a string: {:?}", e))?;
    if cn_iter.next().is_some() {
        return Err("found second common name (CN) entry, but expected a single one".to_string());
    }
    Ok(first_cn_str)
}

fn parse_principal_id(common_name: &str) -> Result<PrincipalId, MalformedPeerCertificateError> {
    PrincipalId::from_str(common_name).map_err(|e| {
        MalformedPeerCertificateError::new(&format!("Principal ID parse error: {}", e))
    })
}
