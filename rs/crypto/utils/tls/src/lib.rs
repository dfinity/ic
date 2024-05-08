#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

use std::{str::FromStr, sync::Arc};

use ic_base_types::{NodeId, PrincipalId};
use rustls::{Certificate, CertificateError};
use x509_parser::certificate::X509Certificate;

/// Tries to extract a single NodeId from a Rustls certificate chain.
///
/// # Errors
///
/// Fails if
/// * the chain is empty or contains more than one certificate
/// * the single certificate in the chain does not have the expected
///   format (e.g., invalid DER, not just a single subject common name,
///   invalid principal)
pub fn node_id_from_rustls_certs(cert: &Certificate) -> Result<NodeId, CertificateError> {
    let (remainder, x509_cert) =
        x509_parser::parse_x509_certificate(&cert.0).map_err(|_| CertificateError::BadEncoding)?;
    if !remainder.is_empty() {
        return Err(CertificateError::BadEncoding);
    }

    let subject_cn = single_subject_cn_as_str(&x509_cert)?;
    let principal_id =
        PrincipalId::from_str(subject_cn).map_err(|err| CertificateError::Other(Arc::from(err)))?;

    Ok(NodeId::from(principal_id))
}

fn single_subject_cn_as_str<'a>(
    x509_cert: &'a X509Certificate,
) -> Result<&'a str, CertificateError> {
    let name = x509_cert.subject();
    let mut cn_iter = name.iter_common_name();
    let first_cn_str = cn_iter
        .next()
        .ok_or(CertificateError::Other(Arc::from(Box::from(
            "missing common name (CN)".to_string(),
        ))))?
        .as_str()
        .map_err(|err| CertificateError::Other(Arc::from(err)))?;
    if cn_iter.next().is_some() {
        return Err(CertificateError::Other(Arc::from(Box::from(
            "found second common name (CN) entry, but expected a single one".to_string(),
        ))));
    }
    Ok(first_cn_str)
}
