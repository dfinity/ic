//! Useful utilities for dealing with TLS handshakes in the IC.
//!
//! Function signatures in this crate
//! should include only primitive or local types. Avoid using 'rustls' types.
//! Otherwise upgrading 'rustls' requires upgrading all callers.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

use std::str::FromStr;

use ic_base_types::{NodeId, PrincipalId};
use thiserror::Error;
use x509_parser::certificate::X509Certificate;

#[derive(Debug, Error)]
pub enum NodeIdFromCertificateDerError {
    /// The passed certificate could not be decoded.
    #[error("Invalid der encoded certificate: `{0}`.")]
    InvalidCertificate(String),
    /// Unexpected content in the certificate. This signals an application error.
    #[error("Invalid content in the certificate: `{0}`.")]
    UnexpectedContent(String),
}

/// Tries to extract a single NodeId from a Rustls certificate chain.
///
/// # Errors
///
/// Fails if
/// * the chain is empty or contains more than one certificate
/// * the single certificate in the chain does not have the expected
///   format (e.g., invalid DER, not just a single subject common name,
///   invalid principal)
pub fn node_id_from_certificate_der(
    certificate_der: &[u8],
) -> Result<NodeId, NodeIdFromCertificateDerError> {
    let (remainder, x509_cert) = x509_parser::parse_x509_certificate(certificate_der)
        .map_err(|err| NodeIdFromCertificateDerError::InvalidCertificate(format!("{err}")))?;
    if !remainder.is_empty() {
        return Err(NodeIdFromCertificateDerError::InvalidCertificate(
            "Input remains after parsing.".to_string(),
        ));
    }

    let subject_cn = single_subject_cn_as_str(&x509_cert)?;
    let principal_id = PrincipalId::from_str(subject_cn)
        .map_err(|err| NodeIdFromCertificateDerError::UnexpectedContent(format!("{err}")))?;

    Ok(NodeId::from(principal_id))
}

fn single_subject_cn_as_str<'a>(
    x509_cert: &'a X509Certificate,
) -> Result<&'a str, NodeIdFromCertificateDerError> {
    let name = x509_cert.subject();
    let mut cn_iter = name.iter_common_name();
    let first_cn_str = cn_iter
        .next()
        .ok_or(NodeIdFromCertificateDerError::UnexpectedContent(
            "Missing common name (CN)".to_string(),
        ))?
        .as_str()
        .map_err(|err| NodeIdFromCertificateDerError::UnexpectedContent(format!("{err}")))?;
    if cn_iter.next().is_some() {
        return Err(NodeIdFromCertificateDerError::UnexpectedContent(
            "found second common name (CN) entry, but expected a single one".to_string(),
        ));
    }
    Ok(first_cn_str)
}
