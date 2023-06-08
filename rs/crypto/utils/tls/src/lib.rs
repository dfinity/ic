#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

use std::str::FromStr;

use ic_base_types::{NodeId, PrincipalId};
use ic_crypto_tls_interfaces::{MalformedPeerCertificateError, TlsPublicKeyCert};
use openssl::{
    nid::Nid,
    string::OpensslString,
    x509::{X509NameEntries, X509NameEntryRef},
};
use tokio_rustls::rustls::{Certificate, CertificateError, Error};

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
    let common_name_entry = ensure_exactly_one_subject_common_name_entry(cert)?;
    let common_name = common_name_entry_as_string(common_name_entry)?;
    let principal_id = parse_principal_id(common_name)?;
    Ok(NodeId::from(principal_id))
}

fn ensure_exactly_one_subject_common_name_entry(
    cert: &TlsPublicKeyCert,
) -> Result<&X509NameEntryRef, MalformedPeerCertificateError> {
    if common_name_entries(cert).count() > 1 {
        return Err(MalformedPeerCertificateError::new(
            "Too many X509NameEntryRefs",
        ));
    }
    common_name_entries(cert)
        .next()
        .ok_or_else(|| MalformedPeerCertificateError::new("Missing X509NameEntryRef"))
}

fn common_name_entry_as_string(
    common_name_entry: &X509NameEntryRef,
) -> Result<OpensslString, MalformedPeerCertificateError> {
    common_name_entry.data().as_utf8().map_err(|e| {
        MalformedPeerCertificateError::new(&format!("ASN1 to UTF-8 conversion error: {}", e))
    })
}

fn parse_principal_id(
    common_name: OpensslString,
) -> Result<PrincipalId, MalformedPeerCertificateError> {
    PrincipalId::from_str(common_name.as_ref()).map_err(|e| {
        MalformedPeerCertificateError::new(&format!("Principal ID parse error: {}", e))
    })
}

fn common_name_entries(cert: &TlsPublicKeyCert) -> X509NameEntries {
    cert.as_x509()
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
}
