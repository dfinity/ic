use std::{sync::Arc, time::SystemTime};

use arc_swap::ArcSwapOption;
use ic_crypto_utils_tls::{
    node_id_from_cert_subject_common_name, tls_pubkey_cert_from_rustls_certs,
};
use rustls::{
    client::{ServerCertVerified, ServerCertVerifier},
    Certificate, CertificateError, Error as RustlsError, ServerName,
};
use x509_parser::{
    prelude::{FromDer, X509Certificate},
    time::ASN1Time,
};

use crate::snapshot::RegistrySnapshot;

pub struct TlsVerifier {
    rs: Arc<ArcSwapOption<RegistrySnapshot>>,
    skip_verification: bool,
}

impl TlsVerifier {
    pub fn new(rs: Arc<ArcSwapOption<RegistrySnapshot>>, skip_verification: bool) -> Self {
        Self {
            rs,
            skip_verification,
        }
    }
}

// Implement the certificate verifier which ensures that the certificate
// that was provided by node during TLS handshake matches its public key from the registry
// This trait is used by Rustls in reqwest under the hood
impl ServerCertVerifier for TlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        now: SystemTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if self.skip_verification {
            return Ok(ServerCertVerified::assertion());
        }

        if !intermediates.is_empty() {
            return Err(RustlsError::General(format!(
                "The peer must send exactly one self signed certificate, but it sent {} certificates.",
                intermediates.len() + 1
            )));
        }

        // Check if the CommonName in the certificate can be parsed into a Principal
        let end_entity_cert = tls_pubkey_cert_from_rustls_certs(std::slice::from_ref(end_entity))?;
        let node_id = node_id_from_cert_subject_common_name(&end_entity_cert).map_err(|e| {
            RustlsError::General(format!(
                "The presented certificate subject CN could not be parsed as node ID: {:?}",
                e
            ))
        })?;

        // Load a routing table if we have one
        let rs = self
            .rs
            .load_full()
            .ok_or_else(|| RustlsError::General("no routing table published".into()))?;

        // Look up a node in the routing table based on the hostname provided by rustls
        let node = match server_name {
            // Currently support only DnsName
            ServerName::DnsName(v) => {
                // Check if certificate CommonName matches the DNS name
                if node_id.to_string() != v.as_ref() {
                    return Err(RustlsError::InvalidCertificate(
                        CertificateError::NotValidForName,
                    ));
                }

                match rs.nodes.get(v.as_ref()) {
                    // If the requested node is not in the routing table
                    None => {
                        return Err(RustlsError::General(format!(
                            "Node '{}' not found in a routing table",
                            v.as_ref()
                        )));
                    }

                    // Found
                    Some(v) => v,
                }
            }

            // Unsupported for now, can be removed later if not needed at all
            ServerName::IpAddress(_) => return Err(RustlsError::UnsupportedNameType),

            // Enum is marked non_exhaustive
            &_ => return Err(RustlsError::UnsupportedNameType),
        };

        // Cert is parsed & checked when we read it from the registry - if we got here then it's correct
        // It's a zero-copy view over byte array
        // Storing X509Certificate directly in Node is problematic since it does not own the data
        let (_, node_cert) = X509Certificate::from_der(&node.tls_certificate).unwrap();

        // Parse the certificate provided by server
        let (_, provided_cert) = X509Certificate::from_der(&end_entity.0)
            .map_err(|_x| RustlsError::InvalidCertificate(CertificateError::BadEncoding))?;

        // Verify the provided self-signed certificate using the public key from registry
        let node_tls_pubkey_from_registry = ic_crypto_ed25519::PublicKey::deserialize_raw(
            &node_cert
                .tbs_certificate
                .subject_pki
                .subject_public_key
                .data,
        )
        .map_err(|e| {
            RustlsError::InvalidCertificate(CertificateError::Other(Arc::from(Box::from(format!(
                "node cert: invalid Ed25519 public key: {e:?}",
            )))))
        })?;

        let provided_cert_sig =
            <[u8; 64]>::try_from(provided_cert.signature_value.data.as_ref()).map_err(|e| {
                RustlsError::InvalidCertificate(CertificateError::Other(Arc::from(Box::from(
                    format!("node cert: invalid Ed25519 signature: {:?}", e),
                ))))
            })?;

        node_tls_pubkey_from_registry
            .verify_signature(provided_cert.tbs_certificate.as_ref(), &provided_cert_sig)
            .map_err(|_x| RustlsError::InvalidCertificate(CertificateError::BadSignature))?;

        // Check if the certificate is valid at provided `now` time
        if !provided_cert.validity.is_valid_at(
            ASN1Time::from_timestamp(
                now.duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64,
            )
            .unwrap(),
        ) {
            return Err(RustlsError::InvalidCertificate(CertificateError::Expired));
        }

        Ok(ServerCertVerified::assertion())
    }
}

#[cfg(test)]
pub mod test;
