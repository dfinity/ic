use crate::tls::rustls::csp_server_signing_key::CspServerEd25519SigningKey;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use rustls::{pki_types::CertificateDer, sign::CertifiedKey};
use std::sync::Arc;

mod cert_resolver;
pub mod client_handshake;
mod csp_server_signing_key;
mod node_cert_verifier;
pub mod server_handshake;

fn certified_key(
    self_tls_cert: TlsPublicKeyCert,
    csp_server_signing_key: CspServerEd25519SigningKey,
) -> CertifiedKey {
    CertifiedKey {
        cert: vec![CertificateDer::from(self_tls_cert.as_der().clone())],
        key: Arc::new(csp_server_signing_key),
        ocsp: None,
    }
}
