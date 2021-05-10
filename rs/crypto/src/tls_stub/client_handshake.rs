use crate::tls_stub::{
    ensure_certificates_equal, node_id_from_cert_subject_common_name, tls_cert_from_registry,
    TlsCertFromRegistryError,
};
use ic_crypto_internal_csp::api::CspTlsClientHandshake;
use ic_crypto_tls_interfaces::{PeerNotAllowedError, TlsClientHandshakeError, TlsStream};
use ic_interfaces::registry::RegistryClient;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_types::{NodeId, RegistryVersion};
use openssl::x509::X509;
use std::sync::Arc;
use tokio::net::TcpStream;

pub async fn perform_tls_client_handshake<C: CspTlsClientHandshake>(
    csp: &C,
    self_node_id: NodeId,
    registry_client: &Arc<dyn RegistryClient>,
    tcp_stream: TcpStream,
    server: NodeId,
    registry_version: RegistryVersion,
) -> Result<TlsStream, TlsClientHandshakeError> {
    let self_tls_cert = tls_cert_from_registry(registry_client, self_node_id, registry_version)?;
    let trusted_server_cert = tls_cert_from_registry(registry_client, server, registry_version)?;

    let (tls_stream, peer_cert) = csp
        .perform_tls_client_handshake(tcp_stream, self_tls_cert, trusted_server_cert.clone())
        .await?;

    check_cert(server, trusted_server_cert, &peer_cert)?;
    Ok(tls_stream)
}

fn check_cert(
    trusted_server_node_id: NodeId,
    trusted_server_cert_from_registry: X509PublicKeyCert,
    server_cert_from_handshake: &X509,
) -> Result<(), TlsClientHandshakeError> {
    let server_node_id_from_handshake_cert =
        node_id_from_cert_subject_common_name(&server_cert_from_handshake)?;
    if server_node_id_from_handshake_cert != trusted_server_node_id {
        return Err(TlsClientHandshakeError::ServerNotAllowed(
            PeerNotAllowedError::HandshakeCertificateNodeIdNotAllowed,
        ));
    }
    ensure_certificates_equal(
        server_cert_from_handshake,
        trusted_server_cert_from_registry,
    )?;
    Ok(())
}

impl From<TlsCertFromRegistryError> for TlsClientHandshakeError {
    fn from(registry_error: TlsCertFromRegistryError) -> Self {
        match registry_error {
            TlsCertFromRegistryError::RegistryError(e) => TlsClientHandshakeError::RegistryError(e),
            TlsCertFromRegistryError::CertificateNotInRegistry {
                node_id,
                registry_version,
            } => TlsClientHandshakeError::CertificateNotInRegistry {
                node_id,
                registry_version,
            },
        }
    }
}
