use crate::tls_stub::{
    node_id_from_cert_subject_common_name, tls_cert_from_registry, TlsCertFromRegistryError,
};
use ic_crypto_internal_csp::api::CspTlsClientHandshake;
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_crypto_tls_interfaces::{
    MalformedPeerCertificateError, PeerNotAllowedError, TlsClientHandshakeError, TlsStream,
};
use ic_interfaces::registry::RegistryClient;
use ic_types::{NodeId, RegistryVersion};
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
    let self_tls_cert = tls_cert_from_registry(registry_client, self_node_id, registry_version)
        .map_err(|e| map_cert_from_registry_error(e, CertFromRegistryOwner::Myself))?;
    let trusted_server_cert = tls_cert_from_registry(registry_client, server, registry_version)
        .map_err(|e| map_cert_from_registry_error(e, CertFromRegistryOwner::Server))?;

    let (tls_stream, peer_cert) = csp
        .perform_tls_client_handshake(tcp_stream, self_tls_cert, trusted_server_cert.clone())
        .await?;

    check_cert(server, &trusted_server_cert, &peer_cert)?;
    Ok(tls_stream)
}

fn check_cert(
    trusted_server_node_id: NodeId,
    trusted_server_cert_from_registry: &TlsPublicKeyCert,
    server_cert_from_handshake: &TlsPublicKeyCert,
) -> Result<(), TlsClientHandshakeError> {
    let server_node_id_from_handshake_cert =
        node_id_from_cert_subject_common_name(&server_cert_from_handshake)?;
    if server_node_id_from_handshake_cert != trusted_server_node_id {
        return Err(TlsClientHandshakeError::ServerNotAllowed(
            PeerNotAllowedError::HandshakeCertificateNodeIdNotAllowed,
        ));
    }
    if server_cert_from_handshake != trusted_server_cert_from_registry {
        return Err(TlsClientHandshakeError::ServerNotAllowed(
            PeerNotAllowedError::CertificatesDiffer,
        ));
    }

    Ok(())
}

enum CertFromRegistryOwner {
    Server,
    Myself,
}

fn map_cert_from_registry_error(
    registry_error: TlsCertFromRegistryError,
    peer: CertFromRegistryOwner,
) -> TlsClientHandshakeError {
    match (registry_error, peer) {
        (TlsCertFromRegistryError::RegistryError(e), _) => {
            TlsClientHandshakeError::RegistryError(e)
        }
        (
            TlsCertFromRegistryError::CertificateNotInRegistry {
                node_id,
                registry_version,
            },
            _,
        ) => TlsClientHandshakeError::CertificateNotInRegistry {
            node_id,
            registry_version,
        },
        (
            TlsCertFromRegistryError::CertificateMalformed { internal_error },
            CertFromRegistryOwner::Server,
        ) => TlsClientHandshakeError::MalformedServerCertificate(MalformedPeerCertificateError {
            internal_error,
        }),
        (
            TlsCertFromRegistryError::CertificateMalformed { internal_error },
            CertFromRegistryOwner::Myself,
        ) => TlsClientHandshakeError::MalformedSelfCertificate { internal_error },
    }
}
