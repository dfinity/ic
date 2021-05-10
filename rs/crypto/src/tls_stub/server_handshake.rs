use crate::tls_stub::{
    ensure_certificates_equal, node_id_from_cert_subject_common_name, tls_cert_from_registry,
    TlsCertFromRegistryError,
};
use ic_crypto_internal_csp::api::CspTlsServerHandshake;
use ic_crypto_internal_csp::tls_stub::cert_chain::CspCertificateChain;
use ic_crypto_tls_interfaces::{
    AllowedClients, AuthenticatedPeer, Peer, PeerNotAllowedError, SomeOrAllNodes,
    TlsServerHandshakeError, TlsStream,
};
use ic_interfaces::registry::RegistryClient;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_registry_client::helper::node::NodeRegistry;
use ic_types::{NodeId, RegistryVersion};
use openssl::x509::X509;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use tokio::net::TcpStream;

// TODO (CRP-772): Simplify handshake code by moving cert equality check to CSP
// TODO (CRP-773): Use X509 domain object instead of protobuf in API
pub async fn perform_tls_server_handshake<C: CspTlsServerHandshake>(
    csp: &C,
    self_node_id: NodeId,
    registry_client: &Arc<dyn RegistryClient>,
    tcp_stream: TcpStream,
    allowed_clients: AllowedClients,
    registry_version: RegistryVersion,
) -> Result<(TlsStream, AuthenticatedPeer), TlsServerHandshakeError> {
    let (tls_stream, peer) = perform_tls_server_handshake_temp_with_optional_client_auth(
        csp,
        self_node_id,
        registry_client,
        tcp_stream,
        allowed_clients,
        registry_version,
    )
    .await?;
    match peer {
        Peer::Authenticated(peer) => Ok((tls_stream, peer)),
        Peer::Unauthenticated => Err(TlsServerHandshakeError::UnauthenticatedClient),
    }
}

pub async fn perform_tls_server_handshake_temp_with_optional_client_auth<
    C: CspTlsServerHandshake,
>(
    csp: &C,
    self_node_id: NodeId,
    registry_client: &Arc<dyn RegistryClient>,
    tcp_stream: TcpStream,
    allowed_authenticating_clients: AllowedClients,
    registry_version: RegistryVersion,
) -> Result<(TlsStream, Peer), TlsServerHandshakeError> {
    let self_tls_cert = tls_cert_from_registry(registry_client, self_node_id, registry_version)?;
    let trusted_node_certs = tls_certs_from_registry(
        registry_client,
        &allowed_authenticating_clients.nodes(),
        registry_version,
    )?;
    let trusted_client_certs =
        combine_certs(&trusted_node_certs, allowed_authenticating_clients.certs());

    let (tls_stream, peer_cert_chain) = csp
        .perform_tls_server_handshake(tcp_stream, self_tls_cert, trusted_client_certs)
        .await?;

    match peer_cert_chain {
        Some(peer_cert_chain) => {
            let peer = authenticated_peer(
                &peer_cert_chain,
                &allowed_authenticating_clients.certs(),
                &trusted_node_certs,
            )?;
            Ok((tls_stream, Peer::Authenticated(peer)))
        }
        None => Ok((tls_stream, Peer::Unauthenticated)),
    }
}

fn tls_certs_from_registry(
    registry_client: &Arc<dyn RegistryClient>,
    nodes: &SomeOrAllNodes,
    registry_version: RegistryVersion,
) -> Result<BTreeMap<NodeId, X509PublicKeyCert>, TlsCertFromRegistryError> {
    match nodes {
        SomeOrAllNodes::Some(nodes) => {
            tls_certs_from_registry_for_nodes(nodes, registry_client, registry_version)
        }
        SomeOrAllNodes::All => {
            let all_nodes = registry_client
                .get_node_ids(registry_version)?
                .into_iter()
                .collect();
            tls_certs_from_registry_for_nodes(&all_nodes, registry_client, registry_version)
        }
    }
}

fn tls_certs_from_registry_for_nodes(
    allowed_clients: &BTreeSet<NodeId>,
    registry_client: &Arc<dyn RegistryClient>,
    registry_version: RegistryVersion,
) -> Result<BTreeMap<NodeId, X509PublicKeyCert>, TlsCertFromRegistryError> {
    let mut node_id_to_cert = BTreeMap::new();
    for client in allowed_clients {
        node_id_to_cert.insert(
            *client,
            tls_cert_from_registry(registry_client, *client, registry_version)?,
        );
    }
    Ok(node_id_to_cert)
}

fn combine_certs(
    node_certs: &BTreeMap<NodeId, X509PublicKeyCert>,
    certs: &[X509PublicKeyCert],
) -> Vec<X509PublicKeyCert> {
    let mut node_certs_and_certs: Vec<_> = node_certs.values().cloned().collect();
    node_certs_and_certs.extend(certs.iter().cloned());
    node_certs_and_certs
}

/// Determines the authenticated peer from the client's certificate chain.
///
/// To do so, the following steps are taken:
/// 1. Determine the peer's node ID N_claimed from the _subject name_ of
///    the certificate C_handshake that the peer presented during the
///    handshake (and for which the peer therefore knows the private key).
///    If N_claimed is contained in `trusted_node_certs`, determine the
///    certificate C_registry by querying the registry for the TLS certificate
///    of node with ID N_claimed, and if C_registry is equal to C_handshake,
///    then the peer successfully authenticated as node N_claimed. Otherwise,
///    step 2 is taken.
/// 2. Compare the root of the certificate chain that the peer presented during
///    the handshake (and for which the peer therefore knows the private key of
///    the chain's leaf certificate) to all the certificates in
///    `allowed_client_certs`. If there is a match, then the peer represented by
///    the chain's leaf certificate successfully authenticated.
///
/// If neither an authenticated node nor an authenticated certificate can be
/// determined, then the error produced when trying to authenticate a node is
/// returned.
fn authenticated_peer(
    client_cert_chain_from_handshake: &CspCertificateChain,
    allowed_client_certs: &[X509PublicKeyCert],
    trusted_node_certs: &BTreeMap<NodeId, X509PublicKeyCert>,
) -> Result<AuthenticatedPeer, TlsServerHandshakeError> {
    let authenticated_node = check_cert_and_get_authenticated_client_node_id(
        trusted_node_certs,
        &client_cert_chain_from_handshake.leaf(),
    );
    match authenticated_node {
        Ok(authenticated_node) => Ok(AuthenticatedPeer::Node(authenticated_node)),
        Err(node_authentication_error) => {
            let client_cert_chain_root_from_handshake_proto =
                x509_to_proto(&client_cert_chain_from_handshake.root())?;
            if allowed_client_certs
                .iter()
                .any(|cert| cert == &client_cert_chain_root_from_handshake_proto)
            {
                Ok(AuthenticatedPeer::Cert(x509_to_proto(
                    &client_cert_chain_from_handshake.leaf(),
                )?))
            } else {
                Err(node_authentication_error)
            }
        }
    }
}

fn x509_to_proto(cert: &X509) -> Result<X509PublicKeyCert, TlsServerHandshakeError> {
    Ok(X509PublicKeyCert {
        certificate_der: cert
            .to_der()
            .map_err(|e| TlsServerHandshakeError::HandshakeError {
                internal_error: format!("failed to DER-encode peer certificate {:?}: {}", cert, e),
            })?,
    })
}

fn check_cert_and_get_authenticated_client_node_id(
    trusted_node_certs: &BTreeMap<NodeId, X509PublicKeyCert>,
    client_cert_from_handshake: &X509,
) -> Result<NodeId, TlsServerHandshakeError> {
    let client_node_id_from_handshake_cert =
        node_id_from_cert_subject_common_name(&client_cert_from_handshake)?;
    let trusted_client_cert_from_registry =
        cert_for_node_id(client_node_id_from_handshake_cert, trusted_node_certs)?;
    ensure_certificates_equal(
        &client_cert_from_handshake,
        trusted_client_cert_from_registry,
    )?;
    Ok(client_node_id_from_handshake_cert)
}

fn cert_for_node_id(
    claimed_node_id_from_handshake_cert: NodeId,
    trusted_node_certs: &BTreeMap<NodeId, X509PublicKeyCert>,
) -> Result<X509PublicKeyCert, TlsServerHandshakeError> {
    trusted_node_certs
        .get(&claimed_node_id_from_handshake_cert)
        .cloned()
        .ok_or(TlsServerHandshakeError::ClientNotAllowed(
            PeerNotAllowedError::HandshakeCertificateNodeIdNotAllowed,
        ))
}

impl From<TlsCertFromRegistryError> for TlsServerHandshakeError {
    fn from(cert_from_registry_error: TlsCertFromRegistryError) -> Self {
        match cert_from_registry_error {
            TlsCertFromRegistryError::RegistryError(e) => TlsServerHandshakeError::RegistryError(e),
            TlsCertFromRegistryError::CertificateNotInRegistry {
                node_id,
                registry_version,
            } => TlsServerHandshakeError::CertificateNotInRegistry {
                node_id,
                registry_version,
            },
        }
    }
}
