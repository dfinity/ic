use crate::tls_stub::{
    node_id_from_cert_subject_common_name, tls_cert_from_registry, TlsCertFromRegistryError,
};
use ic_crypto_internal_csp::api::CspTlsServerHandshake;
use ic_crypto_internal_csp::tls_stub::cert_chain::CspCertificateChain;
use ic_crypto_tls_interfaces::{
    AllowedClients, AuthenticatedPeer, MalformedPeerCertificateError, Peer, PeerNotAllowedError,
    SomeOrAllNodes, TlsPublicKeyCert, TlsServerHandshakeError, TlsStream,
};
use ic_interfaces::registry::RegistryClient;
use ic_registry_client_helpers::node::NodeRegistry;
use ic_types::{NodeId, RegistryVersion};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;
use tokio::net::TcpStream;

// TODO (CRP-772): Simplify handshake code by moving cert equality check to CSP
#[allow(unused)]
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
    let self_tls_cert = tls_cert_from_registry(registry_client, self_node_id, registry_version)
        .map_err(|e| map_cert_from_registry_error(e, CertFromRegistryOwner::Myself))?;
    let trusted_node_certs = tls_certs_from_registry(
        registry_client,
        allowed_authenticating_clients.nodes(),
        registry_version,
    )
    .map_err(|e| map_cert_from_registry_error(e, CertFromRegistryOwner::Client))?;
    let trusted_client_certs =
        combine_certs(&trusted_node_certs, allowed_authenticating_clients.certs());

    let (tls_stream, peer_cert_chain) = csp
        .perform_tls_server_handshake(tcp_stream, self_tls_cert, trusted_client_certs)
        .await?;

    match peer_cert_chain {
        Some(peer_cert_chain) => {
            let peer = authenticated_peer(
                &peer_cert_chain,
                allowed_authenticating_clients.certs(),
                &trusted_node_certs,
            )?;
            Ok((tls_stream, Peer::Authenticated(peer)))
        }
        None => Ok((tls_stream, Peer::Unauthenticated)),
    }
}

#[allow(unused)]
pub async fn perform_tls_server_handshake_without_client_auth<C: CspTlsServerHandshake>(
    csp: &C,
    self_node_id: NodeId,
    registry_client: &Arc<dyn RegistryClient>,
    tcp_stream: TcpStream,
    registry_version: RegistryVersion,
) -> Result<TlsStream, TlsServerHandshakeError> {
    let self_tls_cert = tls_cert_from_registry(registry_client, self_node_id, registry_version)
        .map_err(|e| map_cert_from_registry_error(e, CertFromRegistryOwner::Myself))?;

    let tls_stream = csp
        .perform_tls_server_handshake_without_client_auth(tcp_stream, self_tls_cert)
        .await?;

    Ok(tls_stream)
}

fn tls_certs_from_registry(
    registry_client: &Arc<dyn RegistryClient>,
    nodes: &SomeOrAllNodes,
    registry_version: RegistryVersion,
) -> Result<BTreeMap<NodeId, TlsPublicKeyCert>, TlsCertFromRegistryError> {
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
) -> Result<BTreeMap<NodeId, TlsPublicKeyCert>, TlsCertFromRegistryError> {
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
    node_certs: &BTreeMap<NodeId, TlsPublicKeyCert>,
    certs: &HashSet<TlsPublicKeyCert>,
) -> HashSet<TlsPublicKeyCert> {
    let mut node_certs_and_certs: HashSet<_> = node_certs.values().cloned().collect();
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
    allowed_client_certs: &HashSet<TlsPublicKeyCert>,
    trusted_node_certs: &BTreeMap<NodeId, TlsPublicKeyCert>,
) -> Result<AuthenticatedPeer, TlsServerHandshakeError> {
    let authenticated_node = check_cert_and_get_authenticated_client_node_id(
        trusted_node_certs,
        client_cert_chain_from_handshake.leaf(),
    );
    match authenticated_node {
        Ok(authenticated_node) => Ok(AuthenticatedPeer::Node(authenticated_node)),
        Err(node_authentication_error) => {
            if allowed_client_certs.contains(client_cert_chain_from_handshake.root()) {
                Ok(AuthenticatedPeer::Cert(
                    client_cert_chain_from_handshake.leaf().clone(),
                ))
            } else {
                Err(node_authentication_error)
            }
        }
    }
}

fn check_cert_and_get_authenticated_client_node_id(
    trusted_node_certs: &BTreeMap<NodeId, TlsPublicKeyCert>,
    client_cert_from_handshake: &TlsPublicKeyCert,
) -> Result<NodeId, TlsServerHandshakeError> {
    let client_node_id_from_handshake_cert =
        node_id_from_cert_subject_common_name(client_cert_from_handshake)?;
    let trusted_client_cert_from_registry =
        cert_for_node_id(client_node_id_from_handshake_cert, trusted_node_certs)?;
    if client_cert_from_handshake != trusted_client_cert_from_registry {
        return Err(TlsServerHandshakeError::ClientNotAllowed(
            PeerNotAllowedError::CertificatesDiffer,
        ));
    }

    Ok(client_node_id_from_handshake_cert)
}

fn cert_for_node_id(
    claimed_node_id_from_handshake_cert: NodeId,
    trusted_node_certs: &BTreeMap<NodeId, TlsPublicKeyCert>,
) -> Result<&TlsPublicKeyCert, TlsServerHandshakeError> {
    trusted_node_certs
        .get(&claimed_node_id_from_handshake_cert)
        .ok_or(TlsServerHandshakeError::ClientNotAllowed(
            PeerNotAllowedError::HandshakeCertificateNodeIdNotAllowed,
        ))
}

enum CertFromRegistryOwner {
    Client,
    Myself,
}

fn map_cert_from_registry_error(
    registry_error: TlsCertFromRegistryError,
    peer: CertFromRegistryOwner,
) -> TlsServerHandshakeError {
    match (registry_error, peer) {
        (TlsCertFromRegistryError::RegistryError(e), _) => {
            TlsServerHandshakeError::RegistryError(e)
        }
        (
            TlsCertFromRegistryError::CertificateNotInRegistry {
                node_id,
                registry_version,
            },
            _,
        ) => TlsServerHandshakeError::CertificateNotInRegistry {
            node_id,
            registry_version,
        },
        (
            TlsCertFromRegistryError::CertificateMalformed { internal_error },
            CertFromRegistryOwner::Client,
        ) => TlsServerHandshakeError::MalformedClientCertificate(MalformedPeerCertificateError {
            internal_error,
        }),
        (
            TlsCertFromRegistryError::CertificateMalformed { internal_error },
            CertFromRegistryOwner::Myself,
        ) => TlsServerHandshakeError::MalformedSelfCertificate { internal_error },
    }
}
