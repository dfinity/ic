use std::{
    collections::{BTreeSet, HashMap, HashSet},
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

use axum::Router;
use bytes::Bytes;
use futures::{
    future::{join_all, BoxFuture},
    FutureExt,
};
use http::Request;
use ic_crypto_tls_interfaces::{AllowedClients, TlsConfig, TlsConfigError};
use ic_icos_sev_interfaces::{ValidateAttestationError, ValidateAttestedStream};
use ic_p2p_test_utils::{temp_crypto_component_with_tls_keys, RegistryConsensusHandle};
use ic_quic_transport::Transport;
use ic_types::{NodeId, RegistryVersion};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::{ClientConfig, ServerConfig};

/// Utility to check connectivity between peers.
/// Requires that transport has the `router()` installed
/// and periodically call `check` in a loop.
#[derive(Clone, Debug)]
#[allow(clippy::type_complexity)]
pub struct ConnectivityChecker {
    peers: Arc<RwLock<HashMap<NodeId, HashSet<NodeId>>>>,
}

impl ConnectivityChecker {
    pub fn new(peers: &[NodeId]) -> Self {
        let mut hm = HashMap::new();

        for peer_id in peers {
            hm.insert(*peer_id, HashSet::new());
        }

        Self {
            peers: Arc::new(RwLock::new(hm)),
        }
    }

    /// Router used by check function to verify connectivity.
    pub fn router() -> Router {
        Router::new().route("/Ping", axum::routing::get(|| async { "Pong" }))
    }

    pub fn check_fut(
        &self,
    ) -> impl Fn(NodeId, Arc<dyn Transport>) -> BoxFuture<'static, ()> + Clone + 'static {
        let conn_checker = self.clone();
        move |peer, transport| {
            let conn_checker_clone = conn_checker.clone();
            async move {
                loop {
                    conn_checker_clone.check(peer, transport.clone()).await;
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
            .boxed()
        }
    }

    /// Checks connectivity of this peer to peers provided in `add_peer` function.
    async fn check(&self, this_peer: NodeId, transport: Arc<dyn Transport>) {
        // Collect rpc futures to all peers
        let mut futs = vec![];
        for peer in transport.peers() {
            let request = Request::builder().uri("/Ping").body(Bytes::new()).unwrap();
            let transport_clone = transport.clone();
            futs.push(async move {
                (
                    tokio::time::timeout(
                        Duration::from_secs(1),
                        transport_clone.rpc(&peer, request),
                    )
                    .await,
                    peer,
                )
            });
        }
        let futs_res = join_all(futs).await;
        // Apply results of rpc futures
        let mut peers = self.peers.write().unwrap();
        peers.get_mut(&this_peer).unwrap().clear();
        for res in futs_res {
            match res {
                (Ok(Ok(_)), peer) => {
                    peers.get_mut(&this_peer).unwrap().insert(peer);
                }
                (_, peer) => {
                    peers.get_mut(&this_peer).unwrap().remove(&peer);
                }
            }
        }
    }

    /// Every peer is connected to every other peer.
    pub fn fully_connected(&self) -> bool {
        let peers = self.peers.read().unwrap();
        for p1 in peers.keys() {
            for p2 in peers.keys() {
                if p1 != p2 && !self.connected_pair(p1, p2) {
                    return false;
                }
            }
        }
        true
    }

    /// Every peer is connected to every other peer that is not in the except list.
    pub fn fully_connected_except(&self, except_list: Vec<NodeId>) -> bool {
        let set: HashSet<NodeId> = HashSet::from_iter(except_list.into_iter());
        let peers = self.peers.read().unwrap();
        for p1 in peers.keys() {
            for p2 in peers.keys() {
                if p1 != p2
                    && !set.contains(p1)
                    && !set.contains(p2)
                    && !self.connected_pair(p1, p2)
                {
                    return false;
                }
            }
        }
        true
    }

    /// This peer is not reachable by any other peer.
    pub fn unreachable(&self, unreachable_peer: &NodeId) -> bool {
        let peers = self.peers.read().unwrap();
        for peer_id in peers.keys() {
            if unreachable_peer != peer_id && !self.disconnected_from(peer_id, unreachable_peer) {
                return false;
            }
        }
        true
    }

    /// Clear connected status table for this peer
    pub fn reset(&self, peer: &NodeId) {
        let mut peers = self.peers.write().unwrap();
        peers.get_mut(peer).unwrap().clear();
    }

    /// Check if a both peers are connected to each other.
    pub fn connected_pair(&self, peer_1: &NodeId, peer_2: &NodeId) -> bool {
        let peers = self.peers.read().unwrap();

        let connected_peer_1 = peers.get(peer_1).unwrap();
        let connected_peer_2 = peers.get(peer_2).unwrap();

        connected_peer_1.contains(peer_2) && connected_peer_2.contains(peer_1)
    }

    /// Checks if peer1 is disconnected from peer2.
    pub fn disconnected_from(&self, peer_1: &NodeId, peer_2: &NodeId) -> bool {
        let peers = self.peers.read().unwrap();

        let connected_peer_1 = peers.get(peer_1).unwrap();

        !connected_peer_1.contains(peer_2)
    }
}

pub struct PeerRestrictedSevHandshake {
    allowed_peers: Arc<Mutex<Vec<NodeId>>>,
}

impl Default for PeerRestrictedSevHandshake {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerRestrictedSevHandshake {
    pub fn new() -> Self {
        Self {
            allowed_peers: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn set_allowed_peers(&self, peers: Vec<NodeId>) {
        println!("STE {peers:?}");
        *self.allowed_peers.lock().unwrap() = peers;
    }
}

#[async_trait::async_trait]
impl<S> ValidateAttestedStream<S> for PeerRestrictedSevHandshake
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    async fn perform_attestation_validation(
        &self,
        stream: S,
        peer: NodeId,
        _latest_registry_version: RegistryVersion,
        _earliest_registry_version: RegistryVersion,
    ) -> Result<S, ValidateAttestationError> {
        let peers = self.allowed_peers.lock().unwrap();
        if peers.contains(&peer) {
            Ok(stream)
        } else {
            Err(ValidateAttestationError::HandshakeError {
                description: "Peer rejected".to_string(),
            })
        }
    }
}

pub struct PeerRestrictedTlsConfig {
    allowed_peers: Arc<Mutex<Vec<NodeId>>>,
    crypto: Arc<dyn TlsConfig + Send + Sync>,
}

impl PeerRestrictedTlsConfig {
    pub fn new(node_id: NodeId, registry_handler: &RegistryConsensusHandle) -> Self {
        let crypto = temp_crypto_component_with_tls_keys(registry_handler, node_id);
        Self {
            allowed_peers: Arc::new(Mutex::new(Vec::new())),
            crypto,
        }
    }

    pub fn set_allowed_peers(&self, peers: Vec<NodeId>) {
        *self.allowed_peers.lock().unwrap() = peers;
    }
}

impl TlsConfig for PeerRestrictedTlsConfig {
    fn server_config(
        &self,
        _allowed_clients: AllowedClients,
        registry_version: RegistryVersion,
    ) -> Result<ServerConfig, TlsConfigError> {
        let allowed_clients = AllowedClients::new_with_nodes(BTreeSet::from_iter(
            self.allowed_peers.lock().unwrap().clone().into_iter(),
        ))
        .unwrap();
        self.crypto.server_config(allowed_clients, registry_version)
    }

    fn server_config_without_client_auth(
        &self,
        _registry_version: RegistryVersion,
    ) -> Result<ServerConfig, TlsConfigError> {
        todo!()
    }

    fn client_config(
        &self,
        server: NodeId,
        registry_version: RegistryVersion,
    ) -> Result<ClientConfig, TlsConfigError> {
        self.crypto.client_config(server, registry_version)
    }
}
