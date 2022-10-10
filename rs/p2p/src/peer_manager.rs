use crate::{P2PError, P2PErrorCode, P2PResult};
use ic_interfaces_transport::Transport;
use ic_logger::{info, warn, ReplicaLogger};
use ic_types::{
    artifact::ArtifactId, chunkable::ChunkId, crypto::CryptoHash, NodeId, RegistryVersion,
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Instant, SystemTime},
};

/// The peer manager manages the list of current peers.
pub(crate) trait PeerManager {
    /// The method returns the current list of peers.
    fn get_current_peer_ids(&self) -> Vec<NodeId>;

    /// The method adds the given peer to the list of current peers.
    fn add_peer(
        &self,
        peer_id: NodeId,
        peer_addr: SocketAddr,
        registry_version: RegistryVersion,
    ) -> P2PResult<()>;

    /// The method removes the given peer from the list of current peers.
    fn remove_peer(&self, peer: NodeId);

    fn current_peers(&self) -> &Arc<Mutex<PeerContextDictionary>>;
}

/// A per-peer chunk request tracker for a chunk request sent to a peer.
/// Tracking begins when a request is dispatched and concludes when
///
/// a) 'MAX_CHUNK_WAIT_MS' time has elapsed without a response from the peer OR
/// </br> b) the peer responds with the chunk or an error message.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct GossipRequestTracker {
    /// Instant when the request was initiated.
    pub requested_instant: Instant,
}

/// A node tracks the chunks it requested from each peer.
/// A chunk is identified by the artifact ID and chunk ID.
/// This struct defines a look-up key composed of an artifact ID and chunk ID.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct GossipRequestTrackerKey {
    /// The artifact ID of the requested chunk.
    pub artifact_id: ArtifactId,
    /// The Integrity Hash of the requested artifact.
    pub integrity_hash: CryptoHash,
    /// The chunk ID of the requested chunk.
    pub chunk_id: ChunkId,
}

/// The peer context for a certain peer.
/// It keeps track of the requested chunks at any point in time.
#[derive(Clone)]
pub(crate) struct PeerContext {
    /// The dictionary containing the requested chunks.
    pub requested: HashMap<GossipRequestTrackerKey, GossipRequestTracker>,
    /// The time when the peer was disconnected.
    pub disconnect_time: Option<SystemTime>,
    /// The time of the last processed retransmission request from this peer.
    pub last_retransmission_request_processed_time: Instant,
}

impl PeerContext {
    pub fn new() -> Self {
        PeerContext {
            requested: HashMap::new(),
            disconnect_time: None,
            last_retransmission_request_processed_time: Instant::now(),
        }
    }
}

/// The dictionary mapping node IDs to peer contexts.
pub(crate) type PeerContextDictionary = HashMap<NodeId, PeerContext>;
/// An implementation of the `PeerManager` trait.
pub(crate) struct PeerManagerImpl {
    /// The node ID of the peer.
    node_id: NodeId,
    /// The logger.
    log: ReplicaLogger,
    /// The dictionary containing all peer contexts.
    pub(crate) current_peers: Arc<Mutex<PeerContextDictionary>>,
    /// The underlying *Transport*.
    transport: Arc<dyn Transport>,
}

impl PeerManagerImpl {
    pub(crate) fn new(
        node_id: NodeId,
        log: ReplicaLogger,
        current_peers: Arc<Mutex<PeerContextDictionary>>,
        transport: Arc<dyn Transport>,
    ) -> Self {
        Self {
            node_id,
            log,
            current_peers,
            transport,
        }
    }
}

/// `PeerManagerImpl` implements the `PeerManager` trait.
impl PeerManager for PeerManagerImpl {
    /// The method returns the current list of peers.
    fn get_current_peer_ids(&self) -> Vec<NodeId> {
        self.current_peers
            .lock()
            .unwrap()
            .iter()
            .map(|(k, _v)| k.to_owned())
            .collect()
    }

    /// The method adds the given peer to the list of current peers.
    fn add_peer(
        &self,
        peer_id: NodeId,
        peer_addr: SocketAddr,
        registry_version: RegistryVersion,
    ) -> P2PResult<()> {
        // Only add other peers to the peer list.
        if peer_id == self.node_id {
            return Err(P2PError {
                p2p_error_code: P2PErrorCode::Failed,
            });
        }

        // Add the peer to the list of current peers and the event handler, and drop the
        // lock before calling into transport.
        {
            let mut current_peers = self.current_peers.lock().unwrap();

            if current_peers.contains_key(&peer_id) {
                Err(P2PError {
                    p2p_error_code: P2PErrorCode::Exists,
                })
            } else {
                current_peers
                    .entry(peer_id)
                    .or_insert_with(PeerContext::new);
                info!(self.log, "Nodes {:0} added", peer_id);
                Ok(())
            }?;
        }

        self.transport
            .start_connection(&peer_id, peer_addr, registry_version)
            .map_err(|e| {
                self.current_peers.lock().unwrap().remove(&peer_id);
                warn!(self.log, "start connections failed {:?} {:?}", peer_id, e);
                P2PError {
                    p2p_error_code: P2PErrorCode::InitFailed,
                }
            })
    }

    /// The method removes the given peer from the list of current peers.
    fn remove_peer(&self, node_id: NodeId) {
        let mut current_peers = self.current_peers.lock().unwrap();
        self.transport.stop_connection(&node_id);
        // Remove the peer irrespective of the result of the stop_connection() call.
        current_peers.remove(&node_id);
        info!(self.log, "Nodes {:0} removed", node_id);
    }

    // As a temporary hack return a reference to an Arc. There is little risk in doing
    // this given the code compiles.
    fn current_peers(&self) -> &Arc<Mutex<PeerContextDictionary>> {
        &self.current_peers
    }
}
