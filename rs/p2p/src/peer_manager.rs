use crate::{P2PError, P2PErrorCode, P2PResult};
use ic_interfaces_transport::Transport;
use ic_logger::{info, warn, ReplicaLogger};
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_types::{
    artifact::ArtifactId, chunkable::ChunkId, crypto::CryptoHash, NodeId, RegistryVersion,
};
use std::{
    collections::HashMap,
    convert::TryInto,
    net::{IpAddr, SocketAddr},
    str::FromStr,
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
        peer: NodeId,
        node_record: &NodeRecord,
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
#[allow(dead_code)]
#[derive(Clone)]
pub(crate) struct PeerContext {
    /// The node ID of the peer.
    pub peer_id: NodeId,
    /// The dictionary containing the requested chunks.
    pub requested: HashMap<GossipRequestTrackerKey, GossipRequestTracker>,
    /// The time when the peer was disconnected.
    pub disconnect_time: Option<SystemTime>,
    /// The time of the last processed retransmission request from this peer.
    pub last_retransmission_request_processed_time: Instant,
}

/// A `NodeId` can be converted into a `PeerContext`.
impl From<NodeId> for PeerContext {
    /// The function returns a new peer context associated with the given node
    /// ID.
    fn from(peer_id: NodeId) -> Self {
        PeerContext {
            peer_id,
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
        node_id: NodeId,
        node_record: &NodeRecord,
        registry_version: RegistryVersion,
    ) -> P2PResult<()> {
        // Only add other peers to the peer list.
        if node_id == self.node_id {
            return Err(P2PError {
                p2p_error_code: P2PErrorCode::Failed,
            });
        }

        // Add the peer to the list of current peers and the event handler, and drop the
        // lock before calling into transport.
        {
            let mut current_peers = self.current_peers.lock().unwrap();

            if current_peers.contains_key(&node_id) {
                Err(P2PError {
                    p2p_error_code: P2PErrorCode::Exists,
                })
            } else {
                current_peers
                    .entry(node_id)
                    .or_insert_with(|| PeerContext::from(node_id.to_owned()));
                info!(self.log, "Nodes {:0} added", node_id);
                Ok(())
            }?;
        }

        // If getting the peer socket fails, remove the node from current peer list.
        // This removal makes it possible to attempt a re-connection on the next registry refresh.
        let peer_addr = get_peer_addr(node_record).map_err(|e| {
            let mut current_peers = self.current_peers.lock().unwrap();
            current_peers.remove(&node_id);
            warn!(self.log, "start connections failed {:?} {:?}", node_id, e);
            P2PError {
                p2p_error_code: P2PErrorCode::InitFailed,
            }
        })?;
        self.transport
            .start_connection(&node_id, peer_addr, registry_version)
            .map_err(|e| {
                let mut current_peers = self.current_peers.lock().unwrap();
                current_peers.remove(&node_id);
                warn!(self.log, "start connections failed {:?} {:?}", node_id, e);
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

fn get_peer_addr(node_record: &NodeRecord) -> Result<SocketAddr, String> {
    let socket_addr: (IpAddr, u16) = node_record
        .p2p_flow_endpoints
        .get(0)
        .and_then(|flow_enpoint| flow_enpoint.endpoint.as_ref())
        .and_then(|endpoint| {
            Some((
                IpAddr::from_str(&endpoint.ip_addr).ok()?,
                endpoint.port.try_into().ok()?,
            ))
        })
        .ok_or("Failed to parse NodeRecord to (IpAddr,u16) tuple")?;

    Ok(SocketAddr::from(socket_addr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_protobuf::registry::node::v1::{
        connection_endpoint::Protocol, ConnectionEndpoint, FlowEndpoint,
    };

    #[test]
    fn test_get_peer_addr() {
        {
            let node_record: NodeRecord = Default::default();
            let peer_addr = get_peer_addr(&node_record);
            assert!(peer_addr.is_err());
        }
        {
            let mut node_record: NodeRecord = Default::default();
            node_record.p2p_flow_endpoints.push(FlowEndpoint {
                flow_tag: 2000,
                endpoint: Some(ConnectionEndpoint {
                    ip_addr: "2001:db8:0:1:1:1:1:1".to_string(),
                    port: 200,
                    protocol: Protocol::P2p1Tls13 as i32,
                }),
            });

            let peer_addr = get_peer_addr(&node_record).unwrap();
            assert_eq!(
                peer_addr.to_string(),
                "[2001:db8:0:1:1:1:1:1]:200".to_string()
            );
        }
        {
            let mut node_record: NodeRecord = Default::default();
            node_record.p2p_flow_endpoints.push(FlowEndpoint {
                flow_tag: 1000,
                endpoint: Some(ConnectionEndpoint {
                    ip_addr: "2001:db8:0:1:1:1:1:1".to_string(),
                    port: 100,
                    protocol: Protocol::P2p1Tls13 as i32,
                }),
            });
            node_record.p2p_flow_endpoints.push(FlowEndpoint {
                flow_tag: 2000,
                endpoint: Some(ConnectionEndpoint {
                    ip_addr: "2001:db8:0:1:1:1:1:2".to_string(),
                    port: 200,
                    protocol: Protocol::P2p1Tls13 as i32,
                }),
            });

            let peer_addr = get_peer_addr(&node_record).unwrap();
            assert_eq!(
                peer_addr.to_string(),
                "[2001:db8:0:1:1:1:1:1]:100".to_string()
            );
        }
    }
}
