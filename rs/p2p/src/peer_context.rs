use ic_types::{artifact::ArtifactId, chunkable::ChunkId, crypto::CryptoHash, NodeId};
use std::{
    collections::HashMap,
    time::{Instant, SystemTime},
};

/// A per-peer chunk request tracker for a chunk request sent to a peer.
/// Tracking begins when a request is dispatched and concludes when
///
/// a) 'MAX_CHUNK_WAIT_MS' time has elapsed without a response from the peer
///   OR
/// b) the peer responds with the chunk or an error message.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct GossipChunkRequestTracker {
    /// Instant when the request was initiated.
    pub requested_instant: Instant,
}

/// A node tracks the chunks it requested from each peer.
/// A chunk is identified by the artifact ID and chunk ID.
/// This struct defines a look-up key composed of an artifact ID and chunk ID.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct GossipChunkRequestTrackerKey {
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
    pub requested: HashMap<GossipChunkRequestTrackerKey, GossipChunkRequestTracker>,
    /// The time when the peer was disconnected.
    pub disconnect_time: Option<SystemTime>,
    /// The time of the last processed retransmission request from this peer.
    pub last_retransmission_request_processed_time: Instant,
}

impl PeerContext {
    pub fn new() -> Self {
        Self {
            requested: HashMap::new(),
            disconnect_time: None,
            last_retransmission_request_processed_time: Instant::now(),
        }
    }
}

/// Mapping node IDs to peer contexts.
pub(crate) type PeerContextMap = HashMap<NodeId, PeerContext>;
