//! The file contains the synchronous interface used from P2P, to drive the StateSync protocol.  
use ic_protobuf::p2p::v1 as p2p_pb;
use ic_types::{Height, crypto::CryptoHash};
use phantom_newtype::Id;
use thiserror::Error;

/// Identifier of a state sync artifact.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct StateSyncArtifactId {
    pub height: Height,
    pub hash: CryptoHash,
}

impl From<StateSyncArtifactId> for p2p_pb::StateSyncId {
    fn from(id: StateSyncArtifactId) -> Self {
        Self {
            height: id.height.get(),
            hash: id.hash.0,
        }
    }
}

impl From<p2p_pb::StateSyncId> for StateSyncArtifactId {
    fn from(id: p2p_pb::StateSyncId) -> Self {
        Self {
            height: Height::from(id.height),
            hash: CryptoHash(id.hash),
        }
    }
}

/// To decrease the risk of leaking chunks we make it hard to clone them.
pub struct Chunk(Vec<u8>);

impl From<Vec<u8>> for Chunk {
    fn from(chunk: Vec<u8>) -> Self {
        Chunk(chunk)
    }
}

impl Chunk {
    pub fn take(self) -> Vec<u8> {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Error codes returned by the `Chunkable` interface.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Error)]
pub enum AddChunkError {
    #[error("bad chunk")]
    Invalid,
}

/// The chunk type.
pub struct ChunkIdTag;
pub type ChunkId = Id<ChunkIdTag, u32>;

/// A 'Chunkable' object is used to assemble a single ongoing state sync.
pub trait Chunkable<T> {
    /// Returns the remaining chunks needed to complete the state sync.
    /// The list is dynamic and may change over time based on addition of new chunks.
    /// The function will return empty iff the corresponding state sync is completed.
    fn chunks_to_download(&self) -> Box<dyn Iterator<Item = ChunkId>>;
    /// Delivers the corresponding chunk.
    fn add_chunk(&mut self, chunk_id: ChunkId, chunk: Chunk) -> Result<(), AddChunkError>;
}

pub trait StateSyncClient: Send + Sync {
    type Message;

    /// Returns a list of all states available.
    fn available_states(&self) -> Vec<StateSyncArtifactId>;

    /// Initiates new state sync for the specified Id. If `Some(..)` is returned a new state sync is initiated.
    /// Returns None if the state should not be synced.
    ///
    /// Requires: callers of this interface should not invoke `maybe_start_state_sync`
    /// unless the previously returned (Chunkable) object is dropped. In otherwords,
    /// the caller of this API must assume that there can be a single ongoing state sync.
    ///
    /// TODO: In the future the mentioned caller restriction should be lifted or the API should be adjusted to
    /// capture the requirement.
    fn maybe_start_state_sync(
        &self,
        id: &StateSyncArtifactId,
    ) -> Option<Box<dyn Chunkable<Self::Message> + Send>>;

    /// Returns true if is safe to cancel a potentially ongoing state sync.
    ///
    /// Notes on the interface.
    ///
    /// The decision to cancel an ongoing state sync is not the inverse of starting a new state sync.
    /// One can imagine that the implementer wants to hold on for an older state sync for longer period of time
    /// instead of cancelling and starting the new one. This assumption is even more important given the requirement
    /// that there can be a single active state sync.
    fn cancel_if_running(&self, id: &StateSyncArtifactId) -> bool;

    /// Returns a specific chunk from the specified state.
    fn chunk(&self, id: &StateSyncArtifactId, chunk_id: ChunkId) -> Option<Chunk>;
}
