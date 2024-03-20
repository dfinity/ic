//! The file contains the synchronous interface used from P2P, to drive the StateSync protocol.  
use ic_protobuf::p2p::v1 as p2p_pb;
use ic_types::{crypto::CryptoHash, Height};
use phantom_newtype::Id;
use thiserror::Error;

/// Identifier of a state sync artifact.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

pub type Chunk = Vec<u8>;

/// Error codes returned by the `Chunkable` interface.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Error)]
pub enum AddChunkError {
    #[error("bad chunk")]
    Invalid,
}

/// The chunk type.
pub struct ChunkIdTag;
pub type ChunkId = Id<ChunkIdTag, u32>;

pub trait Chunkable<T> {
    fn chunks_to_download(&self) -> Box<dyn Iterator<Item = ChunkId>>;
    fn add_chunk(&mut self, chunk_id: ChunkId, chunk: Chunk) -> Result<(), AddChunkError>;
    fn completed(&self) -> bool;
}

pub trait StateSyncClient: Send + Sync {
    type Message;

    /// Returns a list of all states available.
    fn available_states(&self) -> Vec<StateSyncArtifactId>;
    /// Initiates new state sync for the specified Id. Returns None if the state should not be synced.
    /// If `Some(..)` is returned a new state sync is initiated.
    /// Callers of this interface need to uphold the following: `start_state_sync` is not called again
    /// before the previously returned object is dropped.
    /// TODO: (NET-1469) In the future the mentioned caller restriction should be lifted.
    fn start_state_sync(
        &self,
        id: &StateSyncArtifactId,
    ) -> Option<Box<dyn Chunkable<Self::Message> + Send>>;
    /// Returns true if a state sync with the specified Id can be cancelled because a newer state is available.
    /// The result of this function is only meaningful the Id refers to a active state sync started with `start_state_sync`.
    /// TODO: (NET-1469) In the future this API should be made safer by only allowing the id of a previously initiated state sync.
    fn should_cancel(&self, id: &StateSyncArtifactId) -> bool;
    /// Get a specific chunk from the specified state.
    fn chunk(&self, id: &StateSyncArtifactId, chunk_id: ChunkId) -> Option<Chunk>;
}
