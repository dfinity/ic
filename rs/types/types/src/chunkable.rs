//! The module contains [`Chunkable`] and [`ChunkableArtifact`] traits.
//! All artifact types delivered by P2P must implement both traits.
//!
//! To better understand the traits, here are some of the requirements imposed by
//! users (state sync) of P2P:
//!
//! - Artifacts don't necessary fit into memory.
//! - Peers may need only some small parts of an artifact but
//!   not the full one. In order to save bandwidth transferring
//!   the full artifact that doesn't fit in memory doesn't make sense.
//!
//! For more context please check `<https://youtu.be/WaNJINjGleg>`
//!
use crate::artifact::{Artifact, StateSyncMessage};
use ic_protobuf::p2p::v1 as p2p_pb;
use phantom_newtype::Id;

pub type Chunk = Vec<u8>;

/// Error codes returned by the `Chunkable` interface.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ArtifactErrorCode {
    ChunksMoreNeeded,
    ChunkVerificationFailed,
}

/// The chunk type.
pub type ChunkId = Id<ArtifactChunk, u32>;

/// An artifact chunk.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ArtifactChunk {
    // Chunk number/id for this chunk
    pub chunk_id: ChunkId,
    // Payload for the chunk
    pub chunk: Chunk,
}

/// Interface providing access to artifact.
pub trait ChunkableArtifact {
    fn get_chunk(self: Box<Self>) -> Artifact;
}

pub trait Chunkable {
    fn chunks_to_download(&self) -> Box<dyn Iterator<Item = ChunkId>>;
    fn add_chunk(
        &mut self,
        artifact_chunk: ArtifactChunk,
    ) -> Result<StateSyncMessage, ArtifactErrorCode>;
}

impl From<ArtifactChunk> for p2p_pb::StateSyncChunkResponse {
    fn from(chunk: ArtifactChunk) -> Self {
        Self { data: chunk.chunk }
    }
}
