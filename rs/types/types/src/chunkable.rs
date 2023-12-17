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
use crate::state_sync::StateSyncMessage;
use phantom_newtype::Id;

pub type Chunk = Vec<u8>;

/// Error codes returned by the `Chunkable` interface.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ArtifactErrorCode {
    ChunksMoreNeeded,
    ChunkVerificationFailed,
}

/// The chunk type.
pub struct ChunkIdTag;
pub type ChunkId = Id<ChunkIdTag, u32>;

pub trait Chunkable {
    fn chunks_to_download(&self) -> Box<dyn Iterator<Item = ChunkId>>;
    fn add_chunk(
        &mut self,
        chunk_id: ChunkId,
        chunk: Chunk,
    ) -> Result<StateSyncMessage, ArtifactErrorCode>;
}
