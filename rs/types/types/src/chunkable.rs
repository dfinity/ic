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
//! For more context please check https://youtu.be/WaNJINjGleg
//!
use crate::{artifact::Artifact, crypto::CryptoHash};
use bincode::{deserialize, serialize};
use ic_protobuf::p2p::v1 as pb;
use ic_protobuf::proxy::ProxyDecodeError;
use phantom_newtype::Id;
use std::convert::TryFrom;

/// Error codes returned by the `Chunkable` interface.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ArtifactErrorCode {
    ChunksMoreNeeded,
    ChunkVerificationFailed,
}

/// The chunk type.
pub type ChunkId = Id<ArtifactChunk, u32>;
pub(crate) const CHUNKID_UNIT_CHUNK: u32 = 0;

/// The data contained in an artifact chunk.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[allow(clippy::large_enum_variant)]
pub enum ArtifactChunkData {
    UnitChunkData(Artifact), // Unit chunk data has 1:1 mapping with real artifacts
    SemiStructuredChunkData(Vec<u8>),
}

/// An artifact chunk.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ArtifactChunk {
    // Chunk number/id for this chunk
    pub chunk_id: ChunkId,
    // Sibling hashes to be used for Merkle proof verification of this chunk
    pub witness: Vec<CryptoHash>,
    // Payload for the chunk
    pub artifact_chunk_data: ArtifactChunkData,
}

/// Interface providing access to artifact chunks.
pub trait ChunkableArtifact {
    /// Retrieves the artifact chunk with the given ID.
    ///
    /// The chunk ID for single-chunked artifacts must be
    /// [`CHUNKID_UNIT_CHUNK`].
    fn get_chunk(self: Box<Self>, chunk_id: ChunkId) -> Option<ArtifactChunk>;
}

/// Basic chunking interface for [`SingleChunked`] artifact tracker.
pub trait Chunkable {
    fn chunks_to_download(&self) -> Box<dyn Iterator<Item = ChunkId>>;
    fn add_chunk(&mut self, artifact_chunk: ArtifactChunk) -> Result<Artifact, ArtifactErrorCode>;
}

impl From<ArtifactChunk> for pb::ArtifactChunk {
    fn from(chunk: ArtifactChunk) -> Self {
        let data: pb::artifact_chunk::Data = match chunk.artifact_chunk_data {
            ArtifactChunkData::UnitChunkData(artifact) => {
                pb::artifact_chunk::Data::Artifact(serialize(&artifact).unwrap())
            }
            ArtifactChunkData::SemiStructuredChunkData(chunk_data) => {
                pb::artifact_chunk::Data::Chunk(chunk_data)
            }
        };
        Self {
            witnesses: chunk
                .witness
                .iter()
                .map(|w| serialize(&w).unwrap())
                .collect(),
            data: Some(data),
        }
    }
}

impl TryFrom<pb::ArtifactChunk> for ArtifactChunk {
    type Error = ProxyDecodeError;

    fn try_from(chunk: pb::ArtifactChunk) -> Result<Self, Self::Error> {
        let witness = chunk.witnesses.iter().map(|w| deserialize(w)).collect();
        let witness = match witness {
            Ok(witness) => witness,
            Err(_) => {
                return Err(ProxyDecodeError::Other(
                    "unable to deserialize CryptoHash".to_string(),
                ))
            }
        };
        let artifact_chunk_data = match chunk.data {
            None => {
                return Err(ProxyDecodeError::Other(
                    "unable to deserialize ArtifactChunk.data".to_string(),
                ))
            }
            Some(d) => match d {
                pb::artifact_chunk::Data::Artifact(a) => {
                    ArtifactChunkData::UnitChunkData(deserialize(&a)?)
                }
                pb::artifact_chunk::Data::Chunk(d) => ArtifactChunkData::SemiStructuredChunkData(d),
            },
        };
        Ok(Self {
            // On the wire chunk_id is passed in GossipChunk.
            chunk_id: ChunkId::from(CHUNKID_UNIT_CHUNK),
            witness,
            artifact_chunk_data,
        })
    }
}
