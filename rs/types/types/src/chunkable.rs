//! [`Chunkable`] Artifact Trait.
//!
//! A de facto trait for P2P assembled/downloadable artifacts. A
//! chunkable artifact lends itself to be downloaded by the P2P layer.
//! This trait has functions that abstract functionality of chunk
//! management for various artifact variants.  P2P needs generic
//! interfaces to perform the following functions:
//!
//! - Create Adverts for Artifacts
//! - Create under-construction object stubs on the receive side
//! - Iterate/Request/Receive/Collate chunks
//!
//! All variants of the Artifact should implement the [`Chunkable`]
//! interface.
//!
//! Polymorphism is implemented as static dispatch over enumerated variants
//! that implement a common trait.
use crate::{
    artifact::{Artifact, StateSyncMessage},
    consensus::{
        certification::CertificationMessage, dkg::Message as DkgMessage, ConsensusMessage,
    },
    crypto::CryptoHash,
    messages::SignedIngress,
};
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
const CHUNKID_UNIT_CHUNK: u32 = 0;

/// The data contained in an artifact chunk.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

impl ArtifactChunk {
    fn new(chunk_id: ChunkId, artifact_chunk_data: ArtifactChunkData) -> ArtifactChunk {
        ArtifactChunk {
            chunk_id,
            witness: Vec::new(),
            artifact_chunk_data,
        }
    }
}

// Static polymorphic dispatch for chunk tracking.
//
// Chunk trackers give a polymorphic interface over client chunk tracking logic.
// For artifacts consisting of a single chunk, P2P provides a default
// [`Chunkable`] trait implementation. Artifact types for which this default
// chunking logic is sufficient are marked using the [`SingleChunked`] marker
// trait.
//
// Why Trackers: Rust doesn't allow objects to be partially
// initialized, i.e we cannot track an under construction
// `ConsensusArtifact` using the same type as assembled
// `Artifact`. Tracker types provide an abstract control point that enables us
// to implement a polymorphic dispatch to per client tracking logic.
//
// Trackers are created from adverts and implement From trait.

/// Artifact types composed of a single chunk.
pub enum SingleChunked {
    Consensus,
    Ingress,
    Certification,
    Dkg,
    Ecdsa,
}

/// Interface providing access to artifact chunks.
pub trait ChunkableArtifact {
    /// Retrieves the artifact chunk with the given ID.
    ///
    /// The chunk ID for single-chunked artifacts must be
    /// [`CHUNKID_UNIT_CHUNK`].
    fn get_chunk(self: Box<Self>, chunk_id: ChunkId) -> Option<ArtifactChunk>;
}

macro_rules! chunkable_artifact_impl {
    ($id:path, |$self:ident| $v:expr) => {
        impl ChunkableArtifact for $id {
            fn get_chunk($self: Box<Self>, chunk_id: ChunkId) -> Option<ArtifactChunk> {
                if chunk_id != ChunkId::from(CHUNKID_UNIT_CHUNK) {
                    // Single chunked in identified only chunk CHUNKID_UNIT_CHUNK
                    None
                } else {
                    Some(ArtifactChunk::new(chunk_id, $v))
                }
            }
        }
    };
}

chunkable_artifact_impl! {ConsensusMessage, |self|
    ArtifactChunkData::UnitChunkData(Artifact::ConsensusMessage(*self))
}
chunkable_artifact_impl! {SignedIngress, |self|
    ArtifactChunkData::UnitChunkData(Artifact::IngressMessage((*self).into()))
}
chunkable_artifact_impl! {CertificationMessage, |self|
    ArtifactChunkData::UnitChunkData(Artifact::CertificationMessage(*self))
}
chunkable_artifact_impl! {DkgMessage, |self|
    ArtifactChunkData::UnitChunkData(Artifact::DkgMessage(*self))
}

impl ChunkableArtifact for StateSyncMessage {
    fn get_chunk(self: Box<Self>, chunk_id: ChunkId) -> Option<ArtifactChunk> {
        let buf = if chunk_id == crate::state_sync::MANIFEST_CHUNK {
            crate::state_sync::encode_manifest(&self.manifest)
        } else if let Some(chunk) = self
            .manifest
            .chunk_table
            .get((chunk_id.get() - 1) as usize)
            .cloned()
        {
            let path = self
                .checkpoint_root
                .join(&self.manifest.file_table[chunk.file_index as usize].relative_path);
            let get_state_sync_chunk = self.get_state_sync_chunk.unwrap();
            get_state_sync_chunk(path, chunk.offset, chunk.size_bytes).ok()?
        } else {
            return None;
        };

        Some(ArtifactChunk::new(
            chunk_id,
            ArtifactChunkData::SemiStructuredChunkData(buf),
        ))
    }
}

// End repetition

/// Basic chunking interface for [`SingleChunked`] artifact tracker.
pub trait Chunkable {
    fn get_artifact_hash(&self) -> CryptoHash;
    fn chunks_to_download(&self) -> Box<dyn Iterator<Item = ChunkId>>;
    fn get_artifact_identifier(&self) -> CryptoHash;
    fn add_chunk(&mut self, artifact_chunk: ArtifactChunk) -> Result<Artifact, ArtifactErrorCode>;
    fn is_complete(&self) -> bool;
    fn get_chunk_size(&self, chunk_id: ChunkId) -> usize;
}

// Basic chunking impl for [`SingleChunked`] object tracking
impl Chunkable for SingleChunked {
    fn get_artifact_hash(&self) -> CryptoHash {
        unimplemented!("")
    }

    fn chunks_to_download(&self) -> Box<dyn Iterator<Item = ChunkId>> {
        let v: Vec<ChunkId> = vec![ChunkId::from(CHUNKID_UNIT_CHUNK)];
        Box::new(v.into_iter())
    }

    fn get_artifact_identifier(&self) -> CryptoHash {
        unimplemented!("")
    }

    fn add_chunk(&mut self, artifact_chunk: ArtifactChunk) -> Result<Artifact, ArtifactErrorCode> {
        match artifact_chunk.artifact_chunk_data {
            ArtifactChunkData::UnitChunkData(artifact) => Ok(artifact),
            _ => Err(ArtifactErrorCode::ChunkVerificationFailed),
        }
    }

    fn is_complete(&self) -> bool {
        unimplemented!("")
    }

    fn get_chunk_size(&self, _chunk_id: ChunkId) -> usize {
        unimplemented!("")
    }
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

// -----------------------------------------------------------------------------
