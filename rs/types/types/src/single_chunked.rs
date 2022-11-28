//! All variants of the Artifact should implement the [`Chunkable`]
//! interface.
//!
//! Polymorphism is implemented as static dispatch over enumerated variants
//! that implement a common trait.
use crate::{
    artifact::Artifact,
    canister_http::CanisterHttpResponseShare,
    chunkable::{
        ArtifactChunk, ArtifactChunkData, ArtifactErrorCode, ChunkId, Chunkable, ChunkableArtifact,
        CHUNKID_UNIT_CHUNK,
    },
    consensus::{
        certification::CertificationMessage, dkg::Message as DkgMessage, ecdsa::EcdsaMessage,
        ConsensusMessage,
    },
    messages::SignedIngress,
};

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
    CanisterHttp,
    Consensus,
    Ingress,
    Certification,
    Dkg,
    Ecdsa,
}

macro_rules! chunkable_artifact_impl {
    ($id:path, |$self:ident| $v:expr) => {
        impl ChunkableArtifact for $id {
            fn get_chunk($self: Box<Self>, chunk_id: ChunkId) -> Option<ArtifactChunk> {
                if chunk_id != ChunkId::from(CHUNKID_UNIT_CHUNK) {
                    // Single chunked in identified only chunk CHUNKID_UNIT_CHUNK
                    None
                } else {
                    Some(ArtifactChunk {
                        chunk_id,
                        witness: Vec::new(),
                        artifact_chunk_data: $v,
                    })
                }
            }
        }
    };
}

chunkable_artifact_impl! {ConsensusMessage, |self|
    ArtifactChunkData::UnitChunkData(Artifact::ConsensusMessage(*self))
}
chunkable_artifact_impl! {SignedIngress, |self|
    ArtifactChunkData::UnitChunkData(Artifact::IngressMessage(*self))
}
chunkable_artifact_impl! {CertificationMessage, |self|
    ArtifactChunkData::UnitChunkData(Artifact::CertificationMessage(*self))
}
chunkable_artifact_impl! {DkgMessage, |self|
    ArtifactChunkData::UnitChunkData(Artifact::DkgMessage(*self))
}
chunkable_artifact_impl! {EcdsaMessage, |self|
    ArtifactChunkData::UnitChunkData(Artifact::EcdsaMessage(*self))
}
chunkable_artifact_impl! {CanisterHttpResponseShare, |self|
    ArtifactChunkData::UnitChunkData(Artifact::CanisterHttpMessage(*self))
}

// Basic chunking impl for [`SingleChunked`] object tracking
impl Chunkable for SingleChunked {
    fn chunks_to_download(&self) -> Box<dyn Iterator<Item = ChunkId>> {
        let v: Vec<ChunkId> = vec![ChunkId::from(CHUNKID_UNIT_CHUNK)];
        Box::new(v.into_iter())
    }

    fn add_chunk(&mut self, artifact_chunk: ArtifactChunk) -> Result<Artifact, ArtifactErrorCode> {
        match artifact_chunk.artifact_chunk_data {
            ArtifactChunkData::UnitChunkData(artifact) => Ok(artifact),
            _ => Err(ArtifactErrorCode::ChunkVerificationFailed),
        }
    }
}
