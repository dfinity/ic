//! All variants of the Artifact should implement the [`Chunkable`]
//! interface.
//!
//! Polymorphism is implemented as static dispatch over enumerated variants
//! that implement a common trait.
use crate::{
    artifact::Artifact,
    canister_http::CanisterHttpResponseShare,
    chunkable::{ChunkId, ChunkableArtifact, CHUNKID_UNIT_CHUNK},
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
            fn get_chunk($self: Box<Self>, chunk_id: ChunkId) -> Option<Artifact> {
                if chunk_id != ChunkId::from(CHUNKID_UNIT_CHUNK) {
                    // Single chunked in identified only chunk CHUNKID_UNIT_CHUNK
                    None
                } else {
                    Some($v)
                }
            }
        }
    };
}

chunkable_artifact_impl! {ConsensusMessage, |self|
    Artifact::ConsensusMessage(*self)
}
chunkable_artifact_impl! {SignedIngress, |self|
    Artifact::IngressMessage(*self)
}
chunkable_artifact_impl! {CertificationMessage, |self|
    Artifact::CertificationMessage(*self)
}
chunkable_artifact_impl! {DkgMessage, |self|
    Artifact::DkgMessage(*self)
}
chunkable_artifact_impl! {EcdsaMessage, |self|
    Artifact::EcdsaMessage(*self)
}
chunkable_artifact_impl! {CanisterHttpResponseShare, |self|
    Artifact::CanisterHttpMessage(*self)
}
