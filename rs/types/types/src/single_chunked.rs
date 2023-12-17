//! All variants of the Artifact should implement the [`Chunkable`]
//! interface.
//!
//! Polymorphism is implemented as static dispatch over enumerated variants
//! that implement a common trait.
use crate::{
    artifact::Artifact,
    canister_http::CanisterHttpResponseShare,
    consensus::{
        certification::CertificationMessage, dkg::Message as DkgMessage, ecdsa::EcdsaMessage,
        ConsensusMessage,
    },
    messages::SignedIngress,
};

/// Interface providing access to artifact.
pub trait ChunkableArtifact {
    fn get_chunk(self: Box<Self>) -> Artifact;
}

macro_rules! chunkable_artifact_impl {
    ($id:path, |$self:ident| $v:expr) => {
        impl ChunkableArtifact for $id {
            fn get_chunk($self: Box<Self>) -> Artifact {
                $v
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
