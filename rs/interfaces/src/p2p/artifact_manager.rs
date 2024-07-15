//! The traits in this file define the interface between the `p2p` and `artifact_manager` crates/packages.
use super::consensus::ArtifactWithOpt;
use ic_types::artifact::IdentifiableArtifact;

/// Event loops/actors that implement a graceful shutdown on destruction implement this trait.
/// This is useful when the the event loop/actor has multiple handles and a separate object
/// that does the shutdown is required.
pub trait JoinGuard {}

pub enum ArtifactProcessorEvent<A: IdentifiableArtifact> {
    Artifact(ArtifactWithOpt<A>),
    Purge(A::Id),
}
