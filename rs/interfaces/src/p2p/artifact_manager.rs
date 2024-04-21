//! The traits in this file define the interface between the `p2p` and `artifact_manager` crates/packages.
use crate::p2p::consensus::ChangeResult;
use crate::time_source::TimeSource;
use ic_types::artifact::{ArtifactKind, UnvalidatedArtifactMutation};

use super::consensus::ArtifactWithOpt;

/// Event loops/actors that implement a graceful shutdown on destruction implement this trait.
/// This is useful when the the event loop/actor has multiple handles and a separate object
/// that does the shutdown is required.
pub trait JoinGuard {}

pub enum ArtifactProcessorEvent<Artifact: ArtifactKind> {
    Artifact(ArtifactWithOpt<Artifact>),
    Purge(Artifact::Id),
}

/// An abstraction of processing changes for each artifact client.
pub trait ArtifactProcessor<Artifact: ArtifactKind>: Send {
    /// Process changes to the client's state, which includes but not
    /// limited to:
    ///   - newly arrived artifacts (passed as input parameters)
    ///   - changes in dependencies
    ///   - changes in time
    ///
    /// As part of the processing, it may also modify its own state
    /// including both unvalidated and validated pools. The return
    /// result includes a list of adverts for P2P to disseminate to
    /// peers, deleted artifact,  as well as a result flag indicating
    /// if there are more changes to be processed so that the caller
    /// can decide whether this function should be called again
    /// immediately, or after certain period of time.
    fn process_changes(
        &self,
        time_source: &dyn TimeSource,
        new_artifact_events: Vec<UnvalidatedArtifactMutation<Artifact>>,
    ) -> ChangeResult<Artifact>;
}
