//! The traits in this file define the interface between the `p2p` and `artifact_manager` crates/packages.
use crate::p2p::consensus::ChangeResult;
use crate::time_source::TimeSource;
use ic_types::artifact;
use ic_types::artifact::{ArtifactKind, PriorityFn, UnvalidatedArtifactMutation};

use super::consensus::ArtifactWithOpt;

/// Event loops/actors that implement a graceful shutdown on destruction implement this trait.
/// This is useful when the the event loop/actor has multiple handles and a separate object
/// that does the shutdown is required.
pub trait JoinGuard {}

pub enum ArtifactProcessorEvent<Artifact: ArtifactKind> {
    Artifact(ArtifactWithOpt<Artifact>),
    Purge(Artifact::Id),
}

/// An abstraction of artifact processing for a sub-type of the overall
/// 'Artifact' type.
pub trait ArtifactClient<Artifact: artifact::ArtifactKind>: Send + Sync {
    /// Checks if the node already has the artifact in the pool by its
    /// identifier.
    fn has_artifact(&self, msg_id: &Artifact::Id) -> bool;

    /// Gets a validated artifact by its identifier. Return `None`
    /// if no valid artifact is found for the given identifier.
    fn get_validated_by_identifier(&self, msg_id: &Artifact::Id) -> Option<Artifact::Message>;

    /// Gets the filter that needs to be sent with re-transmission request to
    /// other peers. This filter contains the information to indicate to
    /// other peers what this peer already has, and what relevant adverts
    /// are still needed.
    ///
    /// Assuming that Node A is a node trying to resume with the help of Node B.
    /// get_filter will be used by Node A to figure out its current filter and
    /// will be sent to Node B as a part of the re-transmission request.
    /// Node B will then use get_all_validated_by_filter with that filter to
    /// derive only the relevant adverts to be sent back to Node A.
    ///
    /// In the first version to be implemented, this filter is the last
    /// finalized height of Consensus. For all pool handlers this can be
    /// used to derive a suitable threshold value. For Consensus it will be
    /// height, for Ingress messages the time stamp of the finalized block at
    /// this height, for DKG the DKG instance relevant at this height, for
    /// Certification and State Synchronization the latest available
    /// executed state referred to in the block at this height.
    ///
    /// `Example`
    /// If Consensus pool has delivered batches up to height 10, the filter will
    /// be 'height = 10' since this node only needs consensus artifacts
    /// with height > 10.
    fn get_filter(&self) -> Artifact::Filter
    where
        Artifact::Filter: Default,
    {
        Default::default()
    }

    /// Get adverts of all validated artifacts by the filter. This filter is
    /// used to derive only the relevant adverts.
    ///
    /// Assuming that Node A is a node trying to resume with the help of Node B.
    /// get_filter will be used by Node A to figure out its current filter and
    /// will be sent to Node B as a part of the re-transmission request.
    /// Node B will then use get_all_validated_by_filter with that filter to
    /// derive only the relevant adverts to be sent back to Node A.
    ///
    /// `Example`
    /// If the filter contains height = 10; adverts for all the validated
    /// artifacts with height > 10 will be returned by this function.
    fn get_all_validated_by_filter(
        &self,
        _filter: &Artifact::Filter,
    ) -> Vec<artifact::Advert<Artifact>> {
        Vec::new()
    }

    /// Return the priority function used by this client.
    #[allow(clippy::type_complexity)]
    fn get_priority_function(&self) -> PriorityFn<Artifact::Id, Artifact::Attribute>;
}

/// An abstraction of processing changes for each artifact client.
pub trait ArtifactProcessor<Artifact: artifact::ArtifactKind>: Send {
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
