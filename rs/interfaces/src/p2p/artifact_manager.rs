//! The traits in this file define the interface between the `p2p` and `artifact_manager` crates/packages.
use crate::p2p::consensus::ChangeResult;
use crate::time_source::TimeSource;
use derive_more::From;
use ic_types::artifact::{
    ArtifactKind, ArtifactPriorityFn, PriorityFn, UnvalidatedArtifactMutation,
};
use ic_types::{artifact, p2p, single_chunked, NodeId};

use super::consensus::ArtifactWithOpt;

/// Event loops/actors that implement a graceful shutdown on destruction implement this trait.
/// This is useful when the the event loop/actor has multiple handles and a separate object
/// that does the shutdown is required.
pub trait JoinGuard {}

#[derive(From, Debug)]
/// An error type that combines 'NotProcessed' status with an actual
/// error that might be returned by artifact pools. It is used as
/// the return type for the `on_artifact` function of `ArtifactManager`.
pub enum OnArtifactError {
    NotProcessed,
}

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

/// The Artifact Manager stores artifacts to be used by this and other nodes in
/// the same subnet in the artifact pool.
///
/// The Artifact Manager is the API between P2P(Gossip+Transport) and
/// its clients.
///
// tag::artifact_manager[]
pub trait ArtifactManager: Send + Sync {
    /// When a new artifact is received, it is forwarded to the
    /// ArtifactManager together with its advert via the on_artifact call.
    /// This then forwards them to be processed by the corresponding
    /// ArtifactClient/ArtifactProcessor based on the artifact type.
    /// Returns `OnArtifactError` if no clients were able to process it or
    /// an error has occurred.
    ///
    /// See `ArtifactClient::on_artifact` for more details.
    #[allow(clippy::result_large_err)]
    fn on_artifact(&self, msg: artifact::Artifact, peer_id: &NodeId)
        -> Result<(), OnArtifactError>;

    /// Check if the artifact specified by the id already exists in the
    /// corresponding artifact pool.
    ///
    /// Gossip calls `has_artifact` to determine if it should proceed with
    /// downloading the corresponding artifact.
    fn has_artifact(&self, artifact_id: &artifact::ArtifactId) -> bool;

    /// Return a `ChunkableArtifact` implementation for the validated
    /// artifact identified by the id. If the artifact doesn't exist then None is
    /// returned.
    ///
    /// Gossip calls `get_validated_by_identifier` when it needs to send a
    /// `Chunk`, from the artifact identified by the id, to the requesting peer.
    fn get_validated_by_identifier(
        &self,
        artifact_id: &artifact::ArtifactId,
    ) -> Option<Box<dyn single_chunked::ChunkableArtifact + '_>>;

    /// Return a filter that is passed along to other peers when Gossip
    /// sends a re-transmission/bootstrap request. This filter is a collection of all
    /// filters returned by all Gossip clients. We do this aggregration because
    /// re-transimission/bootstrap requests happen mainly when a peer joins
    /// the subnet, so instead of requesting the filter for each Gossip client
    /// individually we do it in bulk.
    ///
    /// See `ArtifactClient::get_filter` for more details.
    fn get_filter(&self) -> artifact::ArtifactFilter;

    /// Return adverts for all existing validated artifacts accepted
    /// by the filter.
    ///
    /// After Gossip receives a re-tranmission/bootstrap request it calls
    /// `get_all_validated_by_filter` to get a new set of adverts that sends to the
    /// requesting peer.
    ///
    /// See `ArtifactClient::get_all_validated_by_filter` for more details.
    fn get_all_validated_by_filter(
        &self,
        filter: &artifact::ArtifactFilter,
    ) -> Vec<p2p::GossipAdvert>;

    /// Return the priority function for a specific client that is identified by
    /// the given artifact tag.
    ///
    /// See `ArtifactClient::get_priority_function` for more details.
    fn get_priority_function(&self, tag: artifact::ArtifactTag) -> ArtifactPriorityFn;
}
// end::artifact_manager[]
