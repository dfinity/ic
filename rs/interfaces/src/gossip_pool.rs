//! The gossip pool public interface.
use crate::artifact_pool::ArtifactPoolError;
use ic_types::{artifact::ArtifactKind, NodeId};

/// GossipPool trait is the generic interface used by ArtifactManager
/// to interact with the Pools internally and allow GossipProtocol to
/// serve the gossip functionality. Every pool needs to implement this
/// trait.
pub trait GossipPool<T: ArtifactKind> {
    /// Check if an unvalidated artifact can be inserted into the pool
    /// #Returns:
    /// - `Ok`: The artifact can be inserted into the unvalidated pool.
    /// - `Error`: If there is insufficient quota available for the peer, Return
    ///   InsufficientQuotaError.
    ///
    /// Default implementation is just to return Ok.
    fn check_quota(&self, _msg: &T::Message, _peer_id: &NodeId) -> Result<(), ArtifactPoolError> {
        Ok(())
    }

    /// Check if an artifact exists by its Id.
    fn contains(&self, id: &T::Id) -> bool;

    /// Get a validated artifact by its identifier
    ///
    /// #Returns:
    /// - 'Some`: Artifact from the validated pool.
    /// - `None`: Artifact does not exist in the validated pool.
    fn get_validated_by_identifier(&self, id: &T::Id) -> Option<T::Message>;

    /// Get all validated artifacts by the filter
    /// See interfaces/src/artifact_manager.rs for more details
    ///
    /// #Returns:
    /// A iterator over all the validated artifacts.
    fn get_all_validated_by_filter(
        &self,
        filter: &T::Filter,
    ) -> Box<dyn Iterator<Item = T::Message> + '_>;
}
