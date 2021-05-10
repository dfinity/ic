//! The gossip pool public interface.
use crate::{
    artifact_pool::ArtifactPoolError, certification::ChangeSet as CertificationChangeSet,
    consensus_pool::ChangeSet as ConsensusChangeSet, dkg::ChangeSet as DkgChangeSet,
    ingress_pool::ChangeSet as IngressChangeSet,
};
use ic_types::{
    artifact::{CertificationMessageId, ConsensusMessageId, DkgMessageId, IngressMessageId},
    consensus::{certification::CertificationMessage, dkg, ConsensusMessage},
    messages::SignedIngress,
    Height, NodeId, Time,
};

/// GossipPool trait is the generic interface used by ArtifactManager
/// to interact with the Pools internally and allow GossipProtocol to
/// serve the gossip functionality. Every pool needs to implement this
/// trait.
pub trait GossipPool<T, S> {
    type MessageId;
    type Filter;

    /// Check if an unvalidated artifact can be inserted into the pool
    /// #Returns:
    /// - `Ok`: The artifact can be inserted into the unvalidated pool.
    /// - `Error`: If there is insufficient quota available for the peer, Return
    ///   InsufficientQuotaError.
    ///
    /// Default implementation is just to return Ok.
    fn check_quota(&self, _msg: &T, _peer_id: &NodeId) -> Result<(), ArtifactPoolError> {
        Ok(())
    }

    /// Check if an artifact exists by its Id.
    fn contains(&self, id: &Self::MessageId) -> bool;

    /// Get a validated artifact by its identifier
    ///
    /// #Returns:
    /// - 'Some`: Artifact from the validated pool.
    /// - `None`: Artifact does not exist in the validated pool.
    fn get_validated_by_identifier(&self, id: &Self::MessageId) -> Option<T>;

    /// Get all validated artifacts by the filter
    /// See interfaces/src/artifact_manager.rs for more details
    ///
    /// #Returns:
    /// A iterator over all the validated artifacts.
    fn get_all_validated_by_filter(&self, filter: Self::Filter)
        -> Box<dyn Iterator<Item = T> + '_>;
}

/// GossipPool trait for ConsensusPool
pub trait ConsensusGossipPool:
    GossipPool<ConsensusMessage, ConsensusChangeSet, MessageId = ConsensusMessageId, Filter = Height>
{
}

/// GossipPool trait for IngressPool
pub trait IngressGossipPool:
    GossipPool<
    SignedIngress,
    IngressChangeSet,
    MessageId = IngressMessageId,
    Filter = std::ops::RangeInclusive<Time>,
>
{
}

/// GossipPool trait for CertificationPool
pub trait CertificationGossipPool:
    GossipPool<
    CertificationMessage,
    CertificationChangeSet,
    MessageId = CertificationMessageId,
    Filter = Height,
>
{
}

/// GossipPool trait for DkgPool
pub trait DkgGossipPool:
    GossipPool<dkg::Message, DkgChangeSet, MessageId = DkgMessageId, Filter = ()>
{
}
