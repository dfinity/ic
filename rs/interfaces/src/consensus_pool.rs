//! The consensus pool public interface.

use crate::p2p::consensus::UnvalidatedArtifact;
use ic_base_types::RegistryVersion;
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    types::v1 as pb,
};
use ic_types::{
    artifact::ConsensusMessageId,
    consensus::{
        Block, BlockProposal, CatchUpPackage, CatchUpPackageShare, ConsensusMessage, ContentEq,
        Finalization, FinalizationShare, HasHeight, HashedBlock, Notarization, NotarizationShare,
        RandomBeacon, RandomBeaconShare, RandomTape, RandomTapeShare,
    },
    crypto::CryptoHashOf,
    time::Time,
    Height,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;

/// The height, at which we consider a replica to be behind
pub const HEIGHT_CONSIDERED_BEHIND: Height = Height::new(20);

/// Validated artifact
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct ValidatedArtifact<T> {
    pub msg: T,
    pub timestamp: Time,
}

impl<T> AsRef<T> for ValidatedArtifact<T> {
    fn as_ref(&self) -> &T {
        &self.msg
    }
}

pub type ChangeSet = Vec<ChangeAction>;

/// Change actions applicable to the consensus pool.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ChangeAction {
    /// Add the given artifact to the validated section of the pool.
    AddToValidated(ValidatedConsensusArtifact),
    /// Remove the given artifact from the validated section of the pool.
    RemoveFromValidated(ConsensusMessage),
    /// Remove the given artifact from the unvalidated section of the pool and add it to
    /// the validated section of the pool.
    MoveToValidated(ConsensusMessage),
    /// Remove the given artifact from the unvalidated section of the pool.
    RemoveFromUnvalidated(ConsensusMessage),
    /// Remove an invalid artifact from the unvalidated section of the pool.
    HandleInvalid(ConsensusMessage, String),
    /// Purge all the artifacts _strictly_ below the provided height from the validated
    /// section of the pool.
    PurgeValidatedBelow(Height),
    /// Purge all the artifacts _strictly_ below the provided height from the unvalidated
    /// section of the pool.
    PurgeUnvalidatedBelow(Height),
    /// Purge all the artifacts of the given type _strictly_ below the provided height
    /// from the validated section of the pool.
    PurgeValidatedOfTypeBelow(PurgeableArtifactType, Height),
}

/// A type of consensus artifact which can be selectively deleted from the consensus pool.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PurgeableArtifactType {
    NotarizationShare,
    FinalizationShare,
}

impl From<ChangeAction> for ChangeSet {
    fn from(action: ChangeAction) -> Self {
        vec![action]
    }
}

/// A trait with common methods for change sets.
pub trait ChangeSetOperation: Sized {
    /// Conditional composition when self is empty. Similar to Option::or_else.
    fn or_else<F: FnOnce() -> Self>(self, f: F) -> Self;
    /// Append a change action only when it is not a duplicate of what already
    /// exists in the ChangeSet. Return the rejected action as error when it
    /// is considered as duplicate.
    fn dedup_push(&mut self, action: ChangeAction) -> Result<(), ChangeAction>;
}

impl ChangeSetOperation for ChangeSet {
    fn or_else<F: FnOnce() -> ChangeSet>(self, f: F) -> ChangeSet {
        if self.is_empty() {
            f()
        } else {
            self
        }
    }

    fn dedup_push(&mut self, action: ChangeAction) -> Result<(), ChangeAction> {
        if !self.iter().any(|x| x.content_eq(&action)) {
            self.push(action);
            Ok(())
        } else {
            Err(action)
        }
    }
}

impl ContentEq for ChangeAction {
    fn content_eq(&self, other: &ChangeAction) -> bool {
        match (self, other) {
            (ChangeAction::AddToValidated(x), ChangeAction::AddToValidated(y)) => {
                x.msg.content_eq(&y.msg)
            }
            (ChangeAction::RemoveFromValidated(x), ChangeAction::RemoveFromValidated(y)) => {
                x.content_eq(y)
            }
            (ChangeAction::MoveToValidated(x), ChangeAction::MoveToValidated(y)) => x.content_eq(y),
            (ChangeAction::RemoveFromUnvalidated(x), ChangeAction::RemoveFromUnvalidated(y)) => {
                x.content_eq(y)
            }
            (ChangeAction::HandleInvalid(x, _), ChangeAction::HandleInvalid(y, _)) => {
                x.content_eq(y)
            }
            // Also compare between MoveToValidated and AddToValidated to help remove duplicates
            (ChangeAction::AddToValidated(x), ChangeAction::MoveToValidated(y)) => {
                x.msg.content_eq(y)
            }
            (ChangeAction::MoveToValidated(x), ChangeAction::AddToValidated(y)) => {
                x.content_eq(&y.msg)
            }
            (ChangeAction::PurgeValidatedBelow(x), ChangeAction::PurgeValidatedBelow(y)) => x == y,
            (
                ChangeAction::PurgeValidatedOfTypeBelow(type_1, x),
                ChangeAction::PurgeValidatedOfTypeBelow(type_2, y),
            ) => x == y && type_1 == type_2,
            // Default to false when comparing actions of different type
            _ => false,
        }
    }
}

/// Validated consensus artifact.
pub type ValidatedConsensusArtifact = ValidatedArtifact<ConsensusMessage>;

/// Unvalidated consensus artifact.
pub type UnvalidatedConsensusArtifact = UnvalidatedArtifact<ConsensusMessage>;

impl From<&ValidatedConsensusArtifact> for pb::ValidatedConsensusArtifact {
    fn from(value: &ValidatedConsensusArtifact) -> Self {
        Self {
            msg: Some(value.msg.clone().into()),
            timestamp: value.timestamp.as_nanos_since_unix_epoch(),
        }
    }
}

impl TryFrom<pb::ValidatedConsensusArtifact> for ValidatedConsensusArtifact {
    type Error = ProxyDecodeError;
    fn try_from(value: pb::ValidatedConsensusArtifact) -> Result<Self, Self::Error> {
        Ok(Self {
            msg: try_from_option_field(value.msg, "ValidatedConsensusArtifact::msg")?,
            timestamp: Time::from_nanos_since_unix_epoch(value.timestamp),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeightRange {
    pub min: Height,
    pub max: Height,
}

impl HeightRange {
    pub fn new(min: Height, max: Height) -> HeightRange {
        HeightRange { min, max }
    }
}

#[derive(Debug)]
pub enum OnlyError {
    NoneAvailable,
    MultipleValues,
}

// tag::interface[]

/// A Pool section is a part of the consensus pool which contains
/// artifacts.
///
/// Artifacts in the pool are accessible by their hash or by their
/// type and height.
pub trait PoolSection<T> {
    /// Checks if the artifact with the given Id is present in the pool
    fn contains(&self, msg_id: &ConsensusMessageId) -> bool;

    /// Lookup an artifact by ConsensusMessageId. Return the consensus message
    /// if it exists, or None otherwise.
    fn get(&self, msg_id: &ConsensusMessageId) -> Option<ConsensusMessage>;

    /// Lookup the timestamp of an artifact by its ConsensusMessageId.
    fn get_timestamp(&self, msg_id: &ConsensusMessageId) -> Option<Time>;

    /// Return the HeightIndexedPool for RandomBeacon.
    fn random_beacon(&self) -> &dyn HeightIndexedPool<RandomBeacon>;

    /// Return the HeightIndexedPool for BlockProposal.
    fn block_proposal(&self) -> &dyn HeightIndexedPool<BlockProposal>;

    /// Return the HeightIndexedPool for Notarization.
    fn notarization(&self) -> &dyn HeightIndexedPool<Notarization>;

    /// Return the HeightIndexedPool for Finalization.
    fn finalization(&self) -> &dyn HeightIndexedPool<Finalization>;

    /// Return the HeightIndexedPool for RandomBeaconShare.
    fn random_beacon_share(&self) -> &dyn HeightIndexedPool<RandomBeaconShare>;

    /// Return the HeightIndexedPool for NotarizationShare.
    fn notarization_share(&self) -> &dyn HeightIndexedPool<NotarizationShare>;

    /// Return the HeightIndexedPool for FinalizationShare.
    fn finalization_share(&self) -> &dyn HeightIndexedPool<FinalizationShare>;

    /// Return the HeightIndexedPool for RandomTape.
    fn random_tape(&self) -> &dyn HeightIndexedPool<RandomTape>;

    /// Return the HeightIndexedPool for RandomTapeShare.
    fn random_tape_share(&self) -> &dyn HeightIndexedPool<RandomTapeShare>;

    /// Return the HeightIndexedPool for CatchUpPackage.
    fn catch_up_package(&self) -> &dyn HeightIndexedPool<CatchUpPackage>;

    /// Return the HeightIndexedPool for CatchUpPackageShare.
    fn catch_up_package_share(&self) -> &dyn HeightIndexedPool<CatchUpPackageShare>;

    fn highest_catch_up_package(&self) -> CatchUpPackage {
        let proto = self.highest_catch_up_package_proto();
        CatchUpPackage::try_from(&proto).expect("deserializing CUP from protobuf artifact failed")
    }
    /// Return the HeightIndexedPool for CatchUpPackage in protobuf form.
    fn highest_catch_up_package_proto(&self) -> pb::CatchUpPackage {
        // NOTE: This default implementation is not the actual implementation
        // that will be used for this code path. It simply avoids the need to implement
        // this function on other things implementing PoolSection
        pb::CatchUpPackage::from(
            &self.catch_up_package().get_highest().unwrap_or_else(|err| {
                panic!(
                    "Error getting highest CatchUpPackage in the validated pool: {:?}",
                    err
                )
            }),
        )
    }

    fn size(&self) -> u64;
}

/// The consensus pool contains all the artifacts received by P2P and
/// produced by the local node.
///
/// It contains two sections:
/// - The validated section contains artifacts that have been validated by
///   consensus. To support resumability this section must be persistent.
///
/// - The unvalidated section contains artifacts that have been received but
///   haven't yet been validated. This section is in-memory only and thus
///   volatile.
///
/// It also stores monotonic timestamps ("instants") for block proposals
/// and notarizations.
pub trait ConsensusPool {
    /// Return a reference to the validated PoolSection.
    fn validated(&self) -> &dyn PoolSection<ValidatedConsensusArtifact>;

    /// Return a reference to the unvalidated PoolSection.
    fn unvalidated(&self) -> &dyn PoolSection<UnvalidatedConsensusArtifact>;

    /// Return a reference to the consensus cache (ConsensusPoolCache).
    fn as_cache(&self) -> &dyn ConsensusPoolCache;

    /// Return a reference to the consensus block cache (ConsensusBlockCache).
    fn as_block_cache(&self) -> &dyn ConsensusBlockCache;

    /// Return the block chain between the given start/end.
    fn build_block_chain(&self, start: &Block, end: &Block) -> Arc<dyn ConsensusBlockChain>;

    /// Return the first instant at which a block with the given hash was inserted
    /// into the validated pool. Returns None if no timestamp was found.
    fn block_instant(&self, hash: &CryptoHashOf<Block>) -> Option<Instant>;

    /// Return the first instant at which a consensus message with the given id
    /// arrived in the unvalidated pool. Returns None if no timestamp was found
    /// NOTE: We currently only record notarizations, CUPs and random beacons,
    /// for the purposes of computing a round start instant.
    fn message_instant(&self, id: &ConsensusMessageId) -> Option<Instant>;
}

/// HeightIndexedPool provides a set of interfaces for the Consensus component
/// to query artifacts. The same interface is applicable to both validated and
/// unvalidated partitions of consensus artifacts in the overall ArtifactPool.
pub trait HeightIndexedPool<T> {
    /// Returns the height range of artifacts of type T currently in the pool.
    fn height_range(&self) -> Option<HeightRange>;

    /// Returns the max height across all artifacts of type T currently in the pool.
    fn max_height(&self) -> Option<Height>;

    /// Return an iterator over all of the artifacts of type T.
    fn get_all(&self) -> Box<dyn Iterator<Item = T>>;

    /// Return an iterator over the artifacts of type T at height 'h'.
    fn get_by_height(&self, h: Height) -> Box<dyn Iterator<Item = T>>;

    /// Return an iterator over the artifacts of type T
    /// in range range.min, range.max, inclusive. The items must be sorted
    /// by height in ascending order.
    fn get_by_height_range(&self, range: HeightRange) -> Box<dyn Iterator<Item = T>>;

    /// Return a single instance of artifact of type T, at height 'h', returning
    /// an error if there isn't one, or if there are more than one.
    fn get_only_by_height(&self, h: Height) -> Result<T, OnlyError>;

    /// Return a single instance of artifact of type T at the highest height
    /// currently in the pool. Returns an error if there isn't one, or if there
    /// are more than one.
    fn get_highest(&self) -> Result<T, OnlyError>;

    /// Return an iterator over instances of artifact of type T at the highest
    /// height currently in the pool.
    fn get_highest_iter(&self) -> Box<dyn Iterator<Item = T>>;

    /// Return the number of artifacts of type T in the pool.
    fn size(&self) -> usize;
}
// end::interface[]

/// Reader of time in the latest/highest finalized block.
pub trait ConsensusTime: Send + Sync {
    /// Return the time as recorded in the latest/highest finalized block.
    /// Return None if there has not been any finalized block since genesis.
    fn consensus_time(&self) -> Option<Time>;
}

/// Reader of consensus related states.
pub trait ConsensusPoolCache: Send + Sync {
    /// Return the latest/highest finalized block.
    fn finalized_block(&self) -> Block;

    /// Return the latest/highest CatchUpPackage.
    fn catch_up_package(&self) -> CatchUpPackage;

    /// Return the latest/highest CatchUpPackage in their original protobuf form.
    fn cup_as_protobuf(&self) -> pb::CatchUpPackage;

    /// Return the latest/highest finalized block with DKG summary. In a
    /// situation where we have only finalized the catch-up block but not
    /// yet made a catch-up package, this will be different than the block
    /// in the latest catch-up package.
    fn summary_block(&self) -> Block;

    /// Returns the oldest registry version that is still relevant to DKG.
    ///
    /// P2P should keep up connections to all nodes registered in any registry
    /// between the one returned from this function and the current
    /// `RegistryVersion`.
    fn get_oldest_registry_version_in_use(&self) -> RegistryVersion {
        self.catch_up_package().get_oldest_registry_version_in_use()
    }

    /// The target height that the StateManager should start at given
    /// this consensus pool during startup.
    fn starting_height(&self) -> Height {
        let certified_height = self.finalized_block().context.certified_height;
        let catchup_package_height = self.catch_up_package().height();
        certified_height.max(catchup_package_height)
    }

    /// Returns true if the `certified_height` provided is significantly behind the
    /// `certified_height` referenced by the current finalized block.
    ///
    /// This indicates that the node does not have a recent certified state.
    fn is_replica_behind(&self, certified_height: Height) -> bool {
        certified_height + HEIGHT_CONSIDERED_BEHIND
            < self.finalized_block().context.certified_height
    }

    /// Find ancestor blocks of `block`, and return an iterator that starts
    /// from `block` and ends when a parent is not found (e.g. genesis).
    fn chain_iterator<'a>(
        &self,
        pool: &'a dyn ConsensusPool,
        block: Block,
    ) -> Box<dyn Iterator<Item = Block> + 'a> {
        Box::new(ChainIterator::new(
            pool,
            block,
            Some(self.catch_up_package().content.block),
        ))
    }
}

/// Cache of blocks from the block chain.
pub trait ConsensusBlockCache: Send + Sync {
    /// Returns the block at the given height from the finalized tip.
    /// The implementation can choose the number of past blocks to cache.
    fn finalized_chain(&self) -> Arc<dyn ConsensusBlockChain>;
}

/// Snapshot of the block chain
#[allow(clippy::len_without_is_empty)]
pub trait ConsensusBlockChain: Send + Sync {
    /// Returns the block at the tip in the block chain.
    fn tip(&self) -> &Block;

    /// Returns the Block at the given height.
    fn get_block_by_height(&self, height: Height) -> Result<&Block, ConsensusBlockChainErr>;

    /// Returns the length of the chain.
    fn len(&self) -> usize;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsensusBlockChainErr {
    BlockNotFound(Height),
}

/// An iterator for block ancestors.
pub struct ChainIterator<'a> {
    consensus_pool: &'a dyn ConsensusPool,
    to_block: Option<HashedBlock>,
    cursor: Option<Block>,
}

impl<'a> ChainIterator<'a> {
    /// Return an iterator that iterates block ancestors, going backwards
    /// from the `from_block` to the `to_block` (both inclusive), or until a
    /// parent is not found in the consensus pool if the `to_block` is not
    /// specified.
    pub fn new(
        consensus_pool: &'a dyn ConsensusPool,
        from_block: Block,
        to_block: Option<HashedBlock>,
    ) -> Self {
        ChainIterator {
            consensus_pool,
            to_block,
            cursor: Some(from_block),
        }
    }

    fn get_parent_block(&self, block: &Block) -> Option<Block> {
        let height = block.height();
        if height == Height::from(0) {
            return None;
        }
        let parent_height = height.decrement();
        let parent_hash = &block.parent;
        if let Some(to_block) = &self.to_block {
            match parent_height.cmp(&to_block.height()) {
                std::cmp::Ordering::Less => {
                    return None;
                }
                std::cmp::Ordering::Equal => {
                    if parent_hash == to_block.get_hash() {
                        return Some(to_block.as_ref().clone());
                    } else {
                        return None;
                    }
                }
                _ => (),
            }
        }
        self.consensus_pool
            .validated()
            .block_proposal()
            .get_by_height(parent_height)
            .find_map(|proposal| {
                if proposal.content.get_hash() == parent_hash {
                    Some(proposal.content.into_inner())
                } else {
                    None
                }
            })
    }
}

impl<'a> Iterator for ChainIterator<'a> {
    type Item = Block;

    fn next(&mut self) -> Option<Self::Item> {
        let parent = self
            .cursor
            .as_ref()
            .and_then(|block| self.get_parent_block(block));
        std::mem::replace(&mut self.cursor, parent)
    }
}
