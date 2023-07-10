//! The artifact pool public interface that defines the Consensus-P2P API.
//! Consensus clients must implement the traits in this file in order to use the IC P2P protocol.
use crate::time_source::TimeSource;
use ic_types::{
    artifact::{Advert, ArtifactKind, PriorityFn},
    CountBytes, NodeId, Time,
};
use serde::{Deserialize, Serialize};

/// Produces mutations to be applied on the artifact pool.
pub trait ChangeSetProducer<Pool>: Send {
    type ChangeSet;

    /// Inspect the input `Pool` to build a `ChangeSet` of actions to
    /// be executed.
    ///
    /// The caller is then expected to apply the returned `ChangeSet` to the
    /// input of this call, namely a mutable version of the `Pool`. The reason
    /// that P2P clients (e.g. consensus) do not directly mutate the objects are:
    ///
    /// 1. The actual mutation may need to be coupled with other things,
    /// performed in a single transaction, and so on. So it is better to leave
    /// it to the caller to decide.
    ///
    /// 2. Because `Pool` is passed as an read-only reference, the
    /// caller is free to run other readers concurrently should it choose to.
    ///
    /// 3. The call can take long time, hence the pool should _not_ be guarded
    /// by a write lock which prevents other accesses to the pool.
    fn on_state_change(&self, pool: &Pool) -> Self::ChangeSet;
}

/// Ids of validated artifacts that were purged during the pool mutation, and adverts
/// of artifacts that were validated during the pool mutation. As some changes (i.e.
/// to the unvalidated section) might not generate adverts or purged IDs, `changed`
/// indicates if the mutation changed the pool's state at all.
pub struct ChangeResult<Artifact: ArtifactKind> {
    pub purged: Vec<Artifact::Id>,
    pub adverts: Vec<Advert<Artifact>>,
    /// The result of a single `apply_changes` call can result in either:
    /// - new changes applied to the state. So `on_state_change` + `apply_changes` should be
    ///   immediately called again.
    /// - no change applied and state was unchanged. So calling `on_state_change` + `apply_changes` is
    ///   not immediately required.
    pub changed: bool,
}

/// Defines the canonical way for mutating an artifact pool.
/// Mutations should happen from a single place/component.
pub trait MutablePool<Artifact: ArtifactKind, C> {
    /// Inserts a message into the unvalidated part of the pool.
    fn insert(&mut self, msg: UnvalidatedArtifact<Artifact::Message>);

    /// Removes a message from the unvalidated part of the pool.
    fn remove(&mut self, _id: &Artifact::Id) {
        unimplemented!()
    }

    /// Applies a set of change actions to the pool.
    fn apply_changes(
        &mut self,
        time_source: &dyn TimeSource,
        change_set: C,
    ) -> ChangeResult<Artifact>;
}

pub trait PriorityFnAndFilterProducer<Artifact: ArtifactKind, Pool>: Send + Sync {
    /// Returns a priority function for the given pool.
    fn get_priority_function(&self, pool: &Pool) -> PriorityFn<Artifact::Id, Artifact::Attribute>;

    /// Returns a filter that represents what artifacts are needed.
    /// The filter is derived from the (persisted) state of the client and not directly
    /// from a pool content. Hence, no pool reference is used here.
    fn get_filter(&self) -> Artifact::Filter {
        Artifact::Filter::default()
    }
}

/// ValidatedPoolReader trait is the generic interface used by P2P to interact
/// with the validated portion of an artifact pool without resulting in any mutations.
/// Every pool needs to implement this trait.
pub trait ValidatedPoolReader<T: ArtifactKind> {
    /// Check if an artifact exists by its Id.
    fn contains(&self, id: &T::Id) -> bool;

    /// Get a validated artifact by its identifier
    ///
    /// #Returns:
    /// - 'Some`: Artifact from the validated pool.
    /// - `None`: Artifact does not exist in the validated pool.
    fn get_validated_by_identifier(&self, id: &T::Id) -> Option<T::Message>;

    /// Get all validated artifacts by the filter
    ///
    /// #Returns:
    /// A iterator over all the validated artifacts.
    fn get_all_validated_by_filter(
        &self,
        filter: &T::Filter,
    ) -> Box<dyn Iterator<Item = T::Message> + '_>;
}

/// Validated artifact
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatedArtifact<T> {
    pub msg: T,
    pub timestamp: Time,
}

impl<T> ValidatedArtifact<T> {
    pub fn map<U, F>(self, f: F) -> ValidatedArtifact<U>
    where
        F: FnOnce(T) -> U,
    {
        ValidatedArtifact {
            msg: f(self.msg),
            timestamp: self.timestamp,
        }
    }
}

/// Unvalidated artifact
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnvalidatedArtifact<T> {
    pub message: T,
    pub peer_id: NodeId,
    pub timestamp: Time,
}

// Traits for accessing data for (un)validated artifacts follow.

impl<T: CountBytes> CountBytes for ValidatedArtifact<T> {
    fn count_bytes(&self) -> usize {
        self.msg.count_bytes() + self.timestamp.count_bytes()
    }
}

impl<T> AsRef<T> for ValidatedArtifact<T> {
    fn as_ref(&self) -> &T {
        &self.msg
    }
}

impl<T> AsRef<T> for UnvalidatedArtifact<T> {
    fn as_ref(&self) -> &T {
        &self.message
    }
}

/// A trait similar to Into, but without its restrictions.
pub trait IntoInner<T>: AsRef<T> {
    fn into_inner(self) -> T;
}

impl<T> IntoInner<T> for ValidatedArtifact<T> {
    fn into_inner(self) -> T {
        self.msg
    }
}

impl<T> IntoInner<T> for UnvalidatedArtifact<T> {
    fn into_inner(self) -> T {
        self.message
    }
}

/// A trait to get timestamp.
pub trait HasTimestamp {
    fn timestamp(&self) -> Time;
}

impl<T> HasTimestamp for ValidatedArtifact<T> {
    fn timestamp(&self) -> Time {
        self.timestamp
    }
}

impl<T> HasTimestamp for UnvalidatedArtifact<T> {
    fn timestamp(&self) -> Time {
        self.timestamp
    }
}
