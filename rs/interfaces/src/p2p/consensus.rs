//! The artifact pool public interface that defines the Consensus-P2P API.
//! Consensus clients must implement the traits in this file in order to use the IC P2P protocol.
use ic_types::{
    artifact::{Advert, ArtifactKind, PriorityFn},
    NodeId, Time,
};

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
    pub artifacts_with_opt: Vec<ArtifactWithOpt<Artifact>>,
    /// The field instructs the polling component (the one that calls `on_state_change` + `apply_changes`)
    /// that polling immediately can be benefitial. For example, polling consensus when the field is set to
    /// true results in lower consensus latencies.
    pub poll_immediately: bool,
}

pub struct ArtifactWithOpt<Artifact: ArtifactKind> {
    pub advert: Advert<Artifact>,
    pub is_latency_sensitive: bool,
}

/// Defines the canonical way for mutating an artifact pool.
/// Mutations should happen from a single place/component.
pub trait MutablePool<Artifact: ArtifactKind> {
    type ChangeSet;

    /// Inserts a message into the unvalidated part of the pool.
    fn insert(&mut self, msg: UnvalidatedArtifact<Artifact::Message>);

    /// Removes a message from the unvalidated part of the pool.
    fn remove(&mut self, id: &Artifact::Id);

    /// Applies a set of change actions to the pool.
    fn apply_changes(&mut self, change_set: Self::ChangeSet) -> ChangeResult<Artifact>;
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

/// Unvalidated artifact
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnvalidatedArtifact<T> {
    pub message: T,
    pub peer_id: NodeId,
    pub timestamp: Time,
}

impl<T> AsRef<T> for UnvalidatedArtifact<T> {
    fn as_ref(&self) -> &T {
        &self.message
    }
}
