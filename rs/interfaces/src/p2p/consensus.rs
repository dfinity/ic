//! The artifact pool public interface that defines the Consensus-P2P API.
//! Consensus clients must implement the traits in this file in order to use the IC P2P protocol.
use ic_types::{
    artifact::{IdentifiableArtifact, PbArtifact},
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
    ///    performed in a single transaction, and so on. So it is better to leave
    ///    it to the caller to decide.
    ///
    /// 2. Because `Pool` is passed as an read-only reference, the
    ///    caller is free to run other readers concurrently should it choose to.
    ///
    /// 3. The call can take long time, hence the pool should _not_ be guarded
    ///    by a write lock which prevents other accesses to the pool.
    fn on_state_change(&self, pool: &Pool) -> Self::ChangeSet;
}

/// The enum specifies if a given artifact should be replicated.
/// In other words, this specifies an addition or removal
/// to the outbound set of messages that is replicated.
#[derive(Debug, PartialEq)]
pub enum ArtifactMutation<T: IdentifiableArtifact> {
    Insert(ArtifactWithOpt<T>),
    Remove(T::Id),
}

/// Ids of validated artifacts that were purged during the pool mutation, and adverts
/// of artifacts that were validated during the pool mutation. As some changes (i.e.
/// to the unvalidated section) might not generate adverts or purged IDs, `changed`
/// indicates if the mutation changed the pool's state at all.
pub struct ChangeResult<T: IdentifiableArtifact> {
    /// The list of replication mutations returned by the client. Mutations are applied in order by P2P-replication.
    pub mutations: Vec<ArtifactMutation<T>>,
    /// The field instructs the polling component (the one that calls `on_state_change` + `apply_changes`)
    /// that polling immediately can be benefitial. For example, polling consensus when the field is set to
    /// true results in lower consensus latencies.
    pub poll_immediately: bool,
}

#[derive(Debug, PartialEq)]
pub struct ArtifactWithOpt<T> {
    pub artifact: T,
    pub is_latency_sensitive: bool,
}

/// Defines the canonical way for mutating an artifact pool.
/// Mutations should happen from a single place/component.
pub trait MutablePool<T: IdentifiableArtifact> {
    type ChangeSet;

    /// Inserts a message into the unvalidated part of the pool.
    fn insert(&mut self, msg: UnvalidatedArtifact<T>);

    /// Removes a message from the unvalidated part of the pool.
    fn remove(&mut self, id: &T::Id);

    /// Applies a set of change actions to the pool.
    fn apply_changes(&mut self, change_set: Self::ChangeSet) -> ChangeResult<T>;
}

/// Priority of artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Priority {
    /// Drop the advert, the local replica doesn't need the corresponding artifact for
    /// making progress.
    Drop,
    /// Stash the advert. It may be requested at a later point in time.
    Stash,
    /// High priority adverts, fetch the artifact immediately.
    FetchNow,
}

/// Priority function used by `ArtifactClient`.
pub type PriorityFn<Id> = Box<dyn Fn(&Id) -> Priority + Send + Sync + 'static>;

pub trait PriorityFnFactory<Artifact: IdentifiableArtifact, Pool>: Send + Sync {
    /// Returns a priority function for the given pool.
    fn get_priority_function(&self, pool: &Pool) -> PriorityFn<Artifact::Id>;
}

/// ValidatedPoolReader trait is the generic interface used by P2P to interact
/// with the validated portion of an artifact pool without resulting in any mutations.
/// Every pool needs to implement this trait.
pub trait ValidatedPoolReader<T: IdentifiableArtifact> {
    /// Get a validated artifact by its identifier
    ///
    /// #Returns:
    /// - 'Some`: Artifact from the validated pool.
    /// - `None`: Artifact does not exist in the validated pool.
    fn get(&self, id: &T::Id) -> Option<T>;

    /// Get all validated artifacts.
    ///
    /// #Returns:
    /// A iterator over all the validated artifacts.
    fn get_all_validated(&self) -> Box<dyn Iterator<Item = T> + '_>;
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

#[derive(Debug, PartialEq, Eq)]
pub struct Aborted;

pub trait Peers {
    fn peers(&self) -> Vec<NodeId>;
}

pub trait ArtifactAssembler<A1: IdentifiableArtifact, A2: PbArtifact>:
    Send + Clone + 'static
{
    /// Transform message before sending on the wire. Wire artifact type A2
    /// needs to define protobuf conversions for serialization.
    fn disassemble_message(&self, msg: A1) -> A2;
    /// Reconstruct message A1 from wire message. `peers` is the set of peers that
    /// have the message. Note that it is possible that the peer set changes over time.
    fn assemble_message<P: Peers + Send + 'static>(
        &self,
        id: <A2 as IdentifiableArtifact>::Id,
        artifact: Option<(A2, NodeId)>,
        peers: P,
    ) -> impl std::future::Future<Output = Result<(A1, NodeId), Aborted>> + Send;
}
