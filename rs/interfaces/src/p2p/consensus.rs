//! The public interface that defines the Consensus-P2P API.
//! Clients must implement the traits in this file in order to use the IC's P2P/Replication/Broadcast protocol.
use ic_types::{
    artifact::{IdentifiableArtifact, PbArtifact},
    NodeId, Time,
};
use std::time::Duration;

/// Artifact is the abstracted term for the message that needs to be broadcast/replicated.
#[derive(PartialEq, Debug)]
pub struct ArtifactWithOpt<T> {
    pub artifact: T,
    /// The value defines the strategy to deliver a message to all peers.
    /// If true, the artifact will be pushed (send directly to all peers).
    /// This is fast but it can result in significant traffic overhead.
    /// If false, only the ID (think of advert in legacy terms) of the artifact
    /// is pushed to the peers and then each peer can fetch the artifact on demand.
    pub is_latency_sensitive: bool,
}

/// Specifies an addition or removal to the outbound set of messages that are replicated.
#[derive(PartialEq, Debug)]
pub enum ArtifactTransmit<T: IdentifiableArtifact> {
    Deliver(ArtifactWithOpt<T>),
    Abort(T::Id),
}

/// Produces transmits to be applied on the artifact pool.
pub trait PoolMutationsProducer<Pool>: Send {
    type Mutations;

    /// Inspect the input `Pool` to build a `Mutations` of actions to
    /// be executed.
    ///
    /// The caller is then expected to apply the returned `Mutations` to the
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
    fn on_state_change(&self, pool: &Pool) -> Self::Mutations;
}

pub struct ArtifactTransmits<T: IdentifiableArtifact> {
    /// The list of replication transmits returned by the client. Mutations are applied in order by P2P-replication.
    pub transmits: Vec<ArtifactTransmit<T>>,
    /// The field instructs the polling component (the one that calls `on_state_change` + `apply_changes`)
    /// that polling immediately can be benefitial. For example, polling consensus when the field is set to
    /// true results in lower consensus latencies.
    pub poll_immediately: bool,
}

/// Defines the canonical way for mutating an artifact pool.
/// Mutations should happen from a single place/component.
pub trait MutablePool<T: IdentifiableArtifact> {
    type Mutations;

    /// Inserts a message into the pool.
    fn insert(&mut self, msg: UnvalidatedArtifact<T>);

    /// Removes a message from the pool.
    fn remove(&mut self, id: &T::Id);

    /// Applies a set of change actions to the pool.
    fn apply(&mut self, mutations: Self::Mutations) -> ArtifactTransmits<T>;
}

/// ValidatedPoolReader trait is the generic interface used by P2P to interact
/// with the validated portion of an artifact pool without resulting in any transmits.
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

#[derive(Eq, PartialEq, Debug)]
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
    fn assemble_message<P: Peers + Clone + Send + 'static>(
        &self,
        id: <A2 as IdentifiableArtifact>::Id,
        artifact: Option<(A2, NodeId)>,
        peers: P,
    ) -> impl std::future::Future<Output = Result<(A1, NodeId), Aborted>> + Send;
}

/// Idempotent and non-blocking function which returns a BouncerValue for any artifact ID.
/// Think of this closure as guarding access to the unvalidated pool (similar to a bouncer in a night club).
pub type Bouncer<Id> = Box<dyn Fn(&Id) -> BouncerValue + Send + Sync + 'static>;

/// The Bouncer function returns a value that defines 3 possible handling logics when an artifact or ID is received.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum BouncerValue {
    /// The client doesn't need the corresponding artifact for making progress so it can safely be dropped.
    Unwanted,
    /// The client may need later the artifact.
    MaybeWantsLater,
    /// The artifact needs to be delivered to the client.
    Wants,
}

/// Since the Bouncer above is defined as idempotent, the factory trait provides a way to refresh to a newer function.
/// Invocations of the bouncer closure and factory should happen inside the implentations of the ArtifactAssembler.
pub trait BouncerFactory<Id, Pool>: Send + Sync {
    /// Returns a new bouncer function for the given pool.
    fn new_bouncer(&self, pool: &Pool) -> Bouncer<Id>;

    /// The period at which the bouncer should be refreshed.
    /// Implementors of the bouncer are well suited for determing the refresh period.
    fn refresh_period(&self) -> Duration;
}

/// Unvalidated artifact
// TODO: the API should be unvalidated pool agnostic, to remove this struct we need to sign ingress messages
#[derive(Clone, Eq, PartialEq, Debug)]
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
