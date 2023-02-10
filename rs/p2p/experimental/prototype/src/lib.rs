mod client;
mod p2p;

use ic_artifact_manager::artifact::ConsensusArtifact;
use ic_interfaces::{
    artifact_pool::UnvalidatedArtifact,
    consensus::{Consensus, ConsensusGossip},
    consensus_pool::MutableConsensusPool,
    time_source::TimeSource,
};
use ic_types::artifact::{
    ArtifactKind, ConsensusMessage, ConsensusMessageAttribute, ConsensusMessageId, PriorityFn,
};
use ic_types::NodeId;
use std::sync::Arc;
use tokio::sync::{
    oneshot,
    {mpsc::Sender, watch},
};

#[allow(dead_code)]
enum ArtifactDestination {
    Subnet,
    Peer(NodeId),
}

#[allow(dead_code)]
enum P2PChangeAction<A> {
    AddArtifact(A, ArtifactDestination),
    DeleteArtifact(A),
}

type P2PChangeSet<A> = Vec<P2PChangeAction<A>>;

/// Events coming from P2P to a P2P client(processor).
#[allow(dead_code)]
enum UnvalidatedPoolEvent<A> {
    /// New artifact.
    ///   * the processor adds the artifacts to the unvalidated pool,
    ///   * calls on_state_change
    ///   * applies the ChangeSet to the pools
    ///   * replies back with a P2PChangeSet
    Artifacts(
        (
            // TODO: separate discussion how we do batching
            Vec<UnvalidatedArtifact<A>>,
            oneshot::Sender<P2PChangeSet<A>>,
        ),
    ),
    // TODO: we can merge the tick event with the 'Artifacts' event just be sending
    // empty vec of artifacts
    /// A tick event
    ///   * calls on_state_change
    ///   * applies the ChangeSet to the pools
    ///   * replies back with a P2PChangeSet
    Tick(oneshot::Sender<P2PChangeSet<A>>),
    /// Bootstrap event
    ///   * replies back with the full unvalidated pool
    Bootstrap(oneshot::Sender<P2PChangeSet<A>>),
}

#[allow(dead_code)]
pub(crate) struct PoolProcessorHandle<A: ArtifactKind> {
    pub sender: Sender<UnvalidatedPoolEvent<A::Message>>,
    pub priority_fn_watcher: watch::Receiver<PriorityFn<A::Id, A::Attribute>>,
    pub jh: std::thread::JoinHandle<()>,
}

type ConsensusPoolProcessorHandle = PoolProcessorHandle<ConsensusArtifact>;

pub struct P2P<A: ArtifactKind> {
    #[allow(dead_code)]
    pool_processor_handle: PoolProcessorHandle<A>,
}

impl<A: ArtifactKind> Drop for P2P<A> {
    fn drop(&mut self) {
        // todo figure out the graceful shutdown of the pool processor and P2P
    }
}

type ConsensusP2P = P2P<ConsensusArtifact>;

pub fn start_consensus_p2p<P: MutableConsensusPool + Send + Sync + 'static>(
    pool: P,
    mutation_source: Box<dyn Consensus + Send + Sync>,
    priority_source: Box<dyn ConsensusGossip + Send + Sync>,
    time_source: Arc<dyn TimeSource>,
) -> ConsensusP2P {
    let pool_processor_handle =
        ConsensusPoolProcessorHandle::new(pool, mutation_source, priority_source, time_source);

    ConsensusP2P {
        pool_processor_handle,
    }
}
