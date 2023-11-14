use std::{
    hash::Hash,
    sync::{Arc, RwLock},
};

use crate::metrics::ConsensusManagerMetrics;
use axum::Router;
use crossbeam_channel::Sender as CrossbeamSender;
use ic_interfaces::p2p::{
    artifact_manager::ArtifactProcessorEvent,
    consensus::{PriorityFnAndFilterProducer, ValidatedPoolReader},
};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_peer_manager::SubnetTopology;
use ic_quic_transport::{ConnId, Transport};
use ic_types::artifact::{Advert, ArtifactKind, UnvalidatedArtifactMutation};
use ic_types::NodeId;
use phantom_newtype::AmountOf;
use receiver::build_axum_router;
use receiver::ConsensusManagerReceiver;
use sender::ConsensusManagerSender;
use serde::{Deserialize, Serialize};
use tokio::{
    runtime::Handle,
    sync::{mpsc::Receiver, watch},
};

mod metrics;
mod receiver;
mod sender;

type StartConsensusManagerFn<'a> =
    Box<dyn FnOnce(Arc<dyn Transport>, watch::Receiver<SubnetTopology>) + 'a>;

pub struct ConsensusManagerBuilder<'r> {
    log: ReplicaLogger,
    metrics_registry: &'r MetricsRegistry,
    rt_handle: Handle,
    clients: Vec<StartConsensusManagerFn<'r>>,
    router: Option<Router>,
}

impl<'r> ConsensusManagerBuilder<'r> {
    pub fn new(
        log: ReplicaLogger,
        rt_handle: Handle,
        metrics_registry: &'r MetricsRegistry,
    ) -> Self {
        Self {
            log,
            metrics_registry,
            rt_handle,
            clients: Vec::new(),
            router: None,
        }
    }

    pub fn add_client<Artifact, Pool>(
        &mut self,
        adverts_to_send: Receiver<ArtifactProcessorEvent<Artifact>>,
        raw_pool: Arc<RwLock<Pool>>,
        priority_fn_producer: Arc<dyn PriorityFnAndFilterProducer<Artifact, Pool>>,
        sender: CrossbeamSender<UnvalidatedArtifactMutation<Artifact>>,
    ) where
        Pool: 'static + Send + Sync + ValidatedPoolReader<Artifact>,
        Artifact: ArtifactKind + Serialize + for<'a> Deserialize<'a> + Send + 'static,
        <Artifact as ArtifactKind>::Id:
            Serialize + for<'a> Deserialize<'a> + Clone + Eq + Hash + Send + Sync,
        <Artifact as ArtifactKind>::Message: Serialize + for<'a> Deserialize<'a> + Send,
        <Artifact as ArtifactKind>::Attribute: Serialize + for<'a> Deserialize<'a> + Send + Sync,
    {
        let (router, adverts_from_peers_rx) = build_axum_router(self.log.clone(), raw_pool.clone());

        let log = self.log.clone();
        let rt_handle = self.rt_handle.clone();
        let metrics_registry = self.metrics_registry;

        let builder = move |transport: Arc<dyn Transport>, topology_watcher| {
            start_consensus_manager(
                log,
                metrics_registry,
                rt_handle,
                adverts_to_send,
                adverts_from_peers_rx,
                raw_pool,
                priority_fn_producer,
                sender,
                transport,
                topology_watcher,
            )
        };

        self.router = Some(self.router.take().unwrap_or_default().merge(router));

        self.clients.push(Box::new(builder));
    }

    pub fn router(&mut self) -> Router {
        self.router.take().unwrap_or_default()
    }

    pub fn run(
        self,
        transport: Arc<dyn Transport>,
        topology_watcher: watch::Receiver<SubnetTopology>,
    ) {
        for client in self.clients {
            client(transport.clone(), topology_watcher.clone());
        }
    }
}

fn start_consensus_manager<Artifact, Pool>(
    log: ReplicaLogger,
    metrics_registry: &MetricsRegistry,
    rt_handle: Handle,
    // Locally produced adverts to send to the node's peers.
    adverts_to_send: Receiver<ArtifactProcessorEvent<Artifact>>,
    // Adverts received from peers
    adverts_received: Receiver<(AdvertUpdate<Artifact>, NodeId, ConnId)>,
    raw_pool: Arc<RwLock<Pool>>,
    priority_fn_producer: Arc<dyn PriorityFnAndFilterProducer<Artifact, Pool>>,
    sender: CrossbeamSender<UnvalidatedArtifactMutation<Artifact>>,
    transport: Arc<dyn Transport>,
    topology_watcher: watch::Receiver<SubnetTopology>,
) where
    Pool: 'static + Send + Sync + ValidatedPoolReader<Artifact>,
    Artifact: ArtifactKind + Serialize + for<'a> Deserialize<'a> + Send + 'static,
    <Artifact as ArtifactKind>::Id:
        Serialize + for<'a> Deserialize<'a> + Clone + Eq + Hash + Send + Sync,
    <Artifact as ArtifactKind>::Message: Serialize + for<'a> Deserialize<'a> + Send,
    <Artifact as ArtifactKind>::Attribute: Serialize + for<'a> Deserialize<'a> + Send + Sync,
{
    let metrics = ConsensusManagerMetrics::new::<Artifact>(metrics_registry);

    ConsensusManagerSender::run(
        log.clone(),
        metrics.clone(),
        rt_handle.clone(),
        raw_pool.clone(),
        transport.clone(),
        adverts_to_send,
    );

    ConsensusManagerReceiver::run(
        log,
        metrics,
        rt_handle,
        adverts_received,
        raw_pool,
        priority_fn_producer,
        sender,
        transport,
        topology_watcher,
    );
}

// TODO: Consider creating a types.rs file and move these there:
#[derive(Deserialize, Serialize)]
pub enum Data<Artifact: ArtifactKind>
where
    <Artifact as ArtifactKind>::Id: Serialize + for<'a> Deserialize<'a>,
    <Artifact as ArtifactKind>::Message: Serialize,
    <Artifact as ArtifactKind>::Attribute: Serialize + for<'a> Deserialize<'a>,
{
    Artifact(Artifact::Message),
    Advert(Advert<Artifact>),
}

#[derive(Deserialize, Serialize)]
pub struct AdvertUpdate<Artifact: ArtifactKind>
where
    <Artifact as ArtifactKind>::Id: Serialize + for<'a> Deserialize<'a>,
    <Artifact as ArtifactKind>::Message: Serialize + for<'a> Deserialize<'a>,
    <Artifact as ArtifactKind>::Attribute: Serialize + for<'a> Deserialize<'a>,
{
    slot_number: SlotNumber,
    commit_id: CommitId,
    data: Data<Artifact>,
}

struct SlotNumberTag;
pub(crate) type SlotNumber = AmountOf<SlotNumberTag, u64>;

struct CommitIdTag;
pub(crate) type CommitId = AmountOf<CommitIdTag, u64>;
