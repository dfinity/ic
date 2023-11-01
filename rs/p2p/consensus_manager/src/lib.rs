use std::{
    hash::Hash,
    sync::{Arc, RwLock},
};

use crate::metrics::ConsensusManagerMetrics;
use crossbeam_channel::Sender as CrossbeamSender;
use ic_interfaces::{
    artifact_manager::ArtifactProcessorEvent,
    artifact_pool::{PriorityFnAndFilterProducer, UnvalidatedArtifactEvent, ValidatedPoolReader},
};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_peer_manager::SubnetTopology;
use ic_quic_transport::{ConnId, Transport};
use ic_types::artifact::{Advert, ArtifactKind};
use ic_types::NodeId;
use phantom_newtype::AmountOf;
use receiver::ConsensusManagerReceiver;
use sender::ConsensusManagerSender;
use serde::{Deserialize, Serialize};
use tokio::{
    runtime::Handle,
    sync::{mpsc::Receiver, watch},
};

pub use receiver::build_axum_router;

mod metrics;
mod receiver;
mod sender;

#[allow(unused)]
pub fn start_consensus_manager<Artifact, Pool>(
    log: ReplicaLogger,
    metrics_registry: &MetricsRegistry,
    rt_handle: Handle,
    // Locally produced adverts to send to the node's peers.
    adverts_to_send: Receiver<ArtifactProcessorEvent<Artifact>>,
    // Adverts received from peers
    adverts_received: Receiver<(AdvertUpdate<Artifact>, NodeId, ConnId)>,
    raw_pool: Arc<RwLock<Pool>>,
    priority_fn_producer: Arc<dyn PriorityFnAndFilterProducer<Artifact, Pool>>,
    sender: CrossbeamSender<UnvalidatedArtifactEvent<Artifact>>,
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
