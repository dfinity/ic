use std::sync::Arc;

use crate::{
    metrics::ConsensusManagerMetrics,
    receiver::{ConsensusManagerReceiver, build_axum_router},
    sender::ConsensusManagerSender,
};
use axum::Router;
use ic_base_types::NodeId;
use ic_interfaces::p2p::consensus::{ArtifactAssembler, ArtifactTransmit};
use ic_limits::MAX_P2P_IO_CHANNEL_SIZE;
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_quic_transport::{ConnId, Shutdown, SubnetTopology, Transport};
use ic_types::artifact::{IdentifiableArtifact, PbArtifact, UnvalidatedArtifactMutation};
use phantom_newtype::AmountOf;
use tokio::{
    runtime::Handle,
    sync::{
        mpsc::{Receiver, Sender},
        watch,
    },
};

mod metrics;
mod receiver;
mod sender;

type StartConsensusManagerFn =
    Box<dyn FnOnce(Arc<dyn Transport>, watch::Receiver<SubnetTopology>) -> Vec<Shutdown>>;

pub type AbortableBroadcastSender<T> = Sender<ArtifactTransmit<T>>;
pub type AbortableBroadcastReceiver<T> = Receiver<UnvalidatedArtifactMutation<T>>;

pub struct AbortableBroadcastChannel<T: IdentifiableArtifact> {
    pub outbound_tx: AbortableBroadcastSender<T>,
    pub inbound_rx: AbortableBroadcastReceiver<T>,
    pub inbound_tx: Sender<UnvalidatedArtifactMutation<T>>,
}

pub struct AbortableBroadcastChannelBuilder {
    log: ReplicaLogger,
    metrics_registry: MetricsRegistry,
    rt_handle: Handle,
    managers: Vec<StartConsensusManagerFn>,
    router: Option<Router>,
}

impl AbortableBroadcastChannelBuilder {
    pub fn new(log: ReplicaLogger, rt_handle: Handle, metrics_registry: MetricsRegistry) -> Self {
        Self {
            log,
            metrics_registry,
            rt_handle,
            managers: Vec::new(),
            router: None,
        }
    }

    /// Creates a channel for the corresponding artifact. The channel is used to broadcast artifacts within the subnet.
    pub fn abortable_broadcast_channel<
        Artifact: IdentifiableArtifact,
        WireArtifact: PbArtifact,
        F: FnOnce(Arc<dyn Transport>) -> D + 'static,
        D: ArtifactAssembler<Artifact, WireArtifact>,
    >(
        &mut self,
        (assembler, assembler_router): (F, Router),
        slot_limit: usize,
    ) -> AbortableBroadcastChannel<Artifact> {
        let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(MAX_P2P_IO_CHANNEL_SIZE);
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(MAX_P2P_IO_CHANNEL_SIZE);

        assert!(
            uri_prefix::<WireArtifact>()
                .chars()
                .all(char::is_alphabetic)
        );
        let (router, adverts_from_peers_rx) = build_axum_router(self.log.clone());

        let log = self.log.clone();
        let rt_handle = self.rt_handle.clone();
        let metrics_registry = self.metrics_registry.clone();

        let inbound_tx_clone = inbound_tx.clone();
        let builder = move |transport: Arc<dyn Transport>, topology_watcher| {
            start_consensus_manager(
                log,
                &metrics_registry,
                rt_handle,
                outbound_rx,
                adverts_from_peers_rx,
                inbound_tx_clone,
                assembler(transport.clone()),
                transport,
                topology_watcher,
                slot_limit,
            )
        };

        self.router = Some(
            self.router
                .take()
                .unwrap_or_default()
                .merge(router)
                .merge(assembler_router),
        );

        self.managers.push(Box::new(builder));
        AbortableBroadcastChannel {
            outbound_tx,
            inbound_rx,
            inbound_tx,
        }
    }

    pub fn router(&self) -> Router {
        self.router.clone().unwrap_or_default()
    }

    pub fn start(
        self,
        transport: Arc<dyn Transport>,
        topology_watcher: watch::Receiver<SubnetTopology>,
    ) -> Vec<Shutdown> {
        let mut ret = vec![];
        for m in self.managers {
            ret.append(&mut m(transport.clone(), topology_watcher.clone()));
        }
        ret
    }
}

fn start_consensus_manager<Artifact, WireArtifact, Assembler>(
    log: ReplicaLogger,
    metrics_registry: &MetricsRegistry,
    rt_handle: Handle,
    // Locally produced adverts to send to the node's peers.
    outbound_transmits: Receiver<ArtifactTransmit<Artifact>>,
    // Slot updates received from peers
    slot_updates_rx: Receiver<(SlotUpdate<WireArtifact>, NodeId, ConnId)>,
    sender: Sender<UnvalidatedArtifactMutation<Artifact>>,
    assembler: Assembler,
    transport: Arc<dyn Transport>,
    topology_watcher: watch::Receiver<SubnetTopology>,
    slot_limit: usize,
) -> Vec<Shutdown>
where
    Artifact: IdentifiableArtifact,
    WireArtifact: PbArtifact,
    Assembler: ArtifactAssembler<Artifact, WireArtifact>,
{
    let metrics = ConsensusManagerMetrics::new::<WireArtifact>(metrics_registry);

    let shutdown_send_side = ConsensusManagerSender::<Artifact, WireArtifact, _>::run(
        log.clone(),
        metrics.clone(),
        rt_handle.clone(),
        transport.clone(),
        outbound_transmits,
        assembler.clone(),
    );

    let shutdown_receive_side = ConsensusManagerReceiver::run(
        log,
        metrics,
        rt_handle,
        slot_updates_rx,
        assembler,
        sender,
        topology_watcher,
        slot_limit,
    );
    vec![shutdown_send_side, shutdown_receive_side]
}

struct SlotUpdate<Artifact: PbArtifact> {
    slot_number: SlotNumber,
    commit_id: CommitId,
    update: Update<Artifact>,
}

enum Update<Artifact: PbArtifact> {
    Artifact(Artifact),
    Id(Artifact::Id),
}

fn uri_prefix<Artifact: PbArtifact>() -> String {
    Artifact::NAME.to_lowercase()
}

struct SlotNumberTag;
type SlotNumber = AmountOf<SlotNumberTag, u64>;

struct CommitIdTag;
type CommitId = AmountOf<CommitIdTag, u64>;
