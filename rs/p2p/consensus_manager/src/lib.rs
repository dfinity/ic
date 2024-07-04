use std::sync::{Arc, RwLock};

use crate::{
    metrics::ConsensusManagerMetrics,
    receiver::{build_axum_router, ConsensusManagerReceiver},
    sender::ConsensusManagerSender,
};
use axum::Router;
use ic_base_types::NodeId;
use ic_interfaces::p2p::{
    artifact_manager::ArtifactProcessorEvent,
    consensus::{PriorityFnAndFilterProducer, ValidatedPoolReader},
};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_quic_transport::{ConnId, SubnetTopology, Transport};
use ic_types::artifact::{ArtifactKind, UnvalidatedArtifactMutation};
use phantom_newtype::AmountOf;
use tokio::{
    runtime::Handle,
    sync::{
        mpsc::{Receiver, UnboundedSender},
        watch,
    },
};
use tokio_util::sync::CancellationToken;

mod metrics;
mod receiver;
mod sender;

type StartConsensusManagerFn = Box<dyn FnOnce(Arc<dyn Transport>, watch::Receiver<SubnetTopology>)>;

pub struct ConsensusManagerBuilder {
    log: ReplicaLogger,
    metrics_registry: MetricsRegistry,
    rt_handle: Handle,
    clients: Vec<StartConsensusManagerFn>,
    router: Option<Router>,
    cancellation_token: CancellationToken,
}

impl ConsensusManagerBuilder {
    pub fn new(log: ReplicaLogger, rt_handle: Handle, metrics_registry: MetricsRegistry) -> Self {
        Self {
            log,
            metrics_registry,
            rt_handle,
            clients: Vec::new(),
            router: None,
            cancellation_token: CancellationToken::new(),
        }
    }

    pub fn add_client<Artifact, Pool>(
        &mut self,
        outbound_artifacts_rx: Receiver<ArtifactProcessorEvent<Artifact>>,
        pool: Arc<RwLock<Pool>>,
        priority_fn_producer: Arc<dyn PriorityFnAndFilterProducer<Artifact, Pool>>,
        inbound_artifacts_tx: UnboundedSender<UnvalidatedArtifactMutation<Artifact>>,
    ) where
        Pool: 'static + Send + Sync + ValidatedPoolReader<Artifact>,
        Artifact: ArtifactKind,
    {
        let (router, adverts_from_peers_rx) = build_axum_router(self.log.clone(), pool.clone());

        let log = self.log.clone();
        let rt_handle = self.rt_handle.clone();
        let metrics_registry = self.metrics_registry.clone();
        let cancellation_token = self.cancellation_token.child_token();

        let builder = move |transport: Arc<dyn Transport>, topology_watcher| {
            start_consensus_manager(
                log,
                &metrics_registry,
                rt_handle,
                outbound_artifacts_rx,
                adverts_from_peers_rx,
                pool,
                priority_fn_producer,
                inbound_artifacts_tx,
                transport,
                topology_watcher,
                cancellation_token,
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
    ) -> CancellationToken {
        for client in self.clients {
            client(transport.clone(), topology_watcher.clone());
        }
        self.cancellation_token
    }
}

fn start_consensus_manager<Artifact, Pool>(
    log: ReplicaLogger,
    metrics_registry: &MetricsRegistry,
    rt_handle: Handle,
    // Locally produced adverts to send to the node's peers.
    adverts_to_send: Receiver<ArtifactProcessorEvent<Artifact>>,
    // Adverts received from peers
    adverts_received: Receiver<(SlotUpdate<Artifact>, NodeId, ConnId)>,
    raw_pool: Arc<RwLock<Pool>>,
    priority_fn_producer: Arc<dyn PriorityFnAndFilterProducer<Artifact, Pool>>,
    sender: UnboundedSender<UnvalidatedArtifactMutation<Artifact>>,
    transport: Arc<dyn Transport>,
    topology_watcher: watch::Receiver<SubnetTopology>,
    cancellation_token: CancellationToken,
) where
    Pool: 'static + Send + Sync + ValidatedPoolReader<Artifact>,
    Artifact: ArtifactKind,
{
    let metrics = ConsensusManagerMetrics::new::<Artifact>(metrics_registry);

    ConsensusManagerSender::run(
        log.clone(),
        metrics.clone(),
        rt_handle.clone(),
        transport.clone(),
        adverts_to_send,
        cancellation_token,
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

pub(crate) struct SlotUpdate<Artifact: ArtifactKind> {
    slot_number: SlotNumber,
    commit_id: CommitId,
    update: Update<Artifact>,
}

pub(crate) enum Update<Artifact: ArtifactKind> {
    Artifact(Artifact::Message),
    Advert((Artifact::Id, Artifact::Attribute)),
}

pub(crate) fn uri_prefix<Artifact: ArtifactKind>() -> String {
    Artifact::TAG.to_string().to_lowercase()
}

struct SlotNumberTag;
pub(crate) type SlotNumber = AmountOf<SlotNumberTag, u64>;

struct CommitIdTag;
pub(crate) type CommitId = AmountOf<CommitIdTag, u64>;

#[cfg(test)]
mod tests {
    use ic_types::artifact_kind::{
        CanisterHttpArtifact, CertificationArtifact, ConsensusArtifact, DkgArtifact, IDkgArtifact,
        IngressArtifact,
    };

    use crate::uri_prefix;

    #[test]
    fn no_special_chars_in_uri() {
        assert!(uri_prefix::<ConsensusArtifact>()
            .chars()
            .all(char::is_alphabetic));
        assert!(uri_prefix::<CertificationArtifact>()
            .chars()
            .all(char::is_alphabetic));
        assert!(uri_prefix::<DkgArtifact>().chars().all(char::is_alphabetic));
        assert!(uri_prefix::<IngressArtifact>()
            .chars()
            .all(char::is_alphabetic));
        assert!(uri_prefix::<IDkgArtifact>()
            .chars()
            .all(char::is_alphabetic));
        assert!(uri_prefix::<CanisterHttpArtifact>()
            .chars()
            .all(char::is_alphabetic));
    }
}
