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
use ic_protobuf::{
    p2p::v1 as pb,
    proxy::{try_from_option_field, ProtoProxy, ProxyDecodeError},
};
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
        adverts_to_send: Receiver<ArtifactProcessorEvent<Artifact>>,
        raw_pool: Arc<RwLock<Pool>>,
        priority_fn_producer: Arc<dyn PriorityFnAndFilterProducer<Artifact, Pool>>,
        sender: UnboundedSender<UnvalidatedArtifactMutation<Artifact>>,
    ) where
        Pool: 'static + Send + Sync + ValidatedPoolReader<Artifact>,
        Artifact: ArtifactKind,
    {
        let (router, adverts_from_peers_rx) = build_axum_router(self.log.clone(), raw_pool.clone());

        let log = self.log.clone();
        let rt_handle = self.rt_handle.clone();
        let metrics_registry = self.metrics_registry.clone();
        let cancellation_token = self.cancellation_token.child_token();

        let builder = move |transport: Arc<dyn Transport>, topology_watcher| {
            start_consensus_manager(
                log,
                &metrics_registry,
                rt_handle,
                adverts_to_send,
                adverts_from_peers_rx,
                raw_pool,
                priority_fn_producer,
                sender,
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
        raw_pool.clone(),
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

impl<Artifact: ArtifactKind> From<SlotUpdate<Artifact>> for pb::SlotUpdate {
    fn from(
        SlotUpdate {
            slot_number,
            commit_id,
            update,
        }: SlotUpdate<Artifact>,
    ) -> Self {
        Self {
            commit_id: commit_id.get(),
            slot_id: slot_number.get(),
            update: Some(match update {
                Update::Artifact(artifact) => {
                    pb::slot_update::Update::Artifact(Artifact::PbMessage::proxy_encode(artifact))
                }
                Update::Advert((id, attribute)) => pb::slot_update::Update::Advert(pb::Advert {
                    id: Artifact::PbId::proxy_encode(id),
                    attribute: Artifact::PbAttribute::proxy_encode(attribute),
                }),
            }),
        }
    }
}

impl<Artifact: ArtifactKind> TryFrom<pb::SlotUpdate> for SlotUpdate<Artifact> {
    type Error = ProxyDecodeError;
    fn try_from(value: pb::SlotUpdate) -> Result<Self, Self::Error> {
        Ok(Self {
            slot_number: SlotNumber::from(value.slot_id),
            commit_id: CommitId::from(value.commit_id),
            update: match try_from_option_field(value.update, "update")? {
                pb::slot_update::Update::Artifact(artifact) => {
                    Update::Artifact(Artifact::PbMessage::proxy_decode(&artifact)?)
                }
                pb::slot_update::Update::Advert(pb::Advert { id, attribute }) => Update::Advert((
                    Artifact::PbId::proxy_decode(&id)?,
                    Artifact::PbAttribute::proxy_decode(&attribute)?,
                )),
            },
        })
    }
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
        CanisterHttpArtifact, CertificationArtifact, ConsensusArtifact, DkgArtifact, EcdsaArtifact,
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
        assert!(uri_prefix::<EcdsaArtifact>()
            .chars()
            .all(char::is_alphabetic));
        assert!(uri_prefix::<CanisterHttpArtifact>()
            .chars()
            .all(char::is_alphabetic));
    }
}
