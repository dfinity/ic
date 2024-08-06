use std::sync::{Arc, RwLock};

use ic_interfaces::p2p::consensus::{
    Aborted, ArtifactAssembler, Peers, PriorityFnFactory, ValidatedPoolReader,
};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_quic_transport::Transport;
use ic_types::{
    artifact::{ConsensusMessageId, IdentifiableArtifact, IngressMessageId},
    consensus::ConsensusMessage,
    messages::SignedIngress,
    NodeId,
};

use crate::FetchArtifact;

use super::{
    download::download_ingress, metrics::FetchStrippedConsensusArtifactMetrics,
    stripper::Strippable, types::stripped::MaybeStrippedConsensusMessage,
};

type ValidatedPoolReaderRef<T> = Arc<RwLock<dyn ValidatedPoolReader<T> + Send + Sync>>;

struct PriorityFnFactoryWrapper<Pool: ValidatedPoolReader<ConsensusMessage>> {
    pfn_producer: Arc<dyn PriorityFnFactory<ConsensusMessage, Pool>>,
}

struct ConsensusPoolWrapper<Pool: ValidatedPoolReader<ConsensusMessage>> {
    consensus_pool: Arc<RwLock<Pool>>,
}

impl<Pool: ValidatedPoolReader<ConsensusMessage>> ValidatedPoolReader<MaybeStrippedConsensusMessage>
    for ConsensusPoolWrapper<Pool>
{
    fn get(
        &self,
        id: &<MaybeStrippedConsensusMessage as IdentifiableArtifact>::Id,
    ) -> Option<MaybeStrippedConsensusMessage> {
        self.consensus_pool
            .read()
            .unwrap()
            .get(id.as_ref())
            .map(Strippable::strip)
    }

    fn get_all_validated(&self) -> Box<dyn Iterator<Item = MaybeStrippedConsensusMessage> + '_> {
        Box::new(std::iter::empty())
    }
}

impl<Pool: ValidatedPoolReader<ConsensusMessage>>
    PriorityFnFactory<MaybeStrippedConsensusMessage, ConsensusPoolWrapper<Pool>>
    for PriorityFnFactoryWrapper<Pool>
{
    fn get_priority_function(
        &self,
        pool: &ConsensusPoolWrapper<Pool>,
    ) -> ic_interfaces::p2p::consensus::PriorityFn<
        <MaybeStrippedConsensusMessage as IdentifiableArtifact>::Id,
        <MaybeStrippedConsensusMessage as IdentifiableArtifact>::Attribute,
    > {
        let pool = pool.consensus_pool.read().unwrap();
        let nested = self.pfn_producer.get_priority_function(&pool);

        Box::new(move |id, attributes| nested(id.as_ref(), attributes))
    }
}

#[derive(Clone)]
pub struct FetchStrippedConsensusArtifact {
    log: ReplicaLogger,
    ingress_pool: ValidatedPoolReaderRef<SignedIngress>,
    fetch_stripped: FetchArtifact<MaybeStrippedConsensusMessage>,
    transport: Arc<dyn Transport>,
    node_id: NodeId,
    _metrics: FetchStrippedConsensusArtifactMetrics,
}

impl FetchStrippedConsensusArtifact {
    pub fn new<Pool: ValidatedPoolReader<ConsensusMessage> + Send + Sync + 'static>(
        log: ReplicaLogger,
        rt: tokio::runtime::Handle,
        consensus_pool: Arc<RwLock<Pool>>,
        ingress_pool: ValidatedPoolReaderRef<SignedIngress>,
        pfn_producer: Arc<dyn PriorityFnFactory<ConsensusMessage, Pool>>,
        metrics_registry: MetricsRegistry,
        node_id: NodeId,
    ) -> (impl Fn(Arc<dyn Transport>) -> Self, axum::Router) {
        let ingress_pool_clone = ingress_pool.clone();
        let consensus_pool_clone = consensus_pool.clone();

        let router = super::download::build_axum_router(super::download::Pools {
            consensus_pool: consensus_pool_clone,
            ingress_pool: ingress_pool_clone,
        });

        let (fetch_stripped_fn, subrouter) = FetchArtifact::new(
            log.clone(),
            rt,
            Arc::new(RwLock::new(ConsensusPoolWrapper { consensus_pool })),
            Arc::new(PriorityFnFactoryWrapper { pfn_producer }),
            metrics_registry.clone(),
        );

        let router = axum::Router::new().merge(router).merge(subrouter);

        let handler = move |transport: Arc<dyn Transport>| {
            let fetch_stripped = fetch_stripped_fn(transport.clone());

            Self {
                log: log.clone(),
                ingress_pool: ingress_pool.clone(),
                fetch_stripped,
                transport,
                node_id,
                _metrics: FetchStrippedConsensusArtifactMetrics::new(&metrics_registry),
            }
        };

        (handler, router)
    }
}

impl ArtifactAssembler<ConsensusMessage, MaybeStrippedConsensusMessage>
    for FetchStrippedConsensusArtifact
{
    fn disassemble_message(&self, msg: ConsensusMessage) -> MaybeStrippedConsensusMessage {
        msg.strip()
    }

    fn assemble_message<P: Peers + Clone + Send + 'static>(
        &self,
        id: <MaybeStrippedConsensusMessage as IdentifiableArtifact>::Id,
        attr: <MaybeStrippedConsensusMessage as IdentifiableArtifact>::Attribute,
        artifact: Option<(MaybeStrippedConsensusMessage, NodeId)>,
        peer_rx: P,
    ) -> impl std::future::Future<Output = Result<(ConsensusMessage, NodeId), Aborted>> + Send {
        async move {
            // Download the Stripped message if it hasn't been pushed.
            let (stripped_artifact, peer) = self
                .fetch_stripped
                .assemble_message(id.clone(), attr, artifact, peer_rx.clone())
                .await?;

            let mut stripped_block_proposal = match stripped_artifact {
                MaybeStrippedConsensusMessage::StrippedBlockProposal(stripped) => stripped,
                MaybeStrippedConsensusMessage::Unstripped(unstripped) => {
                    return Ok((unstripped, peer));
                }
            };

            let mut join_set = tokio::task::JoinSet::new();

            let missing_ingress_ids = stripped_block_proposal.missing_ingress_messages();
            // For each stripped object in the message, try to fetch it either from the local pools
            // or from a random peer who is advertising it.
            for missing_ingress_id in missing_ingress_ids {
                join_set.spawn(get_or_fetch(
                    missing_ingress_id,
                    self.ingress_pool.clone(),
                    self.transport.clone(),
                    id.as_ref().clone(),
                    self.log.clone(),
                    self.node_id,
                    peer_rx.clone(),
                ));
            }

            while let Some(join_result) = join_set.join_next().await {
                let Ok((ingress, _peer_id)) = join_result else {
                    return Err(Aborted {});
                };

                stripped_block_proposal
                    .try_insert_ingress_message(ingress)
                    .map_err(|_| Aborted {})?;
            }

            let reconstructed_block_proposal = stripped_block_proposal
                .try_assemble()
                .map_err(|_| Aborted {})?;

            Ok((
                ConsensusMessage::BlockProposal(reconstructed_block_proposal),
                peer,
            ))
        }
    }
}

/// Tries to get the missing object either from the pool(s) or from the peers who are advertising
/// it.
async fn get_or_fetch<P: Peers>(
    ingress_message_id: IngressMessageId,
    ingress_pool: ValidatedPoolReaderRef<SignedIngress>,
    transport: Arc<dyn Transport>,
    // Id of the *full* artifact which should contain the missing data
    full_consensus_message_id: ConsensusMessageId,
    log: ReplicaLogger,
    node_id: NodeId,
    peer_rx: P,
) -> (SignedIngress, NodeId) {
    // First check if the ingress message exists in the Ingress Pool.
    if let Some(ingress_message) = ingress_pool.read().unwrap().get(&ingress_message_id) {
        return (ingress_message, node_id);
    }

    download_ingress(
        transport,
        ingress_message_id,
        full_consensus_message_id,
        &log,
        peer_rx,
    )
    .await
}
