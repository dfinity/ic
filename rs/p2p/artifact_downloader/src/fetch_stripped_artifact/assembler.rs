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
    CountBytes, NodeId,
};

use crate::FetchArtifact;

use super::{
    download::download_ingress,
    metrics::FetchStrippedConsensusArtifactMetrics,
    types::stripped::{MaybeStrippedConsensusMessage, Strippable},
};

const STRIP_THRESHOLD: usize = 1000;

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
            .get(&id.0)
            .map(MaybeStrippedConsensusMessage::Unstripped)
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

        Box::new(move |id, attributes| nested(&id.0, attributes))
    }
}

#[derive(Clone)]
pub struct FetchStrippedConsensusArtifact {
    log: ReplicaLogger,
    ingress_pool: ValidatedPoolReaderRef<SignedIngress>,
    fetch_stripped: FetchArtifact<MaybeStrippedConsensusMessage>,
    transport: Arc<dyn Transport>,
    node_id: NodeId,
    metrics: FetchStrippedConsensusArtifactMetrics,
    // TODO: decide if needed
    // priority_fn: watch::Receiver<PriorityFn<>>,
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
                metrics: FetchStrippedConsensusArtifactMetrics::new(&metrics_registry),
            }
        };

        (handler, router)
    }
}

impl ArtifactAssembler<ConsensusMessage, MaybeStrippedConsensusMessage>
    for FetchStrippedConsensusArtifact
{
    fn disassemble_message(&self, msg: ConsensusMessage) -> MaybeStrippedConsensusMessage {
        match msg {
            ConsensusMessage::BlockProposal(block_proposal)
                if block_proposal.as_ref().payload.payload_type()
                    == ic_types::consensus::PayloadType::Data =>
            {
                MaybeStrippedConsensusMessage::StrippedBlockProposal(
                    block_proposal.strip_ingresses(|ingress_message| {
                        ingress_message.count_bytes() > STRIP_THRESHOLD
                    }),
                )
            }
            msg => MaybeStrippedConsensusMessage::Unstripped(msg),
        }
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

            let block_id = id.0;

            let mut join_set = tokio::task::JoinSet::new();

            let missing_ingresses = stripped_block_proposal.missing();
            let total_ingresses_count = stripped_block_proposal
                .payload
                .ingress
                .ingress_messages
                .len();
            // For each stripped object in the message, try to fetch it either from the local pools
            // or from a random peer who is advertising it.
            for stripped_object_id in missing_ingresses {
                join_set.spawn(get_or_fetch(
                    stripped_object_id,
                    self.ingress_pool.clone(),
                    self.transport.clone(),
                    block_id.clone(),
                    self.log.clone(),
                    self.node_id,
                    peer_rx.clone(),
                ));
            }

            let mut found_stripped_ingress_messages = 0;
            let mut missing_stripped_ingress_messages = 0;

            if !join_set.is_empty() {
                let timer = self
                    .metrics
                    .download_missing_ingress_messages_duration
                    .start_timer();

                // TODO: fix this
                while let Some(Ok(Ok((ingress, peer_id)))) = join_set.join_next().await {
                    if peer_id == self.node_id {
                        found_stripped_ingress_messages += 1;
                    } else {
                        missing_stripped_ingress_messages += 1;
                    }

                    stripped_block_proposal
                        .try_insert(ingress)
                        .map_err(|_| Aborted {})?;
                }

                if missing_stripped_ingress_messages > 0 {
                    timer.stop_and_record();
                } else {
                    timer.stop_and_discard();
                }
            }

            // FIXME(kpop): remove the `unwrap()`.
            let reconstructed_block_proposal = stripped_block_proposal.try_assemble().unwrap();

            self.metrics
                .found_stripped_ingress_messages
                .observe(found_stripped_ingress_messages as f64);
            self.metrics
                .missing_stripped_ingress_messages
                .observe(missing_stripped_ingress_messages as f64);
            self.metrics
                .total_ingress_messages
                .observe(total_ingresses_count as f64);

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
) -> Result<(SignedIngress, NodeId), ()> {
    // First check if the ingress message exists in the Ingress Pool.
    if let Some(ingress_message) = ingress_pool.read().unwrap().get(&ingress_message_id) {
        return Ok((ingress_message, node_id));
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
