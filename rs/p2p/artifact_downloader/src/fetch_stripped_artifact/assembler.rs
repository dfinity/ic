use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

use ic_interfaces::p2p::consensus::{
    Aborted, ArtifactAssembler, BouncerFactory, Peers, ValidatedPoolReader,
};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use ic_quic_transport::Transport;
use ic_types::{
    artifact::{ConsensusMessageId, IdentifiableArtifact, IngressMessageId},
    consensus::{BlockProposal, ConsensusMessage},
    messages::SignedIngress,
    NodeId,
};

use crate::FetchArtifact;

use super::{
    download::download_ingress,
    metrics::FetchStrippedConsensusArtifactMetrics,
    stripper::Strippable,
    types::stripped::{
        MaybeStrippedConsensusMessage, StrippedBlockProposal, StrippedConsensusMessageId,
    },
};

type ValidatedPoolReaderRef<T> = Arc<RwLock<dyn ValidatedPoolReader<T> + Send + Sync>>;

struct BouncerFactoryWrapper<Pool: ValidatedPoolReader<ConsensusMessage>> {
    bouncer_factory: Arc<dyn BouncerFactory<ConsensusMessageId, Pool>>,
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
}

impl<Pool: ValidatedPoolReader<ConsensusMessage>>
    BouncerFactory<StrippedConsensusMessageId, ConsensusPoolWrapper<Pool>>
    for BouncerFactoryWrapper<Pool>
{
    fn new_bouncer(
        &self,
        pool: &ConsensusPoolWrapper<Pool>,
    ) -> ic_interfaces::p2p::consensus::Bouncer<StrippedConsensusMessageId> {
        let pool = pool.consensus_pool.read().unwrap();
        let nested = self.bouncer_factory.new_bouncer(&pool);

        Box::new(move |id| nested(id.as_ref()))
    }

    fn refresh_period(&self) -> Duration {
        Duration::from_secs(3)
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
        bouncer_factory: Arc<dyn BouncerFactory<ConsensusMessageId, Pool>>,
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
            Arc::new(BouncerFactoryWrapper { bouncer_factory }),
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

    async fn assemble_message<P: Peers + Clone + Send + 'static>(
        &self,
        id: <MaybeStrippedConsensusMessage as IdentifiableArtifact>::Id,
        artifact: Option<(MaybeStrippedConsensusMessage, NodeId)>,
        peer_rx: P,
    ) -> Result<(ConsensusMessage, NodeId), Aborted> {
        // Download the Stripped message if it hasn't been pushed.
        let (stripped_artifact, peer) = self
            .fetch_stripped
            .assemble_message(id.clone(), artifact, peer_rx.clone())
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

#[derive(Debug, PartialEq)]
pub(crate) enum InsertionError {}

#[derive(Debug, PartialEq)]
pub(crate) enum AssemblyError {}

impl StrippedBlockProposal {
    /// Returns the list of [`IngressMessageId`]s which have been stripped from the block.
    // TODO(kpop): Implement this
    pub(crate) fn missing_ingress_messages(&self) -> Vec<IngressMessageId> {
        unimplemented!()
    }

    /// Tries to insert a missing ingress message into the block.
    // TODO(kpop): Implement this
    pub(crate) fn try_insert_ingress_message(
        &mut self,
        _ingress_message: SignedIngress,
    ) -> Result<(), InsertionError> {
        unimplemented!()
    }

    /// Tries to reassemble a block.
    ///
    /// Fails if there are still some ingress messages missing.
    // TODO(kpop): Implement this
    pub(crate) fn try_assemble(self) -> Result<BlockProposal, AssemblyError> {
        unimplemented!()
    }
}
