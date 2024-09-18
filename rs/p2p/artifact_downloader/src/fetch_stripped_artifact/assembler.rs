use std::{
    sync::{Arc, RwLock},
    time::Duration,
};
use thiserror::Error;

use ic_interfaces::p2p::consensus::{
    Aborted, ArtifactAssembler, BouncerFactory, Peers, ValidatedPoolReader,
};
use ic_logger::{warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::types::v1 as pb;
use ic_quic_transport::Transport;
use ic_types::{
    artifact::{ConsensusMessageId, IdentifiableArtifact, IngressMessageId},
    batch::IngressPayload,
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

    fn get_all_validated(&self) -> Box<dyn Iterator<Item = MaybeStrippedConsensusMessage> + '_> {
        // This method will never be called, so it's okay to return an empty iterator.
        Box::new(std::iter::empty())
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

        let stripped_block_proposal = match stripped_artifact {
            MaybeStrippedConsensusMessage::StrippedBlockProposal(stripped) => stripped,
            MaybeStrippedConsensusMessage::Unstripped(unstripped) => {
                return Ok((unstripped, peer));
            }
        };

        let mut join_set = tokio::task::JoinSet::new();

        let mut assembler = BlockProposalAssembler::new(stripped_block_proposal);

        let missing_ingress_ids = assembler.missing_ingress_messages();
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

            if let Err(err) = assembler.try_insert_ingress_message(ingress) {
                warn!(
                    self.log,
                    "Failed to ingress message {}. This is a bug.", err
                );

                return Err(Aborted {});
            }
        }

        let reconstructed_block_proposal = assembler.try_assemble().map_err(|err| {
            warn!(
                self.log,
                "Failed to reassemble the block {}. This is a bug.", err
            );

            Aborted {}
        })?;

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

#[derive(Debug, PartialEq, Error)]
pub(crate) enum InsertionError {
    #[error("Trying to insert an ingress message which was never missing")]
    NotNeeded,
    #[error("Trying to insert an ingress message which was already inserted")]
    AlreadyInserted,
}

#[derive(Debug, Error)]
pub(crate) enum AssemblyError {
    #[error("The block proposal is missing ingress message with id {0}")]
    Missing(IngressMessageId),
    #[error("The block proposal cannot be deserialized {0}")]
    DeserializationFailed(ProxyDecodeError),
}

struct BlockProposalAssembler {
    stripped_block_proposal: StrippedBlockProposal,
    ingress_messages: Vec<(IngressMessageId, Option<SignedIngress>)>,
}

impl BlockProposalAssembler {
    fn new(stripped_block_proposal: StrippedBlockProposal) -> Self {
        Self {
            ingress_messages: stripped_block_proposal
                .stripped_ingress_payload
                .ingress_messages
                .iter()
                .map(|ingress_message_id| (ingress_message_id.clone(), None))
                .collect(),
            stripped_block_proposal,
        }
    }

    /// Returns the list of [`IngressMessageId`]s which have been stripped from the block.
    pub(crate) fn missing_ingress_messages(&self) -> Vec<IngressMessageId> {
        self.ingress_messages
            .iter()
            .filter_map(|(ingress_message_id, maybe_ingress)| {
                if maybe_ingress.is_none() {
                    Some(ingress_message_id)
                } else {
                    None
                }
            })
            .cloned()
            .collect()
    }

    /// Tries to insert a missing ingress message into the block.
    pub(crate) fn try_insert_ingress_message(
        &mut self,
        ingress_message: SignedIngress,
    ) -> Result<(), InsertionError> {
        let ingress_message_id = IngressMessageId::from(&ingress_message);

        // We can have at most 1000 elements in the vector, so it should be reasonably fast to do a
        // linear scan here.
        let (_, ingress) = self
            .ingress_messages
            .iter_mut()
            .find(|(id, _maybe_ingress)| *id == ingress_message_id)
            .ok_or(InsertionError::NotNeeded)?;

        if ingress.is_some() {
            Err(InsertionError::AlreadyInserted)
        } else {
            *ingress = Some(ingress_message);
            Ok(())
        }
    }

    /// Tries to reassemble a block.
    ///
    /// Fails if there are still some ingress messages missing,
    /// or the assembled proposal can't be deserialized.
    pub(crate) fn try_assemble(self) -> Result<BlockProposal, AssemblyError> {
        let mut reconstructed_block_proposal_proto = self
            .stripped_block_proposal
            .block_proposal_without_ingresses_proto;

        let ingresses = self
            .ingress_messages
            .into_iter()
            .map(|(id, message)| message.ok_or_else(|| AssemblyError::Missing(id)))
            .collect::<Result<Vec<_>, _>>()?;
        let reconstructed_ingress_payload = IngressPayload::from(ingresses);

        let reconstructed_ingress_payload_proto =
            pb::IngressPayload::from(&reconstructed_ingress_payload);

        if let Some(block) = reconstructed_block_proposal_proto.value.as_mut() {
            block.ingress_payload = Some(reconstructed_ingress_payload_proto);
        }

        reconstructed_block_proposal_proto
            .try_into()
            .map_err(AssemblyError::DeserializationFailed)
    }
}

#[cfg(test)]
mod tests {
    use crate::fetch_stripped_artifact::test_utils::{
        fake_block_proposal_with_ingresses, fake_ingress_message,
        fake_ingress_message_with_arg_size, fake_stripped_block_proposal_with_ingresses,
    };

    use super::*;

    #[test]
    fn strip_assemble_roundtrip_test() {
        let (ingress_1, _ingress_id_1) = fake_ingress_message_with_arg_size("fake_1", 1024);
        let (ingress_2, _ingress_id_2) = fake_ingress_message_with_arg_size("fake_2", 1024);
        let block_proposal =
            fake_block_proposal_with_ingresses(vec![ingress_1.clone(), ingress_2.clone()]);
        let consensus_message = ConsensusMessage::BlockProposal(block_proposal.clone());

        // strip the block
        let MaybeStrippedConsensusMessage::StrippedBlockProposal(stripped_block_proposal) =
            consensus_message.strip()
        else {
            panic!("Didn't properly strip the block proposal");
        };

        let mut assembler = BlockProposalAssembler::new(stripped_block_proposal);

        // insert back the missing messages
        assembler.try_insert_ingress_message(ingress_1).unwrap();
        assembler.try_insert_ingress_message(ingress_2).unwrap();

        // try to reassemble the block
        let assembled_block = assembler.try_assemble().unwrap();

        assert_eq!(assembled_block, block_proposal);
    }

    #[test]
    fn strip_assemble_fails_when_still_missing_ingress_test() {
        let (ingress_1, _ingress_id_1) = fake_ingress_message_with_arg_size("fake_1", 1024);
        let (ingress_2, _ingress_id_2) = fake_ingress_message_with_arg_size("fake_2", 1024);
        let block_proposal =
            fake_block_proposal_with_ingresses(vec![ingress_1.clone(), ingress_2.clone()]);
        let consensus_message = ConsensusMessage::BlockProposal(block_proposal.clone());

        // strip the block
        let MaybeStrippedConsensusMessage::StrippedBlockProposal(stripped_block_proposal) =
            consensus_message.strip()
        else {
            panic!("Didn't properly strip the block proposal");
        };

        let mut assembler = BlockProposalAssembler::new(stripped_block_proposal);

        // insert back only one missing messages
        assembler.try_insert_ingress_message(ingress_1).unwrap();

        // try to reassemble the block
        let assembly_error = assembler.try_assemble().unwrap_err();

        match assembly_error {
            AssemblyError::Missing(_) => (),
            _ => panic!("Wrong error"),
        }
    }

    #[test]
    fn missing_ingress_messages_test() {
        let (_ingress_1, ingress_1_id) = fake_ingress_message("fake_1");
        let (_ingress_2, ingress_2_id) = fake_ingress_message("fake_2");
        let stripped_block_proposal = fake_stripped_block_proposal_with_ingresses(vec![
            ingress_1_id.clone(),
            ingress_2_id.clone(),
        ]);

        let assembler = BlockProposalAssembler::new(stripped_block_proposal);

        assert_eq!(
            assembler.missing_ingress_messages(),
            vec![ingress_1_id, ingress_2_id]
        );
    }

    #[test]
    fn ingress_payload_insertion_works_test() {
        let (ingress_2, ingress_2_id) = fake_ingress_message("fake_2");
        let stripped_block_proposal =
            fake_stripped_block_proposal_with_ingresses(vec![ingress_2_id.clone()]);

        let mut assembler = BlockProposalAssembler::new(stripped_block_proposal);

        assembler
            .try_insert_ingress_message(ingress_2)
            .expect("Should successfully insert the missing ingress");

        assert!(assembler.missing_ingress_messages().is_empty());
    }

    #[test]
    fn ingress_payload_insertion_existing_fails_test() {
        let (ingress_2, ingress_2_id) = fake_ingress_message("fake_2");
        let stripped_block_proposal =
            fake_stripped_block_proposal_with_ingresses(vec![ingress_2_id.clone()]);

        let mut assembler = BlockProposalAssembler::new(stripped_block_proposal);

        assembler
            .try_insert_ingress_message(ingress_2.clone())
            .expect("Should successfully insert the missing ingress");

        assert_eq!(
            assembler.try_insert_ingress_message(ingress_2),
            Err(InsertionError::AlreadyInserted)
        );
    }

    #[test]
    fn ingress_payload_insertion_unknown_fails_test() {
        let (ingress_1, _ingress_1_id) = fake_ingress_message("fake_1");
        let (_ingress_2, ingress_2_id) = fake_ingress_message("fake_2");
        let stripped_block_proposal =
            fake_stripped_block_proposal_with_ingresses(vec![ingress_2_id.clone()]);

        let mut assembler = BlockProposalAssembler::new(stripped_block_proposal);

        assert_eq!(
            assembler.try_insert_ingress_message(ingress_1),
            Err(InsertionError::NotNeeded)
        );
    }
}
