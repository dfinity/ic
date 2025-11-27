use std::{
    sync::{Arc, RwLock},
    time::Duration,
};
use thiserror::Error;

use ic_interfaces::p2p::consensus::{
    ArtifactAssembler, AssembleResult, BouncerFactory, Peers, ValidatedPoolReader,
};
use ic_logger::{ReplicaLogger, warn};
use ic_metrics::MetricsRegistry;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::types::v1 as pb;
use ic_quic_transport::Transport;
use ic_types::{
    CountBytes, NodeId,
    artifact::{ConsensusMessageId, IdentifiableArtifact, IngressMessageId},
    batch::IngressPayload,
    consensus::{BlockProposal, ConsensusMessage, idkg::IDkgMessage},
    messages::SignedIngress,
};

use crate::FetchArtifact;

use super::{
    download::download_ingress,
    metrics::{
        FetchStrippedConsensusArtifactMetrics, IngressMessageSource, StrippedMessageSenderMetrics,
    },
    stripper::Strippable,
    types::{
        SignedIngressId,
        stripped::{
            MaybeStrippedConsensusMessage, StrippedBlockProposal, StrippedConsensusMessageId,
        },
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
    metrics: Arc<FetchStrippedConsensusArtifactMetrics>,
}

impl FetchStrippedConsensusArtifact {
    pub fn new<Pool: ValidatedPoolReader<ConsensusMessage> + Send + Sync + 'static>(
        log: ReplicaLogger,
        rt: tokio::runtime::Handle,
        consensus_pool: Arc<RwLock<Pool>>,
        ingress_pool: ValidatedPoolReaderRef<SignedIngress>,
        idkg_pool: ValidatedPoolReaderRef<IDkgMessage>,
        bouncer_factory: Arc<dyn BouncerFactory<ConsensusMessageId, Pool>>,
        metrics_registry: MetricsRegistry,
        node_id: NodeId,
    ) -> (impl Fn(Arc<dyn Transport>) -> Self, axum::Router) {
        let ingress_pool_clone = ingress_pool.clone();
        let consensus_pool_clone = consensus_pool.clone();

        let router = super::download::build_axum_router(super::download::Pools {
            consensus_pool: consensus_pool_clone,
            ingress_pool: ingress_pool_clone,
            idkg_pool,
            metrics: StrippedMessageSenderMetrics::new(&metrics_registry),
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
                metrics: Arc::new(FetchStrippedConsensusArtifactMetrics::new(
                    &metrics_registry,
                )),
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
    ) -> AssembleResult<ConsensusMessage> {
        let total_timer = self.metrics.total_block_assembly_duration.start_timer();
        // Download the Stripped message if it hasn't been pushed.
        let (stripped_artifact, peer) = match self
            .fetch_stripped
            .assemble_message(id.clone(), artifact, peer_rx.clone())
            .await
        {
            AssembleResult::Unwanted => return AssembleResult::Unwanted,
            AssembleResult::Done { message, peer_id } => (message, peer_id),
        };

        let stripped_block_proposal = match stripped_artifact {
            MaybeStrippedConsensusMessage::StrippedBlockProposal(stripped) => stripped,
            MaybeStrippedConsensusMessage::Unstripped(unstripped) => {
                total_timer.stop_and_discard();
                return AssembleResult::Done {
                    message: unstripped,
                    peer_id: peer,
                };
            }
        };

        let mut join_set = tokio::task::JoinSet::new();

        let timer = self
            .metrics
            .download_missing_ingress_messages_duration
            .start_timer();
        let mut assembler = BlockProposalAssembler::new(stripped_block_proposal);

        let stripped_ingress_ids = assembler.missing_ingress_messages();
        // For each stripped object in the message, try to fetch it either from the local pools
        // or from a random peer who is advertising it.
        for stripped_ingress_id in stripped_ingress_ids {
            join_set.spawn(get_or_fetch(
                stripped_ingress_id,
                self.ingress_pool.clone(),
                self.transport.clone(),
                id.as_ref().clone(),
                self.log.clone(),
                self.metrics.clone(),
                self.node_id,
                peer_rx.clone(),
            ));
        }

        let mut ingress_messages_from_ingress_pool = 0;
        let mut ingress_messages_from_peers = 0;

        while let Some(join_result) = join_set.join_next().await {
            let Ok((ingress, ingress_id, peer_id)) = join_result else {
                return AssembleResult::Unwanted;
            };

            if peer_id == self.node_id {
                ingress_messages_from_ingress_pool += 1;
            } else {
                self.metrics
                    .missing_ingress_messages_bytes
                    .observe(ingress.count_bytes() as f64);
                ingress_messages_from_peers += 1;
            }

            if let Err(err) = assembler.try_insert_ingress_message(ingress, ingress_id) {
                warn!(
                    self.log,
                    "Failed to ingress message {}. This is a bug.", err
                );

                return AssembleResult::Unwanted;
            }
        }

        // Only report the metric if we actually downloaded some ingresses from peers
        if ingress_messages_from_peers > 0 {
            timer.stop_and_record();
        } else {
            timer.stop_and_discard();
        }

        self.metrics
            .report_ingress_messages_count(IngressMessageSource::Peer, ingress_messages_from_peers);

        self.metrics.report_ingress_messages_count(
            IngressMessageSource::IngressPool,
            ingress_messages_from_ingress_pool,
        );

        match assembler.try_assemble() {
            Ok(reconstructed_block_proposal) => AssembleResult::Done {
                message: ConsensusMessage::BlockProposal(reconstructed_block_proposal),
                peer_id: peer,
            },
            Err(err) => {
                warn!(
                    self.log,
                    "Failed to reassemble the block {}. This is a bug.", err
                );

                AssembleResult::Unwanted
            }
        }
    }
}

/// Tries to get the missing object either from the pool(s) or from the peers who are advertising
/// it.
async fn get_or_fetch<P: Peers>(
    signed_ingress_id: SignedIngressId,
    ingress_pool: ValidatedPoolReaderRef<SignedIngress>,
    transport: Arc<dyn Transport>,
    // Id of the *full* artifact which should contain the missing data
    full_consensus_message_id: ConsensusMessageId,
    log: ReplicaLogger,
    metrics: Arc<FetchStrippedConsensusArtifactMetrics>,
    node_id: NodeId,
    peer_rx: P,
) -> (SignedIngress, SignedIngressId, NodeId) {
    // First check if the ingress message exists in the Ingress Pool.
    if let Some(ingress_message) = ingress_pool
        .read()
        .unwrap()
        .get(&signed_ingress_id.ingress_message_id)
    {
        // Make sure that this is the correct ingress message. [`IngressMessageId`] does _not_
        // uniquely identify ingress messages, we thus need to perform an extra check.
        if SignedIngressId::from(&ingress_message) == signed_ingress_id {
            return (ingress_message, signed_ingress_id, node_id);
        }
    }

    let (ingress_message, peer_id) = download_ingress(
        transport,
        &signed_ingress_id,
        full_consensus_message_id,
        &log,
        &metrics,
        peer_rx,
    )
    .await;

    (ingress_message, signed_ingress_id, peer_id)
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
    ingress_messages: Vec<(SignedIngressId, Option<SignedIngress>)>,
}

impl BlockProposalAssembler {
    fn new(stripped_block_proposal: StrippedBlockProposal) -> Self {
        Self {
            ingress_messages: stripped_block_proposal
                .stripped_ingress_payload
                .ingress_messages
                .iter()
                .map(|signed_ingress_id| (signed_ingress_id.clone(), None))
                .collect(),
            stripped_block_proposal,
        }
    }

    /// Returns the list of ingress messages which have been stripped from the block.
    pub(crate) fn missing_ingress_messages(&self) -> Vec<SignedIngressId> {
        self.ingress_messages
            .iter()
            .filter_map(|(signed_ingress_id, maybe_ingress)| {
                if maybe_ingress.is_none() {
                    Some(signed_ingress_id)
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
        signed_ingress_id: SignedIngressId,
    ) -> Result<(), InsertionError> {
        // We can have at most 1000 elements in the vector, so it should be reasonably fast to do a
        // linear scan here.
        let (_, ingress) = self
            .ingress_messages
            .iter_mut()
            .find(|(id, _maybe_ingress)| *id == signed_ingress_id)
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
            .map(|(id, message)| {
                message
                    .ok_or_else(|| AssemblyError::Missing(id.ingress_message_id.clone()))
                    .map(|message| (id.ingress_message_id, message))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let reconstructed_ingress_payload = IngressPayload::from(ingresses);

        let reconstructed_ingress_payload_proto =
            pb::IngressPayload::from(reconstructed_ingress_payload);

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
        fake_ingress_message_with_arg_size, fake_ingress_message_with_sig,
        fake_stripped_block_proposal_with_ingresses,
    };
    use crate::fetch_stripped_artifact::types::rpc::GetIngressMessageInBlockResponse;
    use bytes::Bytes;
    use ic_interfaces::p2p::consensus::BouncerValue;
    use ic_logger::no_op_logger;
    use ic_p2p_test_utils::mocks::MockBouncerFactory;
    use ic_p2p_test_utils::mocks::MockTransport;
    use ic_p2p_test_utils::mocks::MockValidatedPoolReader;
    use ic_protobuf::proxy::ProtoProxy;
    use ic_types_test_utils::ids::NODE_1;

    use super::*;

    #[test]
    fn strip_assemble_roundtrip_test() {
        let (ingress_1, ingress_id_1) = fake_ingress_message_with_arg_size("fake_1", 1024);
        let (ingress_2, ingress_id_2) = fake_ingress_message_with_arg_size("fake_2", 1024);
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
        assembler
            .try_insert_ingress_message(ingress_1, ingress_id_1)
            .unwrap();
        assembler
            .try_insert_ingress_message(ingress_2, ingress_id_2)
            .unwrap();

        // try to reassemble the block
        let assembled_block = assembler.try_assemble().unwrap();

        assert_eq!(assembled_block, block_proposal);
    }

    #[test]
    fn strip_assemble_fails_when_still_missing_ingress_test() {
        let (ingress_1, ingress_id_1) = fake_ingress_message_with_arg_size("fake_1", 1024);
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
        assembler
            .try_insert_ingress_message(ingress_1, ingress_id_1)
            .unwrap();

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
            .try_insert_ingress_message(ingress_2, ingress_2_id.clone())
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
            .try_insert_ingress_message(ingress_2.clone(), ingress_2_id.clone())
            .expect("Should successfully insert the missing ingress");

        assert_eq!(
            assembler.try_insert_ingress_message(ingress_2, ingress_2_id),
            Err(InsertionError::AlreadyInserted)
        );
    }

    #[test]
    fn ingress_payload_insertion_unknown_fails_test() {
        let (ingress_1, ingress_1_id) = fake_ingress_message("fake_1");
        let (_ingress_2, ingress_2_id) = fake_ingress_message("fake_2");
        let stripped_block_proposal =
            fake_stripped_block_proposal_with_ingresses(vec![ingress_2_id.clone()]);

        let mut assembler = BlockProposalAssembler::new(stripped_block_proposal);

        assert_eq!(
            assembler.try_insert_ingress_message(ingress_1, ingress_1_id),
            Err(InsertionError::NotNeeded)
        );
    }

    #[derive(Clone)]
    struct MockPeers(NodeId);

    impl Peers for MockPeers {
        fn peers(&self) -> Vec<NodeId> {
            vec![self.0]
        }
    }

    fn set_up_assembler_with_fake_dependencies(
        ingress_pool_message: Option<SignedIngress>,
        peers_message: Option<SignedIngress>,
    ) -> FetchStrippedConsensusArtifact {
        let mut mock_transport = MockTransport::new();
        let mut ingress_pool = MockValidatedPoolReader::<SignedIngress>::default();

        if let Some(ingress_message) = ingress_pool_message {
            ingress_pool.expect_get().return_const(ingress_message);
        }

        if let Some(ingress_message) = peers_message {
            let fake_response = axum::response::Response::builder()
                .body(Bytes::from(
                    pb::GetIngressMessageInBlockResponse::proxy_encode(
                        GetIngressMessageInBlockResponse {
                            serialized_ingress_message: ingress_message.binary().clone(),
                        },
                    ),
                ))
                .unwrap();

            mock_transport
                .expect_rpc()
                .returning(move |_, _| Ok(fake_response.clone()));
        }

        let consensus_pool = MockValidatedPoolReader::<ConsensusMessage>::default();
        let idkg_pool = MockValidatedPoolReader::<IDkgMessage>::default();
        let mut mock_bouncer_factory = MockBouncerFactory::default();
        mock_bouncer_factory
            .expect_new_bouncer()
            .returning(|_| Box::new(|_| BouncerValue::Wants));

        let f = FetchStrippedConsensusArtifact::new(
            no_op_logger(),
            tokio::runtime::Handle::current(),
            Arc::new(RwLock::new(consensus_pool)),
            Arc::new(RwLock::new(ingress_pool)),
            Arc::new(RwLock::new(idkg_pool)),
            Arc::new(mock_bouncer_factory),
            MetricsRegistry::new(),
            NODE_1,
        )
        .0;

        (f)(Arc::new(mock_transport))
    }

    /// Tests whether the assembler uses the ingress message with the correct signature in the case
    /// when the local ingress pool contains an ingress message with the same content as the one in
    /// the stripped block proposal but with a different signature.
    #[tokio::test]
    async fn roundtrip_test_with_two_identical_ingress_messages_different_signatures() {
        let (ingress_1, _ingress_1_id) = fake_ingress_message_with_sig("fake_1", vec![1, 2, 3]);
        let (ingress_2, _ingress_2_id) = fake_ingress_message_with_sig("fake_1", vec![2, 3, 4]);
        assert_eq!(
            IngressMessageId::from(&ingress_1),
            IngressMessageId::from(&ingress_2)
        );
        let block_proposal = fake_block_proposal_with_ingresses(vec![ingress_2.clone()]);

        let assembler = set_up_assembler_with_fake_dependencies(
            /*ingress_pool_message=*/ Some(ingress_1.clone()),
            /*consensus_pool_message=*/ Some(ingress_2.clone()),
        );
        let stripped_block_proposal =
            assembler.disassemble_message(ConsensusMessage::BlockProposal(block_proposal.clone()));
        let reassembled_block_proposal = assembler
            .assemble_message(
                stripped_block_proposal.id(),
                Some((stripped_block_proposal, NODE_1)),
                MockPeers(NODE_1),
            )
            .await;

        assert_eq!(
            reassembled_block_proposal,
            AssembleResult::Done {
                message: ConsensusMessage::BlockProposal(block_proposal),
                peer_id: NODE_1
            }
        );
    }
}
