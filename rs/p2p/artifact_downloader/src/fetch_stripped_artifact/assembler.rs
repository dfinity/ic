use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
    time::Duration,
};
use thiserror::Error;

use ic_interfaces::p2p::consensus::{
    ArtifactAssembler, AssembleResult, BouncerFactory, Peers, ValidatedPoolReader,
};
use ic_logger::{ReplicaLogger, warn};
use ic_metrics::MetricsRegistry;
use ic_protobuf::{
    proxy::ProxyDecodeError,
    registry::subnet::v1::{IDkgDealing as IDkgDealingProto, IDkgSignedDealingTuple},
};
use ic_protobuf::{proxy::try_from_option_field, types::v1 as pb};
use ic_quic_transport::Transport;
use ic_types::{
    CountBytes, NodeId, NodeIndex,
    artifact::{ConsensusMessageId, IdentifiableArtifact, IngressMessageId},
    batch::IngressPayload,
    consensus::{
        BlockProposal, ConsensusMessage,
        idkg::{IDkgArtifactId, IDkgMessage},
    },
    crypto::{
        Signed,
        canister_threshold_sig::idkg::{IDkgDealing, IDkgTranscriptId, SignedIDkgDealing},
    },
    messages::SignedIngress,
    node_id_into_protobuf,
};

use crate::{
    FetchArtifact,
    fetch_stripped_artifact::types::{StrippedMessage, StrippedMessageId, StrippedMessageType},
};

use super::{
    download::download_stripped_message,
    metrics::{
        FetchStrippedConsensusArtifactMetrics, StrippedMessageSenderMetrics, StrippedMessageSource,
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
    idkg_pool: ValidatedPoolReaderRef<IDkgMessage>,
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
        let idkg_pool_clone = idkg_pool.clone();
        let consensus_pool_clone = consensus_pool.clone();

        let router = super::download::build_axum_router(super::download::Pools {
            consensus_pool: consensus_pool_clone,
            ingress_pool: ingress_pool_clone,
            idkg_pool: idkg_pool_clone,
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
                idkg_pool: idkg_pool.clone(),
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
            .download_missing_stripped_messages_duration
            .start_timer();
        let mut assembler = BlockProposalAssembler::new(stripped_block_proposal);

        let stripped_message_ids = assembler.missing_stripped_messages();
        // For each stripped object in the message, try to fetch it either from the local pools
        // or from a random peer who is advertising it.
        for stripped_message_id in stripped_message_ids {
            join_set.spawn(get_or_fetch(
                stripped_message_id,
                self.ingress_pool.clone(),
                self.idkg_pool.clone(),
                self.transport.clone(),
                id.as_ref().clone(),
                self.log.clone(),
                self.metrics.clone(),
                self.node_id,
                peer_rx.clone(),
            ));
        }

        let mut messages_from_pool = BTreeMap::<StrippedMessageType, usize>::new();
        let mut messages_from_peers = BTreeMap::<StrippedMessageType, usize>::new();

        while let Some(join_result) = join_set.join_next().await {
            let Ok((message, peer_id)) = join_result else {
                return AssembleResult::Unwanted;
            };

            let message_type = StrippedMessageType::from(&message);

            if peer_id == self.node_id {
                *messages_from_pool.entry(message_type).or_default() += 1;
            } else {
                self.metrics
                    .report_missing_stripped_messages_bytes(message_type, message.count_bytes());
                *messages_from_peers.entry(message_type).or_default() += 1;
            }

            if let Err(err) = assembler.try_insert_stripped_message(message) {
                warn!(
                    self.log,
                    "Failed to insert stripped message of type {}: {}. This is a bug.",
                    message_type.as_str(),
                    err
                );

                return AssembleResult::Unwanted;
            }
        }

        // Only report the metric if we actually downloaded some stripped messages from peers
        if !messages_from_peers.is_empty() {
            timer.stop_and_record();
        } else {
            timer.stop_and_discard();
        }

        for (message_type, count) in messages_from_peers.iter() {
            self.metrics.report_stripped_messages_count(
                StrippedMessageSource::Peer,
                *message_type,
                *count,
            );
        }
        for (message_type, count) in messages_from_pool.iter() {
            self.metrics.report_stripped_messages_count(
                StrippedMessageSource::Pool,
                *message_type,
                *count,
            );
        }

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
    stripped_message_id: StrippedMessageId,
    ingress_pool: ValidatedPoolReaderRef<SignedIngress>,
    idkg_pool: ValidatedPoolReaderRef<IDkgMessage>,
    transport: Arc<dyn Transport>,
    // Id of the *full* artifact which should contain the missing data
    full_consensus_message_id: ConsensusMessageId,
    log: ReplicaLogger,
    metrics: Arc<FetchStrippedConsensusArtifactMetrics>,
    node_id: NodeId,
    peer_rx: P,
) -> (StrippedMessage, NodeId) {
    let stripped_message_id = match stripped_message_id {
        StrippedMessageId::Ingress(signed_ingress_id) => {
            // First check if the ingress message exists in the Ingress Pool.
            if let Some(ingress_message) = ingress_pool
                .read()
                .unwrap()
                .get(&signed_ingress_id.ingress_message_id)
            {
                // Make sure that this is the correct ingress message. [`IngressMessageId`] does _not_
                // uniquely identify ingress messages, we thus need to perform an extra check.
                if SignedIngressId::from(&ingress_message) == signed_ingress_id {
                    return (
                        StrippedMessage::Ingress(signed_ingress_id, ingress_message),
                        node_id,
                    );
                }
            }
            StrippedMessageId::Ingress(signed_ingress_id)
        }
        StrippedMessageId::IDkgDealing(dealing_id, node_index) => {
            // First check if the dealing exists in the IDKG Pool.
            if let Some(IDkgMessage::Dealing(signed_dealing)) =
                idkg_pool.read().unwrap().get(&dealing_id)
            {
                return (
                    StrippedMessage::IDkgDealing(dealing_id, node_index, signed_dealing),
                    node_id,
                );
            }
            StrippedMessageId::IDkgDealing(dealing_id, node_index)
        }
    };
    download_stripped_message(
        transport,
        stripped_message_id,
        full_consensus_message_id,
        &log,
        &metrics,
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
    #[error("The block proposal is missing an ingress message with id {0}")]
    MissingIngress(IngressMessageId),
    #[error("The block proposal is missing an IDKG dealing with id {0:?}")]
    MissingIDkgDealing(IDkgArtifactId),
    #[error("The block proposal is missing an IDKG transcript with id {0}")]
    MissingIDkgTranscript(IDkgTranscriptId),
    #[error("The block proposal is missing an IDKG dealer with node index {0}")]
    MissingIDkgNodeIndex(NodeIndex),
    #[error("The block proposal cannot be deserialized {0}")]
    DeserializationFailed(ProxyDecodeError),
}

struct BlockProposalAssembler {
    stripped_block_proposal: StrippedBlockProposal,
    ingress_messages: Vec<(SignedIngressId, Option<SignedIngress>)>,
    signed_dealings: Vec<((NodeIndex, IDkgArtifactId), Option<SignedIDkgDealing>)>,
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
            signed_dealings: stripped_block_proposal
                .stripped_idkg_dealings
                .stripped_dealings
                .iter()
                .map(|(node_index, dealing_id)| ((*node_index, dealing_id.clone()), None))
                .collect(),
            stripped_block_proposal,
        }
    }

    /// Returns the list of messages which have been stripped from the block.
    pub(crate) fn missing_stripped_messages(&self) -> Vec<StrippedMessageId> {
        let ingress =
            self.ingress_messages
                .iter()
                .filter_map(|(signed_ingress_id, maybe_ingress)| {
                    if maybe_ingress.is_none() {
                        Some(StrippedMessageId::Ingress(signed_ingress_id.clone()))
                    } else {
                        None
                    }
                });

        let idkg_dealings =
            self.signed_dealings
                .iter()
                .filter_map(|((node_index, dealing_id), maybe_dealing)| {
                    if maybe_dealing.is_none() {
                        Some(StrippedMessageId::IDkgDealing(
                            dealing_id.clone(),
                            *node_index,
                        ))
                    } else {
                        None
                    }
                });

        ingress.chain(idkg_dealings).collect()
    }

    /// Tries to insert a missing stripped message into the block.
    pub(crate) fn try_insert_stripped_message(
        &mut self,
        message: StrippedMessage,
    ) -> Result<(), InsertionError> {
        match message {
            StrippedMessage::Ingress(signed_ingress_id, signed_ingress) => {
                self.try_insert_ingress_message(signed_ingress, signed_ingress_id)
            }
            StrippedMessage::IDkgDealing(dealing_id, _, signed_dealing) => {
                self.try_insert_idkg_dealing_message(dealing_id, signed_dealing)
            }
        }
    }

    /// Tries to insert a missing ingress message into the block.
    fn try_insert_ingress_message(
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

    /// Tries to insert a missing IDKG dealing into the block.
    fn try_insert_idkg_dealing_message(
        &mut self,
        signed_dealing_id: IDkgArtifactId,
        signed_dealing: SignedIDkgDealing,
    ) -> Result<(), InsertionError> {
        let IDkgArtifactId::Dealing(_, _) = &signed_dealing_id else {
            return Err(InsertionError::NotNeeded);
        };

        let (_, dealing) = self
            .signed_dealings
            .iter_mut()
            .find(|((_, id), _maybe_dealing)| *id == signed_dealing_id)
            .ok_or(InsertionError::NotNeeded)?;

        if dealing.is_some() {
            Err(InsertionError::AlreadyInserted)
        } else {
            *dealing = Some(signed_dealing);
            Ok(())
        }
    }

    /// Tries to reassemble a block.
    ///
    /// Fails if there are still some stripped messages missing,
    /// or the assembled proposal can't be deserialized.
    pub(crate) fn try_assemble(self) -> Result<BlockProposal, AssemblyError> {
        let BlockProposalAssembler {
            stripped_block_proposal,
            ingress_messages,
            signed_dealings,
        } = self;
        let mut reconstructed_block_proposal_proto =
            stripped_block_proposal.pruned_block_proposal_proto;

        let ingresses = ingress_messages
            .into_iter()
            .map(|(id, message)| {
                message
                    .ok_or_else(|| AssemblyError::MissingIngress(id.ingress_message_id.clone()))
                    .map(|message| (id.ingress_message_id, message))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let reconstructed_ingress_payload = IngressPayload::from(ingresses);

        let reconstructed_ingress_payload_proto =
            pb::IngressPayload::from(reconstructed_ingress_payload);

        let mut idkg_dealings =
            BTreeMap::<IDkgTranscriptId, BTreeMap<NodeIndex, SignedIDkgDealing>>::new();
        for ((dealer_index, dealing_id), signed_dealing) in signed_dealings {
            let signed_dealing = signed_dealing
                .ok_or_else(|| AssemblyError::MissingIDkgDealing(dealing_id.clone()))?;
            let transcript_id = signed_dealing.idkg_dealing().transcript_id;
            idkg_dealings
                .entry(transcript_id)
                .or_default()
                .insert(dealer_index, signed_dealing);
        }

        if let Some(block) = reconstructed_block_proposal_proto.value.as_mut() {
            block.ingress_payload = Some(reconstructed_ingress_payload_proto);
            if let Some(idkg) = block.idkg_payload.as_mut() {
                for transcript in &mut idkg.idkg_transcripts {
                    let transcript_id =
                        try_from_option_field(transcript.transcript_id.as_ref(), "transcript_id")
                            .map_err(AssemblyError::DeserializationFailed)?;
                    for dealing in &mut transcript.verified_dealings {
                        let dealer_index = dealing.dealer_index;
                        let found_dealing = idkg_dealings
                            .get_mut(&transcript_id)
                            .ok_or_else(|| AssemblyError::MissingIDkgTranscript(transcript_id))?
                            .remove(&dealer_index)
                            .ok_or_else(|| AssemblyError::MissingIDkgNodeIndex(dealer_index))?;
                        dealing.signed_dealing_tuple = Some(idkg_dealing_proto(found_dealing));
                    }
                }
            }
        }

        reconstructed_block_proposal_proto
            .try_into()
            .map_err(AssemblyError::DeserializationFailed)
    }
}

fn idkg_dealing_proto(signed_dealing: SignedIDkgDealing) -> IDkgSignedDealingTuple {
    let Signed {
        content:
            IDkgDealing {
                transcript_id,
                internal_dealing_raw,
            },
        signature: dealing_signature,
    } = signed_dealing;
    let dealing_proto = IDkgDealingProto {
        transcript_id: Some((&transcript_id).into()),
        raw_dealing: internal_dealing_raw,
    };
    IDkgSignedDealingTuple {
        dealer: Some(node_id_into_protobuf(dealing_signature.signer)),
        dealing: Some(dealing_proto),
        signature: dealing_signature.signature.get().0,
    }
}

#[cfg(test)]
mod tests {
    use crate::fetch_stripped_artifact::test_utils::{
        fake_block_proposal_with_ingresses, fake_block_proposal_with_ingresses_and_idkg,
        fake_idkg_dealing, fake_idkg_payload_with_dealings, fake_ingress_message,
        fake_ingress_message_with_arg_size, fake_ingress_message_with_sig,
        fake_stripped_block_proposal_with_messages,
    };
    use crate::fetch_stripped_artifact::types::rpc::GetIngressMessageInBlockResponse;
    use assert_matches::assert_matches;
    use bytes::Bytes;
    use ic_crypto_test_utils_canister_threshold_sigs::dummy_values::dummy_idkg_dealing_for_tests;
    use ic_interfaces::p2p::consensus::BouncerValue;
    use ic_logger::no_op_logger;
    use ic_p2p_test_utils::mocks::MockBouncerFactory;
    use ic_p2p_test_utils::mocks::MockTransport;
    use ic_p2p_test_utils::mocks::MockValidatedPoolReader;
    use ic_protobuf::proxy::ProtoProxy;
    use ic_test_utilities_consensus::fake::FakeContentSigner;
    use ic_types::consensus::idkg::IDkgObject;
    use ic_types_test_utils::ids::{NODE_1, NODE_2, SUBNET_2};

    use super::*;

    #[test]
    fn strip_assemble_roundtrip_test() {
        let (ingress_1, ingress_id_1) = fake_ingress_message_with_arg_size("fake_1", 1024);
        let (ingress_2, ingress_id_2) = fake_ingress_message_with_arg_size("fake_2", 1024);
        let dealing_1 = SignedIDkgDealing::fake(dummy_idkg_dealing_for_tests(), NODE_1);
        let dealing_2 = SignedIDkgDealing::fake(dummy_idkg_dealing_for_tests(), NODE_2);
        let idkg =
            fake_idkg_payload_with_dealings(vec![(dealing_1.clone(), 1), (dealing_2.clone(), 2)]);
        let block_proposal = fake_block_proposal_with_ingresses_and_idkg(
            vec![ingress_1.clone(), ingress_2.clone()],
            Some(idkg),
            false,
        );
        let consensus_message = ConsensusMessage::BlockProposal(block_proposal.clone());

        // strip the block
        let MaybeStrippedConsensusMessage::StrippedBlockProposal(stripped_block_proposal) =
            consensus_message.strip()
        else {
            panic!("Didn't properly strip the block proposal");
        };

        let mut assembler = BlockProposalAssembler::new(stripped_block_proposal);

        // insert back the missing messages
        for message in [
            StrippedMessage::Ingress(ingress_id_1, ingress_1),
            StrippedMessage::Ingress(ingress_id_2, ingress_2),
            StrippedMessage::IDkgDealing(dealing_1.message_id(), 1, dealing_1),
            StrippedMessage::IDkgDealing(dealing_2.message_id(), 2, dealing_2),
        ] {
            assembler.try_insert_stripped_message(message).unwrap();
        }

        // try to reassemble the block
        let assembled_block = assembler.try_assemble().unwrap();

        assert_eq!(assembled_block, block_proposal);
    }

    #[test]
    fn strip_assemble_roundtrip_same_transcript_id_test() {
        let dealing_1 = SignedIDkgDealing::fake(dummy_idkg_dealing_for_tests(), NODE_1);
        let transcript_id = dealing_1.idkg_dealing().transcript_id;
        let mut dealing_2 = dealing_1.clone();
        // Both dealings have the same transcript id, apart from the subnet id
        dealing_2.content.transcript_id =
            IDkgTranscriptId::new(SUBNET_2, transcript_id.id(), transcript_id.source_height());
        assert_ne!(transcript_id, dealing_2.content.transcript_id);
        // Both dealings have the same dealer index
        let node_index = 1;

        let idkg = fake_idkg_payload_with_dealings(vec![
            (dealing_1.clone(), node_index),
            (dealing_2.clone(), node_index),
        ]);
        let block_proposal = fake_block_proposal_with_ingresses_and_idkg(vec![], Some(idkg), false);
        let consensus_message = ConsensusMessage::BlockProposal(block_proposal.clone());

        // strip the block
        let MaybeStrippedConsensusMessage::StrippedBlockProposal(stripped_block_proposal) =
            consensus_message.strip()
        else {
            panic!("Didn't properly strip the block proposal");
        };

        let mut assembler = BlockProposalAssembler::new(stripped_block_proposal);

        // insert back the missing messages
        for message in [
            StrippedMessage::IDkgDealing(dealing_1.message_id(), node_index, dealing_1),
            StrippedMessage::IDkgDealing(dealing_2.message_id(), node_index, dealing_2),
        ] {
            assembler.try_insert_stripped_message(message).unwrap();
        }

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
            AssemblyError::MissingIngress(_) => (),
            _ => panic!("Wrong error"),
        }
    }

    #[test]
    fn strip_assemble_fails_when_still_missing_idkg_dealing_test() {
        let dealing_1 = SignedIDkgDealing::fake(dummy_idkg_dealing_for_tests(), NODE_1);
        let dealing_2 = SignedIDkgDealing::fake(dummy_idkg_dealing_for_tests(), NODE_2);
        let idkg =
            fake_idkg_payload_with_dealings(vec![(dealing_1.clone(), 1), (dealing_2.clone(), 2)]);
        let block_proposal = fake_block_proposal_with_ingresses_and_idkg(vec![], Some(idkg), false);
        let consensus_message = ConsensusMessage::BlockProposal(block_proposal.clone());

        // strip the block
        let MaybeStrippedConsensusMessage::StrippedBlockProposal(stripped_block_proposal) =
            consensus_message.strip()
        else {
            panic!("Didn't properly strip the block proposal");
        };

        let mut assembler = BlockProposalAssembler::new(stripped_block_proposal);

        // insert back only one missing message
        assembler
            .try_insert_idkg_dealing_message(dealing_1.message_id(), dealing_1)
            .unwrap();

        // try to reassemble the block
        let assembly_error = assembler.try_assemble().unwrap_err();

        match assembly_error {
            AssemblyError::MissingIDkgDealing(id) if id == dealing_2.message_id() => (),
            _ => panic!("Wrong error"),
        }
    }

    #[test]
    fn strip_assemble_fails_when_missing_dealer_id_test() {
        let dealing_1 = SignedIDkgDealing::fake(dummy_idkg_dealing_for_tests(), NODE_1);
        let dealing_2 = SignedIDkgDealing::fake(dummy_idkg_dealing_for_tests(), NODE_2);
        let idkg =
            fake_idkg_payload_with_dealings(vec![(dealing_1.clone(), 1), (dealing_2.clone(), 2)]);
        let block_proposal = fake_block_proposal_with_ingresses_and_idkg(vec![], Some(idkg), false);
        let consensus_message = ConsensusMessage::BlockProposal(block_proposal.clone());

        // strip the block
        let MaybeStrippedConsensusMessage::StrippedBlockProposal(mut stripped_block_proposal) =
            consensus_message.strip()
        else {
            panic!("Didn't properly strip the block proposal");
        };

        // A malicious node sends us a stripped proposal with a missing dealing ID:
        stripped_block_proposal
            .stripped_idkg_dealings
            .stripped_dealings
            .remove(1);

        let mut assembler = BlockProposalAssembler::new(stripped_block_proposal);

        // insert back only the missing message
        assembler
            .try_insert_idkg_dealing_message(dealing_1.message_id(), dealing_1)
            .unwrap();
        let err = assembler
            .try_insert_idkg_dealing_message(dealing_2.message_id(), dealing_2)
            .unwrap_err();
        assert_matches!(err, InsertionError::NotNeeded);

        // try to reassemble the block
        let assembly_error = assembler.try_assemble().unwrap_err();

        assert_matches!(assembly_error, AssemblyError::MissingIDkgNodeIndex(2));
    }

    #[test]
    fn strip_assemble_fails_when_missing_transcript_id_test() {
        let dealing_1 = SignedIDkgDealing::fake(dummy_idkg_dealing_for_tests(), NODE_1);
        let transcript_id_1 = dealing_1.idkg_dealing().transcript_id;
        let mut dealing_2 = dealing_1.clone();
        // Both dealings have the same transcript id, apart from the subnet id
        let transcript_id_2 = IDkgTranscriptId::new(
            SUBNET_2,
            transcript_id_1.id(),
            transcript_id_1.source_height(),
        );
        dealing_2.content.transcript_id = transcript_id_2;
        assert_ne!(transcript_id_1, transcript_id_2);
        let node_index = 1;

        let idkg = fake_idkg_payload_with_dealings(vec![
            (dealing_1.clone(), node_index),
            (dealing_2.clone(), node_index),
        ]);
        let block_proposal = fake_block_proposal_with_ingresses_and_idkg(vec![], Some(idkg), false);
        let consensus_message = ConsensusMessage::BlockProposal(block_proposal.clone());

        // strip the block
        let MaybeStrippedConsensusMessage::StrippedBlockProposal(mut stripped_block_proposal) =
            consensus_message.strip()
        else {
            panic!("Didn't properly strip the block proposal");
        };

        // A malicious node sends us a stripped proposal with a missing transcript ID:
        stripped_block_proposal
            .stripped_idkg_dealings
            .stripped_dealings
            .remove(1);

        let mut assembler = BlockProposalAssembler::new(stripped_block_proposal);

        // insert back only the missing message
        assembler
            .try_insert_idkg_dealing_message(dealing_1.message_id(), dealing_1)
            .unwrap();
        let err = assembler
            .try_insert_idkg_dealing_message(dealing_2.message_id(), dealing_2)
            .unwrap_err();
        assert_matches!(err, InsertionError::NotNeeded);

        // try to reassemble the block
        let assembly_error = assembler.try_assemble().unwrap_err();

        assert_matches!(assembly_error, AssemblyError::MissingIDkgTranscript(t) if t == transcript_id_2);
    }

    #[test]
    fn missing_stripped_messages_test() {
        let ingress_1_id = fake_ingress_message("fake_1").id();
        let ingress_2_id = fake_ingress_message("fake_2").id();
        let idkg_dealing_1_id = fake_idkg_dealing(NODE_1, 1).id();
        let idkg_dealing_2_id = fake_idkg_dealing(NODE_2, 2).id();
        let stripped_block_proposal = fake_stripped_block_proposal_with_messages(vec![
            ingress_1_id.clone(),
            ingress_2_id.clone(),
            idkg_dealing_1_id.clone(),
            idkg_dealing_2_id.clone(),
        ]);

        let assembler = BlockProposalAssembler::new(stripped_block_proposal);

        assert_eq!(
            assembler.missing_stripped_messages(),
            vec![
                ingress_1_id,
                ingress_2_id,
                idkg_dealing_1_id,
                idkg_dealing_2_id
            ]
        );
    }

    #[test]
    fn stripped_message_insertion_works_test() {
        let ingress_2 = fake_ingress_message("fake_2");
        let idkg_dealing_2 = fake_idkg_dealing(NODE_2, 2);
        let stripped_block_proposal =
            fake_stripped_block_proposal_with_messages(vec![ingress_2.id(), idkg_dealing_2.id()]);

        let mut assembler = BlockProposalAssembler::new(stripped_block_proposal);

        assembler
            .try_insert_stripped_message(ingress_2)
            .expect("Should successfully insert the missing ingress");

        assert_eq!(
            assembler.missing_stripped_messages(),
            vec![idkg_dealing_2.id()]
        );

        assembler
            .try_insert_stripped_message(idkg_dealing_2)
            .expect("Should successfully insert the missing dealing");

        assert!(assembler.missing_stripped_messages().is_empty());
    }

    #[test]
    fn stripped_message_insertion_existing_fails_test() {
        let ingress_2 = fake_ingress_message("fake_2");
        let idkg_dealing_2 = fake_idkg_dealing(NODE_2, 2);
        let stripped_block_proposal =
            fake_stripped_block_proposal_with_messages(vec![ingress_2.id(), idkg_dealing_2.id()]);

        let mut assembler = BlockProposalAssembler::new(stripped_block_proposal);

        for message in [ingress_2, idkg_dealing_2] {
            assembler
                .try_insert_stripped_message(message.clone())
                .expect("Should successfully insert the missing message");

            assert_eq!(
                assembler.try_insert_stripped_message(message),
                Err(InsertionError::AlreadyInserted)
            );
        }
    }

    #[test]
    fn stripped_message_insertion_unknown_fails_test() {
        let ingress_1 = fake_ingress_message("fake_1");
        let ingress_2 = fake_ingress_message("fake_2");
        let idkg_dealing_1 = fake_idkg_dealing(NODE_1, 1);
        let idkg_dealing_2 = fake_idkg_dealing(NODE_2, 2);
        let stripped_block_proposal =
            fake_stripped_block_proposal_with_messages(vec![ingress_2.id(), idkg_dealing_2.id()]);

        let mut assembler = BlockProposalAssembler::new(stripped_block_proposal);

        for message in [idkg_dealing_1, ingress_1] {
            assert_eq!(
                assembler.try_insert_stripped_message(message),
                Err(InsertionError::NotNeeded)
            );
        }
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
