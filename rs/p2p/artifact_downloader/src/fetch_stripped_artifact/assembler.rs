use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
    time::Duration,
};
use thiserror::Error;

use ic_interfaces::{
    canister_http::CanisterHttpPool,
    p2p::consensus::{
        ArtifactAssembler, AssembleResult, BouncerFactory, BouncerValue, Peers, ValidatedPoolReader,
    },
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
    canister_http::CanisterHttpResponse,
    consensus::{
        BlockProposal, ConsensusMessage, ConsensusMessageHashable,
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
    fetch_stripped_artifact::{
        canister_http::{CanisterHttpPayloadError, reinsert_responses},
        types::{
            CanisterHttpResponseContentHash, StrippedMessage, StrippedMessageId,
            StrippedMessageType,
        },
    },
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
        // The pool hands out a block proposal with its payload already loaded.
        let message = self.consensus_pool.read().unwrap().get(id.as_ref());
        // Stripping a block can take milliseconds, so it is done once the lock on the
        // pool is released.
        message.map(Strippable::strip)
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
        self.bouncer_factory.refresh_period()
    }
}

#[derive(Clone)]
pub struct FetchStrippedConsensusArtifact {
    log: ReplicaLogger,
    ingress_pool: ValidatedPoolReaderRef<SignedIngress>,
    idkg_pool: ValidatedPoolReaderRef<IDkgMessage>,
    canister_http_pool: Arc<RwLock<dyn CanisterHttpPool>>,
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
        canister_http_pool: Arc<RwLock<dyn CanisterHttpPool>>,
        bouncer_factory: Arc<dyn BouncerFactory<ConsensusMessageId, Pool>>,
        metrics_registry: MetricsRegistry,
        node_id: NodeId,
    ) -> (impl Fn(Arc<dyn Transport>) -> Self, axum::Router) {
        let ingress_pool_clone = ingress_pool.clone();
        let idkg_pool_clone = idkg_pool.clone();
        let canister_http_pool_clone = canister_http_pool.clone();
        let consensus_pool_clone = consensus_pool.clone();

        let router = super::download::build_axum_router(super::download::Pools {
            consensus_pool: consensus_pool_clone,
            ingress_pool: ingress_pool_clone,
            idkg_pool: idkg_pool_clone,
            canister_http_pool: canister_http_pool_clone,
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
                canister_http_pool: canister_http_pool.clone(),
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
                self.canister_http_pool.clone(),
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

        // Abort the assembly as soon as the block proposal is no longer wanted. Returning
        // here drops `join_set`, which aborts all outstanding child fetch tasks.
        let mut bouncer = self.fetch_stripped.bouncer_watcher();

        loop {
            let join_result = tokio::select! {
                _ = bouncer.wait_for(|bouncer| matches!(bouncer(&id), BouncerValue::Unwanted)) => {
                    self.metrics.report_aborted_block_assembly();
                    return AssembleResult::Unwanted;
                }
                join_result = join_set.join_next() => join_result,
            };

            let Some(join_result) = join_result else {
                break;
            };

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
    canister_http_pool: Arc<RwLock<dyn CanisterHttpPool>>,
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
        StrippedMessageId::CanisterHttpResponse(content_hash) => {
            // First check if the response content exists in the canister HTTP pool.
            if let Some(response) = canister_http_pool
                .read()
                .unwrap()
                .get_response_content_by_hash(&content_hash)
                .cloned()
            {
                return (
                    StrippedMessage::CanisterHttpResponse(content_hash, response),
                    node_id,
                );
            }
            StrippedMessageId::CanisterHttpResponse(content_hash)
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
    #[error("Trying to insert a stripped message which was never missing")]
    NotNeeded,
    #[error("Trying to insert a stripped message which was already inserted")]
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
    #[error("The canister http payload of the block proposal could not be reassembled: {0}")]
    CanisterHttpPayload(#[from] CanisterHttpPayloadError),
    #[error("The block proposal cannot be deserialized {0}")]
    DeserializationFailed(ProxyDecodeError),
    #[error(
        "The reconstructed block proposal id {assembled:?} does not match the claimed id {claimed:?}"
    )]
    MismatchedConsensusMessageId {
        claimed: ConsensusMessageId,
        assembled: ConsensusMessageId,
    },
}

/// A trait keeps track of the missing artifacts in a stripped payload,
/// and tries to reconstruct the block from it.
trait PayloadAssembler<ArtifactMessage> {
    type ArtifactId;
    type Payload;

    /// Returns an iterator over stripped artifacts that are still missing.
    fn missing_artifacts(&self) -> impl Iterator<Item = Self::ArtifactId>;

    /// Tries to insert a missing artifact into this payload assembler.
    fn try_insert(
        &mut self,
        id: Self::ArtifactId,
        message: ArtifactMessage,
    ) -> Result<(), InsertionError>;

    /// Tries to reconstruct the part of the block corresponding to this payload assembler.
    fn try_reconstruct_payload(
        messages: BTreeMap<Self::ArtifactId, Option<ArtifactMessage>>,
        payload: &mut Self::Payload,
    ) -> Result<(), AssemblyError>;
}

impl PayloadAssembler<SignedIngress> for BlockProposalAssembler {
    type ArtifactId = SignedIngressId;
    type Payload = Option<pb::IngressPayload>;

    fn missing_artifacts(&self) -> impl Iterator<Item = SignedIngressId> {
        self.ingress_messages
            .iter()
            .filter(|(_, maybe_ingress)| maybe_ingress.is_none())
            .map(|(id, _)| id.clone())
    }

    fn try_insert(
        &mut self,
        signed_ingress_id: SignedIngressId,
        ingress_message: SignedIngress,
    ) -> Result<(), InsertionError> {
        let ingress = self
            .ingress_messages
            .get_mut(&signed_ingress_id)
            .ok_or(InsertionError::NotNeeded)?;

        if ingress.is_some() {
            Err(InsertionError::AlreadyInserted)
        } else {
            *ingress = Some(ingress_message);
            Ok(())
        }
    }

    fn try_reconstruct_payload(
        ingress_messages: BTreeMap<SignedIngressId, Option<SignedIngress>>,
        payload: &mut Self::Payload,
    ) -> Result<(), AssemblyError> {
        let ingresses = ingress_messages
            .into_iter()
            .map(|(id, message)| {
                message
                    .ok_or_else(|| AssemblyError::MissingIngress(id.ingress_message_id.clone()))
                    .map(|message| (id.ingress_message_id, message))
            })
            .collect::<Result<Vec<_>, _>>()?;

        *payload = Some(pb::IngressPayload::from(IngressPayload::from_iter(
            ingresses,
        )));
        Ok(())
    }
}

impl PayloadAssembler<SignedIDkgDealing> for BlockProposalAssembler {
    type ArtifactId = (NodeIndex, IDkgArtifactId);
    type Payload = pb::IDkgPayload;

    fn missing_artifacts(&self) -> impl Iterator<Item = Self::ArtifactId> {
        self.signed_dealings
            .iter()
            .filter(|(_, maybe_dealing)| maybe_dealing.is_none())
            .map(|((node_index, dealing_id), _)| (*node_index, dealing_id.clone()))
    }

    fn try_insert(
        &mut self,
        (node_index, signed_dealing_id): (NodeIndex, IDkgArtifactId),
        signed_dealing: SignedIDkgDealing,
    ) -> Result<(), InsertionError> {
        let IDkgArtifactId::Dealing(_, _) = &signed_dealing_id else {
            return Err(InsertionError::NotNeeded);
        };

        let dealing = self
            .signed_dealings
            .get_mut(&(node_index, signed_dealing_id))
            .ok_or(InsertionError::NotNeeded)?;

        if dealing.is_some() {
            Err(InsertionError::AlreadyInserted)
        } else {
            *dealing = Some(signed_dealing);
            Ok(())
        }
    }

    fn try_reconstruct_payload(
        signed_dealings: BTreeMap<Self::ArtifactId, Option<SignedIDkgDealing>>,
        payload: &mut Self::Payload,
    ) -> Result<(), AssemblyError> {
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

        for transcript in &mut payload.idkg_transcripts {
            let transcript_id =
                try_from_option_field(transcript.transcript_id.clone(), "transcript_id")
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
        Ok(())
    }
}

impl PayloadAssembler<CanisterHttpResponse> for BlockProposalAssembler {
    type ArtifactId = CanisterHttpResponseContentHash;
    type Payload = Vec<u8>;

    fn missing_artifacts(&self) -> impl Iterator<Item = Self::ArtifactId> {
        self.canister_http_responses
            .iter()
            .filter(|(_, maybe_response)| maybe_response.is_none())
            .map(|(content_hash, _)| content_hash.clone())
    }

    fn try_insert(
        &mut self,
        content_hash: CanisterHttpResponseContentHash,
        response: CanisterHttpResponse,
    ) -> Result<(), InsertionError> {
        let slot = self
            .canister_http_responses
            .get_mut(&content_hash)
            .ok_or(InsertionError::NotNeeded)?;

        if slot.is_some() {
            Err(InsertionError::AlreadyInserted)
        } else {
            *slot = Some(response);
            Ok(())
        }
    }

    fn try_reconstruct_payload(
        responses: BTreeMap<Self::ArtifactId, Option<CanisterHttpResponse>>,
        payload: &mut Self::Payload,
    ) -> Result<(), AssemblyError> {
        if responses.is_empty() {
            // No response was declared stripped from this payload.
            return Ok(());
        }

        *payload = reinsert_responses(payload, &responses)?;
        Ok(())
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

struct BlockProposalAssembler {
    /// The block proposal with every stripped message taken out of it.
    pruned_block_proposal_proto: pb::BlockProposal,
    /// The id of the block proposal the stripped messages belong in.
    unstripped_consensus_message_id: ConsensusMessageId,
    ingress_messages: BTreeMap<SignedIngressId, Option<SignedIngress>>,
    signed_dealings: BTreeMap<(NodeIndex, IDkgArtifactId), Option<SignedIDkgDealing>>,
    canister_http_responses:
        BTreeMap<CanisterHttpResponseContentHash, Option<CanisterHttpResponse>>,
}

impl BlockProposalAssembler {
    fn new(stripped_block_proposal: StrippedBlockProposal) -> Self {
        let StrippedBlockProposal {
            pruned_block_proposal_proto,
            unstripped_consensus_message_id,
            stripped_ingress_payload,
            stripped_idkg_dealings,
            stripped_canister_http_responses,
        } = stripped_block_proposal;

        Self {
            pruned_block_proposal_proto,
            unstripped_consensus_message_id,
            ingress_messages: stripped_ingress_payload
                .ingress_messages
                .into_iter()
                .map(|signed_ingress_id| (signed_ingress_id, None))
                .collect(),
            signed_dealings: stripped_idkg_dealings
                .stripped_dealings
                .into_iter()
                .map(|dealer_and_dealing_id| (dealer_and_dealing_id, None))
                .collect(),
            canister_http_responses: stripped_canister_http_responses
                .stripped_responses
                .into_iter()
                .map(|content_hash| (content_hash, None))
                .collect(),
        }
    }

    /// Returns the list of messages which have been stripped from the block.
    pub(crate) fn missing_stripped_messages(&self) -> Vec<StrippedMessageId> {
        let ingress_messages = PayloadAssembler::<SignedIngress>::missing_artifacts(self)
            .map(StrippedMessageId::Ingress);
        let idkg_dealings = PayloadAssembler::<SignedIDkgDealing>::missing_artifacts(self)
            .map(|(node_index, dealing_id)| StrippedMessageId::IDkgDealing(dealing_id, node_index));
        let canister_http_responses =
            PayloadAssembler::<CanisterHttpResponse>::missing_artifacts(self)
                .map(StrippedMessageId::CanisterHttpResponse);

        ingress_messages
            .chain(idkg_dealings)
            .chain(canister_http_responses)
            .collect()
    }

    /// Tries to insert a missing stripped message into the block.
    pub(crate) fn try_insert_stripped_message(
        &mut self,
        message: StrippedMessage,
    ) -> Result<(), InsertionError> {
        match message {
            StrippedMessage::Ingress(signed_ingress_id, signed_ingress) => {
                self.try_insert(signed_ingress_id, signed_ingress)
            }
            StrippedMessage::IDkgDealing(dealing_id, node_index, signed_dealing) => {
                self.try_insert((node_index, dealing_id), signed_dealing)
            }
            StrippedMessage::CanisterHttpResponse(content_hash, response) => {
                self.try_insert(content_hash, response)
            }
        }
    }

    /// Tries to reassemble a block.
    ///
    /// Fails if there are still some stripped messages missing,
    /// the assembled proposal can't be deserialized, or if the
    /// assembled proposal has an ID that doesn't match the claimed ID.
    pub(crate) fn try_assemble(self) -> Result<BlockProposal, AssemblyError> {
        let BlockProposalAssembler {
            pruned_block_proposal_proto: mut reconstructed_block_proposal_proto,
            unstripped_consensus_message_id: claimed_id,
            ingress_messages,
            signed_dealings,
            canister_http_responses,
        } = self;

        if let Some(block) = reconstructed_block_proposal_proto.value.as_mut() {
            Self::try_reconstruct_payload(ingress_messages, &mut block.ingress_payload)?;
            if let Some(idkg) = block.idkg_payload.as_mut() {
                Self::try_reconstruct_payload(signed_dealings, idkg)?;
            }
            Self::try_reconstruct_payload(
                canister_http_responses,
                &mut block.canister_http_payload_bytes,
            )?;
        }

        let reconstructed_block_proposal: BlockProposal = reconstructed_block_proposal_proto
            .try_into()
            .map_err(AssemblyError::DeserializationFailed)?;
        let assembled_id = reconstructed_block_proposal.get_id();
        if assembled_id != claimed_id {
            return Err(AssemblyError::MismatchedConsensusMessageId {
                claimed: claimed_id,
                assembled: assembled_id,
            });
        }

        Ok(reconstructed_block_proposal)
    }
}

#[cfg(test)]
mod tests {
    use crate::fetch_stripped_artifact::test_utils::{
        fake_block_proposal, fake_block_proposal_with_canister_http,
        fake_block_proposal_with_ingresses, fake_block_proposal_with_ingresses_and_idkg,
        fake_canister_http_payload, fake_canister_http_payload_with_every_kind,
        fake_canister_http_response, fake_canister_http_response_message,
        fake_canister_http_stripped_message, fake_canister_http_timeout_message,
        fake_flexible_canister_http_responses_message, fake_idkg_dealing,
        fake_idkg_payload_with_dealings, fake_ingress_message, fake_ingress_message_with_arg_size,
        fake_ingress_message_with_sig, fake_stripped_block_proposal_with_messages, rpc_response,
    };
    use crate::fetch_stripped_artifact::types::stripped::StrippedCanisterHttpResponses;
    use assert_matches::assert_matches;
    use ic_crypto_test_utils_canister_threshold_sigs::dummy_values::dummy_idkg_dealing_for_tests;
    use ic_interfaces::p2p::consensus::BouncerValue;
    use ic_logger::no_op_logger;
    use ic_p2p_test_utils::mocks::FakeCanisterHttpPool;
    use ic_p2p_test_utils::mocks::MockBouncerFactory;
    use ic_p2p_test_utils::mocks::MockTransport;
    use ic_p2p_test_utils::mocks::MockValidatedPoolReader;
    use ic_protobuf::proxy::ProtoProxy;
    use ic_test_utilities_consensus::fake::FakeContentSigner;
    use ic_types::consensus::idkg::IDkgObject;
    use ic_types_test_utils::ids::{NODE_1, NODE_2, SUBNET_2};
    use std::collections::BTreeSet;

    use super::*;

    /// Asserts that `reassembled` is `original`, down to the last byte of its payload.
    fn assert_same_block(reassembled: &BlockProposal, original: &BlockProposal) {
        assert_eq!(reassembled, original);
        assert_eq!(
            reassembled.as_ref().payload.as_ref(),
            original.as_ref().payload.as_ref()
        );
        assert!(reassembled.check_integrity());
    }

    /// Like [`assert_same_block`], for the result of assembling a block proposal
    /// that was received from `NODE_1`.
    fn assert_assembled(result: AssembleResult<ConsensusMessage>, original: &BlockProposal) {
        match result {
            AssembleResult::Done {
                message: ConsensusMessage::BlockProposal(reassembled),
                peer_id,
            } if peer_id == NODE_1 => assert_same_block(&reassembled, original),
            result => panic!("The block proposal was not assembled: {result:?}"),
        }
    }

    /// Strips `block_proposal` the way it goes out to peers, has `assembler` put it
    /// back together the way a peer does, and checks that this reproduces the block.
    /// Returns the content hashes of the canister http responses that the stripped
    /// proposal declared.
    async fn assert_roundtrip(
        assembler: &FetchStrippedConsensusArtifact,
        block_proposal: &BlockProposal,
    ) -> Vec<CanisterHttpResponseContentHash> {
        let stripped =
            assembler.disassemble_message(ConsensusMessage::BlockProposal(block_proposal.clone()));
        let MaybeStrippedConsensusMessage::StrippedBlockProposal(stripped_block_proposal) =
            &stripped
        else {
            panic!("Didn't strip the block proposal");
        };
        let declared = stripped_block_proposal
            .stripped_canister_http_responses
            .stripped_responses
            .clone();

        let reassembled = assembler
            .assemble_message(stripped.id(), Some((stripped, NODE_1)), MockPeers(NODE_1))
            .await;
        assert_assembled(reassembled, block_proposal);

        declared
    }

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

        assert_same_block(&assembled_block, &block_proposal);
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

        assert_same_block(&assembled_block, &block_proposal);
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
        assembler.try_insert(ingress_id_1, ingress_1).unwrap();

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
            .try_insert((1, dealing_1.message_id()), dealing_1)
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
            .try_insert((1, dealing_1.message_id()), dealing_1)
            .unwrap();
        let err = assembler
            .try_insert((2, dealing_2.message_id()), dealing_2)
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
            .try_insert((node_index, dealing_1.message_id()), dealing_1)
            .unwrap();
        let err = assembler
            .try_insert((node_index, dealing_2.message_id()), dealing_2)
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
        let canister_http_response_id = fake_canister_http_stripped_message(1).id();
        let stripped_block_proposal = fake_stripped_block_proposal_with_messages(vec![
            ingress_1_id.clone(),
            ingress_2_id.clone(),
            idkg_dealing_1_id.clone(),
            idkg_dealing_2_id.clone(),
            canister_http_response_id.clone(),
        ]);

        let assembler = BlockProposalAssembler::new(stripped_block_proposal);

        let mut missing = assembler.missing_stripped_messages();
        missing.sort();
        let mut expected = vec![
            ingress_1_id,
            ingress_2_id,
            idkg_dealing_1_id,
            idkg_dealing_2_id,
            canister_http_response_id,
        ];
        expected.sort();
        assert_eq!(missing, expected);
    }

    #[test]
    fn stripped_message_insertion_works_test() {
        let ingress_2 = fake_ingress_message("fake_2");
        let idkg_dealing_2 = fake_idkg_dealing(NODE_2, 2);
        let canister_http_response_2 = fake_canister_http_stripped_message(2);
        let stripped_block_proposal = fake_stripped_block_proposal_with_messages(vec![
            ingress_2.id(),
            idkg_dealing_2.id(),
            canister_http_response_2.id(),
        ]);

        let mut assembler = BlockProposalAssembler::new(stripped_block_proposal);

        assembler
            .try_insert_stripped_message(ingress_2)
            .expect("Should successfully insert the missing ingress");

        assert_eq!(
            assembler.missing_stripped_messages(),
            vec![idkg_dealing_2.id(), canister_http_response_2.id()]
        );

        assembler
            .try_insert_stripped_message(idkg_dealing_2)
            .expect("Should successfully insert the missing dealing");

        assert_eq!(
            assembler.missing_stripped_messages(),
            vec![canister_http_response_2.id()]
        );

        assembler
            .try_insert_stripped_message(canister_http_response_2)
            .expect("Should successfully insert the missing canister http response");

        assert!(assembler.missing_stripped_messages().is_empty());
    }

    #[test]
    fn stripped_message_insertion_existing_fails_test() {
        let ingress_2 = fake_ingress_message("fake_2");
        let idkg_dealing_2 = fake_idkg_dealing(NODE_2, 2);
        let canister_http_response_2 = fake_canister_http_stripped_message(2);
        let stripped_block_proposal = fake_stripped_block_proposal_with_messages(vec![
            ingress_2.id(),
            idkg_dealing_2.id(),
            canister_http_response_2.id(),
        ]);

        let mut assembler = BlockProposalAssembler::new(stripped_block_proposal);

        for message in [ingress_2, idkg_dealing_2, canister_http_response_2] {
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
        let canister_http_response_1 = fake_canister_http_stripped_message(1);
        let canister_http_response_2 = fake_canister_http_stripped_message(2);
        let stripped_block_proposal = fake_stripped_block_proposal_with_messages(vec![
            ingress_2.id(),
            idkg_dealing_2.id(),
            canister_http_response_2.id(),
        ]);

        let mut assembler = BlockProposalAssembler::new(stripped_block_proposal);

        for message in [idkg_dealing_1, ingress_1, canister_http_response_1] {
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

    /// How often the assemblers in these tests refresh their bouncers.
    const BOUNCER_REFRESH_PERIOD: Duration = Duration::from_secs(1);

    /// A bouncer factory whose bouncers want every block proposal.
    fn wanting_bouncer_factory() -> MockBouncerFactory<ConsensusMessage> {
        let mut bouncer_factory = MockBouncerFactory::default();
        bouncer_factory
            .expect_new_bouncer()
            .returning(|_| Box::new(|_| BouncerValue::Wants));
        bouncer_factory
            .expect_refresh_period()
            .return_const(BOUNCER_REFRESH_PERIOD);
        bouncer_factory
    }

    /// The assembler of `NODE_1`, which looks for the messages stripped from a block
    /// proposal in the given pools, and asks its peers for them through `transport`.
    fn build_assembler(
        ingress_pool: MockValidatedPoolReader<SignedIngress>,
        canister_http_pool: FakeCanisterHttpPool,
        bouncer_factory: MockBouncerFactory<ConsensusMessage>,
        transport: MockTransport,
    ) -> FetchStrippedConsensusArtifact {
        let f = FetchStrippedConsensusArtifact::new(
            no_op_logger(),
            tokio::runtime::Handle::current(),
            Arc::new(RwLock::new(
                MockValidatedPoolReader::<ConsensusMessage>::default(),
            )),
            Arc::new(RwLock::new(ingress_pool)),
            Arc::new(RwLock::new(
                MockValidatedPoolReader::<IDkgMessage>::default(),
            )),
            Arc::new(RwLock::new(canister_http_pool)),
            Arc::new(bouncer_factory),
            MetricsRegistry::new(),
            NODE_1,
        )
        .0;

        (f)(Arc::new(transport))
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
            let fake_response = rpc_response(StrippedMessage::Ingress(
                SignedIngressId::from(&ingress_message),
                ingress_message,
            ));

            mock_transport
                .expect_rpc()
                .returning(move |_, _| Ok(fake_response.clone()));
        }

        build_assembler(
            ingress_pool,
            FakeCanisterHttpPool::empty(),
            wanting_bouncer_factory(),
            mock_transport,
        )
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

        assert_roundtrip(&assembler, &block_proposal).await;
    }

    /// Sets up an assembler whose canister http pool serves `pool_responses`, and
    /// whose peers serve `peer_response` over the RPC, which they expect to be asked
    /// for exactly once.
    fn set_up_assembler_with_canister_http_responses(
        pool_responses: Vec<CanisterHttpResponse>,
        peer_response: Option<CanisterHttpResponse>,
    ) -> FetchStrippedConsensusArtifact {
        let mut mock_transport = MockTransport::new();
        if let Some(response) = peer_response {
            let fake_response = rpc_response(StrippedMessage::CanisterHttpResponse(
                ic_types::crypto::crypto_hash(&response),
                response,
            ));
            mock_transport
                .expect_rpc()
                .times(1)
                .returning(move |_, _| Ok(fake_response.clone()));
        }

        let mut ingress_pool = MockValidatedPoolReader::<SignedIngress>::default();
        ingress_pool.expect_get().returning(|_| None);

        build_assembler(
            ingress_pool,
            FakeCanisterHttpPool::new(pool_responses),
            wanting_bouncer_factory(),
            mock_transport,
        )
    }

    /// A content that goes back into several slots is fetched only once, even if
    /// the stripped proposal declares it once for each of them.
    #[tokio::test]
    async fn assemble_canister_http_response_of_several_slots_test() {
        let response = fake_canister_http_response(1, 1024);
        let block_proposal =
            fake_block_proposal_with_canister_http(fake_canister_http_payload(vec![
                fake_flexible_canister_http_responses_message(
                    1,
                    &[(response.clone(), NODE_1), (response.clone(), NODE_2)],
                ),
            ]));
        let MaybeStrippedConsensusMessage::StrippedBlockProposal(mut stripped) =
            ConsensusMessage::BlockProposal(block_proposal.clone()).strip()
        else {
            panic!("Didn't properly strip the block proposal");
        };
        // We declare each content once, but a peer need not.
        stripped
            .stripped_canister_http_responses
            .stripped_responses
            .push(ic_types::crypto::crypto_hash(&response));
        assert_eq!(
            stripped
                .stripped_canister_http_responses
                .stripped_responses
                .len(),
            2
        );

        let assembler = set_up_assembler_with_canister_http_responses(
            /*pool=*/ vec![],
            /*peer=*/ Some(response),
        );
        let stripped = MaybeStrippedConsensusMessage::StrippedBlockProposal(stripped);
        let reassembled = assembler
            .assemble_message(stripped.id(), Some((stripped, NODE_1)), MockPeers(NODE_1))
            .await;

        assert_assembled(reassembled, &block_proposal);
    }

    /// A payload is not put back together while the content of one of its stripped
    /// responses is still missing.
    #[test]
    fn try_assemble_fails_on_a_missing_canister_http_response() {
        let response = fake_canister_http_response(1, 1024);
        let block_proposal =
            fake_block_proposal_with_canister_http(fake_canister_http_payload(vec![
                fake_canister_http_response_message(&response, &[NODE_1]),
            ]));
        let MaybeStrippedConsensusMessage::StrippedBlockProposal(stripped) =
            ConsensusMessage::BlockProposal(block_proposal).strip()
        else {
            panic!("Didn't properly strip the block proposal");
        };

        let assembler = BlockProposalAssembler::new(stripped);
        let assembly_error = assembler.try_assemble().unwrap_err();

        assert_matches!(
            assembly_error,
            AssemblyError::CanisterHttpPayload(CanisterHttpPayloadError::MissingResponse(hash))
                if hash == ic_types::crypto::crypto_hash(&response)
        );
    }

    /// The contents of every kind of response are still in the canister http pool
    /// when the block that delivers them arrives, so the receiver reassembles the
    /// block without asking anyone.
    #[tokio::test]
    async fn roundtrip_test_with_canister_http_responses_from_pool() {
        let (payload, stripped_responses) = fake_canister_http_payload_with_every_kind();
        let block_proposal = fake_block_proposal_with_canister_http(payload);
        let stripped_hashes: BTreeSet<_> = stripped_responses
            .iter()
            .map(ic_types::crypto::crypto_hash)
            .collect();

        let assembler =
            set_up_assembler_with_canister_http_responses(stripped_responses, /*peer=*/ None);

        assert_eq!(
            BTreeSet::from_iter(assert_roundtrip(&assembler, &block_proposal).await),
            stripped_hashes
        );
    }

    #[tokio::test]
    async fn roundtrip_test_with_canister_http_response_from_peer() {
        let response = fake_canister_http_response(1, 1024);
        let block_proposal =
            fake_block_proposal_with_canister_http(fake_canister_http_payload(vec![
                fake_canister_http_response_message(&response, &[NODE_1]),
            ]));

        // The response is nowhere to be found locally, so it has to come from a peer.
        let assembler = set_up_assembler_with_canister_http_responses(
            /*pool=*/ vec![],
            /*peer=*/ Some(response.clone()),
        );

        assert_eq!(
            assert_roundtrip(&assembler, &block_proposal).await,
            vec![ic_types::crypto::crypto_hash(&response)]
        );
    }

    /// Committee members of a flexible outcall that agree deliver the very same
    /// response, once each, which the receiver has to fetch only once. A response too
    /// small to be worth stripping travels in the block, and is not fetched at all.
    #[tokio::test]
    async fn roundtrip_test_with_identical_and_tiny_canister_http_responses() {
        let response = fake_canister_http_response(1, 1024);
        let tiny = fake_canister_http_response(2, 1);
        let block_proposal =
            fake_block_proposal_with_canister_http(fake_canister_http_payload(vec![
                fake_flexible_canister_http_responses_message(
                    1,
                    &[(response.clone(), NODE_1), (response.clone(), NODE_2)],
                ),
                fake_canister_http_response_message(&tiny, &[NODE_1]),
            ]));

        // Neither response is in the pool, and the peer expects to be asked once.
        let assembler = set_up_assembler_with_canister_http_responses(
            /*pool=*/ vec![],
            /*peer=*/ Some(response.clone()),
        );

        assert_eq!(
            assert_roundtrip(&assembler, &block_proposal).await,
            vec![ic_types::crypto::crypto_hash(&response)]
        );
    }

    /// The whole point of the exercise: the block proposal that goes on the wire is
    /// smaller than the one it was stripped from, by about the response contents it
    /// no longer carries.
    #[test]
    fn stripping_a_block_removes_the_canister_http_responses() {
        let (payload, stripped_responses) = fake_canister_http_payload_with_every_kind();
        let block_proposal = fake_block_proposal_with_canister_http(payload.clone());
        let unstripped_size =
            pb::StrippedConsensusMessage::proxy_encode(MaybeStrippedConsensusMessage::Unstripped(
                ConsensusMessage::BlockProposal(block_proposal.clone()),
            ))
            .len();

        let MaybeStrippedConsensusMessage::StrippedBlockProposal(stripped) =
            ConsensusMessage::BlockProposal(block_proposal).strip()
        else {
            panic!("Didn't properly strip the block proposal");
        };

        // Every response was worth stripping, and is declared...
        assert_eq!(
            stripped
                .stripped_canister_http_responses
                .stripped_responses
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>(),
            stripped_responses
                .iter()
                .map(ic_types::crypto::crypto_hash)
                .collect()
        );
        // ...at a cost of exactly 36 bytes each...
        let undeclared = StrippedBlockProposal {
            stripped_canister_http_responses: StrippedCanisterHttpResponses::default(),
            ..stripped.clone()
        };
        assert_eq!(
            pb::StrippedBlockProposal::proxy_encode(stripped.clone()).len()
                - pb::StrippedBlockProposal::proxy_encode(undeclared).len(),
            36 * stripped_responses.len()
        );
        // ...while the payload shrank by at least their contents.
        let pruned_payload = &stripped
            .pruned_block_proposal_proto
            .value
            .as_ref()
            .unwrap()
            .canister_http_payload_bytes;
        let removed_size: usize = stripped_responses
            .iter()
            .map(|response| response.content.count_bytes())
            .sum();
        assert!(
            payload.len() - pruned_payload.len() >= removed_size,
            "the payload shrank from {} B to {} B, by less than the {removed_size} B removed",
            payload.len(),
            pruned_payload.len()
        );

        let stripped_size = pb::StrippedConsensusMessage::proxy_encode(
            MaybeStrippedConsensusMessage::StrippedBlockProposal(stripped),
        )
        .len();
        assert!(
            stripped_size < unstripped_size,
            "the stripped proposal ({stripped_size} B) is not smaller than the \
             unstripped one ({unstripped_size} B)"
        );
    }

    #[test]
    fn a_block_without_canister_http_responses_is_left_untouched() {
        // A payload with nothing to strip, and a block with no payload at all.
        for payload in [
            fake_canister_http_payload(vec![fake_canister_http_timeout_message(5)]),
            Vec::new(),
        ] {
            let block_proposal = fake_block_proposal(vec![], None, payload.clone(), false);
            let MaybeStrippedConsensusMessage::StrippedBlockProposal(stripped) =
                ConsensusMessage::BlockProposal(block_proposal).strip()
            else {
                panic!("Didn't properly strip the block proposal");
            };

            assert_eq!(
                stripped
                    .pruned_block_proposal_proto
                    .value
                    .as_ref()
                    .unwrap()
                    .canister_http_payload_bytes,
                payload
            );
            let assembler = BlockProposalAssembler::new(stripped);
            assert!(
                PayloadAssembler::<CanisterHttpResponse>::missing_artifacts(&assembler)
                    .next()
                    .is_none()
            );
        }
    }

    /// A peer set that advertises no peers (so missing stripped messages can never be fetched
    /// from a peer) and signals the first time it is consulted, letting the test synchronize on
    /// the assembler having reached the missing-stripped-message fetch.
    #[derive(Clone)]
    struct SignallingNoPeers(Arc<tokio::sync::Notify>);

    impl Peers for SignallingNoPeers {
        fn peers(&self) -> Vec<NodeId> {
            self.0.notify_one();
            Vec::new()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn assemble_aborts_when_bouncer_becomes_unwanted() {
        use std::sync::atomic::{AtomicBool, Ordering};

        // A block proposal with a single ingress message that the receiver is missing.
        let (ingress, _) = fake_ingress_message_with_sig("fake_1", vec![1, 2, 3]);
        let block_proposal = fake_block_proposal_with_ingresses(vec![ingress]);

        // The bouncer reports `Wants` until `wants` flips to `false`, after which it reports
        // `Unwanted`.
        let wants = Arc::new(AtomicBool::new(true));
        let wants_clone = wants.clone();
        let mut mock_bouncer_factory = MockBouncerFactory::default();
        mock_bouncer_factory
            .expect_new_bouncer()
            .returning(move |_| {
                let wants = wants_clone.clone();
                Box::new(move |_: &ConsensusMessageId| {
                    if wants.load(Ordering::SeqCst) {
                        BouncerValue::Wants
                    } else {
                        BouncerValue::Unwanted
                    }
                })
            });
        mock_bouncer_factory
            .expect_refresh_period()
            .return_const(BOUNCER_REFRESH_PERIOD);

        // The missing ingress is never in the local pool, and there are no peers to fetch it
        // from, so the fetch of the missing stripped message would otherwise stay pending forever.
        let mut ingress_pool = MockValidatedPoolReader::<SignedIngress>::default();
        ingress_pool.expect_get().returning(|_| None);

        let assembler = build_assembler(
            ingress_pool,
            FakeCanisterHttpPool::empty(),
            mock_bouncer_factory,
            MockTransport::new(),
        );

        let stripped_block_proposal =
            assembler.disassemble_message(ConsensusMessage::BlockProposal(block_proposal));
        let started = Arc::new(tokio::sync::Notify::new());
        let peers = SignallingNoPeers(started.clone());
        let handle = tokio::spawn(async move {
            assembler
                .assemble_message(
                    stripped_block_proposal.id(),
                    Some((stripped_block_proposal, NODE_1)),
                    peers,
                )
                .await
        });

        // Wait until the assembler has downloaded the stripped proposal
        started.notified().await;

        // The proposal is no longer wanted. Advancing by the bouncer refresh period delivers the
        // new `Unwanted` value, which must abort the assembly instead of waiting forever for the
        // missing ingress.
        wants.store(false, Ordering::SeqCst);
        tokio::time::advance(BOUNCER_REFRESH_PERIOD).await;

        assert_eq!(handle.await.unwrap(), AssembleResult::Unwanted);
    }

    /// Stripped consensus messages are bounced like the consensus messages they were stripped
    /// from, so their bouncer is refreshed just as often.
    #[test]
    fn bouncer_factory_wrapper_uses_the_wrapped_refresh_period() {
        let refresh_period = Duration::from_millis(1234);
        let mut bouncer_factory = MockBouncerFactory::<ConsensusMessage>::default();
        bouncer_factory
            .expect_refresh_period()
            .times(1)
            .return_const(refresh_period);
        let wrapper: BouncerFactoryWrapper<MockValidatedPoolReader<ConsensusMessage>> =
            BouncerFactoryWrapper {
                bouncer_factory: Arc::new(bouncer_factory),
            };

        assert_eq!(wrapper.refresh_period(), refresh_period);
    }

    #[test]
    fn try_assemble_rejects_reconstructed_block_with_mismatched_id() {
        let block_proposal = fake_block_proposal_with_ingresses(vec![]);
        let assembled_id = block_proposal.get_id();
        let mismatched_claimed_id = fake_block_proposal_with_ingresses(vec![
            fake_ingress_message_with_arg_size("fake_1", 8).0,
        ])
        .get_id();
        let MaybeStrippedConsensusMessage::StrippedBlockProposal(mut stripped_block_proposal) =
            ConsensusMessage::BlockProposal(block_proposal).strip()
        else {
            unreachable!();
        };
        stripped_block_proposal.unstripped_consensus_message_id = mismatched_claimed_id.clone();
        let assembler = BlockProposalAssembler::new(stripped_block_proposal);
        let assembly_error = assembler.try_assemble().unwrap_err();

        assert_matches!(
            assembly_error,
            AssemblyError::MismatchedConsensusMessageId { claimed, assembled }
                if claimed == mismatched_claimed_id && assembled == assembled_id
        );
    }
}
