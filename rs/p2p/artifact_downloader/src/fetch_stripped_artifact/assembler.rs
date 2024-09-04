use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

use ic_interfaces::p2p::consensus::{
    Aborted, ArtifactAssembler, BouncerFactory, Peers, ValidatedPoolReader,
};
use ic_logger::ReplicaLogger;
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
        MaybeStrippedConsensusMessage, MaybeStrippedIngress, StrippedBlockProposal,
        StrippedConsensusMessageId,
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
pub(crate) enum InsertionError {
    NotNeeded,
    AlreadyInserted,
}

#[derive(Debug)]
pub(crate) enum AssemblyError {
    Missing(IngressMessageId),
    DeserializationFailed(ProxyDecodeError),
}

impl StrippedBlockProposal {
    /// Returns the list of [`IngressMessageId`]s which have been stripped from the block.
    pub(crate) fn missing_ingress_messages(&self) -> Vec<IngressMessageId> {
        self.stripped_ingress_payload
            .ingress_messages
            .iter()
            .filter_map(|maybe_ingress| match maybe_ingress {
                MaybeStrippedIngress::Full(_, _) => None,
                MaybeStrippedIngress::Stripped(ingress_message_id) => Some(ingress_message_id),
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

        let ingress = self
            .stripped_ingress_payload
            .ingress_messages
            .iter_mut()
            .find(|ingress| match ingress {
                MaybeStrippedIngress::Full(id, _) => *id == ingress_message_id,
                MaybeStrippedIngress::Stripped(id) => *id == ingress_message_id,
            })
            .ok_or(InsertionError::NotNeeded)?;

        match &ingress {
            MaybeStrippedIngress::Full(_, _) => Err(InsertionError::AlreadyInserted),
            MaybeStrippedIngress::Stripped(_) => {
                *ingress = MaybeStrippedIngress::Full(ingress_message_id, ingress_message);
                Ok(())
            }
        }
    }

    /// Tries to reassemble a block.
    ///
    /// Fails if there are still some ingress messages missing.
    pub(crate) fn try_assemble(self) -> Result<BlockProposal, AssemblyError> {
        let Self {
            block_proposal_without_ingresses_proto: mut reconstructed_block_proposal_proto,
            stripped_ingress_payload,
            unstripped_consensus_message_id: _unstripped_consensus_message_id,
        } = self;

        let ingresses = stripped_ingress_payload
            .ingress_messages
            .into_iter()
            .map(|msg| match msg {
                MaybeStrippedIngress::Full(_, message) => Ok(message),
                MaybeStrippedIngress::Stripped(id) => Err(AssemblyError::Missing(id)),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let reconstructed_ingress_payload = IngressPayload::from(ingresses);

        let reconstructed_ingress_payload_proto =
            pb::IngressPayload::from(&reconstructed_ingress_payload);

        reconstructed_block_proposal_proto
            .value
            .as_mut()
            .map(|block| block.ingress_payload = Some(reconstructed_ingress_payload_proto));

        reconstructed_block_proposal_proto
            .try_into()
            .map_err(AssemblyError::DeserializationFailed)
    }
}

#[cfg(test)]
mod tests {
    use ic_test_utilities_consensus::{
        fake::{Fake, FakeContentSigner, FromParent},
        make_genesis,
    };
    use ic_types::{
        batch::BatchPayload, consensus::{dkg::{Dealings, Summary}, Block, BlockPayload, ConsensusMessageHash, DataPayload, Payload, Rank}, crypto::{CryptoHash, CryptoHashOf}, messages::{Blob, HttpCallContent, HttpCanisterUpdate, HttpRequestEnvelope}, time::expiry_time_from_now, Height
    };
    use ic_types_test_utils::ids::node_test_id;

    use crate::fetch_stripped_artifact::types::stripped::StrippedIngressPayload;

    use super::*;

    #[test]
    fn strip_assemble_roundtrip_test() {
        let (ingress_1, _ingress_id_1) = fake_ingress_message("fake_1");
        let (ingress_2, _ingress_id_2) = fake_ingress_message("fake_2");
        let block_proposal =
            fake_block_proposal_with_ingresses(vec![ingress_1.clone(), ingress_2.clone()]);

        // strip the block
        let mut stripped_block_proposal = block_proposal.clone().strip();

        // insert back the missing messages
        stripped_block_proposal
            .try_insert_ingress_message(ingress_1)
            .unwrap();
        stripped_block_proposal
            .try_insert_ingress_message(ingress_2)
            .unwrap();

        // try to reassemble the block
        let assembled_block = stripped_block_proposal.try_assemble().unwrap();

        assert_eq!(assembled_block, block_proposal);
    }

    fn strip_assemble_fails_when_still_missing_ingress_test() {
        let (ingress_1, _ingress_id_1) = fake_ingress_message("fake_1");
        let (ingress_2, ingress_id_2) = fake_ingress_message("fake_2");
        let block_proposal =
            fake_block_proposal_with_ingresses(vec![ingress_1.clone(), ingress_2.clone()]);

        // strip the block
        let mut stripped_block_proposal = block_proposal.clone().strip();

        // insert back only one missing messages
        stripped_block_proposal
            .try_insert_ingress_message(ingress_1)
            .unwrap();

        // try to reassemble the block
        let assembly_error = stripped_block_proposal.try_assemble().unwrap_err();

        match assembly_error {
            AssemblyError::Missing(_) => (),
            _ => panic!("Wrong error"),
        }
    }

    #[test]
    fn missing_ingress_messages_test() {
        let (ingress_1, ingress_1_id) = fake_ingress_message("fake_1");
        let (_ingress_2, ingress_2_id) = fake_ingress_message("fake_2");
        let stripped_block_proposal = fake_stripped_block_proposal_with_ingresses(vec![
            MaybeStrippedIngress::Full(ingress_1_id, ingress_1),
            MaybeStrippedIngress::Stripped(ingress_2_id.clone()),
        ]);

        assert_eq!(
            stripped_block_proposal.missing_ingress_messages(),
            vec![ingress_2_id]
        );
    }

    #[test]
    fn ingress_payload_insertion_works_test() {
        let (ingress_1, ingress_1_id) = fake_ingress_message("fake_1");
        let (ingress_2, ingress_2_id) = fake_ingress_message("fake_2");
        let mut stripped_block_proposal = fake_stripped_block_proposal_with_ingresses(vec![
            MaybeStrippedIngress::Full(ingress_1_id, ingress_1),
            MaybeStrippedIngress::Stripped(ingress_2_id),
        ]);

        stripped_block_proposal
            .try_insert_ingress_message(ingress_2)
            .expect("Should successfully insert the missing ingress");

        assert!(stripped_block_proposal
            .missing_ingress_messages()
            .is_empty());
    }

    #[test]
    fn ingress_payload_insertion_existing_fails_test() {
        let (ingress_1, ingress_1_id) = fake_ingress_message("fake_1");
        let (_ingress_2, ingress_2_id) = fake_ingress_message("fake_2");
        let mut stripped_block_proposal = fake_stripped_block_proposal_with_ingresses(vec![
            MaybeStrippedIngress::Full(ingress_1_id, ingress_1.clone()),
            MaybeStrippedIngress::Stripped(ingress_2_id),
        ]);

        assert_eq!(
            stripped_block_proposal.try_insert_ingress_message(ingress_1),
            Err(InsertionError::AlreadyInserted)
        );
    }

    #[test]
    fn ingress_payload_insertion_unknown_fails_test() {
        let (ingress_1, _ingress_1_id) = fake_ingress_message("fake_1");
        let (_ingress_2, ingress_2_id) = fake_ingress_message("fake_2");
        let mut stripped_block_proposal =
            fake_stripped_block_proposal_with_ingresses(vec![MaybeStrippedIngress::Stripped(
                ingress_2_id,
            )]);

        assert_eq!(
            stripped_block_proposal.try_insert_ingress_message(ingress_1),
            Err(InsertionError::NotNeeded)
        );
    }

    fn fake_stripped_block_proposal_with_ingresses(
        ingress_messages: Vec<MaybeStrippedIngress>,
    ) -> StrippedBlockProposal {
        StrippedBlockProposal {
            block_proposal_without_ingresses_proto: pb::BlockProposal::default(),
            stripped_ingress_payload: StrippedIngressPayload { ingress_messages },
            unstripped_consensus_message_id: fake_consensus_message_id(),
        }
    }

    fn fake_block_proposal_with_ingresses(ingress_messages: Vec<SignedIngress>) -> BlockProposal {
        let parent = make_genesis(Summary::fake()).content.block;
        let block = Block::new(
            ic_types::crypto::crypto_hash(parent.as_ref()),
            Payload::new(
                ic_types::crypto::crypto_hash,
                BlockPayload::Data(DataPayload {
                    batch: BatchPayload {
                        ingress: IngressPayload::from(ingress_messages),
                        ..BatchPayload::default()
                    },
                    dealings: Dealings::new_empty(Height::from(0)),
                    idkg: None,
                }),
            ),
            parent.as_ref().height.increment(),
            Rank(0),
            parent.as_ref().context.clone(),
        );
        BlockProposal::fake(block, node_test_id(0))
    }

    fn fake_ingress_message(method_name: &str) -> (SignedIngress, IngressMessageId) {
        let ingress_expiry = expiry_time_from_now();
        let content = HttpCallContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(vec![42; 8]),
                method_name: method_name.to_string(),
                arg: Blob(b"".to_vec()),
                sender: Blob(vec![0x05]),
                nonce: Some(Blob(vec![1, 2, 3, 4])),
                ingress_expiry: ingress_expiry.as_nanos_since_unix_epoch(),
            },
        };
        let ingress = HttpRequestEnvelope::<HttpCallContent> {
            content,
            sender_pubkey: Some(Blob(vec![2; 32])),
            sender_sig: Some(Blob(vec![1; 32])),
            sender_delegation: None,
        }
        .try_into()
        .unwrap();
        let ingress_id = IngressMessageId::from(&ingress);

        (ingress, ingress_id)
    }

    fn fake_consensus_message_id() -> ConsensusMessageId {
        ConsensusMessageId {
            hash: ConsensusMessageHash::BlockProposal(CryptoHashOf::new(CryptoHash(vec![]))),
            height: Height::new(42),
        }
    }
}
