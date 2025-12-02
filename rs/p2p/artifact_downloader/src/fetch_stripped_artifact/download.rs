use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

use axum::{
    Router,
    extract::{DefaultBodyLimit, State},
    http::{Request, StatusCode},
    routing::any,
};
use backoff::{ExponentialBackoffBuilder, backoff::Backoff};
use bytes::Bytes;
use ic_interfaces::p2p::consensus::{Peers, ValidatedPoolReader};
use ic_logger::{ReplicaLogger, warn};
use ic_protobuf::{proxy::ProtoProxy, types::v1 as pb};
use ic_quic_transport::Transport;
use ic_types::{
    NodeId, NodeIndex,
    artifact::ConsensusMessageId,
    consensus::{
        BlockPayload, ConsensusMessage,
        idkg::{IDkgArtifactId, IDkgMessage, IDkgObject},
    },
    crypto::canister_threshold_sig::idkg::{IDkgTranscriptId, SignedIDkgDealing},
    messages::{SignedIngress, SignedRequestBytes},
};
use rand::{SeedableRng, rngs::SmallRng, seq::IteratorRandom};
use tokio::time::{Instant, sleep_until, timeout_at};

use crate::fetch_stripped_artifact::types::{
    StrippedMessage, StrippedMessageId, StrippedMessageType,
    rpc::{GetIDkgDealingInBlockRequest, GetIDkgDealingInBlockResponse},
};

use super::{
    metrics::{FetchStrippedConsensusArtifactMetrics, StrippedMessageSenderMetrics},
    types::{
        SignedIngressId,
        rpc::{GetIngressMessageInBlockRequest, GetIngressMessageInBlockResponse},
    },
};

type ValidatedPoolReaderRef<T> = Arc<RwLock<dyn ValidatedPoolReader<T> + Send + Sync>>;

const INGRESS_URI: &str = "/block/ingress/rpc";
const IDKG_DEALING_URI: &str = "/block/idkg_dealing/rpc";
const MIN_ARTIFACT_RPC_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ARTIFACT_RPC_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone)]
pub(super) struct Pools {
    pub(super) consensus_pool: ValidatedPoolReaderRef<ConsensusMessage>,
    pub(super) ingress_pool: ValidatedPoolReaderRef<SignedIngress>,
    pub(super) idkg_pool: ValidatedPoolReaderRef<IDkgMessage>,
    pub(super) metrics: StrippedMessageSenderMetrics,
}

#[derive(Debug)]
enum IngressPoolAccessError {
    /// The consensus pool doesn't have a block proposal with the given [`ConsensusMessageId`].
    BlockNotFound,
    /// Neither ingress pool nor consensus pool has the requested ingress message.
    IngressMessageNotFound,
    /// The consensus artifact with the given [`ConsensusMessageId`] is not a block proposal.
    NotABlockProposal,
    /// The requested block proposal is a summary block. Summary blocks do not contain ingresses.
    SummaryBlock,
}

#[derive(Debug)]
enum IDkgPoolAccessError {
    /// The consensus pool doesn't have a block proposal with the given [`ConsensusMessageId`].
    BlockNotFound,
    /// Neither IDkg pool nor consensus pool has the requested IDkg dealing.
    DealingNotFound,
    /// The specified proposal doesn't contain the given transcript.
    TranscriptNotFound,
    /// The specified proposal doesn't contain an IDKG payload.
    IDkgPayloadNotFound,
    /// The consensus artifact with the given [`ConsensusMessageId`] is not a block proposal.
    NotABlockProposal,
    /// The IDkg artifact with the given [`IDkgArtifactId`] is not a dealing.
    NotADealing,
}

impl Pools {
    /// Retrieves the request [`SignedIngress`] from either of the pools.
    fn get_ingress(
        &self,
        signed_ingress_id: &SignedIngressId,
        block_proposal_id: &ConsensusMessageId,
    ) -> Result<SignedRequestBytes, IngressPoolAccessError> {
        let message_type = StrippedMessageType::Ingress;
        let ingress_message_id = &signed_ingress_id.ingress_message_id;

        // First check if the requested ingress message exists in the Ingress Pool.
        if let Some(ingress_message) = self.ingress_pool.read().unwrap().get(ingress_message_id) {
            // Make sure that this is the correct ingress message. [`IngressMessageId`] does _not_
            // uniquely identify ingress messages, we thus need to perform an extra check.
            if SignedIngressId::from(&ingress_message) == *signed_ingress_id {
                self.metrics.report_stripped_message_in_pool(message_type);
                return Ok(ingress_message.into());
            }
        }

        // Otherwise find the block which should contain the ingress message.
        let Some(consensus_artifact) = self.consensus_pool.read().unwrap().get(block_proposal_id)
        else {
            self.metrics.report_stripped_message_not_found(message_type);
            return Err(IngressPoolAccessError::BlockNotFound);
        };

        // Double check it is indeed a Block Proposal
        let ConsensusMessage::BlockProposal(block_proposal) = consensus_artifact else {
            return Err(IngressPoolAccessError::NotABlockProposal);
        };

        let BlockPayload::Data(data_payload) = block_proposal.as_ref().payload.as_ref() else {
            return Err(IngressPoolAccessError::SummaryBlock);
        };

        match data_payload
            .batch
            .ingress
            .get_serialized_by_id(ingress_message_id)
        {
            Some(bytes)
            // Make sure that this is the correct ingress message. [`IngressMessageId`]
            // does _not_ uniquely identify ingress messages, we thus need to perform
            // an extra check.
                if SignedIngressId::new(ingress_message_id.clone(), bytes)
                    == *signed_ingress_id =>
            {
                self.metrics.report_stripped_message_in_block(message_type);
                Ok(bytes.clone())
            }
            _ => {
                self.metrics.report_stripped_message_not_found(message_type);
                Err(IngressPoolAccessError::IngressMessageNotFound)
            }
        }
    }

    fn get_idkg_dealing(
        &self,
        node_index: NodeIndex,
        dealing_id: &IDkgArtifactId,
        block_proposal_id: &ConsensusMessageId,
    ) -> Result<SignedIDkgDealing, IDkgPoolAccessError> {
        let message_type = StrippedMessageType::IDkgDealing;
        // First check if the requested dealing exists in the IDkg Pool.
        if let Some(IDkgMessage::Dealing(signed_dealing)) =
            self.idkg_pool.read().unwrap().get(dealing_id)
        {
            self.metrics.report_stripped_message_in_pool(message_type);
            return Ok(signed_dealing);
        }

        // Otherwise find the block which should contain the dealing.
        let Some(consensus_artifact) = self.consensus_pool.read().unwrap().get(block_proposal_id)
        else {
            self.metrics.report_stripped_message_not_found(message_type);
            return Err(IDkgPoolAccessError::BlockNotFound);
        };

        // Double check it is indeed a Block Proposal
        let ConsensusMessage::BlockProposal(block_proposal) = consensus_artifact else {
            return Err(IDkgPoolAccessError::NotABlockProposal);
        };

        let Some(idkg) = block_proposal.as_ref().payload.as_ref().as_idkg() else {
            self.metrics.report_stripped_message_not_found(message_type);
            return Err(IDkgPoolAccessError::IDkgPayloadNotFound);
        };

        let IDkgArtifactId::Dealing(prefix, data) = &dealing_id else {
            return Err(IDkgPoolAccessError::NotADealing);
        };

        let transcript_id = IDkgTranscriptId::new(
            data.get_ref().subnet_id,
            prefix.get_ref().group_tag(),
            data.get_ref().height,
        );
        let Some(transcript) = idkg.idkg_transcripts.get(&transcript_id) else {
            self.metrics.report_stripped_message_not_found(message_type);
            return Err(IDkgPoolAccessError::TranscriptNotFound);
        };

        let Some(batch_signed_dealing) = transcript
            .verified_dealings
            .get(&node_index)
            .filter(|v| v.content.message_id() == *dealing_id)
        else {
            self.metrics.report_stripped_message_not_found(message_type);
            return Err(IDkgPoolAccessError::DealingNotFound);
        };

        self.metrics.report_stripped_message_in_block(message_type);
        Ok(batch_signed_dealing.content.clone())
    }
}

pub(super) fn build_axum_router(pools: Pools) -> Router {
    Router::new()
        .route(INGRESS_URI, any(ingress_rpc_handler))
        .route(IDKG_DEALING_URI, any(idkg_dealing_rpc_handler))
        .with_state(pools)
        // Disable request size limit since consensus might push artifacts larger than limit.
        .layer(DefaultBodyLimit::disable())
}

async fn ingress_rpc_handler(
    State(pools): State<Pools>,
    payload: Bytes,
) -> Result<Bytes, StatusCode> {
    let join_handle = tokio::task::spawn_blocking(move || {
        let request_proto: pb::GetIngressMessageInBlockRequest =
            pb::GetIngressMessageInBlockRequest::proxy_decode(&payload)
                .map_err(|_| StatusCode::BAD_REQUEST)?;
        let request = GetIngressMessageInBlockRequest::try_from(request_proto)
            .map_err(|_| StatusCode::BAD_REQUEST)?;

        match pools.get_ingress(&request.signed_ingress_id, &request.block_proposal_id) {
            Ok(serialized_ingress_message) => Ok::<_, StatusCode>(Bytes::from(
                pb::GetIngressMessageInBlockResponse::proxy_encode(
                    GetIngressMessageInBlockResponse {
                        serialized_ingress_message,
                    },
                ),
            )),
            Err(
                IngressPoolAccessError::IngressMessageNotFound
                | IngressPoolAccessError::BlockNotFound,
            ) => Err(StatusCode::NOT_FOUND),
            Err(
                IngressPoolAccessError::NotABlockProposal | IngressPoolAccessError::SummaryBlock,
            ) => Err(StatusCode::BAD_REQUEST),
        }
    });

    let bytes = join_handle
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)??;

    Ok(bytes)
}

async fn idkg_dealing_rpc_handler(
    State(pools): State<Pools>,
    payload: Bytes,
) -> Result<Bytes, StatusCode> {
    let join_handle = tokio::task::spawn_blocking(move || {
        let request_proto: pb::GetIDkgDealingInBlockRequest =
            pb::GetIDkgDealingInBlockRequest::proxy_decode(&payload)
                .map_err(|_| StatusCode::BAD_REQUEST)?;
        let request = GetIDkgDealingInBlockRequest::try_from(request_proto)
            .map_err(|_| StatusCode::BAD_REQUEST)?;

        match pools.get_idkg_dealing(
            request.node_index,
            &request.dealing_id,
            &request.block_proposal_id,
        ) {
            Ok(signed_dealing) => Ok::<_, StatusCode>(Bytes::from(
                pb::GetIDkgDealingInBlockResponse::proxy_encode(GetIDkgDealingInBlockResponse {
                    signed_dealing,
                }),
            )),
            Err(
                IDkgPoolAccessError::IDkgPayloadNotFound
                | IDkgPoolAccessError::BlockNotFound
                | IDkgPoolAccessError::TranscriptNotFound
                | IDkgPoolAccessError::DealingNotFound,
            ) => Err(StatusCode::NOT_FOUND),
            Err(IDkgPoolAccessError::NotABlockProposal | IDkgPoolAccessError::NotADealing) => {
                Err(StatusCode::BAD_REQUEST)
            }
        }
    });

    let bytes = join_handle
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)??;

    Ok(bytes)
}

/// Downloads the missing messages from a random peer.
pub(crate) async fn download_stripped_message<P: Peers>(
    transport: Arc<dyn Transport>,
    stripped_message_id: StrippedMessageId,
    block_proposal_id: ConsensusMessageId,
    log: &ReplicaLogger,
    metrics: &FetchStrippedConsensusArtifactMetrics,
    peer_rx: P,
) -> (StrippedMessage, NodeId) {
    let message_type = StrippedMessageType::from(&stripped_message_id);
    metrics.report_started_stripped_message_download(message_type);
    let mut artifact_download_timeout = ExponentialBackoffBuilder::new()
        .with_initial_interval(MIN_ARTIFACT_RPC_TIMEOUT)
        .with_max_interval(MAX_ARTIFACT_RPC_TIMEOUT)
        .with_max_elapsed_time(None)
        .build();

    let mut rng = SmallRng::from_entropy();

    let request = match &stripped_message_id {
        StrippedMessageId::Ingress(signed_ingress_id) => {
            let request = GetIngressMessageInBlockRequest {
                signed_ingress_id: signed_ingress_id.clone(),
                block_proposal_id,
            };
            let bytes = Bytes::from(pb::GetIngressMessageInBlockRequest::proxy_encode(request));
            Request::builder().uri(INGRESS_URI).body(bytes).unwrap()
        }
        StrippedMessageId::IDkgDealing(dealing_id, node_index) => {
            let request = GetIDkgDealingInBlockRequest {
                node_index: *node_index,
                dealing_id: dealing_id.clone(),
                block_proposal_id,
            };
            let bytes = Bytes::from(pb::GetIDkgDealingInBlockRequest::proxy_encode(request));
            Request::builder()
                .uri(IDKG_DEALING_URI)
                .body(bytes)
                .unwrap()
        }
    };

    loop {
        let next_request_at = Instant::now()
            + artifact_download_timeout
                .next_backoff()
                .unwrap_or(MAX_ARTIFACT_RPC_TIMEOUT);
        if let Some(peer) = { peer_rx.peers().into_iter().choose(&mut rng) } {
            let message_type = StrippedMessageType::from(&stripped_message_id);
            match timeout_at(next_request_at, transport.rpc(&peer, request.clone())).await {
                Ok(Ok(response)) if response.status() == StatusCode::OK => {
                    match parse_response(&stripped_message_id, response.into_body()) {
                        Ok(stripped_message) => {
                            metrics.report_finished_stripped_message_download(message_type);
                            return (stripped_message, peer);
                        }
                        Err(ParseResponseError::MessageIdMismatch) => {
                            metrics.report_download_error(
                                "mismatched_stripped_message_id",
                                message_type,
                            );
                            warn!(
                                log,
                                "Peer {} responded with wrong {} message for advert",
                                peer,
                                message_type.as_str(),
                            );
                        }
                        Err(ParseResponseError::ParsingError(reason)) => {
                            metrics.report_download_error(reason, message_type);
                        }
                    };
                }
                Ok(Ok(_response)) => {
                    metrics.report_download_error("status_not_ok", message_type);
                }
                Ok(Err(_rpc_error)) => {
                    metrics.report_download_error("rpc_error", message_type);
                }
                Err(_timeout) => {
                    metrics.report_download_error("timeout", message_type);
                }
            }
        }

        sleep_until(next_request_at).await;
    }
}

enum ParseResponseError {
    MessageIdMismatch,
    ParsingError(&'static str),
}

fn parse_response(
    message_id: &StrippedMessageId,
    body: Bytes,
) -> Result<StrippedMessage, ParseResponseError> {
    match &message_id {
        StrippedMessageId::Ingress(ingress_id) => {
            let ingress = parse_ingress_response(body)?;
            let derived_ingress_id = SignedIngressId::from(&ingress);
            if derived_ingress_id == *ingress_id {
                return Ok(StrippedMessage::Ingress(derived_ingress_id, ingress));
            }
        }
        StrippedMessageId::IDkgDealing(dealing_id, node_index) => {
            let dealing = parse_dealing_response(body)?;
            let derived_dealing_id = dealing.message_id();
            if derived_dealing_id == *dealing_id {
                return Ok(StrippedMessage::IDkgDealing(
                    derived_dealing_id,
                    *node_index,
                    dealing,
                ));
            }
        }
    }
    Err(ParseResponseError::MessageIdMismatch)
}

fn parse_ingress_response(body: Bytes) -> Result<SignedIngress, ParseResponseError> {
    let response = pb::GetIngressMessageInBlockResponse::proxy_decode(&body)
        .and_then(|proto: pb::GetIngressMessageInBlockResponse| {
            GetIngressMessageInBlockResponse::try_from(proto)
        })
        .map_err(|_| ParseResponseError::ParsingError("ingress_response_decoding_failed"))?;

    SignedIngress::try_from(response.serialized_ingress_message)
        .map_err(|_| ParseResponseError::ParsingError("ingress_deserialization_failed"))
}

fn parse_dealing_response(body: Bytes) -> Result<SignedIDkgDealing, ParseResponseError> {
    let response = pb::GetIDkgDealingInBlockResponse::proxy_decode(&body)
        .and_then(|proto: pb::GetIDkgDealingInBlockResponse| {
            GetIDkgDealingInBlockResponse::try_from(proto)
        })
        .map_err(|_| ParseResponseError::ParsingError("idkg_dealing_response_decoding_failed"))?;

    Ok(response.signed_dealing)
}

#[cfg(test)]
mod tests {
    use crate::fetch_stripped_artifact::test_utils::{
        fake_block_proposal_with_ingresses, fake_block_proposal_with_ingresses_and_idkg,
        fake_idkg_payload_with_dealing, fake_summary_block_proposal,
    };

    use super::*;

    use http_body_util::Full;
    use ic_canister_client_sender::Sender;
    use ic_crypto_test_utils_canister_threshold_sigs::dummy_values::dummy_idkg_dealing_for_tests;
    use ic_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_p2p_test_utils::mocks::{MockPeers, MockTransport, MockValidatedPoolReader};
    use ic_test_utilities_consensus::fake::{FakeContent, FakeContentSigner};
    use ic_test_utilities_types::messages::SignedIngressBuilder;
    use ic_types::{
        Height,
        artifact::IngressMessageId,
        consensus::{
            Finalization, FinalizationContent,
            idkg::{IDkgArtifactIdDataOf, IDkgPrefixOf},
        },
        crypto::{CryptoHash, CryptoHashOf},
        time::UNIX_EPOCH,
    };
    use ic_types_test_utils::ids::{NODE_1, NODE_2};
    use tower::ServiceExt;

    enum PoolMessage {
        /// We expect an access attempt to the ingress pool, with an optional message being returned.
        Ingress(Option<SignedIngress>),
        /// We expect an access attempt to the IDKG pool, with an optional message being returned.
        IDkgDealing(Option<SignedIDkgDealing>),
        /// We don't expect any access to the pools.
        None,
    }

    #[derive(Clone, Debug, PartialEq)]
    enum GetStrippedMessageRequest {
        Ingress(GetIngressMessageInBlockRequest),
        IDkgDealing(GetIDkgDealingInBlockRequest),
    }

    #[derive(Debug, PartialEq)]
    enum GetStrippedMessageResponse {
        Ingress(GetIngressMessageInBlockResponse),
        IDkgDealing(GetIDkgDealingInBlockResponse),
    }

    impl GetStrippedMessageResponse {
        fn unwrap_ingress(self) -> GetIngressMessageInBlockResponse {
            match self {
                GetStrippedMessageResponse::Ingress(response) => response,
                _ => panic!("Expected Ingress response"),
            }
        }

        fn unwrap_idkg_dealing(self) -> GetIDkgDealingInBlockResponse {
            match self {
                GetStrippedMessageResponse::IDkgDealing(response) => response,
                _ => panic!("Expected IDkgDealing response"),
            }
        }
    }

    fn mock_pools(
        stripped_message: PoolMessage,
        consensus_message: Option<ConsensusMessage>,
        expect_consensus_pool_access: bool,
    ) -> Pools {
        let mut ingress_pool = MockValidatedPoolReader::<SignedIngress>::default();
        let mut idkg_pool = MockValidatedPoolReader::<IDkgMessage>::default();

        match stripped_message {
            PoolMessage::Ingress(maybe_ingress) => {
                idkg_pool.expect_get().never();
                if let Some(ingress_message) = maybe_ingress {
                    ingress_pool
                        .expect_get()
                        .with(mockall::predicate::eq(IngressMessageId::from(
                            &ingress_message,
                        )))
                        .once()
                        .return_const(ingress_message.clone());
                } else {
                    ingress_pool.expect_get().once().return_const(None);
                }
            }
            PoolMessage::IDkgDealing(maybe_dealing) => {
                ingress_pool.expect_get().never();
                if let Some(dealing) = maybe_dealing {
                    idkg_pool
                        .expect_get()
                        .with(mockall::predicate::eq(dealing.message_id()))
                        .once()
                        .return_const(IDkgMessage::Dealing(dealing));
                } else {
                    idkg_pool.expect_get().once().return_const(None);
                }
            }
            PoolMessage::None => {
                ingress_pool.expect_get().never();
                idkg_pool.expect_get().never();
            }
        }

        let mut consensus_pool = MockValidatedPoolReader::<ConsensusMessage>::default();
        if let Some(consensus_message) = consensus_message {
            consensus_pool
                .expect_get()
                .with(mockall::predicate::eq(ConsensusMessageId::from(
                    &consensus_message,
                )))
                .once()
                .return_const(consensus_message.clone());
        } else if expect_consensus_pool_access {
            consensus_pool.expect_get().once().return_const(None);
        } else {
            consensus_pool.expect_get().never();
        }

        Pools {
            consensus_pool: Arc::new(RwLock::new(consensus_pool)),
            ingress_pool: Arc::new(RwLock::new(ingress_pool)),
            idkg_pool: Arc::new(RwLock::new(idkg_pool)),
            metrics: StrippedMessageSenderMetrics::new(&MetricsRegistry::new()),
        }
    }

    async fn send_request(
        router: Router,
        request: GetStrippedMessageRequest,
    ) -> Result<GetStrippedMessageResponse, StatusCode> {
        let (bytes, uri) = match request.clone() {
            GetStrippedMessageRequest::Ingress(req) => (
                Bytes::from(pb::GetIngressMessageInBlockRequest::proxy_encode(req)),
                INGRESS_URI,
            ),
            GetStrippedMessageRequest::IDkgDealing(req) => (
                Bytes::from(pb::GetIDkgDealingInBlockRequest::proxy_encode(req)),
                IDKG_DEALING_URI,
            ),
        };

        let request_bytes = Request::builder().uri(uri).body(Full::new(bytes)).unwrap();
        let rpc_response = router
            .oneshot(request_bytes)
            .await
            .expect("Should successfully handler the request");
        let (parts, body) = rpc_response.into_parts();
        if parts.status != StatusCode::OK {
            return Err(parts.status);
        }

        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        match request {
            GetStrippedMessageRequest::Ingress(_) => {
                let response = pb::GetIngressMessageInBlockResponse::proxy_decode(&bytes)
                    .and_then(|proto: pb::GetIngressMessageInBlockResponse| {
                        GetIngressMessageInBlockResponse::try_from(proto)
                    })
                    .expect("Should return a valid proto");
                Ok(GetStrippedMessageResponse::Ingress(response))
            }
            GetStrippedMessageRequest::IDkgDealing(_) => {
                let response = pb::GetIDkgDealingInBlockResponse::proxy_decode(&bytes)
                    .and_then(|proto: pb::GetIDkgDealingInBlockResponse| {
                        GetIDkgDealingInBlockResponse::try_from(proto)
                    })
                    .expect("Should return a valid proto");
                Ok(GetStrippedMessageResponse::IDkgDealing(response))
            }
        }
    }

    #[tokio::test]
    async fn rpc_get_from_ingress_pool_test() {
        let ingress_message = SignedIngressBuilder::new().nonce(1).build();
        let block = fake_block_proposal(vec![]);
        let pools = mock_pools(
            PoolMessage::Ingress(Some(ingress_message.clone())),
            None,
            /*expect_consensus_pool_access=*/ false,
        );
        let router = build_axum_router(pools);

        let response = send_request(
            router,
            ingress_request(
                ConsensusMessageId::from(&block),
                SignedIngressId::from(&ingress_message),
            ),
        )
        .await
        .expect("Should return a valid response")
        .unwrap_ingress();

        assert_eq!(
            &response.serialized_ingress_message,
            ingress_message.binary()
        );
    }

    #[tokio::test]
    async fn rpc_get_from_idkg_pool_test() {
        let dealing = SignedIDkgDealing::fake(dummy_idkg_dealing_for_tests(), NODE_1);
        let block = fake_block_proposal(vec![]);
        let pools = mock_pools(
            PoolMessage::IDkgDealing(Some(dealing.clone())),
            None,
            /*expect_consensus_pool_access=*/ false,
        );
        let router = build_axum_router(pools);

        let response = send_request(
            router,
            idkg_dealing_request(ConsensusMessageId::from(&block), dealing.message_id(), 1),
        )
        .await
        .expect("Should return a valid response")
        .unwrap_idkg_dealing();

        assert_eq!(response.signed_dealing, dealing);
    }

    #[tokio::test]
    async fn rpc_get_ingress_from_consensus_pool_test() {
        let ingress_message = SignedIngressBuilder::new().nonce(1).build();
        let block = fake_block_proposal(vec![ingress_message.clone()]);
        let pools = mock_pools(
            PoolMessage::Ingress(None),
            Some(block.clone()),
            /*expect_consensus_pool_access=*/ true,
        );
        let router = build_axum_router(pools);

        let response = send_request(
            router,
            ingress_request(
                ConsensusMessageId::from(&block),
                SignedIngressId::from(&ingress_message),
            ),
        )
        .await
        .expect("Should return a valid response")
        .unwrap_ingress();

        assert_eq!(
            &response.serialized_ingress_message,
            ingress_message.binary()
        );
    }

    #[tokio::test]
    async fn rpc_get_idkg_dealing_from_consensus_pool_test() {
        let node_index = 1;
        let dealing = SignedIDkgDealing::fake(dummy_idkg_dealing_for_tests(), NODE_1);
        let data_block = fake_block_proposal_with_idkg_dealing(dealing.clone(), node_index, false);
        let summary_block =
            fake_block_proposal_with_idkg_dealing(dealing.clone(), node_index, true);
        for block in [data_block, summary_block] {
            let pools = mock_pools(
                PoolMessage::IDkgDealing(None),
                Some(block.clone()),
                /*expect_consensus_pool_access=*/ true,
            );
            let router = build_axum_router(pools);

            let response = send_request(
                router,
                idkg_dealing_request(
                    ConsensusMessageId::from(&block),
                    dealing.message_id(),
                    node_index,
                ),
            )
            .await
            .expect("Should return a valid response")
            .unwrap_idkg_dealing();

            assert_eq!(response.signed_dealing, dealing);
        }
    }

    #[tokio::test]
    async fn rpc_get_ingress_not_found_test() {
        let ingress_message = SignedIngressBuilder::new().nonce(1).build();
        let block = fake_block_proposal(vec![]);
        let pools = mock_pools(
            PoolMessage::Ingress(None),
            None,
            /*expect_consensus_pool_access=*/ true,
        );
        let router = build_axum_router(pools);

        let response = send_request(
            router,
            ingress_request(
                ConsensusMessageId::from(&block),
                SignedIngressId::from(&ingress_message),
            ),
        )
        .await;

        assert_eq!(response, Err(StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn rpc_get_idkg_dealing_from_consensus_pool_block_not_found_test() {
        let node_index = 1;
        let dealing = SignedIDkgDealing::fake(dummy_idkg_dealing_for_tests(), NODE_1);
        let block = fake_block_proposal_with_idkg_dealing(dealing.clone(), node_index, false);
        let pools = mock_pools(
            PoolMessage::IDkgDealing(None),
            None,
            /*expect_consensus_pool_access=*/ true,
        );
        let router = build_axum_router(pools);

        let response = send_request(
            router,
            idkg_dealing_request(
                ConsensusMessageId::from(&block),
                dealing.message_id(),
                node_index,
            ),
        )
        .await;

        assert_eq!(response, Err(StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn rpc_get_idkg_dealing_from_consensus_pool_wrong_consensus_id_test() {
        let node_index = 1;
        let dealing = SignedIDkgDealing::fake(dummy_idkg_dealing_for_tests(), NODE_1);
        let finalization = ConsensusMessage::Finalization(Finalization::fake(
            FinalizationContent::new(Height::new(100), CryptoHashOf::from(CryptoHash(vec![]))),
        ));
        let pools = mock_pools(
            PoolMessage::None,
            None,
            /*expect_consensus_pool_access=*/ false,
        );
        let router = build_axum_router(pools);

        let response = send_request(
            router,
            idkg_dealing_request(
                ConsensusMessageId::from(&finalization),
                dealing.message_id(),
                node_index,
            ),
        )
        .await;

        assert_eq!(response, Err(StatusCode::BAD_REQUEST));
    }

    #[tokio::test]
    async fn rpc_get_idkg_dealing_from_consensus_no_idkg_payload_test() {
        let node_index = 1;
        let dealing = SignedIDkgDealing::fake(dummy_idkg_dealing_for_tests(), NODE_1);
        let block = fake_block_proposal(vec![]);
        let pools = mock_pools(
            PoolMessage::IDkgDealing(None),
            Some(block.clone()),
            /*expect_consensus_pool_access=*/ true,
        );
        let router = build_axum_router(pools);

        let response = send_request(
            router,
            idkg_dealing_request(
                ConsensusMessageId::from(&block),
                dealing.message_id(),
                node_index,
            ),
        )
        .await;

        assert_eq!(response, Err(StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn rpc_get_idkg_dealing_from_consensus_pool_wrong_idkg_artifact_id_test() {
        let node_index = 1;
        let dealing = SignedIDkgDealing::fake(dummy_idkg_dealing_for_tests(), NODE_1);
        let block = fake_block_proposal_with_idkg_dealing(dealing.clone(), node_index, false);
        let pools = mock_pools(
            PoolMessage::None,
            None,
            /*expect_consensus_pool_access=*/ false,
        );
        let router = build_axum_router(pools);

        let IDkgArtifactId::Dealing(prefix, data) = dealing.message_id() else {
            panic!("Expected dealing artifact id");
        };
        let response = send_request(
            router,
            idkg_dealing_request(
                ConsensusMessageId::from(&block),
                IDkgArtifactId::DealingSupport(
                    IDkgPrefixOf::from(prefix.get()),
                    IDkgArtifactIdDataOf::from(data.get()),
                ),
                node_index,
            ),
        )
        .await;

        assert_eq!(response, Err(StatusCode::BAD_REQUEST));
    }

    #[tokio::test]
    async fn rpc_get_idkg_dealing_from_consensus_pool_node_index_not_found_test() {
        let node_index_in_block = 1;
        let node_index_in_request = 2;
        let dealing = SignedIDkgDealing::fake(dummy_idkg_dealing_for_tests(), NODE_1);
        let block =
            fake_block_proposal_with_idkg_dealing(dealing.clone(), node_index_in_block, false);
        let pools = mock_pools(
            PoolMessage::IDkgDealing(None),
            Some(block.clone()),
            /*expect_consensus_pool_access=*/ true,
        );
        let router = build_axum_router(pools);

        let response = send_request(
            router,
            idkg_dealing_request(
                ConsensusMessageId::from(&block),
                dealing.message_id(),
                node_index_in_request,
            ),
        )
        .await;

        assert_eq!(response, Err(StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn rpc_get_idkg_dealing_not_found_mismatched_hash_test() {
        let node_index = 1;
        let dealing_in_block = SignedIDkgDealing::fake(dummy_idkg_dealing_for_tests(), NODE_1);
        let dealing_in_request = SignedIDkgDealing::fake(dummy_idkg_dealing_for_tests(), NODE_2);
        let block =
            fake_block_proposal_with_idkg_dealing(dealing_in_block.clone(), node_index, false);
        let pools = mock_pools(
            PoolMessage::IDkgDealing(None),
            Some(block.clone()),
            /*expect_consensus_pool_access=*/ true,
        );
        let router = build_axum_router(pools);

        let response = send_request(
            router,
            idkg_dealing_request(
                ConsensusMessageId::from(&block),
                dealing_in_request.message_id(),
                node_index,
            ),
        )
        .await;

        assert_eq!(response, Err(StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn rpc_get_ingress_not_found_mismatched_hash_test() {
        let ingress_message = |signature: Vec<u8>| {
            SignedIngressBuilder::new()
                .nonce(1)
                .expiry_time(UNIX_EPOCH)
                .sign_for_sender(&Sender::Node {
                    pub_key: vec![0, 1, 2, 3],
                    sign: Arc::new(move |_| Ok(signature.clone())),
                })
                .build()
        };

        let ingress_message_1 = ingress_message(vec![1, 1, 1]);
        let ingress_message_2 = ingress_message(vec![2, 2, 2]);
        let ingress_message_3 = ingress_message(vec![3, 3, 3]);

        assert_eq!(
            IngressMessageId::from(&ingress_message_1),
            IngressMessageId::from(&ingress_message_2)
        );
        assert_eq!(
            IngressMessageId::from(&ingress_message_2),
            IngressMessageId::from(&ingress_message_3)
        );

        let block = fake_block_proposal(vec![ingress_message_2.clone()]);
        let pools = mock_pools(
            PoolMessage::Ingress(Some(ingress_message_1.clone())),
            Some(block.clone()),
            /*expect_consensus_pool_access=*/ true,
        );
        let router = build_axum_router(pools);

        let response = send_request(
            router,
            ingress_request(
                ConsensusMessageId::from(&block),
                SignedIngressId::from(&ingress_message_3),
            ),
        )
        .await;

        assert_eq!(response, Err(StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn rpc_get_ingress_summary_block_returns_bad_request_test() {
        let ingress_message = SignedIngressBuilder::new().nonce(1).build();
        let block = fake_summary_block_proposal();
        let pools = mock_pools(
            PoolMessage::Ingress(None),
            Some(block.clone()),
            /*expect_consensus_pool_access=*/ true,
        );
        let router = build_axum_router(pools);

        let response = send_request(
            router,
            ingress_request(
                ConsensusMessageId::from(&block),
                SignedIngressId::from(&ingress_message),
            ),
        )
        .await;

        assert_eq!(response, Err(StatusCode::BAD_REQUEST));
    }

    #[tokio::test]
    async fn download_works() {
        let block = fake_block_proposal(vec![]);
        let ingress_message = SignedIngressBuilder::new().nonce(1).build();
        let node_index = 1;
        let idkg_dealing = SignedIDkgDealing::fake(dummy_idkg_dealing_for_tests(), NODE_1);
        for stripped_message in [
            StrippedMessage::Ingress(SignedIngressId::from(&ingress_message), ingress_message),
            StrippedMessage::IDkgDealing(idkg_dealing.message_id(), node_index, idkg_dealing),
        ] {
            let mut mock_transport = MockTransport::new();
            let mut mock_peers = MockPeers::default();
            let stripped_message_clone = stripped_message.clone();
            mock_peers.expect_peers().return_const(vec![NODE_1]);
            mock_transport
                .expect_rpc()
                .returning(move |_, _| Ok(response(stripped_message_clone.clone())));
            let response = download_stripped_message(
                Arc::new(mock_transport),
                stripped_message.id(),
                ConsensusMessageId::from(&block),
                &no_op_logger(),
                &FetchStrippedConsensusArtifactMetrics::new(&MetricsRegistry::new()),
                mock_peers,
            )
            .await;

            assert_eq!(response, (stripped_message, NODE_1));
        }
    }

    // Utility functions below
    fn fake_block_proposal(ingress_messages: Vec<SignedIngress>) -> ConsensusMessage {
        let block_proposal = fake_block_proposal_with_ingresses(ingress_messages);

        ConsensusMessage::BlockProposal(block_proposal)
    }

    fn fake_block_proposal_with_idkg_dealing(
        dealing: SignedIDkgDealing,
        node_index: NodeIndex,
        is_summary: bool,
    ) -> ConsensusMessage {
        ConsensusMessage::BlockProposal(fake_block_proposal_with_ingresses_and_idkg(
            vec![],
            Some(fake_idkg_payload_with_dealing(dealing, node_index)),
            is_summary,
        ))
    }

    fn ingress_request(
        consensus_message_id: ConsensusMessageId,
        signed_ingress_id: SignedIngressId,
    ) -> GetStrippedMessageRequest {
        GetStrippedMessageRequest::Ingress(GetIngressMessageInBlockRequest {
            signed_ingress_id,
            block_proposal_id: consensus_message_id,
        })
    }

    fn idkg_dealing_request(
        consensus_message_id: ConsensusMessageId,
        dealing_id: IDkgArtifactId,
        node_index: NodeIndex,
    ) -> GetStrippedMessageRequest {
        GetStrippedMessageRequest::IDkgDealing(GetIDkgDealingInBlockRequest {
            block_proposal_id: consensus_message_id,
            node_index,
            dealing_id,
        })
    }

    fn response(stripped_message: StrippedMessage) -> axum::response::Response<Bytes> {
        axum::response::Response::builder()
            .body(Bytes::from(match stripped_message {
                StrippedMessage::Ingress(_, ingress_message) => {
                    pb::GetIngressMessageInBlockResponse::proxy_encode(
                        GetIngressMessageInBlockResponse {
                            serialized_ingress_message: ingress_message.binary().clone(),
                        },
                    )
                }
                StrippedMessage::IDkgDealing(_, _, dealing) => {
                    pb::GetIDkgDealingInBlockResponse::proxy_encode(GetIDkgDealingInBlockResponse {
                        signed_dealing: dealing,
                    })
                }
            }))
            .unwrap()
    }
}
