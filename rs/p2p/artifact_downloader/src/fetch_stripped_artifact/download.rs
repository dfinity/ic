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
    NodeId,
    artifact::ConsensusMessageId,
    consensus::{BlockPayload, ConsensusMessage},
    messages::{SignedIngress, SignedRequestBytes},
};
use rand::{SeedableRng, rngs::SmallRng, seq::IteratorRandom};
use tokio::time::{Instant, sleep_until, timeout_at};

use super::{
    metrics::{FetchStrippedConsensusArtifactMetrics, IngressSenderMetrics},
    types::{
        SignedIngressId,
        rpc::{GetIngressMessageInBlockRequest, GetIngressMessageInBlockResponse},
    },
};

type ValidatedPoolReaderRef<T> = Arc<RwLock<dyn ValidatedPoolReader<T> + Send + Sync>>;

const URI: &str = "/block/ingress/rpc";
const MIN_ARTIFACT_RPC_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ARTIFACT_RPC_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone)]
pub(super) struct Pools {
    pub(super) consensus_pool: ValidatedPoolReaderRef<ConsensusMessage>,
    pub(super) ingress_pool: ValidatedPoolReaderRef<SignedIngress>,
    pub(super) metrics: IngressSenderMetrics,
}

#[derive(Debug)]
enum PoolsAccessError {
    /// The consensus pool doesn't have a block proposal with the given [`ConsensusMessageId`].
    BlockNotFound,
    /// Neither ingress pool nor consensus pool has the requested ingress message.
    IngressMessageNotFound,
    /// The consensus artifact with the given [`ConsensusMessageId`] is not a block proposal.
    NotABlockProposal,
    /// The requested block proposal is a summary block. Summary blocks do not contain ingresses.
    SummaryBlock,
}

impl Pools {
    /// Retrieves the request [`SignedIngress`] from either of the pools.
    fn get(
        &self,
        signed_ingress_id: &SignedIngressId,
        block_proposal_id: &ConsensusMessageId,
    ) -> Result<SignedRequestBytes, PoolsAccessError> {
        let ingress_message_id = &signed_ingress_id.ingress_message_id;

        // First check if the requested ingress message exists in the Ingress Pool.
        if let Some(ingress_message) = self.ingress_pool.read().unwrap().get(ingress_message_id) {
            // Make sure that this is the correct ingress message. [`IngressMessageId`] does _not_
            // uniquely identify ingress messages, we thus need to perform an extra check.
            if SignedIngressId::from(&ingress_message) == *signed_ingress_id {
                self.metrics.ingress_messages_in_ingress_pool.inc();
                return Ok(ingress_message.into());
            }
        }

        // Otherwise find the block which should contain the ingress message.
        let Some(consensus_artifact) = self.consensus_pool.read().unwrap().get(block_proposal_id)
        else {
            self.metrics.ingress_messages_not_found.inc();
            return Err(PoolsAccessError::BlockNotFound);
        };

        // Double check it is indeed a Block Proposal
        let ConsensusMessage::BlockProposal(block_proposal) = consensus_artifact else {
            return Err(PoolsAccessError::NotABlockProposal);
        };

        let BlockPayload::Data(data_payload) = block_proposal.as_ref().payload.as_ref() else {
            return Err(PoolsAccessError::SummaryBlock);
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
                self.metrics.ingress_messages_in_block.inc();
                Ok(bytes.clone())
            }
            _ => {
                self.metrics.ingress_messages_not_found.inc();
                Err(PoolsAccessError::IngressMessageNotFound)
            }
        }
    }
}

pub(super) fn build_axum_router(pools: Pools) -> Router {
    Router::new()
        .route(URI, any(rpc_handler))
        .with_state(pools)
        // Disable request size limit since consensus might push artifacts larger than limit.
        .layer(DefaultBodyLimit::disable())
}

async fn rpc_handler(State(pools): State<Pools>, payload: Bytes) -> Result<Bytes, StatusCode> {
    let join_handle = tokio::task::spawn_blocking(move || {
        let request_proto: pb::GetIngressMessageInBlockRequest =
            pb::GetIngressMessageInBlockRequest::proxy_decode(&payload)
                .map_err(|_| StatusCode::BAD_REQUEST)?;
        let request = GetIngressMessageInBlockRequest::try_from(request_proto)
            .map_err(|_| StatusCode::BAD_REQUEST)?;

        match pools.get(&request.signed_ingress_id, &request.block_proposal_id) {
            Ok(serialized_ingress_message) => Ok::<_, StatusCode>(Bytes::from(
                pb::GetIngressMessageInBlockResponse::proxy_encode(
                    GetIngressMessageInBlockResponse {
                        serialized_ingress_message,
                    },
                ),
            )),
            Err(PoolsAccessError::IngressMessageNotFound | PoolsAccessError::BlockNotFound) => {
                Err(StatusCode::NOT_FOUND)
            }
            Err(PoolsAccessError::NotABlockProposal | PoolsAccessError::SummaryBlock) => {
                Err(StatusCode::BAD_REQUEST)
            }
        }
    });

    let bytes = join_handle
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)??;

    Ok(bytes)
}

/// Downloads the missing ingress messages from a random peer.
pub(crate) async fn download_ingress<P: Peers>(
    transport: Arc<dyn Transport>,
    signed_ingress_id: &SignedIngressId,
    block_proposal_id: ConsensusMessageId,
    log: &ReplicaLogger,
    metrics: &FetchStrippedConsensusArtifactMetrics,
    peer_rx: P,
) -> (SignedIngress, NodeId) {
    metrics.active_ingress_message_downloads.inc();
    let mut artifact_download_timeout = ExponentialBackoffBuilder::new()
        .with_initial_interval(MIN_ARTIFACT_RPC_TIMEOUT)
        .with_max_interval(MAX_ARTIFACT_RPC_TIMEOUT)
        .with_max_elapsed_time(None)
        .build();

    let mut rng = SmallRng::from_entropy();

    let request = GetIngressMessageInBlockRequest {
        signed_ingress_id: signed_ingress_id.clone(),
        block_proposal_id,
    };
    let bytes = Bytes::from(pb::GetIngressMessageInBlockRequest::proxy_encode(request));
    let request = Request::builder().uri(URI).body(bytes).unwrap();

    loop {
        let next_request_at = Instant::now()
            + artifact_download_timeout
                .next_backoff()
                .unwrap_or(MAX_ARTIFACT_RPC_TIMEOUT);
        if let Some(peer) = { peer_rx.peers().into_iter().choose(&mut rng) } {
            match timeout_at(next_request_at, transport.rpc(&peer, request.clone())).await {
                Ok(Ok(response)) if response.status() == StatusCode::OK => {
                    if let Some(ingress_message) = parse_response(response.into_body(), metrics) {
                        if SignedIngressId::from(&ingress_message) == *signed_ingress_id {
                            metrics.active_ingress_message_downloads.dec();
                            return (ingress_message, peer);
                        } else {
                            metrics.report_download_error("mismatched_signed_ingress_id");
                            warn!(
                                log,
                                "Peer {} responded with wrong artifact for advert", peer
                            );
                        }
                    }
                }
                Ok(Ok(_response)) => {
                    metrics.report_download_error("status_not_ok");
                }
                Ok(Err(_rpc_error)) => {
                    metrics.report_download_error("rpc_error");
                }
                Err(_timeout) => {
                    metrics.report_download_error("timeout");
                }
            }
        }

        sleep_until(next_request_at).await;
    }
}

fn parse_response(
    body: Bytes,
    metrics: &FetchStrippedConsensusArtifactMetrics,
) -> Option<SignedIngress> {
    let Ok(response) = pb::GetIngressMessageInBlockResponse::proxy_decode(&body).and_then(
        |proto: pb::GetIngressMessageInBlockResponse| {
            GetIngressMessageInBlockResponse::try_from(proto)
        },
    ) else {
        metrics.report_download_error("response_decoding_failed");
        return None;
    };

    let Ok(ingress) = SignedIngress::try_from(response.serialized_ingress_message) else {
        metrics.report_download_error("ingress_deserialization_failed");
        return None;
    };

    Some(ingress)
}

#[cfg(test)]
mod tests {
    use crate::fetch_stripped_artifact::test_utils::{
        fake_block_proposal_with_ingresses, fake_summary_block_proposal,
    };

    use super::*;

    use http_body_util::Full;
    use ic_canister_client_sender::Sender;
    use ic_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_p2p_test_utils::mocks::{MockPeers, MockTransport, MockValidatedPoolReader};
    use ic_test_utilities_types::messages::SignedIngressBuilder;
    use ic_types::{artifact::IngressMessageId, time::UNIX_EPOCH};
    use ic_types_test_utils::ids::NODE_1;
    use tower::ServiceExt;

    fn mock_pools(
        ingress_message: Option<SignedIngress>,
        consensus_message: Option<ConsensusMessage>,
        expect_consensus_pool_access: bool,
    ) -> Pools {
        let mut ingress_pool = MockValidatedPoolReader::<SignedIngress>::default();
        if let Some(ingress_message) = ingress_message {
            ingress_pool
                .expect_get()
                .with(mockall::predicate::eq(IngressMessageId::from(
                    &ingress_message,
                )))
                .once()
                .return_const(ingress_message);
        } else {
            ingress_pool.expect_get().once().return_const(None);
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
        }

        Pools {
            consensus_pool: Arc::new(RwLock::new(consensus_pool)),
            ingress_pool: Arc::new(RwLock::new(ingress_pool)),
            metrics: IngressSenderMetrics::new(&MetricsRegistry::new()),
        }
    }

    async fn send_request(
        router: Router,
        bytes: Bytes,
    ) -> Result<GetIngressMessageInBlockResponse, StatusCode> {
        let request = Request::builder().uri(URI).body(Full::new(bytes)).unwrap();

        let rpc_response = router
            .oneshot(request)
            .await
            .expect("Should successfully handler the request");
        let (parts, body) = rpc_response.into_parts();
        if parts.status != StatusCode::OK {
            return Err(parts.status);
        }

        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let response = pb::GetIngressMessageInBlockResponse::proxy_decode(&bytes)
            .and_then(|proto: pb::GetIngressMessageInBlockResponse| {
                GetIngressMessageInBlockResponse::try_from(proto)
            })
            .expect("Should return a valid proto");

        Ok(response)
    }

    #[tokio::test]
    async fn rpc_get_from_ingress_pool_test() {
        let ingress_message = SignedIngressBuilder::new().nonce(1).build();
        let block = fake_block_proposal(vec![]);
        let pools = mock_pools(
            Some(ingress_message.clone()),
            None,
            /*expect_consensus_pool_access=*/ false,
        );
        let router = build_axum_router(pools);

        let response = send_request(
            router,
            request(
                ConsensusMessageId::from(&block),
                SignedIngressId::from(&ingress_message),
            ),
        )
        .await
        .expect("Should return a valid response");

        assert_eq!(
            &response.serialized_ingress_message,
            ingress_message.binary()
        );
    }

    #[tokio::test]
    async fn rpc_get_from_consensus_pool_test() {
        let ingress_message = SignedIngressBuilder::new().nonce(1).build();
        let block = fake_block_proposal(vec![ingress_message.clone()]);
        let pools = mock_pools(
            None,
            Some(block.clone()),
            /*expect_consensus_pool_access=*/ true,
        );
        let router = build_axum_router(pools);

        let response = send_request(
            router,
            request(
                ConsensusMessageId::from(&block),
                SignedIngressId::from(&ingress_message),
            ),
        )
        .await
        .expect("Should return a valid response");

        assert_eq!(
            &response.serialized_ingress_message,
            ingress_message.binary()
        );
    }

    #[tokio::test]
    async fn rpc_get_not_found_test() {
        let ingress_message = SignedIngressBuilder::new().nonce(1).build();
        let block = fake_block_proposal(vec![]);
        let pools = mock_pools(None, None, /*expect_consensus_pool_access=*/ true);
        let router = build_axum_router(pools);

        let response = send_request(
            router,
            request(
                ConsensusMessageId::from(&block),
                SignedIngressId::from(&ingress_message),
            ),
        )
        .await;

        assert_eq!(response, Err(StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn rpc_get_not_found_mismatched_hash_test() {
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
            Some(ingress_message_1.clone()),
            Some(block.clone()),
            /*expect_consensus_pool_access=*/ true,
        );
        let router = build_axum_router(pools);

        let response = send_request(
            router,
            request(
                ConsensusMessageId::from(&block),
                SignedIngressId::from(&ingress_message_3),
            ),
        )
        .await;

        assert_eq!(response, Err(StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn rpc_get_summary_block_returns_bad_request_test() {
        let ingress_message = SignedIngressBuilder::new().nonce(1).build();
        let block = fake_summary_block_proposal();
        let pools = mock_pools(
            None,
            Some(block.clone()),
            /*expect_consensus_pool_access=*/ true,
        );
        let router = build_axum_router(pools);

        let response = send_request(
            router,
            request(
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
        let mut mock_transport = MockTransport::new();
        let mut mock_peers = MockPeers::default();
        let ingress_message_clone = ingress_message.clone();
        mock_peers.expect_peers().return_const(vec![NODE_1]);
        mock_transport
            .expect_rpc()
            .returning(move |_, _| Ok(response(ingress_message_clone.clone())));

        let response = download_ingress(
            Arc::new(mock_transport),
            &SignedIngressId::from(&ingress_message),
            ConsensusMessageId::from(&block),
            &no_op_logger(),
            &FetchStrippedConsensusArtifactMetrics::new(&MetricsRegistry::new()),
            mock_peers,
        )
        .await;

        assert_eq!(response, (ingress_message, NODE_1));
    }

    // Utility functions below
    fn fake_block_proposal(ingress_messages: Vec<SignedIngress>) -> ConsensusMessage {
        let block_proposal = fake_block_proposal_with_ingresses(ingress_messages);

        ConsensusMessage::BlockProposal(block_proposal)
    }

    fn request(
        consensus_message_id: ConsensusMessageId,
        signed_ingress_id: SignedIngressId,
    ) -> Bytes {
        let request = GetIngressMessageInBlockRequest {
            signed_ingress_id,
            block_proposal_id: consensus_message_id,
        };

        Bytes::from(pb::GetIngressMessageInBlockRequest::proxy_encode(request))
    }

    fn response(ingress_message: SignedIngress) -> axum::response::Response<Bytes> {
        axum::response::Response::builder()
            .body(Bytes::from(
                pb::GetIngressMessageInBlockResponse::proxy_encode(
                    GetIngressMessageInBlockResponse {
                        serialized_ingress_message: ingress_message.binary().clone(),
                    },
                ),
            ))
            .unwrap()
    }
}
