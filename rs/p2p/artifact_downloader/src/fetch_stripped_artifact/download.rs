use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

use axum::{
    extract::{DefaultBodyLimit, State},
    http::{Request, StatusCode},
    routing::any,
    Router,
};
use backoff::{backoff::Backoff, ExponentialBackoffBuilder};
use bytes::Bytes;
use ic_interfaces::p2p::consensus::{Peers, ValidatedPoolReader};
use ic_logger::{warn, ReplicaLogger};
use ic_protobuf::{types::v1 as pb, proxy::ProtoProxy};
use ic_quic_transport::Transport;
use ic_types::{
    artifact::{ConsensusMessageId, IngressMessageId},
    consensus::{BlockPayload, ConsensusMessage},
    messages::SignedIngress,
    NodeId,
};
use rand::{rngs::SmallRng, seq::IteratorRandom, SeedableRng};
use tokio::time::{sleep_until, timeout_at, Instant};

use super::types::rpc::{GetIngressMessageInBlockRequest, GetIngressMessageInBlockResponse};

type ValidatedPoolReaderRef<T> = Arc<RwLock<dyn ValidatedPoolReader<T> + Send + Sync>>;

const URI: &str = "/block/ingress/rpc";
const MIN_ARTIFACT_RPC_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ARTIFACT_RPC_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone)]
pub(super) struct Pools {
    pub(super) consensus_pool: ValidatedPoolReaderRef<ConsensusMessage>,
    pub(super) ingress_pool: ValidatedPoolReaderRef<SignedIngress>,
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
        ingress_message_id: &IngressMessageId,
        block_proposal_id: &ConsensusMessageId,
    ) -> Result<SignedIngress, PoolsAccessError> {
        // First check if the requested ingress message exists in the Ingress Pool.
        if let Some(ingress_message) = self.ingress_pool.read().unwrap().get(ingress_message_id) {
            return Ok(ingress_message);
        }

        // Otherwise find the block which should contain the ingress message.
        let Some(consensus_artifact) = self.consensus_pool.read().unwrap().get(block_proposal_id)
        else {
            return Err(PoolsAccessError::BlockNotFound);
        };

        // Double check it is indeed a Block Proposal
        let block_proposal = match consensus_artifact {
            ConsensusMessage::BlockProposal(block_proposal) => block_proposal,
            _ => return Err(PoolsAccessError::NotABlockProposal),
        };

        let data_payload = match block_proposal.as_ref().payload.as_ref() {
            BlockPayload::Summary(_) => return Err(PoolsAccessError::SummaryBlock),
            BlockPayload::Data(data_payload) => data_payload,
        };

        data_payload
            .batch
            .ingress
            .get_by_id(ingress_message_id)
            .ok_or(PoolsAccessError::IngressMessageNotFound)
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

        match pools.get(&request.ingress_message_id, &request.block_proposal_id) {
            Ok(ingress_message) => Ok::<_, StatusCode>(Bytes::from(
                pb::GetIngressMessageInBlockResponse::proxy_encode(
                    GetIngressMessageInBlockResponse { ingress_message },
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
    ingress_message_id: IngressMessageId,
    block_proposal_id: ConsensusMessageId,
    log: &ReplicaLogger,
    peer_rx: P,
) -> (SignedIngress, NodeId) {
    let mut artifact_download_timeout = ExponentialBackoffBuilder::new()
        .with_initial_interval(MIN_ARTIFACT_RPC_TIMEOUT)
        .with_max_interval(MAX_ARTIFACT_RPC_TIMEOUT)
        .with_max_elapsed_time(None)
        .build();

    let mut rng = SmallRng::from_entropy();

    let request = GetIngressMessageInBlockRequest {
        ingress_message_id: ingress_message_id.clone(),
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
                    let body = response.into_body();
                    if let Ok(response) = pb::GetIngressMessageInBlockResponse::proxy_decode(&body)
                        .and_then(|proto: pb::GetIngressMessageInBlockResponse| {
                            GetIngressMessageInBlockResponse::try_from(proto)
                        })
                    {
                        if IngressMessageId::from(&response.ingress_message) == ingress_message_id {
                            return (response.ingress_message, peer);
                        } else {
                            warn!(
                                log,
                                "Peer {} responded with wrong artifact for advert", peer
                            );
                        }
                    }
                }
                _ => {}
            }
        }

        sleep_until(next_request_at).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use http_body_util::Full;
    use ic_logger::no_op_logger;
    use ic_p2p_test_utils::mocks::{MockPeers, MockTransport, MockValidatedPoolReader};
    use ic_test_utilities_consensus::{
        fake::{Fake, FakeContentSigner},
        make_genesis,
    };
    use ic_test_utilities_types::messages::SignedIngressBuilder;
    use ic_types::batch::{BatchPayload, IngressPayload};
    use ic_types::consensus::{dkg::Dealings, Block, BlockProposal, DataPayload, Payload, Rank};
    use ic_types::Height;
    use ic_types_test_utils::ids::{node_test_id, NODE_1};
    use tower::ServiceExt;

    fn mock_pools(
        ingress_message: Option<SignedIngress>,
        consensus_message: Option<ConsensusMessage>,
    ) -> Pools {
        let should_call_consensus_pool = ingress_message.is_none();

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
        } else if should_call_consensus_pool {
            consensus_pool.expect_get().once().return_const(None);
        }

        Pools {
            consensus_pool: Arc::new(RwLock::new(consensus_pool)),
            ingress_pool: Arc::new(RwLock::new(ingress_pool)),
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
        let pools = mock_pools(Some(ingress_message.clone()), None);
        let router = build_axum_router(pools);

        let response = send_request(
            router,
            request(
                ConsensusMessageId::from(&block),
                IngressMessageId::from(&ingress_message),
            ),
        )
        .await
        .expect("Should return a valid response");

        assert_eq!(response.ingress_message, ingress_message);
    }

    #[tokio::test]
    async fn rpc_get_from_consensus_pool_test() {
        let ingress_message = SignedIngressBuilder::new().nonce(1).build();
        let block = fake_block_proposal(vec![ingress_message.clone()]);
        let pools = mock_pools(None, Some(block.clone()));
        let router = build_axum_router(pools);

        let response = send_request(
            router,
            request(
                ConsensusMessageId::from(&block),
                IngressMessageId::from(&ingress_message),
            ),
        )
        .await
        .expect("Should return a valid response");

        assert_eq!(response.ingress_message, ingress_message);
    }

    #[tokio::test]
    async fn rpc_get_not_found_test() {
        let ingress_message = SignedIngressBuilder::new().nonce(1).build();
        let block = fake_block_proposal(vec![]);
        let pools = mock_pools(None, None);
        let router = build_axum_router(pools);

        let response = send_request(
            router,
            request(
                ConsensusMessageId::from(&block),
                IngressMessageId::from(&ingress_message),
            ),
        )
        .await;

        assert_eq!(response, Err(StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn rpc_get_summary_block_returns_bad_request_test() {
        let ingress_message = SignedIngressBuilder::new().nonce(1).build();
        let block = fake_summary_block_proposal();
        let pools = mock_pools(None, Some(block.clone()));
        let router = build_axum_router(pools);

        let response = send_request(
            router,
            request(
                ConsensusMessageId::from(&block),
                IngressMessageId::from(&ingress_message),
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
            IngressMessageId::from(&ingress_message),
            ConsensusMessageId::from(&block),
            &no_op_logger(),
            mock_peers,
        )
        .await;

        assert_eq!(response, (ingress_message, NODE_1));
    }

    // Utility functions below

    fn fake_block_proposal(ingress_messages: Vec<SignedIngress>) -> ConsensusMessage {
        let parent = make_genesis(ic_types::consensus::dkg::Summary::fake())
            .content
            .block
            .into_inner();

        let batch = BatchPayload {
            ingress: IngressPayload::from(ingress_messages),
            ..Default::default()
        };

        let block = Block::new(
            ic_types::crypto::crypto_hash(&parent),
            Payload::new(
                ic_types::crypto::crypto_hash,
                BlockPayload::Data(DataPayload {
                    batch,
                    dealings: Dealings::new_empty(Height::from(0)),
                    idkg: None,
                }),
            ),
            parent.height.increment(),
            Rank(0),
            parent.context.clone(),
        );
        ConsensusMessage::BlockProposal(BlockProposal::fake(block, node_test_id(0)))
    }

    fn fake_summary_block_proposal() -> ConsensusMessage {
        let block = make_genesis(ic_types::consensus::dkg::Summary::fake())
            .content
            .block
            .into_inner();

        ConsensusMessage::BlockProposal(BlockProposal::fake(block, node_test_id(0)))
    }

    fn request(
        consensus_message_id: ConsensusMessageId,
        ingress_message_id: IngressMessageId,
    ) -> Bytes {
        let request = GetIngressMessageInBlockRequest {
            ingress_message_id,
            block_proposal_id: consensus_message_id,
        };

        Bytes::from(pb::GetIngressMessageInBlockRequest::proxy_encode(request))
    }

    fn response(ingress_message: SignedIngress) -> axum::response::Response<Bytes> {
        axum::response::Response::builder()
            .body(Bytes::from(
                pb::GetIngressMessageInBlockResponse::proxy_encode(
                    GetIngressMessageInBlockResponse { ingress_message },
                ),
            ))
            .unwrap()
    }
}
