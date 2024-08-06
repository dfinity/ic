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
use ic_protobuf::{p2p::v1 as pb, proxy::ProtoProxy};
use ic_quic_transport::Transport;
use ic_types::{
    artifact::{ConsensusMessageId, IngressMessageId},
    batch::IngressPayloadError,
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

enum PoolsAccessError {
    /// The consensus pool doesn't have a block proposal with the given [`ConsensusMessageId`].
    BlockNotFound,
    /// Neither ingress pool nor consensus pool has the requested ingress message.
    IngressMessageNotFound,
    /// The consensus artifact with the given [`ConsensusMessageId`] is not a block proposal.
    NotABlockProposal,
    /// The requested block proposal is a summary block. Summary blocks do not contain ingresses.
    SummaryBlock,
    Internal,
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
            .map_err(|err| match err {
                IngressPayloadError::IdNotFound(_) => PoolsAccessError::IngressMessageNotFound,
                _ => PoolsAccessError::Internal,
            })
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
            Err(PoolsAccessError::Internal) => Err(StatusCode::INTERNAL_SERVER_ERROR),
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

    loop {
        let next_request_at = Instant::now()
            + artifact_download_timeout
                .next_backoff()
                .unwrap_or(MAX_ARTIFACT_RPC_TIMEOUT);
        if let Some(peer) = { peer_rx.peers().into_iter().choose(&mut rng) } {
            let bytes = Bytes::from(pb::GetIngressMessageInBlockRequest::proxy_encode(
                request.clone(),
            ));
            let request = Request::builder().uri(URI).body(bytes).unwrap();

            match timeout_at(next_request_at, transport.rpc(&peer, request)).await {
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
