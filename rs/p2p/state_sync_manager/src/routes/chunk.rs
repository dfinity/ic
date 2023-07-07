use std::sync::Arc;

use crate::metrics::{StateSyncManagerHandlerMetrics, CHUNK_HANDLER_LABEL};
use crate::ongoing::DownloadChunkError;
use axum::{
    body::Bytes,
    extract::State,
    http::{Request, Response, StatusCode},
};
use bytes::BytesMut;
use ic_interfaces::state_sync_client::StateSyncClient;
use ic_logger::ReplicaLogger;
use ic_protobuf::p2p::v1 as pb;
use ic_types::{
    artifact::StateSyncArtifactId,
    chunkable::{ArtifactChunk, ChunkId},
    NodeId,
};
use prost::Message;

pub const STATE_SYNC_CHUNK_PATH: &str = "/chunk";

pub(crate) struct StateSyncChunkHandler {
    _log: ReplicaLogger,
    state_sync: Arc<dyn StateSyncClient>,
    metrics: StateSyncManagerHandlerMetrics,
}

impl StateSyncChunkHandler {
    pub fn new(
        log: ReplicaLogger,
        state_sync: Arc<dyn StateSyncClient>,
        metrics: StateSyncManagerHandlerMetrics,
    ) -> Self {
        Self {
            _log: log,
            state_sync,
            metrics,
        }
    }
}

pub(crate) async fn state_sync_chunk_handler(
    State(state): State<Arc<StateSyncChunkHandler>>,
    payload: Bytes,
) -> Result<Bytes, StatusCode> {
    let _timer = state
        .metrics
        .request_duration
        .with_label_values(&[CHUNK_HANDLER_LABEL])
        .start_timer();

    // Parse payload
    let pb::StateSyncChunkRequest { id, chunk_id } =
        pb::StateSyncChunkRequest::decode(payload).map_err(|_| StatusCode::BAD_REQUEST)?;
    let artifact_id: StateSyncArtifactId = id.map(From::from).ok_or(StatusCode::BAD_REQUEST)?;
    let chunk_id = ChunkId::from(chunk_id);

    // TODO: (NET-1442) move this to threadpool
    let jh = tokio::task::spawn_blocking(move || {
        state
            .state_sync
            .chunk(&artifact_id, chunk_id)
            .ok_or(StatusCode::NO_CONTENT)
    });
    let chunk = jh.await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)??;

    let pb_chunk: pb::StateSyncChunkResponse = chunk.into();
    let mut raw = BytesMut::with_capacity(pb_chunk.encoded_len());
    pb_chunk.encode(&mut raw).expect("Allocated enough memory");

    Ok(raw.into())
}

pub(crate) fn build_chunk_handler_request(
    artifact_id: StateSyncArtifactId,
    chunk_id: ChunkId,
) -> Request<Bytes> {
    let pb = pb::StateSyncChunkRequest {
        id: Some(artifact_id.into()),
        chunk_id: chunk_id.get(),
    };

    let mut raw = BytesMut::with_capacity(pb.encoded_len());
    pb.encode(&mut raw).expect("Allocated enough memory");

    Request::builder()
        .uri(STATE_SYNC_CHUNK_PATH)
        .body(raw.freeze())
        .expect("Building from typed values")
}

/// Transforms the http response received into typed responses expected from this handler.
pub(crate) fn parse_chunk_handler_response(
    response: Response<Bytes>,
    chunk_id: ChunkId,
) -> Result<ArtifactChunk, DownloadChunkError> {
    let (parts, body) = response.into_parts();

    let peer_id = *parts
        .extensions
        .get::<NodeId>()
        .expect("Transport attaches peer id");
    match parts.status {
        StatusCode::OK => {
            let pb = pb::StateSyncChunkResponse::decode(body).map_err(|e| {
                DownloadChunkError::RequestError {
                    peer_id,
                    chunk_id,
                    err: e.to_string(),
                }
            })?;

            let chunk = ArtifactChunk {
                chunk_id,
                witness: Vec::new(),
                artifact_chunk_data:
                    ic_types::chunkable::ArtifactChunkData::SemiStructuredChunkData(pb.data),
            };
            Ok(chunk)
        }
        StatusCode::NO_CONTENT => Err(DownloadChunkError::NoContent { peer_id }),
        StatusCode::TOO_MANY_REQUESTS => Err(DownloadChunkError::Overloaded),
        StatusCode::REQUEST_TIMEOUT => Err(DownloadChunkError::Timeout),
        _ => Err(DownloadChunkError::RequestError {
            peer_id,
            chunk_id,
            err: String::from_utf8_lossy(&body).to_string(),
        }),
    }
}
