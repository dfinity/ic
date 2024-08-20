use std::sync::Arc;

use crate::metrics::{OngoingStateSyncMetrics, StateSyncManagerHandlerMetrics};
use crate::ongoing::DownloadChunkError;
use axum::{
    body::Bytes,
    extract::State,
    http::{Request, Response, StatusCode},
};
use bytes::BytesMut;
use ic_interfaces::p2p::state_sync::{Chunk, ChunkId, StateSyncArtifactId, StateSyncClient};
use ic_logger::ReplicaLogger;
use ic_protobuf::p2p::v1 as pb;
use prost::Message;

pub const STATE_SYNC_CHUNK_PATH: &str = "/state-sync/chunk";

/// State sync uses 1Mb chunks. To be safe we use 8Mib here same as transport.
const MAX_CHUNK_SIZE: usize = 8 * 1024 * 1024;

pub(crate) struct StateSyncChunkHandler<T> {
    _log: ReplicaLogger,
    state_sync: Arc<dyn StateSyncClient<Message = T>>,
    metrics: StateSyncManagerHandlerMetrics,
}

impl<T> StateSyncChunkHandler<T> {
    pub fn new(
        log: ReplicaLogger,
        state_sync: Arc<dyn StateSyncClient<Message = T>>,
        metrics: StateSyncManagerHandlerMetrics,
    ) -> Self {
        Self {
            _log: log,
            state_sync,
            metrics,
        }
    }
}

pub(crate) async fn state_sync_chunk_handler<T: 'static>(
    State(state): State<Arc<StateSyncChunkHandler<T>>>,
    payload: Bytes,
) -> Result<Bytes, StatusCode> {
    // Parse payload
    let pb::StateSyncChunkRequest { id, chunk_id } =
        pb::StateSyncChunkRequest::decode(payload).map_err(|_| StatusCode::BAD_REQUEST)?;
    let artifact_id: StateSyncArtifactId = id.map(From::from).ok_or(StatusCode::BAD_REQUEST)?;
    let chunk_id = ChunkId::from(chunk_id);

    let jh =
        tokio::task::spawn_blocking(
            move || match state.state_sync.chunk(&artifact_id, chunk_id) {
                Some(data) => {
                    let pb_chunk = pb::StateSyncChunkResponse { data: data.take() };
                    let mut raw = BytesMut::with_capacity(pb_chunk.encoded_len());
                    pb_chunk.encode(&mut raw).expect("Allocated enough memory");
                    let raw = raw.freeze();

                    let compressed = zstd::bulk::compress(&raw, zstd::DEFAULT_COMPRESSION_LEVEL)
                        .expect("Compression failed");
                    state
                        .metrics
                        .compression_ratio
                        .observe(raw.len() as f64 / compressed.len() as f64);
                    Ok(compressed)
                }
                None => Err(StatusCode::NO_CONTENT),
            },
        );
    let data = jh.await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)??;

    Ok(data.into())
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
    metrics: OngoingStateSyncMetrics,
) -> Result<Chunk, DownloadChunkError> {
    let (parts, body) = response.into_parts();

    match parts.status {
        StatusCode::OK => {
            metrics
                .chunk_size_compressed_total
                .inc_by(body.len() as u64);
            let decompressed = zstd::bulk::decompress(&body, MAX_CHUNK_SIZE).map_err(|e| {
                DownloadChunkError::RequestError {
                    chunk_id,
                    err: e.to_string(),
                }
            })?;

            metrics
                .chunk_size_decompressed_total
                .inc_by(decompressed.len() as u64);

            let pb =
                pb::StateSyncChunkResponse::decode(Bytes::from(decompressed)).map_err(|e| {
                    DownloadChunkError::RequestError {
                        chunk_id,
                        err: e.to_string(),
                    }
                })?;

            Ok(pb.data.into())
        }
        StatusCode::NO_CONTENT => Err(DownloadChunkError::NoContent),
        StatusCode::TOO_MANY_REQUESTS => Err(DownloadChunkError::Overloaded),
        StatusCode::REQUEST_TIMEOUT => Err(DownloadChunkError::Timeout),
        _ => Err(DownloadChunkError::RequestError {
            chunk_id,
            err: String::from_utf8_lossy(&body).to_string(),
        }),
    }
}
