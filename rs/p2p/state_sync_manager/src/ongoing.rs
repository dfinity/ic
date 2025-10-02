//! State sync manager.
//!
//! Implements the logic that drives the chunk download for a particular state sync.
//! Mechanism:
//!  - Ask State sync for which chunks to download
//!  - Download this batch of chunk in parallel with a concurrency limiter per peer.
//!    Note:
//!      - We randomly chose a peer from the set of peers advertised this state.
//!      - We don't retry failed downloads immediately. Failed downloads are retried
//!        in the next batch download.
//!  - Add downloaded chunk to state.
//!  - Repeat until state sync reports completed or we hit the state sync timeout or
//!    this object is dropped.
use crate::utils::PeerState;
use crate::{metrics::OngoingStateSyncMetrics, utils::XorDistance};
use crate::{
    routes::{build_chunk_handler_request, parse_chunk_handler_response},
    utils::ChunksToDownload,
};
use ic_base_types::NodeId;
use ic_http_endpoints_async_utils::JoinMap;
use ic_interfaces::p2p::state_sync::{ChunkId, Chunkable, StateSyncArtifactId};
use ic_logger::{ReplicaLogger, error, info};
use ic_quic_transport::{Shutdown, Transport};
use rand::{
    SeedableRng,
    distributions::{Distribution, WeightedIndex},
    rngs::SmallRng,
};
use std::{
    collections::{HashMap, hash_map::Entry},
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
use tokio::{
    runtime::Handle,
    select,
    sync::mpsc::{Receiver, Sender},
};
use tokio_util::sync::CancellationToken;

// TODO: NET-1461 find appropriate value for the parallelism
const PARALLEL_CHUNK_DOWNLOADS: usize = 10;
const ONGOING_STATE_SYNC_CHANNEL_SIZE: usize = 200;
const CHUNK_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(10);

struct OngoingStateSync {
    log: ReplicaLogger,
    rt: Handle,
    artifact_id: StateSyncArtifactId,
    metrics: OngoingStateSyncMetrics,
    transport: Arc<dyn Transport>,
    node_id: NodeId,
    // Peer management
    new_peers_rx: Receiver<(NodeId, Option<XorDistance>)>,
    // Peers that advertised state and the number of outstanding chunk downloads to that peer.
    peer_state: HashMap<NodeId, PeerState>,
    // Download management
    allowed_downloads: usize,
    chunks_to_download: ChunksToDownload,
    partial_state: Arc<RwLock<Option<XorDistance>>>,
    is_base_layer: bool,
    // Event tasks
    downloading_chunks: JoinMap<ChunkId, DownloadResult>,
}

pub(crate) struct OngoingStateSyncHandle {
    pub sender: Sender<(NodeId, Option<XorDistance>)>,
    pub artifact_id: StateSyncArtifactId,
    pub partial_state: Arc<RwLock<Option<XorDistance>>>,
    pub shutdown: Shutdown,
}

pub(crate) struct DownloadResult {
    peer_id: NodeId,
    result: Result<(), DownloadChunkError>,
}

pub(crate) fn start_ongoing_state_sync<T: Send + 'static>(
    log: ReplicaLogger,
    rt: &Handle,
    metrics: OngoingStateSyncMetrics,
    tracker: Arc<Mutex<Box<dyn Chunkable<T> + Send>>>,
    node_id: NodeId,
    artifact_id: StateSyncArtifactId,
    transport: Arc<dyn Transport>,
) -> OngoingStateSyncHandle {
    let (new_peers_tx, new_peers_rx) = tokio::sync::mpsc::channel(ONGOING_STATE_SYNC_CHANNEL_SIZE);
    let partial_state = Arc::new(RwLock::new(None));

    let ongoing = OngoingStateSync {
        log: log.clone(),
        rt: rt.clone(),
        artifact_id: artifact_id.clone(),
        metrics,
        transport,
        node_id,
        new_peers_rx,
        peer_state: HashMap::new(),
        allowed_downloads: 0,
        chunks_to_download: ChunksToDownload::new(&log),
        partial_state: partial_state.clone(),
        is_base_layer: false,
        downloading_chunks: JoinMap::new(),
    };

    let shutdown = Shutdown::spawn_on_with_cancellation(
        |cancellation: CancellationToken| ongoing.run(cancellation, tracker),
        rt,
    );

    OngoingStateSyncHandle {
        sender: new_peers_tx,
        artifact_id,
        partial_state,
        shutdown,
    }
}

impl OngoingStateSync {
    pub async fn run<T: 'static + Send>(
        mut self,
        cancellation: CancellationToken,
        tracker: Arc<Mutex<Box<dyn Chunkable<T> + Send>>>,
    ) {
        loop {
            select! {
                () = cancellation.cancelled() => {
                    break
                },
                Some((new_peer, partial_state)) = self.new_peers_rx.recv() => {
                    // For now, adverts with a partial state are ignored
                    if partial_state.is_some() {
                        info!(self.log, "STATE_SYNC: Received a partial state advert from {}", new_peer);
                        continue;
                    }

                    if let Entry::Vacant(entry) = self.peer_state.entry(new_peer) {
                        info!(self.log, "STATE_SYNC: Adding peer {} to ongoing state sync of height {}.", new_peer, self.artifact_id.height);
                        entry.insert(PeerState::new(partial_state));
                        self.allowed_downloads += PARALLEL_CHUNK_DOWNLOADS;
                        self.spawn_chunk_downloads(cancellation.clone(), tracker.clone()).await;
                    }
                }
                Some(download_result) = self.downloading_chunks.join_next() => {
                    match download_result {
                        Ok((result, chunk_id)) => {
                            // We do a saturating sub here because it can happen (in rare cases) that a peer that just joined this sync
                            // was previously removed from the sync and still had outstanding downloads. As a consequence there is the possibiliy
                            // of an underflow. In the case where we close old download task while having active downloads we might start to
                            // undercount active downloads for this peer but this is acceptable since everything will be reset anyway every
                            // 5-10min when state sync restarts.
                            self.peer_state.entry(result.peer_id).and_modify(|peer| { peer.deregister_download();});
                            self.handle_downloaded_chunk_result(chunk_id, result);
                            self.spawn_chunk_downloads(cancellation.clone(), tracker.clone()).await;

                            if self.is_base_layer {
                                let new_partial_state = self.chunks_to_download.next_xor_distance();
                                *self.partial_state.write().await = new_partial_state;
                            }

                            info!(self.log, "STATE_SYNC: Finished downloading chunk {}", chunk_id);
                        }
                        Err(err) => {
                            // If task panic we propagate but we allow tasks to be cancelled.
                            // Task can be cancelled if someone calls .abort()
                            if err.is_panic() {
                                std::panic::resume_unwind(err.into_panic());
                            } else {
                                error!(self.log, "Bug: JoinMap task was cancelled.");
                            }
                        }
                    }
                }
            }

            debug_assert!(
                self.peer_state.len() * PARALLEL_CHUNK_DOWNLOADS == self.allowed_downloads
            );

            // Collect metrics
            self.metrics
                .allowed_parallel_downloads
                .set(self.allowed_downloads as i64);
            self.metrics
                .peers_serving_state
                .set(self.peer_state.len() as i64);
            if self.peer_state.is_empty() {
                info!(
                    self.log,
                    "STATE_SYNC: Stopping ongoing state sync because no peers."
                );
                break;
            }
        }
        // All tracker objects must be dropped before closing the channel.
        while let Some(Ok((finished, chunk_id))) = self.downloading_chunks.join_next().await {
            self.handle_downloaded_chunk_result(chunk_id, finished);
        }
        self.new_peers_rx.close();
    }

    fn handle_downloaded_chunk_result(
        &mut self,
        chunk_id: ChunkId,
        DownloadResult { peer_id, result }: DownloadResult,
    ) {
        self.metrics.record_chunk_download_result(&result);
        match result {
            // Received chunk
            Ok(()) => {
                self.chunks_to_download.download_finished(chunk_id);
            }
            Err(DownloadChunkError::NoContent) => {
                if self.peer_state.remove(&peer_id).is_some() {
                    self.allowed_downloads -= PARALLEL_CHUNK_DOWNLOADS;
                    info!(self.log, "STATE_SYNC: Peer returned no content");
                }
                self.chunks_to_download.download_failed(chunk_id);
            }
            Err(DownloadChunkError::RequestError { chunk_id, err }) => {
                info!(
                    self.log,
                    "Failed to download chunk {} from {}: {} ", chunk_id, peer_id, err
                );
                if self.peer_state.remove(&peer_id).is_some() {
                    self.allowed_downloads -= PARALLEL_CHUNK_DOWNLOADS;
                }
                self.chunks_to_download.download_failed(chunk_id);
            }
            Err(DownloadChunkError::Overloaded)
            | Err(DownloadChunkError::Timeout)
            | Err(DownloadChunkError::Cancelled) => {
                self.chunks_to_download.download_failed(chunk_id);
            }
        }
    }

    async fn spawn_chunk_downloads<T: 'static + Send>(
        &mut self,
        cancellation: CancellationToken,
        tracker: Arc<Mutex<Box<dyn Chunkable<T> + Send>>>,
    ) {
        let available_download_capacity = self
            .allowed_downloads
            .saturating_sub(self.downloading_chunks.len());

        if self.peer_state.is_empty() {
            return;
        }

        let mut small_rng = SmallRng::from_entropy();
        let max_active_downloads = self
            .peer_state
            .values()
            .map(|peer| peer.active_downloads())
            .max()
            .expect("Peers not empty");
        let mut peers = Vec::with_capacity(self.peer_state.len());
        let mut weights = Vec::with_capacity(self.peer_state.len());
        for (peer_id, peer) in &self.peer_state {
            peers.push(*peer_id);
            // Add one such that all peers can get selected.
            weights.push(max_active_downloads - peer.active_downloads() + 1);
        }
        info!(
            self.log,
            "STATE_SYNC: Spawning chunks to download from {} out of {} peers",
            peers.len(),
            self.peer_state.len(),
        );

        let dist = WeightedIndex::new(weights).expect("weights>=0, sum(weights)>0, len(weigths)>0");
        for _ in 0..available_download_capacity {
            match self.chunks_to_download.next_chunk_to_download() {
                Some(chunk) if !self.downloading_chunks.contains(&chunk) => {
                    // Select random peer weighted proportional to active downloads.
                    // Peers with less active downloads are more likely to be selected.
                    let peer_id = *peers.get(dist.sample(&mut small_rng)).expect("Is present");

                    info!(
                        self.log,
                        "STATE_SYNC: Spawning download chunk {} for peer {}", chunk, peer_id
                    );
                    self.peer_state
                        .entry(peer_id)
                        .and_modify(|peer| peer.register_download());
                    self.downloading_chunks.spawn_on(
                        chunk,
                        self.metrics
                            .download_task_monitor
                            .instrument(Self::download_chunk_task(
                                peer_id,
                                self.transport.clone(),
                                tracker.clone(),
                                self.artifact_id.clone(),
                                chunk,
                                cancellation.child_token(),
                                self.metrics.clone(),
                            )),
                        &self.rt,
                    );
                }
                Some(_) => {}
                None => {
                    if self.chunks_to_download.num_entries() != 0 {
                        return;
                    }

                    // If we store chunks in self.chunks_to_download we will eventually initiate and
                    // by filtering with the current in flight request we avoid double download.
                    let tracker = tracker.lock().await;

                    let chunks_to_download = tracker
                        .chunks_to_download()
                        .filter(|chunk| !self.downloading_chunks.contains(chunk));

                    let added = self.chunks_to_download.add_chunks(
                        self.node_id,
                        self.artifact_id.clone(),
                        chunks_to_download,
                    );

                    if added != 0 {
                        info!(
                            self.log,
                            "STATE_SYNC: Requesting new chunks, added {}", added
                        );
                    }

                    if !self.is_base_layer && tracker.is_base_layer() {
                        info!(self.log, "STATE_SYNC: Starting to download base layer");
                        self.is_base_layer = true;
                    }

                    self.metrics.chunks_to_download_calls_total.inc();
                    self.metrics.chunks_to_download_total.inc_by(added as u64);
                }
            }
        }
    }

    async fn download_chunk_task<T: 'static + Send>(
        peer_id: NodeId,
        client: Arc<dyn Transport>,
        tracker: Arc<Mutex<Box<dyn Chunkable<T> + Send>>>,
        artifact_id: StateSyncArtifactId,
        chunk_id: ChunkId,
        download_cancel_token: CancellationToken,
        metrics: OngoingStateSyncMetrics,
    ) -> DownloadResult {
        let _timer = metrics.chunk_download_duration.start_timer();

        let response_result = select! {
            () = download_cancel_token.cancelled() => {
                return DownloadResult {
                    peer_id,
                    result: Err(DownloadChunkError::Cancelled)
                }
            }
            res = tokio::time::timeout(CHUNK_DOWNLOAD_TIMEOUT,client.rpc(&peer_id, build_chunk_handler_request(artifact_id, chunk_id))) => {
                res
            }
        };

        let response = match response_result {
            Ok(Ok(response)) => response,
            Ok(Err(e)) => {
                return DownloadResult {
                    peer_id,
                    result: Err(DownloadChunkError::RequestError {
                        chunk_id,
                        err: e.to_string(),
                    }),
                };
            }
            Err(_) => {
                return DownloadResult {
                    peer_id,
                    result: Err(DownloadChunkError::Timeout),
                };
            }
        };

        let mut tracker_guard = tracker.clone().lock_owned().await;
        let result = tokio::task::spawn_blocking(move || {
            let chunk = parse_chunk_handler_response(response, chunk_id, metrics)?;
            tracker_guard.add_chunk(chunk_id, chunk).map_err(|err| {
                DownloadChunkError::RequestError {
                    chunk_id,
                    err: err.to_string(),
                }
            })
        })
        .await
        .map_err(|err| DownloadChunkError::RequestError {
            chunk_id,
            err: err.to_string(),
        })
        .flatten();
        //.and_then(std::convert::identity);

        DownloadResult { peer_id, result }
    }
}

#[derive(Clone, Debug, Error)]
pub(crate) enum DownloadChunkError {
    /// Request was processed but requested content was not available.
    /// This error is permanent.
    #[error("no_content")]
    NoContent,
    /// Download was cancelled.
    #[error("cancelled")]
    Cancelled,
    /// Request was not processed because peer endpoint is overloaded.
    /// This error is transient.
    #[error("overloaded")]
    Overloaded,
    /// Request was not processed because of a timeout either on the client side or on the server side.
    #[error("timeout")]
    Timeout,
    /// An unexpected error occurred during the request. Requests to well-behaving peers
    /// do not return a RequestError.
    #[error("request_error")]
    RequestError { chunk_id: ChunkId, err: String },
}

#[cfg(test)]
mod tests {
    use axum::http::{Response, StatusCode};
    use bytes::{Bytes, BytesMut};
    use ic_interfaces::p2p::state_sync::AddChunkError;
    use ic_metrics::MetricsRegistry;
    use ic_p2p_test_utils::mocks::{MockChunkable, MockTransport};
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_types::{Height, crypto::CryptoHash};
    use ic_types_test_utils::ids::{NODE_1, node_test_id};
    use prost::Message;
    use tokio::runtime::Runtime;

    use super::*;
    #[derive(Clone)]
    struct TestMessage;

    fn compress_empty_bytes() -> Bytes {
        let mut raw = BytesMut::new();
        Bytes::new()
            .encode(&mut raw)
            .expect("Allocated enough memory");
        Bytes::from(zstd::bulk::compress(&raw, zstd::DEFAULT_COMPRESSION_LEVEL).unwrap())
    }

    /// Verify that state sync gets aborted if state sync should be cancelled.
    #[test]
    fn test_cancel_if_running() {
        with_test_replica_logger(|log| {
            let mut t = MockTransport::default();
            t.expect_rpc().returning(|_, _| {
                Ok(Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .body(compress_empty_bytes())
                    .unwrap())
            });
            let mut c = MockChunkable::<TestMessage>::default();
            c.expect_chunks_to_download()
                .returning(|| Box::new(std::iter::once(ChunkId::from(1))));
            c.expect_is_base_layer().returning(|| false);

            let rt = Runtime::new().unwrap();
            let ongoing = start_ongoing_state_sync(
                log,
                rt.handle(),
                OngoingStateSyncMetrics::new(&MetricsRegistry::default()),
                Arc::new(Mutex::new(Box::new(c))),
                node_test_id(0),
                StateSyncArtifactId {
                    height: Height::from(1),
                    hash: CryptoHash(vec![]),
                },
                Arc::new(t),
            );

            rt.block_on(async move {
                ongoing.sender.send((NODE_1, None)).await.unwrap();
                ongoing.shutdown.shutdown().await.unwrap();
            });
        });
    }

    /// Verify that peer gets removed if chunk verification fails.
    #[test]
    fn test_chunk_verification_failed() {
        with_test_replica_logger(|log| {
            let mut t = MockTransport::default();
            t.expect_rpc().returning(|_, _| {
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .body(compress_empty_bytes())
                    .unwrap())
            });
            let mut c = MockChunkable::<TestMessage>::default();
            c.expect_chunks_to_download()
                .returning(|| Box::new(std::iter::once(ChunkId::from(1))));
            c.expect_is_base_layer().returning(|| false);
            c.expect_add_chunk()
                .return_const(Err(AddChunkError::Invalid));

            let rt = Runtime::new().unwrap();
            let ongoing = start_ongoing_state_sync(
                log,
                rt.handle(),
                OngoingStateSyncMetrics::new(&MetricsRegistry::default()),
                Arc::new(Mutex::new(Box::new(c))),
                node_test_id(0),
                StateSyncArtifactId {
                    height: Height::from(1),
                    hash: CryptoHash(vec![]),
                },
                Arc::new(t),
            );

            rt.block_on(async move {
                ongoing.sender.send((NODE_1, None)).await.unwrap();
                // State sync should exit because NODE_1 got removed.
                ongoing.shutdown.shutdown().await.unwrap();
            });
        });
    }

    /// Add peer multiple times to ongoing sync. Debug assertion in event loop verifies
    /// that download budget is correct.
    #[test]
    fn test_add_peer_multiple_times_to_ongoing_state_sync() {
        with_test_replica_logger(|log| {
            let mut t = MockTransport::default();
            t.expect_rpc().returning(|_, _| {
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .body(compress_empty_bytes())
                    .unwrap())
            });
            let mut c = MockChunkable::<TestMessage>::default();
            // Endless iterator
            c.expect_chunks_to_download()
                .returning(|| Box::new(std::iter::once(ChunkId::from(1))));
            c.expect_is_base_layer().returning(|| false);
            c.expect_add_chunk().return_const(Ok(()));

            let rt = Runtime::new().unwrap();
            let ongoing = start_ongoing_state_sync(
                log,
                rt.handle(),
                OngoingStateSyncMetrics::new(&MetricsRegistry::default()),
                Arc::new(Mutex::new(Box::new(c))),
                node_test_id(0),
                StateSyncArtifactId {
                    height: Height::from(1),
                    hash: CryptoHash(vec![]),
                },
                Arc::new(t),
            );

            rt.block_on(async move {
                ongoing.sender.send((NODE_1, None)).await.unwrap();
                ongoing.sender.send((NODE_1, None)).await.unwrap();
                ongoing.sender.send((NODE_1, None)).await.unwrap();
                // State sync should exit because NODE_1 got removed.
                ongoing.shutdown.shutdown().await.unwrap();
            });
        });
    }
}
