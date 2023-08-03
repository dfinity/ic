//! State sync manager.
//!
//! Implements the logic that drives the chunk download for a particular state sync.
//! Mechanism:
//!  - Ask State sync for which chunks to download
//!  - Download this batch of chunk in parallel with a concurrency limiter per peer.
//!    Note: - We randomly chose a peer from the set of peers advertised this state.
//!          - We don't retry failed downloads immediately. Failed downloads are retried
//!            in the next batch download.
//!  - Add downloaded chunk to state.
//!  - Repeat until state sync reports completed or we hit the state sync timeout or
//!    this object is dropped.
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::metrics::OngoingStateSyncMetrics;
use crate::routes::{build_chunk_handler_request, parse_chunk_handler_response};

use ic_async_utils::JoinMap;
use ic_interfaces::state_sync_client::StateSyncClient;
use ic_logger::{error, info, ReplicaLogger};
use ic_quic_transport::Transport;
use ic_types::{
    artifact::{Artifact, StateSyncArtifactId, StateSyncMessage},
    chunkable::ChunkId,
    chunkable::{ArtifactErrorCode, Chunkable},
    NodeId,
};
use rand::{rngs::SmallRng, Rng, SeedableRng};
use strum_macros::Display;
use tokio::{
    runtime::Handle,
    select,
    sync::mpsc::{Receiver, Sender},
    task::JoinHandle,
};

// TODO: NET-1461 find appropriate value for the parallelism
const PARALLEL_CHUNK_DOWNLOADS: usize = 50;
const ONGOING_STATE_SYNC_CHANNEL_SIZE: usize = 200;
const CHUNK_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(10);
/// Same reasoning as old state sync mechanism:
/// Maximum timeout for fetching state sync. 10_000s.
/// Reasoning: Block rate can be as low as 0.1 and we want to allow state sync
/// to last for 1000 blocks (two checkpoint intervals) -> 1000b/0.1b/s = 10000s
const STATE_SYNC_TIMEOUT: Duration = Duration::from_secs(10000);

struct OngoingStateSync {
    log: ReplicaLogger,
    rt: Handle,
    artifact_id: StateSyncArtifactId,
    metrics: OngoingStateSyncMetrics,
    transport: Arc<dyn Transport>,
    // Peer management
    new_peers_rx: Receiver<NodeId>,
    peers: HashSet<NodeId>,
    // Download management
    allowed_downloads: usize,
    chunks_to_download: Box<dyn Iterator<Item = ChunkId> + Send>,
    // Event tasks
    downloading_chunks: JoinMap<ChunkId, Result<Option<CompletedStateSync>, DownloadChunkError>>,
    // State sync
    state_sync: Arc<dyn StateSyncClient>,
    tracker: Arc<Mutex<Box<dyn Chunkable + Send + Sync>>>,
    state_sync_finished: bool,
}

pub(crate) struct OngoingStateSyncHandle {
    pub sender: Sender<NodeId>,
    pub jh: JoinHandle<()>,
}

pub(crate) fn start_ongoing_state_sync(
    log: ReplicaLogger,
    rt: &Handle,
    metrics: OngoingStateSyncMetrics,
    tracker: Arc<Mutex<Box<dyn Chunkable + Send + Sync>>>,
    artifact_id: StateSyncArtifactId,
    state_sync: Arc<dyn StateSyncClient>,
    transport: Arc<dyn Transport>,
) -> OngoingStateSyncHandle {
    let (new_peers_tx, new_peers_rx) = tokio::sync::mpsc::channel(ONGOING_STATE_SYNC_CHANNEL_SIZE);
    let ongoing = OngoingStateSync {
        log,
        rt: rt.clone(),
        artifact_id,
        metrics,
        transport,
        new_peers_rx,
        peers: HashSet::new(),
        allowed_downloads: 0,
        chunks_to_download: Box::new(std::iter::empty()),
        downloading_chunks: JoinMap::new(),
        state_sync,
        tracker,
        state_sync_finished: false,
    };

    let jh = rt.spawn(ongoing.run());
    OngoingStateSyncHandle {
        sender: new_peers_tx,
        jh,
    }
}

impl OngoingStateSync {
    pub async fn run(mut self) {
        let state_sync_timeout = tokio::time::sleep(STATE_SYNC_TIMEOUT);
        tokio::pin!(state_sync_timeout);
        loop {
            select! {
                _ = &mut state_sync_timeout => {
                    info!(self.log, "State sync for height {} timed out.", self.artifact_id.height);
                    break;
                }
                Some(new_peer) = self.new_peers_rx.recv() => {
                    if self.peers.insert(new_peer) {
                        info!(self.log, "Adding peer {} to ongoing state sync of height {}.", new_peer, self.artifact_id.height);
                        self.allowed_downloads += PARALLEL_CHUNK_DOWNLOADS;
                        self.spawn_chunk_downloads();
                    }
                }
                Some(download_result) = self.downloading_chunks.join_next() => {
                    match download_result {
                        Ok((chunk_download_result, _)) => {
                            // Usually it is discouraged to use await in the event loop.
                            // In this case it is ok because the function only is async if state sync completed.
                            self.handle_downloaded_chunk_result(chunk_download_result).await;
                            self.spawn_chunk_downloads();
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

            debug_assert!(self.peers.len() * PARALLEL_CHUNK_DOWNLOADS == self.allowed_downloads);

            // Collect metrics
            self.metrics
                .allowed_parallel_downloads
                .set(self.allowed_downloads as i64);
            self.metrics
                .peers_serving_state
                .set(self.peers.len() as i64);
            // Conditions on when to exit (in addition to timeout)
            if self.state_sync_finished
                || self.peers.is_empty()
                || self.state_sync.should_cancel(&self.artifact_id)
            {
                info!(self.log, "Stopping ongoing state sync because: finished: {}; no peers: {}; should cancel: {};",
                    self.state_sync_finished,
                    self.peers.is_empty(),
                    self.state_sync.should_cancel(&self.artifact_id)
                );
                break;
            }
        }

        self.downloading_chunks.shutdown().await;
    }

    async fn handle_downloaded_chunk_result(
        &mut self,
        res: Result<Option<CompletedStateSync>, DownloadChunkError>,
    ) {
        self.metrics.record_chunk_download_result(&res);
        match res {
            // Received chunk
            Ok(Some(CompletedStateSync { msg, peer_id })) => {
                let state_sync_c = self.state_sync.clone();
                let _ = self
                    .rt
                    .spawn_blocking(move || state_sync_c.deliver_state_sync(msg, peer_id))
                    .await;
                self.state_sync_finished = true;
            }
            Ok(None) => {}
            Err(DownloadChunkError::NoContent { peer_id }) => {
                if self.peers.remove(&peer_id) {
                    self.allowed_downloads -= PARALLEL_CHUNK_DOWNLOADS;
                }
            }
            Err(DownloadChunkError::RequestError {
                peer_id,
                chunk_id,
                err,
            }) => {
                info!(
                    self.log,
                    "Failed to download chunk {} from {}: {} ", chunk_id, peer_id, err
                );
                if self.peers.remove(&peer_id) {
                    self.allowed_downloads -= PARALLEL_CHUNK_DOWNLOADS;
                }
            }
            Err(DownloadChunkError::Overloaded) => {}
            Err(DownloadChunkError::Timeout) => {}
        }
    }

    fn spawn_chunk_downloads(&mut self) {
        let available_download_capacity = self
            .allowed_downloads
            .saturating_sub(self.downloading_chunks.len());

        let mut small_rng = SmallRng::from_entropy();
        for _ in 0..available_download_capacity {
            match self.chunks_to_download.next() {
                Some(chunk) if !self.downloading_chunks.contains(&chunk) => {
                    // Select random peer.
                    let peers: Vec<_> = self.peers.iter().copied().collect();
                    if peers.is_empty() {
                        break;
                    }
                    // Spawn chunk download to random peer.
                    let peer_id = peers.get(small_rng.gen_range(0..peers.len())).unwrap();
                    self.downloading_chunks.spawn_on(
                        chunk,
                        self.metrics
                            .download_task_monitor
                            .instrument(Self::download_chunk_task(
                                *peer_id,
                                self.transport.clone(),
                                self.tracker.clone(),
                                self.artifact_id.clone(),
                                chunk,
                                self.metrics.clone(),
                            )),
                        &self.rt,
                    );
                }
                Some(_) => {}
                None => {
                    // If we store chunks in self.chunks_to_download we will eventually initiate  and
                    // by filtering with the current in flight request we avoid double download.
                    // TODO: Evaluate performance impact of this since on mainnet it is possible
                    // that `chunks_to_download` returns 1Million elements.
                    let mut v = Vec::new();
                    for c in self.tracker.lock().unwrap().chunks_to_download() {
                        if !self.downloading_chunks.contains(&c) {
                            v.push(c);
                        }
                    }
                    self.metrics.chunks_to_download_calls_total.inc();
                    self.metrics.chunks_to_download_total.inc_by(v.len() as u64);
                    self.chunks_to_download = Box::new(v.into_iter());
                }
            }
        }
    }

    async fn download_chunk_task(
        peer_id: NodeId,
        client: Arc<dyn Transport>,
        tracker: Arc<Mutex<Box<dyn Chunkable + Send + Sync>>>,
        artifact_id: StateSyncArtifactId,
        chunk_id: ChunkId,
        metrics: OngoingStateSyncMetrics,
    ) -> Result<Option<CompletedStateSync>, DownloadChunkError> {
        let _timer = metrics.chunk_download_duration.start_timer();

        let response_result = tokio::time::timeout(
            CHUNK_DOWNLOAD_TIMEOUT,
            client.rpc(&peer_id, build_chunk_handler_request(artifact_id, chunk_id)),
        )
        .await;

        let response = match response_result {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(e)) => Err(DownloadChunkError::RequestError {
                peer_id,
                chunk_id,
                err: e.to_string(),
            }),
            Err(_) => Err(DownloadChunkError::Timeout),
        }?;

        let chunk = parse_chunk_handler_response(response, chunk_id)?;

        // TODO: This should be done in a threadpool of size 1.
        let chunk_add_result =
            tokio::task::spawn_blocking(move || tracker.lock().unwrap().add_chunk(chunk)).await;

        match chunk_add_result {
            Ok(Ok(Artifact::StateSync(msg))) => Ok(Some(CompletedStateSync { msg, peer_id })),
            Ok(Ok(_)) => {
                //TODO: (NET-1448) With new protobufs this condition will redundant.
                panic!("Should not happen");
            }
            Ok(Err(ArtifactErrorCode::ChunksMoreNeeded)) => Ok(None),
            Ok(Err(ArtifactErrorCode::ChunkVerificationFailed)) => {
                Err(DownloadChunkError::RequestError {
                    peer_id,
                    chunk_id,
                    err: String::from("Chunk verification failed."),
                })
            }
            // If task panic we propagate  but we allow tasks to be cancelled.
            // Task can be cancelled if someone calls .abort()
            Err(err) => {
                if err.is_panic() {
                    std::panic::resume_unwind(err.into_panic());
                }
                Err(DownloadChunkError::RequestError {
                    peer_id,
                    chunk_id,
                    err: String::from("Add chunk canceled."),
                })
            }
        }
    }
}

pub(crate) struct CompletedStateSync {
    msg: StateSyncMessage,
    peer_id: NodeId,
}

#[derive(Debug, Clone, Display)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum DownloadChunkError {
    /// Request was processed but requested content was not available.
    /// This error is permanent.
    NoContent { peer_id: NodeId },
    /// Request was not processed because peer endpoint is overloaded.
    /// This error is transient.
    Overloaded,
    /// Request was not processed beacuse of a timeout either on the client side or on the server side.
    Timeout,
    /// An unexpected error occurred during the request. Requests to well-behaving peers
    /// do not return a RequestError.
    RequestError {
        peer_id: NodeId,
        chunk_id: ChunkId,
        err: String,
    },
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use async_trait::async_trait;
    use axum::http::{Request, Response, StatusCode};
    use bytes::Bytes;
    use ic_metrics::MetricsRegistry;
    use ic_quic_transport::TransportError;
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_types::{chunkable::ArtifactChunk, crypto::CryptoHash, CryptoHashOfState, Height};
    use ic_types_test_utils::ids::{NODE_1, NODE_2};
    use mockall::mock;
    use tokio::runtime::Runtime;

    use super::*;

    mock! {
        pub StateSync {}

        impl StateSyncClient for StateSync {
            fn available_states(&self) -> Vec<StateSyncArtifactId>;

            fn start_state_sync(
                &self,
                id: &StateSyncArtifactId,
            ) -> Option<Box<dyn Chunkable + Send + Sync>>;

            fn should_cancel(&self, id: &StateSyncArtifactId) -> bool;

            fn chunk(&self, id: &StateSyncArtifactId, chunk_id: ChunkId) -> Option<ArtifactChunk>;

            fn deliver_state_sync(&self, msg: StateSyncMessage, peer_id: NodeId);
        }
    }

    mock! {
        pub Transport {}

        #[async_trait]
        impl Transport for Transport{
            async fn rpc(
                &self,
                peer_id: &NodeId,
                request: Request<Bytes>,
            ) -> Result<Response<Bytes>, TransportError>;

            async fn push(
                &self,
                peer_id: &NodeId,
                request: Request<Bytes>,
            ) -> Result<(), TransportError>;

            fn peers(&self) -> Vec<NodeId>;
        }
    }

    mock! {
        pub Chunkable {}

        impl Chunkable for Chunkable{
            fn chunks_to_download(&self) -> Box<dyn Iterator<Item = ChunkId>>;
            fn add_chunk(&mut self, artifact_chunk: ArtifactChunk) -> Result<Artifact, ArtifactErrorCode>;
        }
    }

    /// Verify that state sync gets aborted if state sync should be cancelled.
    #[test]
    fn test_should_cancel() {
        with_test_replica_logger(|log| {
            let mut s = MockStateSync::default();
            s.expect_should_cancel()
                .return_once(|_| false)
                .return_const(true);
            let mut t = MockTransport::default();
            t.expect_rpc().returning(|_, _| {
                Ok(Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .body(Bytes::new())
                    .unwrap())
            });
            let mut c = MockChunkable::default();
            c.expect_chunks_to_download()
                .returning(|| Box::new(std::iter::once(ChunkId::from(1))));

            let rt = Runtime::new().unwrap();
            let ongoing = start_ongoing_state_sync(
                log,
                rt.handle(),
                OngoingStateSyncMetrics::new(&MetricsRegistry::default()),
                Arc::new(Mutex::new(Box::new(c))),
                StateSyncArtifactId {
                    height: Height::from(1),
                    hash: CryptoHashOfState::new(CryptoHash(vec![])),
                },
                Arc::new(s),
                Arc::new(t),
            );

            rt.block_on(async move {
                ongoing.sender.send(NODE_1).await.unwrap();
                ongoing.jh.await.unwrap();
            });
        });
    }

    /// Verify that peer gets removed if chunk verification fails.
    #[test]
    fn test_chunk_verification_failed() {
        with_test_replica_logger(|log| {
            let mut s = MockStateSync::default();
            s.expect_should_cancel().return_const(false);
            let mut t = MockTransport::default();
            t.expect_rpc().returning(|_, _| {
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .extension(NODE_2)
                    .body(Bytes::new())
                    .unwrap())
            });
            let mut c = MockChunkable::default();
            c.expect_chunks_to_download()
                .returning(|| Box::new(std::iter::once(ChunkId::from(1))));
            c.expect_add_chunk()
                .return_const(Err(ArtifactErrorCode::ChunkVerificationFailed));

            let rt = Runtime::new().unwrap();
            let ongoing = start_ongoing_state_sync(
                log,
                rt.handle(),
                OngoingStateSyncMetrics::new(&MetricsRegistry::default()),
                Arc::new(Mutex::new(Box::new(c))),
                StateSyncArtifactId {
                    height: Height::from(1),
                    hash: CryptoHashOfState::new(CryptoHash(vec![])),
                },
                Arc::new(s),
                Arc::new(t),
            );

            rt.block_on(async move {
                ongoing.sender.send(NODE_1).await.unwrap();
                // State sync should exit because NODE_1 got removed.
                ongoing.jh.await.unwrap();
            });
        });
    }

    /// Add peer multiple times to ongoing sync. Debug assertion in event loop verifies
    /// that download budget is correct.
    #[test]
    fn test_add_peer_multiple_times_to_ongoing_state_sync() {
        with_test_replica_logger(|log| {
            let should_cancel = Arc::new(AtomicBool::default());
            let should_cancel_c = should_cancel.clone();
            let mut s = MockStateSync::default();
            s.expect_should_cancel()
                .returning(move |_| should_cancel_c.load(Ordering::SeqCst));
            let mut t = MockTransport::default();
            t.expect_rpc().returning(|_, _| {
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .extension(NODE_2)
                    .body(Bytes::new())
                    .unwrap())
            });
            let mut c = MockChunkable::default();
            // Endless iterator
            c.expect_chunks_to_download()
                .returning(|| Box::new(std::iter::once(ChunkId::from(1))));
            c.expect_add_chunk()
                .return_const(Err(ArtifactErrorCode::ChunksMoreNeeded));

            let rt = Runtime::new().unwrap();
            let ongoing = start_ongoing_state_sync(
                log,
                rt.handle(),
                OngoingStateSyncMetrics::new(&MetricsRegistry::default()),
                Arc::new(Mutex::new(Box::new(c))),
                StateSyncArtifactId {
                    height: Height::from(1),
                    hash: CryptoHashOfState::new(CryptoHash(vec![])),
                },
                Arc::new(s),
                Arc::new(t),
            );

            rt.block_on(async move {
                ongoing.sender.send(NODE_1).await.unwrap();
                ongoing.sender.send(NODE_1).await.unwrap();
                should_cancel.store(true, Ordering::SeqCst);
                ongoing.sender.send(NODE_1).await.unwrap();
                // State sync should exit because NODE_1 got removed.
                ongoing.jh.await.unwrap();
            });
        });
    }
}
