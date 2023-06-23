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
                    info!(self.log, "State sync timed out.");
                    break;
                }
                Some(new_peer) = self.new_peers_rx.recv() => {
                    if self.peers.insert(new_peer) {
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
            // Conditions on when to exit (in addition to timeout)
            if self.state_sync_finished
                || self.peers.is_empty()
                || self.state_sync.should_cancel(&self.artifact_id)
            {
                break;
            }
        }

        self.downloading_chunks.shutdown().await;
    }

    async fn handle_downloaded_chunk_result(
        &mut self,
        res: Result<Option<CompletedStateSync>, DownloadChunkError>,
    ) {
        self.metrics.active_downloads.dec();
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
                    self.metrics.active_downloads.inc();
                    // Select random peer.
                    let peers: Vec<_> = self.peers.iter().copied().collect();
                    if peers.is_empty() {
                        break;
                    }
                    // Spawn chunk download to random peer.
                    let peer = peers.get(small_rng.gen_range(0..peers.len())).unwrap();
                    self.downloading_chunks.spawn_on(
                        chunk,
                        Self::download_chunk_task(
                            *peer,
                            self.transport.clone(),
                            self.tracker.clone(),
                            self.artifact_id.clone(),
                            chunk,
                        ),
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
    ) -> Result<Option<CompletedStateSync>, DownloadChunkError> {
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
            Err(e) => Err(DownloadChunkError::RequestError {
                peer_id,
                chunk_id,
                err: e.to_string(),
            }),
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

struct CompletedStateSync {
    msg: StateSyncMessage,
    peer_id: NodeId,
}

#[derive(Debug, Clone)]
pub(crate) enum DownloadChunkError {
    /// Request was processed but requested content was not available.
    /// This error is permanent.
    NoContent { peer_id: NodeId },
    /// Request was not processed because endpoint is overloaded.
    /// This error is transient.
    // TODO: Add peer id for collecting metrics
    Overloaded,
    /// An unexpected error occurred during the request. Requests to well-behaving peers
    /// do not return a RequestError.
    RequestError {
        peer_id: NodeId,
        chunk_id: ChunkId,
        err: String,
    },
}
