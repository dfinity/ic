//! State sync manager.
//!
//! Implements the necessary network logic for state sync:
//!    - Periodic broadcasting of the latest state advert to all peers.
//!    - Checking advertisments for peers against local state and
//!      starting state sync if necessary.
//!    - Adding peers to ongoing state sync if they advertise the same state.
//!
//! API:
//!    - `/chunk` route takes `pb::GossipChunkRequest` and responds with `pb::ArtifactChunk`
//!      if the chunk was found. It responds with NOT_FOUND if the chunk is not available.
//!    - `/advert` accepts `pb::GossipAdvert` and returns nothing.
//!
//! GUARANTEES:
//!    - There is only ever one active state sync.
//!    - State sync is started for the advert that returned FETCH.
//!    - State advert is periodically broadcasted and there is no delivery guarantee.
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{routing::any, Router};
use ic_interfaces::state_sync_client::StateSyncClient;
use ic_logger::{info, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_quic_transport::Transport;
use ic_types::{artifact::StateSyncArtifactId, NodeId};
use metrics::{StateSyncManagerHandlerMetrics, StateSyncManagerMetrics};
use ongoing::OngoingStateSyncHandle;
use routes::{
    build_advert_handler_request, state_sync_advert_handler, state_sync_chunk_handler,
    StateSyncAdvertHandler, StateSyncChunkHandler, STATE_SYNC_ADVERT_PATH, STATE_SYNC_CHUNK_PATH,
};
use tokio::{runtime::Handle, select, task::JoinHandle};

use crate::ongoing::start_ongoing_state_sync;

mod metrics;
mod ongoing;
mod routes;

pub fn build_axum_router(
    state_sync: Arc<dyn StateSyncClient>,
    log: ReplicaLogger,
    metrics_registry: &MetricsRegistry,
) -> (
    Router,
    tokio::sync::mpsc::Receiver<(StateSyncArtifactId, NodeId)>,
) {
    let metrics = StateSyncManagerHandlerMetrics::new(metrics_registry);
    let shared_chunk_state = Arc::new(StateSyncChunkHandler::new(
        log.clone(),
        state_sync,
        metrics.clone(),
    ));

    let (tx, rx) = tokio::sync::mpsc::channel(20);
    let advert_handler_state = Arc::new(StateSyncAdvertHandler::new(log, tx, metrics));

    let app = Router::new()
        .route(STATE_SYNC_CHUNK_PATH, any(state_sync_chunk_handler))
        .with_state(shared_chunk_state)
        .route(
            STATE_SYNC_ADVERT_PATH,
            axum::routing::any(state_sync_advert_handler),
        )
        .with_state(advert_handler_state);

    (app, rx)
}

pub fn start_state_sync_manager(
    log: ReplicaLogger,
    metrics: &MetricsRegistry,
    rt: &Handle,
    transport: Arc<dyn Transport>,
    state_sync: Arc<dyn StateSyncClient>,
    advert_receiver: tokio::sync::mpsc::Receiver<(StateSyncArtifactId, NodeId)>,
) -> JoinHandle<()> {
    let state_sync_manager_metrics = StateSyncManagerMetrics::new(metrics);
    let manager = StateSyncManager {
        log,
        rt: rt.clone(),
        metrics: state_sync_manager_metrics,
        transport,
        state_sync,
        advert_receiver,
        ongoing_state_sync: None,
    };
    rt.spawn(manager.run())
}

struct StateSyncManager {
    log: ReplicaLogger,
    rt: Handle,
    metrics: StateSyncManagerMetrics,
    transport: Arc<dyn Transport>,
    state_sync: Arc<dyn StateSyncClient>,
    advert_receiver: tokio::sync::mpsc::Receiver<(StateSyncArtifactId, NodeId)>,
    ongoing_state_sync: Option<OngoingStateSyncHandle>,
}

impl StateSyncManager {
    async fn run(mut self) {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            select! {
                _ = interval.tick() => {
                    self.handle_advert_tick();
                },
                Some((advert, peer)) = self.advert_receiver.recv() =>{
                    self.handle_advert(advert, peer).await;
                }
            }
        }
    }

    async fn handle_advert(&mut self, artifact_id: StateSyncArtifactId, peer: NodeId) {
        // Remove ongoing state sync if finished or try to add peer if ongoing.
        if let Some(ongoing) = &mut self.ongoing_state_sync {
            // Try to add peer to state sync peer set.
            let _ = ongoing.sender.send(peer).await;
            if ongoing.jh.is_finished() {
                self.ongoing_state_sync = None;
            }
        }

        // `start_state_sync` should not be called if we have ongoing state sync!
        if self.ongoing_state_sync.is_some() {
            return;
        }

        if let Some(chunkable) = self.state_sync.start_state_sync(&artifact_id) {
            info!(
                self.log,
                "Starting state sync for height {}", artifact_id.height
            );
            self.metrics.state_syncs.inc();

            // This will spawn a task that downloads the chunk according to the tracker.
            // If it is done/timeout it will finish and drop the tracker. Until the state is dropped
            // the priority function guarantees to never return FETCH again.
            let ongoing = start_ongoing_state_sync(
                self.log.clone(),
                &self.rt,
                self.metrics.ongoing_state_sync_metrics.clone(),
                Arc::new(Mutex::new(chunkable)),
                artifact_id,
                self.state_sync.clone(),
                self.transport.clone(),
            );
            // Add peer that initiated this state sync to ongoing state sync.
            ongoing
                .sender
                .send(peer)
                .await
                .expect("Receive side is not dropped");
            self.ongoing_state_sync = Some(ongoing);
        }
    }

    fn handle_advert_tick(&mut self) {
        if let Some(state_id) = self.state_sync.latest_state() {
            self.transport
                .broadcast(build_advert_handler_request(state_id));
        }
    }
}
