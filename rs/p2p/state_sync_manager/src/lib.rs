//! State sync manager.
//!
//! Implements the necessary network logic for state sync:
//!    - Periodic broadcasting of the latest state advert to all peers.
//!    - Checking advertisements for peers against local state and
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
use futures::future::join_all;
use ic_base_types::NodeId;
use ic_interfaces::p2p::state_sync::{StateSyncArtifactId, StateSyncClient};
use ic_logger::{info, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_quic_transport::{Shutdown, Transport};
use metrics::{StateSyncManagerHandlerMetrics, StateSyncManagerMetrics};
use ongoing::{start_ongoing_state_sync, OngoingStateSyncHandle};
use routes::{
    build_advert_handler_request, state_sync_advert_handler, state_sync_chunk_handler,
    StateSyncAdvertHandler, StateSyncChunkHandler, STATE_SYNC_ADVERT_PATH, STATE_SYNC_CHUNK_PATH,
};
use tokio::{runtime::Handle, select, task::JoinSet, time::MissedTickBehavior};
use tokio_util::sync::CancellationToken;

mod metrics;
mod ongoing;
mod routes;

// Interval with which state is advertised to peers.
const ADVERT_BROADCAST_INTERVAL: Duration = Duration::from_secs(5);
// Timeout that is applies to advert broadcasts. This should be lower than the interval itself to
// avoid unnecessary build up of pending adverts in case of timeouts.
const ADVERT_BROADCAST_TIMEOUT: Duration =
    ADVERT_BROADCAST_INTERVAL.saturating_sub(Duration::from_secs(2));

pub fn build_axum_router<T: 'static>(
    state_sync: Arc<dyn StateSyncClient<Message = T>>,
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
    let advert_handler_state = Arc::new(StateSyncAdvertHandler::new(log, tx));

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

pub fn start_state_sync_manager<T: Send + 'static>(
    log: &ReplicaLogger,
    metrics: &MetricsRegistry,
    rt: &Handle,
    transport: Arc<dyn Transport>,
    state_sync: Arc<dyn StateSyncClient<Message = T>>,
    advert_receiver: tokio::sync::mpsc::Receiver<(StateSyncArtifactId, NodeId)>,
) -> Shutdown {
    let state_sync_manager_metrics = StateSyncManagerMetrics::new(metrics);
    let manager = StateSyncManager {
        log: log.clone(),
        rt: rt.clone(),
        metrics: state_sync_manager_metrics,
        transport,
        state_sync,
        advert_receiver,
        ongoing_state_sync: None,
    };
    Shutdown::spawn_on_with_cancellation(
        |cancellation: CancellationToken| manager.run(cancellation),
        rt,
    )
}

struct StateSyncManager<T> {
    log: ReplicaLogger,
    rt: Handle,
    metrics: StateSyncManagerMetrics,
    transport: Arc<dyn Transport>,
    state_sync: Arc<dyn StateSyncClient<Message = T>>,
    advert_receiver: tokio::sync::mpsc::Receiver<(StateSyncArtifactId, NodeId)>,
    ongoing_state_sync: Option<OngoingStateSyncHandle>,
}

impl<T: 'static + Send> StateSyncManager<T> {
    async fn run(mut self, cancellation: CancellationToken) {
        let mut interval = tokio::time::interval(ADVERT_BROADCAST_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut advertise_task = JoinSet::new();
        loop {
            select! {
                () = cancellation.cancelled() => {
                    break;
                }
                // Make sure we only have one active advertise task.
                _ = interval.tick(), if advertise_task.is_empty() => {
                    advertise_task.spawn_on(
                        Self::send_state_adverts(
                            self.rt.clone(),
                            self.state_sync.clone(),
                            self.transport.clone(),
                            self.metrics.clone(),
                            cancellation.clone(),
                        ),
                        &self.rt
                    );
                },
                Some((advert, peer_id)) = self.advert_receiver.recv() =>{
                    self.handle_advert(advert, peer_id).await;
                }
                Some(_) = advertise_task.join_next() => {}
            }
        }
        while advertise_task.join_next().await.is_some() {}
        if let Some(ongoing_state_sync) = self.ongoing_state_sync.take() {
            ongoing_state_sync.shutdown.shutdown().await;
        }
    }

    async fn handle_advert(&mut self, artifact_id: StateSyncArtifactId, peer_id: NodeId) {
        self.metrics.adverts_received_total.inc();
        // Remove ongoing state sync if finished or try to add peer if ongoing.
        if let Some(ongoing) = &mut self.ongoing_state_sync {
            if ongoing.artifact_id == artifact_id {
                // `try_send` is used beacuse the ongoing state sync can be blocked. This can, for example happen because of
                // file system operations. In that case we don't want to block the main event loop here. It is also fine
                // to drop adverts since peers will readvertise anyway.
                let _ = ongoing.sender.try_send(peer_id);
            }
            if ongoing.shutdown.completed() {
                info!(self.log, "Cleaning up state sync {}", artifact_id.height);
                self.ongoing_state_sync = None;
            } else {
                if self.state_sync.cancel_if_running(&ongoing.artifact_id) {
                    ongoing.shutdown.cancel();
                }
                return;
            }
        }
        // `maybe_start_state_sync` should not be called if we have ongoing state sync!
        debug_assert!(self.ongoing_state_sync.is_none());
        if let Some(chunkable) = self.state_sync.maybe_start_state_sync(&artifact_id) {
            info!(
                self.log,
                "Starting state sync for height {}", artifact_id.height
            );
            self.metrics.state_syncs_total.inc();

            // This spawns an event loop that downloads chunks for the specified Id.
            // When the state sync is done or cancelled it will drop the Chunkable object.
            // Until the Chunkable object is dropped 'maybe_start_state_sync' will always return None.
            let ongoing = start_ongoing_state_sync(
                self.log.clone(),
                &self.rt,
                self.metrics.ongoing_state_sync_metrics.clone(),
                Arc::new(Mutex::new(chunkable)),
                artifact_id.clone(),
                self.transport.clone(),
            );
            // Add peer that initiated this state sync to ongoing state sync.
            ongoing
                .sender
                .send(peer_id)
                .await
                .expect("Receive side is not dropped");
            self.ongoing_state_sync = Some(ongoing);
        }
    }

    // The future should be cancelled and awaited instead of aborted in order to guarantee a graceful shutdown.
    async fn send_state_adverts(
        rt: Handle,
        state_sync: Arc<dyn StateSyncClient<Message = T>>,
        transport: Arc<dyn Transport>,
        metrics: StateSyncManagerMetrics,
        cancellation: CancellationToken,
    ) {
        let available_states = match rt
            .spawn_blocking(move || state_sync.available_states())
            .await
        {
            Ok(states) => states,
            Err(_) => return,
        };

        metrics.lowest_state_broadcasted.set(
            available_states
                .iter()
                .map(|h| h.height.get())
                .min()
                .unwrap_or_default() as i64,
        );
        metrics.highest_state_broadcasted.set(
            available_states
                .iter()
                .map(|h| h.height.get())
                .max()
                .unwrap_or_default() as i64,
        );

        let mut futures = vec![];
        for state_id in available_states {
            // Unreliable broadcast of adverts to all current peers.
            for (peer_id, _) in transport.peers() {
                let request = build_advert_handler_request(state_id.clone());
                let transport_c = transport.clone();
                let cancellation_c = cancellation.clone();
                futures.push(async move {
                    select! {
                        _ = tokio::time::timeout(
                            ADVERT_BROADCAST_TIMEOUT,
                            transport_c.rpc(&peer_id, request)) => {}
                        () = cancellation_c.cancelled() => {}
                    }
                });
            }
        }
        let _ = join_all(futures).await;
    }
}

#[cfg(test)]
mod tests {
    use axum::{http::StatusCode, response::Response};
    use bytes::{Bytes, BytesMut};
    use ic_interfaces::p2p::state_sync::ChunkId;
    use ic_metrics::MetricsRegistry;
    use ic_p2p_test_utils::mocks::{MockChunkable, MockStateSync, MockTransport};
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_types::{crypto::CryptoHash, Height};
    use ic_types_test_utils::ids::{NODE_1, NODE_2};
    use mockall::Sequence;
    use prost::Message;
    use tokio::{runtime::Runtime, sync::Notify};

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

    /// Don't add peers that advertise a state that differs from the current sync.
    #[test]
    fn test_reject_peer_with_different_state() {
        with_test_replica_logger(|log| {
            let finished = Arc::new(Notify::new());
            let finished_c = finished.clone();
            let mut s = MockStateSync::<TestMessage>::default();
            let mut seq = Sequence::new();
            s.expect_cancel_if_running().returning(move |_| false);
            s.expect_available_states().return_const(vec![]);
            let mut t = MockTransport::default();
            t.expect_rpc().times(50).returning(|p, _| {
                if p == &NODE_2 {
                    panic!("NODE 2 should not be added to the state sync")
                }
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .extension(NODE_1)
                    .body(compress_empty_bytes())
                    .unwrap())
            });
            let mut c = MockChunkable::<TestMessage>::default();
            // Endless iterator
            c.expect_chunks_to_download()
                .once()
                .returning(|| Box::new((0..50).map(ChunkId::from)));
            c.expect_chunks_to_download()
                .returning(|| Box::new(std::iter::empty()));

            c.expect_add_chunk()
                .times(49)
                .return_const(Ok(()))
                .in_sequence(&mut seq);
            c.expect_add_chunk()
                .once()
                .return_once(move |_, _| {
                    finished_c.notify_waiters();
                    Ok(())
                })
                .in_sequence(&mut seq);
            s.expect_maybe_start_state_sync()
                .once()
                .return_once(|_| Some(Box::new(c)));

            let rt = Runtime::new().unwrap();
            let old_id = StateSyncArtifactId {
                height: Height::from(0),
                hash: CryptoHash(vec![]),
            };
            let id = StateSyncArtifactId {
                height: Height::from(1),
                hash: CryptoHash(vec![]),
            };

            let (handler_tx, handler_rx) = tokio::sync::mpsc::channel(100);
            start_state_sync_manager(
                &log,
                &MetricsRegistry::default(),
                rt.handle(),
                Arc::new(t) as Arc<_>,
                Arc::new(s) as Arc<_>,
                handler_rx,
            );
            rt.block_on(async move {
                handler_tx.send((id, NODE_1)).await.unwrap();
                handler_tx.send((old_id, NODE_2)).await.unwrap();
                finished.notified().await;
            });
        });
    }
}
