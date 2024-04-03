#![allow(clippy::disallowed_methods)]

use std::{
    collections::{hash_map::Entry, HashMap},
    panic,
    sync::{Arc, RwLock},
    time::Duration,
};

use axum::http::Request;
use backoff::{backoff::Backoff, ExponentialBackoffBuilder};
use bytes::Bytes;
use ic_base_types::NodeId;
use ic_interfaces::p2p::{
    artifact_manager::ArtifactProcessorEvent,
    consensus::{ArtifactWithOpt, ValidatedPoolReader},
};
use ic_logger::{error, warn, ReplicaLogger};
use ic_protobuf::{p2p::v1 as pb, proxy::ProtoProxy};
use ic_quic_transport::{ConnId, Transport};
use ic_types::artifact::{Advert, ArtifactKind};
use tokio::{
    runtime::Handle,
    select,
    sync::mpsc::Receiver,
    task::{JoinError, JoinHandle, JoinSet},
    time,
};
use tokio_util::sync::CancellationToken;

use crate::{
    metrics::ConsensusManagerMetrics, uri_prefix, CommitId, SlotNumber, SlotUpdate, Update,
};

/// The size threshold for an artifact to be pushed. Artifacts smaller than this constant
/// in size are pushed.
const ARTIFACT_PUSH_THRESHOLD_BYTES: usize = 1024; // 1KB

const MIN_BACKOFF_INTERVAL: Duration = Duration::from_millis(250);
const MAX_BACKOFF_INTERVAL: Duration = Duration::from_secs(60);
const BACKOFF_MULTIPLIER: f64 = 2.0;

// Used to log warnings if the slot table grows beyond the threshold.
const SLOT_TABLE_THRESHOLD: u64 = 30_000;

// Convenience function to check for join errors and panic on them.
fn panic_on_join_err<T>(result: Result<T, JoinError>) -> T {
    match result {
        Ok(value) => value,
        Err(err) => {
            if err.is_panic() {
                panic::resume_unwind(err.into_panic());
            } else {
                panic!("Join error: {:?}", err);
            }
        }
    }
}

pub(crate) struct ConsensusManagerSender<Artifact: ArtifactKind> {
    log: ReplicaLogger,
    metrics: ConsensusManagerMetrics,
    rt_handle: Handle,
    pool_reader: Arc<RwLock<dyn ValidatedPoolReader<Artifact> + Send + Sync>>,
    transport: Arc<dyn Transport>,
    adverts_to_send: Receiver<ArtifactProcessorEvent<Artifact>>,
    slot_manager: AvailableSlotSet,
    current_commit_id: CommitId,
    active_adverts: HashMap<Artifact::Id, (CancellationToken, SlotNumber)>,
    join_set: JoinSet<()>,
    cancellation_token: CancellationToken,
}

impl<Artifact: ArtifactKind> ConsensusManagerSender<Artifact> {
    pub(crate) fn run(
        log: ReplicaLogger,
        metrics: ConsensusManagerMetrics,
        rt_handle: Handle,
        pool_reader: Arc<RwLock<dyn ValidatedPoolReader<Artifact> + Send + Sync>>,
        transport: Arc<dyn Transport>,
        adverts_to_send: Receiver<ArtifactProcessorEvent<Artifact>>,
        cancellation_token: CancellationToken,
    ) -> JoinHandle<()> {
        let slot_manager =
            AvailableSlotSet::new(log.clone(), metrics.clone(), Artifact::TAG.into());

        let manager = Self {
            log,
            metrics,
            rt_handle: rt_handle.clone(),
            pool_reader,
            transport,
            adverts_to_send,
            slot_manager,
            current_commit_id: CommitId::from(0),
            active_adverts: HashMap::new(),
            join_set: JoinSet::new(),
            cancellation_token,
        };

        rt_handle.spawn(manager.start_event_loop())
    }

    async fn start_event_loop(mut self) {
        // Check if we have artifacts in the validated pool on startup.
        // This can for example happen if the node restarts.
        let artifacts_in_validated_pool: Vec<Artifact::Message> = {
            let pool_read_lock = self.pool_reader.read().unwrap();
            pool_read_lock
                .get_all_validated_by_filter(&Artifact::Filter::default())
                .collect()
        };

        for artifact in artifacts_in_validated_pool {
            let advert = Artifact::message_to_advert(&artifact);
            self.handle_send_advert(ArtifactWithOpt {
                advert,
                is_latency_sensitive: false,
            });
        }

        loop {
            select! {
                _ = self.cancellation_token.cancelled() => {
                    error!(
                        self.log,
                        "Sender event loop for the P2P client `{:?}` terminated. No more adverts will be sent for this client.",
                        uri_prefix::<Artifact>()
                    );
                    break;
                }
                Some(advert) = self.adverts_to_send.recv() => {
                    match advert {
                        ArtifactProcessorEvent::Artifact(new_artifact) => self.handle_send_advert(new_artifact),
                        ArtifactProcessorEvent::Purge(id) => self.handle_purge_advert(&id),
                    }

                    self.current_commit_id.inc_assign();
                }

                Some(result) = self.join_set.join_next() => {
                    panic_on_join_err(result);
                }
            }

            #[cfg(debug_assertions)]
            {
                if self.join_set.len() < self.active_adverts.len() {
                    // This invariant can be violated if the root cancellation token is cancelled.
                    // It can be violated because the active_adverts HashMap is only cleared
                    // when purging artifacts, and not when the tasks join due to a cancellation
                    // not triggered by the manager.
                    let is_not_cancelled =
                        time::timeout(Duration::from_secs(5), self.cancellation_token.cancelled())
                            .await
                            .is_err();

                    if is_not_cancelled {
                        panic!(
                            "Invariant violated: join_set.len() {:?} >= active_adverts.len() {:?}.",
                            self.join_set.len(),
                            self.active_adverts.len()
                        );
                    }
                }
            }
        }

        while let Some(result) = self.join_set.join_next().await {
            panic_on_join_err(result);
        }
    }

    fn handle_purge_advert(&mut self, id: &Artifact::Id) {
        if let Some((cancellation_token, free_slot)) = self.active_adverts.remove(id) {
            self.metrics.send_view_consensus_purge_active_total.inc();
            cancellation_token.cancel();
            self.slot_manager.push(free_slot);
        } else {
            self.metrics.send_view_consensus_dup_purge_total.inc();
        }
    }

    fn handle_send_advert(&mut self, new_artifact: ArtifactWithOpt<Artifact>) {
        let entry = self.active_adverts.entry(new_artifact.advert.id.clone());

        if let Entry::Vacant(entry) = entry {
            self.metrics.send_view_consensus_new_adverts_total.inc();

            let slot = self.slot_manager.pop();

            let child_token = self.cancellation_token.child_token();
            let child_token_clone = child_token.clone();

            let send_future = Self::send_advert_to_all_peers(
                self.rt_handle.clone(),
                self.log.clone(),
                self.metrics.clone(),
                self.transport.clone(),
                self.current_commit_id,
                slot,
                new_artifact,
                self.pool_reader.clone(),
                child_token_clone,
            );

            self.join_set.spawn_on(send_future, &self.rt_handle);
            entry.insert((child_token, slot));
        } else {
            self.metrics.send_view_consensus_dup_adverts_total.inc();
        }
    }

    /// Sends an advert to all peers.
    async fn send_advert_to_all_peers(
        rt_handle: Handle,
        log: ReplicaLogger,
        metrics: ConsensusManagerMetrics,
        transport: Arc<dyn Transport>,
        commit_id: CommitId,
        slot_number: SlotNumber,
        ArtifactWithOpt {
            advert:
                Advert {
                    id,
                    attribute,
                    size,
                    ..
                },
            is_latency_sensitive,
        }: ArtifactWithOpt<Artifact>,
        pool_reader: Arc<RwLock<dyn ValidatedPoolReader<Artifact> + Send + Sync>>,
        cancellation_token: CancellationToken,
    ) {
        // Try to push artifact if size below threshold or it is latency sensitive.
        let artifact = if size < ARTIFACT_PUSH_THRESHOLD_BYTES || is_latency_sensitive {
            let id = id.clone();
            let artifact = tokio::task::spawn_blocking(move || {
                pool_reader.read().unwrap().get_validated_by_identifier(&id)
            })
            .await;

            match artifact {
                Ok(Some(artifact)) => Some(artifact),
                _ => {
                    warn!(log, "Attempted to push Artifact, but the Artifact was not found in the pool. Sending an advert instead.");
                    None
                }
            }
        } else {
            None
        };

        let advert_update: SlotUpdate<Artifact> = SlotUpdate {
            slot_number,
            commit_id,
            update: match artifact {
                Some(artifact) => Update::Artifact(artifact),
                None => Update::Advert((id, attribute)),
            },
        };

        let body = Bytes::from(pb::SlotUpdate::proxy_encode(advert_update));

        let mut in_progress_transmissions = JoinSet::new();
        // Stores the connection ID and the [`CancellationToken`] of the last successful transmission task to a peer.
        let mut initiated_transmissions: HashMap<NodeId, (ConnId, CancellationToken)> =
            HashMap::new();
        let mut periodic_check_interval = time::interval(Duration::from_secs(5));

        loop {
            select! {
                _ = periodic_check_interval.tick() => {
                    // check for new peers/connection IDs
                    // spawn task for peers with higher conn id or not in completed transmissions.
                    // add task to join map
                    for (peer, connection_id) in transport.peers() {
                        let is_initiated = initiated_transmissions.get(&peer).is_some_and(|(id, token)| {
                            if *id == connection_id {
                                true
                            } else {
                                token.cancel();
                                metrics.send_view_resend_reconnect_total.inc();
                                false
                            }
                        });


                        if !is_initiated {
                            let child_token = cancellation_token.child_token();
                            let child_token_clone = child_token.clone();
                            metrics.send_view_send_to_peer_total.inc();

                            let transport = transport.clone();
                            let body = body.clone();

                            let send_future = async move {
                                select! {
                                    _ = send_advert_to_peer(transport, body, peer, uri_prefix::<Artifact>()) => {},
                                    _ = child_token.cancelled() => {},
                                }
                            };

                            in_progress_transmissions.spawn_on(send_future, &rt_handle);
                            initiated_transmissions.insert(peer, (connection_id, child_token_clone));
                        }
                    }
                }
                Some(result) = in_progress_transmissions.join_next() => {
                    panic_on_join_err(result);
                    metrics.send_view_send_to_peer_delivered_total.inc();
                }
                _ = cancellation_token.cancelled() => {
                    while let Some(result) = in_progress_transmissions.join_next().await {
                        metrics.send_view_send_to_peer_cancelled_total.inc();
                        panic_on_join_err(result);
                    }
                    break;
                }
            }
        }
    }
}

/// Sends a serialized advert or artifact message to a peer.
/// If the peer is not reachable, it will retry with an exponential backoff.
async fn send_advert_to_peer(
    transport: Arc<dyn Transport>,
    message: Bytes,
    peer: NodeId,
    uri_prefix: String,
) {
    let mut backoff = ExponentialBackoffBuilder::new()
        .with_initial_interval(MIN_BACKOFF_INTERVAL)
        .with_max_interval(MAX_BACKOFF_INTERVAL)
        .with_multiplier(BACKOFF_MULTIPLIER)
        .with_max_elapsed_time(None)
        .build();

    loop {
        let request = Request::builder()
            .uri(format!("/{}/update", uri_prefix))
            .body(message.clone())
            .expect("Building from typed values");

        if let Ok(()) = transport.push(&peer, request).await {
            return;
        }

        let backoff_duration = backoff.next_backoff().unwrap_or(MAX_BACKOFF_INTERVAL);
        time::sleep(backoff_duration).await;
    }
}

struct AvailableSlotSet {
    next_free_slot: SlotNumber,
    free_slots: Vec<SlotNumber>,
    log: ReplicaLogger,
    metrics: ConsensusManagerMetrics,
    service_name: &'static str,
}

impl AvailableSlotSet {
    fn new(
        log: ReplicaLogger,
        metrics: ConsensusManagerMetrics,
        service_name: &'static str,
    ) -> Self {
        Self {
            next_free_slot: 0.into(),
            free_slots: vec![],
            log,
            metrics,
            service_name,
        }
    }

    fn push(&mut self, slot: SlotNumber) {
        self.free_slots.push(slot);
        self.metrics.slot_set_in_use_slots.dec();
    }

    /// Returns available slot.
    fn pop(&mut self) -> SlotNumber {
        self.metrics.slot_set_in_use_slots.inc();
        match self.free_slots.pop() {
            Some(slot) => slot,
            None => {
                if self.next_free_slot.get() > SLOT_TABLE_THRESHOLD {
                    warn!(
                        self.log,
                        "Slot table threshold exceeded for service {}. Slots in use = {}.",
                        self.service_name,
                        self.next_free_slot
                    );
                }

                let new_slot = self.next_free_slot;
                self.next_free_slot.inc_assign();

                self.metrics.slot_set_allocated_slots_total.inc();

                new_slot
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_p2p_test_utils::{
        consensus::U64Artifact,
        mocks::{MockTransport, MockValidatedPoolReader},
    };
    use ic_protobuf::proxy::ProtoProxy;
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_types_test_utils::ids::{NODE_1, NODE_2};
    use mockall::Sequence;
    use tokio::{runtime::Handle, time::timeout};

    use super::*;

    /// Verify that initial validated pool is sent to peers.
    #[tokio::test]
    async fn initial_validated_pool_is_sent_to_all_peers() {
        let (push_tx, mut push_rx) = tokio::sync::mpsc::unbounded_channel();
        let cancel_token = CancellationToken::new();
        let cancel_token_clone = cancel_token.clone();

        let consensus_sender_join_handle = with_test_replica_logger(move |log| {
            let mut mock_reader: MockValidatedPoolReader<U64Artifact> =
                MockValidatedPoolReader::new();
            let mut mock_transport = MockTransport::new();
            mock_transport
                .expect_peers()
                .return_const(vec![(NODE_1, ConnId::from(1))]);
            mock_transport
                .expect_push()
                .times(1)
                .returning(move |n, _| {
                    push_tx.send(*n).unwrap();
                    Ok(())
                });
            // Initial validated pool contains one element.
            mock_reader
                .expect_get_all_validated_by_filter()
                .returning(|_| Box::new(std::iter::once(1)));
            mock_reader
                .expect_get_validated_by_identifier()
                .returning(|id| Some(*id));

            let (_tx, rx) = tokio::sync::mpsc::channel(100);
            ConsensusManagerSender::run(
                log,
                ConsensusManagerMetrics::new::<U64Artifact>(&MetricsRegistry::default()),
                Handle::current(),
                Arc::new(RwLock::new(mock_reader)),
                Arc::new(mock_transport),
                rx,
                cancel_token_clone,
            )
        });

        assert_eq!(push_rx.recv().await.unwrap(), NODE_1);

        cancel_token.cancel();

        timeout(Duration::from_secs(5), consensus_sender_join_handle)
            .await
            .expect("ConsensusManagerSender did not terminate in time.")
            .unwrap()
    }

    /// Verify that advert is sent to multiple peers.
    #[tokio::test]
    async fn send_advert_to_all_peers() {
        let (push_tx, mut push_rx) = tokio::sync::mpsc::unbounded_channel();
        let cancel_token = CancellationToken::new();
        let cancel_token_clone = cancel_token.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(100);

        let consensus_sender_join_handle = with_test_replica_logger(|log| {
            let mut mock_reader: MockValidatedPoolReader<U64Artifact> =
                MockValidatedPoolReader::new();
            let mut mock_transport = MockTransport::new();
            mock_transport
                .expect_peers()
                .return_const(vec![(NODE_1, ConnId::from(1)), (NODE_2, ConnId::from(2))]);
            mock_transport
                .expect_push()
                .times(2)
                .returning(move |n, _| {
                    push_tx.send(*n).unwrap();
                    Ok(())
                });
            mock_reader
                .expect_get_all_validated_by_filter()
                .returning(|_| Box::new(std::iter::empty()));
            mock_reader
                .expect_get_validated_by_identifier()
                .returning(|id| Some(*id));

            ConsensusManagerSender::run(
                log,
                ConsensusManagerMetrics::new::<U64Artifact>(&MetricsRegistry::default()),
                Handle::current(),
                Arc::new(RwLock::new(mock_reader)),
                Arc::new(mock_transport),
                rx,
                cancel_token_clone,
            )
        });

        tx.send(ArtifactProcessorEvent::Artifact(ArtifactWithOpt {
            advert: U64Artifact::message_to_advert(&1),
            is_latency_sensitive: false,
        }))
        .await
        .unwrap();

        let first_push_node = push_rx.recv().await.unwrap();
        let second_push_node: phantom_newtype::Id<
            ic_base_types::NodeTag,
            ic_base_types::PrincipalId,
        > = push_rx.recv().await.unwrap();
        assert!(
            first_push_node == NODE_1 && second_push_node == NODE_2
                || first_push_node == NODE_2 && second_push_node == NODE_1
        );

        cancel_token.cancel();

        timeout(Duration::from_secs(5), consensus_sender_join_handle)
            .await
            .expect("ConsensusManagerSender did not terminate in time.")
            .unwrap()
    }

    /// Verify that increasing connection id causes advert to be resent.
    #[tokio::test]
    async fn resend_advert_to_reconnected_peer() {
        let (push_tx, mut push_rx) = tokio::sync::mpsc::unbounded_channel();
        let cancel_token = CancellationToken::new();
        let cancel_token_clone = cancel_token.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(100);

        let consensus_sender_join_handle = with_test_replica_logger(|log| {
            let mut mock_reader: MockValidatedPoolReader<U64Artifact> =
                MockValidatedPoolReader::new();
            let mut mock_transport = MockTransport::new();
            let mut seq = Sequence::new();

            mock_transport
                .expect_peers()
                .times(1)
                .return_once(|| vec![(NODE_1, ConnId::from(1)), (NODE_2, ConnId::from(2))])
                .in_sequence(&mut seq);
            mock_transport
                .expect_peers()
                .times(1)
                .returning(|| vec![(NODE_1, ConnId::from(3)), (NODE_2, ConnId::from(2))])
                .in_sequence(&mut seq);
            mock_transport.expect_peers().return_const(vec![]);
            mock_transport
                .expect_push()
                .times(3)
                .returning(move |n, _| {
                    push_tx.send(*n).unwrap();
                    Ok(())
                });
            mock_reader
                .expect_get_all_validated_by_filter()
                .returning(|_| Box::new(std::iter::empty()));
            mock_reader
                .expect_get_validated_by_identifier()
                .returning(|id| Some(*id));

            ConsensusManagerSender::run(
                log,
                ConsensusManagerMetrics::new::<U64Artifact>(&MetricsRegistry::default()),
                Handle::current(),
                Arc::new(RwLock::new(mock_reader)),
                Arc::new(mock_transport),
                rx,
                cancel_token_clone,
            )
        });

        tx.send(ArtifactProcessorEvent::Artifact(ArtifactWithOpt {
            advert: U64Artifact::message_to_advert(&1),
            is_latency_sensitive: false,
        }))
        .await
        .unwrap();

        // Received two messages from NODE_1 because of reconnection.
        let pushes = [
            push_rx.recv().await.unwrap(),
            push_rx.recv().await.unwrap(),
            push_rx.recv().await.unwrap(),
        ];
        assert_eq!(pushes.iter().filter(|&&n| n == NODE_1).count(), 2);
        assert_eq!(pushes.iter().filter(|&&n| n == NODE_2).count(), 1);

        cancel_token.cancel();
        timeout(Duration::from_secs(5), consensus_sender_join_handle)
            .await
            .expect("ConsensusManagerSender did not terminate in time.")
            .unwrap()
    }

    /// Verify failed send is retried.
    #[tokio::test]
    async fn retry_peer_error() {
        let (push_tx, mut push_rx) = tokio::sync::mpsc::unbounded_channel();
        let cancel_token = CancellationToken::new();
        let cancel_token_clone = cancel_token.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(100);

        let consensus_sender_join_handle = with_test_replica_logger(|log| {
            let mut mock_reader: MockValidatedPoolReader<U64Artifact> =
                MockValidatedPoolReader::new();
            let mut mock_transport = MockTransport::new();
            let mut seq = Sequence::new();

            mock_transport
                .expect_peers()
                .return_const(vec![(NODE_1, ConnId::from(1))]);
            // Let transport push fail a few times.
            mock_transport
                .expect_push()
                .times(5)
                .returning(move |_, _| Err(anyhow!("")))
                .in_sequence(&mut seq);
            mock_transport
                .expect_push()
                .times(1)
                .returning(move |n, _| {
                    push_tx.send(*n).unwrap();
                    Ok(())
                });
            mock_reader
                .expect_get_all_validated_by_filter()
                .returning(|_| Box::new(std::iter::empty()));
            mock_reader
                .expect_get_validated_by_identifier()
                .returning(|id| Some(*id));

            ConsensusManagerSender::run(
                log,
                ConsensusManagerMetrics::new::<U64Artifact>(&MetricsRegistry::default()),
                Handle::current(),
                Arc::new(RwLock::new(mock_reader)),
                Arc::new(mock_transport),
                rx,
                cancel_token_clone,
            )
        });
        tx.send(ArtifactProcessorEvent::Artifact(ArtifactWithOpt {
            advert: U64Artifact::message_to_advert(&1),
            is_latency_sensitive: false,
        }))
        .await
        .unwrap();
        // Verify that we successfully retried.
        assert_eq!(push_rx.recv().await.unwrap(), NODE_1);

        cancel_token.cancel();
        timeout(Duration::from_secs(5), consensus_sender_join_handle)
            .await
            .expect("ConsensusManagerSender did not terminate in time.")
            .unwrap()
    }

    /// Verify commit id increases with new adverts/purge events.
    #[tokio::test]
    async fn increasing_commit_id() {
        let (commit_id_tx, mut commit_id_rx) = tokio::sync::mpsc::unbounded_channel();
        let cancel_token = CancellationToken::new();
        let cancel_token_clone = cancel_token.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(100);

        let consensus_sender_join_handle = with_test_replica_logger(|log| {
            let mut mock_reader: MockValidatedPoolReader<U64Artifact> =
                MockValidatedPoolReader::new();
            let mut mock_transport = MockTransport::new();

            mock_transport
                .expect_peers()
                .return_const(vec![(NODE_1, ConnId::from(1))]);
            mock_transport
                .expect_push()
                .times(3)
                .returning(move |_, r| {
                    let advert: SlotUpdate<U64Artifact> =
                        pb::SlotUpdate::proxy_decode(&r.into_body()).unwrap();
                    commit_id_tx.send(advert.commit_id).unwrap();
                    Ok(())
                });
            mock_reader
                .expect_get_all_validated_by_filter()
                .returning(|_| Box::new(std::iter::empty()));
            mock_reader
                .expect_get_validated_by_identifier()
                .returning(|id| Some(*id));

            ConsensusManagerSender::run(
                log,
                ConsensusManagerMetrics::new::<U64Artifact>(&MetricsRegistry::default()),
                Handle::current(),
                Arc::new(RwLock::new(mock_reader)),
                Arc::new(mock_transport),
                rx,
                cancel_token_clone,
            )
        });
        // Send advert and verify commit it.
        tx.send(ArtifactProcessorEvent::Artifact(ArtifactWithOpt {
            advert: U64Artifact::message_to_advert(&1),
            is_latency_sensitive: false,
        }))
        .await
        .unwrap();
        assert_eq!(commit_id_rx.recv().await.unwrap().get(), 0);

        // Send second advert and observe commit id bump.
        tx.send(ArtifactProcessorEvent::Artifact(ArtifactWithOpt {
            advert: U64Artifact::message_to_advert(&2),
            is_latency_sensitive: false,
        }))
        .await
        .unwrap();
        assert_eq!(commit_id_rx.recv().await.unwrap().get(), 1);
        // Send purge and new advert and observe commit id increase by 2.
        tx.send(ArtifactProcessorEvent::Purge(2)).await.unwrap();
        tx.send(ArtifactProcessorEvent::Artifact(ArtifactWithOpt {
            advert: U64Artifact::message_to_advert(&3),
            is_latency_sensitive: false,
        }))
        .await
        .unwrap();

        assert_eq!(commit_id_rx.recv().await.unwrap().get(), 3);

        cancel_token.cancel();
        timeout(Duration::from_secs(5), consensus_sender_join_handle)
            .await
            .expect("ConsensusManagerSender did not terminate in time.")
            .unwrap()
    }

    /// Verify that duplicate Advert event does not cause sending twice.
    #[tokio::test]
    async fn send_same_advert_twice() {
        let (commit_id_tx, mut commit_id_rx) = tokio::sync::mpsc::unbounded_channel();
        let cancel_token = CancellationToken::new();
        let cancel_token_clone = cancel_token.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(100);

        let consensus_sender_join_handle = with_test_replica_logger(|log| {
            let mut mock_reader: MockValidatedPoolReader<U64Artifact> =
                MockValidatedPoolReader::new();
            let mut mock_transport = MockTransport::new();

            mock_transport
                .expect_peers()
                .return_const(vec![(NODE_1, ConnId::from(1))]);
            mock_transport
                .expect_push()
                .times(2)
                .returning(move |_, r| {
                    let advert: SlotUpdate<U64Artifact> =
                        pb::SlotUpdate::proxy_decode(&r.into_body()).unwrap();
                    commit_id_tx.send(advert.commit_id).unwrap();
                    Ok(())
                });
            mock_reader
                .expect_get_all_validated_by_filter()
                .returning(|_| Box::new(std::iter::empty()));
            mock_reader
                .expect_get_validated_by_identifier()
                .returning(|id| Some(*id));

            ConsensusManagerSender::run(
                log,
                ConsensusManagerMetrics::new::<U64Artifact>(&MetricsRegistry::default()),
                Handle::current(),
                Arc::new(RwLock::new(mock_reader)),
                Arc::new(mock_transport),
                rx,
                cancel_token_clone,
            )
        });
        // Send advert and verify commit id.
        tx.send(ArtifactProcessorEvent::Artifact(ArtifactWithOpt {
            advert: U64Artifact::message_to_advert(&1),
            is_latency_sensitive: false,
        }))
        .await
        .unwrap();
        assert_eq!(commit_id_rx.recv().await.unwrap().get(), 0);

        // Send same advert again. This should be noop.
        tx.send(ArtifactProcessorEvent::Artifact(ArtifactWithOpt {
            advert: U64Artifact::message_to_advert(&1),
            is_latency_sensitive: false,
        }))
        .await
        .unwrap();

        // Check that new advert is advertised with correct commit id.
        tx.send(ArtifactProcessorEvent::Artifact(ArtifactWithOpt {
            advert: U64Artifact::message_to_advert(&2),
            is_latency_sensitive: false,
        }))
        .await
        .unwrap();

        assert_eq!(commit_id_rx.recv().await.unwrap().get(), 2);

        cancel_token.cancel();
        timeout(Duration::from_secs(5), consensus_sender_join_handle)
            .await
            .expect("ConsensusManagerSender did not terminate in time.")
            .unwrap()
    }

    /// Verify that a panic happening in one of the tasks spawned by the ConsensusManagerSender
    /// is propagated when awaiting on [`ConsensusManagerSender::run`].
    ///
    // This test is ignored because the panic is caught in the panic hook set in /consensus_manager/receiver.rs
    #[ignore]
    #[tokio::test]
    async fn panic_in_task_is_propagated() {
        let cancel_token = CancellationToken::new();
        let cancel_token_clone = cancel_token.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(100);

        let consensus_sender_join_handle = with_test_replica_logger(|log| {
            let mut mock_reader = MockValidatedPoolReader::new();
            let mut mock_transport = MockTransport::new();

            mock_transport
                .expect_peers()
                .return_const(vec![(NODE_1, ConnId::from(1))]);

            // We don't create an expectation for `push` here, so that we can trigger a panic
            mock_transport
                .expect_push()
                .times(2)
                .returning(move |_, _| {
                    panic!("Panic in mock transport expectation.");
                });

            mock_reader
                .expect_get_all_validated_by_filter()
                .returning(|_| Box::new(std::iter::empty()));
            mock_reader
                .expect_get_validated_by_identifier()
                .returning(|id| Some(*id));

            ConsensusManagerSender::run(
                log,
                ConsensusManagerMetrics::new::<U64Artifact>(&MetricsRegistry::default()),
                Handle::current(),
                Arc::new(RwLock::new(mock_reader)),
                Arc::new(mock_transport),
                rx,
                cancel_token_clone,
            )
        });

        tx.send(ArtifactProcessorEvent::Artifact(ArtifactWithOpt {
            advert: U64Artifact::message_to_advert(&1),
            is_latency_sensitive: false,
        }))
        .await
        .unwrap();

        let join_error = timeout(Duration::from_secs(5), consensus_sender_join_handle)
            .await
            .expect("ConsensusManagerSender should terminate since the downstream service `transport` panicked.")
            .expect_err("Expected a join error");

        assert!(join_error.is_panic(), "The join error should be a panic.");
    }

    /// Test that we can take more slots than SLOT_TABLE_THRESHOLD
    #[test]
    fn slot_manager_unrestricted() {
        let mut sm = AvailableSlotSet::new(
            no_op_logger(),
            ConsensusManagerMetrics::new::<U64Artifact>(&MetricsRegistry::default()),
            "test",
        );

        // Take more than SLOT_TABLE_THRESHOLD number of slots
        for i in 0..(SLOT_TABLE_THRESHOLD * 5) {
            assert_eq!(sm.pop().get(), i);
        }
        // Give back all the slots.
        for i in 0..(SLOT_TABLE_THRESHOLD * 5) {
            sm.push(SlotNumber::from(i));
        }
        // Check that we get the slot that was returned last
        assert_eq!(sm.pop().get(), SLOT_TABLE_THRESHOLD * 5 - 1);
    }
}
