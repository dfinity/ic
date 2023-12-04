use std::{
    collections::{hash_map::Entry, HashMap},
    sync::{Arc, RwLock},
    time::Duration,
};

use axum::http::Request;
use backoff::backoff::Backoff;
use bytes::Bytes;
use ic_interfaces::p2p::{
    artifact_manager::ArtifactProcessorEvent, consensus::ValidatedPoolReader,
};
use ic_logger::{error, warn, ReplicaLogger};
use ic_protobuf::{p2p::v1 as pb, proxy::ProtoProxy};
use ic_quic_transport::{ConnId, Transport};
use ic_types::artifact::{Advert, ArtifactKind};
use ic_types::NodeId;
use tokio::{
    runtime::Handle,
    select,
    sync::mpsc::Receiver,
    task::{JoinHandle, JoinSet},
    time,
};

use crate::{metrics::ConsensusManagerMetrics, AdvertUpdate, CommitId, SlotNumber, Update};

/// The size threshold for an artifact to be pushed. Artifacts smaller than this constant
/// in size are pushed.
const ARTIFACT_PUSH_THRESHOLD_BYTES: usize = 1024; // 1KB

//TODO(NET-1539): Move all these bounds to the ArtifactKind trait directly.
// pub trait Send + Sync + Hash +'static: Send + Sync  + Hash + 'static {}

const MIN_BACKOFF_INTERVAL: Duration = Duration::from_millis(250);
// The value must be smaller than `ic_http_handler::MAX_TCP_PEEK_TIMEOUT_SECS`.
// See VER-1060 for details.
const MAX_BACKOFF_INTERVAL: Duration = Duration::from_secs(10);
// The multiplier is chosen such that the sum of all intervals is about 100
// seconds: `sum ~= (1.1^25 - 1) / (1.1 - 1) ~= 98`.
const BACKOFF_INTERVAL_MULTIPLIER: f64 = 1.1;
const MAX_ELAPSED_TIME: Duration = Duration::from_secs(60 * 5); // 5 minutes

// Used to log warnings if the slot table grows beyond the threshold.
const SLOT_TABLE_THRESHOLD: u64 = 30_000;

pub fn get_backoff_policy() -> backoff::ExponentialBackoff {
    backoff::ExponentialBackoff {
        initial_interval: MIN_BACKOFF_INTERVAL,
        current_interval: MIN_BACKOFF_INTERVAL,
        randomization_factor: 0.1,
        multiplier: BACKOFF_INTERVAL_MULTIPLIER,
        start_time: std::time::Instant::now(),
        max_interval: MAX_BACKOFF_INTERVAL,
        max_elapsed_time: Some(MAX_ELAPSED_TIME),
        clock: backoff::SystemClock::default(),
    }
}

pub(crate) struct ConsensusManagerSender<Artifact: ArtifactKind> {
    log: ReplicaLogger,
    metrics: ConsensusManagerMetrics,
    rt_handle: Handle,
    pool_reader: Arc<RwLock<dyn ValidatedPoolReader<Artifact> + Send + Sync>>,
    transport: Arc<dyn Transport>,

    adverts_to_send: Receiver<ArtifactProcessorEvent<Artifact>>,
    slot_manager: SlotManager,
    current_commit_id: CommitId,
    active_adverts: HashMap<Artifact::Id, (JoinHandle<()>, SlotNumber)>,
}

impl<Artifact: ArtifactKind> ConsensusManagerSender<Artifact> {
    pub(crate) fn run(
        log: ReplicaLogger,
        metrics: ConsensusManagerMetrics,
        rt_handle: Handle,
        pool_reader: Arc<RwLock<dyn ValidatedPoolReader<Artifact> + Send + Sync>>,
        transport: Arc<dyn Transport>,
        adverts_to_send: Receiver<ArtifactProcessorEvent<Artifact>>,
    ) {
        let slot_manager = SlotManager::new(log.clone(), metrics.clone());

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
        };

        rt_handle.spawn(manager.start_event_loop());
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
            self.handle_send_advert(advert);
        }

        while let Some(advert) = self.adverts_to_send.recv().await {
            match advert {
                ArtifactProcessorEvent::Advert(advert) => self.handle_send_advert(advert),
                ArtifactProcessorEvent::Purge(id) => {
                    self.handle_purge_advert(&id);
                }
            }

            self.current_commit_id.inc_assign();
        }

        error!(
            self.log,
            "Sender event loop for the P2P client `{:?}` terminated. No more adverts will be sent for this client.",
            Artifact::TAG
        );
    }

    fn handle_purge_advert(&mut self, id: &Artifact::Id) {
        if let Some((send_task, free_slot)) = self.active_adverts.remove(id) {
            self.metrics.send_view_consensus_purge_active_total.inc();
            send_task.abort();
            self.slot_manager.give_slot(free_slot);
        } else {
            self.metrics.send_view_consensus_dup_purge_total.inc();
        }
    }

    fn handle_send_advert(&mut self, advert: Advert<Artifact>) {
        let entry = self.active_adverts.entry(advert.id.clone());

        if let Entry::Vacant(entry) = entry {
            self.metrics.send_view_consensus_new_adverts_total.inc();

            let slot = self.slot_manager.take_free_slot();

            let send_future = Self::send_advert_to_all_peers(
                self.rt_handle.clone(),
                self.log.clone(),
                self.metrics.clone(),
                self.transport.clone(),
                self.current_commit_id,
                slot,
                advert,
                self.pool_reader.clone(),
            );

            entry.insert((self.rt_handle.spawn(send_future), slot));
        } else {
            self.metrics.send_view_consensus_dup_adverts_total.inc();
        }
    }

    /// Sends an advert to all peers.
    ///
    /// Memory Consumption:
    /// - JoinMap: #peers * (32 + ~32)
    /// - HashMap: #peers * (32 + 8)
    /// - advert: ±200
    /// For 10k tasks ~50Mb
    async fn send_advert_to_all_peers(
        rt_handle: Handle,
        log: ReplicaLogger,
        metrics: ConsensusManagerMetrics,
        transport: Arc<dyn Transport>,
        commit_id: CommitId,
        slot_number: SlotNumber,
        Advert {
            id,
            attribute,
            size,
            ..
        }: Advert<Artifact>,
        pool_reader: Arc<RwLock<dyn ValidatedPoolReader<Artifact> + Send + Sync>>,
    ) {
        // Try to push artifact if size below threshold && the artifact is not a relay.
        let push_artifact = size < ARTIFACT_PUSH_THRESHOLD_BYTES;

        let artifact = if push_artifact {
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

        let advert_update: AdvertUpdate<Artifact> = AdvertUpdate {
            slot_number,
            commit_id,
            update: match artifact {
                Some(artifact) => Update::Artifact(artifact),
                None => Update::Advert((id, attribute)),
            },
        };

        let body = Bytes::from(pb::AdvertUpdate::proxy_encode(advert_update));

        let mut in_progress_transmissions = JoinSet::new();
        // stores the connection ID of the last successful transmission to a peer.
        let mut initiated_transmissions: HashMap<NodeId, ConnId> = HashMap::new();
        let mut periodic_check_interval = time::interval(Duration::from_secs(5));

        loop {
            select! {
                _ = periodic_check_interval.tick() => {
                    // check for new peers/connection IDs
                    // spawn task for peers with higher conn id or not in completed transmissions.
                    // add task to join map
                    for (peer, connection_id) in transport.peers() {
                        let is_initiated = initiated_transmissions.get(&peer).is_some_and(|c| *c == connection_id);

                        if !is_initiated {
                            metrics.send_view_send_to_peer_total.inc();
                            let task = send_advert_to_peer(transport.clone(), body.clone(), peer, Artifact::TAG.into());
                            in_progress_transmissions.spawn_on(task, &rt_handle);
                            initiated_transmissions.insert(peer, connection_id);
                        }
                    }
                }
                Some(result) = in_progress_transmissions.join_next() => {
                    match result {
                        Ok(_) => {
                            metrics.send_view_send_to_peer_delivered_total.inc();
                        },
                        Err(err) => {
                            // Cancelling tasks is ok. Panicking tasks are not.
                            if err.is_panic() {
                                std::panic::resume_unwind(err.into_panic());
                            }
                        },
                    }
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
    uri_prefix: &str,
) {
    let mut backoff = get_backoff_policy();

    loop {
        let request = Request::builder()
            .uri(format!("/{}/update", uri_prefix))
            .body(message.clone())
            .expect("Building from typed values");

        if let Ok(()) = transport.push(&peer, request).await {
            return;
        }

        let backoff_duration = backoff.next_backoff().unwrap_or(MAX_ELAPSED_TIME);
        time::sleep(backoff_duration).await;
    }
}

struct SlotManager {
    next_free_slot: SlotNumber,
    free_slots: Vec<SlotNumber>,
    log: ReplicaLogger,
    metrics: ConsensusManagerMetrics,
}

impl SlotManager {
    fn new(log: ReplicaLogger, metrics: ConsensusManagerMetrics) -> Self {
        Self {
            next_free_slot: 0.into(),
            free_slots: vec![],
            log,
            metrics,
        }
    }

    fn give_slot(&mut self, slot: SlotNumber) {
        self.free_slots.push(slot);
        self.metrics.slot_manager_used_slots.dec();
    }

    fn take_free_slot(&mut self) -> SlotNumber {
        self.metrics.slot_manager_used_slots.inc();
        match self.free_slots.pop() {
            Some(slot) => slot,
            None => {
                if self.next_free_slot.get() > SLOT_TABLE_THRESHOLD {
                    warn!(
                        self.log,
                        "Slot table threshold exceeded. Slots in use = {}.", self.next_free_slot
                    );
                }

                let new_slot = self.next_free_slot;
                self.next_free_slot.inc_assign();

                self.metrics.slot_manager_maximum_slots_total.inc();

                new_slot
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::backtrace::Backtrace;

    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_p2p_test_utils::{
        consensus::U64Artifact,
        mocks::{MockTransport, MockValidatedPoolReader},
    };
    use ic_protobuf::proxy::ProtoProxy;
    use ic_quic_transport::SendError;
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_types_test_utils::ids::{NODE_1, NODE_2};
    use mockall::Sequence;

    use super::*;

    /// Verify that initial validated pool is sent to peers.
    #[test]
    fn initial_validated_pool_is_sent_to_all_peers() {
        // Abort process if a thread panics. This catches detached tokio tasks that panic.
        // https://github.com/tokio-rs/tokio/issues/4516
        std::panic::set_hook(Box::new(|info| {
            let stacktrace = Backtrace::force_capture();
            println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
            std::process::abort();
        }));

        with_test_replica_logger(|log| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let mut mock_reader = MockValidatedPoolReader::new();
            let mut mock_transport = MockTransport::new();
            let (push_tx, mut push_rx) = tokio::sync::mpsc::unbounded_channel();
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
                rt.handle().clone(),
                Arc::new(RwLock::new(mock_reader)),
                Arc::new(mock_transport),
                rx,
            );
            assert_eq!(push_rx.blocking_recv().unwrap(), NODE_1);
        });
    }

    /// Verify that advert is sent to multiple peers.
    #[test]
    fn send_advert_to_all_peers() {
        // Abort process if a thread panics. This catches detached tokio tasks that panic.
        // https://github.com/tokio-rs/tokio/issues/4516
        std::panic::set_hook(Box::new(|info| {
            let stacktrace = Backtrace::force_capture();
            println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
            std::process::abort();
        }));

        with_test_replica_logger(|log| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let mut mock_reader = MockValidatedPoolReader::new();
            let mut mock_transport = MockTransport::new();
            let (push_tx, mut push_rx) = tokio::sync::mpsc::unbounded_channel();
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

            let (tx, rx) = tokio::sync::mpsc::channel(100);
            ConsensusManagerSender::run(
                log,
                ConsensusManagerMetrics::new::<U64Artifact>(&MetricsRegistry::default()),
                rt.handle().clone(),
                Arc::new(RwLock::new(mock_reader)),
                Arc::new(mock_transport),
                rx,
            );
            tx.blocking_send(ArtifactProcessorEvent::Advert(
                U64Artifact::message_to_advert(&1),
            ))
            .unwrap();
            let first_push_node = push_rx.blocking_recv().unwrap();
            let second_push_node = push_rx.blocking_recv().unwrap();
            assert!(
                first_push_node == NODE_1 && second_push_node == NODE_2
                    || first_push_node == NODE_2 && second_push_node == NODE_1
            );
        });
    }

    /// Verify that increasing connection id causes advert to be resent.
    #[test]
    fn resend_advert_to_reconnected_peer() {
        // Abort process if a thread panics. This catches detached tokio tasks that panic.
        // https://github.com/tokio-rs/tokio/issues/4516
        std::panic::set_hook(Box::new(|info| {
            let stacktrace = Backtrace::force_capture();
            println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
            std::process::abort();
        }));

        with_test_replica_logger(|log| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let mut mock_reader = MockValidatedPoolReader::new();
            let mut mock_transport = MockTransport::new();
            let (push_tx, mut push_rx) = tokio::sync::mpsc::unbounded_channel();
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

            let (tx, rx) = tokio::sync::mpsc::channel(100);
            ConsensusManagerSender::run(
                log,
                ConsensusManagerMetrics::new::<U64Artifact>(&MetricsRegistry::default()),
                rt.handle().clone(),
                Arc::new(RwLock::new(mock_reader)),
                Arc::new(mock_transport),
                rx,
            );
            tx.blocking_send(ArtifactProcessorEvent::Advert(
                U64Artifact::message_to_advert(&1),
            ))
            .unwrap();

            // Received two messages from NODE_1 because of reconnection.
            let pushes = [
                push_rx.blocking_recv().unwrap(),
                push_rx.blocking_recv().unwrap(),
                push_rx.blocking_recv().unwrap(),
            ];
            assert_eq!(pushes.iter().filter(|&&n| n == NODE_1).count(), 2);
            assert_eq!(pushes.iter().filter(|&&n| n == NODE_2).count(), 1);
        });
    }

    /// Verify failed send is retried.
    #[test]
    fn retry_peer_error() {
        // Abort process if a thread panics. This catches detached tokio tasks that panic.
        // https://github.com/tokio-rs/tokio/issues/4516
        std::panic::set_hook(Box::new(|info| {
            let stacktrace = Backtrace::force_capture();
            println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
            std::process::abort();
        }));

        with_test_replica_logger(|log| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let mut mock_reader = MockValidatedPoolReader::new();
            let mut mock_transport = MockTransport::new();
            let (push_tx, mut push_rx) = tokio::sync::mpsc::unbounded_channel();
            let mut seq = Sequence::new();

            mock_transport
                .expect_peers()
                .return_const(vec![(NODE_1, ConnId::from(1))]);
            // Let transport push fail a few times.
            mock_transport
                .expect_push()
                .times(5)
                .returning(move |_, _| {
                    Err(SendError::ConnectionNotFound {
                        reason: String::new(),
                    })
                })
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

            let (tx, rx) = tokio::sync::mpsc::channel(100);
            ConsensusManagerSender::run(
                log,
                ConsensusManagerMetrics::new::<U64Artifact>(&MetricsRegistry::default()),
                rt.handle().clone(),
                Arc::new(RwLock::new(mock_reader)),
                Arc::new(mock_transport),
                rx,
            );
            tx.blocking_send(ArtifactProcessorEvent::Advert(
                U64Artifact::message_to_advert(&1),
            ))
            .unwrap();
            // Verify that we successfully retried.
            assert_eq!(push_rx.blocking_recv().unwrap(), NODE_1);
        });
    }

    /// Verify commit id increases with new adverts/purge events.
    #[test]
    fn increasing_commit_id() {
        // Abort process if a thread panics. This catches detached tokio tasks that panic.
        // https://github.com/tokio-rs/tokio/issues/4516
        std::panic::set_hook(Box::new(|info| {
            let stacktrace = Backtrace::force_capture();
            println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
            std::process::abort();
        }));

        with_test_replica_logger(|log| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let mut mock_reader = MockValidatedPoolReader::new();
            let mut mock_transport = MockTransport::new();
            let (commit_id_tx, mut commit_id_rx) = tokio::sync::mpsc::unbounded_channel();

            mock_transport
                .expect_peers()
                .return_const(vec![(NODE_1, ConnId::from(1))]);
            mock_transport
                .expect_push()
                .times(3)
                .returning(move |_, r| {
                    let advert: AdvertUpdate<U64Artifact> =
                        pb::AdvertUpdate::proxy_decode(&r.into_body()).unwrap();
                    commit_id_tx.send(advert.commit_id).unwrap();
                    Ok(())
                });
            mock_reader
                .expect_get_all_validated_by_filter()
                .returning(|_| Box::new(std::iter::empty()));
            mock_reader
                .expect_get_validated_by_identifier()
                .returning(|id| Some(*id));

            let (tx, rx) = tokio::sync::mpsc::channel(100);
            ConsensusManagerSender::run(
                log,
                ConsensusManagerMetrics::new::<U64Artifact>(&MetricsRegistry::default()),
                rt.handle().clone(),
                Arc::new(RwLock::new(mock_reader)),
                Arc::new(mock_transport),
                rx,
            );
            // Send advert and verify commit it.
            tx.blocking_send(ArtifactProcessorEvent::Advert(
                U64Artifact::message_to_advert(&1),
            ))
            .unwrap();
            assert_eq!(commit_id_rx.blocking_recv().unwrap().get(), 0);

            // Send second advert and observe commit id bump.
            tx.blocking_send(ArtifactProcessorEvent::Advert(
                U64Artifact::message_to_advert(&2),
            ))
            .unwrap();
            assert_eq!(commit_id_rx.blocking_recv().unwrap().get(), 1);
            // Send purge and new advert and observe commit id increase by 2.
            tx.blocking_send(ArtifactProcessorEvent::Purge(2)).unwrap();
            tx.blocking_send(ArtifactProcessorEvent::Advert(
                U64Artifact::message_to_advert(&3),
            ))
            .unwrap();
            assert_eq!(commit_id_rx.blocking_recv().unwrap().get(), 3);
        });
    }

    /// Verify that duplicate Advert event does not cause sending twice.
    #[test]
    fn send_same_advert_twice() {
        // Abort process if a thread panics. This catches detached tokio tasks that panic.
        // https://github.com/tokio-rs/tokio/issues/4516
        std::panic::set_hook(Box::new(|info| {
            let stacktrace = Backtrace::force_capture();
            println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
            std::process::abort();
        }));

        with_test_replica_logger(|log| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let mut mock_reader = MockValidatedPoolReader::new();
            let mut mock_transport = MockTransport::new();
            let (commit_id_tx, mut commit_id_rx) = tokio::sync::mpsc::unbounded_channel();

            mock_transport
                .expect_peers()
                .return_const(vec![(NODE_1, ConnId::from(1))]);
            mock_transport
                .expect_push()
                .times(2)
                .returning(move |_, r| {
                    let advert: AdvertUpdate<U64Artifact> =
                        pb::AdvertUpdate::proxy_decode(&r.into_body()).unwrap();
                    commit_id_tx.send(advert.commit_id).unwrap();
                    Ok(())
                });
            mock_reader
                .expect_get_all_validated_by_filter()
                .returning(|_| Box::new(std::iter::empty()));
            mock_reader
                .expect_get_validated_by_identifier()
                .returning(|id| Some(*id));

            let (tx, rx) = tokio::sync::mpsc::channel(100);
            ConsensusManagerSender::run(
                log,
                ConsensusManagerMetrics::new::<U64Artifact>(&MetricsRegistry::default()),
                rt.handle().clone(),
                Arc::new(RwLock::new(mock_reader)),
                Arc::new(mock_transport),
                rx,
            );
            // Send advert and verify commit id.
            tx.blocking_send(ArtifactProcessorEvent::Advert(
                U64Artifact::message_to_advert(&1),
            ))
            .unwrap();
            assert_eq!(commit_id_rx.blocking_recv().unwrap().get(), 0);
            // Send same advert again. This should be noop.
            tx.blocking_send(ArtifactProcessorEvent::Advert(
                U64Artifact::message_to_advert(&1),
            ))
            .unwrap();
            // Check that new advert is advertised with correct commit id.
            tx.blocking_send(ArtifactProcessorEvent::Advert(
                U64Artifact::message_to_advert(&2),
            ))
            .unwrap();
            assert_eq!(commit_id_rx.blocking_recv().unwrap().get(), 2);
        });
    }

    /// Test that we can take more slots than SLOT_TABLE_THRESHOLD
    #[test]
    fn slot_manager_unrestricted() {
        let mut sm = SlotManager::new(
            no_op_logger(),
            ConsensusManagerMetrics::new::<U64Artifact>(&MetricsRegistry::default()),
        );

        // Take more than SLOT_TABLE_THRESHOLD number of slots
        for i in 0..(SLOT_TABLE_THRESHOLD * 5) {
            assert_eq!(sm.take_free_slot().get(), i);
        }
        // Give back all the slots.
        for i in 0..(SLOT_TABLE_THRESHOLD * 5) {
            sm.give_slot(SlotNumber::from(i));
        }
        // Check that we get the slot that was returned last
        assert_eq!(sm.take_free_slot().get(), SLOT_TABLE_THRESHOLD * 5 - 1);
    }
}
