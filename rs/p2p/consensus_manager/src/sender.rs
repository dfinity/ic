use std::{
    collections::{HashMap, hash_map::Entry},
    marker::PhantomData,
    panic,
    sync::Arc,
    time::Duration,
};

use axum::http::Request;
use backoff::{ExponentialBackoffBuilder, backoff::Backoff};
use bytes::Bytes;
use ic_base_types::NodeId;
use ic_interfaces::p2p::consensus::{ArtifactAssembler, ArtifactTransmit, ArtifactWithOpt};
use ic_logger::{ReplicaLogger, error, warn};
use ic_protobuf::{p2p::v1 as pb, proxy::ProtoProxy};
use ic_quic_transport::{ConnId, Shutdown, Transport};
use ic_types::artifact::{IdentifiableArtifact, PbArtifact};
use prost::Message;
use tokio::{
    runtime::Handle,
    select,
    sync::mpsc::Receiver,
    task::{JoinError, JoinSet},
    time,
};
use tokio_util::sync::CancellationToken;
use tracing::instrument;

use crate::{CommitId, SlotNumber, metrics::ConsensusManagerMetrics, uri_prefix};

use self::available_slot_set::{AvailableSlot, AvailableSlotSet};

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
                panic!("Join error: {err:?}");
            }
        }
    }
}

pub struct ConsensusManagerSender<Artifact: IdentifiableArtifact, WireArtifact, Assembler> {
    log: ReplicaLogger,
    metrics: ConsensusManagerMetrics,
    rt_handle: Handle,
    transport: Arc<dyn Transport>,
    outbound_transmits: Receiver<ArtifactTransmit<Artifact>>,
    slot_manager: AvailableSlotSet,
    current_commit_id: CommitId,
    active_slots: HashMap<Artifact::Id, (CancellationToken, AvailableSlot)>,
    active_transmit_tasks: JoinSet<()>,
    assembler: Assembler,
    marker: PhantomData<WireArtifact>,
}

impl<
    Artifact: IdentifiableArtifact,
    WireArtifact: PbArtifact,
    Assembler: ArtifactAssembler<Artifact, WireArtifact>,
> ConsensusManagerSender<Artifact, WireArtifact, Assembler>
{
    pub fn run(
        log: ReplicaLogger,
        metrics: ConsensusManagerMetrics,
        rt_handle: Handle,
        transport: Arc<dyn Transport>,
        outbound_transmits: Receiver<ArtifactTransmit<Artifact>>,
        assembler: Assembler,
    ) -> Shutdown {
        let slot_manager = AvailableSlotSet::new(log.clone(), metrics.clone(), WireArtifact::NAME);

        let manager = Self {
            log,
            metrics,
            rt_handle: rt_handle.clone(),
            transport,
            outbound_transmits,
            slot_manager,
            current_commit_id: CommitId::from(0),
            active_slots: HashMap::new(),
            active_transmit_tasks: JoinSet::new(),
            assembler,
            marker: PhantomData,
        };

        Shutdown::spawn_on_with_cancellation(
            |cancellation: CancellationToken| manager.start_event_loop(cancellation),
            &rt_handle,
        )
    }

    async fn start_event_loop(mut self, cancellation_token: CancellationToken) {
        loop {
            select! {
                _ = cancellation_token.cancelled() => {
                    error!(
                        self.log,
                        "Sender event loop for the P2P client `{:?}` terminated. No more transmits \
                        will be sent for this client.",
                        uri_prefix::<WireArtifact>()
                    );
                    break;
                }
                Some(result) = self.active_transmit_tasks.join_next() => {
                    panic_on_join_err(result);
                }
                Some(outbound_transmit) = self.outbound_transmits.recv() => {
                    match outbound_transmit {
                        ArtifactTransmit::Deliver(artifact) => {
                            self.handle_deliver_transmit(artifact, cancellation_token.clone())
                        },
                        ArtifactTransmit::Abort(id) => self.handle_abort_transmit(&id),
                    }
                    self.current_commit_id.inc_assign();
                }
            }

            #[cfg(debug_assertions)]
            {
                if self.active_transmit_tasks.len() < self.active_slots.len() {
                    // This invariant can be violated if the root cancellation token is cancelled.
                    // It can be violated because the active_slots HashMap is only cleared
                    // when purging artifacts, and not when the tasks join due to a cancellation
                    // not triggered by the manager.
                    let is_not_cancelled =
                        time::timeout(Duration::from_secs(5), cancellation_token.cancelled())
                            .await
                            .is_err();

                    if is_not_cancelled {
                        panic!(
                            "Invariant violated: active_transmit_tasks.len() {:?} >= active_slots.len() {:?}.",
                            self.active_transmit_tasks.len(),
                            self.active_slots.len()
                        );
                    }
                }
            }
        }

        while let Some(result) = self.active_transmit_tasks.join_next().await {
            panic_on_join_err(result);
        }
    }

    fn handle_abort_transmit(&mut self, id: &Artifact::Id) {
        if let Some((cancellation_token, free_slot)) = self.active_slots.remove(id) {
            self.metrics.send_view_consensus_purge_active_total.inc();
            cancellation_token.cancel();
            self.slot_manager.push(free_slot);
        } else {
            self.metrics.send_view_consensus_dup_purge_total.inc();
        }
    }

    #[instrument(skip_all)]
    fn handle_deliver_transmit(
        &mut self,
        new_artifact: ArtifactWithOpt<Artifact>,
        cancellation_token: CancellationToken,
    ) {
        let id = new_artifact.artifact.id();
        let wire_artifact = self.assembler.disassemble_message(new_artifact.artifact);
        let wire_artifact_id = wire_artifact.id();
        let entry = self.active_slots.entry(id.clone());

        if let Entry::Vacant(entry) = entry {
            self.metrics.send_view_consensus_new_adverts_total.inc();

            let used_slot = self.slot_manager.pop();

            let child_token = cancellation_token.child_token();
            let child_token_clone = child_token.clone();
            let payload = Self::get_transmit_payload(
                self.current_commit_id,
                used_slot.slot_number(),
                ArtifactWithOpt {
                    artifact: wire_artifact,
                    is_latency_sensitive: new_artifact.is_latency_sensitive,
                },
                wire_artifact_id,
            );
            let route = uri_prefix::<WireArtifact>();
            let send_future = send_transmit_to_all_peers(
                self.rt_handle.clone(),
                self.metrics.clone(),
                self.transport.clone(),
                payload,
                route,
                child_token_clone,
            );

            self.active_transmit_tasks
                .spawn_on(send_future, &self.rt_handle);
            entry.insert((child_token, used_slot));
        } else {
            self.metrics.send_view_consensus_dup_adverts_total.inc();
        }
    }

    fn get_transmit_payload(
        commit_id: CommitId,
        slot_number: SlotNumber,
        ArtifactWithOpt {
            artifact,
            is_latency_sensitive,
        }: ArtifactWithOpt<WireArtifact>,
        id: WireArtifact::Id,
    ) -> Bytes {
        let pb_slot_update = pb::SlotUpdate {
            commit_id: commit_id.get(),
            slot_id: slot_number.get(),
            update: Some({
                let pb_artifact: WireArtifact::PbMessage = artifact.into();
                // Try to push artifact if size below threshold or it is latency sensitive.
                if pb_artifact.encoded_len() < ARTIFACT_PUSH_THRESHOLD_BYTES || is_latency_sensitive
                {
                    pb::slot_update::Update::Artifact(pb_artifact.encode_to_vec())
                } else {
                    pb::slot_update::Update::Id(WireArtifact::PbId::proxy_encode(id))
                }
            }),
        };
        Bytes::from(pb_slot_update.encode_to_vec())
    }
}
#[instrument(skip_all)]
async fn send_transmit_to_all_peers(
    rt_handle: Handle,
    metrics: ConsensusManagerMetrics,
    transport: Arc<dyn Transport>,
    body: Bytes,
    route: String,
    cancellation_token: CancellationToken,
) {
    let mut in_progress_transmissions = JoinSet::new();
    // Stores the connection ID and the [`CancellationToken`] of the last successful transmission task to a peer.
    let mut initiated_transmissions: HashMap<NodeId, (ConnId, CancellationToken)> = HashMap::new();
    let mut periodic_check_interval = time::interval(Duration::from_secs(5));
    loop {
        select! {
            _ = cancellation_token.cancelled() => {
                while let Some(result) = in_progress_transmissions.join_next().await {
                    metrics.send_view_send_to_peer_cancelled_total.inc();
                    panic_on_join_err(result);
                }
                break;
            }
            Some(result) = in_progress_transmissions.join_next() => {
                panic_on_join_err(result);
                metrics.send_view_send_to_peer_delivered_total.inc();
            }
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
                        let route = route.clone();

                        let send_future = async move {
                            select! {
                                _ = send_transmit_to_peer(transport, body, peer, route) => {},
                                _ = child_token.cancelled() => {},
                            }
                        };

                        in_progress_transmissions.spawn_on(send_future, &rt_handle);
                        initiated_transmissions.insert(peer, (connection_id, child_token_clone));
                    }
                }
            }
        }
    }
}

#[instrument(skip(transport, message))]
async fn send_transmit_to_peer(
    transport: Arc<dyn Transport>,
    message: Bytes,
    peer: NodeId,
    route: String,
) {
    let mut backoff = ExponentialBackoffBuilder::new()
        .with_initial_interval(MIN_BACKOFF_INTERVAL)
        .with_max_interval(MAX_BACKOFF_INTERVAL)
        .with_multiplier(BACKOFF_MULTIPLIER)
        .with_max_elapsed_time(None)
        .build();

    loop {
        let request = Request::builder()
            .uri(format!("/{route}/update"))
            .body(message.clone())
            .expect("Building from typed values");

        // TODO: NET-1748
        if transport.rpc(&peer, request).await.is_ok() {
            return;
        }

        let backoff_duration = backoff.next_backoff().unwrap_or(MAX_BACKOFF_INTERVAL);
        time::sleep(backoff_duration).await;
    }
}

mod available_slot_set {
    use super::SLOT_TABLE_THRESHOLD;
    use crate::{ConsensusManagerMetrics, SlotNumber};
    use ic_logger::{ReplicaLogger, warn};

    pub struct AvailableSlot(u64);

    impl AvailableSlot {
        pub fn slot_number(&self) -> SlotNumber {
            self.0.into()
        }
    }

    pub struct AvailableSlotSet {
        next_free_slot: u64,
        free_slots: Vec<AvailableSlot>,
        log: ReplicaLogger,
        metrics: ConsensusManagerMetrics,
        service_name: &'static str,
    }

    impl AvailableSlotSet {
        pub fn new(
            log: ReplicaLogger,
            metrics: ConsensusManagerMetrics,
            service_name: &'static str,
        ) -> Self {
            Self {
                next_free_slot: 0,
                free_slots: vec![],
                log,
                metrics,
                service_name,
            }
        }

        pub fn push(&mut self, slot: AvailableSlot) {
            self.free_slots.push(slot);
            self.metrics.slot_set_in_use_slots.dec();
        }

        /// Returns available slot.
        pub fn pop(&mut self) -> AvailableSlot {
            self.metrics.slot_set_in_use_slots.inc();
            match self.free_slots.pop() {
                Some(slot) => slot,
                None => {
                    if self.next_free_slot > SLOT_TABLE_THRESHOLD {
                        warn!(
                            self.log,
                            "Slot table threshold exceeded for service {}. Slots in use = {}.",
                            self.service_name,
                            self.next_free_slot
                        );
                    }

                    let new_slot = AvailableSlot(self.next_free_slot);
                    self.next_free_slot += 1;

                    self.metrics.slot_set_allocated_slots_total.inc();

                    new_slot
                }
            }
        }
    }
}

#[allow(clippy::disallowed_methods)]
#[cfg(test)]
mod tests {
    use axum::http::Response;
    use ic_interfaces::p2p::consensus::{AssembleResult, Peers};
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_p2p_test_utils::{consensus::U64Artifact, mocks::MockTransport};
    use ic_quic_transport::P2PError;
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_types_test_utils::ids::{NODE_1, NODE_2};
    use mockall::Sequence;
    use tokio::{runtime::Handle, time::timeout};

    use super::*;

    #[derive(Clone)]
    struct IdentityAssembler;

    impl ArtifactAssembler<U64Artifact, U64Artifact> for IdentityAssembler {
        fn disassemble_message(&self, msg: U64Artifact) -> U64Artifact {
            msg
        }
        async fn assemble_message<P: Peers + Send + 'static>(
            &self,
            _id: <U64Artifact as IdentifiableArtifact>::Id,
            _artifact: Option<(U64Artifact, NodeId)>,
            _peers: P,
        ) -> AssembleResult<U64Artifact> {
            todo!()
        }
    }

    /// Verify that advert is sent to multiple peers.
    #[tokio::test]
    async fn send_transmit_to_all_peers() {
        with_test_replica_logger(|log| async {
            let (push_tx, mut push_rx) = tokio::sync::mpsc::unbounded_channel();
            let (tx, rx) = tokio::sync::mpsc::channel(100);

            let mut mock_transport = MockTransport::new();
            mock_transport
                .expect_peers()
                .return_const(vec![(NODE_1, ConnId::from(1)), (NODE_2, ConnId::from(2))]);
            mock_transport.expect_rpc().times(2).returning(move |n, _| {
                push_tx.send(*n).unwrap();
                Ok(Response::new("".into()))
            });

            let shutdown = ConsensusManagerSender::<U64Artifact, U64Artifact, _>::run(
                log,
                ConsensusManagerMetrics::new::<U64Artifact>(&MetricsRegistry::default()),
                Handle::current(),
                Arc::new(mock_transport),
                rx,
                IdentityAssembler,
            );

            tx.send(ArtifactTransmit::Deliver(ArtifactWithOpt {
                artifact: U64Artifact::id_to_msg(1, 1024),
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

            timeout(Duration::from_secs(5), shutdown.shutdown())
                .await
                .expect("ConsensusManagerSender did not terminate in time.")
        })
        .await
        .unwrap();
    }

    /// Verify that increasing connection id causes advert to be resent.
    #[tokio::test]
    async fn resend_advert_to_reconnected_peer() {
        with_test_replica_logger(|log| async {
            let (push_tx, mut push_rx) = tokio::sync::mpsc::unbounded_channel();
            let (tx, rx) = tokio::sync::mpsc::channel(100);

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
            mock_transport.expect_rpc().times(3).returning(move |n, _| {
                push_tx.send(*n).unwrap();
                Ok(Response::new("".into()))
            });

            let shutdown = ConsensusManagerSender::<U64Artifact, U64Artifact, _>::run(
                log,
                ConsensusManagerMetrics::new::<U64Artifact>(&MetricsRegistry::default()),
                Handle::current(),
                Arc::new(mock_transport),
                rx,
                IdentityAssembler,
            );

            tx.send(ArtifactTransmit::Deliver(ArtifactWithOpt {
                artifact: U64Artifact::id_to_msg(1, 1024),
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

            timeout(Duration::from_secs(5), shutdown.shutdown())
                .await
                .expect("ConsensusManagerSender did not terminate in time.")
        })
        .await
        .unwrap();
    }

    /// Verify failed send is retried.
    #[tokio::test]
    async fn retry_peer_error() {
        with_test_replica_logger(|log| async {
            let (push_tx, mut push_rx) = tokio::sync::mpsc::unbounded_channel();
            let (tx, rx) = tokio::sync::mpsc::channel(100);

            let mut mock_transport = MockTransport::new();
            let mut seq = Sequence::new();

            mock_transport
                .expect_peers()
                .return_const(vec![(NODE_1, ConnId::from(1))]);
            // Let transport push fail a few times.
            mock_transport
                .expect_rpc()
                .times(5)
                .returning(move |_, _| Err(P2PError::from("".to_string())))
                .in_sequence(&mut seq);
            mock_transport.expect_rpc().times(1).returning(move |n, _| {
                push_tx.send(*n).unwrap();
                Ok(Response::new("".into()))
            });

            let shutdown = ConsensusManagerSender::<U64Artifact, U64Artifact, _>::run(
                log,
                ConsensusManagerMetrics::new::<U64Artifact>(&MetricsRegistry::default()),
                Handle::current(),
                Arc::new(mock_transport),
                rx,
                IdentityAssembler,
            );

            tx.send(ArtifactTransmit::Deliver(ArtifactWithOpt {
                artifact: U64Artifact::id_to_msg(1, 1024),
                is_latency_sensitive: false,
            }))
            .await
            .unwrap();
            // Verify that we successfully retried.
            assert_eq!(push_rx.recv().await.unwrap(), NODE_1);

            timeout(Duration::from_secs(5), shutdown.shutdown())
                .await
                .expect("ConsensusManagerSender did not terminate in time.")
        })
        .await
        .unwrap();
    }

    /// Verify commit id increases with new adverts/purge events.
    #[tokio::test]
    async fn increasing_commit_id() {
        with_test_replica_logger(|log| async {
            let (commit_id_tx, mut commit_id_rx) = tokio::sync::mpsc::unbounded_channel();
            let (tx, rx) = tokio::sync::mpsc::channel(100);

            let mut mock_transport = MockTransport::new();

            mock_transport
                .expect_peers()
                .return_const(vec![(NODE_1, ConnId::from(1))]);
            mock_transport.expect_rpc().times(3).returning(move |_, r| {
                let pb_slot = pb::SlotUpdate::decode(&mut r.into_body()).unwrap();
                commit_id_tx.send(pb_slot.commit_id).unwrap();
                Ok(Response::new("".into()))
            });

            let shutdown = ConsensusManagerSender::<U64Artifact, U64Artifact, _>::run(
                log,
                ConsensusManagerMetrics::new::<U64Artifact>(&MetricsRegistry::default()),
                Handle::current(),
                Arc::new(mock_transport),
                rx,
                IdentityAssembler,
            );
            // Send advert and verify commit it.
            tx.send(ArtifactTransmit::Deliver(ArtifactWithOpt {
                artifact: U64Artifact::id_to_msg(1, 1024),
                is_latency_sensitive: false,
            }))
            .await
            .unwrap();
            assert_eq!(commit_id_rx.recv().await.unwrap(), 0);

            // Send second advert and observe commit id bump.
            tx.send(ArtifactTransmit::Deliver(ArtifactWithOpt {
                artifact: U64Artifact::id_to_msg(2, 1024),
                is_latency_sensitive: false,
            }))
            .await
            .unwrap();
            assert_eq!(commit_id_rx.recv().await.unwrap(), 1);
            // Send purge and new advert and observe commit id increase by 2.
            tx.send(ArtifactTransmit::Abort(2)).await.unwrap();
            tx.send(ArtifactTransmit::Deliver(ArtifactWithOpt {
                artifact: U64Artifact::id_to_msg(3, 1024),
                is_latency_sensitive: false,
            }))
            .await
            .unwrap();

            assert_eq!(commit_id_rx.recv().await.unwrap(), 3);
            timeout(Duration::from_secs(5), shutdown.shutdown())
                .await
                .expect("ConsensusManagerSender did not terminate in time.")
        })
        .await
        .unwrap();
    }

    /// Verify that duplicate Advert event does not cause sending twice.
    #[tokio::test]
    async fn send_same_advert_twice() {
        with_test_replica_logger(|log| async {
            let (commit_id_tx, mut commit_id_rx) = tokio::sync::mpsc::unbounded_channel();
            let (tx, rx) = tokio::sync::mpsc::channel(100);

            let mut mock_transport = MockTransport::new();

            mock_transport
                .expect_peers()
                .return_const(vec![(NODE_1, ConnId::from(1))]);
            mock_transport.expect_rpc().times(2).returning(move |_, r| {
                let pb_slot = pb::SlotUpdate::decode(&mut r.into_body()).unwrap();
                commit_id_tx.send(pb_slot.commit_id).unwrap();
                Ok(Response::new("".into()))
            });

            let shutdown = ConsensusManagerSender::<U64Artifact, U64Artifact, _>::run(
                log,
                ConsensusManagerMetrics::new::<U64Artifact>(&MetricsRegistry::default()),
                Handle::current(),
                Arc::new(mock_transport),
                rx,
                IdentityAssembler,
            );

            // Send advert and verify commit id.
            tx.send(ArtifactTransmit::Deliver(ArtifactWithOpt {
                artifact: U64Artifact::id_to_msg(1, 1024),
                is_latency_sensitive: false,
            }))
            .await
            .unwrap();
            assert_eq!(commit_id_rx.recv().await.unwrap(), 0);

            // Send same advert again. This should be noop.
            tx.send(ArtifactTransmit::Deliver(ArtifactWithOpt {
                artifact: U64Artifact::id_to_msg(1, 1024),
                is_latency_sensitive: false,
            }))
            .await
            .unwrap();

            // Check that new advert is advertised with correct commit id.
            tx.send(ArtifactTransmit::Deliver(ArtifactWithOpt {
                artifact: U64Artifact::id_to_msg(2, 1024),
                is_latency_sensitive: false,
            }))
            .await
            .unwrap();

            assert_eq!(commit_id_rx.recv().await.unwrap(), 2);

            timeout(Duration::from_secs(5), shutdown.shutdown())
                .await
                .expect("ConsensusManagerSender did not terminate in time.")
        })
        .await
        .unwrap();
    }

    /// Verify that a panic happening in one of the tasks spawned by the ConsensusManagerSender
    /// is propagated when awaiting on [`ConsensusManagerSender::run`].
    ///
    // This test is ignored because the panic is caught in the panic hook set in /consensus_manager/receiver.rs
    #[ignore]
    #[tokio::test]
    async fn panic_in_task_is_propagated() {
        with_test_replica_logger(|log| async {
        let (tx, rx) = tokio::sync::mpsc::channel(100);

            let mut mock_transport = MockTransport::new();

            mock_transport
                .expect_peers()
                .return_const(vec![(NODE_1, ConnId::from(1))]);

            // We don't create an expectation for `push` here, so that we can trigger a panic
            mock_transport
                .expect_rpc()
                .times(2)
                .returning(move |_, _| {
                    panic!("Panic in mock transport expectation.");
                });

            let shutdown = ConsensusManagerSender::<U64Artifact, U64Artifact, _>::run(
                log,
                ConsensusManagerMetrics::new::<U64Artifact>(&MetricsRegistry::default()),
                Handle::current(),
                Arc::new(mock_transport),
                rx,
                IdentityAssembler,
            );

        tx.send(ArtifactTransmit::Deliver(ArtifactWithOpt {
            artifact: U64Artifact::id_to_msg(1, 1024),
            is_latency_sensitive: false,
        }))
        .await
        .unwrap();

        timeout(Duration::from_secs(5), shutdown.shutdown())
            .await
            .expect("ConsensusManagerSender should terminate since the downstream service `transport` panicked.")
            .unwrap();

        //assert!(join_error.is_panic(), "The join error should be a panic.");
    }).await
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
        let mut used_slots = Vec::new();
        for i in 0..(SLOT_TABLE_THRESHOLD * 5) {
            let new_slot = sm.pop();
            assert_eq!(new_slot.slot_number(), SlotNumber::from(i));
            used_slots.push(new_slot);
        }
        // Give back all the slots.
        for slot in used_slots {
            sm.push(slot);
        }
        // Check that we get the slot that was returned last
        assert_eq!(
            sm.pop().slot_number(),
            SlotNumber::from(SLOT_TABLE_THRESHOLD * 5 - 1)
        );
    }
}
