#![allow(clippy::disallowed_methods)]

use std::collections::{hash_map::Entry, HashMap, HashSet};

use crate::{
    metrics::{
        ConsensusManagerMetrics, ASSEMBLE_TASK_RESULT_ALL_PEERS_DELETED,
        ASSEMBLE_TASK_RESULT_COMPLETED, ASSEMBLE_TASK_RESULT_DROP,
    },
    uri_prefix, CommitId, SlotNumber, SlotUpdate, Update,
};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::IntoResponse,
    routing::any,
    Extension, Router,
};
use bytes::Bytes;
use ic_base_types::NodeId;
use ic_interfaces::p2p::consensus::{Aborted, ArtifactAssembler, Peers};
use ic_logger::{error, warn, ReplicaLogger};
use ic_protobuf::p2p::v1 as pb;
use ic_quic_transport::{ConnId, Shutdown, SubnetTopology};
use ic_types::artifact::{IdentifiableArtifact, PbArtifact, UnvalidatedArtifactMutation};
use prost::{DecodeError, Message};
use tokio::{
    runtime::Handle,
    select,
    sync::{
        mpsc::{Receiver, Sender, UnboundedSender},
        watch,
    },
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use tracing::instrument;

type ReceivedAdvertSender<A> = Sender<(SlotUpdate<A>, NodeId, ConnId)>;

#[allow(unused)]
pub fn build_axum_router<Artifact: PbArtifact>(
    log: ReplicaLogger,
) -> (Router, Receiver<(SlotUpdate<Artifact>, NodeId, ConnId)>) {
    let (update_tx, update_rx) = tokio::sync::mpsc::channel(100);
    let router = Router::new()
        .route(
            &format!("/{}/update", uri_prefix::<Artifact>()),
            any(update_handler),
        )
        .with_state((log, update_tx))
        // Disable request size limit since consensus might push artifacts larger than limit.
        .layer(DefaultBodyLimit::disable());

    (router, update_rx)
}

enum UpdateHandlerError<Artifact: PbArtifact> {
    SlotUpdateDecoding(DecodeError),
    IdDecoding(DecodeError),
    IdPbConversion(Artifact::PbIdError),
    MessageDecoding(DecodeError),
    MessagePbConversion(Artifact::PbMessageError),
    MissingUpdate,
}

impl<Artifact: PbArtifact> IntoResponse for UpdateHandlerError<Artifact> {
    fn into_response(self) -> axum::response::Response {
        let r = match self {
            Self::SlotUpdateDecoding(e) => (StatusCode::BAD_REQUEST, e.to_string()),
            Self::IdDecoding(e) => (StatusCode::BAD_REQUEST, e.to_string()),
            Self::IdPbConversion(e) => (StatusCode::BAD_REQUEST, e.to_string()),
            Self::MessageDecoding(e) => (StatusCode::BAD_REQUEST, e.to_string()),
            Self::MessagePbConversion(e) => (StatusCode::BAD_REQUEST, e.to_string()),
            Self::MissingUpdate => (StatusCode::BAD_REQUEST, "Missing update field".to_string()),
        };
        r.into_response()
    }
}

async fn update_handler<Artifact: PbArtifact>(
    State((log, sender)): State<(ReplicaLogger, ReceivedAdvertSender<Artifact>)>,
    Extension(peer): Extension<NodeId>,
    Extension(conn_id): Extension<ConnId>,
    payload: Bytes,
) -> Result<(), UpdateHandlerError<Artifact>> {
    let pb_slot_update = pb::SlotUpdate::decode(payload)
        .map_err(|e| UpdateHandlerError::SlotUpdateDecoding::<Artifact>(e))?;

    let update = SlotUpdate {
        commit_id: CommitId::from(pb_slot_update.commit_id),
        slot_number: SlotNumber::from(pb_slot_update.slot_id),
        update: match pb_slot_update.update {
            Some(pb::slot_update::Update::Id(id)) => {
                let id: Artifact::Id = Artifact::PbId::decode(id.as_slice())
                    .map_err(|e| UpdateHandlerError::IdDecoding(e))
                    .and_then(|pb_id| {
                        pb_id
                            .try_into()
                            .map_err(|e| UpdateHandlerError::IdPbConversion(e))
                    })?;
                Update::Id(id)
            }
            Some(pb::slot_update::Update::Artifact(artifact)) => {
                let message: Artifact = Artifact::PbMessage::decode(artifact.as_slice())
                    .map_err(|e| UpdateHandlerError::MessageDecoding(e))
                    .and_then(|pb_msg| {
                        pb_msg
                            .try_into()
                            .map_err(|e| UpdateHandlerError::MessagePbConversion(e))
                    })?;
                Update::Artifact(message)
            }
            None => return Err(UpdateHandlerError::MissingUpdate),
        },
    };

    if sender.send((update, peer, conn_id)).await.is_err() {
        error!(
            log,
            "Failed to send advert update from handler to event loop"
        )
    }

    Ok(())
}

#[derive(Debug)]
pub struct PeerCounter(HashMap<NodeId, u32>);

impl PeerCounter {
    pub(crate) fn new() -> Self {
        Self(HashMap::new())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn peers(&self) -> impl Iterator<Item = &NodeId> {
        self.0.keys()
    }

    /// Returns true if value is newly inserted
    pub(crate) fn insert(&mut self, node: NodeId) -> bool {
        match self.0.entry(node) {
            Entry::Occupied(mut entry) => {
                *entry.get_mut() += 1;
                false
            }
            Entry::Vacant(entry) => {
                entry.insert(1);
                true
            }
        }
    }

    /// Returns true if removed key was present and counter got to zero
    pub(crate) fn remove(&mut self, node: NodeId) -> bool {
        match self.0.entry(node) {
            Entry::Occupied(mut entry) => {
                assert!(*entry.get() != 0);

                if *entry.get() == 1 {
                    entry.remove();
                    true
                } else {
                    *entry.get_mut() -= 1;
                    false
                }
            }
            Entry::Vacant(_) => false,
        }
    }
}

#[allow(unused)]
pub(crate) struct ConsensusManagerReceiver<
    Artifact: IdentifiableArtifact,
    WireArtifact: IdentifiableArtifact,
    Assembler,
    ReceivedAdvert,
> {
    log: ReplicaLogger,
    metrics: ConsensusManagerMetrics,
    rt_handle: Handle,

    // Receive side:
    adverts_received: Receiver<ReceivedAdvert>,
    sender: UnboundedSender<UnvalidatedArtifactMutation<Artifact>>,
    artifact_assembler: Assembler,

    slot_table: HashMap<NodeId, HashMap<SlotNumber, SlotEntry<WireArtifact::Id>>>,
    active_assembles: HashMap<WireArtifact::Id, watch::Sender<PeerCounter>>,

    #[allow(clippy::type_complexity)]
    artifact_processor_tasks: JoinSet<(watch::Receiver<PeerCounter>, WireArtifact::Id)>,

    topology_watcher: watch::Receiver<SubnetTopology>,
}

#[allow(unused)]
impl<Artifact, WireArtifact, Assembler>
    ConsensusManagerReceiver<
        Artifact,
        WireArtifact,
        Assembler,
        (SlotUpdate<WireArtifact>, NodeId, ConnId),
    >
where
    Artifact: IdentifiableArtifact,
    WireArtifact: PbArtifact,
    Assembler: ArtifactAssembler<Artifact, WireArtifact>,
{
    pub(crate) fn run(
        log: ReplicaLogger,
        metrics: ConsensusManagerMetrics,
        rt_handle: Handle,
        adverts_received: Receiver<(SlotUpdate<WireArtifact>, NodeId, ConnId)>,
        artifact_assembler: Assembler,
        sender: UnboundedSender<UnvalidatedArtifactMutation<Artifact>>,
        topology_watcher: watch::Receiver<SubnetTopology>,
    ) -> Shutdown {
        let receive_manager = Self {
            log,
            metrics,
            rt_handle: rt_handle.clone(),
            adverts_received,
            artifact_assembler,
            sender,
            active_assembles: HashMap::new(),
            slot_table: HashMap::new(),
            artifact_processor_tasks: JoinSet::new(),
            topology_watcher,
        };

        Shutdown::spawn_on_with_cancellation(
            |cancellation| receive_manager.start_event_loop(cancellation),
            &rt_handle,
        )
    }

    /// Event loop that processes advert updates and artifact assembles.
    /// The event loop preserves the invariants checked with `debug_assert`.
    async fn start_event_loop(mut self, cancellation_token: CancellationToken) {
        loop {
            select! {
                _ = cancellation_token.cancelled() => {
                    error!(
                        self.log,
                        "Sender event loop for the P2P client `{:?}` terminated. No more adverts will be sent for this client.",
                        uri_prefix::<WireArtifact>()
                    );
                    break;
                }
                Some((advert_update, peer_id, conn_id)) = self.adverts_received.recv() => {
                    self.handle_advert_receive(advert_update, peer_id, conn_id, cancellation_token.clone());
                }
                Some(result) = self.artifact_processor_tasks.join_next() => {
                    match result {
                        Ok((receiver, id)) => {
                            self.handle_artifact_processor_joined(receiver, id, cancellation_token.clone());

                        }
                        Err(err) => {
                            // If the task panics we propagate the panic. But we allow tasks to be canceled.
                            // Task can be cancelled if someone calls .abort()
                            if err.is_panic() {
                                std::panic::resume_unwind(err.into_panic());
                            }
                        }
                    }
                }
                Ok(()) = self.topology_watcher.changed() => {
                    self.handle_topology_update();
                }
            }
            debug_assert_eq!(
                self.active_assembles.len(),
                self.artifact_processor_tasks.len(),
                "Number of artifact processing tasks differs from the available number of channels that communicate with the processing tasks"
            );
            debug_assert!(
                self.artifact_processor_tasks.len()
                    >= HashSet::<WireArtifact::Id>::from_iter(
                        self.slot_table
                            .iter()
                            .flat_map(|(k, v)| v.iter())
                            .map(|(_, s)| s.id.clone())
                    )
                    .len(),
                "Number of assemble tasks should always be the same or exceed the number of distinct ids stored."
            );
        }
    }

    pub(crate) fn handle_artifact_processor_joined(
        &mut self,
        peer_rx: watch::Receiver<PeerCounter>,
        id: WireArtifact::Id,
        cancellation_token: CancellationToken,
    ) {
        self.metrics.assemble_task_finished_total.inc();
        // Invariant: Peer sender should only be dropped in this task..
        debug_assert!(peer_rx.has_changed().is_ok());

        // peer advertised after task finished.
        if !peer_rx.borrow().is_empty() {
            self.metrics.assemble_task_restart_after_join_total.inc();
            self.metrics.assemble_task_started_total.inc();
            self.artifact_processor_tasks.spawn_on(
                Self::process_advert(
                    self.log.clone(),
                    id,
                    None,
                    peer_rx,
                    self.sender.clone(),
                    self.artifact_assembler.clone(),
                    self.metrics.clone(),
                    cancellation_token.clone(),
                ),
                &self.rt_handle,
            );
        } else {
            self.active_assembles.remove(&id);
        }
        debug_assert!(
            self.slot_table
                .iter()
                .flat_map(|(k, v)| v.iter())
                .all(|(k, v)| self.active_assembles.contains_key(&v.id)),
            "Every entry in the slot table should have an active assemble task."
        );
    }

    #[instrument(skip_all)]
    pub(crate) fn handle_advert_receive(
        &mut self,
        advert_update: SlotUpdate<WireArtifact>,
        peer_id: NodeId,
        connection_id: ConnId,
        cancellation_token: CancellationToken,
    ) {
        self.metrics.slot_table_updates_total.inc();
        let SlotUpdate {
            slot_number,
            commit_id,
            update,
        } = advert_update;

        let (id, artifact) = match update {
            Update::Artifact(artifact) => (artifact.id(), Some(artifact)),
            Update::Id(id) => (id, None),
        };

        if artifact.is_some() {
            self.metrics.slot_table_updates_with_artifact_total.inc();
        }

        let new_slot_entry: SlotEntry<WireArtifact::Id> = SlotEntry {
            commit_id,
            conn_id: connection_id,
            id: id.clone(),
        };

        let (to_add, to_remove) = match self
            .slot_table
            .entry(peer_id)
            .or_default()
            .entry(slot_number)
        {
            Entry::Occupied(mut slot_entry_mut) => {
                if slot_entry_mut.get().should_be_replaced(&new_slot_entry) {
                    self.metrics.slot_table_overwrite_total.inc();
                    let to_remove = slot_entry_mut.insert(new_slot_entry).id;
                    (true, Some(to_remove))
                } else {
                    self.metrics.slot_table_stale_total.inc();
                    (false, None)
                }
            }
            Entry::Vacant(empty_slot) => {
                empty_slot.insert(new_slot_entry);
                self.metrics
                    .slot_table_new_entry_total
                    .with_label_values(&[peer_id.to_string().as_str()])
                    .inc();
                (true, None)
            }
        };

        if to_add {
            match self.active_assembles.get(&id) {
                Some(sender) => {
                    self.metrics.slot_table_seen_id_total.inc();
                    sender.send_if_modified(|h| h.insert(peer_id));
                }
                None => {
                    self.metrics.assemble_task_started_total.inc();

                    let mut peer_counter = PeerCounter::new();
                    let (tx, rx) = watch::channel(peer_counter);
                    tx.send_if_modified(|h| h.insert(peer_id));
                    self.active_assembles.insert(id.clone(), tx);

                    self.artifact_processor_tasks.spawn_on(
                        Self::process_advert(
                            self.log.clone(),
                            id.clone(),
                            artifact.map(|a| (a, peer_id)),
                            rx,
                            self.sender.clone(),
                            self.artifact_assembler.clone(),
                            self.metrics.clone(),
                            cancellation_token.clone(),
                        ),
                        &self.rt_handle,
                    );
                }
            }
        }

        if let Some(to_remove) = to_remove {
            match self.active_assembles.get_mut(&to_remove) {
                Some(sender) => {
                    sender.send_if_modified(|h| h.remove(peer_id));
                    self.metrics.slot_table_removals_total.inc();
                }
                None => {
                    error!(
                        self.log,
                        "Slot table contains an artifact ID that is not present in the `active_assembles`. This should never happen."
                    );
                    if cfg!(debug_assertions) {
                        panic!("Invariant violated");
                    }
                }
            };
        }
    }

    /// Tries to assemble the given artifact, and insert it into the unvalidated pool.
    ///
    /// This future waits for all peers that advertise the artifact to delete it.
    /// The artifact is deleted from the unvalidated pool upon completion.
    #[instrument(skip_all)]
    async fn process_advert(
        log: ReplicaLogger,
        id: WireArtifact::Id,
        // Only first peer for specific artifact ID is considered for push
        mut artifact: Option<(WireArtifact, NodeId)>,
        mut peer_rx: watch::Receiver<PeerCounter>,
        sender: UnboundedSender<UnvalidatedArtifactMutation<Artifact>>,
        mut artifact_assembler: Assembler,
        metrics: ConsensusManagerMetrics,
        cancellation_token: CancellationToken,
    ) -> (watch::Receiver<PeerCounter>, WireArtifact::Id) {
        let _timer = metrics.assemble_task_duration.start_timer();

        let mut peer_rx_clone = peer_rx.clone();
        let all_peers_deleted_artifact = async move {
            loop {
                match peer_rx_clone.changed().await {
                    Err(_) => break,
                    Ok(x) if peer_rx_clone.borrow().is_empty() => break,
                    _ => {}
                }
            }
        };

        let mut peer_rx_c = peer_rx.clone();
        let id_c = id.clone();
        let assemble_artifact = async move {
            artifact_assembler
                .assemble_message(id, artifact, PeerWatcher::new(peer_rx_c))
                .await
        };

        select! {
            assemble_result = assemble_artifact => {
                match assemble_result {
                    Ok((artifact, peer_id)) => {
                        let id = artifact.id();
                        // Send artifact to pool
                        sender.send(UnvalidatedArtifactMutation::Insert((artifact, peer_id)));

                        // wait for deletion from peers
                        peer_rx.wait_for(|p| p.is_empty()).await;

                        // Purge from the unvalidated pool
                        sender.send(UnvalidatedArtifactMutation::Remove(id));
                        metrics
                            .assemble_task_result_total
                            .with_label_values(&[ASSEMBLE_TASK_RESULT_COMPLETED])
                            .inc();
                    }
                    Err(Aborted) => {
                        // wait for deletion from peers
                        peer_rx.wait_for(|p| p.is_empty()).await;
                        metrics
                            .assemble_task_result_total
                            .with_label_values(&[ASSEMBLE_TASK_RESULT_DROP])
                            .inc();

                    },
                }
            }
            _ = cancellation_token.cancelled() => {
            }
            _ = all_peers_deleted_artifact => {
                metrics
                    .assemble_task_result_total
                    .with_label_values(&[ASSEMBLE_TASK_RESULT_ALL_PEERS_DELETED])
                    .inc();
            },
        };

        (peer_rx, id_c)
    }

    /// Notifies all running tasks about the topology update.
    fn handle_topology_update(&mut self) {
        self.metrics.topology_updates_total.inc();
        let new_topology = self.topology_watcher.borrow().clone();
        let mut nodes_leaving_topology = HashSet::new();

        self.slot_table.retain(|node_id, _| {
            if !new_topology.is_member(node_id) {
                nodes_leaving_topology.insert(*node_id);
                self.metrics
                    .slot_table_new_entry_total
                    .remove_label_values(&[node_id.to_string().as_str()]);
                false
            } else {
                true
            }
        });

        for peers_sender in self.active_assembles.values() {
            peers_sender.send_if_modified(|set| {
                nodes_leaving_topology
                    .iter()
                    .map(|n| set.remove(*n))
                    .any(|r| r)
            });
        }
        debug_assert!(
            self.slot_table.len() <= self.topology_watcher.borrow().iter().count(),
            "Slot table contains more nodes than nodes in subnet after pruning"
        );
    }
}

struct PeerWatcher(watch::Receiver<PeerCounter>);

impl PeerWatcher {
    pub fn new(w: watch::Receiver<PeerCounter>) -> Self {
        Self(w)
    }
}

impl Peers for PeerWatcher {
    fn peers(&self) -> Vec<NodeId> {
        self.0.borrow().peers().cloned().collect()
    }
}

#[derive(PartialEq, Eq, Debug)]
struct SlotEntry<T> {
    conn_id: ConnId,
    commit_id: CommitId,
    id: T,
}

impl<T> SlotEntry<T> {
    fn should_be_replaced(&self, other: &SlotEntry<T>) -> bool {
        if other.conn_id != self.conn_id {
            return other.conn_id > self.conn_id;
        }
        // connection ids are the same
        other.commit_id > self.commit_id
    }
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, time::Duration};

    use axum::{body::Body, http::Request};
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_p2p_test_utils::{consensus::U64Artifact, mocks::MockArtifactAssembler};
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_types::{artifact::IdentifiableArtifact, RegistryVersion};
    use ic_types_test_utils::ids::{NODE_1, NODE_2};
    use tokio::{sync::mpsc::UnboundedReceiver, time::timeout};
    use tower::util::ServiceExt;

    use super::*;

    const PROCESS_ARTIFACT_TIMEOUT: Duration = Duration::from_millis(1000);

    struct ReceiverManagerBuilder {
        // Adverts received from peers
        adverts_received: Receiver<(SlotUpdate<U64Artifact>, NodeId, ConnId)>,
        sender: UnboundedSender<UnvalidatedArtifactMutation<U64Artifact>>,
        artifact_assembler: MockArtifactAssembler,
        topology_watcher: watch::Receiver<SubnetTopology>,

        channels: Channels,
    }

    type ConsensusManagerReceiverForTest = ConsensusManagerReceiver<
        U64Artifact,
        U64Artifact,
        MockArtifactAssembler,
        (SlotUpdate<U64Artifact>, NodeId, ConnId),
    >;

    struct Channels {
        unvalidated_artifact_receiver: UnboundedReceiver<UnvalidatedArtifactMutation<U64Artifact>>,
    }

    impl ReceiverManagerBuilder {
        fn make_mock_artifact_assembler_with_clone(
            make_mock: fn() -> MockArtifactAssembler,
        ) -> MockArtifactAssembler {
            let mut assembler = make_mock();
            assembler
                .expect_clone()
                .returning(move || Self::make_mock_artifact_assembler_with_clone(make_mock));
            assembler
        }

        fn new() -> Self {
            let (_, adverts_received) = tokio::sync::mpsc::channel(100);
            let (sender, unvalidated_artifact_receiver) = tokio::sync::mpsc::unbounded_channel();
            let (_, topology_watcher) = watch::channel(SubnetTopology::default());
            let artifact_assembler =
                Self::make_mock_artifact_assembler_with_clone(MockArtifactAssembler::default);

            Self {
                adverts_received,
                sender,
                topology_watcher,
                artifact_assembler,
                channels: Channels {
                    unvalidated_artifact_receiver,
                },
            }
        }

        fn with_topology_watcher(
            mut self,
            topology_watcher: watch::Receiver<SubnetTopology>,
        ) -> Self {
            self.topology_watcher = topology_watcher;
            self
        }

        fn with_artifact_assembler_maker(
            mut self,
            make_mock: fn() -> MockArtifactAssembler,
        ) -> Self {
            self.artifact_assembler = Self::make_mock_artifact_assembler_with_clone(make_mock);
            self
        }

        fn build(self) -> (ConsensusManagerReceiverForTest, Channels) {
            let consensus_manager_receiver =
                with_test_replica_logger(|log| ConsensusManagerReceiver {
                    log,
                    metrics: ConsensusManagerMetrics::new::<U64Artifact>(
                        &MetricsRegistry::default(),
                    ),
                    rt_handle: Handle::current(),
                    adverts_received: self.adverts_received,
                    sender: self.sender,
                    artifact_assembler: self.artifact_assembler,
                    topology_watcher: self.topology_watcher,
                    active_assembles: HashMap::new(),
                    slot_table: HashMap::new(),
                    artifact_processor_tasks: JoinSet::new(),
                });

            (consensus_manager_receiver, self.channels)
        }
    }

    /// Check that all variants of stale adverts to not get added to the slot table.
    #[tokio::test]
    async fn receiving_stale_advert_updates() {
        let (mut mgr, _channels) = ReceiverManagerBuilder::new().build();

        let cancellation = CancellationToken::new();
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(1),
                update: Update::Id(0),
            },
            NODE_1,
            ConnId::from(1),
            cancellation.clone(),
        );
        assert_eq!(
            mgr.slot_table
                .get(&NODE_1)
                .unwrap()
                .get(&SlotNumber::from(1))
                .unwrap(),
            &SlotEntry {
                conn_id: ConnId::from(1),
                commit_id: CommitId::from(1),
                id: 0,
            }
        );
        assert_eq!(mgr.slot_table.len(), 1);
        assert_eq!(mgr.slot_table.get(&NODE_1).unwrap().len(), 1);
        assert_eq!(mgr.active_assembles.len(), 1);
        assert_eq!(mgr.artifact_processor_tasks.len(), 1);
        // Send stale advert with lower commit id.
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(0),
                update: Update::Id(0),
            },
            NODE_1,
            ConnId::from(1),
            cancellation.clone(),
        );
        // Check that slot table did not get updated.
        assert_eq!(
            mgr.slot_table
                .get(&NODE_1)
                .unwrap()
                .get(&SlotNumber::from(1))
                .unwrap(),
            &SlotEntry {
                conn_id: ConnId::from(1),
                commit_id: CommitId::from(1),
                id: 0,
            }
        );
        // Send stale advert with lower conn id
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(0),
                update: Update::Id(0),
            },
            NODE_1,
            ConnId::from(0),
            cancellation.clone(),
        );
        // Check that slot table did not get updated.
        assert_eq!(
            mgr.slot_table
                .get(&NODE_1)
                .unwrap()
                .get(&SlotNumber::from(1))
                .unwrap(),
            &SlotEntry {
                conn_id: ConnId::from(1),
                commit_id: CommitId::from(1),
                id: 0,
            }
        );
        // Send stale advert with lower conn id but higher commit id
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(10),
                update: Update::Id(0),
            },
            NODE_1,
            ConnId::from(0),
            cancellation.clone(),
        );
        // Check that slot table did not get updated.
        assert_eq!(
            mgr.slot_table
                .get(&NODE_1)
                .unwrap()
                .get(&SlotNumber::from(1))
                .unwrap(),
            &SlotEntry {
                conn_id: ConnId::from(1),
                commit_id: CommitId::from(1),
                id: 0,
            }
        );
        // Send stale advert with lower conn id and lower commit id
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(0),
                update: Update::Id(0),
            },
            NODE_1,
            ConnId::from(0),
            cancellation.clone(),
        );
        // Check that slot table did not get updated.
        assert_eq!(
            mgr.slot_table
                .get(&NODE_1)
                .unwrap()
                .get(&SlotNumber::from(1))
                .unwrap(),
            &SlotEntry {
                conn_id: ConnId::from(1),
                commit_id: CommitId::from(1),
                id: 0,
            }
        );
        assert_eq!(mgr.slot_table.len(), 1);
        assert_eq!(mgr.slot_table.get(&NODE_1).unwrap().len(), 1);
        assert_eq!(mgr.active_assembles.len(), 1);
        assert_eq!(mgr.artifact_processor_tasks.len(), 1);
    }

    /// Check that adverts updates with higher connection ids take precedence.
    #[tokio::test]
    async fn overwrite_slot1() {
        fn make_artifact_assembler() -> MockArtifactAssembler {
            let mut artifact_assembler = MockArtifactAssembler::default();
            artifact_assembler
                .expect_assemble_message()
                .returning(|id, _, _: PeerWatcher| {
                    Box::pin(async move { Ok((U64Artifact::id_to_msg(id, 100), NODE_1)) })
                });
            artifact_assembler
        }
        let (mut mgr, _channels) = ReceiverManagerBuilder::new()
            .with_artifact_assembler_maker(make_artifact_assembler)
            .build();
        let cancellation = CancellationToken::new();
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(1),
                update: Update::Id(0),
            },
            NODE_1,
            ConnId::from(1),
            cancellation.clone(),
        );
        // Verify that advert is correctly inserted into slot table.
        assert_eq!(
            mgr.slot_table
                .get(&NODE_1)
                .unwrap()
                .get(&SlotNumber::from(1))
                .unwrap(),
            &SlotEntry {
                conn_id: ConnId::from(1),
                commit_id: CommitId::from(1),
                id: 0,
            }
        );
        assert_eq!(mgr.slot_table.len(), 1);
        assert_eq!(mgr.slot_table.get(&NODE_1).unwrap().len(), 1);
        assert_eq!(mgr.active_assembles.len(), 1);
        assert_eq!(mgr.artifact_processor_tasks.len(), 1);
        // Send advert with higher conn id.
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(0),
                update: Update::Id(1),
            },
            NODE_1,
            ConnId::from(2),
            cancellation.clone(),
        );
        // Verify that slot table now only contains newer entry.
        assert_eq!(
            mgr.slot_table
                .get(&NODE_1)
                .unwrap()
                .get(&SlotNumber::from(1))
                .unwrap(),
            &SlotEntry {
                conn_id: ConnId::from(2),
                commit_id: CommitId::from(0),
                id: 1,
            }
        );
        assert_eq!(mgr.slot_table.len(), 1);
        assert_eq!(mgr.slot_table.get(&NODE_1).unwrap().len(), 1);

        let joined_artifact_processor = mgr.artifact_processor_tasks.join_next().await;

        let result = joined_artifact_processor
            .expect("Joining artifact processor task failed")
            .expect("Artifact processor task panicked");

        // Check that assemble task for first advert closes.
        assert_eq!(result.1, 0);
    }

    /// Check that adverts updates with higher connection ids take precedence.
    #[tokio::test]
    async fn overwrite_slot_send_remove() {
        fn make_artifact_assembler() -> MockArtifactAssembler {
            let mut artifact_assembler = MockArtifactAssembler::default();
            artifact_assembler
                .expect_assemble_message()
                .returning(|id, _, _: PeerWatcher| {
                    Box::pin(async move { Ok((U64Artifact::id_to_msg(id, 100), NODE_1)) })
                });
            artifact_assembler
        }
        let (mut mgr, mut channels) = ReceiverManagerBuilder::new()
            .with_artifact_assembler_maker(make_artifact_assembler)
            .build();
        let cancellation = CancellationToken::new();
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(1),
                update: Update::Id(0),
            },
            NODE_1,
            ConnId::from(1),
            cancellation.clone(),
        );
        // Verify that advert is correctly inserted into slot table.
        assert_eq!(
            mgr.slot_table
                .get(&NODE_1)
                .unwrap()
                .get(&SlotNumber::from(1))
                .unwrap(),
            &SlotEntry {
                conn_id: ConnId::from(1),
                commit_id: CommitId::from(1),
                id: 0,
            }
        );
        assert_eq!(mgr.slot_table.len(), 1);
        assert_eq!(mgr.slot_table.get(&NODE_1).unwrap().len(), 1);
        assert_eq!(mgr.active_assembles.len(), 1);
        assert_eq!(mgr.artifact_processor_tasks.len(), 1);
        assert_eq!(
            channels.unvalidated_artifact_receiver.recv().await.unwrap(),
            UnvalidatedArtifactMutation::Insert((U64Artifact::id_to_msg(0, 100), NODE_1))
        );

        // Send advert with higher conn id.
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(0),
                update: Update::Id(1),
            },
            NODE_1,
            ConnId::from(2),
            cancellation.clone(),
        );
        // Verify that slot table now only contains newer entry.
        assert_eq!(
            mgr.slot_table
                .get(&NODE_1)
                .unwrap()
                .get(&SlotNumber::from(1))
                .unwrap(),
            &SlotEntry {
                conn_id: ConnId::from(2),
                commit_id: CommitId::from(0),
                id: 1,
            }
        );
        assert_eq!(mgr.slot_table.len(), 1);
        assert_eq!(mgr.slot_table.get(&NODE_1).unwrap().len(), 1);

        let joined_artifact_processor = mgr.artifact_processor_tasks.join_next().await;
        let result = joined_artifact_processor
            .expect("Joining artifact processor task failed")
            .expect("Artifact processor task panicked");
        let receiver_unvalidated_1 = channels.unvalidated_artifact_receiver.recv().await.unwrap();
        let receiver_unvalidated_2 = channels.unvalidated_artifact_receiver.recv().await.unwrap();
        assert!(
            (receiver_unvalidated_1
                == UnvalidatedArtifactMutation::Insert((U64Artifact::id_to_msg(1, 100), NODE_1))
                && receiver_unvalidated_2 == UnvalidatedArtifactMutation::Remove(0))
                || (receiver_unvalidated_2
                    == UnvalidatedArtifactMutation::Insert((
                        U64Artifact::id_to_msg(1, 100),
                        NODE_1
                    ))
                    && receiver_unvalidated_1 == UnvalidatedArtifactMutation::Remove(0))
        );

        // Check that assemble task for first advert closes.
        assert_eq!(result.1, 0);
    }

    /// Verify that if two peers advertise the same advert it will get added to the same assemble task.
    #[tokio::test]
    async fn two_peers_advertise_same_advert() {
        let (mut mgr, _channels) = ReceiverManagerBuilder::new().build();
        let cancellation = CancellationToken::new();
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(1),
                update: Update::Id(0),
            },
            NODE_1,
            ConnId::from(1),
            cancellation.clone(),
        );
        // Second advert for advert 0.
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(1),
                update: Update::Id(0),
            },
            NODE_2,
            ConnId::from(1),
            cancellation.clone(),
        );
        // Verify that we only have one assemble task.
        assert_eq!(mgr.slot_table.len(), 2);
        assert_eq!(mgr.slot_table.get(&NODE_1).unwrap().len(), 1);
        assert_eq!(mgr.slot_table.get(&NODE_2).unwrap().len(), 1);
        assert_eq!(mgr.active_assembles.len(), 1);
    }

    /// Verify that a new assemble task is started if we receive a new update for an already finished assemble.
    #[tokio::test]
    async fn new_advert_while_assemble_finished() {
        fn make_artifact_assembler() -> MockArtifactAssembler {
            let mut artifact_assembler = MockArtifactAssembler::default();
            artifact_assembler
                .expect_assemble_message()
                .returning(|id, _, _: PeerWatcher| {
                    Box::pin(async move { Ok((U64Artifact::id_to_msg(id, 100), NODE_1)) })
                });
            artifact_assembler
        }
        let (mut mgr, _channels) = ReceiverManagerBuilder::new()
            .with_artifact_assembler_maker(make_artifact_assembler)
            .build();
        let cancellation = CancellationToken::new();
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(1),
                update: Update::Id(0),
            },
            NODE_1,
            ConnId::from(1),
            cancellation.clone(),
        );
        // Overwrite advert to close the assemble task.
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(2),
                update: Update::Id(1),
            },
            NODE_1,
            ConnId::from(1),
            cancellation.clone(),
        );
        // Check that the assemble task is closed.
        let (peer_rx, id) = mgr
            .artifact_processor_tasks
            .join_next()
            .await
            .unwrap()
            .unwrap();
        // Simulate that a new peer was added for this advert while closing.
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(3),
                update: Update::Id(0),
            },
            NODE_2,
            ConnId::from(1),
            cancellation.clone(),
        );
        assert_eq!(mgr.active_assembles.len(), 2);
        // Verify that we reopened the assemble task for advert 0.
        mgr.handle_artifact_processor_joined(peer_rx, id, cancellation.clone());
        assert_eq!(mgr.active_assembles.len(), 2);
    }

    /// Verify that slot table is pruned if node leaves subnet.
    #[tokio::test]
    async fn topology_update() {
        let (pfn_tx, pfn_rx) = watch::channel(SubnetTopology::default());
        let (mut mgr, _channels) = ReceiverManagerBuilder::new()
            .with_topology_watcher(pfn_rx)
            .build();
        let cancellation = CancellationToken::new();
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(1),
                update: Update::Id(0),
            },
            NODE_1,
            ConnId::from(1),
            cancellation.clone(),
        );
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(1),
                update: Update::Id(0),
            },
            NODE_2,
            ConnId::from(1),
            cancellation.clone(),
        );
        let addr = "127.0.0.1:8080".parse().unwrap();
        // Send current topology of two nodes.
        pfn_tx
            .send(SubnetTopology::new(
                vec![(NODE_1, addr), (NODE_2, addr)],
                RegistryVersion::from(1),
                RegistryVersion::from(1),
            ))
            .unwrap();
        mgr.handle_topology_update();
        assert_eq!(mgr.slot_table.len(), 2);
        assert_eq!(mgr.slot_table.get(&NODE_1).unwrap().len(), 1);
        assert_eq!(mgr.slot_table.get(&NODE_2).unwrap().len(), 1);
        // Remove one node from topology.
        pfn_tx
            .send(SubnetTopology::new(
                vec![(NODE_1, addr)],
                RegistryVersion::from(1),
                RegistryVersion::from(1),
            ))
            .unwrap();
        mgr.handle_topology_update();
        assert_eq!(mgr.slot_table.len(), 1);
        assert_eq!(mgr.slot_table.get(&NODE_1).unwrap().len(), 1);
        assert!(!mgr.slot_table.contains_key(&NODE_2));
        // Remove all nodes.
        pfn_tx
            .send(SubnetTopology::new(
                vec![],
                RegistryVersion::from(1),
                RegistryVersion::from(1),
            ))
            .unwrap();
        mgr.handle_topology_update();
        assert_eq!(mgr.slot_table.len(), 0);
        assert!(!mgr.slot_table.contains_key(&NODE_1));
        assert!(!mgr.slot_table.contains_key(&NODE_2));
    }

    /// Verify that if node leaves subnet all assemble tasks are informed.
    #[tokio::test]
    async fn topology_update_finish_assemble() {
        let (pfn_tx, pfn_rx) = watch::channel(SubnetTopology::default());

        fn make_artifact_assembler() -> MockArtifactAssembler {
            let mut artifact_assembler = MockArtifactAssembler::default();
            artifact_assembler
                .expect_assemble_message()
                .returning(|id, _, _: PeerWatcher| {
                    Box::pin(async move { Ok((U64Artifact::id_to_msg(id, 100), NODE_1)) })
                });
            artifact_assembler
        }
        let (mut mgr, _channels) = ReceiverManagerBuilder::new()
            .with_artifact_assembler_maker(make_artifact_assembler)
            .with_topology_watcher(pfn_rx)
            .build();
        let cancellation = CancellationToken::new();
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(1),
                update: Update::Id(0),
            },
            NODE_1,
            ConnId::from(1),
            cancellation.clone(),
        );
        assert_eq!(mgr.active_assembles.len(), 1);
        assert_eq!(mgr.artifact_processor_tasks.len(), 1);
        // Remove node with active assemble from topology.
        pfn_tx
            .send(SubnetTopology::new(
                vec![],
                RegistryVersion::from(1),
                RegistryVersion::from(1),
            ))
            .unwrap();
        mgr.handle_topology_update();
        assert_eq!(
            mgr.artifact_processor_tasks
                .join_next()
                .await
                .unwrap()
                .unwrap()
                .1,
            0
        );
    }

    #[tokio::test]
    /// Advertise same id on different slots and overwrite both slots with new ids.
    async fn duplicate_advert_on_different_slots() {
        fn make_artifact_assembler() -> MockArtifactAssembler {
            let mut artifact_assembler = MockArtifactAssembler::default();
            artifact_assembler
                .expect_assemble_message()
                .returning(|id, _, _: PeerWatcher| {
                    Box::pin(async move { Ok((U64Artifact::id_to_msg(id, 100), NODE_1)) })
                });
            artifact_assembler
        }
        let (mut mgr, _channels) = ReceiverManagerBuilder::new()
            .with_artifact_assembler_maker(make_artifact_assembler)
            .build();
        let cancellation: CancellationToken = CancellationToken::new();
        // Add id 0 on slot 1.
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(1),
                update: Update::Id(0),
            },
            NODE_1,
            ConnId::from(1),
            cancellation.clone(),
        );
        // Add id 0 on slot 2.
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(2),
                commit_id: CommitId::from(2),
                update: Update::Id(0),
            },
            NODE_1,
            ConnId::from(1),
            cancellation.clone(),
        );
        // Overwrite id 0 on slot 1.
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(3),
                update: Update::Id(1),
            },
            NODE_1,
            ConnId::from(1),
            cancellation.clone(),
        );

        // Make sure no assemble task closes since we still have slot entries for 0 and 1.
        tokio::time::timeout(
            PROCESS_ARTIFACT_TIMEOUT,
            mgr.artifact_processor_tasks.join_next(),
        )
        .await
        .unwrap_err();

        assert_eq!(mgr.artifact_processor_tasks.len(), 2);
        // Overwrite remaining id 0 at slot 2.
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(2),
                commit_id: CommitId::from(4),
                update: Update::Id(1),
            },
            NODE_1,
            ConnId::from(1),
            cancellation.clone(),
        );

        // Make sure the assemble task for 0 closes since both entries got overwritten.
        let joined_artifact_processor = mgr.artifact_processor_tasks.join_next().await;

        let result = joined_artifact_processor
            .expect("Joining artifact processor task failed")
            .expect("Artifact processor task panicked");

        assert_eq!(
            result.1, 0,
            "Expected artifact processor task for id 0 to closed"
        );
        assert_eq!(mgr.artifact_processor_tasks.len(), 1);
    }

    #[tokio::test]
    /// Advertise same id on different slots where one slot is occupied.
    async fn same_id_different_occupied_slot() {
        fn make_artifact_assembler() -> MockArtifactAssembler {
            let mut artifact_assembler = MockArtifactAssembler::default();
            artifact_assembler
                .expect_assemble_message()
                .returning(|id, _, _: PeerWatcher| {
                    Box::pin(async move { Ok((U64Artifact::id_to_msg(id, 100), NODE_1)) })
                });
            artifact_assembler
        }
        let (mut mgr, _channels) = ReceiverManagerBuilder::new()
            .with_artifact_assembler_maker(make_artifact_assembler)
            .build();
        let cancellation: CancellationToken = CancellationToken::new();
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(1),
                update: Update::Id(0),
            },
            NODE_1,
            ConnId::from(1),
            cancellation.clone(),
        );
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(2),
                commit_id: CommitId::from(2),
                update: Update::Id(1),
            },
            NODE_1,
            ConnId::from(1),
            cancellation.clone(),
        );
        assert_eq!(mgr.artifact_processor_tasks.len(), 2);

        // Make sure no assemble task closes since we still have slot entries for 0 and 1.
        tokio::time::timeout(
            Duration::from_millis(100),
            mgr.artifact_processor_tasks.join_next(),
        )
        .await
        .unwrap_err();

        // Overwrite id 1 with id 0.
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(2),
                commit_id: CommitId::from(3),
                update: Update::Id(0),
            },
            NODE_1,
            ConnId::from(1),
            cancellation.clone(),
        );
        // Only assemble task 1 closes because it got overwritten.
        tokio::time::timeout(Duration::from_millis(100), async {
            while let Some(id) = mgr.artifact_processor_tasks.join_next().await {
                assert_eq!(id.unwrap().1, 1);
            }
        })
        .await
        .unwrap_err();

        assert_eq!(mgr.artifact_processor_tasks.len(), 1);
    }

    #[tokio::test]
    /// Advertise same id on same slots. This should be a noop where only the commit id and connection id get updated.
    async fn same_id_same_slot() {
        fn make_artifact_assembler() -> MockArtifactAssembler {
            let mut artifact_assembler = MockArtifactAssembler::default();
            artifact_assembler
                .expect_assemble_message()
                .returning(|id, _, _: PeerWatcher| {
                    Box::pin(async move { Ok((U64Artifact::id_to_msg(id, 100), NODE_1)) })
                });
            artifact_assembler
        }
        let (mut mgr, _channels) = ReceiverManagerBuilder::new()
            .with_artifact_assembler_maker(make_artifact_assembler)
            .build();
        let cancellation: CancellationToken = CancellationToken::new();
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(1),
                update: Update::Id(0),
            },
            NODE_1,
            ConnId::from(1),
            cancellation.clone(),
        );
        assert_eq!(
            mgr.slot_table
                .get(&NODE_1)
                .unwrap()
                .get(&SlotNumber::from(1))
                .unwrap(),
            &SlotEntry {
                conn_id: ConnId::from(1),
                commit_id: CommitId::from(1),
                id: 0,
            }
        );
        // Advertise id 0 again on same slot.
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(2),
                update: Update::Id(0),
            },
            NODE_1,
            ConnId::from(1),
            cancellation.clone(),
        );

        // Make sure no assemble task closes since we still have entry for 0.
        let joined_artifact_processor = timeout(
            PROCESS_ARTIFACT_TIMEOUT,
            mgr.artifact_processor_tasks.join_next(),
        )
        .await;

        assert!(
            joined_artifact_processor.is_err(),
            "Artifact task should not close when overwriting with same artifact id."
        );
        assert_eq!(mgr.artifact_processor_tasks.len(), 1);

        // Check that newer commit id is stored.
        assert_eq!(mgr.slot_table.len(), 1);
        assert_eq!(mgr.slot_table.get(&NODE_1).unwrap().len(), 1);
        assert_eq!(
            mgr.slot_table
                .get(&NODE_1)
                .unwrap()
                .get(&1.into())
                .unwrap()
                .commit_id,
            2.into()
        );
        assert_eq!(mgr.artifact_processor_tasks.len(), 1);

        // Overwrite id 0.
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(3),
                update: Update::Id(2),
            },
            NODE_1,
            ConnId::from(1),
            cancellation.clone(),
        );

        // Make sure the assemble task for 0 closes.
        let joined_artifact_processor = timeout(
            PROCESS_ARTIFACT_TIMEOUT,
            mgr.artifact_processor_tasks.join_next(),
        )
        .await;

        let result = joined_artifact_processor
            .expect("Joining artifact processor join-set timed out")
            .expect("Joining artifact processor task failed")
            .expect("Artifact processor task panicked");

        assert_eq!(
            result.1, 0,
            "Expected artifact processor task for id 0 to closed"
        );
        assert_eq!(mgr.artifact_processor_tasks.len(), 1);
    }

    #[tokio::test]
    async fn large_artifact() {
        use ic_protobuf::p2p::v1 as pb;

        #[derive(PartialEq, Eq, Debug, Clone)]
        pub struct BigArtifact(Vec<u8>);
        impl IdentifiableArtifact for BigArtifact {
            const NAME: &'static str = "big";
            type Id = ();
            fn id(&self) -> Self::Id {}
        }
        impl From<BigArtifact> for Vec<u8> {
            fn from(value: BigArtifact) -> Self {
                value.0
            }
        }
        impl From<Vec<u8>> for BigArtifact {
            fn from(value: Vec<u8>) -> Self {
                Self(value)
            }
        }

        impl PbArtifact for BigArtifact {
            type PbMessage = Vec<u8>;
            type PbIdError = Infallible;
            type PbMessageError = Infallible;
            type PbId = ();
        }

        let (router, mut update_rx) = build_axum_router::<BigArtifact>(no_op_logger());

        let req_pb = pb::SlotUpdate {
            commit_id: 0,
            slot_id: 0,
            update: Some(pb::slot_update::Update::Artifact(
                vec![0; 100_000_000].encode_to_vec(),
            )),
        }
        .encode_to_vec();

        let resp = router
            .oneshot(
                Request::builder()
                    .uri(format!("/{}/update", uri_prefix::<BigArtifact>()))
                    .extension(NODE_1)
                    .extension(ConnId::from(1))
                    .body(Body::from(req_pb))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        update_rx.recv().await.unwrap();
    }
}
