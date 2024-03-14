#![allow(clippy::disallowed_methods)]

use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    sync::{Arc, RwLock},
    time::Duration,
};

use crate::{
    metrics::{
        ConsensusManagerMetrics, DOWNLOAD_TASK_RESULT_ALL_PEERS_DELETED,
        DOWNLOAD_TASK_RESULT_COMPLETED, DOWNLOAD_TASK_RESULT_DROP,
    },
    uri_prefix, CommitId, SlotNumber, SlotUpdate, Update,
};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{Request, StatusCode},
    routing::any,
    Extension, Router,
};
use backoff::{backoff::Backoff, ExponentialBackoffBuilder};
use bytes::Bytes;
use ic_base_types::NodeId;
use ic_interfaces::p2p::consensus::{PriorityFnAndFilterProducer, ValidatedPoolReader};
use ic_logger::{error, warn, ReplicaLogger};
use ic_protobuf::{p2p::v1 as pb, proxy::ProtoProxy};
use ic_quic_transport::{ConnId, SubnetTopology, Transport};
use ic_types::artifact::{ArtifactKind, Priority, PriorityFn, UnvalidatedArtifactMutation};
use rand::{rngs::SmallRng, seq::IteratorRandom, SeedableRng};
use tokio::{
    runtime::Handle,
    select,
    sync::{
        mpsc::{Receiver, Sender, UnboundedSender},
        watch,
    },
    task::JoinSet,
    time::{self, sleep_until, timeout_at, Instant, MissedTickBehavior},
};

const MIN_ARTIFACT_RPC_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ARTIFACT_RPC_TIMEOUT: Duration = Duration::from_secs(120);
const PRIORITY_FUNCTION_UPDATE_INTERVAL: Duration = Duration::from_secs(3);

type ValidatedPoolReaderRef<T> = Arc<RwLock<dyn ValidatedPoolReader<T> + Send + Sync>>;
type ReceivedAdvertSender<A> = Sender<(SlotUpdate<A>, NodeId, ConnId)>;

#[allow(unused)]
pub fn build_axum_router<Artifact: ArtifactKind>(
    log: ReplicaLogger,
    pool: ValidatedPoolReaderRef<Artifact>,
) -> (Router, Receiver<(SlotUpdate<Artifact>, NodeId, ConnId)>) {
    let (update_tx, update_rx) = tokio::sync::mpsc::channel(100);
    let router = Router::new()
        .route(
            &format!("/{}/rpc", uri_prefix::<Artifact>()),
            any(rpc_handler),
        )
        .with_state(pool)
        .route(
            &format!("/{}/update", uri_prefix::<Artifact>()),
            any(update_handler),
        )
        .with_state((log, update_tx))
        // Disable request size limit since consensus might push artifacts larger than limit.
        .layer(DefaultBodyLimit::disable());

    (router, update_rx)
}

async fn rpc_handler<Artifact: ArtifactKind>(
    State(pool): State<ValidatedPoolReaderRef<Artifact>>,
    payload: Bytes,
) -> Result<Bytes, StatusCode> {
    let jh = tokio::task::spawn_blocking(move || {
        let id: Artifact::Id =
            Artifact::PbId::proxy_decode(&payload).map_err(|_| StatusCode::BAD_REQUEST)?;
        let artifact = pool
            .read()
            .unwrap()
            .get_validated_by_identifier(&id)
            .ok_or(StatusCode::NO_CONTENT)?;
        Ok::<_, StatusCode>(Bytes::from(Artifact::PbMessage::proxy_encode(artifact)))
    });
    let bytes = jh.await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)??;

    Ok(bytes)
}

async fn update_handler<Artifact: ArtifactKind>(
    State((log, sender)): State<(ReplicaLogger, ReceivedAdvertSender<Artifact>)>,
    Extension(peer): Extension<NodeId>,
    Extension(conn_id): Extension<ConnId>,
    payload: Bytes,
) -> Result<(), StatusCode> {
    let update: SlotUpdate<Artifact> =
        pb::SlotUpdate::proxy_decode(&payload).map_err(|_| StatusCode::BAD_REQUEST)?;

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
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn peers(&self) -> impl Iterator<Item = &NodeId> {
        self.0.keys()
    }

    /// Returns true if value is newly inserted
    pub fn insert(&mut self, node: NodeId) -> bool {
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
    pub fn remove(&mut self, node: NodeId) -> bool {
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
pub(crate) struct ConsensusManagerReceiver<Artifact: ArtifactKind, Pool, ReceivedAdvert> {
    log: ReplicaLogger,
    metrics: ConsensusManagerMetrics,
    rt_handle: Handle,
    transport: Arc<dyn Transport>,

    // Receive side:
    adverts_received: Receiver<ReceivedAdvert>,
    pool_reader: Arc<RwLock<dyn ValidatedPoolReader<Artifact> + Send + Sync>>,
    raw_pool: Arc<RwLock<Pool>>,
    priority_fn_producer: Arc<dyn PriorityFnAndFilterProducer<Artifact, Pool>>,
    current_priority_fn: watch::Sender<PriorityFn<Artifact::Id, Artifact::Attribute>>,
    sender: UnboundedSender<UnvalidatedArtifactMutation<Artifact>>,

    slot_table: HashMap<NodeId, HashMap<SlotNumber, SlotEntry<Artifact::Id>>>,
    active_downloads: HashMap<Artifact::Id, watch::Sender<PeerCounter>>,

    #[allow(clippy::type_complexity)]
    artifact_processor_tasks: JoinSet<(
        watch::Receiver<PeerCounter>,
        Artifact::Id,
        Artifact::Attribute,
    )>,

    topology_watcher: watch::Receiver<SubnetTopology>,
}

#[allow(unused)]
impl<Artifact, Pool>
    ConsensusManagerReceiver<Artifact, Pool, (SlotUpdate<Artifact>, NodeId, ConnId)>
where
    Pool: 'static + Send + Sync + ValidatedPoolReader<Artifact>,
    Artifact: ArtifactKind,
{
    pub(crate) fn run(
        log: ReplicaLogger,
        metrics: ConsensusManagerMetrics,
        rt_handle: Handle,
        adverts_received: Receiver<(SlotUpdate<Artifact>, NodeId, ConnId)>,
        raw_pool: Arc<RwLock<Pool>>,
        priority_fn_producer: Arc<dyn PriorityFnAndFilterProducer<Artifact, Pool>>,
        sender: UnboundedSender<UnvalidatedArtifactMutation<Artifact>>,
        transport: Arc<dyn Transport>,
        topology_watcher: watch::Receiver<SubnetTopology>,
    ) {
        let priority_fn = priority_fn_producer.get_priority_function(&raw_pool.read().unwrap());
        let (current_priority_fn, _) = watch::channel(priority_fn);

        let receive_manager = Self {
            log,
            metrics,
            rt_handle: rt_handle.clone(),
            adverts_received,
            pool_reader: raw_pool.clone() as Arc<_>,
            raw_pool,
            priority_fn_producer,
            current_priority_fn,
            sender,
            transport,
            active_downloads: HashMap::new(),
            slot_table: HashMap::new(),
            artifact_processor_tasks: JoinSet::new(),
            topology_watcher,
        };

        rt_handle.spawn(receive_manager.start_event_loop());
    }

    /// Event loop that processes advert updates and artifact downloads.
    /// The event loop preserves the invariants checked with `debug_assert`.
    async fn start_event_loop(mut self) {
        let mut priority_fn_interval = time::interval(PRIORITY_FUNCTION_UPDATE_INTERVAL);
        priority_fn_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            select! {
                _ = priority_fn_interval.tick() => {
                    self.handle_pfn_timer_tick();
                }
                Some((advert_update, peer_id, conn_id)) = self.adverts_received.recv() => {
                    self.handle_advert_receive(advert_update, peer_id, conn_id);
                }
                Some(result) = self.artifact_processor_tasks.join_next() => {
                    match result {
                        Ok((receiver, id, attr)) => {
                            self.handle_artifact_processor_joined(receiver, id, attr);

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
                self.active_downloads.len(),
                self.artifact_processor_tasks.len(),
                "Number of artifact processing tasks differs from the available number of channels that communicate with the processing tasks"
            );
            debug_assert!(
                self.artifact_processor_tasks.len()
                    >= HashSet::<Artifact::Id>::from_iter(
                        self.slot_table
                            .iter()
                            .flat_map(|(k, v)| v.iter())
                            .map(|(_, s)| s.id.clone())
                    )
                    .len(),
                "Number of download tasks should always be the same or exceed the number of distinct ids stored."
            );
            debug_assert!(
                self.active_downloads
                    .iter()
                    .all(|(k, v)| { v.receiver_count() == 1 }),
                "Some download task has two node receivers or it was dropped."
            );
        }
    }

    pub(crate) fn handle_pfn_timer_tick(&mut self) {
        let pool = &self.raw_pool.read().unwrap();
        let priority_fn = self.priority_fn_producer.get_priority_function(pool);
        self.current_priority_fn.send_replace(priority_fn);
    }

    pub(crate) fn handle_artifact_processor_joined(
        &mut self,
        peer_rx: watch::Receiver<PeerCounter>,
        id: Artifact::Id,
        attr: Artifact::Attribute,
    ) {
        self.metrics.download_task_finished_total.inc();
        // Invariant: Peer sender should only be dropped in this task..
        debug_assert!(peer_rx.has_changed().is_ok());

        // peer advertised after task finished.
        if !peer_rx.borrow().is_empty() {
            self.metrics.download_task_restart_after_join_total.inc();
            self.metrics.download_task_started_total.inc();
            self.artifact_processor_tasks.spawn_on(
                Self::process_advert(
                    self.log.clone(),
                    id,
                    attr,
                    None,
                    peer_rx,
                    self.current_priority_fn.subscribe(),
                    self.sender.clone(),
                    self.transport.clone(),
                    self.metrics.clone(),
                ),
                &self.rt_handle,
            );
        } else {
            self.active_downloads.remove(&id);
        }
        debug_assert!(
            self.slot_table
                .iter()
                .flat_map(|(k, v)| v.iter())
                .all(|(k, v)| self.active_downloads.contains_key(&v.id)),
            "Every entry in the slot table should have an active download task."
        );
    }

    pub(crate) fn handle_advert_receive(
        &mut self,
        advert_update: SlotUpdate<Artifact>,
        peer_id: NodeId,
        connection_id: ConnId,
    ) {
        self.metrics.slot_table_updates_total.inc();
        let SlotUpdate {
            slot_number,
            commit_id,
            update,
        } = advert_update;

        let (id, attribute, artifact) = match update {
            Update::Artifact(artifact) => {
                let advert = Artifact::message_to_advert(&artifact);
                (advert.id, advert.attribute, Some(artifact))
            }
            Update::Advert((id, attribute)) => (id, attribute, None),
        };

        if artifact.is_some() {
            self.metrics.slot_table_updates_with_artifact_total.inc();
        }

        let new_slot_entry: SlotEntry<Artifact::Id> = SlotEntry {
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
            match self.active_downloads.get(&id) {
                Some(sender) => {
                    self.metrics.slot_table_seen_id_total.inc();
                    sender.send_if_modified(|h| h.insert(peer_id));
                }
                None => {
                    self.metrics.download_task_started_total.inc();

                    let mut peer_counter = PeerCounter::new();
                    let (tx, rx) = watch::channel(peer_counter);
                    tx.send_if_modified(|h| h.insert(peer_id));
                    self.active_downloads.insert(id.clone(), tx);

                    self.artifact_processor_tasks.spawn_on(
                        Self::process_advert(
                            self.log.clone(),
                            id.clone(),
                            attribute,
                            artifact.map(|a| (a, peer_id)),
                            rx,
                            self.current_priority_fn.subscribe(),
                            self.sender.clone(),
                            self.transport.clone(),
                            self.metrics.clone(),
                        ),
                        &self.rt_handle,
                    );
                }
            }
        }

        if let Some(to_remove) = to_remove {
            match self.active_downloads.get_mut(&to_remove) {
                Some(sender) => {
                    sender.send_if_modified(|h| h.remove(peer_id));
                    self.metrics.slot_table_removals_total.inc();
                }
                None => {
                    error!(
                        self.log,
                        "Slot table contains an artifact ID that is not present in the `active_downloads`. This should never happen."
                    );
                    if cfg!(debug_assertions) {
                        panic!("Invariant violated");
                    }
                }
            };
        }
    }

    /// Waits until advert resolves to fetch. If all peers are removed or priority becomes drop `DownloadStopped` is returned.
    async fn wait_fetch(
        id: &Artifact::Id,
        attr: &Artifact::Attribute,
        artifact: &mut Option<(Artifact::Message, NodeId)>,
        metrics: &ConsensusManagerMetrics,
        mut peer_rx: &mut watch::Receiver<PeerCounter>,
        mut priority_fn_watcher: &mut watch::Receiver<
            PriorityFn<Artifact::Id, Artifact::Attribute>,
        >,
    ) -> Result<(), DownloadStopped> {
        let mut priority = priority_fn_watcher.borrow_and_update()(id, attr);

        // Clear the artifact from memory if it was pushed.
        if let Priority::Stash = priority {
            artifact.take();
            metrics.download_task_stashed_total.inc();
        }

        while let Priority::Stash = priority {
            select! {
                Ok(_) = priority_fn_watcher.changed() => {
                    priority = priority_fn_watcher.borrow_and_update()(id, attr);
                }
                res = peer_rx.changed() => {
                    match res {
                        Ok(()) if peer_rx.borrow().is_empty() => {
                            return Err(DownloadStopped::AllPeersDeletedTheArtifact);
                        },
                        Ok(()) => {},
                        Err(_) => {
                            return Err(DownloadStopped::AllPeersDeletedTheArtifact);
                        }
                    }
                }
            }
        }

        if let Priority::Drop = priority {
            return Err(DownloadStopped::PriorityIsDrop);
        }
        Ok(())
    }

    /// Downloads a given artifact.
    ///
    /// The download will be scheduled based on the given priority function, `priority_fn_watcher`.
    ///
    /// The download fails iff:
    /// - The priority function evaluates the advert to [`Priority::Drop`] -> [`DownloadStopped::PriorityIsDrop`]
    /// - The set of peers advertising the artifact, `peer_rx`, becomes empty -> [`DownloadStopped::AllPeersDeletedTheArtifact`]
    /// and the failure condition is reported in the error variant of the returned result.
    async fn download_artifact(
        log: ReplicaLogger,
        id: &Artifact::Id,
        attr: &Artifact::Attribute,
        // Only first peer for specific artifact ID is considered for push
        mut artifact: Option<(Artifact::Message, NodeId)>,
        mut peer_rx: &mut watch::Receiver<PeerCounter>,
        mut priority_fn_watcher: watch::Receiver<PriorityFn<Artifact::Id, Artifact::Attribute>>,
        transport: Arc<dyn Transport>,
        metrics: ConsensusManagerMetrics,
    ) -> Result<(Artifact::Message, NodeId), DownloadStopped> {
        // Evaluate priority and wait until we should fetch.
        Self::wait_fetch(
            id,
            attr,
            &mut artifact,
            &metrics,
            peer_rx,
            &mut priority_fn_watcher,
        )
        .await?;

        let mut artifact_download_timeout = ExponentialBackoffBuilder::new()
            .with_initial_interval(MIN_ARTIFACT_RPC_TIMEOUT)
            .with_max_interval(MAX_ARTIFACT_RPC_TIMEOUT)
            .with_max_elapsed_time(None)
            .build();

        match artifact {
            // Artifact was pushed by peer. In this case we don't need check that the artifact ID corresponds
            // to the artifact because we earlier derived the ID from the artifact.
            Some((artifact, peer_id)) => Ok((artifact, peer_id)),

            // Fetch artifact
            None => {
                let mut result = Err(DownloadStopped::AllPeersDeletedTheArtifact);

                let timer = metrics
                    .download_task_artifact_download_duration
                    .start_timer();
                let mut rng = SmallRng::from_entropy();
                while let Some(peer) = {
                    let peer = peer_rx.borrow().peers().choose(&mut rng).copied();
                    peer
                } {
                    let bytes = Bytes::from(Artifact::PbId::proxy_encode(id.clone()));
                    let request = Request::builder()
                        .uri(format!("/{}/rpc", uri_prefix::<Artifact>()))
                        .body(bytes)
                        .unwrap();

                    if peer_rx.has_changed().unwrap_or(false) {
                        artifact_download_timeout.reset();
                    }

                    let next_request_at = Instant::now()
                        + artifact_download_timeout
                            .next_backoff()
                            .unwrap_or(MAX_ARTIFACT_RPC_TIMEOUT);
                    match timeout_at(next_request_at, transport.rpc(&peer, request)).await {
                        Ok(Ok(response)) if response.status() == StatusCode::OK => {
                            let body = response.into_body();
                            if let Ok(message) = Artifact::PbMessage::proxy_decode(&body) {
                                if &Artifact::message_to_advert(&message).id == id {
                                    result = Ok((message, peer));
                                    break;
                                } else {
                                    warn!(
                                        log,
                                        "Peer {} responded with wrong artifact for advert", peer
                                    );
                                }
                            }
                        }
                        _ => {
                            metrics.download_task_artifact_download_errors_total.inc();
                        }
                    }

                    // Wait before checking the priority so we might be able to avoid an unnecessary download.
                    sleep_until(next_request_at).await;
                    Self::wait_fetch(
                        id,
                        attr,
                        &mut artifact,
                        &metrics,
                        peer_rx,
                        &mut priority_fn_watcher,
                    )
                    .await?;
                }

                timer.stop_and_record();

                result
            }
        }
    }

    /// Tries to download the given artifact, and insert it into the unvalidated pool.
    ///
    /// This future waits for all peers that advertise the artifact to delete it.
    /// The artifact is deleted from the unvalidated pool upon completion.
    async fn process_advert(
        log: ReplicaLogger,
        id: Artifact::Id,
        attr: Artifact::Attribute,
        // Only first peer for specific artifact ID is considered for push
        mut artifact: Option<(Artifact::Message, NodeId)>,
        mut peer_rx: watch::Receiver<PeerCounter>,
        mut priority_fn_watcher: watch::Receiver<PriorityFn<Artifact::Id, Artifact::Attribute>>,
        sender: UnboundedSender<UnvalidatedArtifactMutation<Artifact>>,
        transport: Arc<dyn Transport>,
        metrics: ConsensusManagerMetrics,
    ) -> (
        watch::Receiver<PeerCounter>,
        Artifact::Id,
        Artifact::Attribute,
    ) {
        let _timer = metrics.download_task_duration.start_timer();
        let download_result = Self::download_artifact(
            log,
            &id,
            &attr,
            artifact,
            &mut peer_rx,
            priority_fn_watcher,
            transport,
            metrics.clone(),
        )
        .await;

        match download_result {
            Ok((artifact, peer_id)) => {
                // Send artifact to pool
                sender.send(UnvalidatedArtifactMutation::Insert((artifact, peer_id)));

                // wait for deletion from peers
                peer_rx.wait_for(|p| p.is_empty()).await;

                // Purge from the unvalidated pool
                sender.send(UnvalidatedArtifactMutation::Remove(id.clone()));
                metrics
                    .download_task_result_total
                    .with_label_values(&[DOWNLOAD_TASK_RESULT_COMPLETED])
                    .inc();
            }
            Err(DownloadStopped::PriorityIsDrop) => {
                // wait for deletion from peers
                peer_rx.wait_for(|p| p.is_empty()).await;
                metrics
                    .download_task_result_total
                    .with_label_values(&[DOWNLOAD_TASK_RESULT_DROP])
                    .inc();
            }
            Err(DownloadStopped::AllPeersDeletedTheArtifact) => {
                metrics
                    .download_task_result_total
                    .with_label_values(&[DOWNLOAD_TASK_RESULT_ALL_PEERS_DELETED])
                    .inc();
            }
        }

        (peer_rx, id, attr)
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

        for peers_sender in self.active_downloads.values() {
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

#[derive(Debug, PartialEq, Eq)]
enum DownloadStopped {
    AllPeersDeletedTheArtifact,
    PriorityIsDrop,
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
    use std::{backtrace::Backtrace, convert::Infallible, sync::Mutex};

    use axum::{body::Body, http::Response};
    use ic_logger::replica_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_p2p_test_utils::{
        consensus::U64Artifact,
        mocks::{MockPriorityFnAndFilterProducer, MockTransport, MockValidatedPoolReader},
    };
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_types::{
        artifact::{Advert, ArtifactTag},
        RegistryVersion,
    };
    use ic_types_test_utils::ids::{NODE_1, NODE_2};
    use mockall::Sequence;
    use tokio::{sync::mpsc::UnboundedReceiver, time::timeout};
    use tower::util::ServiceExt;

    use super::*;

    const PROCESS_ARTIFACT_TIMEOUT: Duration = Duration::from_millis(1000);

    struct ReceiverManagerBuilder {
        // Adverts received from peers
        adverts_received: Receiver<(SlotUpdate<U64Artifact>, NodeId, ConnId)>,
        raw_pool: MockValidatedPoolReader<U64Artifact>,
        priority_fn_producer:
            Arc<dyn PriorityFnAndFilterProducer<U64Artifact, MockValidatedPoolReader<U64Artifact>>>,
        sender: UnboundedSender<UnvalidatedArtifactMutation<U64Artifact>>,
        transport: Arc<dyn Transport>,
        topology_watcher: watch::Receiver<SubnetTopology>,

        channels: Channels,
    }

    type ConsensusManagerReceiverForTest = ConsensusManagerReceiver<
        U64Artifact,
        MockValidatedPoolReader<U64Artifact>,
        (SlotUpdate<U64Artifact>, NodeId, ConnId),
    >;

    struct Channels {
        unvalidated_artifact_receiver: UnboundedReceiver<UnvalidatedArtifactMutation<U64Artifact>>,
    }

    impl ReceiverManagerBuilder {
        fn new() -> Self {
            let (_, adverts_received) = tokio::sync::mpsc::channel(100);
            let (sender, unvalidated_artifact_receiver) = tokio::sync::mpsc::unbounded_channel();
            let (_, topology_watcher) = watch::channel(SubnetTopology::default());

            let mut mock_pfn = MockPriorityFnAndFilterProducer::new();

            mock_pfn
                .expect_get_priority_function()
                .returning(|_| Box::new(|_, _| Priority::Stash));

            Self {
                adverts_received,
                raw_pool: MockValidatedPoolReader::new(),
                priority_fn_producer: Arc::new(mock_pfn),
                sender,
                transport: Arc::new(MockTransport::new()),
                topology_watcher,
                channels: Channels {
                    unvalidated_artifact_receiver,
                },
            }
        }

        fn with_priority_fn_producer(
            mut self,
            priority_fn_producer: Arc<
                dyn PriorityFnAndFilterProducer<U64Artifact, MockValidatedPoolReader<U64Artifact>>,
            >,
        ) -> Self {
            self.priority_fn_producer = priority_fn_producer;
            self
        }

        fn with_transport(mut self, transport: Arc<dyn Transport>) -> Self {
            self.transport = transport;
            self
        }

        fn with_topology_watcher(
            mut self,
            topology_watcher: watch::Receiver<SubnetTopology>,
        ) -> Self {
            self.topology_watcher = topology_watcher;
            self
        }

        fn build(self) -> (ConsensusManagerReceiverForTest, Channels) {
            let consensus_manager_receiver = with_test_replica_logger(|log| {
                let priority_fn = self
                    .priority_fn_producer
                    .get_priority_function(&self.raw_pool);
                let (current_priority_fn, _) = watch::channel(priority_fn);

                let raw_pool = Arc::new(RwLock::new(self.raw_pool));
                ConsensusManagerReceiver {
                    log,
                    metrics: ConsensusManagerMetrics::new::<U64Artifact>(
                        &MetricsRegistry::default(),
                    ),
                    rt_handle: Handle::current(),
                    adverts_received: self.adverts_received,
                    pool_reader: raw_pool.clone() as Arc<_>,
                    raw_pool: raw_pool.clone() as Arc<_>,
                    priority_fn_producer: self.priority_fn_producer,
                    current_priority_fn,
                    sender: self.sender,
                    transport: self.transport,
                    topology_watcher: self.topology_watcher,
                    active_downloads: HashMap::new(),
                    slot_table: HashMap::new(),
                    artifact_processor_tasks: JoinSet::new(),
                }
            });

            (consensus_manager_receiver, self.channels)
        }
    }

    /// Check that all variants of stale adverts to not get added to the slot table.
    #[tokio::test]
    async fn receiving_stale_advert_updates() {
        // Abort process if a thread panics. This catches detached tokio tasks that panic.
        // https://github.com/tokio-rs/tokio/issues/4516
        std::panic::set_hook(Box::new(|info| {
            let stacktrace = Backtrace::force_capture();
            println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
            std::process::abort();
        }));

        let (mut mgr, _channels) = ReceiverManagerBuilder::new().build();

        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(1),
                update: Update::Advert((0, ())),
            },
            NODE_1,
            ConnId::from(1),
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
        assert_eq!(mgr.active_downloads.len(), 1);
        assert_eq!(mgr.artifact_processor_tasks.len(), 1);
        // Send stale advert with lower commit id.
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(0),
                update: Update::Advert((0, ())),
            },
            NODE_1,
            ConnId::from(1),
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
                update: Update::Advert((0, ())),
            },
            NODE_1,
            ConnId::from(0),
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
                update: Update::Advert((0, ())),
            },
            NODE_1,
            ConnId::from(0),
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
                update: Update::Advert((0, ())),
            },
            NODE_1,
            ConnId::from(0),
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
        assert_eq!(mgr.active_downloads.len(), 1);
        assert_eq!(mgr.artifact_processor_tasks.len(), 1);
    }

    /// Check that adverts updates with higher connection ids take precedence.
    #[tokio::test]
    async fn overwrite_slot() {
        // Abort process if a thread panics. This catches detached tokio tasks that panic.
        // https://github.com/tokio-rs/tokio/issues/4516
        std::panic::set_hook(Box::new(|info| {
            let stacktrace = Backtrace::force_capture();
            println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
            std::process::abort();
        }));

        let (mut mgr, _channels) = ReceiverManagerBuilder::new().build();

        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(1),
                update: Update::Advert((0, ())),
            },
            NODE_1,
            ConnId::from(1),
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
        assert_eq!(mgr.active_downloads.len(), 1);
        assert_eq!(mgr.artifact_processor_tasks.len(), 1);
        // Send advert with higher conn id.
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(0),
                update: Update::Advert((1, ())),
            },
            NODE_1,
            ConnId::from(2),
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

        // Check that download task for first advert closes.
        assert_eq!(result.1, 0);
    }

    /// Verify that if two peers advertise the same advert it will get added to the same download task.
    #[tokio::test]
    async fn two_peers_advertise_same_advert() {
        // Abort process if a thread panics. This catches detached tokio tasks that panic.
        // https://github.com/tokio-rs/tokio/issues/4516
        std::panic::set_hook(Box::new(|info| {
            let stacktrace = Backtrace::force_capture();
            println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
            std::process::abort();
        }));

        let (mut mgr, _channels) = ReceiverManagerBuilder::new().build();

        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(1),
                update: Update::Advert((0, ())),
            },
            NODE_1,
            ConnId::from(1),
        );
        // Second advert for advert 0.
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(1),
                update: Update::Advert((0, ())),
            },
            NODE_2,
            ConnId::from(1),
        );
        // Verify that we only have one download task.
        assert_eq!(mgr.slot_table.len(), 2);
        assert_eq!(mgr.slot_table.get(&NODE_1).unwrap().len(), 1);
        assert_eq!(mgr.slot_table.get(&NODE_2).unwrap().len(), 1);
        assert_eq!(mgr.active_downloads.len(), 1);
    }

    /// Verify that a new download task is started if we receive a new update for an already finished download.
    #[tokio::test]
    async fn new_advert_while_download_finished() {
        // Abort process if a thread panics. This catches detached tokio tasks that panic.
        // https://github.com/tokio-rs/tokio/issues/4516
        std::panic::set_hook(Box::new(|info| {
            let stacktrace = Backtrace::force_capture();
            println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
            std::process::abort();
        }));

        let (mut mgr, _channels) = ReceiverManagerBuilder::new().build();

        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(1),
                update: Update::Advert((0, ())),
            },
            NODE_1,
            ConnId::from(1),
        );
        // Overwrite advert to close the download task.
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(2),
                update: Update::Advert((1, ())),
            },
            NODE_1,
            ConnId::from(1),
        );
        // Check that the download task is closed.
        let (peer_rx, id, attr) = mgr
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
                update: Update::Advert((0, ())),
            },
            NODE_2,
            ConnId::from(1),
        );
        assert_eq!(mgr.active_downloads.len(), 2);
        // Verify that we reopened the download task for advert 0.
        mgr.handle_artifact_processor_joined(peer_rx, id, attr);
        assert_eq!(mgr.active_downloads.len(), 2);
    }

    /// Verify that advert that transitions from stash to drop is not downloaded.
    #[tokio::test]
    async fn priority_from_stash_to_drop() {
        // Abort process if a thread panics. This catches detached tokio tasks that panic.
        // https://github.com/tokio-rs/tokio/issues/4516
        std::panic::set_hook(Box::new(|info| {
            let stacktrace = Backtrace::force_capture();
            println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
            std::process::abort();
        }));

        let mut mock_pfn = MockPriorityFnAndFilterProducer::new();
        let mut seq = Sequence::new();
        mock_pfn
            .expect_get_priority_function()
            .times(1)
            .returning(|_| Box::new(|_, _| Priority::Stash))
            .in_sequence(&mut seq);
        mock_pfn
            .expect_get_priority_function()
            .times(1)
            .returning(|_| Box::new(|_, _| Priority::Drop))
            .in_sequence(&mut seq);

        let (mut mgr, _channels) = ReceiverManagerBuilder::new()
            .with_priority_fn_producer(Arc::new(mock_pfn))
            .build();

        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(1),
                update: Update::Advert((0, ())),
            },
            NODE_1,
            ConnId::from(1),
        );
        assert_eq!(mgr.slot_table.len(), 1);
        assert_eq!(mgr.slot_table.get(&NODE_1).unwrap().len(), 1);
        assert_eq!(mgr.active_downloads.len(), 1);
        assert_eq!(mgr.artifact_processor_tasks.len(), 1);
        // Update priority fn to drop.
        mgr.handle_pfn_timer_tick();
        // Overwrite existing advert to finish download task.
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(2),
                update: Update::Advert((1, ())),
            },
            NODE_1,
            ConnId::from(1),
        );
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

    /// Check that an advert for which the priority changes from stash to fetch is downloaded.
    #[tokio::test]
    async fn priority_from_stash_to_fetch() {
        // Abort process if a thread panics. This catches detached tokio tasks that panic.
        // https://github.com/tokio-rs/tokio/issues/4516
        std::panic::set_hook(Box::new(|info| {
            let stacktrace = Backtrace::force_capture();
            println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
            std::process::abort();
        }));

        let mut mock_pfn = MockPriorityFnAndFilterProducer::new();
        let mut seq = Sequence::new();
        mock_pfn
            .expect_get_priority_function()
            .times(1)
            .returning(|_| Box::new(|_, _| Priority::Stash))
            .in_sequence(&mut seq);
        mock_pfn
            .expect_get_priority_function()
            .times(1)
            .returning(|_| Box::new(|_, _| Priority::Fetch))
            .in_sequence(&mut seq);

        let mut mock_transport = MockTransport::new();
        mock_transport.expect_rpc().returning(|_, _| {
            Ok(Response::builder()
                .body(Bytes::from(
                    <<U64Artifact as ArtifactKind>::PbMessage>::proxy_encode(0_u64),
                ))
                .unwrap())
        });

        let (mut mgr, mut channels) = ReceiverManagerBuilder::new()
            .with_priority_fn_producer(Arc::new(mock_pfn))
            .with_transport(Arc::new(mock_transport))
            .build();

        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(1),
                update: Update::Advert((0, ())),
            },
            NODE_1,
            ConnId::from(1),
        );
        assert_eq!(mgr.slot_table.len(), 1);
        assert_eq!(mgr.slot_table.get(&NODE_1).unwrap().len(), 1);
        assert_eq!(mgr.active_downloads.len(), 1);
        assert_eq!(mgr.artifact_processor_tasks.len(), 1);
        // Update priority fn to fetch.
        mgr.handle_pfn_timer_tick();
        // Check that we received downloaded artifact.
        assert_eq!(
            channels.unvalidated_artifact_receiver.recv().await.unwrap(),
            UnvalidatedArtifactMutation::Insert((0, NODE_1))
        );
    }

    /// Verify that slot table is pruned if node leaves subnet.
    #[tokio::test]
    async fn topology_update() {
        // Abort process if a thread panics. This catches detached tokio tasks that panic.
        // https://github.com/tokio-rs/tokio/issues/4516
        std::panic::set_hook(Box::new(|info| {
            let stacktrace = Backtrace::force_capture();
            println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
            std::process::abort();
        }));

        let mut mock_pfn = MockPriorityFnAndFilterProducer::new();
        mock_pfn
            .expect_get_priority_function()
            .returning(|_| Box::new(|_, _| Priority::Stash));
        let (pfn_tx, pfn_rx) = watch::channel(SubnetTopology::default());
        let (mut mgr, _channels) = ReceiverManagerBuilder::new()
            .with_priority_fn_producer(Arc::new(mock_pfn))
            .with_topology_watcher(pfn_rx)
            .build();

        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(1),
                update: Update::Advert((0, ())),
            },
            NODE_1,
            ConnId::from(1),
        );
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(1),
                update: Update::Advert((0, ())),
            },
            NODE_2,
            ConnId::from(1),
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
        assert!(mgr.slot_table.get(&NODE_2).is_none());
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
        assert!(mgr.slot_table.get(&NODE_1).is_none());
        assert!(mgr.slot_table.get(&NODE_2).is_none());
    }

    /// Verify that if node leaves subnet all download tasks are informed.
    #[tokio::test]
    async fn topology_update_finish_download() {
        // Abort process if a thread panics. This catches detached tokio tasks that panic.
        // https://github.com/tokio-rs/tokio/issues/4516
        std::panic::set_hook(Box::new(|info| {
            let stacktrace = Backtrace::force_capture();
            println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
            std::process::abort();
        }));

        let mut mock_pfn = MockPriorityFnAndFilterProducer::new();
        mock_pfn
            .expect_get_priority_function()
            .returning(|_| Box::new(|_, _| Priority::Stash));

        let (pfn_tx, pfn_rx) = watch::channel(SubnetTopology::default());

        let (mut mgr, _channels) = ReceiverManagerBuilder::new()
            .with_priority_fn_producer(Arc::new(mock_pfn))
            .with_topology_watcher(pfn_rx)
            .build();

        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(1),
                update: Update::Advert((0, ())),
            },
            NODE_1,
            ConnId::from(1),
        );
        assert_eq!(mgr.active_downloads.len(), 1);
        assert_eq!(mgr.artifact_processor_tasks.len(), 1);
        // Remove node with active download from topology.
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
        // Abort process if a thread panics. This catches detached tokio tasks that panic.
        // https://github.com/tokio-rs/tokio/issues/4516
        std::panic::set_hook(Box::new(|info| {
            let stacktrace = Backtrace::force_capture();
            println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
            std::process::abort();
        }));

        let (mut mgr, _channels) = ReceiverManagerBuilder::new().build();

        // Add id 0 on slot 1.
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(1),
                update: Update::Advert((0, ())),
            },
            NODE_1,
            ConnId::from(1),
        );
        // Add id 0 on slot 2.
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(2),
                commit_id: CommitId::from(2),
                update: Update::Advert((0, ())),
            },
            NODE_1,
            ConnId::from(1),
        );
        // Overwrite id 0 on slot 1.
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(3),
                update: Update::Advert((1, ())),
            },
            NODE_1,
            ConnId::from(1),
        );

        // Make sure no download task closes since we still have slot entries for 0 and 1.
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
                update: Update::Advert((1, ())),
            },
            NODE_1,
            ConnId::from(1),
        );

        // Make sure the download task for 0 closes since both entries got overwritten.
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
        // Abort process if a thread panics. This catches detached tokio tasks that panic.
        // https://github.com/tokio-rs/tokio/issues/4516
        std::panic::set_hook(Box::new(|info| {
            let stacktrace = Backtrace::force_capture();
            println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
            std::process::abort();
        }));

        let mut mock_pfn = MockPriorityFnAndFilterProducer::new();
        mock_pfn
            .expect_get_priority_function()
            .returning(|_| Box::new(|_, _| Priority::Stash));

        let (mut mgr, _channels) = ReceiverManagerBuilder::new()
            .with_priority_fn_producer(Arc::new(mock_pfn))
            .build();

        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(1),
                update: Update::Advert((0, ())),
            },
            NODE_1,
            ConnId::from(1),
        );
        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(2),
                commit_id: CommitId::from(2),
                update: Update::Advert((1, ())),
            },
            NODE_1,
            ConnId::from(1),
        );
        assert_eq!(mgr.artifact_processor_tasks.len(), 2);

        // Make sure no download task closes since we still have slot entries for 0 and 1.
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
                update: Update::Advert((0, ())),
            },
            NODE_1,
            ConnId::from(1),
        );
        // Only download task 1 closes because it got overwritten.
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
        // Abort process if a thread panics. This catches detached tokio tasks that panic.
        // https://github.com/tokio-rs/tokio/issues/4516
        std::panic::set_hook(Box::new(|info| {
            let stacktrace = Backtrace::force_capture();
            println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
            std::process::abort();
        }));

        let (mut mgr, _channels) = ReceiverManagerBuilder::new().build();

        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(1),
                update: Update::Advert((0, ())),
            },
            NODE_1,
            ConnId::from(1),
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
                update: Update::Advert((0, ())),
            },
            NODE_1,
            ConnId::from(1),
        );

        // Make sure no download task closes since we still have entry for 0.
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
                update: Update::Advert((2, ())),
            },
            NODE_1,
            ConnId::from(1),
        );

        // Make sure the download task for 0 closes.
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
    async fn fetch_to_stash() {
        // Abort process if a thread panics. This catches detached tokio tasks that panic.
        // https://github.com/tokio-rs/tokio/issues/4516
        std::panic::set_hook(Box::new(|info| {
            let stacktrace = Backtrace::force_capture();
            println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
            std::process::abort();
        }));

        let mut mock_pfn = MockPriorityFnAndFilterProducer::new();
        let priorities = Arc::new(Mutex::new(vec![Priority::Fetch, Priority::Stash]));
        mock_pfn
            .expect_get_priority_function()
            .times(1)
            .returning(move |_| {
                let priorities = priorities.clone();
                Box::new(move |_, _| priorities.lock().unwrap().remove(0))
            });
        let mut mock_transport = MockTransport::new();
        mock_transport.expect_rpc().once().returning(|_, _| {
            Ok(Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Bytes::new())
                .unwrap())
        });

        let (mut mgr, _channels) = ReceiverManagerBuilder::new()
            .with_priority_fn_producer(Arc::new(mock_pfn))
            .with_transport(Arc::new(mock_transport))
            .build();

        mgr.handle_advert_receive(
            SlotUpdate {
                slot_number: SlotNumber::from(1),
                commit_id: CommitId::from(1),
                update: Update::Advert((0, ())),
            },
            NODE_1,
            ConnId::from(1),
        );

        timeout(
            Duration::from_secs(4),
            mgr.artifact_processor_tasks.join_next(),
        )
        .await
        .expect_err("Task should not close because it is stash.");
    }

    /// Verify that downloads with AdvertId != ArtifactId are not added to the pool.
    #[test]
    fn invalid_artifact_not_accepted() {
        // Abort process if a thread panics. This catches detached tokio tasks that panic.
        // https://github.com/tokio-rs/tokio/issues/4516
        std::panic::set_hook(Box::new(|info| {
            let stacktrace = Backtrace::force_capture();
            println!("Got panic. @info:{}\n@stackTrace:{}", info, stacktrace);
            std::process::abort();
        }));
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut mock_transport = MockTransport::new();
        let mut seq = Sequence::new();
        // Respond with artifact that does not correspond to the advertised ID
        mock_transport
            .expect_rpc()
            .once()
            .returning(|_, _| {
                Ok(Response::builder()
                    .body(Bytes::from(
                        <<U64Artifact as ArtifactKind>::PbMessage>::proxy_encode(1_u64),
                    ))
                    .unwrap())
            })
            .in_sequence(&mut seq);
        // Respond with artifact that does correspond to the advertised ID
        mock_transport
            .expect_rpc()
            .once()
            .returning(|_, _| {
                // Respond with artifact that does correspond to the advertised ID
                Ok(Response::builder()
                    .body(Bytes::from(
                        <<U64Artifact as ArtifactKind>::PbMessage>::proxy_encode(0_u64),
                    ))
                    .unwrap())
            })
            .in_sequence(&mut seq);

        let mut pc = PeerCounter::new();
        pc.insert(NODE_1);
        let (_peer_tx, mut peer_rx) = watch::channel(pc);
        let pfn = |_: &_, _: &_| Priority::Fetch;
        let (_pfn_tx, pfn_rx) = watch::channel(Box::new(pfn) as Box<_>);

        rt.block_on(async {
            assert_eq!(
                ConsensusManagerReceiver::<
                    U64Artifact,
                    MockValidatedPoolReader<U64Artifact>,
                    (SlotUpdate<U64Artifact>, NodeId, ConnId),
                >::download_artifact(
                    no_op_logger(),
                    &0,
                    &(),
                    None,
                    &mut peer_rx,
                    pfn_rx,
                    Arc::new(mock_transport),
                    ConsensusManagerMetrics::new::<U64Artifact>(&MetricsRegistry::default()),
                )
                .await,
                Ok((0, NODE_1))
            )
        });
    }

    #[tokio::test]
    async fn large_artifact() {
        use ic_protobuf::p2p::v1 as pb;

        #[derive(PartialEq, Eq, Debug, Clone)]
        pub struct BigArtifact;

        impl ArtifactKind for BigArtifact {
            // Does not matter
            const TAG: ArtifactTag = ArtifactTag::ConsensusArtifact;
            type PbMessage = Vec<u8>;
            type PbIdError = Infallible;
            type PbMessageError = Infallible;
            type PbAttributeError = Infallible;
            type PbFilterError = Infallible;
            type Message = Vec<u8>;
            type PbId = ();
            type Id = ();
            type PbAttribute = ();
            type Attribute = ();
            type PbFilter = ();
            type Filter = ();

            fn message_to_advert(_: &Self::Message) -> Advert<BigArtifact> {
                todo!()
            }
        }

        let (router, mut update_rx) = build_axum_router::<BigArtifact>(
            no_op_logger(),
            Arc::new(RwLock::new(MockValidatedPoolReader::default())),
        );

        let slot_update = SlotUpdate::<BigArtifact> {
            slot_number: 0.into(),
            commit_id: 0.into(),
            update: Update::Artifact(vec![0; 100_000_000]),
        };

        let req_pb = pb::SlotUpdate::proxy_encode(slot_update);

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
