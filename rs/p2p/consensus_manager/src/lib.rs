use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    sync::{Arc, RwLock},
    time::Duration,
};

use axum::{
    extract::State,
    http::{Request, StatusCode},
    routing::any,
    Extension, Router,
};
use backoff::backoff::Backoff;
use bytes::Bytes;
use crossbeam_channel::Sender as CrossbeamSender;
use ic_async_utils::JoinMap;
use ic_interfaces::{
    artifact_manager::ArtifactProcessorEvent,
    artifact_pool::{
        PriorityFnAndFilterProducer, UnvalidatedArtifact, UnvalidatedArtifactEvent,
        ValidatedPoolReader,
    },
    time_source::TimeSource,
};
use ic_logger::{error, ReplicaLogger};
use ic_metrics::{buckets::decimal_buckets_with_zero, MetricsRegistry};
use ic_peer_manager::SubnetTopology;
use ic_quic_transport::{ConnId, Transport};
use ic_types::artifact::{Advert, ArtifactKind, Priority, PriorityFn};
use ic_types::NodeId;
use phantom_newtype::AmountOf;
use prometheus::{Histogram, IntCounter, IntGauge};
use rand::{rngs::SmallRng, seq::IteratorRandom, SeedableRng};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::{
    runtime::Handle,
    select,
    sync::{
        mpsc::{Receiver, Sender},
        watch,
    },
    task::{JoinHandle, JoinSet},
    time,
};

const ENABLE_ARTIFACT_PUSH: bool = false;
/// Artifact push threshold. Artifacts smaller or equal than this are pushed.
const ARTIFACT_PUSH_THRESHOLD: usize = 5 * 1024;

const MIN_BACKOFF_INTERVAL: Duration = Duration::from_millis(250);
// The value must be smaller than `ic_http_handler::MAX_TCP_PEEK_TIMEOUT_SECS`.
// See VER-1060 for details.
const MAX_BACKOFF_INTERVAL: Duration = Duration::from_secs(10);
// The multiplier is chosen such that the sum of all intervals is about 100
// seconds: `sum ~= (1.1^25 - 1) / (1.1 - 1) ~= 98`.
const BACKOFF_INTERVAL_MULTIPLIER: f64 = 1.1;
const MAX_ELAPSED_TIME: Duration = Duration::from_secs(60 * 5); // 5 minutes

/// Validated artifact pool on mainnet contains ~10k artifacts.
/// Since the slot table mirrors the pool, we chose 50k slots for now.
/// This number is not enforced, but will log errors if the number of slots
/// used exceeds this number.
const MAX_SLOTS: u64 = 50_000;

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

#[derive(Debug, Clone)]
pub(crate) struct ConsensusManagerMetrics {
    pub active_downloads: IntGauge,
    /// free slots in the slot table of the send side.
    pub free_slots: IntGauge,
    /// The capacity of the slot table on the send side.
    pub maximum_slots_total: IntCounter,

    /// Number of adverts sent to peers from this node.
    pub adverts_to_send_total: IntCounter,

    pub adverts_to_purge_total: IntCounter,

    pub artifacts_pushed_total: IntCounter,

    /// Number of adverts received from peers.
    pub adverts_received_total: IntCounter,

    /// Number of adverts received from after joining the task and already deleted the advert.
    pub peer_advertising_after_deletion_total: IntCounter,

    /// Number of adverts that were stashed at least once.
    pub adverts_stashed_total: IntCounter,

    /// Download attempts for an advert
    pub advert_download_attempts: Histogram,

    /// Dropped adverts
    pub adverts_dropped_total: IntCounter,

    /// Active advert being sent to peers.
    pub active_advert_transmits: IntGauge,

    pub receive_new_adverts_total: IntCounter,

    pub receive_seen_adverts_total: IntCounter,

    pub receive_slot_table_removals_total: IntCounter,

    pub active_download_removals_total: IntCounter,

    pub receive_used_slot_to_overwrite_total: IntCounter,

    pub receive_used_slot_stale_total: IntCounter,
}

impl ConsensusManagerMetrics {
    pub fn new<Artifact: ArtifactKind>(metrics_registry: &MetricsRegistry) -> Self {
        let prefix = Artifact::TAG.to_string().to_lowercase();
        Self {
            active_downloads: metrics_registry.int_gauge(
                format!("{prefix}_manager_active_downloads").as_str(),
                "TODO.",
            ),
            free_slots: metrics_registry
                .int_gauge(format!("{prefix}_manager_free_slots").as_str(), "TODO."),
            maximum_slots_total: metrics_registry.int_counter(
                format!("{prefix}_manager_maximum_slots_total").as_str(),
                "TODO.",
            ),
            adverts_to_send_total: metrics_registry.int_counter(
                format!("{prefix}_manager_adverts_to_send_total").as_str(),
                "TODO.",
            ),
            adverts_to_purge_total: metrics_registry.int_counter(
                format!("{prefix}_manager_adverts_to_purge_total").as_str(),
                "TODO.",
            ),
            artifacts_pushed_total: metrics_registry.int_counter(
                format!("{prefix}_manager_artifacts_pushed_total").as_str(),
                "TODO.",
            ),
            adverts_received_total: metrics_registry.int_counter(
                format!("{prefix}_manager_adverts_received_total").as_str(),
                "TODO.",
            ),
            peer_advertising_after_deletion_total: metrics_registry.int_counter(
                format!("{prefix}_manager_peer_advertising_after_deletion_total").as_str(),
                "TODO.",
            ),
            adverts_stashed_total: metrics_registry.int_counter(
                format!("{prefix}_manager_adverts_stashed_total").as_str(),
                "TODO.",
            ),
            advert_download_attempts: metrics_registry.histogram(
                format!("{prefix}_manager_advert_download_attempts").as_str(),
                "TODO.",
                decimal_buckets_with_zero(0, 1),
            ),
            active_advert_transmits: metrics_registry.int_gauge(
                format!("{prefix}_manager_active_advert_transmits").as_str(),
                "TODO.",
            ),
            adverts_dropped_total: metrics_registry.int_counter(
                format!("{prefix}_manager_adverts_dropped_total").as_str(),
                "TODO.",
            ),
            receive_new_adverts_total: metrics_registry.int_counter(
                format!("{prefix}_manager_receive_new_adverts_total").as_str(),
                "TODO.",
            ),
            receive_seen_adverts_total: metrics_registry.int_counter(
                format!("{prefix}_manager_receive_seen_adverts_total").as_str(),
                "TODO.",
            ),
            receive_slot_table_removals_total: metrics_registry.int_counter(
                format!("{prefix}_manager_receive_slot_table_removals_total").as_str(),
                "TODO.",
            ),
            active_download_removals_total: metrics_registry.int_counter(
                format!("{prefix}_manager_active_download_removals_total").as_str(),
                "TODO.",
            ),
            receive_used_slot_to_overwrite_total: metrics_registry.int_counter(
                format!("{prefix}_manager_receive_used_slot_to_overwrite_total").as_str(),
                "TODO.",
            ),
            receive_used_slot_stale_total: metrics_registry.int_counter(
                format!("{prefix}_manager_receive_used_slot_stale_total").as_str(),
                "TODO.",
            ),
        }
    }
}

type ValidatedPoolReaderRef<T> = Arc<RwLock<dyn ValidatedPoolReader<T> + Send + Sync>>;
type ReceivedAdvertSender<A> = Sender<(AdvertUpdate<A>, NodeId, ConnId)>;

#[allow(unused)]
pub fn build_axum_router<Artifact: ArtifactKind>(
    log: ReplicaLogger,
    rt: Handle,
    pool: ValidatedPoolReaderRef<Artifact>,
) -> (Router, Receiver<(AdvertUpdate<Artifact>, NodeId, ConnId)>) {
    let (update_tx, update_rx) = tokio::sync::mpsc::channel(100);
    let endpoint: &'static str = Artifact::TAG.into();
    let router = Router::new()
        .route(&format!("/{}/rpc", endpoint), any(rpc_handler))
        .with_state(pool)
        .route(&format!("/{}/update", endpoint), any(update_handler))
        .with_state(update_tx);

    (router, update_rx)
}

async fn rpc_handler<Artifact: ArtifactKind>(
    State(pool): State<ValidatedPoolReaderRef<Artifact>>,
    payload: Bytes,
) -> Result<Bytes, StatusCode> {
    let id: Artifact::Id = bincode::deserialize(&payload).map_err(|_| StatusCode::BAD_REQUEST)?;

    let jh =
        tokio::task::spawn_blocking(move || pool.read().unwrap().get_validated_by_identifier(&id));
    let msg = jh
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NO_CONTENT)?;

    let bytes = Bytes::from(bincode::serialize(&msg).unwrap());

    Ok(bytes)
}

async fn update_handler<Artifact: ArtifactKind>(
    State(sender): State<ReceivedAdvertSender<Artifact>>,
    Extension(peer): Extension<NodeId>,
    Extension(conn_id): Extension<ConnId>,
    payload: Bytes,
) -> Result<(), StatusCode> {
    let update: AdvertUpdate<Artifact> =
        bincode::deserialize(&payload).map_err(|_| StatusCode::BAD_REQUEST)?;

    sender
        .send((update, peer, conn_id))
        .await
        .expect("Channel should not be closed");

    Ok(())
}

fn build_rpc_handler_request<T: Serialize>(uri_prefix: &str, id: &T) -> Request<Bytes> {
    Request::builder()
        .uri(format!("/{}/rpc", uri_prefix))
        .body(Bytes::from(bincode::serialize(id).unwrap()))
        .unwrap()
}

#[allow(unused)]

pub struct ConsensusManager<Artifact: ArtifactKind, Pool, ReceivedAdvert> {
    log: ReplicaLogger,
    metrics: ConsensusManagerMetrics,
    rt_handle: Handle,
    // Send side:
    adverts_to_send: Receiver<ArtifactProcessorEvent<Artifact>>,
    // Receive side:
    adverts_received: Receiver<ReceivedAdvert>,
    pool_reader: Arc<RwLock<dyn ValidatedPoolReader<Artifact> + Send + Sync>>,
    raw_pool: Arc<RwLock<Pool>>,
    priority_fn_producer: Arc<dyn PriorityFnAndFilterProducer<Artifact, Pool>>,
    current_priority_fn: watch::Sender<PriorityFn<Artifact::Id, Artifact::Attribute>>,
    sender: CrossbeamSender<UnvalidatedArtifactEvent<Artifact>>,
    time_source: Arc<dyn TimeSource>,
    transport: Arc<dyn Transport>,
    active_adverts: HashMap<Artifact::Id, (JoinHandle<()>, SlotNumber)>,
    current_commit_id: CommitId,
    slot_manager: SlotManager,
    // Todo: create a struct for the receive side slot tables?
    slot_table: HashMap<NodeId, HashMap<SlotNumber, SlotEntry<Artifact::Id>>>,
    active_downloads: HashMap<Artifact::Id, watch::Sender<HashSet<NodeId>>>,
    #[allow(clippy::type_complexity)]
    artifact_processor_tasks: JoinSet<(
        watch::Receiver<HashSet<NodeId>>,
        Artifact::Id,
        Artifact::Attribute,
    )>,
    topology_watcher: watch::Receiver<SubnetTopology>,
}

#[allow(unused)]

impl<Artifact, Pool> ConsensusManager<Artifact, Pool, (AdvertUpdate<Artifact>, NodeId, ConnId)>
where
    Pool: 'static + Send + Sync + ValidatedPoolReader<Artifact>,
    Artifact: ArtifactKind,
{
    pub fn start_consensus_manager(
        log: ReplicaLogger,
        metrics_registry: &MetricsRegistry,
        rt: Handle,
        // Locally produced adverts to send to the node's peers.
        adverts_to_send: Receiver<ArtifactProcessorEvent<Artifact>>,
        // Adverts received from peers
        adverts_received: Receiver<(AdvertUpdate<Artifact>, NodeId, ConnId)>,
        raw_pool: Arc<RwLock<Pool>>,
        priority_fn_producer: Arc<dyn PriorityFnAndFilterProducer<Artifact, Pool>>,
        sender: CrossbeamSender<UnvalidatedArtifactEvent<Artifact>>,
        time_source: Arc<dyn TimeSource>,
        transport: Arc<dyn Transport>,
        topology_watcher: watch::Receiver<SubnetTopology>,
    ) {
        let metrics = ConsensusManagerMetrics::new::<Artifact>(metrics_registry);
        let slot_manager = SlotManager::new(log.clone(), metrics.clone());

        let priority_fn = priority_fn_producer.get_priority_function(&raw_pool.read().unwrap());
        let (current_priority_fn, _) = watch::channel(priority_fn);

        let manager = ConsensusManager {
            log,
            metrics,
            rt_handle: rt.clone(),
            adverts_to_send,
            adverts_received,
            pool_reader: raw_pool.clone() as Arc<_>,
            raw_pool,
            priority_fn_producer,
            current_priority_fn,
            sender,
            time_source,
            transport,
            active_adverts: HashMap::new(),
            current_commit_id: CommitId::from(0),
            slot_manager,
            active_downloads: HashMap::new(),
            slot_table: HashMap::new(),
            artifact_processor_tasks: JoinSet::new(),
            topology_watcher,
        };

        rt.spawn(manager.run());
    }

    async fn run(mut self) {
        let mut pfn_interval = time::interval(Duration::from_secs(1));
        loop {
            select! {
                _ = pfn_interval.tick() => {
                    let pool = &self.raw_pool.read().unwrap();
                    let priority_fn = self.priority_fn_producer.get_priority_function(pool);

                    self.current_priority_fn.send_replace(priority_fn);
                }
                Some(advert) = self.adverts_to_send.recv() => {
                    self.handle_advert_to_send(advert);
                }
                Some((advert_update, peer_id, conn_id)) = self.adverts_received.recv() => {
                    self.metrics.adverts_received_total.inc();
                    self.handle_advert_receive(advert_update, peer_id, conn_id);
                }
                Some(result) = self.artifact_processor_tasks.join_next() => {
                    let (peer_rx,id,attr) = result.expect("Should not be cancelled or panic");

                    // peer advertised after task finished.
                    if !peer_rx.borrow().is_empty() {

                        self.metrics.peer_advertising_after_deletion_total.inc();

                        self.artifact_processor_tasks.spawn_on(
                            Self::process_advert(
                                id,
                                attr,
                                None,
                                peer_rx,
                                self.current_priority_fn.subscribe(),
                                self.sender.clone(),
                                self.time_source.clone(),
                                self.transport.clone(),
                                self.metrics.clone()
                            ),
                            &self.rt_handle,
                        );

                    } else {
                        self.metrics.active_download_removals_total.inc();
                        self.active_downloads.remove(&id);
                    }
                }
                Ok(()) = self.topology_watcher.changed() => {
                    self.handle_topology_update();
                }
            }
            self.metrics
                .active_downloads
                .set(self.active_downloads.len() as i64);

            self.metrics
                .active_advert_transmits
                .set(self.active_adverts.len() as i64);
        }
    }

    /// Notifies all running tasks about the topology update.
    fn handle_topology_update(&mut self) {
        let new_topology = self.topology_watcher.borrow().clone();
        let mut nodes_leaving_topology: HashSet<NodeId> = HashSet::new();

        self.slot_table.retain(|node_id, _| {
            if !new_topology.is_member(node_id) {
                nodes_leaving_topology.insert(*node_id);
                false
            } else {
                true
            }
        });

        for peers_sender in self.active_downloads.values() {
            peers_sender.send_if_modified(|set| {
                nodes_leaving_topology
                    .iter()
                    .map(|n| set.remove(n))
                    .any(|r| r)
            });
        }
    }

    /// Downloads a given artifact.
    ///
    /// The download will be scheduled based on the given priority function, `priority_fn_watcher`.
    ///
    /// The download fails iff:
    /// - The priority function evaluates the advert to [`Priority::Drop`] -> [`DownloadResult::PriorityIsDrop`]
    /// - The set of peers advertising the artifact, `peer_rx`, becomes empty -> [`DownloadResult::AllPeersDeletedTheArtifact`]
    async fn download_artifact(
        id: &Artifact::Id,
        attr: &Artifact::Attribute,
        // Only first peer for specific artifact ID is considered for push
        mut artifact: Option<(Artifact::Message, NodeId)>,
        mut peer_rx: &mut watch::Receiver<HashSet<NodeId>>,
        mut priority_fn_watcher: watch::Receiver<PriorityFn<Artifact::Id, Artifact::Attribute>>,
        transport: Arc<dyn Transport>,
        metrics: ConsensusManagerMetrics,
    ) -> DownloadResult<Artifact::Message> {
        let mut priority = priority_fn_watcher.borrow_and_update()(id, attr);

        // Clear the artifact from memory if it was pushed.
        if let Priority::Stash = priority {
            artifact.take();
            metrics.adverts_stashed_total.inc();
        }

        while let Priority::Stash = priority {
            select! {
                _ = priority_fn_watcher.changed() => {
                    priority = priority_fn_watcher.borrow_and_update()(id, attr);
                }
                _ = peer_rx.changed() => {
                    if peer_rx.borrow().is_empty() {
                        return DownloadResult::AllPeersDeletedTheArtifact;
                    }
                }
            }
        }

        if let Priority::Drop = priority {
            return DownloadResult::PriorityIsDrop;
        }

        match artifact {
            // Artifact was pushed by peer.
            Some((artifact, peer_id)) => DownloadResult::Completed(artifact, peer_id),

            // Fetch artifact
            None => {
                let mut result = DownloadResult::AllPeersDeletedTheArtifact;
                let mut download_attempts = 0;

                let mut rng = SmallRng::from_entropy();
                while let Some(peer) = {
                    let peer = peer_rx.borrow().iter().choose(&mut rng).copied();
                    peer
                } {
                    download_attempts += 1;

                    let request = build_rpc_handler_request(Artifact::TAG.into(), &id);

                    let peer_deleted_the_artifact = async {
                        peer_rx.changed().await;
                        while peer_rx.borrow().contains(&peer) {
                            peer_rx.changed().await;
                        }
                    };

                    let priority_is_drop = async {
                        priority_fn_watcher.changed().await;
                        while Priority::Drop != priority_fn_watcher.borrow()(id, attr) {
                            priority_fn_watcher.changed().await;
                        }
                    };

                    select! {
                        _ = time::sleep(Duration::from_secs(5)) => {}

                        _ = peer_deleted_the_artifact => {}

                        _ = priority_is_drop => {
                            result = DownloadResult::PriorityIsDrop;
                            break;
                        }

                        rpc_response = transport.rpc(&peer, request) => {
                            if let Ok(response) = rpc_response {
                                if let StatusCode::OK = response.status() {
                                    if let Ok(message) =
                                        bincode::deserialize::<Artifact::Message>(response.body())
                                    {
                                        result = DownloadResult::Completed(message, peer);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                // TODO: Add labels based on if it was dropped or not?
                metrics
                    .advert_download_attempts
                    .observe(download_attempts as f64);

                result
            }
        }
    }

    /// Tries to download the given artifact, and insert it into the unvalidated pool.
    ///
    /// This future completes waits for all peers that advertise the artifact to delete it.
    /// The artifact is deleted from the unvalidated pool upon completion.
    async fn process_advert(
        id: Artifact::Id,
        attr: Artifact::Attribute,
        // Only first peer for specific artifact ID is considered for push
        mut artifact: Option<(Artifact::Message, NodeId)>,
        mut peer_rx: watch::Receiver<HashSet<NodeId>>,
        mut priority_fn_watcher: watch::Receiver<PriorityFn<Artifact::Id, Artifact::Attribute>>,
        sender: CrossbeamSender<UnvalidatedArtifactEvent<Artifact>>,
        time_source: Arc<dyn TimeSource>,
        transport: Arc<dyn Transport>,
        metrics: ConsensusManagerMetrics,
    ) -> (
        watch::Receiver<HashSet<NodeId>>,
        Artifact::Id,
        Artifact::Attribute,
    ) {
        let download_result = Self::download_artifact(
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
            DownloadResult::Completed(artifact, peer_id) => {
                // Send artifact to pool
                sender
                    .send(UnvalidatedArtifactEvent::Insert(UnvalidatedArtifact {
                        message: artifact,
                        peer_id,
                        timestamp: time_source.get_relative_time(),
                    }))
                    .expect("Channel should not be closed");

                // wait for deletion from peers
                peer_rx
                    .wait_for(|p| p.is_empty())
                    .await
                    .expect("Channel should not be closed");

                // Purge from the unvalidated pool
                sender
                    .send(UnvalidatedArtifactEvent::Remove(id.clone()))
                    .expect("Channel should not be closed");
            }
            DownloadResult::PriorityIsDrop => {
                metrics.adverts_dropped_total.inc();

                // wait for deletion from peers
                peer_rx
                    .wait_for(|p| p.is_empty())
                    .await
                    .expect("Channel should not be closed");
            }
            DownloadResult::AllPeersDeletedTheArtifact => {}
        }

        (peer_rx, id, attr)
    }

    fn handle_advert_receive(
        &mut self,
        advert_update: AdvertUpdate<Artifact>,
        peer_id: NodeId,
        connection_id: ConnId,
    ) {
        let AdvertUpdate {
            slot_number,
            commit_id,
            data,
        } = advert_update;
        let (advert, artifact) = match data {
            Data::Artifact(artifact) => (Artifact::message_to_advert(&artifact), Some(artifact)),
            Data::Advert(advert) => (advert, None),
        };
        let Advert { id, attribute, .. } = advert;
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
            // .get_mut(&slot_number)
        {
            Entry::Occupied(mut slot_entry_mut) => {
                // TODO: What if same advert update is sent twice? (Seen this in a test)
                if slot_entry_mut.get().should_be_replaced(&new_slot_entry) {
                    self.metrics.receive_used_slot_to_overwrite_total.inc();
                    let to_remove = slot_entry_mut.insert(new_slot_entry).id;
                    (true, Some(to_remove))
                } else {
                    self.metrics.receive_used_slot_stale_total.inc();

                    (false, None)
                }
            }
            Entry::Vacant(empty_slot) => {
                empty_slot.insert(new_slot_entry);
                (true, None)},
        };

        if to_add {
            match self.active_downloads.get(&id) {
                Some(sender) => {
                    self.metrics.receive_seen_adverts_total.inc();
                    sender.send_if_modified(|h| h.insert(peer_id));
                }
                None => {
                    self.metrics.receive_new_adverts_total.inc();
                    let (tx, rx) = watch::channel(HashSet::new());
                    tx.send_if_modified(|h| h.insert(peer_id));
                    self.active_downloads.insert(id.clone(), tx);
                    self.artifact_processor_tasks.spawn_on(
                        Self::process_advert(
                            id.clone(),
                            attribute,
                            artifact.map(|a| (a, peer_id)),
                            rx,
                            self.current_priority_fn.subscribe(),
                            self.sender.clone(),
                            self.time_source.clone(),
                            self.transport.clone(),
                            self.metrics.clone(),
                        ),
                        &self.rt_handle,
                    );
                }
            }
        }
        if let Some(to_remove) = to_remove {
            // TODO: this should always be a Some.
            // Sender should not be dropped before all peers have overwritten/removed the slot.
            if let Some(sender) = self.active_downloads.get_mut(&to_remove) {
                self.metrics.receive_slot_table_removals_total.inc();
                sender.send_if_modified(|h| {
                    if !h.remove(&peer_id) {
                        panic!("Removed node should always be present")
                    }
                    true
                });
            } else {
                panic!("Sender should always be present for slots in use");
            }
        }
    }

    fn handle_advert_to_send(&mut self, advert: ArtifactProcessorEvent<Artifact>) {
        self.current_commit_id.inc_assign();
        match advert {
            ArtifactProcessorEvent::Advert(advert) => {
                self.metrics.adverts_to_send_total.inc();
                // Only send advert if it is not already being sent.
                if !self.active_adverts.contains_key(&advert.id) {
                    let slot = self.slot_manager.take_free_slot();
                    if advert.size <= ARTIFACT_PUSH_THRESHOLD && ENABLE_ARTIFACT_PUSH {
                        self.metrics.artifacts_pushed_total.inc();
                    }
                    self.active_adverts.insert(
                        advert.id.clone(),
                        (
                            self.rt_handle.spawn(send_advert_to_all_peers(
                                self.rt_handle.clone(),
                                self.transport.clone(),
                                self.current_commit_id,
                                slot,
                                advert,
                                self.pool_reader.clone(),
                            )),
                            slot,
                        ),
                    );
                }
            }
            ArtifactProcessorEvent::Purge(id) => {
                self.metrics.adverts_to_purge_total.inc();
                if let Some((send_task, free_slot)) = self.active_adverts.remove(&id) {
                    send_task.abort();
                    self.slot_manager.give_slot(free_slot);
                }
            }
        }
    }
}

/// Sends an advert to all peers.
///
/// Memory Consumption:
/// - JoinMap: #peers * (32 + ~32)
/// - HashMap: #peers * (32 + 8)
/// - advert: ±200
/// For 10k tasks ~50Mb
async fn send_advert_to_all_peers<Artifact: ArtifactKind>(
    rt_handle: Handle,
    transport: Arc<dyn Transport>,
    commit_id: CommitId,
    slot_number: SlotNumber,
    advert: Advert<Artifact>,
    pool_reader: Arc<RwLock<dyn ValidatedPoolReader<Artifact> + Send + Sync>>,
) {
    let mut in_progress_transmissions = JoinMap::new();
    // stores the connection ID of the last successful transmission to a peer.
    let mut completed_transmissions: HashMap<NodeId, ConnId> = HashMap::new();
    let mut periodic_check_interval = time::interval(Duration::from_secs(5));

    // Try to push artifact if size below threshold
    let artifact = if advert.size <= ARTIFACT_PUSH_THRESHOLD && ENABLE_ARTIFACT_PUSH {
        let id = advert.id.clone();
        tokio::task::spawn_blocking(move || {
            pool_reader.read().unwrap().get_validated_by_identifier(&id)
        })
        .await
        .expect("Should not be cancelled")
    } else {
        None
    };

    let advert_update = if let Some(artifact) = artifact {
        AdvertUpdate {
            slot_number,
            commit_id,
            data: Data::Artifact(artifact),
        }
    } else {
        AdvertUpdate {
            slot_number,
            commit_id,
            data: Data::Advert(advert),
        }
    };

    let body: Bytes = bincode::serialize(&advert_update)
        .expect("Serializing advert update")
        .into();

    loop {
        select! {
            _ = periodic_check_interval.tick() => {
                // check for new peers/connection IDs
                // spawn task for peers with higher conn id or not in completed transmissions.
                // add task to join map
                for (peer, connection_id) in transport.peers() {
                    let is_completed = completed_transmissions.get(&peer).is_some_and(|c| *c == connection_id);

                    if !is_completed {
                        let task = send_advert_to_peer(transport.clone(), connection_id, body.clone(), peer, Artifact::TAG.into());
                        in_progress_transmissions.spawn_on(peer, task, &rt_handle);
                    }
                }
            }
            Some(result) = in_progress_transmissions.join_next() => {
                match result {
                    Ok((connection_id, peer)) => {
                        completed_transmissions.insert(peer, connection_id);
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

/// Sends a serialized advert or artifact message to a peer.
/// If the peer is not reachable, it will retry with an exponential backoff.
/// Memory Consumption:
///  - Backoffpolicy: ±128B
///  - body: ±250B
///  - peer: 32B
///  - connId: 8B
/// For 10k tasks and 40 peers ~100Mb
/// Note: If we start pushing adverts we probably want to just try pushing once
/// and revert back to the advert if the inital push fails.
async fn send_advert_to_peer(
    transport: Arc<dyn Transport>,
    connection_id: ConnId,
    message: Bytes,
    peer: NodeId,
    uri_prefix: &str,
) -> ConnId {
    let mut backoff = get_backoff_policy();

    loop {
        let request = Request::builder()
            .uri(format!("/{}/update", uri_prefix))
            .body(message.clone())
            .expect("Building from typed values");

        if let Ok(()) = transport.push(&peer, request).await {
            return connection_id;
        }

        let backoff_duration = backoff.next_backoff().unwrap_or(MAX_ELAPSED_TIME);
        time::sleep(backoff_duration).await;
    }
}

#[derive(Deserialize, Serialize)]
pub enum Data<Artifact: ArtifactKind> {
    #[serde(bound(deserialize = ""))]
    Artifact(Artifact::Message),
    #[serde(bound(deserialize = ""))]
    Advert(Advert<Artifact>),
}

#[derive(Deserialize, Serialize)]
pub struct AdvertUpdate<Artifact: ArtifactKind> {
    slot_number: SlotNumber,
    commit_id: CommitId,
    #[serde(bound(deserialize = "Artifact: DeserializeOwned"))]
    data: Data<Artifact>,
}

struct SlotManager {
    next_free_slot: SlotNumber,
    free_slots: Vec<SlotNumber>,
    log: ReplicaLogger,
    metrics: ConsensusManagerMetrics,
}

impl SlotManager {
    fn new(log: ReplicaLogger, metrics: ConsensusManagerMetrics) -> Self {
        metrics.free_slots.add(MAX_SLOTS as i64);
        metrics.maximum_slots_total.inc_by(MAX_SLOTS);

        Self {
            next_free_slot: MAX_SLOTS.into(),
            free_slots: (0..MAX_SLOTS).map(AmountOf::from).collect(),
            log,
            metrics,
        }
    }

    fn give_slot(&mut self, slot: SlotNumber) {
        self.free_slots.push(slot);
        self.metrics.free_slots.set(self.free_slots.len() as i64);
    }

    fn take_free_slot(&mut self) -> SlotNumber {
        match self.free_slots.pop() {
            Some(slot) => {
                self.metrics.free_slots.dec();
                slot
            }
            None => {
                error!(
                    self.log,
                    "Slot table exceeded the maximum configured slots = {}. Slots in use = {}.",
                    MAX_SLOTS,
                    self.next_free_slot
                );

                let new_slot = self.next_free_slot;
                self.next_free_slot += new_slot.increment();

                self.metrics.maximum_slots_total.inc();

                new_slot
            }
        }
    }
}

struct SlotEntry<T> {
    conn_id: ConnId,
    commit_id: CommitId,
    id: T,
}

impl<T> SlotEntry<T> {
    // TODO: Revisit this. We should never reach the error case since we don't transmit twice
    // for same connid/commitid so it would only happen in the malicious case.
    fn should_be_replaced(&self, other: &SlotEntry<T>) -> bool {
        if other.conn_id != self.conn_id {
            return other.conn_id > self.conn_id;
        }
        // connection ids are the same
        if other.commit_id != self.commit_id {
            return other.commit_id > self.commit_id;
        }
        false
    }
}

struct CommitIdTag;

type CommitId = AmountOf<CommitIdTag, u64>;

struct SlotNumberTag;

type SlotNumber = AmountOf<SlotNumberTag, u64>;

enum DownloadResult<T> {
    Completed(T, NodeId),
    AllPeersDeletedTheArtifact,
    PriorityIsDrop,
}
