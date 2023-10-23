use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    hash::Hash,
    sync::{Arc, RwLock},
    time::Duration,
};

use crate::{metrics::ConsensusManagerMetrics, AdvertUpdate, CommitId, Data, SlotNumber};
use axum::{
    extract::State,
    http::{Request, StatusCode},
    routing::any,
    Extension, Router,
};
use bytes::Bytes;
use crossbeam_channel::Sender as CrossbeamSender;
use ic_interfaces::{
    artifact_pool::{
        PriorityFnAndFilterProducer, UnvalidatedArtifact, UnvalidatedArtifactEvent,
        ValidatedPoolReader,
    },
    time_source::TimeSource,
};
use ic_logger::ReplicaLogger;
use ic_peer_manager::SubnetTopology;
use ic_quic_transport::{ConnId, Transport};
use ic_types::artifact::{Advert, ArtifactKind, Priority, PriorityFn};
use ic_types::NodeId;
use rand::{rngs::SmallRng, seq::IteratorRandom, SeedableRng};
use serde::{Deserialize, Serialize};
use tokio::{
    runtime::Handle,
    select,
    sync::{
        mpsc::{Receiver, Sender},
        watch,
    },
    task::JoinSet,
    time::{self, MissedTickBehavior},
};

type ValidatedPoolReaderRef<T> = Arc<RwLock<dyn ValidatedPoolReader<T> + Send + Sync>>;
type ReceivedAdvertSender<A> = Sender<(AdvertUpdate<A>, NodeId, ConnId)>;

#[allow(unused)]
pub fn build_axum_router<Artifact: ArtifactKind>(
    log: ReplicaLogger,
    rt: Handle,
    pool: ValidatedPoolReaderRef<Artifact>,
) -> (Router, Receiver<(AdvertUpdate<Artifact>, NodeId, ConnId)>)
where
    Artifact: ArtifactKind + Serialize + for<'a> Deserialize<'a> + Send + 'static,
    <Artifact as ArtifactKind>::Id:
        Serialize + for<'a> Deserialize<'a> + Clone + Eq + Hash + Send + Sync,
    <Artifact as ArtifactKind>::Attribute: Serialize + for<'a> Deserialize<'a> + Send + Sync,
    <Artifact as ArtifactKind>::Message: Serialize + for<'a> Deserialize<'a> + Send,
{
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
) -> Result<Bytes, StatusCode>
where
    Artifact: ArtifactKind + Serialize + for<'a> Deserialize<'a> + Send + 'static,
    <Artifact as ArtifactKind>::Id:
        Serialize + for<'a> Deserialize<'a> + Clone + Eq + Hash + Send + Sync,
    <Artifact as ArtifactKind>::Message: Serialize + for<'a> Deserialize<'a> + Send,
    <Artifact as ArtifactKind>::Attribute: Serialize + for<'a> Deserialize<'a> + Send + Sync,
{
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
) -> Result<(), StatusCode>
where
    Artifact: ArtifactKind + Serialize + for<'a> Deserialize<'a>,
    <Artifact as ArtifactKind>::Id: Serialize + for<'a> Deserialize<'a> + Sync,
    <Artifact as ArtifactKind>::Message: Serialize + for<'a> Deserialize<'a>,
    <Artifact as ArtifactKind>::Attribute: Serialize + for<'a> Deserialize<'a> + Sync,
{
    let update: AdvertUpdate<Artifact> =
        bincode::deserialize(&payload).map_err(|_| StatusCode::BAD_REQUEST)?;

    sender
        .send((update, peer, conn_id))
        .await
        .expect("Channel should not be closed");

    Ok(())
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
    sender: CrossbeamSender<UnvalidatedArtifactEvent<Artifact>>,
    time_source: Arc<dyn TimeSource>,

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
impl<Artifact, Pool>
    ConsensusManagerReceiver<Artifact, Pool, (AdvertUpdate<Artifact>, NodeId, ConnId)>
where
    Pool: 'static + Send + Sync + ValidatedPoolReader<Artifact>,
    Artifact: ArtifactKind + Serialize + for<'a> Deserialize<'a> + Send + 'static,
    <Artifact as ArtifactKind>::Id:
        Serialize + for<'a> Deserialize<'a> + Clone + Eq + Hash + Send + Sync,
    <Artifact as ArtifactKind>::Message: Serialize + for<'a> Deserialize<'a> + Send,
    <Artifact as ArtifactKind>::Attribute: Serialize + for<'a> Deserialize<'a> + Send + Sync,
{
    pub(crate) fn run(
        log: ReplicaLogger,
        metrics: ConsensusManagerMetrics,
        rt_handle: Handle,

        // Adverts received from peers
        adverts_received: Receiver<(AdvertUpdate<Artifact>, NodeId, ConnId)>,
        raw_pool: Arc<RwLock<Pool>>,
        priority_fn_producer: Arc<dyn PriorityFnAndFilterProducer<Artifact, Pool>>,
        sender: CrossbeamSender<UnvalidatedArtifactEvent<Artifact>>,
        time_source: Arc<dyn TimeSource>,
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
            time_source,
            transport,
            active_downloads: HashMap::new(),
            slot_table: HashMap::new(),
            artifact_processor_tasks: JoinSet::new(),
            topology_watcher,
        };

        rt_handle.spawn(receive_manager.start_event_loop());
    }

    async fn start_event_loop(mut self) {
        let mut pfn_interval = time::interval(Duration::from_secs(1));
        pfn_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            select! {
                _ = pfn_interval.tick() => {
                    let pool = &self.raw_pool.read().unwrap();
                    let priority_fn = self.priority_fn_producer.get_priority_function(pool);
                    self.current_priority_fn.send_replace(priority_fn);

                    pfn_interval.reset();
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
        }
    }

    pub(crate) fn handle_advert_receive(
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
                self.metrics.slots_in_use_per_peer.with_label_values(&[peer_id.to_string().as_str()]).inc();
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

    /// Notifies all running tasks about the topology update.
    fn handle_topology_update(&mut self) {
        let new_topology = self.topology_watcher.borrow().clone();
        let mut nodes_leaving_topology: HashSet<NodeId> = HashSet::new();

        self.slot_table.retain(|node_id, _| {
            if !new_topology.is_member(node_id) {
                nodes_leaving_topology.insert(*node_id);
                self.metrics
                    .slots_in_use_per_peer
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
                    .map(|n| set.remove(n))
                    .any(|r| r)
            });
        }
    }
}

fn build_rpc_handler_request<T: Serialize>(uri_prefix: &str, id: &T) -> Request<Bytes> {
    Request::builder()
        .uri(format!("/{}/rpc", uri_prefix))
        .body(Bytes::from(bincode::serialize(id).unwrap()))
        .unwrap()
}

enum DownloadResult<T> {
    Completed(T, NodeId),
    AllPeersDeletedTheArtifact,
    PriorityIsDrop,
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
