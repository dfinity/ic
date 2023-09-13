use std::{
    collections::HashMap,
    fmt::Debug,
    hash::Hash,
    sync::{Arc, RwLock},
    time::Duration,
};

use axum::{http::Request, Router};
use backoff::backoff::Backoff;
use bytes::Bytes;
use crossbeam_channel::Sender as CrossbeamSender;
use ic_async_utils::JoinMap;
use ic_interfaces::{
    artifact_manager::ArtifactProcessorEvent,
    artifact_pool::{PriorityFnAndFilterProducer, UnvalidatedArtifact, ValidatedPoolReader},
    time_source::TimeSource,
};
use ic_logger::{error, ReplicaLogger};
use ic_quic_transport::{ConnId, Transport};
use ic_types::artifact::{Advert, ArtifactKind};
use ic_types::NodeId;
use serde::{Deserialize, Serialize};
use tokio::{
    runtime::Handle,
    select,
    sync::mpsc::Receiver,
    task::JoinHandle,
    time::{self},
};

//TODO: Move all these bounds to the ArtifactKind trait directly.
pub trait CommonTraits: Clone + Send + Sync + Eq + Hash + Debug + 'static {}

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

pub fn build_axum_router<Artifact: ArtifactKind>(
    _log: ReplicaLogger,
    _rt: Handle,
    _pool: Arc<RwLock<dyn ValidatedPoolReader<Artifact> + Send + Sync>>,
) -> (Router, Receiver<()>) {
    todo!("")
}

pub fn start_consensus_manager<Artifact: ArtifactKind, Pool>(
    log: ReplicaLogger,
    rt: Handle,
    // Locally produced adverts to send to the node's peers.
    adverts_to_send: Receiver<ArtifactProcessorEvent<Artifact>>,
    // Adverts received from peers
    adverts_received: Receiver<()>,
    pool: Arc<RwLock<dyn ValidatedPoolReader<Artifact> + Send + Sync>>,
    priority_fn: Arc<dyn PriorityFnAndFilterProducer<Artifact, Pool>>,
    sender: CrossbeamSender<UnvalidatedArtifact<Artifact::Message>>,
    time_source: Arc<dyn TimeSource>,
    transport: Arc<dyn Transport>,
) where
    Pool: 'static,
    Artifact: ArtifactKind + Serialize + for<'a> Deserialize<'a> + CommonTraits,
    <Artifact as ArtifactKind>::Id: Serialize + for<'a> Deserialize<'a> + CommonTraits,
    <Artifact as ArtifactKind>::Message: Serialize + for<'a> Deserialize<'a> + CommonTraits,
    <Artifact as ArtifactKind>::Attribute: Serialize + for<'a> Deserialize<'a> + CommonTraits,
{
    let slot_manager = SlotManager::new(log.clone());

    let manager = ConsensusManager {
        log,
        rt_handle: rt.clone(),
        advert_event: adverts_to_send,
        adverts_received,
        pool,
        priority_fn,
        sender,
        time_source,
        transport,
        active_adverts: HashMap::new(),
        current_commit_id: 0,
        slot_manager,
    };

    rt.spawn(manager.run());
}

#[allow(unused)]
struct ConsensusManager<Artifact: ArtifactKind, Pool> {
    log: ReplicaLogger,
    rt_handle: Handle,
    adverts_received: Receiver<()>,
    advert_event: Receiver<ArtifactProcessorEvent<Artifact>>,
    pool: Arc<RwLock<dyn ValidatedPoolReader<Artifact> + Send + Sync>>,
    priority_fn: Arc<dyn PriorityFnAndFilterProducer<Artifact, Pool>>,
    sender: CrossbeamSender<UnvalidatedArtifact<Artifact::Message>>,
    time_source: Arc<dyn TimeSource>,
    transport: Arc<dyn Transport>,
    active_adverts: HashMap<Artifact::Id, (JoinHandle<()>, u64)>,
    current_commit_id: u64,
    slot_manager: SlotManager,
}

impl<Artifact, Pool> ConsensusManager<Artifact, Pool>
where
    Pool: 'static,
    Artifact: ArtifactKind + Serialize + for<'a> Deserialize<'a> + CommonTraits,
    <Artifact as ArtifactKind>::Id: Serialize + for<'a> Deserialize<'a> + CommonTraits,
    <Artifact as ArtifactKind>::Message: Serialize + for<'a> Deserialize<'a> + CommonTraits,
    <Artifact as ArtifactKind>::Attribute: Serialize + for<'a> Deserialize<'a> + CommonTraits,
{
    async fn run(mut self) {
        loop {
            select! {
                Some(advert) = self.advert_event.recv() => {
                    self.handle_advert_event(advert);
                }
            }
        }
    }

    /// Handles
    fn handle_advert_event(&mut self, advert_event: ArtifactProcessorEvent<Artifact>) {
        self.current_commit_id += 1;
        match advert_event {
            ArtifactProcessorEvent::Advert(advert) => {
                if !self.active_adverts.contains_key(&advert.id) {
                    let slot = self.slot_manager.get_free_slot();
                    self.active_adverts.insert(
                        advert.id.clone(),
                        (
                            self.rt_handle.spawn(send_advert_to_all_peers(
                                self.rt_handle.clone(),
                                self.transport.clone(),
                                self.current_commit_id,
                                slot,
                                advert.clone(),
                                self.pool.clone(),
                            )),
                            slot,
                        ),
                    );
                }
            }
            // Advert is purged from the pool
            ArtifactProcessorEvent::Purge(id) => {
                // Free the slot and cancel the task
                if let Some((send_task, slot_used_by_advert)) = self.active_adverts.remove(&id) {
                    send_task.abort();

                    self.slot_manager.free_up_slot(slot_used_by_advert);
                }
            }
        }
    }
}

/// Sends an advert to all peers configured with the given `commit_id` and `slot_number`.
/// Memory Consumption:
/// - JoinMap: #peers * (32 + ~32)
/// - HashMap: #peers * (32 + 8)
/// - advert: ±200
/// For 10k tasks ~50Mb
async fn send_advert_to_all_peers<Artifact>(
    rt_handle: Handle,
    transport: Arc<dyn Transport>,
    commit_id: u64,
    slot_number: u64,
    advert: Advert<Artifact>,
    _pool_reader: Arc<RwLock<dyn ValidatedPoolReader<Artifact> + Send + Sync>>,
) where
    Artifact: ArtifactKind + Serialize + for<'a> Deserialize<'a> + CommonTraits,
    <Artifact as ArtifactKind>::Id: Serialize + for<'a> Deserialize<'a> + CommonTraits,
    <Artifact as ArtifactKind>::Message: Serialize + for<'a> Deserialize<'a> + CommonTraits,
    <Artifact as ArtifactKind>::Attribute: Serialize + for<'a> Deserialize<'a> + CommonTraits,
{
    let mut in_progress_transmissions = JoinMap::new();
    // stores the connection ID of the last successful transmission to a peer.
    let mut completed_transmissions: HashMap<NodeId, ConnId> = HashMap::new();
    let mut periodic_check_interval = time::interval(Duration::from_secs(5));

    let advert_update = AdvertUpdate {
        slot_number,
        commit_id,
        data: Data::Advert(advert),
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
                        let task = send_advert_to_peer::<Artifact>(transport.clone(), connection_id, body.clone(), peer);
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

/// This function will try to send a serialized advert to a peer.
/// If the peer is not reachable, it will retry with an exponential backoff.
/// --
/// Memory Consumption:
///  - Backoffpolicy: ±128B
///  - body: ±250B
///  - peer: 32B
///  - connId: 8B
/// For 10k tasks and 40 peers ~100Mb
/// Note: If we start pushing adverts we probably want to just try pushing once
/// and revert back to the advert if the inital push fails.
async fn send_advert_to_peer<Artifact: ArtifactKind>(
    transport: Arc<dyn Transport>,
    connection_id: ConnId,
    serialized_advert: Bytes,
    peer: NodeId,
) -> ConnId {
    let mut backoff = get_backoff_policy();

    loop {
        let request = Request::builder()
            .uri(format!("/{}/update", Artifact::TAG))
            .body(serialized_advert.clone())
            .expect("Building from typed values");

        if let Ok(()) = transport.push(&peer, request).await {
            return connection_id;
        }

        let backoff_duration = backoff.next_backoff().unwrap_or(MAX_ELAPSED_TIME);
        time::sleep(backoff_duration).await;
    }
}

#[derive(Deserialize, Serialize)]
enum Data<Artifact>
where
    Artifact: ArtifactKind + CommonTraits,
    <Artifact as ArtifactKind>::Id: Serialize + for<'a> Deserialize<'a> + CommonTraits,
    <Artifact as ArtifactKind>::Message: Serialize + CommonTraits,
    <Artifact as ArtifactKind>::Attribute: Serialize + for<'a> Deserialize<'a> + CommonTraits,
{
    Artifact(Artifact::Message),
    Advert(Advert<Artifact>),
}

#[derive(Deserialize, Serialize)]
struct AdvertUpdate<Artifact>
where
    Artifact: ArtifactKind + CommonTraits,
    <Artifact as ArtifactKind>::Id: Serialize + for<'a> Deserialize<'a> + CommonTraits,
    <Artifact as ArtifactKind>::Message: Serialize + for<'a> Deserialize<'a> + CommonTraits,
    <Artifact as ArtifactKind>::Attribute: Serialize + for<'a> Deserialize<'a> + CommonTraits,
{
    slot_number: u64,
    commit_id: u64,
    data: Data<Artifact>,
}

/// Data structure to keep track of available slots to use for sending of
struct SlotManager {
    next_free_slot: u64,
    free_slots: Vec<u64>,
    log: ReplicaLogger,
}

impl SlotManager {
    fn new(log: ReplicaLogger) -> Self {
        Self {
            next_free_slot: MAX_SLOTS,
            free_slots: (0..MAX_SLOTS).collect(),
            log,
        }
    }

    fn free_up_slot(&mut self, slot: u64) {
        self.free_slots.push(slot);
    }

    fn get_free_slot(&mut self) -> u64 {
        match self.free_slots.pop() {
            Some(slot) => slot,
            None => {
                error!(
                    self.log,
                    "Slot table exceeded the maximum configured slots = {}. Slots in use = {}.",
                    MAX_SLOTS,
                    self.next_free_slot
                );

                let new_slot = self.next_free_slot;
                self.next_free_slot += 1;

                new_slot
            }
        }
    }
}
