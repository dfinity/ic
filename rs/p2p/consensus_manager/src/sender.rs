use std::{
    collections::HashMap,
    hash::Hash,
    sync::{Arc, RwLock},
    time::Duration,
};

use axum::http::Request;
use backoff::backoff::Backoff;
use bytes::Bytes;
use ic_async_utils::JoinMap;
use ic_interfaces::{artifact_manager::ArtifactProcessorEvent, artifact_pool::ValidatedPoolReader};
use ic_logger::{warn, ReplicaLogger};
use ic_quic_transport::{ConnId, Transport};
use ic_types::artifact::{Advert, ArtifactKind};
use ic_types::NodeId;
use serde::{Deserialize, Serialize};
use tokio::{runtime::Handle, select, sync::mpsc::Receiver, task::JoinHandle, time};

use crate::{metrics::ConsensusManagerMetrics, AdvertUpdate, CommitId, Data, SlotNumber};

const ENABLE_ARTIFACT_PUSH: bool = false;
/// Artifact push threshold. Artifacts smaller or equal than this are pushed.
const ARTIFACT_PUSH_THRESHOLD: usize = 5 * 1024;

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

impl<Artifact> ConsensusManagerSender<Artifact>
where
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
        loop {
            if let Some(advert) = self.adverts_to_send.recv().await {
                self.handle_advert_to_send(advert);

                self.metrics
                    .active_advert_transmits
                    .set(self.active_adverts.len() as i64);
            }
        }
    }

    // TODO: rename this method. This function also handles purging adverts.
    fn handle_advert_to_send(&mut self, advert: ArtifactProcessorEvent<Artifact>) {
        self.current_commit_id.inc_assign();
        match advert {
            ArtifactProcessorEvent::Advert { advert, is_relay } => {
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
                            self.rt_handle.spawn(Self::send_advert_to_all_peers(
                                self.rt_handle.clone(),
                                self.log.clone(),
                                self.metrics.clone(),
                                self.transport.clone(),
                                self.current_commit_id,
                                slot,
                                advert,
                                is_relay,
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
        advert: Advert<Artifact>,
        is_relay: bool,
        pool_reader: Arc<RwLock<dyn ValidatedPoolReader<Artifact> + Send + Sync>>,
    ) {
        // Try to push artifact if size below threshold && the artifact is not a relay.
        let push_artifact =
            ENABLE_ARTIFACT_PUSH && !is_relay && advert.size <= ARTIFACT_PUSH_THRESHOLD;

        let data = if push_artifact {
            let id = advert.id.clone();

            let artifact = tokio::task::spawn_blocking(move || {
                pool_reader.read().unwrap().get_validated_by_identifier(&id)
            })
            .await
            .expect("Should not be cancelled");

            match artifact {
                Some(artifact) => {
                    metrics.artifacts_pushed_total.inc();
                    Data::Artifact(artifact)
                }
                None => {
                    warn!(log, "Attempted to push Artifact, but the Artifact was not found in the pool. Sending an advert instead.");
                    Data::Advert(advert)
                }
            }
        } else {
            Data::Advert(advert)
        };

        let advert_update = AdvertUpdate {
            slot_number,
            commit_id,
            data,
        };

        let body: Bytes = bincode::serialize(&advert_update)
            .expect("Serializing advert update")
            .into();

        let mut in_progress_transmissions = JoinMap::new();
        // stores the connection ID of the last successful transmission to a peer.
        let mut completed_transmissions: HashMap<NodeId, ConnId> = HashMap::new();
        let mut periodic_check_interval = time::interval(Duration::from_secs(5));

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
        self.metrics.free_slots.set(self.free_slots.len() as i64);
    }

    fn take_free_slot(&mut self) -> SlotNumber {
        match self.free_slots.pop() {
            Some(slot) => {
                self.metrics.free_slots.dec();
                slot
            }
            None => {
                if self.next_free_slot.get() > SLOT_TABLE_THRESHOLD {
                    warn!(
                        self.log,
                        "Slot table threshold exceeded. Slots in use = {}.", self.next_free_slot
                    );
                }

                let new_slot = self.next_free_slot;
                self.next_free_slot.inc_assign();

                self.metrics.maximum_slots_total.inc();

                new_slot
            }
        }
    }
}
