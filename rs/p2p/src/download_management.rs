//! The download manager maintains data structures on adverts and download state
//! per peer.
//!
//! A replica connects to all peers that are listed in the current subnet record
//! or the subnet record preceding the current record.
//! For each connected peer, the peer manager manages the list
//! of adverts and ongoing chunk downloads.
//!
//! The following data structures represent the state of the download manager
//! and all ongoing download activity.
//!
//! ```text
//!   +---------------------+
//!   |Download manager     |
//!   |----------- ---------|   +------------------+    +----------+     +----------+
//!   |UnderconstructionList|-->|Artifact          |....|Artifact  |.....|Artifact  |
//!   |                     |   |Download          |    |Download  |     |Download  |
//!   |                     |   |Tracker#1         |    |Tracker#2 |     |Tracker#N |
//!   |                     |   |requested_instant |    |          |     |          |
//!   |                     |   +------------------+    +----------+     +----------+
//!   |                     |
//!   |                     |
//!   |          PeerList   |-->+-------------------------------------------+---> ....
//!   |                     |   |Peer#1  (PeerContext)                      |
//!   |                     |   +-------------------------------------------+
//!   +---------------------+   |Peer In-flight Chunk "requested" map       |
//!                             +-----------------------+-------------------+
//!                             |Key                    |Value              |
//!                             +-----------------------+-------------------+
//!                             |ArtifactID +ChunkID    |requested_instant  |
//!                             +-----------------------+-------------------+
//!                             |...                    |                   |
//!                             +-----------------------+-------------------+
//! ```
//!
//! Locking is required to protect the data structures. The locking Hierarchy
//! is as follows:
//! 1) Peer context lock
//! 2) Under construction list lock
//! 3) Prioritizer Lock (R/W)
//! 4) Advert tracker Lock (R/W)
//!
//! Note that only the `download_next_compute_work()` workflow
//! *requires* the acquisition of multiple/all locks in the correct order:
//!
//! 1) Peer context lock to update the peer context "requested" list.
//! 2) Under construction list lock to add new artifacts being constructed.
//! 3) Prioritizer lock to iterate over adverts that are eligible for download.
//! 4) Advert tracker lock to mark a download attempt on a advert.
//!
//! All other workflows, viz. `on_timeout()`, `on_chunk()` and so forth DO NOT
//! require locks to be acquired simultaneously. The general approach
//! is to lock and copy out the state and then immediately drop the
//! lock before proceeding to acquire the next lock. The pattern is as
//! follows:
//!
//!  // Copy state and drop locks.</br>
//!  `let state = advert_tracker.lock().unwrap().[state].clone();`</br>
//!  // Acquire the next lock.</br>
//!  `prioritizer.lock().unwrap();`
//!
//! The locking hierarchy is irrelevant if only 1 lock is acquired at a time.
//!
//! In theory, the above locking rules prevent "circular waits" and thus
//! guarantee deadlock avoidance.

extern crate lru;

use crate::{
    artifact_download_list::ArtifactDownloadList,
    download_prioritization::{AdvertTracker, DownloadAttemptTracker},
    gossip_protocol::{GossipImpl, ReceiveCheckCache},
    gossip_types::{GossipChunk, GossipChunkRequest, GossipMessage},
    peer_context::{GossipChunkRequestTracker, PeerContext, PeerContextMap},
    P2PError, P2PErrorCode, P2PResult,
};
use ic_interfaces::p2p::state_sync::ChunkId;
use ic_interfaces_transport::TransportPayload;
use ic_logger::{info, trace, warn};
use ic_protobuf::{proxy::ProtoProxy, types::v1 as pb};
use ic_types::{
    artifact::{Advert, Artifact, ArtifactFilter, ArtifactId, ArtifactKind, ArtifactTag},
    artifact_kind::{
        CanisterHttpArtifact, CertificationArtifact, ConsensusArtifact, DkgArtifact, EcdsaArtifact,
        IngressArtifact,
    },
    crypto::CryptoHash,
    p2p::GossipAdvert,
    NodeId, RegistryVersion,
};
use std::{
    collections::hash_map::Entry,
    error::Error,
    net::SocketAddr,
    ops::DerefMut,
    time::{Instant, SystemTime},
};

const CHUNKID_UNIT_CHUNK: u32 = 0;

/// `DownloadManagerImpl` implements the `DownloadManager` trait.
impl GossipImpl {
    /// The method downloads chunks for adverts with the highest priority from
    /// the given peer.
    pub fn on_advert(&self, gossip_advert: GossipAdvert, peer_id: NodeId) {
        // The precondition ensured by gossip_protocol.on_advert() is that
        // the corresponding artifact is not in the artifact pool.
        // Check if we have seen this artifact before:
        if self
            .receive_check_caches
            .read()
            .values()
            .any(|cache| cache.contains(&gossip_advert.integrity_hash))
        {
            // If yes, the advert is ignored.
            return;
        }

        let mut current_peers = self.current_peers.lock();
        if let Some(_peer_context) = current_peers.get_mut(&peer_id) {
            let _ = self.prioritizer.add_advert(gossip_advert, peer_id);
        } else {
            warn!(every_n_seconds => 30, self.log, "Dropping advert from unknown node {:?}", peer_id);
        }
        self.metrics.adverts_received.inc();
    }

    /// The method starts downloading a chunk of the highest-priority
    /// artifact in the request queue if sufficient bandwidth is
    /// available.
    ///
    /// The method looks at the adverts queue for the given peer i and
    /// retrieves the highest-priority advert that is not already
    /// being downloaded from other peers more times in parallel than
    /// the maximum duplicity and for which there is room to store the
    /// corresponding artifact in the unvalidated artifact pool of
    /// peer i. If such an advert is found, the node adds a tracker
    /// for the advert to the requested queue of peer i, and sends a
    /// chunk requests for the corresponding artifact.
    ///
    /// The node also sets a download timeout for this chunk request
    /// with a duration that is appropriate for the size of the chunk.
    /// Periodically, the node iterates over the requested chunks and
    /// checks timed-out requests. The timed-out requests are removed
    /// from the requested queue of this peer and a history of such
    /// time-outs is retained.  Future download_next(i) calls take the
    /// download time-out history into account, de-prioritizing the
    /// request for peers that timed out in the past.
    ///
    /// This is a security requirement because in case no duplicity is
    /// allowed, a bad peer could otherwise maintain a "monopoly" on
    /// providing the node with a particular artifact and prevent the
    /// node from ever receiving it.
    pub fn download_next(&self, peer_id: NodeId) -> Result<(), Box<dyn Error>> {
        self.metrics.download_next_calls.inc();
        let start_time = Instant::now();
        let gossip_requests = self.download_next_compute_work(peer_id)?;
        self.metrics
            .download_next_time
            .set(start_time.elapsed().as_micros() as i64);
        for request in gossip_requests {
            let message = GossipMessage::ChunkRequest(request);
            self.transport_send(message, peer_id);
        }
        Ok(())
    }

    /// The method reacts to a chunk received from the peer with the given node
    /// ID.
    pub fn on_chunk(&self, gossip_chunk: GossipChunk, peer_id: NodeId) {
        trace!(
            self.log,
            "Node-{:?} received chunk from Node-{:?} ->{:?}",
            self.node_id,
            peer_id,
            gossip_chunk
        );

        // Remove the chunk request tracker.
        let mut current_peers = self.current_peers.lock();
        if let Some(peer_context) = current_peers.get_mut(&peer_id) {
            if let Some(tracker) = peer_context.requested.remove(&gossip_chunk.request) {
                let artifact_tag: &'static str =
                    ArtifactTag::from(&gossip_chunk.request.artifact_id).into();
                self.metrics
                    .chunk_delivery_time
                    .with_label_values(&[artifact_tag])
                    .observe(tracker.requested_instant.elapsed().as_millis() as f64);
            } else {
                trace!(
                    self.log,
                    "unsolicited or timed out artifact {:?} chunk {:?} from peer {:?}",
                    gossip_chunk.request.artifact_id,
                    gossip_chunk.request.chunk_id,
                    peer_id.get()
                );
                self.metrics.chunks_unsolicited_or_timed_out.inc();
            }
        }

        // Check if the request has been served. If an error is
        // returned, the artifact chunk cannot be served by this peer.
        // In this case, the chunk download is marked as failed but
        // the advert is still being tracked for other chunks (as this might be useful
        // for StateSync). This situation is possible if one of the replicas
        // misses a part of the artifact due to corruption or progress
        // (if the peer has a higher executed height now, it might
        // have changed its state and thus may only be able to serve
        // some but not all chunks of the artifact the node is
        // interested in).
        // Allowing the rest of the artifact to be downloaded and
        // skipping only the affected chunk increase overall
        // resilience.
        if let Err(error) = gossip_chunk.artifact {
            self.metrics.chunks_not_served_from_peer.inc();
            trace!(
                self.log,
                "Chunk download failed for artifact{:?} chunk {:?} from peer {:?}",
                gossip_chunk.request.artifact_id,
                gossip_chunk.request.chunk_id,
                peer_id
            );
            if let P2PErrorCode::NotFound = error.p2p_error_code {
                // If the artifact is not found on the sender's side, drop the
                // advert from the context for this peer to prevent it from
                // being requested again from this peer.
                self.delete_advert_from_peer(
                    &peer_id,
                    &gossip_chunk.request.artifact_id,
                    &gossip_chunk.request.integrity_hash,
                    self.artifacts_under_construction.write().deref_mut(),
                )
            }
            return;
        }

        // Increment the received chunks counter.
        self.metrics.chunks_received.inc();

        // Feed the chunk to artifact tracker-
        let mut artifacts_under_construction = self.artifacts_under_construction.write();

        // Find the tracker to feed the chunk.
        let artifact_tracker =
            artifacts_under_construction.get_tracker(&gossip_chunk.request.integrity_hash);
        if artifact_tracker.is_none() {
            trace!(
                self.log,
                "Chunk received although artifact is complete or dropped from under construction list (e.g., due to priority function change) {:?} chunk {:?} from peer {:?}",
                gossip_chunk.request.artifact_id,
                gossip_chunk.request.chunk_id,
                peer_id.get()
            );
            let _ = self.prioritizer.delete_advert_from_peer(
                &gossip_chunk.request.artifact_id,
                &gossip_chunk.request.integrity_hash,
                &peer_id,
            );
            self.metrics.chunks_redundant_residue.inc();
            return;
        }
        let artifact_tracker = artifact_tracker.unwrap();

        // Feed the chunk to the tracker.
        let completed_artifact = gossip_chunk.artifact.unwrap();

        // Record metrics.
        self.metrics.artifacts_received.inc();

        self.metrics
            .artifact_download_time
            .observe(artifact_tracker.get_duration_sec());

        // Check whether the artifact matches the advertised integrity hash.
        let advert = match self.prioritizer.get_advert_from_peer(
            &gossip_chunk.request.artifact_id,
            &gossip_chunk.request.integrity_hash,
            &peer_id,
        ) {
            Ok(advert) => advert,
            Err(_) => {
                trace!(
                self.log,
                "The advert for {:?} chunk {:?} from peer {:?} was not found, seems the peer never sent it.",
                gossip_chunk.request.artifact_id,
                gossip_chunk.request.chunk_id,
                peer_id.get()
            );
                return;
            }
        };
        // Check if the artifact's integrity hash matches the advertised hash
        // This construction to compute the integrity hash over all variants of an enum
        // may be updated in the future.
        let expected_ih = match &completed_artifact {
            Artifact::ConsensusMessage(msg) => ic_types::crypto::crypto_hash(msg).get(),
            Artifact::IngressMessage(msg) => ic_types::crypto::crypto_hash(msg.binary()).get(),
            Artifact::CertificationMessage(msg) => ic_types::crypto::crypto_hash(msg).get(),
            Artifact::DkgMessage(msg) => ic_types::crypto::crypto_hash(msg).get(),
            Artifact::EcdsaMessage(msg) => ic_types::crypto::crypto_hash(msg).get(),
            Artifact::CanisterHttpMessage(msg) => ic_types::crypto::crypto_hash(msg).get(),
            // FileTreeSync is not of ArtifactKind kind, and it's used only for testing.
            // Thus, we make up the integrity_hash.
            Artifact::FileTreeSync(_msg) => CryptoHash(vec![]),
        };

        if expected_ih != advert.integrity_hash {
            warn!(
                self.log,
                "The integrity hash for {:?} from peer {:?} does not match. Expected {:?}, got {:?}.",
                gossip_chunk.request.artifact_id,
                peer_id.get(),
                expected_ih,
                advert.integrity_hash;
            );
            self.metrics.integrity_hash_check_failed.inc();

            // The advert is deleted from this particular peer. Gossip may fetch the
            // artifact again from another peer.
            let _ = self.prioritizer.delete_advert_from_peer(
                &gossip_chunk.request.artifact_id,
                &gossip_chunk.request.integrity_hash,
                &peer_id,
            );
            return;
        }

        // Add the artifact hash to the receive check set.
        let charged_peer = artifact_tracker.peer_id;
        match self.receive_check_caches.write().get_mut(&charged_peer) {
            Some(v) => {
                v.put(advert.integrity_hash.clone(), ());
            }
            None => warn!(
                every_n_seconds => 5,
                self.log,
                "Peer {:?} has no receive check cache", charged_peer
            ),
        }

        // The artifact is complete and the integrity hash is okay.
        // Clean up the adverts for all peers:
        let _ = self.prioritizer.delete_advert(
            &gossip_chunk.request.artifact_id,
            &gossip_chunk.request.integrity_hash,
        );
        artifacts_under_construction.remove_tracker(&gossip_chunk.request.integrity_hash);

        // Drop the locks before calling client callbacks.
        std::mem::drop(artifacts_under_construction);
        std::mem::drop(current_peers);

        // Client callbacks.
        trace!(
            self.log,
            "Node-{:?} received artifact from Node-{:?} ->{:?}",
            self.node_id,
            peer_id,
            gossip_chunk.request.artifact_id
        );

        let advert_matches_completed_artifact = match &completed_artifact {
            Artifact::ConsensusMessage(msg) => {
                advert_matches_artifact::<ConsensusArtifact>(msg, &advert)
            }
            Artifact::IngressMessage(msg) => {
                advert_matches_artifact::<IngressArtifact>(msg, &advert)
            }
            Artifact::CertificationMessage(msg) => {
                advert_matches_artifact::<CertificationArtifact>(msg, &advert)
            }
            Artifact::DkgMessage(msg) => advert_matches_artifact::<DkgArtifact>(msg, &advert),
            Artifact::EcdsaMessage(msg) => advert_matches_artifact::<EcdsaArtifact>(msg, &advert),
            Artifact::CanisterHttpMessage(msg) => {
                advert_matches_artifact::<CanisterHttpArtifact>(msg, &advert)
            }
            // This artifact is used only in tests.
            Artifact::FileTreeSync(_) => true,
        };
        if advert_matches_completed_artifact {
            match self
                .artifact_manager
                .on_artifact(completed_artifact, &peer_id)
            {
                Ok(()) => (),
                Err(err) => warn!(
                    self.log,
                    "Artifact is not processed successfully by Artifact Manager: {:?}", err
                ),
            }
        } else {
            warn!(
                self.log,
                "Artifact {:?} dropped because it doesn't match the corresponding advert {:?}",
                completed_artifact,
                advert
            )
        }
    }

    /// The method reacts to a disconnect event event for the peer with the
    /// given node ID.
    pub fn peer_connection_down(&self, peer_id: NodeId) {
        let now = SystemTime::now();
        let mut current_peers = self.current_peers.lock();
        if let Some(peer_context) = current_peers.get_mut(&peer_id) {
            peer_context.disconnect_time = Some(now);
            trace!(
                self.log,
                "Gossip On Disconnect event with peer: {:?} at time {:?}",
                peer_id,
                now
            );
        };
    }

    /// The method reacts to a connect event event for the peer with the given
    /// node ID.
    pub fn peer_connection_up(&self, peer_id: NodeId) {
        let last_disconnect = self
            .current_peers
            .lock()
            .get_mut(&peer_id)
            .and_then(|res| res.disconnect_time);
        match last_disconnect {
            Some(last_disconnect) => {
                match last_disconnect.elapsed() {
                    Ok(elapsed) => {
                        trace!(
                            self.log,
                            "Disconnect to peer {:?} for {:?} seconds",
                            peer_id,
                            elapsed
                        );

                        // Clear the send queues and send re-transmission request to the peer on
                        // connect.
                        self.transport.clear_send_queues(&peer_id);
                    }
                    Err(e) => {
                        warn!(self.log, "Error in elapsed time calculation: {:?}", e);
                    }
                }
            }
            None => {
                trace!(
                    self.log,
                    "No previous disconnect event recorded in peer manager for node : {:?}",
                    peer_id
                );
            }
        }
        self.send_retransmission_request(peer_id);
    }

    /// The method reacts to a retransmission request.
    pub fn on_retransmission_request(
        &self,
        gossip_re_request: &ArtifactFilter,
        peer_id: NodeId,
    ) -> P2PResult<()> {
        const BUSY_ERR: P2PResult<()> = Err(P2PError {
            p2p_error_code: P2PErrorCode::Busy,
        });
        // Throttle processing of incoming re-transmission request
        self.current_peers
            .lock()
            .get_mut(&peer_id)
            .ok_or_else(|| {
                warn!(self.log, "Can't find peer context for peer: {:?}", peer_id);
                P2PError {
                    p2p_error_code: P2PErrorCode::NotFound,
                }
            })
            .map_or_else(Err, |peer_context| {
                let elapsed_ms = peer_context
                    .last_retransmission_request_processed_time
                    .elapsed()
                    .as_millis();
                if elapsed_ms < self.gossip_config.retransmission_request_ms as u128 {
                    BUSY_ERR
                } else {
                    peer_context.last_retransmission_request_processed_time = Instant::now();
                    Ok(())
                }
            })?;

        // A retransmission request was received from a peer.
        // The send queues are cleared and a response is sent containing all the adverts
        // that satisfy the filter.
        self.transport.clear_send_queues(&peer_id);

        let adverts = self
            .artifact_manager
            .get_all_validated_by_filter(gossip_re_request)
            .into_iter();

        adverts.for_each(|gossip_advert| {
            let message = GossipMessage::Advert(gossip_advert);
            self.transport_send(message, peer_id);
        });
        Ok(())
    }

    /// The method sends a retransmission request to the peer with the given
    /// node ID.
    pub fn send_retransmission_request(&self, peer_id: NodeId) {
        let filter = self.artifact_manager.get_filter();
        let message = GossipMessage::RetransmissionRequest(filter);
        let start_time = Instant::now();
        self.transport_send(message, peer_id);
        self.metrics
            .retransmission_request_time
            .observe(start_time.elapsed().as_millis() as f64)
    }

    /// The method is invoked periodically by the *Gossip* component to perform
    /// P2P book keeping tasks.
    pub fn on_timer(&self) {
        let (update_priority_fns, retransmission_request, refresh_registry) =
            self.get_timer_tasks();
        if update_priority_fns {
            let dropped_adverts = self
                .prioritizer
                .update_priority_functions(self.artifact_manager.as_ref());
            let mut artifacts_under_construction = self.artifacts_under_construction.write();
            dropped_adverts
                .iter()
                .for_each(|id| artifacts_under_construction.remove_tracker(id));
        }

        if retransmission_request {
            // Send a retransmission request to all peers.
            let current_peers = self.get_current_peer_ids();
            for peer in current_peers {
                self.send_retransmission_request(peer);
            }
        }

        if refresh_registry {
            self.refresh_topology();
        }

        // Collect the peers with timed-out requests.
        let mut timed_out_peers = Vec::new();
        for (node_id, peer_context) in self.current_peers.lock().iter_mut() {
            if self.process_timed_out_requests(node_id, peer_context) {
                timed_out_peers.push(*node_id);
            }
        }

        // Process timed-out artifacts.
        self.process_timed_out_artifacts();

        // Compute the set of peers that need to be evaluated by the download manager.
        let peer_ids = if update_priority_fns {
            self.get_current_peer_ids().into_iter()
        } else {
            timed_out_peers.into_iter()
        };

        // Invoke download_next(i) for each peer i.
        for peer_id in peer_ids {
            let _ = self.download_next(peer_id);
        }
    }

    pub(crate) fn get_current_peer_ids(&self) -> Vec<NodeId> {
        self.current_peers
            .lock()
            .iter()
            .map(|(k, _v)| k.to_owned())
            .collect()
    }

    /// Adds a new peer for the node (initialize data structs, start connection, etc.).
    /// This method is called from the 'discovery' module. This method signals intent.
    /// Not to be confused with 'on_peer_up' method which is called when the connection is established.
    pub(crate) fn add_peer(
        &self,
        peer_id: NodeId,
        peer_addr: SocketAddr,
        latest_registry_version: RegistryVersion,
        earliest_registry_version: RegistryVersion,
    ) {
        // Only add other peers to the peer list.
        if peer_id == self.node_id {
            return;
        }
        match self.current_peers.lock().entry(peer_id) {
            Entry::Occupied(_) => (),
            Entry::Vacant(v) => {
                info!(self.log, "Peer {:0} added.", peer_id);
                // Hold the lock for the duration of all operations.
                v.insert(PeerContext::new());
                self.transport.start_connection(
                    &peer_id,
                    peer_addr,
                    latest_registry_version,
                    earliest_registry_version,
                );
                self.receive_check_caches.write().insert(
                    peer_id,
                    ReceiveCheckCache::new(self.gossip_config.receive_check_cache_size as usize),
                );
            }
        }
    }

    /// This helper method returns a list of tasks to be performed by this timer
    /// invocation.
    fn get_timer_tasks(&self) -> (bool, bool, bool) {
        let mut update_priority_fns = false;
        let mut refresh_registry = false;
        let mut retransmission_request = false;
        // Check if the priority function should be updated.
        {
            let mut pfn_invocation_instant = self.pfn_invocation_instant.lock();
            if pfn_invocation_instant.elapsed().as_millis()
                >= self.gossip_config.pfn_evaluation_period_ms as u128
            {
                update_priority_fns = true;
                *pfn_invocation_instant = Instant::now();
            }
        }

        // Check if a retransmission request needs to be sent.
        {
            let mut retransmission_request_instant = self.retransmission_request_instant.lock();
            if retransmission_request_instant.elapsed().as_millis()
                >= self.gossip_config.retransmission_request_ms as u128
            {
                retransmission_request = true;
                *retransmission_request_instant = Instant::now();
            }
        }

        // Check if the registry has to be refreshed.
        {
            let mut registry_refresh_instant = self.registry_refresh_instant.lock();
            if registry_refresh_instant.elapsed().as_millis()
                >= self.gossip_config.pfn_evaluation_period_ms as u128
            {
                refresh_registry = true;
                *registry_refresh_instant = Instant::now();
            }
        }
        (
            update_priority_fns,
            retransmission_request,
            refresh_registry,
        )
    }

    /// Removes the peer for the node (delete data structs, stop connection, etc.).
    /// This method is called from the 'discovery' module. This method signals intent.
    /// Not to be confused with 'on_peer_down' method which is called when the connection
    /// is down, which is transient state.
    pub(crate) fn remove_peer(&self, peer_id: &NodeId) {
        match self.current_peers.lock().remove(peer_id) {
            None => (),
            Some(_) => {
                self.metrics.nodes_removed.inc();
                info!(self.log, "Peer {:0} removed.", peer_id);
                // Hold the lock for the duration of all operations.
                self.transport.stop_connection(peer_id);
                self.receive_check_caches.write().remove(peer_id);
                self.prioritizer
                    .clear_peer_adverts(peer_id)
                    .unwrap_or_else(|e| {
                        info!(
                            self.log,
                            "Failed to clear peer adverts when removing peer {:?} with error {:?}",
                            peer_id,
                            e
                        )
                    });
            }
        }
    }

    /// The method sends the given message over transport to the given peer.
    // TODO(NET-1299): transport send error should be propagaed and handled by P2P
    pub(crate) fn transport_send(&self, message: GossipMessage, peer_id: NodeId) {
        let _timer = self
            .metrics
            .op_duration
            .with_label_values(&["transport_send"])
            .start_timer();
        let channel_id = self.transport_channel_mapper.map(&message);
        let message_label: &'static str = (&message).into();
        let message = TransportPayload(pb::GossipMessage::proxy_encode(message));
        match self.transport.send(&peer_id, channel_id, message) {
            Ok(()) => self
                .metrics
                .transport_send_messages
                .with_label_values(&[message_label, "success"])
                .inc(),
            Err(err) => self
                .metrics
                .transport_send_messages
                .with_label_values(&[message_label, err.into()])
                .inc(),
        }
    }

    /// The method returns a chunk request if a chunk can be downloaded from the
    /// given peer.
    ///
    /// This is a helper function for `download_next()`. It consolidates checks
    /// and conditions that dictate a chunk's download eligibility from a
    /// given peer.
    fn get_chunk_request(
        &self,
        peers: &PeerContextMap,
        peer_id: NodeId,
        advert_tracker: &AdvertTracker,
        chunk_id: ChunkId,
    ) -> Option<GossipChunkRequest> {
        // Skip if the chunk download has been already attempted even if the node is
        // currently downloading it OR has a failed attempt in this round.
        if advert_tracker.peer_attempted(chunk_id, &peer_id) {
            None?
        }

        let chunk_request = GossipChunkRequest {
            artifact_id: advert_tracker.advert().artifact_id.clone(),
            integrity_hash: advert_tracker.advert().integrity_hash.clone(),
            chunk_id,
        };
        // Skip if some other peer is downloading the chunk and maximum
        // duplicity has been reached.
        let duplicity = advert_tracker
            .peers()
            .iter()
            .filter_map(|advertiser| peers.get(advertiser)?.requested.get(&chunk_request))
            .count();

        if duplicity >= self.gossip_config.max_duplicity as usize {
            None?
        }

        // Since the peer has not attempted a chunk download in this round and will not
        // violate duplicity constraints, a gossip chunk request is returned.
        Some(chunk_request)
    }

    /// The method returns the next set of downloads that can be initiated
    /// within the constraints of the ICP protocol.
    fn download_next_compute_work(
        &self,
        peer_id: NodeId,
    ) -> Result<Vec<GossipChunkRequest>, impl Error> {
        // Get the peer context.
        let mut current_peers = self.current_peers.lock();
        //  Checks if a download from a peer can be initiated.
        // A peer may not be ready for downloads for various reasons:
        //
        // a) The peer's download request capacity has been reached.
        // b) The peer is not a current peer (e.g., it is an unknown peer or a peer
        // that was removed)
        // c) The peer was disconnected (TODO -  P2P512)
        let peer_context = match current_peers.get(&peer_id) {
            // Check that the peer is present and
            // there is available capacity to stream chunks from this peer.
            Some(peer_context)
                if peer_context.requested.len()
                    < self.gossip_config.max_artifact_streams_per_peer as usize =>
            {
                Ok(peer_context)
            }
            _ => Err(P2PError {
                p2p_error_code: P2PErrorCode::Busy,
            }),
        }?;

        let requested_instant = Instant::now(); // function granularity for instant is good enough
        let max_streams_per_peer = self.gossip_config.max_artifact_streams_per_peer as usize;

        assert!(peer_context.requested.len() <= max_streams_per_peer);
        let num_downloadable_chunks = max_streams_per_peer - peer_context.requested.len();
        if num_downloadable_chunks == 0 {
            return Err(Box::new(P2PError {
                p2p_error_code: P2PErrorCode::Busy,
            }));
        }

        let mut requests = Vec::new();
        let mut artifacts_under_construction = self.artifacts_under_construction.write();
        // Get a prioritized iterator.
        let peer_advert_queues = self.prioritizer.get_peer_priority_queues(peer_id);
        let peer_advert_map = peer_advert_queues.peer_advert_map_ref.read().unwrap();

        let mut visited = 0;
        for (_, advert_tracker) in peer_advert_map.iter() {
            visited += 1;
            if requests.len() >= num_downloadable_chunks {
                break;
            }

            let mut advert_tracker = advert_tracker.write().unwrap();
            let advert_tracker = advert_tracker.deref_mut();

            // Try to begin a download for the artifact and collect its chunk requests.
            if artifacts_under_construction.schedule_download(
                peer_id,
                advert_tracker.advert(),
                &self.gossip_config,
                current_peers.len() as u32,
            ) {
                // Collect gossip requests that can be initiated for this artifact.
                // The function get_chunk_request() returns requests for chunks that satisfy
                // chunk download constraints. These requests are collected and download
                // attempts are recorded.
                let v: Vec<ChunkId> = vec![ChunkId::from(CHUNKID_UNIT_CHUNK)];
                let chunks_to_download = Box::new(v.into_iter());

                let new_chunk_requests = chunks_to_download
                    .filter_map(|id: ChunkId| {
                        self.get_chunk_request(&current_peers, peer_id, advert_tracker, id)
                            .map(|req| {
                                advert_tracker.record_attempt(id, &peer_id);
                                req
                            })
                    })
                    .take(num_downloadable_chunks - requests.len());

                // Extend the requests to be send out to this peer
                requests.extend(new_chunk_requests);
            }
        }

        self.metrics.download_next_visited.set(visited as i64);
        self.metrics
            .download_next_selected
            .set(requests.len() as i64);

        let peer_context = current_peers.get_mut(&peer_id).unwrap();
        peer_context.requested.extend(
            requests
                .iter()
                .map(|req| (req.clone(), GossipChunkRequestTracker { requested_instant })),
        );

        assert!(peer_context.requested.len() <= max_streams_per_peer);
        Ok(requests)
    }

    /// The method deletes the given advert from a particular peer.
    ///
    /// If the deletion results in zero peers downloading the advert, then the
    /// entry in the under-construction list is cleaned up as well.
    fn delete_advert_from_peer(
        &self,
        peer_id: &NodeId,
        artifact_id: &ArtifactId,
        integrity_hash: &CryptoHash,
        artifacts_under_construction: &mut dyn ArtifactDownloadList,
    ) {
        let ret = self
            .prioritizer
            .delete_advert_from_peer(artifact_id, integrity_hash, peer_id);
        // Remove the artifact from the under-construction list if this peer was the
        // last peer with an advert tracker for this artifact, indicated by the
        // previous call's return value.
        if ret.is_ok() {
            artifacts_under_construction.remove_tracker(integrity_hash);
        }
    }

    /// The method processes timed-out artifacts.
    ///
    /// This method is called by the method on_timer(). It checks if there are
    /// any timed-out artifacts in the under-construction list and removes
    /// them from.
    fn process_timed_out_artifacts(&self) {
        // Prune the expired downloads from the under-construction list.
        let expired_downloads = self
            .artifacts_under_construction
            .write()
            .deref_mut()
            .prune_expired_downloads();

        self.metrics
            .artifact_timeouts
            .inc_by(expired_downloads.len() as u64);

        // Add the timed-out adverts to the end of their respective
        // priority queue in the prioritizer.
        expired_downloads
            .into_iter()
            .for_each(|(artifact_id, integrity_hash)| {
                let _ = self
                    .prioritizer
                    .reinsert_advert_at_tail(&artifact_id, &integrity_hash);
            });
    }

    /// The method processes timed-out requests
    ///
    /// This method is called by the method on_timer(). It checks if there are
    /// any chunk requests that timed out from the given peer and returns
    /// "true" if this is the case.
    fn process_timed_out_requests(&self, node_id: &NodeId, peer_context: &mut PeerContext) -> bool {
        // Mark time-out chunks.
        let mut timed_out_chunks: Vec<_> = Vec::new();
        let mut peer_timed_out: bool = false;
        peer_context.requested.retain(|key, tracker| {
            let timed_out = tracker.requested_instant.elapsed().as_millis()
                >= self.gossip_config.max_chunk_wait_ms as u128;
            if timed_out {
                self.metrics.chunks_timed_out.inc();
                timed_out_chunks.push((
                    *node_id,
                    key.chunk_id,
                    key.artifact_id.clone(),
                    key.integrity_hash.clone(),
                ));
                peer_timed_out = true;
                trace!(
                    self.log,
                    "Chunk timeout Key {:?} Tracker {:?} elapsed{:?} requested {:?} Now {:?}",
                    key,
                    tracker,
                    tracker.requested_instant.elapsed().as_millis(),
                    tracker.requested_instant,
                    std::time::Instant::now()
                )
            }
            // Retain chunks that have not timed out.
            !timed_out
        });

        for (node_id, chunk_id, artifact_id, integrity_hash) in timed_out_chunks.into_iter() {
            self.process_timed_out_chunk(&node_id, artifact_id, integrity_hash, chunk_id)
        }

        peer_timed_out
    }

    /// The method processes a timed-out chunk.
    fn process_timed_out_chunk(
        &self,
        node_id: &NodeId,
        artifact_id: ArtifactId,
        integrity_hash: CryptoHash,
        chunk_id: ChunkId,
    ) {
        // Drop it and switch the preferred primary so that the next node that
        // advertised the chunk picks it up.
        let _ = self
            .prioritizer
            .get_advert_tracker(&artifact_id, &integrity_hash)
            .map(|advert_tracker| {
                // unset the in-progress flag.
                let mut advert_tracker = advert_tracker.write().unwrap();
                advert_tracker.unset_in_progress(chunk_id);
                // If we have exhausted a round of download attempts (i.e., each peer that
                // advertised it has timed out once), then reset the attempts
                // history so that peers can be probed once for the next round.
                if advert_tracker.is_attempts_round_complete(chunk_id) {
                    advert_tracker.attempts_round_reset(chunk_id)
                }
            });
        #[rustfmt::skip]
        trace!(self.log, "Timed-out: Peer{:?} Artifact{:?} Chunk{:?}",
               node_id, chunk_id, artifact_id);
    }
}

/// Checks if the given advert matches what is computed from the message.
fn advert_matches_artifact<A: ArtifactKind>(msg: &A::Message, gossip_advert: &GossipAdvert) -> bool
where
    Advert<A>: Eq,
    ic_types::artifact::Advert<A>: TryFrom<ic_types::p2p::GossipAdvert>,
{
    let computed = A::message_to_advert(msg);
    Advert::<A>::try_from(gossip_advert.clone()).is_ok_and(|advert| advert == computed)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::download_prioritization::DownloadPrioritizerError;
    use ic_interfaces::consensus_pool::ConsensusPoolCache;
    use ic_interfaces::p2p::artifact_manager::{ArtifactManager, OnArtifactError};
    use ic_interfaces_mocks::consensus_pool::MockConsensusPoolCache;
    use ic_interfaces_registry::RegistryClient;
    use ic_interfaces_transport::TransportChannelId;
    use ic_logger::{LoggerImpl, ReplicaLogger};
    use ic_metrics::MetricsRegistry;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_client_helpers::subnet::SubnetTransportRegistry;
    use ic_test_utilities::port_allocation::allocate_ports;
    use ic_test_utilities::{p2p::*, thread_transport::*};
    use ic_test_utilities_consensus::{fake::*, make_genesis};
    use ic_test_utilities_registry::{add_subnet_record, SubnetRecordBuilder};
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::consensus::dkg::{DealingContent, DkgMessageId, Message as DkgMessage};
    use ic_types::crypto::{
        threshold_sig::ni_dkg::{NiDkgDealing, NiDkgId, NiDkgTag, NiDkgTargetSubnet},
        CryptoHash,
    };
    use ic_types::signature::BasicSignature;
    use ic_types::SubnetId;
    use ic_types::{
        artifact,
        artifact::{Artifact, ArtifactAttribute, ArtifactPriorityFn, Priority},
        single_chunked::ChunkableArtifact,
        Height, NodeId, PrincipalId,
    };
    use ic_types::{artifact::ArtifactKind, artifact_kind::ConsensusArtifact, consensus::*};
    use parking_lot::Mutex;
    use std::collections::HashSet;
    use std::convert::TryFrom;
    use std::ops::Range;
    use std::sync::Arc;

    /// This priority function always returns Priority::FetchNow.
    fn priority_fn_fetch_now_all(_: &ArtifactId, _: &ArtifactAttribute) -> Priority {
        Priority::FetchNow
    }

    /// The test artifact manager.
    #[derive(Default)]
    pub(crate) struct TestArtifactManager {}

    /// The `TestArtifactManager` implements the `TestArtifact` trait.
    impl ArtifactManager for TestArtifactManager {
        /// The method ignores the artifact and always returns Ok(()).
        fn on_artifact(
            &self,
            mut _msg: artifact::Artifact,
            _peer_id: &NodeId,
        ) -> Result<(), OnArtifactError> {
            Ok(())
        }

        /// The method to test if an artifact is available is not implemented as
        /// it is not used.
        fn has_artifact(&self, _message_id: &artifact::ArtifactId) -> bool {
            unimplemented!()
        }

        /// The method to return a validated artifact is not implemented as
        /// it is not used.
        fn get_validated_by_identifier(
            &self,
            _message_id: &artifact::ArtifactId,
        ) -> Option<Box<dyn ChunkableArtifact + '_>> {
            unimplemented!()
        }

        /// The method to get the artifact filter is not implemented as
        /// it is not used.
        fn get_filter(&self) -> artifact::ArtifactFilter {
            unimplemented!()
        }
        /// The method to get the list of validated adverts is not implemented
        /// as it is not used.
        fn get_all_validated_by_filter(
            &self,
            _filter: &artifact::ArtifactFilter,
        ) -> Vec<GossipAdvert> {
            unimplemented!()
        }

        /// The method returns the priority function that always uses
        /// Priority::FetchAll.
        fn get_priority_function(&self, _: artifact::ArtifactTag) -> ArtifactPriorityFn {
            Box::new(priority_fn_fetch_now_all)
        }
    }

    /// The function returns a new
    /// ic_test_utilities::thread_transport::ThreadPort instance.
    fn get_transport(
        instance_id: u32,
        hub: Arc<Mutex<Hub>>,
        logger: &LoggerImpl,
        rt_handle: tokio::runtime::Handle,
    ) -> Arc<ThreadPort> {
        let log: ReplicaLogger = logger.root.clone().into();
        ThreadPort::new(node_test_id(instance_id as u64), hub, log, rt_handle)
    }

    pub(crate) fn new_test_gossip_impl_with_registry(
        num_replicas: u32,
        logger: &LoggerImpl,
        registry_client: Arc<dyn RegistryClient>,
        consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
        rt_handle: tokio::runtime::Handle,
    ) -> GossipImpl {
        let log: ReplicaLogger = logger.root.clone().into();
        let artifact_manager = TestArtifactManager {};

        // Set up transport.
        let hub_access: HubAccess = Arc::new(Mutex::new(Default::default()));
        for instance_id in 0..num_replicas {
            let thread_port =
                get_transport(instance_id, hub_access.clone(), logger, rt_handle.clone());
            hub_access
                .lock()
                .insert(node_test_id(instance_id as u64), thread_port);
        }

        let transport_hub = hub_access.lock();
        let tp = transport_hub.get(&node_test_id(0));

        // Set up the prioritizer.
        let metrics_registry = MetricsRegistry::new();

        let transport_channels = vec![TransportChannelId::from(0)];

        // Create fake peers.
        let artifact_manager = Arc::new(artifact_manager);
        GossipImpl::new(
            node_test_id(0),
            subnet_test_id(0),
            consensus_pool_cache,
            registry_client,
            artifact_manager,
            tp,
            transport_channels,
            log,
            &metrics_registry,
        )
    }

    fn new_test_gossip(
        num_replicas: u32,
        logger: &LoggerImpl,
        rt_handle: tokio::runtime::Handle,
    ) -> GossipImpl {
        let allocated_ports = allocate_ports("127.0.0.1", num_replicas as u16)
            .expect("Port allocation for test failed");
        let node_port_allocation: Vec<u16> = allocated_ports.iter().map(|np| np.port).collect();
        assert_eq!(num_replicas as usize, node_port_allocation.len());
        let node_port_allocation = Arc::new(node_port_allocation);
        let data_provider =
            test_group_set_registry(subnet_test_id(P2P_SUBNET_ID_DEFAULT), node_port_allocation);
        let registry_client = Arc::new(FakeRegistryClient::new(data_provider));
        registry_client.update_to_latest_version();

        let mut mock_consensus_cache = MockConsensusPoolCache::new();
        mock_consensus_cache
            .expect_get_oldest_registry_version_in_use()
            .returning(move || RegistryVersion::from(1));
        let consensus_pool_cache = Arc::new(mock_consensus_cache);

        new_test_gossip_impl_with_registry(
            num_replicas,
            logger,
            registry_client,
            consensus_pool_cache,
            rt_handle,
        )
    }

    /// The function adds the given number of adverts to the download manager.
    fn test_add_adverts(gossip: &GossipImpl, range: Range<u32>, node_id: NodeId) {
        for advert_id in range {
            let gossip_advert = GossipAdvert {
                artifact_id: ArtifactId::FileTreeSync(advert_id.to_string()),
                attribute: ic_types::artifact::ArtifactAttribute::Empty(()),
                size: 0,
                integrity_hash: CryptoHash(Vec::from(advert_id.to_be_bytes())),
            };
            gossip.on_advert(gossip_advert, node_id)
        }
    }

    /// The functions tests that the peer context drops all requests after a
    /// time-out.
    fn test_timeout_peer(gossip: &GossipImpl, node_id: &NodeId) {
        let sleep_duration =
            std::time::Duration::from_millis((gossip.gossip_config.max_chunk_wait_ms * 2) as u64);
        std::thread::sleep(sleep_duration);
        let mut current_peers = gossip.current_peers.lock();
        let peer_context = current_peers.get_mut(node_id).unwrap();
        gossip.process_timed_out_requests(node_id, peer_context);
        assert_eq!(peer_context.requested.len(), 0);
    }

    /// This function tests the functionality to add adverts to the
    /// download manager.
    #[tokio::test]
    async fn download_manager_remove_replica() {
        let logger = p2p_test_setup_logger();
        let num_replicas = 3;
        let num_peers = num_replicas - 1;

        let allocated_ports = allocate_ports("127.0.0.1", num_replicas as u16)
            .expect("Port allocation for test failed");
        let node_port_allocation: Vec<u16> = allocated_ports.iter().map(|np| np.port).collect();
        assert_eq!(num_replicas as usize, node_port_allocation.len());
        let node_port_allocation = Arc::new(node_port_allocation);

        // Create data provider which will have subnet record of all replicas at version
        // 1.
        let data_provider = test_group_set_registry(
            subnet_test_id(P2P_SUBNET_ID_DEFAULT),
            node_port_allocation.clone(),
        );
        let registry_data_provider = data_provider.clone();
        let registry_client = Arc::new(FakeRegistryClient::new(registry_data_provider));
        registry_client.update_to_latest_version();

        // Create consensus cache which returns CUP with version 1, the registry version
        // which contains the subnet record with all replicas.
        let mut mock_consensus_cache = MockConsensusPoolCache::new();
        let consensus_registry_client = registry_client.clone();
        mock_consensus_cache
            .expect_get_oldest_registry_version_in_use()
            .returning(move || consensus_registry_client.get_latest_version());
        let consensus_pool_cache = Arc::new(mock_consensus_cache);

        let gossip = new_test_gossip_impl_with_registry(
            num_replicas,
            &logger,
            Arc::clone(&registry_client) as Arc<_>,
            Arc::clone(&consensus_pool_cache) as Arc<_>,
            tokio::runtime::Handle::current(),
        );
        // Add new subnet record with one less replica and at version 2.
        let node_nums: Vec<u64> = (0..((node_port_allocation.len() - 1) as u64)).collect();
        assert_eq!((num_replicas - 1) as usize, node_nums.len());
        add_subnet_record(
            &data_provider,
            2,
            subnet_test_id(P2P_SUBNET_ID_DEFAULT),
            SubnetRecordBuilder::from(&node_nums.into_iter().map(node_test_id).collect::<Vec<_>>())
                .build(),
        );
        // Get latest subnet record and assert it has one less replica than the initial
        // version.
        registry_client.update_to_latest_version();
        let registry_version = registry_client.get_latest_version();
        let node_records = registry_client
            .get_subnet_node_records(subnet_test_id(P2P_SUBNET_ID_DEFAULT), registry_version)
            .unwrap_or(None)
            .unwrap_or_default();
        assert_eq!((num_replicas - 1) as usize, node_records.len());

        // Get removed node
        let peers = gossip.get_current_peer_ids();
        let nodes: HashSet<NodeId> = node_records.iter().map(|node_id| node_id.0).collect();
        let mut removed_peer = node_test_id(10);
        let iter_peers = gossip.get_current_peer_ids();
        for peer in iter_peers.into_iter() {
            if !nodes.contains(&peer) {
                removed_peer = peer;
            }
        }
        assert_ne!(removed_peer, node_test_id(10));
        // Ensure number of peers are the expected amount
        // from registry version 1 (version registry is currently using).
        assert_eq!(num_peers as usize, peers.len());

        // Add adverts from the peer that is removed in the latest registry version
        test_add_adverts(&gossip, 0..5, removed_peer);

        // Refresh registry to get latest version.
        gossip.refresh_topology();
        // Assert number of peers has been decreased by one.
        assert_eq!(
            (num_peers - 1) as usize,
            gossip.get_current_peer_ids().len()
        );

        // Validate adverts from the removed_peer are no longer present.
        for advert_id in 0..5 {
            let advert = gossip.prioritizer.get_advert_from_peer(
                &ArtifactId::FileTreeSync(advert_id.to_string()),
                &CryptoHash(vec![u8::try_from(advert_id).unwrap()]),
                &removed_peer,
            );
            assert_eq!(advert, Err(DownloadPrioritizerError::NotFound));
        }

        // Validate adverts added from removed_peer are rejected
        test_add_adverts(&gossip, 0..5, removed_peer);
        for advert_id in 0..5 {
            let advert = gossip.prioritizer.get_advert_from_peer(
                &ArtifactId::FileTreeSync(advert_id.to_string()),
                &CryptoHash(vec![u8::try_from(advert_id).unwrap()]),
                &removed_peer,
            );
            assert_eq!(advert, Err(DownloadPrioritizerError::NotFound));
        }
    }

    #[tokio::test]
    async fn download_manager_add_adverts() {
        let logger = p2p_test_setup_logger();
        let gossip = new_test_gossip(2, &logger, tokio::runtime::Handle::current());
        test_add_adverts(&gossip, 0..1000, node_test_id(1));
    }

    /// This function asserts that the chunks to be downloaded is correctly
    /// upper bounded, where the upper bound is specified in the gossip
    /// configuration.
    #[tokio::test]
    async fn download_manager_compute_work_basic() {
        let logger = p2p_test_setup_logger();
        let num_replicas = 2;
        let gossip = new_test_gossip(num_replicas, &logger, tokio::runtime::Handle::current());
        test_add_adverts(&gossip, 0..1000, node_test_id(num_replicas as u64 - 1));
        let chunks_to_be_downloaded = gossip
            .download_next_compute_work(node_test_id(num_replicas as u64 - 1))
            .unwrap();
        assert_eq!(
            chunks_to_be_downloaded.len(),
            gossip.gossip_config.max_artifact_streams_per_peer as usize
        );
        for (i, chunk_req) in chunks_to_be_downloaded.iter().enumerate() {
            assert_eq!(
                chunk_req.artifact_id,
                ArtifactId::FileTreeSync(i.to_string())
            );
            assert_eq!(chunk_req.chunk_id, ChunkId::from(0));
        }
    }

    /// This function tests the correct functioning when a single chunk times
    /// out.
    ///
    /// All peers advertise the same set of adverts. A download is initiated at
    /// the first peer. After it times out, the test verifies that the chunk
    /// gets requested from the next peer.
    /// Once the chunk has been requested from every peer, a new round of
    /// download requests begins.
    #[tokio::test]
    async fn download_manager_single_chunked_timeout() {
        // The total number of replicas is 4 in this test.
        let num_replicas = 4;
        let logger = p2p_test_setup_logger();
        let mut gossip = new_test_gossip(num_replicas, &logger, tokio::runtime::Handle::current());
        gossip.gossip_config.max_chunk_wait_ms = 1000;

        let test_assert_compute_work_len =
            |gossip: &GossipImpl, node_id, compute_work_count: usize| {
                let chunks_to_be_downloaded = gossip.download_next_compute_work(node_id).unwrap();
                assert_eq!(chunks_to_be_downloaded.len(), compute_work_count);
                for (i, chunk_req) in chunks_to_be_downloaded.iter().enumerate() {
                    assert_eq!(
                        chunk_req.artifact_id,
                        ArtifactId::FileTreeSync(i.to_string())
                    );
                    assert_eq!(chunk_req.chunk_id, ChunkId::from(0));
                }
            };
        let request_queue_size = gossip.gossip_config.max_artifact_streams_per_peer as usize;

        // Skip the first peer at index 0 as it is the requesting node.
        for peer_id in 1..num_replicas {
            test_add_adverts(
                &gossip,
                0..request_queue_size as u32,
                node_test_id(peer_id as u64),
            );
        }

        for peer_id in 1..num_replicas {
            test_assert_compute_work_len(&gossip, node_test_id(peer_id as u64), request_queue_size);
            for other_peer in 1..num_replicas {
                if other_peer != peer_id {
                    test_assert_compute_work_len(&gossip, node_test_id(other_peer as u64), 0);
                }
            }
            test_timeout_peer(&gossip, &node_test_id(peer_id as u64));
            if peer_id != num_replicas - 1 {
                test_assert_compute_work_len(&gossip, node_test_id(peer_id as u64), 0);
            }
        }

        // All peers have been probed once. Thus, this attempt round is
        // exhausted and download attempts can start afresh.
        for advert_id in 0..request_queue_size as u32 {
            let artifact_id = ArtifactId::FileTreeSync(advert_id.to_string());
            let advert_tracker = gossip
                .prioritizer
                .get_advert_tracker(
                    &artifact_id,
                    &CryptoHash(Vec::from(advert_id.to_be_bytes())),
                )
                .unwrap();
            let mut advert_tracker = advert_tracker.write().unwrap();
            assert!(!advert_tracker.is_attempts_round_complete(ChunkId::from(0)),);
            for peer_id in 0..num_replicas {
                assert!(
                    !advert_tracker.peer_attempted(ChunkId::from(0), &node_test_id(peer_id as u64)),
                );
            }
        }
    }

    /// This functions tests the correct functioning when chunks and artifacts
    /// time out.
    #[tokio::test]
    async fn download_manager_timeout_artifact() {
        // There are 3 nodes in total, Node 1 and 2 are actively used in the test.
        let num_replicas = 3;
        let logger = p2p_test_setup_logger();
        let mut gossip = new_test_gossip(num_replicas, &logger, tokio::runtime::Handle::current());
        gossip.gossip_config.max_artifact_streams_per_peer = 1;
        gossip.gossip_config.max_chunk_wait_ms = 1000;
        let advert_range = 1..num_replicas;
        // Node 1 and 2 both advertise advert 1 and 2.
        for i in 1..num_replicas {
            test_add_adverts(&gossip, advert_range.clone(), node_test_id(i as u64))
        }

        // Advert 1 and 2 are now being downloaded by node 1 and 2.
        for i in 1..num_replicas {
            let chunks_to_be_downloaded = gossip
                .download_next_compute_work(node_test_id(i as u64))
                .unwrap();
            assert_eq!(
                chunks_to_be_downloaded.len(),
                gossip.gossip_config.max_artifact_streams_per_peer as usize
            );
        }

        // Time out the artifact as well as the chunks.
        let sleep_duration =
            std::time::Duration::from_millis((gossip.gossip_config.max_chunk_wait_ms * 2) as u64);
        std::thread::sleep(sleep_duration);

        // Node 1 and 2 now both have moved forward and advertise advert 3 and
        // 4 while advert 1 and 2 have timed out.
        for i in 1..num_replicas {
            test_add_adverts(&gossip, 3..5, node_test_id(i as u64))
        }

        // Test that chunks have timed out.
        for i in 1..num_replicas {
            test_timeout_peer(&gossip, &node_test_id(i as u64))
        }
        // Test that artifacts also have timed out.
        gossip.process_timed_out_artifacts();
        {
            let mut artifacts_under_construction = gossip.artifacts_under_construction.write();

            for i in advert_range {
                assert!(artifacts_under_construction
                    .get_tracker(&CryptoHash(Vec::from(i.to_be_bytes())))
                    .is_none());
            }
        }

        // After advert 1 and 2 have timed out, the download manager must start
        // downloading the next artifacts 3 and 4 now.
        for i in 1..num_replicas {
            let chunks_to_be_downloaded = gossip
                .download_next_compute_work(node_test_id(i as u64))
                .unwrap();
            assert_eq!(
                chunks_to_be_downloaded.len(),
                gossip.gossip_config.max_artifact_streams_per_peer as usize
            );
        }

        {
            let mut artifacts_under_construction = gossip.artifacts_under_construction.write();
            // Advert 1 and 2 timed out, so check adverts starting from 3 exists.
            for counter in 1u32..3 {
                assert!(artifacts_under_construction
                    .get_tracker(&CryptoHash(Vec::from(counter.to_be_bytes())))
                    .is_none());
            }
            for counter in 3u32..5 {
                assert!(artifacts_under_construction
                    .get_tracker(&CryptoHash(Vec::from(counter.to_be_bytes())))
                    .is_some());
            }
        }
    }

    /// The function returns a simple DKG message which changes according to the
    /// number passed in.
    fn receive_check_test_create_message(number: u32) -> DkgMessage {
        let dkg_id = NiDkgId {
            start_block_height: Height::from(number as u64),
            dealer_subnet: SubnetId::from(PrincipalId::new_subnet_test_id(number as u64)),
            dkg_tag: NiDkgTag::LowThreshold,
            target_subnet: NiDkgTargetSubnet::Local,
        };
        DkgMessage {
            content: DealingContent::new(
                NiDkgDealing::dummy_dealing_for_tests(number as u8),
                dkg_id,
            ),
            signature: BasicSignature::fake(NodeId::from(PrincipalId::new_node_test_id(
                number as u64,
            ))),
        }
    }
    /// The function returns a new chunk with the given chunk ID and artifact
    /// ID. The chunk created differs based on the number provided (same as the
    /// advert).
    fn receive_check_test_create_chunk(
        chunk_id: ChunkId,
        artifact_id: ArtifactId,
        number: u32,
        integrity_hash: CryptoHash,
    ) -> GossipChunk {
        let payload = Artifact::DkgMessage(receive_check_test_create_message(number));

        let request = GossipChunkRequest {
            artifact_id,
            integrity_hash,
            chunk_id,
        };
        GossipChunk {
            request,
            artifact: Ok(payload),
        }
    }

    /// The function returns the given number of adverts.
    fn receive_check_test_create_adverts(range: Range<u32>) -> Vec<GossipAdvert> {
        let mut result = vec![];
        for advert_number in range {
            let msg = receive_check_test_create_message(advert_number);
            let artifact_id = ArtifactId::DkgMessage(DkgMessageId::from(&msg));
            let gossip_advert = GossipAdvert {
                artifact_id,
                attribute: ic_types::artifact::ArtifactAttribute::Empty(()),
                size: 0,
                integrity_hash: ic_types::crypto::crypto_hash(&msg).get(),
            };
            result.push(gossip_advert);
        }
        result
    }

    /// The function tests the processing of chunks.
    ///
    /// In particular, it tests that the cache contains the artifact hash(es)
    /// afterwards and that the download manager does not consider
    /// downloading the same artifact(s) again when receiving the corresponding
    /// adverts again.
    ///
    /// This test also validates that adverts with the same artifact ID but
    /// different integrity hashes can be processed from advert -> artifact.
    #[tokio::test]
    async fn receive_check_test() {
        // Initialize the logger and download manager for the test.
        let logger = p2p_test_setup_logger();
        let gossip = new_test_gossip(2, &logger, tokio::runtime::Handle::current());
        let node_id = node_test_id(1);
        let max_adverts = gossip.gossip_config.max_artifact_streams_per_peer;
        let mut adverts = receive_check_test_create_adverts(0..max_adverts);
        let msg = receive_check_test_create_message(0);
        let artifact_id = ArtifactId::DkgMessage(DkgMessageId::from(&msg));
        for advert in &mut adverts {
            advert.artifact_id = artifact_id.clone();
        }

        for gossip_advert in &adverts {
            gossip.on_advert(gossip_advert.clone(), node_id);
        }
        let chunks_to_be_downloaded = gossip.download_next_compute_work(node_id).unwrap();

        // Add the chunk(s).
        for (index, chunk_req) in chunks_to_be_downloaded.iter().enumerate() {
            // Verify all the chunk requests processed have the same artifact id.
            assert_eq!(chunk_req.artifact_id, artifact_id);
            assert_eq!(
                chunk_req.integrity_hash,
                ic_types::crypto::crypto_hash(&receive_check_test_create_message(index as u32))
                    .get(),
            );
            assert_eq!(chunk_req.chunk_id, ChunkId::from(0));

            let gossip_chunk = receive_check_test_create_chunk(
                chunks_to_be_downloaded[index].chunk_id,
                chunks_to_be_downloaded[index].artifact_id.clone(),
                index as u32,
                chunk_req.integrity_hash.clone(),
            );

            gossip.on_chunk(gossip_chunk, node_id);
        }

        // Test that the cache contains the artifact(s).
        {
            let receive_check_caches = gossip.receive_check_caches.read();
            let cache = &receive_check_caches.get(&node_id).unwrap();
            for gossip_advert in &adverts {
                assert!(cache.contains(&gossip_advert.integrity_hash));
            }
        }

        // Test that the artifact is ignored when providing the same adverts again.
        for gossip_advert in &adverts {
            gossip.on_advert(gossip_advert.clone(), node_id);
        }
        let new_chunks_to_be_downloaded = gossip.download_next_compute_work(node_id).unwrap();

        assert!(new_chunks_to_be_downloaded.is_empty());
    }

    /// This test will verify that artifacts with incorrect integrity hashes
    /// will not be processed.
    #[tokio::test]
    async fn integrity_hash_test() {
        // Initialize the logger and download manager for the test.
        let logger = p2p_test_setup_logger();
        let gossip = new_test_gossip(2, &logger, tokio::runtime::Handle::current());
        let node_id = node_test_id(1);
        let max_adverts = 20;
        let adverts = receive_check_test_create_adverts(0..max_adverts);
        for gossip_advert in &adverts {
            gossip.on_advert(gossip_advert.clone(), node_id);
        }
        let chunks_to_be_downloaded = gossip.download_next_compute_work(node_id).unwrap();

        // Add the chunks with incorrect integrity hash
        for (i, chunk_req) in adverts.iter().enumerate() {
            // Create chunks with different integrity hashes
            let gossip_chunk = receive_check_test_create_chunk(
                chunks_to_be_downloaded[i].chunk_id,
                chunks_to_be_downloaded[i].artifact_id.clone(),
                max_adverts,
                chunk_req.integrity_hash.clone(),
            );

            gossip.on_chunk(gossip_chunk, node_id);
        }

        // Validate that the cache does not contain the artifacts since we put chunks
        // with incorrect integrity hashes
        {
            let receive_check_caches = gossip.receive_check_caches.read();
            let cache = &receive_check_caches.get(&node_id).unwrap();
            for gossip_advert in &adverts {
                assert!(!cache.contains(&gossip_advert.integrity_hash));
            }
        }

        // Validate that the number of integrity check failures is equivalent to the
        // length of the adverts in the incorrect integrity hash bucket
        assert_eq!(
            adverts.len(),
            gossip.metrics.integrity_hash_check_failed.get() as usize
        );
    }

    #[test]
    fn test_artifact_advert_match() {
        // Positive case: advert matches artifact
        let cup = make_genesis(ic_types::consensus::dkg::Summary::fake());
        let block = BlockProposal::fake(cup.content.block.into_inner(), node_test_id(0));
        let msg = block.into_message();
        let mut advert: ic_types::p2p::GossipAdvert =
            ConsensusArtifact::message_to_advert(&msg).into();
        assert!(advert_matches_artifact::<ConsensusArtifact>(&msg, &advert));
        // Negative case: advert does not match artifact
        advert.size = 0;
        assert!(!advert_matches_artifact::<ConsensusArtifact>(&msg, &advert));
    }
}
