//! A module that maintains priority of adverts that need to be downloaded.
//!
//! <h1>Overview</h1>
//!
//! The DownloadPrioritizer maintains an inventory of all adverts seen by this
//! replica.  This is in contrast to the peer manager that has inventory
//! on-going downloads from a peer and chunks tracking those downloads.
//!
//! The download prioritizer provides efficient and real-time indexing of
//! adverts based on priority functions provided by P2P clients.
//!
//!  The download prioritizer is primarily used by clients to index their next
//! most important  downloads and is consulted by the peer manager to compute
//! the download order.

/// DownloadPrioritizer trait definition.
/// Used for adding, removing, and managing adverts per peer, as well as to set
/// the priority function.
pub(crate) trait DownloadPrioritizer: Send + Sync {
    /// Returns the priority of a given advert using the priority function of
    /// the corresponding client
    fn peek_priority(&self, advert: &GossipAdvert) -> Result<Priority, DownloadPrioritizerError>;

    /// Add/Register the receipt of an advert from a peer.
    ///
    /// The same advert may be received from multiple peers.  Prioritization of
    /// added adverts is always in sync with the last updated priority
    /// function.
    fn add_advert(
        &self,
        advert: GossipAdvert,
        peer_id: NodeId,
    ) -> Result<(), DownloadPrioritizerError>;

    /// Delete an advert.
    ///
    /// The advert may have been received from N peers. Retiring an advert
    /// atomically clears it from download list of all peers.  NOTE: Adverts
    /// should only be deleted AFTER verification of their integrity hash.
    fn delete_advert(
        &self,
        id: &ArtifactId,
        integrity_hash: &CryptoHash,
        final_action: AdvertTrackerFinalAction,
    ) -> Result<(), DownloadPrioritizerError>;

    /// Delete an advert from a specific peer.
    ///
    /// Similar to delete_advert but deletes an advert from a particular peer.
    /// If this peer was the last peer that with an advert tracker for this
    /// artifact return Ok() and an error otherwise.
    fn delete_advert_from_peer(
        &self,
        id: &ArtifactId,
        integrity_hash: &CryptoHash,
        peer_id: NodeId,
        final_action: AdvertTrackerFinalAction,
    ) -> Result<(), DownloadPrioritizerError>;

    /// Clears all adverts for a specific peer.
    fn clear_peer_adverts(
        &self,
        peer_id: NodeId,
        final_action: AdvertTrackerFinalAction,
    ) -> Result<(), DownloadPrioritizerError>;

    /// Re-insert advert at the tail as fresh advert
    ///
    /// Advert for the artifact is removed and re-inserted at the tail of
    /// received adverts from all advertisers.
    ///
    /// Re-insertion at the tails allows this peer  to peek into other (possibly
    /// subsequent) adverts from its neighbors. The subsequent adverts may
    /// obviate the use of the timed-out artifact.
    ///
    /// If there are no subsequent adverts or no other signal of IC progress the
    /// priority function remains the same.  In this case the node will
    /// re-attempt downloading the timed out artifact.
    fn reinsert_advert_at_tail(
        &self,
        id: &ArtifactId,
        integrity_hash: &CryptoHash,
    ) -> Result<(), DownloadPrioritizerError>;

    /// Get the advert as received from the particular peer.
    fn get_advert_from_peer(
        &self,
        id: &ArtifactId,
        integrity_hash: &CryptoHash,
        peer_id: &NodeId,
    ) -> Result<Option<GossipAdvert>, DownloadPrioritizerError>;

    /// Update priority function and advert queues.
    ///
    /// This function updates the priority functions for all gossip clients. In
    /// addition, it updates the advert queues for all peers to reflect the
    /// updated prioritization.
    ///
    /// The function returns a list of adverts that have been dropped by
    /// the application of the current priority function. Dropped
    /// adverts/artifacts are no longer referenced by the prioritizer. The
    /// return list can be used to clean ancillary data structures, namely the
    /// `artifacts_under_construction` list in
    /// [`DownloadManager`](../download_management/index.html).
    #[must_use]
    fn update_priority_functions(&self, artifact_manager: &dyn ArtifactManager) -> Vec<CryptoHash>;

    /// Get peer priority queues.
    /// Returns a guarded iterator of advert trackers, grouped by priorities,
    /// for a given peer. This queue/iterator is guarded against
    /// simultaneous addition/delete/re-prioritization of adverts that are
    /// contained in the queue.
    ///  (Concurrent operations will block until this queue is destroyed)
    //
    /// These queue elements are real-time prioritized and always
    /// reflect the priority order for artifacts to be downloaded as per last
    /// priority function update.
    ///
    /// This queue returns a lazy iterator of shallow objects (i.e Arc's to
    /// actual adverts). This means that the runtime complexity of this function
    /// is low and therefore it can be called many times without much
    /// performance overhead.
    fn get_peer_priority_queues(&self, peer_id: NodeId) -> PeerAdvertQueues<'_>;

    /// Given an artifact ID and integrity hash, fetches the advert tracker.
    fn get_advert_tracker(
        &self,
        id: &ArtifactId,
        integrity_hash: &CryptoHash,
    ) -> Result<AdvertTrackerRef, DownloadPrioritizerError>;
}

use crate::metrics::DownloadPrioritizerMetrics;
use linked_hash_map::LinkedHashMap;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Deref, DerefMut, Index, IndexMut};
use std::sync::{Arc, RwLock, RwLockReadGuard};
use std::time::Instant;
use strum::IntoEnumIterator;

use ic_types::{
    artifact::{ArtifactAttribute, ArtifactId, ArtifactPriorityFn, ArtifactTag, Priority},
    chunkable::ChunkId,
    p2p::GossipAdvert,
    NodeId,
};

use ic_interfaces::artifact_manager::ArtifactManager;
use ic_types::crypto::CryptoHash;

// Priority function (defaults)
/// Internal representation of a priority function
type InternalPriorityFn = Arc<ArtifactPriorityFn>;
/// Function type that returns a corresponding priority function
type GetPriorityFn =
    Arc<dyn Fn(&dyn ArtifactManager, ArtifactTag) -> InternalPriorityFn + Send + Sync + 'static>;

/// Returns a default priority value
fn priority_fn_default(_: &ArtifactId, _: &ArtifactAttribute) -> Priority {
    Priority::Fetch
}

/// Returns the default priority using the internal representation
fn get_priority_fn_default(_: &dyn ArtifactManager, _: ArtifactTag) -> InternalPriorityFn {
    Arc::new(Box::new(priority_fn_default))
}

/// Gets priority function from artifact manager
fn get_priority_fn_from_manager(
    artifact_manager: &dyn ArtifactManager,
    tag: ArtifactTag,
) -> InternalPriorityFn {
    match artifact_manager.get_priority_function(tag) {
        Some(function) => Arc::new(function),
        None => Arc::new(Box::new(priority_fn_default)),
    }
}

/// Tracks download attempt history for a chunk
#[derive(Default)]
struct DownloadAttempt {
    /// Nodes from which the chunk has been requested
    peers: BTreeSet<NodeId>,
    /// True if chunk download request is in progress
    /// (i.e has not timed-out or failed) with
    /// at least 1 advertiser.
    in_progress: bool,
}

/// Per chunk download attempts tracker data structure
type DownloadAttemptMap = BTreeMap<ChunkId, DownloadAttempt>;

/// A struct that holds information for tracking the state of an advert
pub(crate) struct AdvertTracker {
    /// Advert for this tracker
    pub advert: GossipAdvert,
    /// Peers that have advertised this advert
    pub peers: Vec<NodeId>,
    /// Per chunk download attempt history map
    download_attempt_map: DownloadAttemptMap,
    /// Priority as computed by the last priority function
    priority: Priority,
}

/// Chunk download attempt tracker
///
/// This trait primarily assists in timeout and error handling.  It is a
/// book-keeping trait that helps the download manager remember a "short"
/// download history for a chunk download.
///
/// The history is short as it only remembers 1 last round worth of
/// chunk download attempts. aka an "attempt round"
///
/// For every downloadable chunk an "attempt round" consists of each of its
/// advertiser being requested once for the chunk. The advertiser are probed one
/// at a time in no particular order. Any peer that has BW available can
/// initiate a chunk request given no other peer is downloading the same chunk
/// in parallel.
///
/// A round completes when
/// a. A peer successfully downloads the chunk
/// b. All peers have failed once. At this point the download attempt history is
/// reset
///
/// Once reset the chunk download attempt is evaluated afresh as per
/// the above rules.
///
/// This assures that the download will eventually succeed by requesting the
/// chunk from an honest peer.
///
/// max duplicity or download duplicity is built on top of the above
/// construct and maintains the invariant provided by above logic.
pub(crate) trait DownloadAttemptTracker {
    /// Record a chunk download attempt by a peer.  This signifies that this
    /// chunk download was attempted in this attempt round  by a peer.
    fn record_attempt(&mut self, chunk_id: ChunkId, node_id: &NodeId);

    /// Returns true if the download attempt "round" has concluded. Signifies
    /// that peers that advertised the chunk have been requested once for
    /// the chunk.
    #[allow(clippy::wrong_self_convention)]
    fn is_attempts_round_complete(&mut self, chunk_id: ChunkId) -> bool;

    /// Reset attempt history for a chunk after the attempt round is completed.
    fn attempts_round_reset(&mut self, chunk_id: ChunkId);

    /// Checks if a peer has participated in the current download attempt round.
    /// This is used to ensure that a peer request a chunk once per round.
    fn peer_attempted(&self, chunk_id: ChunkId, node_id: &NodeId) -> bool;

    /// The `in_progress` flag signifies that a chunk request is in
    /// progress/flight from a peer. This stops multiple peers from
    /// requesting the same chunk at the same time. This ensures that peer
    /// BW is primarily utilized to download unique chunks required for the
    /// IC to make progress.
    fn set_in_progress(&mut self, chunk_id: ChunkId, node_id: &NodeId);

    /// Unsets the `in_progress` flag for a chunk
    fn unset_in_progress(&mut self, chunk_id: ChunkId);

    /// Returns the value of the `in_progress` flag for a chunk
    #[allow(clippy::wrong_self_convention)]
    fn is_in_progress(&mut self, chunk_id: ChunkId) -> bool;
}

/// Implementation for the DownloadAttemptTracker trait
impl DownloadAttemptTracker for AdvertTracker {
    fn record_attempt(&mut self, chunk_id: ChunkId, node_id: &NodeId) {
        let attempt = self
            .download_attempt_map
            .entry(chunk_id)
            .or_insert_with(Default::default);
        attempt.peers.insert(*node_id);
    }

    fn attempts_round_reset(&mut self, chunk_id: ChunkId) {
        self.download_attempt_map
            .insert(chunk_id, Default::default());
    }

    fn is_attempts_round_complete(&mut self, chunk_id: ChunkId) -> bool {
        let attempt = self
            .download_attempt_map
            .entry(chunk_id)
            .or_insert_with(Default::default);
        !attempt.in_progress && attempt.peers.len() == self.peers.len()
    }

    fn peer_attempted(&self, chunk_id: ChunkId, node_id: &NodeId) -> bool {
        if let Some(attempt) = self.download_attempt_map.get(&chunk_id) {
            attempt.peers.contains(node_id)
        } else {
            false
        }
    }

    fn set_in_progress(&mut self, chunk_id: ChunkId, node_id: &NodeId) {
        let mut attempt = self
            .download_attempt_map
            .entry(chunk_id)
            .or_insert_with(Default::default);
        attempt.peers.insert(*node_id);
        attempt.in_progress = true;
    }

    fn unset_in_progress(&mut self, chunk_id: ChunkId) {
        self.get_download_attempt_tracker(chunk_id).in_progress = false;
    }

    fn is_in_progress(&mut self, chunk_id: ChunkId) -> bool {
        self.get_download_attempt_tracker(chunk_id).in_progress
    }
}

/// Implementation for the AdvertTracker data structure
impl AdvertTracker {
    /// Adds a peer. If the peer already exists, it is ignored.
    fn add_peer(&mut self, node_id: NodeId) {
        for x in &self.peers {
            if (*x).get() == node_id.get() {
                return;
            }
        }
        self.peers.push(node_id);
    }

    /// Removes a peer
    fn remove_peer(&mut self, node_id: NodeId) {
        self.peers.retain(|x| (*x).get() != node_id.get());
    }

    /// Returns the DownloadAttemptTracker for a chunk
    fn get_download_attempt_tracker(&mut self, chunk_id: ChunkId) -> &mut DownloadAttempt {
        self.download_attempt_map
            .entry(chunk_id)
            .or_insert_with(Default::default)
    }

    /// Returns `true` if a peer exists, or `false` otherwise
    fn has_peer(&self, peer_id: &NodeId) -> bool {
        self.peers.contains(peer_id)
    }
}

/// Guarded reference to an advert tracker
pub(crate) type AdvertTrackerRef = Arc<RwLock<AdvertTracker>>;

// Primary data structure to create multiple indices for Adverts. An Aliased
// Index is a set of adverts that are simultaneously indexed on multiple
// dimension
/// Mapping from an integrity hash to the corresponding advert tracker
pub(crate) type AdvertTrackerAliasedMap = LinkedHashMap<CryptoHash, AdvertTrackerRef>;

/// Final action to be taken for the advert
pub enum AdvertTrackerFinalAction {
    Success,
    Abort,
    #[cfg(test)]
    Failed,
}

// Client Index:
//
// Replica Adverts indexed/categorized by various P2P clients.  A client is an
// entity that defines a variant in the ArtifactId enum.  (vice-versa, every
// variant in the ArtifactId enum is a type owned by a unique client.

/// Advert mapping (`ArtifactId` -> `AdvertTracker`), along with the
/// corresponding priority function, for each type of gossip client
#[derive(Default)]
struct ClientAdvertMap {
    consensus: ClientAdvertMapInt,
    ingress: ClientAdvertMapInt,
    certification: ClientAdvertMapInt,
    canister_http: ClientAdvertMapInt,
    dkg: ClientAdvertMapInt,
    ecdsa: ClientAdvertMapInt,
    file_tree_sync: ClientAdvertMapInt,
    state: ClientAdvertMapInt,
}

/// A single client advert tracking data structure
struct ClientAdvertMapInt {
    advert_map: AdvertTrackerAliasedMap,
    get_priority_fn: GetPriorityFn,
    priority_fn: InternalPriorityFn,
}

impl Default for ClientAdvertMapInt {
    fn default() -> Self {
        ClientAdvertMapInt {
            advert_map: Default::default(),
            get_priority_fn: Arc::new(get_priority_fn_default),
            priority_fn: Arc::new(Box::new(priority_fn_default)),
        }
    }
}

impl Index<&ArtifactId> for ClientAdvertMap {
    type Output = ClientAdvertMapInt;
    fn index(&self, artifact_id: &ArtifactId) -> &Self::Output {
        match artifact_id {
            ArtifactId::ConsensusMessage(_) => &self.consensus,
            ArtifactId::IngressMessage(_) => &self.ingress,
            ArtifactId::CanisterHttpMessage(_) => &self.canister_http,
            ArtifactId::CertificationMessage(_) => &self.certification,
            ArtifactId::DkgMessage(_) => &self.dkg,
            ArtifactId::EcdsaMessage(_) => &self.ecdsa,
            ArtifactId::FileTreeSync(_) => &self.file_tree_sync,
            ArtifactId::StateSync(_) => &self.state,
        }
    }
}

impl IndexMut<&ArtifactId> for ClientAdvertMap {
    fn index_mut(&mut self, artifact_id: &ArtifactId) -> &mut Self::Output {
        match artifact_id {
            ArtifactId::ConsensusMessage(_) => &mut self.consensus,
            ArtifactId::IngressMessage(_) => &mut self.ingress,
            ArtifactId::CertificationMessage(_) => &mut self.certification,
            ArtifactId::CanisterHttpMessage(_) => &mut self.canister_http,
            ArtifactId::DkgMessage(_) => &mut self.dkg,
            ArtifactId::EcdsaMessage(_) => &mut self.ecdsa,
            ArtifactId::FileTreeSync(_) => &mut self.file_tree_sync,
            ArtifactId::StateSync(_) => &mut self.state,
        }
    }
}

impl Index<ArtifactTag> for ClientAdvertMap {
    type Output = ClientAdvertMapInt;
    fn index(&self, p2p_client: ArtifactTag) -> &Self::Output {
        match p2p_client {
            ArtifactTag::ConsensusArtifact => &self.consensus,
            ArtifactTag::IngressArtifact => &self.ingress,
            ArtifactTag::CertificationArtifact => &self.certification,
            ArtifactTag::CanisterHttpArtifact => &self.canister_http,
            ArtifactTag::DkgArtifact => &self.dkg,
            ArtifactTag::EcdsaArtifact => &self.ecdsa,
            ArtifactTag::FileTreeSyncArtifact => &self.file_tree_sync,
            ArtifactTag::StateSyncArtifact => &self.state,
        }
    }
}

impl IndexMut<ArtifactTag> for ClientAdvertMap {
    fn index_mut(&mut self, p2p_client: ArtifactTag) -> &mut Self::Output {
        match p2p_client {
            ArtifactTag::ConsensusArtifact => &mut self.consensus,
            ArtifactTag::IngressArtifact => &mut self.ingress,
            ArtifactTag::CertificationArtifact => &mut self.certification,
            ArtifactTag::CanisterHttpArtifact => &mut self.canister_http,
            ArtifactTag::DkgArtifact => &mut self.dkg,
            ArtifactTag::EcdsaArtifact => &mut self.ecdsa,
            ArtifactTag::FileTreeSyncArtifact => &mut self.file_tree_sync,
            ArtifactTag::StateSyncArtifact => &mut self.state,
        }
    }
}

// Peer Index:
//
// Replica adverts are simultaneously indexed on the Client type and peer id.
// Peer index is based on the peer ids that advertised the artifact, and the
// current download priority assigned to the artifact sitting on the respective
// peer's priority queue.
//
// Peer index is a real time (always up-to-date) index that orders the next
// artifacts to be  downloaded by all known peers. Index order confirms to the
// last updated client priority  function.
/// Mapping from peer ID to its advert mapping
type PeerAdvertMap = LinkedHashMap<NodeId, PeerAdvertMapRef>;
/// Guarded reference for a PeerAdvertMapInt
type PeerAdvertMapRef = Arc<RwLock<PeerAdvertMapInt>>;

/// Advert mapping for each priority class
#[derive(Default)]
pub(crate) struct PeerAdvertMapInt {
    fetch_now: AdvertTrackerAliasedMap,
    fetch: AdvertTrackerAliasedMap,
    later: AdvertTrackerAliasedMap,
    stash: AdvertTrackerAliasedMap,
}

impl Index<Priority> for PeerAdvertMapInt {
    type Output = AdvertTrackerAliasedMap;
    fn index(&self, priority: Priority) -> &Self::Output {
        match priority {
            Priority::Drop => panic!("Index out of bounds"),
            Priority::FetchNow => &self.fetch_now,
            Priority::Fetch => &self.fetch,
            Priority::Later => &self.later,
            Priority::Stash => &self.stash,
        }
    }
}

impl IndexMut<Priority> for PeerAdvertMapInt {
    fn index_mut(&mut self, priority: Priority) -> &mut Self::Output {
        match priority {
            Priority::Drop => panic!("Index out of bounds"),
            Priority::FetchNow => &mut self.fetch_now,
            Priority::Fetch => &mut self.fetch,
            Priority::Later => &mut self.later,
            Priority::Stash => &mut self.stash,
        }
    }
}

/// Implementation for the PeerAdvertMapInt data structure. Allows retrieving an
/// iterator over the mapping.
impl PeerAdvertMapInt {
    /// Returns an iterator over the advert mapping, ordered by priority
    pub fn iter(&self) -> impl Iterator<Item = (&CryptoHash, &AdvertTrackerRef)> {
        self[Priority::FetchNow]
            .iter()
            .chain(self[Priority::Fetch].iter())
            .chain(self[Priority::Later].iter())
    }
}

/// The Advert Prioritization Manager struct.
///
/// Maintains two Indices over received adverts
///  a. Client Index and
///  b. Peer Index
///
/// The Advert manager implements the "AdvertManager" trait. This
/// trait has functionality that amounts to ..
///  1. addition/removal of adverts
///  2. index/re-index adverts based on client priority functions
///  3. provided a prioritized advert iterator for the download_next()
///  function of the "PeerManager" trait.
pub(crate) struct DownloadPrioritizerImpl {
    /// Metrics collection
    metrics: DownloadPrioritizerMetrics,
    /// Adverts Indexed by clients types and peer ids
    replica_map: RwLock<(ClientAdvertMap, PeerAdvertMap)>,
}

/// Guarded Iterators for per-peer download list
///
/// The Advert Manager generates guarded iterators that iterate over
/// prioritized adverts to be downloaded from a specific peer.
///
/// The iterators are guarded in the sense that as no mutating updates are
/// allowed to the peer's advert list while a guarded iterator object is alive.
///
/// PeerManager periodically pulls out the guarded iterators for known peers and
/// "quickly" computes the artifacts to be downloaded before destroying the
/// guarded iterator.  Here "quickly" means that the operations on these
/// iterators should not involve any blocking operations.
///
/// If the PeerManager needs a blocking operation on the iterator it should copy
/// out the iterator elements and drop the iterator before initiating a blocking
/// call.
///
/// This fits in with the working model of "compute_work" and "do_work" phases
/// of the peer manager's download next call. "compute_work" quickly computes
/// the work to be done and leaves the heavy lifting to the "do_work" phase.
///
/// Note: The download prioritizer is thread-safe and multiple threads can work
/// on it.
pub(crate) struct PeerAdvertQueues<'a> {
    /// A guard
    _guard: RwLockReadGuard<'a, (ClientAdvertMap, PeerAdvertMap)>,
    /// Reference for the peer's advert map that holds the iterators
    pub peer_advert_map_ref: PeerAdvertMapRef,
}

/// Download Prioritizer Error Codes
#[derive(PartialEq, Debug)]
pub(crate) enum DownloadPrioritizerError {
    /// Advert was dropped immediately upon insert into the download prioritizer
    ImmediatelyDropped,
    /// Advert was deleted from a peer, but other peers hold references
    HasPeerReferences,
    /// Advert was not found
    NotFound,
}

///  DownloadPrioritizer Trait implementation
impl DownloadPrioritizer for DownloadPrioritizerImpl {
    fn peek_priority(&self, advert: &GossipAdvert) -> Result<Priority, DownloadPrioritizerError> {
        let guard = self.replica_map.read().unwrap();
        let (client_advert_map, _) = guard.deref();
        let client = client_advert_map.index(&advert.artifact_id);
        let priority = (client.priority_fn)(&advert.artifact_id, &advert.attribute);
        if priority == Priority::Drop {
            self.metrics.priority_adverts_dropped.inc();
        }
        Ok(priority)
    }

    fn add_advert(
        &self,
        advert: GossipAdvert,
        peer_id: NodeId,
    ) -> Result<(), DownloadPrioritizerError> {
        let mut guard = self.replica_map.write().unwrap();
        let (client_advert_map, peer_map) = guard.deref_mut();

        let client = client_advert_map.index_mut(&advert.artifact_id);
        let priority = (client.priority_fn)(&advert.artifact_id, &advert.attribute);
        if priority == Priority::Drop {
            self.metrics.priority_adverts_dropped.inc();
            return Err(DownloadPrioritizerError::ImmediatelyDropped);
        }
        let integrity_hash = advert.integrity_hash.clone();
        let integrity_hash_peer_index = advert.integrity_hash.clone();

        // Insert into the client advert map
        let advert_tracker = client.advert_map.entry(integrity_hash).or_insert_with(|| {
            Arc::new(RwLock::new(AdvertTracker {
                advert,
                priority,
                peers: Default::default(),
                download_attempt_map: Default::default(),
            }))
        });

        let peer = peer_map.entry(peer_id).or_insert_with(Default::default);

        // Insert into the peer advert map
        assert!(priority != Priority::Drop);
        let mut peer = peer.write().unwrap();
        peer[priority]
            .entry(integrity_hash_peer_index)
            .or_insert_with(|| {
                self.metrics
                    .advert_queue_add
                    .with_label_values(&[&peer_id.to_string(), &format!("{:?}", priority)])
                    .inc();
                self.metrics
                    .advert_queue_size
                    .with_label_values(&[&peer_id.to_string(), &format!("{:?}", priority)])
                    .inc();
                advert_tracker.clone()
            });

        // Track the peer in the advert
        let mut advert_tracker = advert_tracker.write().unwrap();
        advert_tracker.add_peer(peer_id);
        Ok(())
    }

    fn update_priority_functions(&self, artifact_manager: &dyn ArtifactManager) -> Vec<CryptoHash> {
        // Atomic update is a simplification and is one of the ways to implement
        // priority fns.  A non-atomic version where we calculate priorities on
        // shadow structures and then periodically update the peer advert
        // priority queues is also a possibility.  In the non-atomic
        // implementation, there will be a lag between the clients updating the
        // priority_fn and its output getting reflected in the peer's advert
        // queues (this trades off performance vs exposure to stale priorities)

        self.metrics.priority_fn_updates.inc();
        let guard = self.replica_map.read().unwrap();
        let (client_advert_map, _) = guard.deref();
        let get_priority_fns: LinkedHashMap<_, _> = ArtifactTag::iter()
            .map(|id| (id, client_advert_map[id].get_priority_fn.clone()))
            .collect();
        drop(guard);

        // Capture the new priority functions.  This is a compute heavy operation so the
        // priority functions are collected with locks dropped.
        let priority_update_start = Instant::now();
        let priority_fns: LinkedHashMap<_, _> = get_priority_fns
            .iter()
            .map(|(k, get_priority_fn)| {
                let client_priority_fn = (*get_priority_fn)(artifact_manager, *k);
                (k, client_priority_fn)
            })
            .collect();

        // Set the newly collected priority functions
        let mut guard = self.replica_map.write().unwrap();
        let (client_advert_map, peer_map) = guard.deref_mut();
        priority_fns.into_iter().for_each(|(id, priority_fn)| {
            client_advert_map[*id].priority_fn = priority_fn.clone();
        });

        // Atomically(under lock) update all references from peers queues as per new
        // priority
        let mut dropped_artifacts = Vec::new();
        for client_idx in ArtifactTag::iter() {
            let client = &mut client_advert_map.index_mut(client_idx);
            let client_priority_fn = &client.priority_fn;
            client
                .advert_map
                .iter_mut()
                .map(|(_, advert_tracker_ref)| {
                    let mut advert_tracker = advert_tracker_ref.write().unwrap();
                    let old_priority = advert_tracker.priority;
                    let new_priority = (client_priority_fn)(
                        &advert_tracker.advert.artifact_id,
                        &advert_tracker.advert.attribute,
                    );
                    advert_tracker.priority = new_priority;
                    if new_priority == Priority::Drop {
                        self.metrics.priority_adverts_dropped.inc();
                        dropped_artifacts.push(advert_tracker.advert.integrity_hash.clone());
                    }
                    (advert_tracker_ref.clone(), old_priority, new_priority)
                })
                .filter(|(_, old_priority, new_priority)| old_priority != new_priority)
                .for_each(|(advert_tracker_ref, old_priority, new_priority)| {
                    self.peer_queues_update(
                        peer_map,
                        (advert_tracker_ref, old_priority, new_priority),
                    )
                });

            dropped_artifacts.iter().for_each(|x| {
                client.advert_map.remove(x);
            });
        }
        self.metrics
            .priority_fn_timer
            .observe(priority_update_start.elapsed().as_secs_f64());
        dropped_artifacts
    }

    fn delete_advert(
        &self,
        artifact_id: &ArtifactId,
        integrity_hash: &CryptoHash,
        _final_action: AdvertTrackerFinalAction,
    ) -> Result<(), DownloadPrioritizerError> {
        // remove from client queues
        let mut guard = self.replica_map.write().unwrap();
        let (client_advert_map, peer_map) = guard.deref_mut();
        let advert_tracker_ref: AdvertTrackerRef = client_advert_map[artifact_id]
            .advert_map
            .remove(integrity_hash)
            .map_or(Err(DownloadPrioritizerError::NotFound), Ok)?;
        // remove from peer maps
        let advert_tracker = advert_tracker_ref.read().unwrap();
        self.peer_queues_update(
            peer_map,
            (
                advert_tracker_ref.clone(),
                advert_tracker.priority,
                Priority::Drop,
            ),
        );

        Ok(())
    }

    fn get_peer_priority_queues(&self, peer_id: NodeId) -> PeerAdvertQueues<'_> {
        let _guard = self.replica_map.read().unwrap();
        let (_, peer_map) = _guard.deref();
        let peer_advert_map = peer_map.get(&peer_id);
        let peer_advert_map_ref: PeerAdvertMapRef = if let Some(peer_advert_map) = peer_advert_map {
            peer_advert_map.clone()
        } else {
            Default::default()
        };
        PeerAdvertQueues {
            _guard,
            peer_advert_map_ref,
        }
    }

    fn delete_advert_from_peer(
        &self,
        id: &ArtifactId,
        integrity_hash: &CryptoHash,
        peer_id: NodeId,
        _final_action: AdvertTrackerFinalAction,
    ) -> Result<(), DownloadPrioritizerError> {
        let mut guard = self.replica_map.write().unwrap();
        let (client_advert_map, peer_map) = guard.deref_mut();
        let client = &mut client_advert_map.index_mut(ArtifactTag::from(id));
        let advert_tracker = client
            .advert_map
            .get(integrity_hash)
            .ok_or(DownloadPrioritizerError::NotFound)?;

        // Remove from peer map
        let len = {
            let mut advert_tracker = advert_tracker.write().unwrap();
            if let Some(peer_advert_map) = peer_map.get_mut(&peer_id) {
                let mut peer_advert_map = peer_advert_map.write().unwrap();
                peer_advert_map[advert_tracker.priority]
                    .remove(&advert_tracker.advert.integrity_hash);
                self.metrics
                    .advert_queue_remove
                    .with_label_values(&[
                        &peer_id.to_string(),
                        &format!("{:?}", advert_tracker.priority),
                    ])
                    .inc();
                self.metrics
                    .advert_queue_size
                    .with_label_values(&[
                        &peer_id.to_string(),
                        &format!("{:?}", advert_tracker.priority),
                    ])
                    .dec();
            }
            advert_tracker.remove_peer(peer_id);
            advert_tracker.peers.len()
        };

        // Remove from client map
        match len {
            0 => {
                client.advert_map.remove(integrity_hash);
                self.metrics.adverts_deleted_from_peer.inc();
                Ok(())
            }
            _ => Err(DownloadPrioritizerError::HasPeerReferences),
        }
    }

    fn clear_peer_adverts(
        &self,
        peer_id: NodeId,
        _final_action: AdvertTrackerFinalAction,
    ) -> Result<(), DownloadPrioritizerError> {
        let mut guard = self.replica_map.write().unwrap();
        let (client_advert_map, peer_map) = guard.deref_mut();

        let mut peer_advert_map = peer_map
            .get_mut(&peer_id)
            .ok_or(DownloadPrioritizerError::NotFound)?
            .write()
            .unwrap();

        Priority::iter()
            .filter(|p| *p != Priority::Drop)
            .for_each(|p| {
                let priority_map = &mut peer_advert_map[p];
                while let Some((integrity_hash, advert_tracker)) = priority_map.pop_front() {
                    let mut advert_tracker = advert_tracker.write().unwrap();
                    self.metrics
                        .advert_queue_remove
                        .with_label_values(&[
                            &peer_id.to_string(),
                            &format!("{:?}", advert_tracker.priority),
                        ])
                        .inc();
                    self.metrics
                        .advert_queue_size
                        .with_label_values(&[
                            &peer_id.to_string(),
                            &format!("{:?}", advert_tracker.priority),
                        ])
                        .dec();
                    advert_tracker.remove_peer(peer_id);
                    if advert_tracker.peers.is_empty() {
                        client_advert_map[&advert_tracker.advert.artifact_id]
                            .advert_map
                            .remove(&integrity_hash);
                    }
                }
            });
        Ok(())
    }

    fn reinsert_advert_at_tail(
        &self,
        id: &ArtifactId,
        integrity_hash: &CryptoHash,
    ) -> Result<(), DownloadPrioritizerError> {
        let (advert, advertisers) = {
            let advert_tracker = self.get_advert_tracker(id, integrity_hash)?;
            let advert_tracker = advert_tracker.read().unwrap();
            (advert_tracker.advert.clone(), advert_tracker.peers.clone())
        };
        self.delete_advert(id, integrity_hash, AdvertTrackerFinalAction::Abort)?;
        advertisers.into_iter().for_each(|peer_id| {
            let _ = self.add_advert(advert.clone(), peer_id);
        });
        Ok(())
    }

    fn get_advert_tracker(
        &self,
        id: &ArtifactId,
        integrity_hash: &CryptoHash,
    ) -> Result<AdvertTrackerRef, DownloadPrioritizerError> {
        let mut guard = self.replica_map.write().unwrap();
        let (client_advert_map, _) = guard.deref_mut();
        let client = &mut client_advert_map.index_mut(ArtifactTag::from(id));
        let advert_tracker = client
            .advert_map
            .get(integrity_hash)
            .ok_or(DownloadPrioritizerError::NotFound)?;
        Ok(advert_tracker.clone())
    }

    fn get_advert_from_peer(
        &self,
        id: &ArtifactId,
        integrity_hash: &CryptoHash,
        peer_id: &NodeId,
    ) -> Result<Option<GossipAdvert>, DownloadPrioritizerError> {
        let guard = self.replica_map.read().unwrap();
        let (client_advert_map, _) = guard.deref();
        let client = client_advert_map.index(ArtifactTag::from(id));
        let advert_tracker = client
            .advert_map
            .get(integrity_hash)
            .ok_or(DownloadPrioritizerError::NotFound)?;

        let advert_tracker = advert_tracker.read().unwrap();
        if advert_tracker.has_peer(peer_id) {
            Ok(Some(advert_tracker.advert.clone()))
        } else {
            Ok(None)
        }
    }
}

/// Download Prioritizer Implementation
impl DownloadPrioritizerImpl {
    /// Updates peer queues by setting a new priority for an advert.
    fn peer_queues_update(
        &self,
        peer_map: &mut PeerAdvertMap,
        change: (AdvertTrackerRef, Priority, Priority),
    ) {
        let (advert_tracker_ref, old_priority, new_priority) = change;
        let advert_tracker = advert_tracker_ref.read().unwrap();
        advert_tracker.peers.iter().for_each(|peer_id| {
            if let Some(peer_advert_map) = peer_map.get_mut(peer_id) {
                let mut peer_advert_map = peer_advert_map.write().unwrap();
                peer_advert_map[old_priority].remove(&advert_tracker.advert.integrity_hash);
                self.metrics
                    .advert_queue_remove
                    .with_label_values(&[&peer_id.to_string(), &format!("{:?}", old_priority)])
                    .inc();
                self.metrics
                    .advert_queue_size
                    .with_label_values(&[&peer_id.to_string(), &format!("{:?}", old_priority)])
                    .dec();
                if new_priority != Priority::Drop {
                    peer_advert_map[new_priority].insert(
                        advert_tracker.advert.integrity_hash.clone(),
                        advert_tracker_ref.clone(),
                    );
                    self.metrics
                        .advert_queue_add
                        .with_label_values(&[&peer_id.to_string(), &format!("{:?}", new_priority)])
                        .inc();
                    self.metrics
                        .advert_queue_size
                        .with_label_values(&[&peer_id.to_string(), &format!("{:?}", new_priority)])
                        .inc();
                }
            }
        })
    }

    /// Constructor. Returns a new instance of DownloadPrioritizer.
    pub fn new(
        artifact_manager: &dyn ArtifactManager,
        metrics: DownloadPrioritizerMetrics,
    ) -> Self {
        let download_prioritizer = Self {
            metrics,
            replica_map: Default::default(),
        };
        {
            let mut guard = download_prioritizer.replica_map.write().unwrap();
            let (client_advert_map, _) = guard.deref_mut();

            for client in ArtifactTag::iter() {
                let client = &mut client_advert_map.index_mut(client);
                client.get_priority_fn = Arc::new(get_priority_fn_from_manager);
            }
        }
        // Get all the priority functions from the clients !!
        let _ = download_prioritizer.update_priority_functions(artifact_manager);
        download_prioritizer
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use ic_artifact_manager::manager::ArtifactManagerImpl;
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities::{
        metrics::fetch_histogram_stats, types::ids::node_test_id, FastForwardTimeSource,
    };
    use ic_types::crypto::CryptoHash;
    use std::time::Duration;

    /// Returns a priority for a given artifact based on its content.
    /// This function is used for tests where artifacts are expected to be of
    /// a certain type (`FileTreeSync`).
    fn priority_fn_dynamic(_id: &ArtifactId, attribute: &ArtifactAttribute) -> Priority {
        if let ArtifactAttribute::FileTreeSync(attr) = attribute {
            let attr = attr.parse::<i32>().unwrap();
            // Divvy up the 30 adverts in groups of 12, 9, 9
            // Equally distribute the 3 groups to 3 peers
            if attr > 17 {
                Priority::Fetch
            } else if attr > 8 {
                Priority::FetchNow
            } else {
                Priority::Later
            }
        } else {
            Priority::Drop
        }
    }

    /// Returns a boxed reference to the function `priority_fn_dynamic`
    fn get_priority_dynamic_fn(_: &dyn ArtifactManager, _: ArtifactTag) -> InternalPriorityFn {
        Arc::new(Box::new(priority_fn_dynamic))
    }

    /// Returns `Drop` priority
    fn priority_fn_drop_all(_: &ArtifactId, _: &ArtifactAttribute) -> Priority {
        Priority::Drop
    }

    /// Returns a boxed reference to the function that returns `Drop` priority
    fn get_priority_fn_drop_all(_: &dyn ArtifactManager, _: ArtifactTag) -> InternalPriorityFn {
        Arc::new(Box::new(priority_fn_drop_all))
    }

    /// Returns `Stash` priority
    fn priority_fn_stash_all(_: &ArtifactId, _: &ArtifactAttribute) -> Priority {
        Priority::Stash
    }

    /// Returns a boxed reference to the function that returns `Stash` priority
    fn get_priority_fn_stash_all(_: &dyn ArtifactManager, _: ArtifactTag) -> InternalPriorityFn {
        Arc::new(Box::new(priority_fn_stash_all))
    }

    /// Returns `Stash` priority after a short delay
    fn priority_fn_with_delay(_: &ArtifactId, _: &ArtifactAttribute) -> Priority {
        std::thread::sleep(Duration::from_millis(100));
        Priority::Stash
    }

    /// Returns a boxed reference to the function that returns a delayed `Stash`
    /// priority
    fn get_priority_fn_with_delay(_: &dyn ArtifactManager, _: ArtifactTag) -> InternalPriorityFn {
        Arc::new(Box::new(priority_fn_with_delay))
    }

    /// Returns `FetchNow` priority
    fn priority_fn_fetch_now_all(_: &ArtifactId, _: &ArtifactAttribute) -> Priority {
        Priority::FetchNow
    }

    /// Returns a boxed reference to the function that returns `FetchNow`
    /// priority
    fn get_priority_fn_fetch_now_all(
        _: &dyn ArtifactManager,
        _: ArtifactTag,
    ) -> InternalPriorityFn {
        Arc::new(Box::new(priority_fn_fetch_now_all))
    }

    /// Returns an advert with the given ID
    pub(crate) fn make_gossip_advert(id: u64) -> GossipAdvert {
        let artifact_id = id.to_string();
        GossipAdvert {
            artifact_id: ArtifactId::FileTreeSync(artifact_id.clone()),
            attribute: ArtifactAttribute::FileTreeSync(artifact_id),
            size: 0,
            // Integrity hash is not checked in the tests here
            integrity_hash: CryptoHash(vec![id as u8]),
        }
    }

    /// This test checks a sequence of operations on the prioritizer.
    /// It inserts adverts, then checks that they are prioritized as expected.
    /// Then, it removes all of them and verifies that they are indeed removed.
    #[test]
    fn basic_insert_delete_update() {
        let time_source = FastForwardTimeSource::new();
        let artifact_manager = ArtifactManagerImpl::new(time_source);
        let download_prioritizer: DownloadPrioritizerImpl = DownloadPrioritizerImpl::new(
            &artifact_manager,
            DownloadPrioritizerMetrics::new(&MetricsRegistry::new()),
        );

        // Insert
        for advert_id in 0..30 {
            let peer_id = node_test_id(advert_id % 3);
            let gossip_advert = make_gossip_advert(advert_id);
            println!("advert {} node{}", advert_id, peer_id);
            let _ = download_prioritizer.add_advert(gossip_advert, peer_id);
        }

        // Check for  correct prioritization
        for peer in 0..3 {
            let peer_advert_queues =
                download_prioritizer.get_peer_priority_queues(node_test_id(peer));
            let peer_advert_map = peer_advert_queues.peer_advert_map_ref.read().unwrap();
            assert_eq!(peer_advert_map[Priority::Fetch].keys().len(), 10);
            assert_eq!(peer_advert_map[Priority::FetchNow].keys().len(), 0);
            assert_eq!(peer_advert_map[Priority::Later].keys().len(), 0);
        }

        // drop all the adverts
        for advert_id in 0..30 {
            let id = ArtifactId::FileTreeSync(advert_id.to_string());
            let ret = download_prioritizer.delete_advert(
                &id,
                &CryptoHash(vec![advert_id as u8]),
                AdvertTrackerFinalAction::Success,
            );
            assert!(ret.is_ok());
        }

        // Check for correct prioritization
        for peer in 0..3 {
            let peer_advert_queues =
                download_prioritizer.get_peer_priority_queues(node_test_id(peer));
            let peer_advert_map = peer_advert_queues.peer_advert_map_ref.read().unwrap();
            assert_eq!(peer_advert_map[Priority::Fetch].keys().len(), 0);
            assert_eq!(peer_advert_map[Priority::FetchNow].keys().len(), 0);
            assert_eq!(peer_advert_map[Priority::Later].keys().len(), 0);
        }

        // Flake drops
        // Check that dropped adverts are not found
        for advert_id in 0..30 {
            let id = ArtifactId::FileTreeSync(advert_id.to_string());
            let ret = download_prioritizer.delete_advert(
                &id,
                &CryptoHash(vec![advert_id as u8]),
                AdvertTrackerFinalAction::Abort,
            );
            assert_eq!(ret, Err(DownloadPrioritizerError::NotFound));
        }

        for advert_id in 0..30 {
            let id = ArtifactId::FileTreeSync(advert_id.to_string());
            let ret = download_prioritizer.delete_advert(
                &id,
                &CryptoHash(vec![advert_id as u8]),
                AdvertTrackerFinalAction::Failed,
            );
            assert_eq!(ret, Err(DownloadPrioritizerError::NotFound));
        }
    }

    /// A test to verify reported metrics
    #[test]
    fn validate_timing_metric() {
        let time_source = FastForwardTimeSource::new();
        let artifact_manager = ArtifactManagerImpl::new(time_source);
        let metrics_registry = MetricsRegistry::new();
        let download_prioritizer: DownloadPrioritizerImpl = DownloadPrioritizerImpl::new(
            &artifact_manager,
            DownloadPrioritizerMetrics::new(&metrics_registry),
        );

        // Insert
        for advert_id in 0..10 {
            let peer_id = node_test_id(advert_id % 3);
            let gossip_advert = make_gossip_advert(advert_id);
            let _ = download_prioritizer.add_advert(gossip_advert, peer_id);
        }
        {
            // update to new priority function
            let mut guard = download_prioritizer.replica_map.write().unwrap();
            let (client_advert_map, _peer_map) = guard.deref_mut();
            for client in ArtifactTag::iter() {
                let client = &mut client_advert_map.index_mut(client);
                client.get_priority_fn = Arc::new(get_priority_fn_with_delay);
            }
        }
        let dropped_artifacts = download_prioritizer.update_priority_functions(&artifact_manager);
        assert_eq!(dropped_artifacts.len(), 0);
        let timer_metric = fetch_histogram_stats(&metrics_registry, "priority_fn_time").unwrap();
        println!("{:?}", timer_metric);
        assert!(timer_metric.count > 0)
    }

    /// This test checks the correctness of the process of updating the priority
    /// function
    #[test]
    fn update_priority_queues() {
        let time_source = FastForwardTimeSource::new();
        let artifact_manager = ArtifactManagerImpl::new(time_source);
        let download_prioritizer: DownloadPrioritizerImpl = DownloadPrioritizerImpl::new(
            &artifact_manager,
            DownloadPrioritizerMetrics::new(&MetricsRegistry::new()),
        );

        // Insert
        for advert_id in 0..30 {
            let peer_id = node_test_id(advert_id % 3);
            let gossip_advert = make_gossip_advert(advert_id);
            let _ = download_prioritizer.add_advert(gossip_advert, peer_id);
        }

        // Check for correct prioritization
        for peer in 0..3 {
            let peer_advert_queues =
                download_prioritizer.get_peer_priority_queues(node_test_id(peer));
            let peer_advert_map = peer_advert_queues.peer_advert_map_ref.read().unwrap();
            assert_eq!(peer_advert_map[Priority::Fetch].keys().len(), 10);
            assert_eq!(peer_advert_map[Priority::FetchNow].keys().len(), 0);
            assert_eq!(peer_advert_map[Priority::Later].keys().len(), 0);
        }

        {
            // update to new priority function
            let mut guard = download_prioritizer.replica_map.write().unwrap();
            let (client_advert_map, _peer_map) = guard.deref_mut();
            for client in ArtifactTag::iter() {
                let client = &mut client_advert_map.index_mut(client);
                client.get_priority_fn = Arc::new(get_priority_dynamic_fn);
            }
        }
        let dropped_artifacts = download_prioritizer.update_priority_functions(&artifact_manager);
        assert_eq!(dropped_artifacts.len(), 0);
        // Check for correct prioritization
        for peer in 0..3 {
            let peer_advert_queues =
                download_prioritizer.get_peer_priority_queues(node_test_id(peer));
            let peer_advert_map = peer_advert_queues.peer_advert_map_ref.read().unwrap();
            assert_eq!(peer_advert_map[Priority::Fetch].keys().len(), 4);
            assert_eq!(peer_advert_map[Priority::FetchNow].keys().len(), 3);
            assert_eq!(peer_advert_map[Priority::Later].keys().len(), 3);
        }

        let mut count: u32 = 0;
        let peer_advert_queues = download_prioritizer.get_peer_priority_queues(node_test_id(0));
        let peer_advert_map = peer_advert_queues.peer_advert_map_ref.read().unwrap();
        for (_, _v) in peer_advert_map.iter() {
            count += 1;
        }
        assert_eq!(count, 10);

        // Check if iter is not consuming the adverts
        count = 0;
        for (_, _v) in peer_advert_map.iter() {
            count += 1;
        }
        assert_eq!(count, 10);
    }

    /// This test checks the behavior of the prioritizer when the priority
    /// function sets the priority of all adverts to `Drop`
    #[test]
    fn drop_all() {
        let time_source = FastForwardTimeSource::new();
        let artifact_manager = ArtifactManagerImpl::new(time_source);
        let download_prioritizer: DownloadPrioritizerImpl = DownloadPrioritizerImpl::new(
            &artifact_manager,
            DownloadPrioritizerMetrics::new(&MetricsRegistry::new()),
        );
        // Insert
        for advert_id in 0..30 {
            let peer_id = node_test_id(advert_id % 3);
            let gossip_advert = make_gossip_advert(advert_id);
            let _ = download_prioritizer.add_advert(gossip_advert, peer_id);
        }

        {
            // update to new new priority function
            let mut guard = download_prioritizer.replica_map.write().unwrap();
            let (client_advert_map, _peer_map) = guard.deref_mut();
            for client in ArtifactTag::iter() {
                let client = &mut client_advert_map.index_mut(client);
                client.get_priority_fn = Arc::new(get_priority_fn_drop_all);
            }
        }
        let dropped_artifacts = download_prioritizer.update_priority_functions(&artifact_manager);
        assert_eq!(dropped_artifacts.len(), 30);
        // Check for correct prioritization
        for peer in 0..3 {
            let peer_advert_queues =
                download_prioritizer.get_peer_priority_queues(node_test_id(peer));
            let peer_advert_map = peer_advert_queues.peer_advert_map_ref.read().unwrap();
            assert_eq!(peer_advert_map[Priority::Fetch].keys().len(), 0);
            assert_eq!(peer_advert_map[Priority::FetchNow].keys().len(), 0);
            assert_eq!(peer_advert_map[Priority::Later].keys().len(), 0);
        }

        let mut guard = download_prioritizer.replica_map.write().unwrap();
        let (client_advert_map, _peer_map) = guard.deref_mut();
        for client_idx in ArtifactTag::iter() {
            assert!(client_advert_map[client_idx].advert_map.keys().len() == 0);
        }
    }

    /// Translates a priority value to a numeric value
    fn priority_to_num(p: Priority) -> i32 {
        match p {
            Priority::Stash => -1,
            Priority::Drop => 0,
            Priority::FetchNow => 1,
            Priority::Fetch => 2,
            Priority::Later => 3,
        }
    }

    /// Adds adverts
    fn add_adverts(
        download_prioritizer: &DownloadPrioritizerImpl,
        num_adverts: u64,
        num_nodes: u64,
    ) {
        // Insert
        for advert_id in 0..num_adverts {
            let peer_id = node_test_id(advert_id % num_nodes);
            let gossip_advert = make_gossip_advert(advert_id);
            let _ = download_prioritizer.add_advert(gossip_advert, peer_id);
        }
    }

    /// This test checks the behavior of the prioritizer with a dynamic priority
    /// function
    #[test]
    fn priority_test() {
        let time_source = FastForwardTimeSource::new();
        let artifact_manager = ArtifactManagerImpl::new(time_source);
        let download_prioritizer: DownloadPrioritizerImpl = DownloadPrioritizerImpl::new(
            &artifact_manager,
            DownloadPrioritizerMetrics::new(&MetricsRegistry::new()),
        );

        // Insert
        add_adverts(&download_prioritizer, 30, 3);

        // updates
        {
            // update to new priority function
            let mut guard = download_prioritizer.replica_map.write().unwrap();
            let (client_advert_map, _peer_map) = guard.deref_mut();
            for client in ArtifactTag::iter() {
                let client = &mut client_advert_map.index_mut(client);
                client.get_priority_fn = Arc::new(get_priority_dynamic_fn);
            }
        }
        let dropped_artifacts = download_prioritizer.update_priority_functions(&artifact_manager);
        assert_eq!(dropped_artifacts.len(), 0);
        // correct prioritization
        let mut last_prio = priority_to_num(Priority::Stash);
        for peer in 0..3 {
            last_prio = priority_to_num(Priority::Stash);

            let peer_advert_queues =
                download_prioritizer.get_peer_priority_queues(node_test_id(peer));
            let peer_advert_map = peer_advert_queues.peer_advert_map_ref.read().unwrap();
            for (_, advert_tracker) in peer_advert_map.iter() {
                let mut advert_tracker = advert_tracker.write().unwrap();
                let advert_tracker = advert_tracker.deref_mut();
                println!("{:?}", advert_tracker.priority);
                assert!(advert_tracker.priority != Priority::Stash);
                assert!(advert_tracker.priority != Priority::Drop);
                let this_prio = priority_to_num(advert_tracker.priority);
                assert!(this_prio >= last_prio);
                last_prio = this_prio;
            }
        }
        assert!(last_prio == priority_to_num(Priority::Later));
    }

    /// Tests various behaviors
    #[test]
    fn crud_test() {
        let time_source = FastForwardTimeSource::new();
        let artifact_manager = ArtifactManagerImpl::new(time_source);
        let download_prioritizer: DownloadPrioritizerImpl = DownloadPrioritizerImpl::new(
            &artifact_manager,
            DownloadPrioritizerMetrics::new(&MetricsRegistry::new()),
        );

        // Insert
        for advert_id in 0..30 {
            let peer_id = node_test_id(advert_id % 3);
            let gossip_advert = make_gossip_advert(advert_id);
            let _ = download_prioritizer.add_advert(gossip_advert, peer_id);
        }

        // updates
        {
            // update to new priority function
            let mut guard = download_prioritizer.replica_map.write().unwrap();
            let (client_advert_map, _peer_map) = guard.deref_mut();
            for client in ArtifactTag::iter() {
                let client = &mut client_advert_map.index_mut(client);
                client.get_priority_fn = Arc::new(get_priority_dynamic_fn);
            }
        }
        let dropped_artifacts = download_prioritizer.update_priority_functions(&artifact_manager);
        assert_eq!(dropped_artifacts.len(), 0);
        let mut peer_adverts = std::vec::Vec::new();
        for peer in 0..3 {
            let peer_advert_queues =
                download_prioritizer.get_peer_priority_queues(node_test_id(peer));
            let peer_advert_map = peer_advert_queues.peer_advert_map_ref.read().unwrap();
            let mut fetch_count = 0;
            let mut fetchnow_count = 0;
            let mut later_count = 0;
            for (_, advert_tracker) in peer_advert_map.iter() {
                let mut advert_tracker = advert_tracker.write().unwrap();
                let advert_tracker = advert_tracker.deref_mut();
                match advert_tracker.priority {
                    Priority::Fetch => fetch_count += 1,
                    Priority::FetchNow => fetchnow_count += 1,
                    Priority::Later => later_count += 1,
                    unexpected_priority => panic!("unexpected priority: {:?}", unexpected_priority),
                }
                let advert = &advert_tracker.advert;
                peer_adverts.push((
                    peer,
                    advert.artifact_id.clone(),
                    advert.integrity_hash.clone(),
                ));
            }
            assert_eq!(fetch_count, 4);
            assert_eq!(fetchnow_count, 3);
            assert_eq!(later_count, 3);
        }

        // deletes
        peer_adverts.iter().for_each(|(p, i, hash)| {
            let ret = download_prioritizer.delete_advert_from_peer(
                i,
                hash,
                node_test_id(*p),
                AdvertTrackerFinalAction::Abort,
            );
            assert!(ret.is_ok());
        });
        for peer in 0..3 {
            let peer_advert_queues =
                download_prioritizer.get_peer_priority_queues(node_test_id(peer));
            let peer_advert_map = peer_advert_queues.peer_advert_map_ref.read().unwrap();
            assert_eq!(peer_advert_map.iter().count(), 0);
        }

        let mut guard = download_prioritizer.replica_map.write().unwrap();
        let (client_advert_map, _peer_map) = guard.deref_mut();
        for client_idx in ArtifactTag::iter() {
            let client = &mut client_advert_map.index_mut(client_idx);
            assert_eq!(client.advert_map.len(), 0);
        }
    }

    /// Tests the `clear_peer_adverts` method of the prioritizer
    #[test]
    fn clear_peer_adverts() {
        let time_source = FastForwardTimeSource::new();
        let artifact_manager = ArtifactManagerImpl::new(time_source);
        let download_prioritizer: DownloadPrioritizerImpl = DownloadPrioritizerImpl::new(
            &artifact_manager,
            DownloadPrioritizerMetrics::new(&MetricsRegistry::new()),
        );

        // Insert
        for advert_id in 0..20 {
            let peer_id = node_test_id(advert_id % 2);
            let gossip_advert = make_gossip_advert(advert_id);
            let _ = download_prioritizer.add_advert(gossip_advert, peer_id);
        }

        for node in 0..2 {
            let peer_advert_queues =
                download_prioritizer.get_peer_priority_queues(node_test_id(node));
            let peer_advert_map = peer_advert_queues.peer_advert_map_ref.read().unwrap();
            assert_eq!(peer_advert_map.iter().count(), 10);
        }

        for node in 0..2 {
            assert_eq!(
                download_prioritizer
                    .clear_peer_adverts(node_test_id(node), AdvertTrackerFinalAction::Abort),
                Ok(())
            );
        }

        for node in 0..2 {
            let peer_advert_queues =
                download_prioritizer.get_peer_priority_queues(node_test_id(node));
            let peer_advert_map = peer_advert_queues.peer_advert_map_ref.read().unwrap();
            assert_eq!(peer_advert_map.iter().count(), 0);
        }
    }

    /// Tests the behavior of the prioritizer when all adverts are stashed
    #[test]
    fn stash_advert() {
        let time_source = FastForwardTimeSource::new();
        let artifact_manager = ArtifactManagerImpl::new(time_source);
        let download_prioritizer: DownloadPrioritizerImpl = DownloadPrioritizerImpl::new(
            &artifact_manager,
            DownloadPrioritizerMetrics::new(&MetricsRegistry::new()),
        );

        {
            // stash all
            let mut guard = download_prioritizer.replica_map.write().unwrap();
            let (client_advert_map, _peer_map) = guard.deref_mut();
            for client in ArtifactTag::iter() {
                let client = &mut client_advert_map.index_mut(client);
                client.get_priority_fn = Arc::new(get_priority_fn_stash_all);
            }
        }

        // Insert
        for advert_id in 0..30 {
            let peer_id = node_test_id(advert_id % 3);
            let gossip_advert = make_gossip_advert(advert_id);
            println!("advert {} node{}", advert_id, peer_id);
            let _ = download_prioritizer.add_advert(gossip_advert, peer_id);
        }

        let dropped_artifacts = download_prioritizer.update_priority_functions(&artifact_manager);
        assert_eq!(dropped_artifacts.len(), 0);
        // Check for  correct prioritization
        for peer in 0..3 {
            let peer_advert_queues =
                download_prioritizer.get_peer_priority_queues(node_test_id(peer));
            let peer_advert_map = peer_advert_queues.peer_advert_map_ref.read().unwrap();
            assert_eq!(peer_advert_map[Priority::Fetch].keys().len(), 0);
            assert_eq!(peer_advert_map[Priority::FetchNow].keys().len(), 0);
            assert_eq!(peer_advert_map[Priority::Later].keys().len(), 0);
            assert_eq!(peer_advert_map[Priority::Stash].keys().len(), 10);
        }

        {
            // fetch now all
            let mut guard = download_prioritizer.replica_map.write().unwrap();
            let (client_advert_map, _peer_map) = guard.deref_mut();
            for client in ArtifactTag::iter() {
                let client = &mut client_advert_map.index_mut(client);
                client.get_priority_fn = Arc::new(get_priority_fn_fetch_now_all);
            }
        }
        let dropped_artifacts = download_prioritizer.update_priority_functions(&artifact_manager);
        assert_eq!(dropped_artifacts.len(), 0);

        for peer in 0..3 {
            let peer_advert_queues =
                download_prioritizer.get_peer_priority_queues(node_test_id(peer));
            let peer_advert_map = peer_advert_queues.peer_advert_map_ref.read().unwrap();
            let mut fetchnow_count = 0;
            for (_, advert_tracker) in peer_advert_map.iter() {
                let mut advert_tracker = advert_tracker.write().unwrap();
                let advert_tracker = advert_tracker.deref_mut();
                match advert_tracker.priority {
                    Priority::FetchNow => fetchnow_count += 1,
                    unexpected_priority => panic!(
                        "unexpected priority: expected {:?}, got {:?}",
                        Priority::FetchNow,
                        unexpected_priority,
                    ),
                }
            }
            assert_eq!(fetchnow_count, 10);
        }
    }

    /// Tests the `peek_priority` method
    #[test]
    fn peek_advert() {
        let time_source = FastForwardTimeSource::new();
        let artifact_manager = ArtifactManagerImpl::new(time_source);
        let download_prioritizer: DownloadPrioritizerImpl = DownloadPrioritizerImpl::new(
            &artifact_manager,
            DownloadPrioritizerMetrics::new(&MetricsRegistry::new()),
        );

        {
            // stash all
            let mut guard = download_prioritizer.replica_map.write().unwrap();
            let (client_advert_map, _peer_map) = guard.deref_mut();
            for client in ArtifactTag::iter() {
                let client = &mut client_advert_map.index_mut(client);
                client.get_priority_fn = Arc::new(get_priority_fn_drop_all);
            }
        }
        let dropped_artifacts = download_prioritizer.update_priority_functions(&artifact_manager);
        assert_eq!(dropped_artifacts.len(), 0);

        // Insert
        for advert_id in 0..30 {
            let gossip_advert = make_gossip_advert(advert_id);
            assert_eq!(
                download_prioritizer.peek_priority(&gossip_advert).unwrap(),
                Priority::Drop
            );
        }
    }

    /// Add the same advert from multiple peers
    fn test_add_unique_adverts(
        download_prioritizer: &DownloadPrioritizerImpl,
        advert_id: u32,
        num_peers: u64,
    ) {
        // Insert
        for peer_id in 0..num_peers {
            download_prioritizer
                .add_advert(
                    GossipAdvert {
                        artifact_id: ArtifactId::FileTreeSync(advert_id.to_string()),
                        attribute: ArtifactAttribute::FileTreeSync(advert_id.to_string()),
                        size: 0,
                        integrity_hash: CryptoHash(vec![]),
                    },
                    node_test_id(peer_id),
                )
                .unwrap()
        }
    }

    /// Test download attempt tracking functionality. Advertise the same
    /// artifact from 2 node and test if the both participate in the
    /// download attempt round. After the attempt is complete checks if the
    /// download attempt round is reset.
    #[test]
    fn download_attempt_basic() {
        let time_source = FastForwardTimeSource::new();
        let artifact_manager = ArtifactManagerImpl::new(time_source);
        let download_prioritizer: DownloadPrioritizerImpl = DownloadPrioritizerImpl::new(
            &artifact_manager,
            DownloadPrioritizerMetrics::new(&MetricsRegistry::new()),
        );

        let chunk_id0 = ChunkId::from(0);
        // insert
        test_add_unique_adverts(&download_prioritizer, 0, 3);

        // check if peers attempted is false
        let mut node_count = 0;
        for peer in 0..3 {
            let peer_advert_queues =
                download_prioritizer.get_peer_priority_queues(node_test_id(peer));
            let peer_advert_map = peer_advert_queues.peer_advert_map_ref.read().unwrap();
            for (_, advert_tracker) in peer_advert_map.iter() {
                let advert_tracker = advert_tracker.read().unwrap();
                assert!(!advert_tracker.peer_attempted(chunk_id0, &node_test_id(peer)));
                node_count += 1;
            }
        }
        assert_eq!(node_count, 3);

        // record attempts for 2 peers
        let mut node_count = 0;
        for peer in 0..2 {
            let peer_advert_queues =
                download_prioritizer.get_peer_priority_queues(node_test_id(peer));
            let peer_advert_map = peer_advert_queues.peer_advert_map_ref.read().unwrap();
            for (_, advert_tracker) in peer_advert_map.iter() {
                let mut advert_tracker = advert_tracker.write().unwrap();
                advert_tracker.record_attempt(chunk_id0, &node_test_id(peer));
                assert!(advert_tracker.peer_attempted(chunk_id0, &node_test_id(peer)));
                node_count += 1;
            }
        }
        assert_eq!(node_count, 2);

        node_count = 0;
        let peer_advert_queues = download_prioritizer.get_peer_priority_queues(node_test_id(2));
        let peer_advert_map = peer_advert_queues.peer_advert_map_ref.read().unwrap();
        for (_, advert_tracker) in peer_advert_map.iter() {
            let mut advert_tracker = advert_tracker.write().unwrap();
            assert!(!advert_tracker.peer_attempted(chunk_id0, &node_test_id(2)));
            advert_tracker.record_attempt(chunk_id0, &node_test_id(2));
            assert!(advert_tracker.peer_attempted(chunk_id0, &node_test_id(2)));
            node_count += 1;
            // check is attempts are saturated
            assert!(advert_tracker.is_attempts_round_complete(chunk_id0));
            advert_tracker.attempts_round_reset(chunk_id0);
        }
        assert_eq!(node_count, 1);

        // check if peers attempted is false
        let mut node_count = 0;
        for peer in 0..3 {
            let peer_advert_queues =
                download_prioritizer.get_peer_priority_queues(node_test_id(peer));
            let peer_advert_map = peer_advert_queues.peer_advert_map_ref.read().unwrap();
            for (_, advert_tracker) in peer_advert_map.iter() {
                let advert_tracker = advert_tracker.read().unwrap();
                assert!(!advert_tracker.peer_attempted(chunk_id0, &node_test_id(peer)));
                node_count += 1;
            }
        }
        assert_eq!(node_count, 3);
    }

    /// Test the set/unset of the `in_progress` flag in the advert tracker
    #[test]
    fn download_in_progress_set_reset() {
        let time_source = FastForwardTimeSource::new();
        let artifact_manager = ArtifactManagerImpl::new(time_source);
        let download_prioritizer: DownloadPrioritizerImpl = DownloadPrioritizerImpl::new(
            &artifact_manager,
            DownloadPrioritizerMetrics::new(&MetricsRegistry::new()),
        );
        let chunk_id0 = ChunkId::from(0);
        // insert
        test_add_unique_adverts(&download_prioritizer, 0, 3);
        let _ = download_prioritizer
            .get_advert_tracker(
                &ArtifactId::FileTreeSync(0.to_string()),
                &CryptoHash(vec![]),
            )
            .map(|t| {
                let mut tracker = t.write().unwrap();
                tracker.unset_in_progress(chunk_id0);
                assert!(!tracker.is_in_progress(chunk_id0));
                tracker.set_in_progress(chunk_id0, &node_test_id(0));
                assert!(tracker.is_in_progress(chunk_id0));
            });
    }
}
