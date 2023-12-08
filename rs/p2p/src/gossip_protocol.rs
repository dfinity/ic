//! <h1>Overview</h1>
//!
//! This module implements the *Gossip* broadcast of the Internet
//! computer (IC) as defined
//!
//! [here](../../../../../../docs/spec/replica/protocol/p2p/gossip/index.adoc).
//!
//! The *Gossip* protocol implements artifact pools with
//! eventual/bounded delivery guarantees for its clients. The P2P
//! layer treats the artifacts in these pools as binary blob
//! structures. The primary data structures are
//!
//! a) the peer context, which tracks the per-peer download activity.
//!
//! b) the global list of artifacts currently under construction
//! (i.e., being downloaded).
//!
//! Only artifacts under construction are owned by the P2P layer. Once
//! completed, these objects are handed over to the artifact manager,
//! which manages various application pools.

//! Overall, the protocol activity is controlled using the flow of
//!
//! a) adverts,
//!
//! b) requests, and
//!
//! c) artifact chunks.
//!
//! When serialized, the objects above should conform to the IC
//! on-wire protocol specification.  Internally, an implementation may
//! choose to have augmented structures that describe
//! implementation-specific details of the above on-wire concepts.
//!
//! <h1>Underlying Network Model</h1>
//!
//! The underlying network model provided by *Transport* is based on
//! the "fire and forget" principle. This means that adverts,
//! requests, chunks, artifacts, and other messages exchanged over
//! *Transport* have no delivery guarantees. With this transport
//! model, the P2P implementation has to be made idempotent such that
//! the repeated transmission of (identical) adverts, requests, or
//! chunks do not have any effect.  In other words, P2P guarantees "at
//! least once" delivery semantics for artifacts.

//! Artifact retention and transmission prioritization is left up to
//! client applications, i.e., applications are to retain objects
//! until they get side-band signals of objects being
//! fully/sufficiently gossiped. For example, *Consensus* purges
//! artifacts with a height lower than a specific height.  The state
//! manager only retains artifacts with heights not much lower than
//! the current height.

use crate::{
    artifact_download_list::ArtifactDownloadListImpl,
    download_prioritization::{DownloadPrioritizer, DownloadPrioritizerImpl},
    gossip_types::{GossipChunk, GossipChunkRequest, GossipMessage},
    metrics::{DownloadManagementMetrics, DownloadPrioritizerMetrics, GossipMetrics},
    peer_context::PeerContextMap,
    utils::TransportChannelIdMapper,
    P2PError, P2PErrorCode,
};
use ic_interfaces::consensus_pool::ConsensusPoolCache;
use ic_interfaces::p2p::artifact_manager::ArtifactManager;
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_transport::{Transport, TransportChannelId};
use ic_logger::{info, replica_logger::ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::subnet::v1::GossipConfig;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_types::{
    artifact::ArtifactFilter, chunkable::ArtifactChunk, chunkable::ArtifactChunkData,
    crypto::CryptoHash, p2p::GossipAdvert, NodeId, SubnetId,
};
use lru::LruCache;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::{sync::Arc, time::Instant};

/// The main *Gossip* trait, specifying the P2P gossip functionality.
pub trait Gossip {
    /// The *Gossip* advert type.
    type GossipAdvert;
    /// The *Gossip* chunk request type.
    type GossipChunkRequest;
    /// The *Gossip* chunk type.
    type GossipChunk;
    /// The *Gossip* retranmision request type.
    type GossipRetransmissionRequest;

    /// The method handles the given advert received from the peer
    /// with the given node ID.
    fn on_gossip_advert(&self, gossip_advert: Self::GossipAdvert, peer_id: NodeId);

    /// The method handles the given chunk request received from the
    /// peer with the given node ID.
    fn on_chunk_request(&self, gossip_request: Self::GossipChunkRequest, node_id: NodeId);

    /// The method adds the given chunk to the corresponding artifact
    /// under construction.
    ///
    /// Once the download is complete, the artifact is handed over to
    /// the artifact manager.DownloadPrioritizer
    fn on_gossip_chunk(&self, gossip_chunk: Self::GossipChunk, peer_id: NodeId);

    /// The method broadcasts the given advert to other peers.
    fn broadcast_advert(&self, advert_request: Self::GossipAdvert);

    /// The method reacts to a retransmission request from another peer.
    fn on_gossip_retransmission_request(
        &self,
        gossip_request: Self::GossipRetransmissionRequest,
        node_id: NodeId,
    );

    /// The following two methods react to a peer connecting or disconnecting.
    ///
    /// Missing disconnect events in case of dropped connections are
    /// detected and handled using request timeouts. Timeouts thus
    /// constitute the method for explicit detection of dropped
    /// connections.  P2P guarantees liveness relying on a) timeouts
    /// for each request and b) *Transport* having an additional error
    /// detection mechanism (not implemented yet).
    fn on_peer_up(&self, peer_id: NodeId);
    fn on_peer_down(&self, peer_id: NodeId);
    /// The method is called periodically from a dedicated thread.
    fn on_gossip_timer(&self);
}

/// The cache used to check if a certain artifact has been received recently.
pub(crate) type ReceiveCheckCache = LruCache<CryptoHash, ()>;

/// The canonical implementation of the `GossipMessage` trait.
pub(crate) struct GossipImpl {
    /// The artifact manager used to handle received artifacts.
    pub artifact_manager: Arc<dyn ArtifactManager>,
    /// The replica logger.
    pub log: ReplicaLogger,
    /// The *Gossip* metrics.
    pub gossip_metrics: GossipMetrics,

    /// The node ID of the peer.
    pub node_id: NodeId,
    /// The subnet ID.
    pub subnet_id: SubnetId,
    /// The registry client.
    pub registry_client: Arc<dyn RegistryClient>,
    /// The consensus pool cache.
    pub consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    /// The download prioritizer.
    pub prioritizer: Arc<dyn DownloadPrioritizer>,
    /// The peer manager.
    pub current_peers: Mutex<PeerContextMap>,
    /// The underlying *Transport* layer.
    pub transport: Arc<dyn Transport>,
    /// The flow mapper.
    pub transport_channel_mapper: TransportChannelIdMapper,
    /// The list of artifacts that is under construction.
    pub artifacts_under_construction: RwLock<ArtifactDownloadListImpl>,
    /// The download management metrics.
    pub metrics: DownloadManagementMetrics,
    /// The *Gossip* configuration.
    pub gossip_config: GossipConfig,
    /// The cache that is used to check if an artifact has been downloaded
    /// recently.
    pub receive_check_caches: RwLock<HashMap<NodeId, ReceiveCheckCache>>,
    /// The priority function invocation time.
    pub pfn_invocation_instant: Mutex<Instant>,
    /// The last registry refresh time.
    pub registry_refresh_instant: Mutex<Instant>,
    /// The last retransmission request time.
    pub retransmission_request_instant: Mutex<Instant>,
}

impl GossipImpl {
    /// The constructor creates a new *Gossip* component.
    ///
    /// The *Gossip* component interacts with the download manager
    /// component, which initiates and tracks downloads of artifacts
    /// from a peer group.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_id: NodeId,
        subnet_id: SubnetId,
        consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
        registry_client: Arc<dyn RegistryClient>,
        artifact_manager: Arc<dyn ArtifactManager>,
        transport: Arc<dyn Transport>,
        transport_channels: Vec<TransportChannelId>,
        log: ReplicaLogger,
        metrics_registry: &MetricsRegistry,
    ) -> Self {
        let prioritizer = Arc::new(DownloadPrioritizerImpl::new(
            artifact_manager.as_ref(),
            DownloadPrioritizerMetrics::new(metrics_registry),
        ));
        let gossip_config = fetch_gossip_config(registry_client.clone(), subnet_id);
        let gossip = GossipImpl {
            artifact_manager,
            log: log.clone(),
            gossip_metrics: GossipMetrics::new(metrics_registry),
            node_id,
            subnet_id,
            consensus_pool_cache,
            prioritizer,
            current_peers: Mutex::new(PeerContextMap::default()),
            registry_client,
            transport,
            transport_channel_mapper: TransportChannelIdMapper::new(transport_channels),
            artifacts_under_construction: RwLock::new(ArtifactDownloadListImpl::default()),
            metrics: DownloadManagementMetrics::new(metrics_registry),
            gossip_config,
            receive_check_caches: RwLock::new(HashMap::new()),
            pfn_invocation_instant: Mutex::new(Instant::now()),
            registry_refresh_instant: Mutex::new(Instant::now()),
            retransmission_request_instant: Mutex::new(Instant::now()),
        };
        gossip.refresh_topology();
        gossip
    }
}

/// Canonical Implementation for the *Gossip* trait.
impl Gossip for GossipImpl {
    type GossipAdvert = GossipAdvert;
    type GossipChunkRequest = GossipChunkRequest;
    type GossipChunk = GossipChunk;
    type GossipRetransmissionRequest = ArtifactFilter;

    /// The method is called when a new advert is received from the
    /// peer with the given node ID.
    ///
    /// Adverts for artifacts that have been downloaded before are
    /// dropped.  If the artifact is not available locally, the advert
    /// is added to this peer's advert list.
    fn on_gossip_advert(&self, gossip_advert: GossipAdvert, peer_id: NodeId) {
        let _timer = self
            .gossip_metrics
            .op_duration
            .with_label_values(&["in_advert"])
            .start_timer();
        if self
            .artifact_manager
            .has_artifact(&gossip_advert.artifact_id)
        {
            return;
        }

        // The download manager handles the received advert.
        self.on_advert(gossip_advert, peer_id);
        // The next download is triggered for the given peer ID.
        let _ = self.download_next(peer_id);
    }

    /// The method handles the given chunk request received from the peer with
    /// the given node ID.
    fn on_chunk_request(&self, chunk_request: GossipChunkRequest, node_id: NodeId) {
        let _timer = self
            .gossip_metrics
            .op_duration
            .with_label_values(&["in_chunk_request"])
            .start_timer();

        let artifact_chunk = match self
            .artifact_manager
            .get_validated_by_identifier(&chunk_request.artifact_id)
        {
            Some(artifact) => artifact
                .get_chunk(chunk_request.chunk_id)
                .map(|a| ArtifactChunk {
                    chunk_id: chunk_request.chunk_id,
                    artifact_chunk_data: ArtifactChunkData::UnitChunkData(a),
                })
                .ok_or_else(|| {
                    self.gossip_metrics.requested_chunks_not_found.inc();
                    P2PError {
                        p2p_error_code: P2PErrorCode::NotFound,
                    }
                }),
            None => {
                self.gossip_metrics.requested_chunks_not_found.inc();
                Err(P2PError {
                    p2p_error_code: P2PErrorCode::NotFound,
                })
            }
        };

        let gossip_chunk = GossipChunk {
            request: chunk_request,
            artifact_chunk,
        };
        let message = GossipMessage::Chunk(gossip_chunk);
        self.transport_send(message, node_id);
    }

    /// The method adds the given chunk to the corresponding artifact
    /// under construction.
    fn on_gossip_chunk(&self, gossip_chunk: GossipChunk, peer_id: NodeId) {
        let _timer = self
            .gossip_metrics
            .op_duration
            .with_label_values(&["in_chunk"])
            .start_timer();
        self.on_chunk(gossip_chunk, peer_id);
        let _ = self.download_next(peer_id);
    }

    /// The method broadcasts the given advert to other peers.
    fn broadcast_advert(&self, advert: GossipAdvert) {
        let _timer = self
            .gossip_metrics
            .op_duration
            .with_label_values(&["out_advert"])
            .start_timer();

        let (peers, label) = (self.get_current_peer_ids(), "all_peers");
        self.metrics
            .adverts_by_action
            .with_label_values(&[label])
            .inc_by(peers.len() as u64);

        let message = GossipMessage::Advert(advert);
        for peer_id in peers {
            self.transport_send(message.clone(), peer_id);
        }
    }

    /// The method reacts to a retransmission request from another
    /// peer.
    ///
    /// All validated artifacts that pass the given filter are
    /// collected and sent to the peer.
    fn on_gossip_retransmission_request(
        &self,
        gossip_retransmission_request: Self::GossipRetransmissionRequest,
        peer_id: NodeId,
    ) {
        let _timer = self
            .gossip_metrics
            .op_duration
            .with_label_values(&["out_retransmission"])
            .start_timer();
        let _ = self.on_retransmission_request(&gossip_retransmission_request, peer_id);
    }

    fn on_peer_up(&self, peer_id: NodeId) {
        let _timer = self
            .gossip_metrics
            .op_duration
            .with_label_values(&["peer_up"])
            .start_timer();
        info!(self.log, "Peer is up: {:?}", peer_id);
        self.peer_connection_up(peer_id)
    }

    fn on_peer_down(&self, peer_id: NodeId) {
        let _timer = self
            .gossip_metrics
            .op_duration
            .with_label_values(&["peer_down"])
            .start_timer();
        info!(self.log, "Peer is down: {:?}", peer_id);
        self.peer_connection_down(peer_id)
    }

    /// The method is called on a periodic timer event.
    ///
    /// The periodic invocation of this method guarantees IC liveness.
    /// Specifically, the following actions occur on each call:
    ///
    /// - It polls all artifact clients, enabling the IC to make
    /// progress without the need for any external triggers.
    ///
    /// - It checks each peer for request timeouts and advert download
    /// eligibility.
    ///
    /// In short, the method is a catch-all for a periodic and
    /// holistic refresh of IC state.
    fn on_gossip_timer(&self) {
        let _timer = self
            .gossip_metrics
            .op_duration
            .with_label_values(&["timer"])
            .start_timer();
        self.on_timer();
    }
}

/// Fetch the Gossip configuration from the registry.
fn fetch_gossip_config(
    registry_client: Arc<dyn RegistryClient>,
    subnet_id: SubnetId,
) -> GossipConfig {
    if let Ok(Some(Some(gossip_config))) =
        registry_client.get_gossip_config(subnet_id, registry_client.get_latest_version())
    {
        gossip_config
    } else {
        ic_types::p2p::build_default_gossip_config()
    }
}
