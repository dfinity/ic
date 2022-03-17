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
    download_management::{DownloadManager, DownloadManagerImpl},
    metrics::GossipMetrics,
    use_gossip_malicious_behavior_on_chunk_request,
    utils::FlowMapper,
    P2PError, P2PErrorCode, P2PResult,
};
use ic_artifact_manager::artifact::IngressArtifact;
use ic_interfaces::artifact_manager::ArtifactManager;
use ic_interfaces::registry::RegistryClient;
use ic_interfaces::transport::Transport;
use ic_logger::{info, replica_logger::ReplicaLogger, warn};
use ic_metrics::MetricsRegistry;
use ic_protobuf::p2p::v1 as pb;
use ic_protobuf::p2p::v1::gossip_chunk::Response;
use ic_protobuf::p2p::v1::gossip_message::Body;
use ic_protobuf::proxy::{try_from_option_field, ProxyDecodeError, ProxyDecodeError::*};
use ic_types::{
    artifact::{Artifact, ArtifactFilter, ArtifactId, ArtifactKind},
    canonical_error::{unavailable_error, CanonicalError},
    chunkable::{ArtifactChunk, ArtifactChunkData, ChunkId},
    crypto::CryptoHash,
    malicious_flags::MaliciousFlags,
    messages::SignedIngress,
    p2p::GossipAdvert,
    transport::{FlowTag, TransportError, TransportNotification, TransportStateChange},
    NodeId, SubnetId,
};

use bincode::{deserialize, serialize};
use ic_interfaces::consensus_pool::ConsensusPoolCache;
use phantom_newtype::AmountOf;
use std::convert::{TryFrom, TryInto};
use std::sync::Arc;

/// The main *Gossip* trait, specifying the P2P gossip functionality.
pub trait Gossip {
    /// The *Gossip* advert type.
    type GossipAdvert;
    /// The *Gossip* chunk request type.
    type GossipChunkRequest;
    /// The *Gossip* chunk type.
    type GossipChunk;
    /// The node ID type.
    type NodeId;
    /// The *Transport* notification type.
    type TransportNotification;
    /// The ingress message type.
    type Ingress;

    /// The method handles the given advert received from the peer
    /// with the given node ID.
    fn on_advert(&self, gossip_advert: Self::GossipAdvert, peer_id: Self::NodeId);

    /// The method handles the given chunk request received from the
    /// peer with the given node ID.
    fn on_chunk_request(&self, gossip_request: GossipChunkRequest, node_id: NodeId);

    /// The method adds the given chunk to the corresponding artifact
    /// under construction.
    ///
    /// Once the download is complete, the artifact is handed over to
    /// the artifact manager.
    fn on_chunk(&self, gossip_chunk: Self::GossipChunk, peer_id: Self::NodeId);

    /// The method handles the received user ingress message.
    fn on_user_ingress(
        &self,
        ingress: Self::Ingress,
        peer_id: Self::NodeId,
    ) -> Result<(), CanonicalError>;

    /// The method broadcasts the given advert to other peers.
    fn broadcast_advert(&self, advert_request: GossipAdvertSendRequest);

    /// The method reacts to a retransmission request from another peer.
    fn on_retransmission_request(
        &self,
        gossip_request: GossipRetransmissionRequest,
        node_id: NodeId,
    );

    /// The method reacts to a *Transport* state change message due to
    /// a peer connecting or disconnecting.
    ///
    /// Missing disconnect events in case of dropped connections are
    /// detected and handled using request timeouts. Timeouts thus
    /// constitute the method for explicit detection of dropped
    /// connections.  P2P guarantees liveness relying on a) timeouts
    /// for each request and b) *Transport* having an additional error
    /// detection mechanism (not implemented yet).
    fn on_transport_state_change(&self, transport_state_change: TransportStateChange);

    /// The method reacts to a transport error message.
    fn on_transport_error(&self, transport_error: TransportError);

    /// The method is called periodically from a dedicated thread.
    fn on_timer(&self);
}

/// A request for an artifact sent to the peer.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GossipChunkRequest {
    /// The artifact ID.
    pub(crate) artifact_id: ArtifactId,
    /// The integrity hash
    pub integrity_hash: CryptoHash,
    /// The chunk ID.
    pub(crate) chunk_id: ChunkId,
}

/// A re-transmission request. A filter is used to restrict the set of
/// adverts that are to be returned as a response to this request.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GossipRetransmissionRequest {
    /// The artifact filter used to restrict the set of returned adverts.
    pub(crate) filter: ArtifactFilter,
}

/// A *Gossip* chunk, identified by its artifact ID and chunk ID.
/// It contains the actual chunk data in an artifact chunk.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GossipChunk {
    /// The artifact ID.
    pub(crate) artifact_id: ArtifactId,
    /// The integrity hash.
    pub integrity_hash: CryptoHash,
    /// The chunk ID.
    pub(crate) chunk_id: ChunkId,
    /// The artifact chunk, encapsulated in a `P2PResult`.
    pub(crate) artifact_chunk: P2PResult<ArtifactChunk>,
}

/// This is the message exchanged on the wire with other peers.  This
/// enum is private to the gossip layer because lower layers like
/// *Transport* do not need to interpret the content.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum GossipMessage {
    /// The advert variant.
    Advert(GossipAdvert),
    /// The chunk request variant.
    ChunkRequest(GossipChunkRequest),
    /// The chunk variant.
    Chunk(GossipChunk),
    /// The retransmission request variant.
    RetransmissionRequest(GossipRetransmissionRequest),
}

/// Request from artifact manager to send adverts for newly added validated
/// artifacts
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GossipAdvertSendRequest {
    /// The advert to be sent
    pub(crate) advert: GossipAdvert,

    /// How to distribute the advert
    pub(crate) action: GossipAdvertAction,
}

pub(crate) enum PercentageType {}
pub(crate) type Percentage = AmountOf<PercentageType, u32>;

/// Specifies how to distribute the adverts
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum GossipAdvertAction {
    /// Send to all peers
    SendToAllPeers,

    /// Send to a random subset of peers.
    /// The argument specifies the subset size, as percentage of subnet size
    SendToRandomSubset(Percentage),
}

/// A *Gossip* message can be converted into a
/// `FlowTag`.
impl From<&GossipMessage> for FlowTag {
    /// The method returns the flow tag corresponding to the gossip message.
    ///
    /// Currently, the flow tag is always 0.
    fn from(_: &GossipMessage) -> Self {
        FlowTag::from(0)
    }
}

/// The canonical implementation of the `GossipMessage` trait.
pub struct GossipImpl {
    /// The download manager used to initiate and track downloads.
    download_manager: DownloadManagerImpl,
    /// The artifact manager used to handle received artifacts.
    artifact_manager: Arc<dyn ArtifactManager>,
    /// The replica logger.
    log: ReplicaLogger,
    /// The *Gossip* metrics.
    metrics: GossipMetrics,
    /// Flags for malicious behavior used in testing.
    malicious_flags: MaliciousFlags,
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
        flow_tags: Vec<FlowTag>,
        log: ReplicaLogger,
        metrics_registry: &MetricsRegistry,
        malicious_flags: MaliciousFlags,
    ) -> Self {
        let download_manager = DownloadManagerImpl::new(
            node_id,
            subnet_id,
            consensus_pool_cache,
            registry_client.clone(),
            artifact_manager.clone(),
            transport.clone(),
            Arc::new(FlowMapper::new(flow_tags)),
            log.clone(),
            metrics_registry,
        );
        GossipImpl {
            malicious_flags,
            download_manager,
            artifact_manager,
            log,
            metrics: GossipMetrics::new(metrics_registry),
        }
    }

    /// The method returns the artifact chunk matching the given chunk request
    /// (if available).
    fn serve_chunk(&self, gossip_request: &GossipChunkRequest) -> P2PResult<ArtifactChunk> {
        self.artifact_manager
            .get_validated_by_identifier(&gossip_request.artifact_id)
            .ok_or_else(|| {
                self.metrics.chunk_req_not_found.inc();
                P2PError {
                    p2p_error_code: P2PErrorCode::NotFound,
                }
            })?
            .get_chunk(gossip_request.chunk_id)
            .ok_or_else(|| {
                self.metrics.chunk_req_not_found.inc();
                P2PError {
                    p2p_error_code: P2PErrorCode::NotFound,
                }
            })
    }

    /// The method reacts in a malicious way when receiving a chunk
    /// request from a certain peer.
    ///
    /// The malicious flags define the actual behavior, which may
    /// either drop the request, respond that the artifact could not
    /// be found, sending too many artifacts back, or sending invalid
    /// artifacts.
    fn malicious_behavior_on_chunk_request(&self, gossip_chunk: GossipChunk, node_id: NodeId) {
        if self.malicious_flags.maliciously_gossip_drop_requests {
            warn!(self.log, "Malicious behavior: dropping requests");
        } else if self.malicious_flags.maliciously_gossip_artifact_not_found {
            warn!(self.log, "Malicious behavior: artifact not found");
            let chunk_not_found = GossipChunk {
                artifact_id: gossip_chunk.artifact_id,
                integrity_hash: gossip_chunk.integrity_hash,
                chunk_id: gossip_chunk.chunk_id,
                artifact_chunk: Err(P2PError {
                    p2p_error_code: P2PErrorCode::NotFound,
                }),
            };
            self.download_manager
                .send_chunk_to_peer(chunk_not_found, node_id);
        } else if self.malicious_flags.maliciously_gossip_send_many_artifacts {
            warn!(self.log, "Malicious behavior: sending too many artifacts");
            for _n in 1..10000 {
                self.download_manager
                    .send_chunk_to_peer(gossip_chunk.clone(), node_id);
            }
        } else if self
            .malicious_flags
            .maliciously_gossip_send_invalid_artifacts
        {
            warn!(self.log, "Malicious behavior: sending invalid artifacts");
            let artifact_id = gossip_chunk.artifact_id;
            let integrity_hash = gossip_chunk.integrity_hash;
            let chunk_id = gossip_chunk.chunk_id;
            let artifact_chunk_data = ArtifactChunkData::SemiStructuredChunkData([].to_vec());
            let artifact_chunk = Ok(ArtifactChunk {
                chunk_id,
                witness: Default::default(),
                artifact_chunk_data,
            });
            let invalid_chunk = GossipChunk {
                artifact_id,
                integrity_hash,
                chunk_id,
                artifact_chunk,
            };
            self.download_manager
                .send_chunk_to_peer(invalid_chunk, node_id);
        } else {
            warn!(self.log, "Malicious behavior: This should never happen!");
        }
    }
}

/// Canonical Implementation for the *Gossip* trait.
impl Gossip for GossipImpl {
    type GossipAdvert = GossipAdvert;
    type GossipChunkRequest = GossipChunkRequest;
    type GossipChunk = GossipChunk;
    type NodeId = NodeId;
    type TransportNotification = TransportNotification;
    type Ingress = SignedIngress;

    /// The method is called when a new advert is received from the
    /// peer with the given node ID.
    ///
    /// Adverts for artifacts that have been downloaded before are
    /// dropped.  If the artifact is not available locally, the advert
    /// is added to this peer's advert list.
    fn on_advert(&self, gossip_advert: GossipAdvert, peer_id: NodeId) {
        if self
            .artifact_manager
            .has_artifact(&gossip_advert.artifact_id)
        {
            return;
        }

        // The download manager handles the received advert.
        self.download_manager.on_advert(gossip_advert, peer_id);
        // The next download is triggered for the given peer ID.
        let _ = self.download_manager.download_next(peer_id);
    }

    /// The method handles the given chunk request received from the peer with
    /// the given node ID.
    fn on_chunk_request(&self, gossip_request: GossipChunkRequest, node_id: NodeId) {
        let start = std::time::Instant::now();
        let artifact_chunk = self.serve_chunk(&gossip_request);
        self.metrics
            .op_duration
            .with_label_values(&["serve_chunk"])
            .observe(start.elapsed().as_millis() as f64);
        let gossip_chunk = GossipChunk {
            artifact_id: gossip_request.artifact_id.clone(),
            integrity_hash: gossip_request.integrity_hash.clone(),
            chunk_id: gossip_request.chunk_id,
            artifact_chunk,
        };
        use_gossip_malicious_behavior_on_chunk_request!(
            self,
            self.malicious_behavior_on_chunk_request(gossip_chunk, node_id),
            {
                self.download_manager
                    .send_chunk_to_peer(gossip_chunk, node_id);
            }
        );
    }

    /// The method adds the given chunk to the corresponding artifact
    /// under construction.
    fn on_chunk(&self, gossip_chunk: GossipChunk, peer_id: NodeId) {
        self.download_manager.on_chunk(gossip_chunk, peer_id);
        let _ = self.download_manager.download_next(peer_id);
    }

    /// The method handles the received user ingress message.
    fn on_user_ingress(
        &self,
        ingress: Self::Ingress,
        peer_id: Self::NodeId,
    ) -> Result<(), CanonicalError> {
        let advert = IngressArtifact::message_to_advert(&ingress);
        self.artifact_manager
            .on_artifact(
                Artifact::IngressMessage(ingress.into()),
                advert.into(),
                &peer_id,
            )
            .map_err(|e| {
                info!(self.log, "Artifact not inserted {:?}", e);
                unavailable_error("Service Unavailable!".to_string())
            })
    }

    /// The method broadcasts the given advert to other peers.
    fn broadcast_advert(&self, advert_request: GossipAdvertSendRequest) {
        self.download_manager.send_advert_to_peers(advert_request);
    }

    /// The method reacts to a retransmission request from another
    /// peer.
    ///
    /// All validated artifacts that pass the given filter are
    /// collected and sent to the peer.
    fn on_retransmission_request(
        &self,
        gossip_retransmission_request: GossipRetransmissionRequest,
        peer_id: NodeId,
    ) {
        let _ = self
            .download_manager
            .on_retransmission_request(&gossip_retransmission_request, peer_id);
    }

    /// The method reacts to a *Transport* state change message due to a peer
    /// connecting or disconnecting.
    fn on_transport_state_change(&self, transport_state_change: TransportStateChange) {
        warn!(
            self.log,
            "Transport state change: {:?}", transport_state_change
        );
        match transport_state_change {
            TransportStateChange::PeerFlowDown(info) => {
                self.download_manager.peer_connection_down(info.peer_id)
            }
            TransportStateChange::PeerFlowUp(info) => {
                self.download_manager.peer_connection_up(info.peer_id)
            }
        }
    }

    /// The method reacts to a *Transport* error message.
    fn on_transport_error(&self, _transport_error: TransportError) {
        // TODO: P2P-435 Re-instate call to
        //
        // download_manager
        //    .send_retransmission_request(flow.peer_id)
        //
        // when using multiple flows in Transport and when having the
        // new throttling mechanisms in download_management JIRA
        // Tickets:
        //
        // - Multiple flows: P2P-435
        // - Error handling: P2P-261
        //
        // We cannot send a retransmission request without having
        // multiple flows support as we have to be able to clear the
        // adverts queue (and only it) before responding to such a
        // request. Otherwise, we'll have to clear the entire queue to
        // that peer. This queue may contain a re-transmission
        // request. So we must send a re-transmission request before
        // the adverts (that are sent as a response to a
        // retransmission request from the other side).  This would
        // create an infinite loop of re-transmission requests. We
        // could throttle them (as we would anyway do even with
        // multiple flows support), but then we'll end up with
        // periodic retransmission and not event-based.
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
    fn on_timer(&self) {
        self.download_manager.on_timer();
    }
}

/// A *Gossip* message can be converted into a
/// `pb::GossipMessage`.
impl From<GossipMessage> for pb::GossipMessage {
    /// The function converts the given *Gossip* message into the Protobuf
    /// equivalent.
    fn from(message: GossipMessage) -> Self {
        match message {
            GossipMessage::Advert(a) => Self {
                body: Some(Body::Advert(a.into())),
            },
            GossipMessage::ChunkRequest(r) => Self {
                body: Some(Body::ChunkRequest(r.into())),
            },
            GossipMessage::Chunk(c) => Self {
                body: Some(Body::Chunk(c.into())),
            },
            GossipMessage::RetransmissionRequest(r) => Self {
                body: Some(Body::RetransmissionRequest(r.into())),
            },
        }
    }
}

/// A `pb::GossipMessage` can be converted into a *Gossip* message.
impl TryFrom<pb::GossipMessage> for GossipMessage {
    type Error = ProxyDecodeError;
    /// The function attempts to convert the given
    /// Protobuf gossip message into a *Gossip* message.
    fn try_from(message: pb::GossipMessage) -> Result<Self, Self::Error> {
        let body = message.body.ok_or(MissingField("GossipMessage::body"))?;
        let message = match body {
            Body::Advert(a) => Self::Advert(a.try_into()?),
            Body::ChunkRequest(r) => Self::ChunkRequest(r.try_into()?),
            Body::Chunk(c) => Self::Chunk(c.try_into()?),
            Body::RetransmissionRequest(r) => Self::RetransmissionRequest(r.try_into()?),
        };
        Ok(message)
    }
}

/// A chunk request can be converted into a `pb::GossipChunkRequest`.
impl From<GossipChunkRequest> for pb::GossipChunkRequest {
    /// The function converts the given chunk request into the Protobuf
    /// equivalent.
    fn from(gossip_chunk_request: GossipChunkRequest) -> Self {
        Self {
            artifact_id: serialize(&gossip_chunk_request.artifact_id)
                .expect("Local value serialization should succeed"),
            chunk_id: gossip_chunk_request.chunk_id.get(),
            integrity_hash: serialize(&gossip_chunk_request.integrity_hash)
                .expect("Local value serialization should succeed"),
        }
    }
}

/// A chunk request can be converted into a `pb::GossipChunkRequest`.
impl TryFrom<pb::GossipChunkRequest> for GossipChunkRequest {
    type Error = ProxyDecodeError;
    /// The function attempts to convert the given Protobuf chunk request into a
    /// GossipChunkRequest.
    fn try_from(gossip_chunk_request: pb::GossipChunkRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            artifact_id: deserialize(&gossip_chunk_request.artifact_id)?,
            chunk_id: ChunkId::from(gossip_chunk_request.chunk_id),
            integrity_hash: deserialize(&gossip_chunk_request.integrity_hash)?,
        })
    }
}

/// An artifact chunk can be converted into a `pb::GossipChunk`.
impl From<GossipChunk> for pb::GossipChunk {
    /// The function converts the given chunk into the Protobuf equivalent.
    fn from(gossip_chunk: GossipChunk) -> Self {
        let response = match gossip_chunk.artifact_chunk {
            Ok(artifact_chunk) => Some(Response::Chunk(artifact_chunk.into())),
            // Add additional cases as required.
            Err(_) => Some(Response::Error(pb::P2pError::NotFound as i32)),
        };
        Self {
            artifact_id: serialize(&gossip_chunk.artifact_id)
                .expect("Local value serialization should succeed"),
            chunk_id: gossip_chunk.chunk_id.get(),
            response,
            integrity_hash: serialize(&gossip_chunk.integrity_hash)
                .expect("Local value serialization should succeed"),
        }
    }
}

/// A `pb::GossipChunk` can be converted into an artifact chunk.
impl TryFrom<pb::GossipChunk> for GossipChunk {
    type Error = ProxyDecodeError;
    /// The function attempts to convert a Protobuf chunk into a GossipChunk.
    fn try_from(gossip_chunk: pb::GossipChunk) -> Result<Self, Self::Error> {
        let response = try_from_option_field(gossip_chunk.response, "GossipChunk.response")?;
        let chunk_id = ChunkId::from(gossip_chunk.chunk_id);
        Ok(Self {
            artifact_id: deserialize(&gossip_chunk.artifact_id)?,
            chunk_id,
            artifact_chunk: match response {
                Response::Chunk(c) => Ok(add_chunk_id(c.try_into()?, chunk_id)),
                Response::Error(_e) => Err(P2PError {
                    p2p_error_code: P2PErrorCode::NotFound,
                }),
            },
            integrity_hash: deserialize(&gossip_chunk.integrity_hash)?,
        })
    }
}

/// The function returns a new artifact chunk with the given chunk ID
/// and the same chunk data as the given artifact chunk.
fn add_chunk_id(artifact_chunk: ArtifactChunk, chunk_id: ChunkId) -> ArtifactChunk {
    ArtifactChunk {
        chunk_id,
        witness: artifact_chunk.witness,
        artifact_chunk_data: artifact_chunk.artifact_chunk_data,
    }
}

/// An re-transmission request can be converted into a
/// `pb::GossipRetransmissionRequest`.
impl From<GossipRetransmissionRequest> for pb::GossipRetransmissionRequest {
    /// The function converts a retransmission request into the Protobuf
    /// equivalent.
    fn from(gossip_request: GossipRetransmissionRequest) -> Self {
        Self {
            filter: Some(gossip_request.filter.into()),
        }
    }
}

/// A `pb::GossipRetransmissionRequest` can be converted into a
/// retransmission request.
impl TryFrom<pb::GossipRetransmissionRequest> for GossipRetransmissionRequest {
    type Error = ProxyDecodeError;
    /// The function attempts to convert a Protobuf retransmission request into
    /// a GossipRetransmissionRequest.
    fn try_from(
        gossip_retransmission_request: pb::GossipRetransmissionRequest,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            filter: try_from_option_field(
                gossip_retransmission_request.filter,
                "GossipRetransmissionRequest.filter",
            )?,
        })
    }
}
