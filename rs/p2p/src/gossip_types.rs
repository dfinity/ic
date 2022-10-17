use crate::{P2PError, P2PErrorCode, P2PResult};
use bincode::{deserialize, serialize};
use ic_interfaces_transport::TransportChannelId;
use ic_protobuf::p2p::v1 as pb;
use ic_protobuf::p2p::v1::gossip_chunk::Response;
use ic_protobuf::p2p::v1::gossip_message::Body;
use ic_protobuf::proxy::{try_from_option_field, ProxyDecodeError, ProxyDecodeError::*};
use ic_types::{
    artifact::{ArtifactFilter, ArtifactId},
    chunkable::{ArtifactChunk, ChunkId},
    crypto::CryptoHash,
    p2p::GossipAdvert,
};
use std::convert::{TryFrom, TryInto};

/// A request for an artifact sent to the peer.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct GossipChunkRequest {
    /// The artifact ID.
    pub(crate) artifact_id: ArtifactId,
    /// The integrity hash
    pub(crate) integrity_hash: CryptoHash,
    /// The chunk ID.
    pub(crate) chunk_id: ChunkId,
}

/// A re-transmission request. A filter is used to restrict the set of
/// adverts that are to be returned as a response to this request.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct GossipRetransmissionRequest {
    /// The artifact filter used to restrict the set of returned adverts.
    pub(crate) filter: ArtifactFilter,
}

/// A *Gossip* chunk, identified by its artifact ID and chunk ID.
/// It contains the actual chunk data in an artifact chunk.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct GossipChunk {
    /// The artifact ID.
    pub(crate) artifact_id: ArtifactId,
    /// The integrity hash.
    pub(crate) integrity_hash: CryptoHash,
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

/// A *Gossip* message can be converted into a
/// `TransportChannelId`.
impl From<&GossipMessage> for TransportChannelId {
    /// The method returns the flow tag corresponding to the gossip message.
    ///
    /// Currently, the flow tag is always 0.
    fn from(_: &GossipMessage) -> Self {
        TransportChannelId::from(0)
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
                Response::Chunk(c) => {
                    let artifact_chunk: ArtifactChunk = c.try_into()?;
                    Ok(ArtifactChunk {
                        chunk_id,
                        witness: artifact_chunk.witness,
                        artifact_chunk_data: artifact_chunk.artifact_chunk_data,
                    })
                }
                Response::Error(_e) => Err(P2PError {
                    p2p_error_code: P2PErrorCode::NotFound,
                }),
            },
            integrity_hash: deserialize(&gossip_chunk.integrity_hash)?,
        })
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
