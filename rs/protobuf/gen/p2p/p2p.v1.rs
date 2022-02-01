#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GossipMessage {
    #[prost(oneof="gossip_message::Body", tags="1, 2, 3, 4")]
    pub body: ::core::option::Option<gossip_message::Body>,
}
/// Nested message and enum types in `GossipMessage`.
pub mod gossip_message {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Body {
        #[prost(message, tag="1")]
        Advert(super::GossipAdvert),
        #[prost(message, tag="2")]
        ChunkRequest(super::GossipChunkRequest),
        #[prost(message, tag="3")]
        Chunk(super::GossipChunk),
        #[prost(message, tag="4")]
        RetransmissionRequest(super::GossipRetransmissionRequest),
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GossipAdvert {
    #[prost(bytes="vec", tag="1")]
    pub attribute: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag="2")]
    pub size: u64,
    #[prost(bytes="vec", tag="3")]
    pub artifact_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="4")]
    pub integrity_hash: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GossipChunkRequest {
    #[prost(bytes="vec", tag="1")]
    pub artifact_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag="2")]
    pub chunk_id: u32,
    #[prost(bytes="vec", tag="3")]
    pub integrity_hash: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ArtifactFilter {
    #[prost(message, optional, tag="1")]
    pub consensus_filter: ::core::option::Option<ConsensusMessageFilter>,
    #[prost(message, optional, tag="2")]
    pub ingress_filter: ::core::option::Option<IngressMessageFilter>,
    #[prost(message, optional, tag="3")]
    pub certification_message_filter: ::core::option::Option<CertificationMessageFilter>,
    #[prost(message, optional, tag="4")]
    pub state_sync_filter: ::core::option::Option<StateSyncFilter>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsensusMessageFilter {
    #[prost(uint64, tag="1")]
    pub height: u64,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IngressMessageFilter {
    #[prost(uint64, tag="1")]
    pub time: u64,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CertificationMessageFilter {
    #[prost(uint64, tag="1")]
    pub height: u64,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StateSyncFilter {
    #[prost(uint64, tag="1")]
    pub height: u64,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GossipRetransmissionRequest {
    #[prost(message, optional, tag="1")]
    pub filter: ::core::option::Option<ArtifactFilter>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GossipChunk {
    #[prost(bytes="vec", tag="1")]
    pub artifact_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag="2")]
    pub chunk_id: u32,
    #[prost(bytes="vec", tag="5")]
    pub integrity_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(oneof="gossip_chunk::Response", tags="3, 4")]
    pub response: ::core::option::Option<gossip_chunk::Response>,
}
/// Nested message and enum types in `GossipChunk`.
pub mod gossip_chunk {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Response {
        #[prost(message, tag="3")]
        Chunk(super::ArtifactChunk),
        #[prost(enumeration="super::P2pError", tag="4")]
        Error(i32),
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ArtifactChunk {
    #[prost(bytes="vec", repeated, tag="1")]
    pub witnesses: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(oneof="artifact_chunk::Data", tags="2, 3")]
    pub data: ::core::option::Option<artifact_chunk::Data>,
}
/// Nested message and enum types in `ArtifactChunk`.
pub mod artifact_chunk {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Data {
        /// TODO(P2P-483): bincode-encoded Artifact to proto-encoding
        #[prost(bytes, tag="2")]
        Artifact(::prost::alloc::vec::Vec<u8>),
        #[prost(bytes, tag="3")]
        Chunk(::prost::alloc::vec::Vec<u8>),
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum P2pError {
    Unspecified = 0,
    NotFound = 1,
}
