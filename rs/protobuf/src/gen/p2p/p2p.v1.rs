#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StateSyncId {
    #[prost(uint64, tag = "1")]
    pub height: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StateSyncChunkRequest {
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<StateSyncId>,
    #[prost(uint32, tag = "2")]
    pub chunk_id: u32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StateSyncChunkResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub data: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SlotUpdate {
    #[prost(uint64, tag = "1")]
    pub commit_id: u64,
    #[prost(uint64, tag = "2")]
    pub slot_id: u64,
    #[prost(oneof = "slot_update::Update", tags = "3, 5")]
    pub update: ::core::option::Option<slot_update::Update>,
}
/// Nested message and enum types in `SlotUpdate`.
pub mod slot_update {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Update {
        #[prost(bytes, tag = "3")]
        Artifact(::prost::alloc::vec::Vec<u8>),
        /// ID of the artifact the sending peer has.
        /// The ID can be used to explicitly fetch the artifact.
        #[prost(bytes, tag = "5")]
        Id(::prost::alloc::vec::Vec<u8>),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetIngressMessageInBlockRequest {
    #[prost(message, optional, tag = "1")]
    pub ingress_message_id: ::core::option::Option<super::super::types::v1::IngressMessageId>,
    #[prost(message, optional, tag = "2")]
    pub block_proposal_id: ::core::option::Option<super::super::types::v1::ConsensusMessageId>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetIngressMessageInBlockResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub ingress_message: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StrippedBlockProposal {}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StrippedConsensusMessage {
    #[prost(oneof = "stripped_consensus_message::Msg", tags = "1, 2")]
    pub msg: ::core::option::Option<stripped_consensus_message::Msg>,
}
/// Nested message and enum types in `StrippedConsensusMessage`.
pub mod stripped_consensus_message {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Msg {
        #[prost(message, tag = "1")]
        StrippedBlockProposal(super::StrippedBlockProposal),
        #[prost(message, tag = "2")]
        Unstripped(super::super::super::types::v1::ConsensusMessage),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StrippedConsensusMessageId {
    #[prost(message, optional, tag = "1")]
    pub unstripped_id: ::core::option::Option<super::super::types::v1::ConsensusMessageId>,
}
