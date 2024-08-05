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
    #[prost(oneof = "slot_update::Update", tags = "3, 4")]
    pub update: ::core::option::Option<slot_update::Update>,
}
/// Nested message and enum types in `SlotUpdate`.
pub mod slot_update {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Update {
        #[prost(bytes, tag = "3")]
        Artifact(::prost::alloc::vec::Vec<u8>),
        #[prost(message, tag = "4")]
        Advert(super::Advert),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Advert {
    #[prost(bytes = "vec", tag = "1")]
    pub id: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub attribute: ::prost::alloc::vec::Vec<u8>,
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
pub struct StrippedBlockProposal {
    #[prost(message, optional, tag = "1")]
    pub stripped_block: ::core::option::Option<StrippedBlock>,
    /// / Hash of the pre-stripped block
    #[prost(bytes = "vec", tag = "2")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
    /// / Signature of the pre-stripped block
    #[prost(bytes = "vec", tag = "3")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "4")]
    pub signer: ::core::option::Option<super::super::types::v1::NodeId>,
    #[prost(message, optional, tag = "5")]
    pub unstripped_id: ::core::option::Option<super::super::types::v1::ConsensusMessageId>,
}
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
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StrippedBlock {
    #[prost(string, tag = "1")]
    pub version: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "2")]
    pub parent: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub dkg_payload: ::core::option::Option<super::super::types::v1::DkgPayload>,
    #[prost(uint64, tag = "4")]
    pub height: u64,
    #[prost(uint64, tag = "5")]
    pub rank: u64,
    /// ValidationContext
    #[prost(uint64, tag = "6")]
    pub time: u64,
    #[prost(uint64, tag = "7")]
    pub registry_version: u64,
    #[prost(uint64, tag = "8")]
    pub certified_height: u64,
    /// Payloads
    #[prost(message, optional, tag = "9")]
    pub ingress_payload: ::core::option::Option<StrippedIngressPayload>,
    #[prost(message, optional, tag = "10")]
    pub xnet_payload: ::core::option::Option<super::super::types::v1::XNetPayload>,
    #[prost(bytes = "vec", tag = "11")]
    pub payload_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "12")]
    pub self_validating_payload:
        ::core::option::Option<super::super::types::v1::SelfValidatingPayload>,
    #[prost(message, optional, tag = "13")]
    pub idkg_payload: ::core::option::Option<super::super::types::v1::IDkgPayload>,
    #[prost(bytes = "vec", tag = "15")]
    pub canister_http_payload_bytes: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "16")]
    pub query_stats_payload_bytes: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IngressMessage {
    #[prost(uint64, tag = "1")]
    pub expiry: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub message_id: ::prost::alloc::vec::Vec<u8>,
    /// can be empty
    #[prost(bytes = "vec", tag = "3")]
    pub ingress_message: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StrippedIngressPayload {
    #[prost(message, repeated, tag = "1")]
    pub ingress_messages: ::prost::alloc::vec::Vec<IngressMessage>,
}
