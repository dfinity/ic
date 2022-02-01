#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Eq, Hash)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PrincipalId {
    #[prost(bytes="vec", tag="1")]
    pub raw: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterId {
    #[prost(message, optional, tag="1")]
    pub principal_id: ::core::option::Option<PrincipalId>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Eq, Hash)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetId {
    #[prost(message, optional, tag="1")]
    pub principal_id: ::core::option::Option<PrincipalId>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UserId {
    #[prost(message, optional, tag="1")]
    pub principal_id: ::core::option::Option<PrincipalId>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeId {
    #[prost(message, optional, tag="1")]
    pub principal_id: ::core::option::Option<PrincipalId>,
}
/// A non-interactive distributed key generation (NI-DKG) ID.
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Eq, Hash)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NiDkgId {
    #[prost(uint64, tag="1")]
    pub start_block_height: u64,
    #[prost(bytes="vec", tag="2")]
    pub dealer_subnet: ::prost::alloc::vec::Vec<u8>,
    #[prost(enumeration="NiDkgTag", tag="4")]
    pub dkg_tag: i32,
    #[prost(message, optional, tag="5")]
    pub remote_target_id: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NominalCycles {
    #[prost(uint64, tag="1")]
    pub high: u64,
    #[prost(uint64, tag="2")]
    pub low: u64,
}
/// A non-interactive distributed key generation (NI-DKG) tag.
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum NiDkgTag {
    Unspecified = 0,
    LowThreshold = 1,
    HighThreshold = 2,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DkgMessage {
    #[prost(message, optional, tag="5")]
    pub signer: ::core::option::Option<NodeId>,
    #[prost(bytes="vec", tag="1")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(string, tag="2")]
    pub replica_version: ::prost::alloc::string::String,
    #[prost(message, optional, tag="3")]
    pub dkg_id: ::core::option::Option<NiDkgId>,
    #[prost(bytes="vec", tag="4")]
    pub dealing: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DkgPayload {
    #[prost(oneof="dkg_payload::Val", tags="1, 2")]
    pub val: ::core::option::Option<dkg_payload::Val>,
}
/// Nested message and enum types in `DkgPayload`.
pub mod dkg_payload {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Val {
        #[prost(message, tag="1")]
        Summary(super::Summary),
        #[prost(message, tag="2")]
        Dealings(super::Dealings),
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Dealings {
    #[prost(message, repeated, tag="1")]
    pub dealings: ::prost::alloc::vec::Vec<DkgMessage>,
    #[prost(uint64, tag="2")]
    pub summary_height: u64,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Summary {
    #[prost(uint64, tag="1")]
    pub registry_version: u64,
    #[prost(uint64, tag="2")]
    pub interval_length: u64,
    #[prost(uint64, tag="3")]
    pub next_interval_length: u64,
    #[prost(uint64, tag="4")]
    pub height: u64,
    #[prost(message, repeated, tag="5")]
    pub current_transcripts: ::prost::alloc::vec::Vec<TaggedNiDkgTranscript>,
    #[prost(message, repeated, tag="6")]
    pub next_transcripts: ::prost::alloc::vec::Vec<TaggedNiDkgTranscript>,
    #[prost(message, repeated, tag="7")]
    pub configs: ::prost::alloc::vec::Vec<NiDkgConfig>,
    #[prost(message, repeated, tag="8")]
    pub transcripts_for_new_subnets: ::prost::alloc::vec::Vec<IdedNiDkgTranscript>,
    #[prost(message, repeated, tag="9")]
    pub initial_dkg_attempts: ::prost::alloc::vec::Vec<InitialDkgAttemptCount>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TaggedNiDkgTranscript {
    #[prost(message, optional, tag="1")]
    pub transcript: ::core::option::Option<NiDkgTranscript>,
    #[prost(enumeration="NiDkgTag", tag="2")]
    pub tag: i32,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IdedNiDkgTranscript {
    #[prost(message, optional, tag="1")]
    pub dkg_id: ::core::option::Option<NiDkgId>,
    #[prost(message, optional, tag="2")]
    pub transcript_result: ::core::option::Option<NiDkgTranscriptResult>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NiDkgTranscriptResult {
    #[prost(oneof="ni_dkg_transcript_result::Val", tags="1, 2")]
    pub val: ::core::option::Option<ni_dkg_transcript_result::Val>,
}
/// Nested message and enum types in `NiDkgTranscriptResult`.
pub mod ni_dkg_transcript_result {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Val {
        #[prost(message, tag="1")]
        Transcript(super::NiDkgTranscript),
        #[prost(bytes, tag="2")]
        ErrorString(::prost::alloc::vec::Vec<u8>),
    }
}
/// A transcript for non-interactive Distributed Key Generation (NI-DKG).
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NiDkgTranscript {
    #[prost(message, optional, tag="1")]
    pub dkg_id: ::core::option::Option<NiDkgId>,
    #[prost(uint32, tag="2")]
    pub threshold: u32,
    #[prost(message, repeated, tag="3")]
    pub committee: ::prost::alloc::vec::Vec<NodeId>,
    #[prost(uint64, tag="4")]
    pub registry_version: u64,
    #[prost(bytes="vec", tag="5")]
    pub internal_csp_transcript: ::prost::alloc::vec::Vec<u8>,
}
/// A configuration for non-interactive Distributed Key Generation (NI-DKG).
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NiDkgConfig {
    #[prost(message, optional, tag="1")]
    pub dkg_id: ::core::option::Option<NiDkgId>,
    #[prost(uint32, tag="2")]
    pub max_corrupt_dealers: u32,
    #[prost(message, repeated, tag="3")]
    pub dealers: ::prost::alloc::vec::Vec<NodeId>,
    #[prost(uint32, tag="4")]
    pub max_corrupt_receivers: u32,
    #[prost(message, repeated, tag="5")]
    pub receivers: ::prost::alloc::vec::Vec<NodeId>,
    #[prost(uint32, tag="6")]
    pub threshold: u32,
    #[prost(uint64, tag="7")]
    pub registry_version: u64,
    #[prost(message, optional, tag="8")]
    pub resharing_transcript: ::core::option::Option<NiDkgTranscript>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InitialDkgAttemptCount {
    #[prost(bytes="vec", tag="1")]
    pub target_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag="2")]
    pub attempt_no: u32,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Eq, Hash)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CatchUpPackage {
    #[prost(bytes="vec", tag="1")]
    pub content: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="2")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag="3")]
    pub signer: ::core::option::Option<NiDkgId>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CatchUpContent {
    #[prost(message, optional, tag="1")]
    pub block: ::core::option::Option<Block>,
    #[prost(message, optional, tag="2")]
    pub random_beacon: ::core::option::Option<RandomBeacon>,
    #[prost(bytes="vec", tag="3")]
    pub state_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="4")]
    pub block_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="5")]
    pub random_beacon_hash: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Block {
    #[prost(string, tag="1")]
    pub version: ::prost::alloc::string::String,
    #[prost(bytes="vec", tag="2")]
    pub parent: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag="3")]
    pub dkg_payload: ::core::option::Option<DkgPayload>,
    #[prost(uint64, tag="4")]
    pub height: u64,
    #[prost(uint64, tag="5")]
    pub rank: u64,
    /// ValidationContext
    #[prost(uint64, tag="6")]
    pub time: u64,
    #[prost(uint64, tag="7")]
    pub registry_version: u64,
    #[prost(uint64, tag="8")]
    pub certified_height: u64,
    /// Payloads
    #[prost(message, optional, tag="9")]
    pub ingress_payload: ::core::option::Option<IngressPayload>,
    #[prost(message, optional, tag="10")]
    pub xnet_payload: ::core::option::Option<XNetPayload>,
    #[prost(message, optional, tag="12")]
    pub self_validating_payload: ::core::option::Option<SelfValidatingPayload>,
    #[prost(bytes="vec", tag="11")]
    pub payload_hash: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockProposal {
    #[prost(bytes="vec", tag="1")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag="2")]
    pub value: ::core::option::Option<Block>,
    #[prost(bytes="vec", tag="3")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="4")]
    pub signer: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RandomBeacon {
    #[prost(string, tag="1")]
    pub version: ::prost::alloc::string::String,
    #[prost(uint64, tag="2")]
    pub height: u64,
    #[prost(bytes="vec", tag="3")]
    pub parent: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="4")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag="5")]
    pub signer: ::core::option::Option<NiDkgId>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RandomTape {
    #[prost(string, tag="1")]
    pub version: ::prost::alloc::string::String,
    #[prost(uint64, tag="2")]
    pub height: u64,
    #[prost(bytes="vec", tag="3")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag="4")]
    pub signer: ::core::option::Option<NiDkgId>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Finalization {
    #[prost(string, tag="1")]
    pub version: ::prost::alloc::string::String,
    #[prost(uint64, tag="2")]
    pub height: u64,
    #[prost(bytes="vec", tag="3")]
    pub block: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="4")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", repeated, tag="5")]
    pub signers: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Notarization {
    #[prost(string, tag="1")]
    pub version: ::prost::alloc::string::String,
    #[prost(uint64, tag="2")]
    pub height: u64,
    #[prost(bytes="vec", tag="3")]
    pub block: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="4")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", repeated, tag="5")]
    pub signers: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetStreamSlice {
    #[prost(message, optional, tag="1")]
    pub subnet_id: ::core::option::Option<SubnetId>,
    #[prost(message, optional, tag="2")]
    pub stream_slice: ::core::option::Option<super::super::messaging::xnet::v1::CertifiedStreamSlice>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SelfValidatingPayload {
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct XNetPayload {
    #[prost(message, repeated, tag="1")]
    pub stream_slices: ::prost::alloc::vec::Vec<SubnetStreamSlice>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IngressIdOffset {
    #[prost(uint64, tag="1")]
    pub expiry: u64,
    #[prost(bytes="vec", tag="2")]
    pub message_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag="3")]
    pub offset: u64,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IngressPayload {
    #[prost(message, repeated, tag="1")]
    pub id_and_pos: ::prost::alloc::vec::Vec<IngressIdOffset>,
    #[prost(bytes="vec", tag="2")]
    pub buffer: ::prost::alloc::vec::Vec<u8>,
}
