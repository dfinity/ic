#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterUpgradeOptions {
    #[prost(bool, optional, tag = "1")]
    pub skip_pre_upgrade: ::core::option::Option<bool>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterInstallModeV2 {
    #[prost(
        oneof = "canister_install_mode_v2::CanisterInstallModeV2",
        tags = "1, 2"
    )]
    pub canister_install_mode_v2:
        ::core::option::Option<canister_install_mode_v2::CanisterInstallModeV2>,
}
/// Nested message and enum types in `CanisterInstallModeV2`.
pub mod canister_install_mode_v2 {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum CanisterInstallModeV2 {
        #[prost(enumeration = "super::CanisterInstallMode", tag = "1")]
        Mode(i32),
        #[prost(message, tag = "2")]
        Mode2(super::CanisterUpgradeOptions),
    }
}
#[derive(
    serde::Serialize,
    serde::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    ::prost::Enumeration,
)]
#[repr(i32)]
pub enum CanisterInstallMode {
    Unspecified = 0,
    Install = 1,
    Reinstall = 2,
    Upgrade = 3,
}
impl CanisterInstallMode {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            CanisterInstallMode::Unspecified => "CANISTER_INSTALL_MODE_UNSPECIFIED",
            CanisterInstallMode::Install => "CANISTER_INSTALL_MODE_INSTALL",
            CanisterInstallMode::Reinstall => "CANISTER_INSTALL_MODE_REINSTALL",
            CanisterInstallMode::Upgrade => "CANISTER_INSTALL_MODE_UPGRADE",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "CANISTER_INSTALL_MODE_UNSPECIFIED" => Some(Self::Unspecified),
            "CANISTER_INSTALL_MODE_INSTALL" => Some(Self::Install),
            "CANISTER_INSTALL_MODE_REINSTALL" => Some(Self::Reinstall),
            "CANISTER_INSTALL_MODE_UPGRADE" => Some(Self::Upgrade),
            _ => None,
        }
    }
}
#[derive(serde::Serialize, serde::Deserialize, Eq, Hash)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PrincipalId {
    #[prost(bytes = "vec", tag = "1")]
    pub raw: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterId {
    #[prost(message, optional, tag = "1")]
    pub principal_id: ::core::option::Option<PrincipalId>,
}
#[derive(serde::Serialize, serde::Deserialize, Eq, Hash)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetId {
    #[prost(message, optional, tag = "1")]
    pub principal_id: ::core::option::Option<PrincipalId>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UserId {
    #[prost(message, optional, tag = "1")]
    pub principal_id: ::core::option::Option<PrincipalId>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeId {
    #[prost(message, optional, tag = "1")]
    pub principal_id: ::core::option::Option<PrincipalId>,
}
/// A non-interactive distributed key generation (NI-DKG) ID.
#[derive(serde::Serialize, serde::Deserialize, Eq, Hash)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NiDkgId {
    #[prost(uint64, tag = "1")]
    pub start_block_height: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub dealer_subnet: ::prost::alloc::vec::Vec<u8>,
    #[prost(enumeration = "NiDkgTag", tag = "4")]
    pub dkg_tag: i32,
    #[prost(message, optional, tag = "5")]
    pub remote_target_id: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NominalCycles {
    #[prost(uint64, tag = "1")]
    pub high: u64,
    #[prost(uint64, tag = "2")]
    pub low: u64,
}
/// A non-interactive distributed key generation (NI-DKG) tag.
#[derive(
    serde::Serialize,
    serde::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    ::prost::Enumeration,
)]
#[repr(i32)]
pub enum NiDkgTag {
    Unspecified = 0,
    LowThreshold = 1,
    HighThreshold = 2,
}
impl NiDkgTag {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            NiDkgTag::Unspecified => "NI_DKG_TAG_UNSPECIFIED",
            NiDkgTag::LowThreshold => "NI_DKG_TAG_LOW_THRESHOLD",
            NiDkgTag::HighThreshold => "NI_DKG_TAG_HIGH_THRESHOLD",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "NI_DKG_TAG_UNSPECIFIED" => Some(Self::Unspecified),
            "NI_DKG_TAG_LOW_THRESHOLD" => Some(Self::LowThreshold),
            "NI_DKG_TAG_HIGH_THRESHOLD" => Some(Self::HighThreshold),
            _ => None,
        }
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DkgMessage {
    #[prost(message, optional, tag = "5")]
    pub signer: ::core::option::Option<NodeId>,
    #[prost(bytes = "vec", tag = "1")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(string, tag = "2")]
    pub replica_version: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "3")]
    pub dkg_id: ::core::option::Option<NiDkgId>,
    #[prost(bytes = "vec", tag = "4")]
    pub dealing: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DkgPayload {
    #[prost(oneof = "dkg_payload::Val", tags = "1, 2")]
    pub val: ::core::option::Option<dkg_payload::Val>,
}
/// Nested message and enum types in `DkgPayload`.
pub mod dkg_payload {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Val {
        #[prost(message, tag = "1")]
        Summary(super::Summary),
        #[prost(message, tag = "2")]
        Dealings(super::Dealings),
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Dealings {
    #[prost(message, repeated, tag = "1")]
    pub dealings: ::prost::alloc::vec::Vec<DkgMessage>,
    #[prost(uint64, tag = "2")]
    pub summary_height: u64,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Summary {
    #[prost(uint64, tag = "1")]
    pub registry_version: u64,
    #[prost(uint64, tag = "2")]
    pub interval_length: u64,
    #[prost(uint64, tag = "3")]
    pub next_interval_length: u64,
    #[prost(uint64, tag = "4")]
    pub height: u64,
    #[prost(message, repeated, tag = "5")]
    pub current_transcripts: ::prost::alloc::vec::Vec<TaggedNiDkgTranscript>,
    #[prost(message, repeated, tag = "6")]
    pub next_transcripts: ::prost::alloc::vec::Vec<TaggedNiDkgTranscript>,
    #[prost(message, repeated, tag = "7")]
    pub configs: ::prost::alloc::vec::Vec<NiDkgConfig>,
    #[prost(message, repeated, tag = "9")]
    pub initial_dkg_attempts: ::prost::alloc::vec::Vec<InitialDkgAttemptCount>,
    #[prost(message, repeated, tag = "10")]
    pub transcripts_for_new_subnets_with_callback_ids:
        ::prost::alloc::vec::Vec<CallbackIdedNiDkgTranscript>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TaggedNiDkgTranscript {
    #[prost(message, optional, tag = "1")]
    pub transcript: ::core::option::Option<NiDkgTranscript>,
    #[prost(enumeration = "NiDkgTag", tag = "2")]
    pub tag: i32,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CallbackIdedNiDkgTranscript {
    #[prost(message, optional, tag = "1")]
    pub dkg_id: ::core::option::Option<NiDkgId>,
    #[prost(message, optional, tag = "2")]
    pub transcript_result: ::core::option::Option<NiDkgTranscriptResult>,
    #[prost(uint64, tag = "3")]
    pub callback_id: u64,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NiDkgTranscriptResult {
    #[prost(oneof = "ni_dkg_transcript_result::Val", tags = "1, 2")]
    pub val: ::core::option::Option<ni_dkg_transcript_result::Val>,
}
/// Nested message and enum types in `NiDkgTranscriptResult`.
pub mod ni_dkg_transcript_result {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Val {
        #[prost(message, tag = "1")]
        Transcript(super::NiDkgTranscript),
        #[prost(bytes, tag = "2")]
        ErrorString(::prost::alloc::vec::Vec<u8>),
    }
}
/// A transcript for non-interactive Distributed Key Generation (NI-DKG).
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NiDkgTranscript {
    #[prost(message, optional, tag = "1")]
    pub dkg_id: ::core::option::Option<NiDkgId>,
    #[prost(uint32, tag = "2")]
    pub threshold: u32,
    #[prost(message, repeated, tag = "3")]
    pub committee: ::prost::alloc::vec::Vec<NodeId>,
    #[prost(uint64, tag = "4")]
    pub registry_version: u64,
    #[prost(bytes = "vec", tag = "5")]
    pub internal_csp_transcript: ::prost::alloc::vec::Vec<u8>,
}
/// A configuration for non-interactive Distributed Key Generation (NI-DKG).
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NiDkgConfig {
    #[prost(message, optional, tag = "1")]
    pub dkg_id: ::core::option::Option<NiDkgId>,
    #[prost(uint32, tag = "2")]
    pub max_corrupt_dealers: u32,
    #[prost(message, repeated, tag = "3")]
    pub dealers: ::prost::alloc::vec::Vec<NodeId>,
    #[prost(uint32, tag = "4")]
    pub max_corrupt_receivers: u32,
    #[prost(message, repeated, tag = "5")]
    pub receivers: ::prost::alloc::vec::Vec<NodeId>,
    #[prost(uint32, tag = "6")]
    pub threshold: u32,
    #[prost(uint64, tag = "7")]
    pub registry_version: u64,
    #[prost(message, optional, tag = "8")]
    pub resharing_transcript: ::core::option::Option<NiDkgTranscript>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InitialDkgAttemptCount {
    #[prost(bytes = "vec", tag = "1")]
    pub target_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub attempt_no: u32,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BasicSignature {
    #[prost(bytes = "vec", tag = "1")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "2")]
    pub signer: ::core::option::Option<NodeId>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ThresholdSignature {
    #[prost(bytes = "vec", tag = "1")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "2")]
    pub signer: ::core::option::Option<NiDkgId>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ThresholdSignatureShare {
    #[prost(bytes = "vec", tag = "1")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "2")]
    pub signer: ::core::option::Option<NodeId>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaPayload {
    #[prost(message, repeated, tag = "1")]
    pub signature_agreements: ::prost::alloc::vec::Vec<CompletedSignature>,
    #[prost(message, repeated, tag = "2")]
    pub ongoing_signatures: ::prost::alloc::vec::Vec<OngoingSignature>,
    #[prost(message, repeated, tag = "3")]
    pub available_quadruples: ::prost::alloc::vec::Vec<AvailableQuadruple>,
    #[prost(message, repeated, tag = "4")]
    pub quadruples_in_creation: ::prost::alloc::vec::Vec<QuadrupleInProgress>,
    #[prost(message, optional, tag = "5")]
    pub next_unused_transcript_id:
        ::core::option::Option<super::super::registry::subnet::v1::IDkgTranscriptId>,
    #[prost(message, repeated, tag = "6")]
    pub idkg_transcripts:
        ::prost::alloc::vec::Vec<super::super::registry::subnet::v1::IDkgTranscript>,
    #[prost(message, repeated, tag = "7")]
    pub ongoing_xnet_reshares: ::prost::alloc::vec::Vec<OngoingXnetReshare>,
    #[prost(message, repeated, tag = "8")]
    pub xnet_reshare_agreements: ::prost::alloc::vec::Vec<XnetReshareAgreement>,
    #[prost(uint64, tag = "10")]
    pub next_unused_quadruple_id: u64,
    #[prost(message, repeated, tag = "13")]
    pub key_transcripts: ::prost::alloc::vec::Vec<EcdsaKeyTranscript>,
    /// TODO: retire these fields, once we start using `key_transcripts`.
    #[prost(message, optional, tag = "9")]
    pub current_key_transcript: ::core::option::Option<UnmaskedTranscriptWithAttributes>,
    #[prost(message, optional, tag = "11")]
    pub next_key_in_creation: ::core::option::Option<KeyTranscriptCreation>,
    #[prost(message, optional, tag = "12")]
    pub key_id: ::core::option::Option<super::super::registry::crypto::v1::EcdsaKeyId>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsensusResponse {
    #[prost(message, optional, tag = "1")]
    pub originator: ::core::option::Option<CanisterId>,
    #[prost(message, optional, tag = "2")]
    pub respondent: ::core::option::Option<CanisterId>,
    #[prost(uint64, tag = "3")]
    pub callback: u64,
    #[prost(message, optional, tag = "4")]
    pub refund: ::core::option::Option<super::super::state::queues::v1::Funds>,
    #[prost(message, optional, tag = "7")]
    pub cycles_refund: ::core::option::Option<super::super::state::queues::v1::Cycles>,
    #[prost(uint32, optional, tag = "8")]
    pub deadline_seconds: ::core::option::Option<u32>,
    #[prost(oneof = "consensus_response::Payload", tags = "5, 6")]
    pub payload: ::core::option::Option<consensus_response::Payload>,
}
/// Nested message and enum types in `ConsensusResponse`.
pub mod consensus_response {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Payload {
        #[prost(bytes, tag = "5")]
        Data(::prost::alloc::vec::Vec<u8>),
        #[prost(message, tag = "6")]
        Reject(super::super::super::state::queues::v1::RejectContext),
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaKeyTranscript {
    #[prost(message, optional, tag = "1")]
    pub key_id: ::core::option::Option<super::super::registry::crypto::v1::EcdsaKeyId>,
    #[prost(message, optional, tag = "2")]
    pub current: ::core::option::Option<UnmaskedTranscriptWithAttributes>,
    #[prost(message, optional, tag = "3")]
    pub next_in_creation: ::core::option::Option<KeyTranscriptCreation>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OngoingSignature {
    #[prost(message, optional, tag = "1")]
    pub request_id: ::core::option::Option<RequestId>,
    #[prost(message, optional, tag = "2")]
    pub sig_inputs: ::core::option::Option<ThresholdEcdsaSigInputsRef>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AvailableQuadruple {
    #[prost(uint64, tag = "1")]
    pub quadruple_id: u64,
    #[prost(message, optional, tag = "2")]
    pub quadruple: ::core::option::Option<PreSignatureQuadrupleRef>,
    /// Deprecated. Use `quadruple.key_id` instead.
    #[prost(message, optional, tag = "3")]
    pub key_id: ::core::option::Option<super::super::registry::crypto::v1::EcdsaKeyId>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QuadrupleInProgress {
    #[prost(uint64, tag = "1")]
    pub quadruple_id: u64,
    #[prost(message, optional, tag = "2")]
    pub quadruple: ::core::option::Option<QuadrupleInCreation>,
    /// Deprecated. Use `quadruple.key_id` instead.
    #[prost(message, optional, tag = "3")]
    pub key_id: ::core::option::Option<super::super::registry::crypto::v1::EcdsaKeyId>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OngoingXnetReshare {
    #[prost(message, optional, tag = "1")]
    pub request: ::core::option::Option<EcdsaReshareRequest>,
    #[prost(message, optional, tag = "2")]
    pub transcript: ::core::option::Option<ReshareOfUnmaskedParams>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct XnetReshareAgreement {
    #[prost(message, optional, tag = "1")]
    pub request: ::core::option::Option<EcdsaReshareRequest>,
    #[prost(message, optional, tag = "4")]
    pub initial_dealings: ::core::option::Option<ConsensusResponse>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RequestId {
    #[prost(bytes = "vec", tag = "1")]
    pub pseudo_random_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub quadruple_id: u64,
    #[prost(uint64, tag = "3")]
    pub height: u64,
    #[prost(message, optional, tag = "4")]
    pub key_id: ::core::option::Option<super::super::registry::crypto::v1::EcdsaKeyId>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TranscriptRef {
    #[prost(uint64, tag = "1")]
    pub height: u64,
    #[prost(message, optional, tag = "2")]
    pub transcript_id: ::core::option::Option<super::super::registry::subnet::v1::IDkgTranscriptId>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MaskedTranscript {
    #[prost(message, optional, tag = "1")]
    pub transcript_ref: ::core::option::Option<TranscriptRef>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UnmaskedTranscript {
    #[prost(message, optional, tag = "1")]
    pub transcript_ref: ::core::option::Option<TranscriptRef>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UnmaskedTranscriptWithAttributes {
    #[prost(message, optional, tag = "1")]
    pub transcript_ref: ::core::option::Option<TranscriptRef>,
    #[prost(message, optional, tag = "2")]
    pub attributes: ::core::option::Option<IDkgTranscriptAttributes>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IDkgTranscriptOperationRef {
    #[prost(int32, tag = "1")]
    pub op_type: i32,
    #[prost(message, optional, tag = "2")]
    pub masked: ::core::option::Option<MaskedTranscript>,
    #[prost(message, optional, tag = "3")]
    pub unmasked: ::core::option::Option<UnmaskedTranscript>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IDkgTranscriptAttributes {
    #[prost(message, repeated, tag = "1")]
    pub receivers: ::prost::alloc::vec::Vec<NodeId>,
    #[prost(int32, tag = "2")]
    pub algorithm_id: i32,
    #[prost(uint64, tag = "3")]
    pub registry_version: u64,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IDkgTranscriptParamsRef {
    #[prost(message, optional, tag = "1")]
    pub transcript_id: ::core::option::Option<super::super::registry::subnet::v1::IDkgTranscriptId>,
    #[prost(message, repeated, tag = "2")]
    pub dealers: ::prost::alloc::vec::Vec<NodeId>,
    #[prost(message, repeated, tag = "3")]
    pub receivers: ::prost::alloc::vec::Vec<NodeId>,
    #[prost(uint64, tag = "4")]
    pub registry_version: u64,
    #[prost(int32, tag = "5")]
    pub algorithm_id: i32,
    #[prost(message, optional, tag = "6")]
    pub operation_type_ref: ::core::option::Option<IDkgTranscriptOperationRef>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RandomTranscriptParams {
    #[prost(message, optional, tag = "1")]
    pub transcript_ref: ::core::option::Option<IDkgTranscriptParamsRef>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RandomUnmaskedTranscriptParams {
    #[prost(message, optional, tag = "1")]
    pub transcript_ref: ::core::option::Option<IDkgTranscriptParamsRef>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReshareOfMaskedParams {
    #[prost(message, optional, tag = "1")]
    pub transcript_ref: ::core::option::Option<IDkgTranscriptParamsRef>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReshareOfUnmaskedParams {
    #[prost(message, optional, tag = "1")]
    pub transcript_ref: ::core::option::Option<IDkgTranscriptParamsRef>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UnmaskedTimesMaskedParams {
    #[prost(message, optional, tag = "1")]
    pub transcript_ref: ::core::option::Option<IDkgTranscriptParamsRef>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QuadrupleInCreation {
    #[prost(message, optional, tag = "1")]
    pub kappa_masked_config: ::core::option::Option<RandomTranscriptParams>,
    #[prost(message, optional, tag = "2")]
    pub kappa_masked: ::core::option::Option<MaskedTranscript>,
    #[prost(message, optional, tag = "3")]
    pub lambda_config: ::core::option::Option<RandomTranscriptParams>,
    #[prost(message, optional, tag = "4")]
    pub lambda_masked: ::core::option::Option<MaskedTranscript>,
    #[prost(message, optional, tag = "11")]
    pub kappa_unmasked_config: ::core::option::Option<RandomUnmaskedTranscriptParams>,
    #[prost(message, optional, tag = "5")]
    pub unmask_kappa_config: ::core::option::Option<ReshareOfMaskedParams>,
    #[prost(message, optional, tag = "6")]
    pub kappa_unmasked: ::core::option::Option<UnmaskedTranscript>,
    #[prost(message, optional, tag = "7")]
    pub key_times_lambda_config: ::core::option::Option<UnmaskedTimesMaskedParams>,
    #[prost(message, optional, tag = "8")]
    pub key_times_lambda: ::core::option::Option<MaskedTranscript>,
    #[prost(message, optional, tag = "9")]
    pub kappa_times_lambda_config: ::core::option::Option<UnmaskedTimesMaskedParams>,
    #[prost(message, optional, tag = "10")]
    pub kappa_times_lambda: ::core::option::Option<MaskedTranscript>,
    #[prost(message, optional, tag = "12")]
    pub key_id: ::core::option::Option<super::super::registry::crypto::v1::EcdsaKeyId>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PreSignatureQuadrupleRef {
    #[prost(message, optional, tag = "1")]
    pub kappa_unmasked_ref: ::core::option::Option<UnmaskedTranscript>,
    #[prost(message, optional, tag = "2")]
    pub lambda_masked_ref: ::core::option::Option<MaskedTranscript>,
    #[prost(message, optional, tag = "3")]
    pub kappa_times_lambda_ref: ::core::option::Option<MaskedTranscript>,
    #[prost(message, optional, tag = "4")]
    pub key_times_lambda_ref: ::core::option::Option<MaskedTranscript>,
    #[prost(message, optional, tag = "5")]
    pub key_unmasked_ref: ::core::option::Option<UnmaskedTranscript>,
    #[prost(message, optional, tag = "6")]
    pub key_id: ::core::option::Option<super::super::registry::crypto::v1::EcdsaKeyId>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ThresholdEcdsaSigInputsRef {
    #[prost(message, optional, tag = "1")]
    pub derivation_path:
        ::core::option::Option<super::super::registry::subnet::v1::ExtendedDerivationPath>,
    #[prost(bytes = "vec", tag = "2")]
    pub hashed_message: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub nonce: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "4")]
    pub presig_quadruple_ref: ::core::option::Option<PreSignatureQuadrupleRef>,
    #[prost(message, optional, tag = "5")]
    pub key_transcript_ref: ::core::option::Option<UnmaskedTranscript>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CompletedSignature {
    #[prost(message, optional, tag = "3")]
    pub unreported: ::core::option::Option<ConsensusResponse>,
    #[prost(bytes = "vec", tag = "4")]
    pub pseudo_random_id: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaReshareRequest {
    #[prost(message, repeated, tag = "2")]
    pub receiving_node_ids: ::prost::alloc::vec::Vec<NodeId>,
    #[prost(uint64, tag = "3")]
    pub registry_version: u64,
    #[prost(message, optional, tag = "4")]
    pub key_id: ::core::option::Option<super::super::registry::crypto::v1::EcdsaKeyId>,
    #[prost(message, optional, tag = "5")]
    pub master_key_id:
        ::core::option::Option<super::super::registry::crypto::v1::MasterPublicKeyId>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeyTranscriptCreation {
    #[prost(enumeration = "KeyTranscriptCreationState", tag = "1")]
    pub state: i32,
    #[prost(message, optional, tag = "2")]
    pub random: ::core::option::Option<RandomTranscriptParams>,
    #[prost(message, optional, tag = "3")]
    pub reshare_of_masked: ::core::option::Option<ReshareOfMaskedParams>,
    #[prost(message, optional, tag = "4")]
    pub reshare_of_unmasked: ::core::option::Option<ReshareOfUnmaskedParams>,
    #[prost(message, optional, tag = "5")]
    pub xnet_reshare_of_unmasked: ::core::option::Option<ReshareOfUnmaskedParams>,
    #[prost(message, optional, tag = "6")]
    pub xnet_reshare_initial_dealings:
        ::core::option::Option<super::super::registry::subnet::v1::InitialIDkgDealings>,
    #[prost(message, optional, tag = "9")]
    pub created: ::core::option::Option<UnmaskedTranscript>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaMessage {
    #[prost(oneof = "ecdsa_message::Msg", tags = "1, 2, 3, 4, 5")]
    pub msg: ::core::option::Option<ecdsa_message::Msg>,
}
/// Nested message and enum types in `EcdsaMessage`.
pub mod ecdsa_message {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Msg {
        #[prost(message, tag = "1")]
        SignedDealing(super::super::super::registry::subnet::v1::IDkgSignedDealingTuple),
        #[prost(message, tag = "2")]
        DealingSupport(super::IDkgDealingSupport),
        #[prost(message, tag = "3")]
        SigShare(super::EcdsaSigShare),
        #[prost(message, tag = "4")]
        Complaint(super::EcdsaComplaint),
        #[prost(message, tag = "5")]
        Opening(super::EcdsaOpening),
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaSigShare {
    #[prost(message, optional, tag = "1")]
    pub signer_id: ::core::option::Option<NodeId>,
    #[prost(message, optional, tag = "2")]
    pub request_id: ::core::option::Option<RequestId>,
    #[prost(bytes = "vec", tag = "3")]
    pub sig_share_raw: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaComplaint {
    #[prost(message, optional, tag = "1")]
    pub content: ::core::option::Option<EcdsaComplaintContent>,
    #[prost(message, optional, tag = "2")]
    pub signature: ::core::option::Option<BasicSignature>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaComplaintContent {
    #[prost(message, optional, tag = "1")]
    pub idkg_complaint: ::core::option::Option<super::super::registry::subnet::v1::IDkgComplaint>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaOpening {
    #[prost(message, optional, tag = "1")]
    pub content: ::core::option::Option<EcdsaOpeningContent>,
    #[prost(message, optional, tag = "2")]
    pub signature: ::core::option::Option<BasicSignature>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaOpeningContent {
    #[prost(message, optional, tag = "1")]
    pub idkg_opening: ::core::option::Option<super::super::registry::subnet::v1::IDkgOpening>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IDkgDealingSupport {
    #[prost(message, optional, tag = "1")]
    pub transcript_id: ::core::option::Option<super::super::registry::subnet::v1::IDkgTranscriptId>,
    #[prost(message, optional, tag = "2")]
    pub dealer: ::core::option::Option<NodeId>,
    #[prost(bytes = "vec", tag = "3")]
    pub dealing_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "4")]
    pub sig_share: ::core::option::Option<BasicSignature>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaPrefix {
    #[prost(uint64, tag = "1")]
    pub group_tag: u64,
    #[prost(uint64, tag = "2")]
    pub meta_hash: u64,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PrefixHashPair {
    #[prost(message, optional, tag = "1")]
    pub prefix: ::core::option::Option<EcdsaPrefix>,
    #[prost(bytes = "vec", tag = "2")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaArtifactId {
    #[prost(oneof = "ecdsa_artifact_id::Kind", tags = "1, 2, 3, 4, 5")]
    pub kind: ::core::option::Option<ecdsa_artifact_id::Kind>,
}
/// Nested message and enum types in `EcdsaArtifactId`.
pub mod ecdsa_artifact_id {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "1")]
        Dealing(super::PrefixHashPair),
        #[prost(message, tag = "2")]
        DealingSupport(super::PrefixHashPair),
        #[prost(message, tag = "3")]
        SigShare(super::PrefixHashPair),
        #[prost(message, tag = "4")]
        Complaint(super::PrefixHashPair),
        #[prost(message, tag = "5")]
        Opening(super::PrefixHashPair),
    }
}
#[derive(
    serde::Serialize,
    serde::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    ::prost::Enumeration,
)]
#[repr(i32)]
pub enum KeyTranscriptCreationState {
    BeginUnspecified = 0,
    RandomTranscriptParams = 1,
    ReshareOfMaskedParams = 2,
    ReshareOfUnmaskedParams = 3,
    XnetReshareOfUnmaskedParams = 4,
    Created = 5,
}
impl KeyTranscriptCreationState {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            KeyTranscriptCreationState::BeginUnspecified => {
                "KEY_TRANSCRIPT_CREATION_STATE_BEGIN_UNSPECIFIED"
            }
            KeyTranscriptCreationState::RandomTranscriptParams => {
                "KEY_TRANSCRIPT_CREATION_STATE_RANDOM_TRANSCRIPT_PARAMS"
            }
            KeyTranscriptCreationState::ReshareOfMaskedParams => {
                "KEY_TRANSCRIPT_CREATION_STATE_RESHARE_OF_MASKED_PARAMS"
            }
            KeyTranscriptCreationState::ReshareOfUnmaskedParams => {
                "KEY_TRANSCRIPT_CREATION_STATE_RESHARE_OF_UNMASKED_PARAMS"
            }
            KeyTranscriptCreationState::XnetReshareOfUnmaskedParams => {
                "KEY_TRANSCRIPT_CREATION_STATE_XNET_RESHARE_OF_UNMASKED_PARAMS"
            }
            KeyTranscriptCreationState::Created => "KEY_TRANSCRIPT_CREATION_STATE_CREATED",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "KEY_TRANSCRIPT_CREATION_STATE_BEGIN_UNSPECIFIED" => Some(Self::BeginUnspecified),
            "KEY_TRANSCRIPT_CREATION_STATE_RANDOM_TRANSCRIPT_PARAMS" => {
                Some(Self::RandomTranscriptParams)
            }
            "KEY_TRANSCRIPT_CREATION_STATE_RESHARE_OF_MASKED_PARAMS" => {
                Some(Self::ReshareOfMaskedParams)
            }
            "KEY_TRANSCRIPT_CREATION_STATE_RESHARE_OF_UNMASKED_PARAMS" => {
                Some(Self::ReshareOfUnmaskedParams)
            }
            "KEY_TRANSCRIPT_CREATION_STATE_XNET_RESHARE_OF_UNMASKED_PARAMS" => {
                Some(Self::XnetReshareOfUnmaskedParams)
            }
            "KEY_TRANSCRIPT_CREATION_STATE_CREATED" => Some(Self::Created),
            _ => None,
        }
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CertificationMessage {
    #[prost(oneof = "certification_message::Msg", tags = "1, 2")]
    pub msg: ::core::option::Option<certification_message::Msg>,
}
/// Nested message and enum types in `CertificationMessage`.
pub mod certification_message {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Msg {
        #[prost(message, tag = "1")]
        Certification(super::super::super::messaging::xnet::v1::Certification),
        #[prost(message, tag = "2")]
        CertificationShare(super::super::super::messaging::xnet::v1::CertificationShare),
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ValidatedConsensusArtifact {
    #[prost(message, optional, tag = "1")]
    pub msg: ::core::option::Option<ConsensusMessage>,
    #[prost(uint64, tag = "2")]
    pub timestamp: u64,
}
#[derive(serde::Serialize, serde::Deserialize, Eq, Hash)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CatchUpPackage {
    #[prost(bytes = "vec", tag = "1")]
    pub content: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub signer: ::core::option::Option<NiDkgId>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CatchUpPackageShare {
    #[prost(string, tag = "1")]
    pub version: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub random_beacon: ::core::option::Option<RandomBeacon>,
    #[prost(bytes = "vec", tag = "3")]
    pub state_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub block_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub random_beacon_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "7")]
    pub signer: ::core::option::Option<NodeId>,
    #[prost(uint64, optional, tag = "8")]
    pub oldest_registry_version_in_use_by_replicated_state: ::core::option::Option<u64>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CatchUpContent {
    #[prost(message, optional, tag = "1")]
    pub block: ::core::option::Option<Block>,
    #[prost(message, optional, tag = "2")]
    pub random_beacon: ::core::option::Option<RandomBeacon>,
    #[prost(bytes = "vec", tag = "3")]
    pub state_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub block_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub random_beacon_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, optional, tag = "6")]
    pub oldest_registry_version_in_use_by_replicated_state: ::core::option::Option<u64>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Block {
    #[prost(string, tag = "1")]
    pub version: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "2")]
    pub parent: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub dkg_payload: ::core::option::Option<DkgPayload>,
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
    pub ingress_payload: ::core::option::Option<IngressPayload>,
    #[prost(message, optional, tag = "10")]
    pub xnet_payload: ::core::option::Option<XNetPayload>,
    #[prost(message, optional, tag = "12")]
    pub self_validating_payload: ::core::option::Option<SelfValidatingPayload>,
    #[prost(message, optional, tag = "13")]
    pub ecdsa_payload: ::core::option::Option<EcdsaPayload>,
    #[prost(bytes = "vec", tag = "15")]
    pub canister_http_payload_bytes: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "16")]
    pub query_stats_payload_bytes: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "11")]
    pub payload_hash: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::large_enum_variant)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsensusMessage {
    #[prost(
        oneof = "consensus_message::Msg",
        tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11"
    )]
    pub msg: ::core::option::Option<consensus_message::Msg>,
}
/// Nested message and enum types in `ConsensusMessage`.
pub mod consensus_message {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[allow(clippy::large_enum_variant)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Msg {
        #[prost(message, tag = "1")]
        RandomBeacon(super::RandomBeacon),
        #[prost(message, tag = "2")]
        Finalization(super::Finalization),
        #[prost(message, tag = "3")]
        Notarization(super::Notarization),
        #[prost(message, tag = "4")]
        BlockProposal(super::BlockProposal),
        #[prost(message, tag = "5")]
        RandomBeaconShare(super::RandomBeaconShare),
        #[prost(message, tag = "6")]
        NotarizationShare(super::NotarizationShare),
        #[prost(message, tag = "7")]
        FinalizationShare(super::FinalizationShare),
        #[prost(message, tag = "8")]
        RandomTape(super::RandomTape),
        #[prost(message, tag = "9")]
        RandomTapeShare(super::RandomTapeShare),
        #[prost(message, tag = "10")]
        Cup(super::CatchUpPackage),
        #[prost(message, tag = "11")]
        CupShare(super::CatchUpPackageShare),
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockProposal {
    #[prost(bytes = "vec", tag = "1")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "2")]
    pub value: ::core::option::Option<Block>,
    #[prost(bytes = "vec", tag = "3")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "5")]
    pub signer: ::core::option::Option<NodeId>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RandomBeacon {
    #[prost(string, tag = "1")]
    pub version: ::prost::alloc::string::String,
    #[prost(uint64, tag = "2")]
    pub height: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub parent: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "5")]
    pub signer: ::core::option::Option<NiDkgId>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RandomBeaconShare {
    #[prost(string, tag = "1")]
    pub version: ::prost::alloc::string::String,
    #[prost(uint64, tag = "2")]
    pub height: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub parent: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "5")]
    pub signer: ::core::option::Option<NodeId>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RandomTape {
    #[prost(string, tag = "1")]
    pub version: ::prost::alloc::string::String,
    #[prost(uint64, tag = "2")]
    pub height: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "4")]
    pub signer: ::core::option::Option<NiDkgId>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RandomTapeShare {
    #[prost(string, tag = "1")]
    pub version: ::prost::alloc::string::String,
    #[prost(uint64, tag = "2")]
    pub height: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "4")]
    pub signer: ::core::option::Option<NodeId>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Finalization {
    #[prost(string, tag = "1")]
    pub version: ::prost::alloc::string::String,
    #[prost(uint64, tag = "2")]
    pub height: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub block: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "5")]
    pub signers: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FinalizationShare {
    #[prost(string, tag = "1")]
    pub version: ::prost::alloc::string::String,
    #[prost(uint64, tag = "2")]
    pub height: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub block: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "5")]
    pub signer: ::core::option::Option<NodeId>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Notarization {
    #[prost(string, tag = "1")]
    pub version: ::prost::alloc::string::String,
    #[prost(uint64, tag = "2")]
    pub height: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub block: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "5")]
    pub signers: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NotarizationShare {
    #[prost(string, tag = "1")]
    pub version: ::prost::alloc::string::String,
    #[prost(uint64, tag = "2")]
    pub height: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub block: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "5")]
    pub signer: ::core::option::Option<NodeId>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetStreamSlice {
    #[prost(message, optional, tag = "1")]
    pub subnet_id: ::core::option::Option<SubnetId>,
    #[prost(message, optional, tag = "2")]
    pub stream_slice:
        ::core::option::Option<super::super::messaging::xnet::v1::CertifiedStreamSlice>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SelfValidatingPayload {
    /// Responses from the Bitcoin Adapter talking to the Bitcoin testnet.
    #[prost(message, repeated, tag = "1")]
    pub bitcoin_testnet_payload:
        ::prost::alloc::vec::Vec<super::super::bitcoin::v1::BitcoinAdapterResponse>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct XNetPayload {
    #[prost(message, repeated, tag = "1")]
    pub stream_slices: ::prost::alloc::vec::Vec<SubnetStreamSlice>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryStatsPayload {
    #[prost(message, repeated, tag = "2")]
    pub canister_stats: ::prost::alloc::vec::Vec<CanisterQueryStats>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterQueryStats {
    #[prost(message, optional, tag = "1")]
    pub canister_id: ::core::option::Option<CanisterId>,
    #[prost(uint32, tag = "2")]
    pub num_calls: u32,
    #[prost(uint64, tag = "3")]
    pub num_instructions: u64,
    #[prost(uint64, tag = "4")]
    pub ingress_payload_size: u64,
    #[prost(uint64, tag = "5")]
    pub egress_payload_size: u64,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IngressIdOffset {
    #[prost(uint64, tag = "1")]
    pub expiry: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub message_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub offset: u64,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IngressPayload {
    #[prost(message, repeated, tag = "1")]
    pub id_and_pos: ::prost::alloc::vec::Vec<IngressIdOffset>,
    #[prost(bytes = "vec", tag = "2")]
    pub buffer: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HttpHeader {
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "2")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterHttpRequest {
    #[prost(string, tag = "1")]
    pub url: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "2")]
    pub body: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, repeated, tag = "3")]
    pub headers: ::prost::alloc::vec::Vec<HttpHeader>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterHttpResponse {
    #[prost(uint64, tag = "1")]
    pub id: u64,
    #[prost(uint64, tag = "2")]
    pub timeout: u64,
    #[prost(message, optional, tag = "4")]
    pub canister_id: ::core::option::Option<CanisterId>,
    #[prost(message, optional, tag = "3")]
    pub content: ::core::option::Option<CanisterHttpResponseContent>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterHttpResponseMetadata {
    #[prost(uint64, tag = "1")]
    pub id: u64,
    #[prost(uint64, tag = "2")]
    pub timeout: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub content_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "4")]
    pub registry_version: u64,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterHttpResponseContent {
    #[prost(oneof = "canister_http_response_content::Status", tags = "2, 3")]
    pub status: ::core::option::Option<canister_http_response_content::Status>,
}
/// Nested message and enum types in `CanisterHttpResponseContent`.
pub mod canister_http_response_content {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Status {
        #[prost(message, tag = "2")]
        Reject(super::CanisterHttpReject),
        #[prost(bytes, tag = "3")]
        Success(::prost::alloc::vec::Vec<u8>),
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterHttpReject {
    #[prost(uint32, tag = "1")]
    pub reject_code: u32,
    #[prost(string, tag = "2")]
    pub message: ::prost::alloc::string::String,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterHttpResponseSignature {
    #[prost(bytes = "vec", tag = "1")]
    pub signer: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterHttpResponseWithConsensus {
    #[prost(message, optional, tag = "1")]
    pub response: ::core::option::Option<CanisterHttpResponse>,
    #[prost(bytes = "vec", tag = "2")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub registry_version: u64,
    #[prost(message, repeated, tag = "7")]
    pub signatures: ::prost::alloc::vec::Vec<CanisterHttpResponseSignature>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterHttpShare {
    #[prost(message, optional, tag = "1")]
    pub metadata: ::core::option::Option<CanisterHttpResponseMetadata>,
    #[prost(message, optional, tag = "2")]
    pub signature: ::core::option::Option<CanisterHttpResponseSignature>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterHttpResponseDivergence {
    #[prost(message, repeated, tag = "1")]
    pub shares: ::prost::alloc::vec::Vec<CanisterHttpShare>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterHttpResponseMessage {
    #[prost(
        oneof = "canister_http_response_message::MessageType",
        tags = "1, 2, 3"
    )]
    pub message_type: ::core::option::Option<canister_http_response_message::MessageType>,
}
/// Nested message and enum types in `CanisterHttpResponseMessage`.
pub mod canister_http_response_message {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum MessageType {
        #[prost(message, tag = "1")]
        Response(super::CanisterHttpResponseWithConsensus),
        #[prost(uint64, tag = "2")]
        Timeout(u64),
        #[prost(message, tag = "3")]
        DivergenceResponse(super::CanisterHttpResponseDivergence),
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ArtifactAttribute {
    #[prost(oneof = "artifact_attribute::Kind", tags = "1, 3, 5")]
    pub kind: ::core::option::Option<artifact_attribute::Kind>,
}
/// Nested message and enum types in `ArtifactAttribute`.
pub mod artifact_attribute {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "1")]
        ConsensusMessage(super::ConsensusMessageAttribute),
        #[prost(message, tag = "3")]
        EcdsaMessage(super::EcdsaMessageAttribute),
        #[prost(message, tag = "5")]
        Empty(()),
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsensusMessageAttribute {
    #[prost(oneof = "consensus_message_attribute::Kind", tags = "2, 3, 12")]
    pub kind: ::core::option::Option<consensus_message_attribute::Kind>,
}
/// Nested message and enum types in `ConsensusMessageAttribute`.
pub mod consensus_message_attribute {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "2")]
        Finalization(super::FinalizationAttribute),
        #[prost(message, tag = "3")]
        Notarization(super::NotarizationAttribute),
        #[prost(message, tag = "12")]
        Empty(()),
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FinalizationAttribute {
    #[prost(bytes = "vec", tag = "1")]
    pub block_hash: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NotarizationAttribute {
    #[prost(bytes = "vec", tag = "1")]
    pub block_hash: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaMessageAttribute {
    #[prost(oneof = "ecdsa_message_attribute::Kind", tags = "1, 2, 3, 4, 5")]
    pub kind: ::core::option::Option<ecdsa_message_attribute::Kind>,
}
/// Nested message and enum types in `EcdsaMessageAttribute`.
pub mod ecdsa_message_attribute {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "1")]
        SignedDealing(super::super::super::registry::subnet::v1::IDkgTranscriptId),
        #[prost(message, tag = "2")]
        DealingSupport(super::super::super::registry::subnet::v1::IDkgTranscriptId),
        #[prost(message, tag = "3")]
        SigShare(super::RequestId),
        #[prost(message, tag = "4")]
        Complaint(super::super::super::registry::subnet::v1::IDkgTranscriptId),
        #[prost(message, tag = "5")]
        Opening(super::super::super::registry::subnet::v1::IDkgTranscriptId),
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ArtifactId {
    #[prost(oneof = "artifact_id::Kind", tags = "1, 2, 3, 11, 10, 6, 7")]
    pub kind: ::core::option::Option<artifact_id::Kind>,
}
/// Nested message and enum types in `ArtifactId`.
pub mod artifact_id {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "1")]
        Consensus(super::ConsensusMessageId),
        #[prost(message, tag = "2")]
        Ingress(super::IngressMessageId),
        #[prost(message, tag = "3")]
        Certification(super::CertificationMessageId),
        #[prost(message, tag = "11")]
        CanisterHttp(super::CanisterHttpShare),
        #[prost(message, tag = "10")]
        DkgMessage(super::DkgMessageId),
        #[prost(message, tag = "6")]
        Ecdsa(super::EcdsaArtifactId),
        #[prost(string, tag = "7")]
        FileTreeSync(::prost::alloc::string::String),
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DkgMessageId {
    #[prost(bytes = "vec", tag = "1")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub height: u64,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsensusMessageId {
    #[prost(message, optional, tag = "1")]
    pub hash: ::core::option::Option<ConsensusMessageHash>,
    #[prost(uint64, tag = "2")]
    pub height: u64,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsensusMessageHash {
    #[prost(
        oneof = "consensus_message_hash::Kind",
        tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11"
    )]
    pub kind: ::core::option::Option<consensus_message_hash::Kind>,
}
/// Nested message and enum types in `ConsensusMessageHash`.
pub mod consensus_message_hash {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        #[prost(bytes, tag = "1")]
        RandomBeacon(::prost::alloc::vec::Vec<u8>),
        #[prost(bytes, tag = "2")]
        Finalization(::prost::alloc::vec::Vec<u8>),
        #[prost(bytes, tag = "3")]
        Notarization(::prost::alloc::vec::Vec<u8>),
        #[prost(bytes, tag = "4")]
        BlockProposal(::prost::alloc::vec::Vec<u8>),
        #[prost(bytes, tag = "5")]
        RandomBeaconShare(::prost::alloc::vec::Vec<u8>),
        #[prost(bytes, tag = "6")]
        NotarizationShare(::prost::alloc::vec::Vec<u8>),
        #[prost(bytes, tag = "7")]
        FinalizationShare(::prost::alloc::vec::Vec<u8>),
        #[prost(bytes, tag = "8")]
        RandomTape(::prost::alloc::vec::Vec<u8>),
        #[prost(bytes, tag = "9")]
        RandomTapeShare(::prost::alloc::vec::Vec<u8>),
        #[prost(bytes, tag = "10")]
        CatchUpPackage(::prost::alloc::vec::Vec<u8>),
        #[prost(bytes, tag = "11")]
        CatchUpPackageShare(::prost::alloc::vec::Vec<u8>),
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IngressMessageId {
    #[prost(uint64, tag = "1")]
    pub expiry: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub message_id: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CertificationMessageId {
    #[prost(message, optional, tag = "1")]
    pub hash: ::core::option::Option<CertificationMessageHash>,
    #[prost(uint64, tag = "2")]
    pub height: u64,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CertificationMessageHash {
    #[prost(oneof = "certification_message_hash::Kind", tags = "1, 2")]
    pub kind: ::core::option::Option<certification_message_hash::Kind>,
}
/// Nested message and enum types in `CertificationMessageHash`.
pub mod certification_message_hash {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        #[prost(bytes, tag = "1")]
        Certification(::prost::alloc::vec::Vec<u8>),
        #[prost(bytes, tag = "2")]
        CertificationShare(::prost::alloc::vec::Vec<u8>),
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::large_enum_variant)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GossipMessage {
    #[prost(oneof = "gossip_message::Body", tags = "1, 2, 3, 5")]
    pub body: ::core::option::Option<gossip_message::Body>,
}
/// Nested message and enum types in `GossipMessage`.
pub mod gossip_message {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[allow(clippy::large_enum_variant)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Body {
        #[prost(message, tag = "1")]
        Advert(super::GossipAdvert),
        #[prost(message, tag = "2")]
        ChunkRequest(super::GossipChunkRequest),
        #[prost(message, tag = "3")]
        Chunk(super::GossipChunk),
        #[prost(message, tag = "5")]
        RetransmissionRequest(super::ArtifactFilter),
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GossipAdvert {
    #[prost(message, optional, tag = "5")]
    pub attribute: ::core::option::Option<ArtifactAttribute>,
    #[prost(uint64, tag = "2")]
    pub size: u64,
    #[prost(message, optional, tag = "6")]
    pub artifact_id: ::core::option::Option<ArtifactId>,
    #[prost(bytes = "vec", tag = "4")]
    pub integrity_hash: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GossipChunkRequest {
    #[prost(message, optional, tag = "4")]
    pub artifact_id: ::core::option::Option<ArtifactId>,
    #[prost(uint32, tag = "2")]
    pub chunk_id: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub integrity_hash: ::prost::alloc::vec::Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::large_enum_variant)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GossipChunk {
    #[prost(message, optional, tag = "6")]
    pub request: ::core::option::Option<GossipChunkRequest>,
    #[prost(oneof = "gossip_chunk::Response", tags = "7, 4")]
    pub response: ::core::option::Option<gossip_chunk::Response>,
}
/// Nested message and enum types in `GossipChunk`.
pub mod gossip_chunk {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[allow(clippy::large_enum_variant)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Response {
        #[prost(message, tag = "7")]
        Artifact(super::Artifact),
        #[prost(enumeration = "super::P2pError", tag = "4")]
        Error(i32),
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ArtifactFilter {
    #[prost(message, optional, tag = "6")]
    pub consensus_filter: ::core::option::Option<ConsensusMessageFilter>,
    #[prost(message, optional, tag = "7")]
    pub certification_message_filter: ::core::option::Option<CertificationMessageFilter>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsensusMessageFilter {
    #[prost(uint64, tag = "1")]
    pub height: u64,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CertificationMessageFilter {
    #[prost(uint64, tag = "1")]
    pub height: u64,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FileTreeSyncArtifact {
    /// UNIX-compatible path
    #[prost(bytes = "vec", tag = "1")]
    pub absolute_path: ::prost::alloc::vec::Vec<u8>,
    #[prost(string, tag = "2")]
    pub id: ::prost::alloc::string::String,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[allow(clippy::large_enum_variant)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Artifact {
    #[prost(oneof = "artifact::Kind", tags = "1, 2, 3, 4, 5, 6, 7")]
    pub kind: ::core::option::Option<artifact::Kind>,
}
/// Nested message and enum types in `Artifact`.
pub mod artifact {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[allow(clippy::large_enum_variant)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "1")]
        Consensus(super::ConsensusMessage),
        /// CBOR-encoded signed ingress message
        #[prost(bytes, tag = "2")]
        SignedIngress(::prost::alloc::vec::Vec<u8>),
        #[prost(message, tag = "3")]
        Certification(super::CertificationMessage),
        #[prost(message, tag = "4")]
        Dkg(super::DkgMessage),
        #[prost(message, tag = "5")]
        Ecdsa(super::EcdsaMessage),
        #[prost(message, tag = "6")]
        HttpShare(super::CanisterHttpShare),
        #[prost(message, tag = "7")]
        FileTreeSync(super::FileTreeSyncArtifact),
    }
}
#[derive(
    serde::Serialize,
    serde::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    ::prost::Enumeration,
)]
#[repr(i32)]
pub enum P2pError {
    Unspecified = 0,
    NotFound = 1,
}
impl P2pError {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            P2pError::Unspecified => "P2P_ERROR_UNSPECIFIED",
            P2pError::NotFound => "P2P_ERROR_NOT_FOUND",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "P2P_ERROR_UNSPECIFIED" => Some(Self::Unspecified),
            "P2P_ERROR_NOT_FOUND" => Some(Self::NotFound),
            _ => None,
        }
    }
}
