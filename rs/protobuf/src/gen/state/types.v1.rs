#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PrincipalId {
    #[prost(bytes = "vec", tag = "1")]
    pub raw: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterId {
    #[prost(message, optional, tag = "1")]
    pub principal_id: ::core::option::Option<PrincipalId>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetId {
    #[prost(message, optional, tag = "1")]
    pub principal_id: ::core::option::Option<PrincipalId>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UserId {
    #[prost(message, optional, tag = "1")]
    pub principal_id: ::core::option::Option<PrincipalId>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeId {
    #[prost(message, optional, tag = "1")]
    pub principal_id: ::core::option::Option<PrincipalId>,
}
/// A non-interactive distributed key generation (NI-DKG) ID.
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
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NominalCycles {
    #[prost(uint64, tag = "1")]
    pub high: u64,
    #[prost(uint64, tag = "2")]
    pub low: u64,
}
/// A non-interactive distributed key generation (NI-DKG) tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum RejectCode {
    Unspecified = 0,
    SysFatal = 1,
    SysTransient = 2,
    DestinationInvalid = 3,
    CanisterReject = 4,
    CanisterError = 5,
}
impl RejectCode {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            RejectCode::Unspecified => "REJECT_CODE_UNSPECIFIED",
            RejectCode::SysFatal => "REJECT_CODE_SYS_FATAL",
            RejectCode::SysTransient => "REJECT_CODE_SYS_TRANSIENT",
            RejectCode::DestinationInvalid => "REJECT_CODE_DESTINATION_INVALID",
            RejectCode::CanisterReject => "REJECT_CODE_CANISTER_REJECT",
            RejectCode::CanisterError => "REJECT_CODE_CANISTER_ERROR",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "REJECT_CODE_UNSPECIFIED" => Some(Self::Unspecified),
            "REJECT_CODE_SYS_FATAL" => Some(Self::SysFatal),
            "REJECT_CODE_SYS_TRANSIENT" => Some(Self::SysTransient),
            "REJECT_CODE_DESTINATION_INVALID" => Some(Self::DestinationInvalid),
            "REJECT_CODE_CANISTER_REJECT" => Some(Self::CanisterReject),
            "REJECT_CODE_CANISTER_ERROR" => Some(Self::CanisterError),
            _ => None,
        }
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterUpgradeOptions {
    #[prost(bool, optional, tag = "1")]
    pub skip_pre_upgrade: ::core::option::Option<bool>,
    #[prost(enumeration = "WasmMemoryPersistence", optional, tag = "2")]
    pub wasm_memory_persistence: ::core::option::Option<i32>,
}
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
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum CanisterInstallModeV2 {
        #[prost(enumeration = "super::CanisterInstallMode", tag = "1")]
        Mode(i32),
        #[prost(message, tag = "2")]
        Mode2(super::CanisterUpgradeOptions),
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum WasmMemoryPersistence {
    Unspecified = 0,
    Keep = 1,
    Replace = 2,
}
impl WasmMemoryPersistence {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            WasmMemoryPersistence::Unspecified => "WASM_MEMORY_PERSISTENCE_UNSPECIFIED",
            WasmMemoryPersistence::Keep => "WASM_MEMORY_PERSISTENCE_KEEP",
            WasmMemoryPersistence::Replace => "WASM_MEMORY_PERSISTENCE_REPLACE",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "WASM_MEMORY_PERSISTENCE_UNSPECIFIED" => Some(Self::Unspecified),
            "WASM_MEMORY_PERSISTENCE_KEEP" => Some(Self::Keep),
            "WASM_MEMORY_PERSISTENCE_REPLACE" => Some(Self::Replace),
            _ => None,
        }
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BasicSignature {
    #[prost(bytes = "vec", tag = "1")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "2")]
    pub signer: ::core::option::Option<NodeId>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ThresholdSignature {
    #[prost(bytes = "vec", tag = "1")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "2")]
    pub signer: ::core::option::Option<NiDkgId>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ThresholdSignatureShare {
    #[prost(bytes = "vec", tag = "1")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "2")]
    pub signer: ::core::option::Option<NodeId>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IDkgPayload {
    #[prost(message, repeated, tag = "1")]
    pub signature_agreements: ::prost::alloc::vec::Vec<CompletedSignature>,
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
    pub next_unused_pre_signature_id: u64,
    #[prost(message, repeated, tag = "13")]
    pub key_transcripts: ::prost::alloc::vec::Vec<MasterKeyTranscript>,
    #[prost(message, repeated, tag = "14")]
    pub available_pre_signatures: ::prost::alloc::vec::Vec<AvailablePreSignature>,
    #[prost(message, repeated, tag = "15")]
    pub pre_signatures_in_creation: ::prost::alloc::vec::Vec<PreSignatureInProgress>,
    #[prost(message, repeated, tag = "17")]
    pub prev_key_transcript_refs: ::prost::alloc::vec::Vec<TranscriptRef>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsensusResponse {
    #[prost(uint64, tag = "3")]
    pub callback: u64,
    #[prost(oneof = "consensus_response::Payload", tags = "5, 6")]
    pub payload: ::core::option::Option<consensus_response::Payload>,
}
/// Nested message and enum types in `ConsensusResponse`.
pub mod consensus_response {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Payload {
        #[prost(bytes, tag = "5")]
        Data(::prost::alloc::vec::Vec<u8>),
        #[prost(message, tag = "6")]
        Reject(super::super::super::state::queues::v1::RejectContext),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MasterKeyTranscript {
    #[prost(message, optional, tag = "2")]
    pub current: ::core::option::Option<UnmaskedTranscriptWithAttributes>,
    #[prost(message, optional, tag = "3")]
    pub next_in_creation: ::core::option::Option<KeyTranscriptCreation>,
    #[prost(message, optional, tag = "4")]
    pub master_key_id:
        ::core::option::Option<super::super::registry::crypto::v1::MasterPublicKeyId>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AvailablePreSignature {
    #[prost(uint64, tag = "1")]
    pub pre_signature_id: u64,
    #[prost(message, optional, tag = "2")]
    pub pre_signature: ::core::option::Option<PreSignatureRef>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PreSignatureInProgress {
    #[prost(uint64, tag = "1")]
    pub pre_signature_id: u64,
    #[prost(message, optional, tag = "2")]
    pub pre_signature: ::core::option::Option<PreSignatureInCreation>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OngoingXnetReshare {
    #[prost(message, optional, tag = "1")]
    pub request: ::core::option::Option<IDkgReshareRequest>,
    #[prost(message, optional, tag = "2")]
    pub transcript: ::core::option::Option<ReshareOfUnmaskedParams>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct XnetReshareAgreement {
    #[prost(message, optional, tag = "1")]
    pub request: ::core::option::Option<IDkgReshareRequest>,
    #[prost(message, optional, tag = "4")]
    pub initial_dealings: ::core::option::Option<ConsensusResponse>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RequestId {
    #[prost(bytes = "vec", tag = "1")]
    pub pseudo_random_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub pre_signature_id: u64,
    #[prost(uint64, tag = "3")]
    pub height: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TranscriptRef {
    #[prost(uint64, tag = "1")]
    pub height: u64,
    #[prost(message, optional, tag = "2")]
    pub transcript_id: ::core::option::Option<super::super::registry::subnet::v1::IDkgTranscriptId>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MaskedTranscript {
    #[prost(message, optional, tag = "1")]
    pub transcript_ref: ::core::option::Option<TranscriptRef>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UnmaskedTranscript {
    #[prost(message, optional, tag = "1")]
    pub transcript_ref: ::core::option::Option<TranscriptRef>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UnmaskedTranscriptWithAttributes {
    #[prost(message, optional, tag = "1")]
    pub transcript_ref: ::core::option::Option<TranscriptRef>,
    #[prost(message, optional, tag = "2")]
    pub attributes: ::core::option::Option<IDkgTranscriptAttributes>,
}
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
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RandomTranscriptParams {
    #[prost(message, optional, tag = "1")]
    pub transcript_ref: ::core::option::Option<IDkgTranscriptParamsRef>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RandomUnmaskedTranscriptParams {
    #[prost(message, optional, tag = "1")]
    pub transcript_ref: ::core::option::Option<IDkgTranscriptParamsRef>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReshareOfMaskedParams {
    #[prost(message, optional, tag = "1")]
    pub transcript_ref: ::core::option::Option<IDkgTranscriptParamsRef>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReshareOfUnmaskedParams {
    #[prost(message, optional, tag = "1")]
    pub transcript_ref: ::core::option::Option<IDkgTranscriptParamsRef>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UnmaskedTimesMaskedParams {
    #[prost(message, optional, tag = "1")]
    pub transcript_ref: ::core::option::Option<IDkgTranscriptParamsRef>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PreSignatureInCreation {
    #[prost(oneof = "pre_signature_in_creation::Msg", tags = "1, 2")]
    pub msg: ::core::option::Option<pre_signature_in_creation::Msg>,
}
/// Nested message and enum types in `PreSignatureInCreation`.
pub mod pre_signature_in_creation {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Msg {
        #[prost(message, tag = "1")]
        Ecdsa(super::QuadrupleInCreation),
        #[prost(message, tag = "2")]
        Schnorr(super::TranscriptInCreation),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PreSignatureRef {
    #[prost(oneof = "pre_signature_ref::Msg", tags = "1, 2")]
    pub msg: ::core::option::Option<pre_signature_ref::Msg>,
}
/// Nested message and enum types in `PreSignatureRef`.
pub mod pre_signature_ref {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Msg {
        #[prost(message, tag = "1")]
        Ecdsa(super::PreSignatureQuadrupleRef),
        #[prost(message, tag = "2")]
        Schnorr(super::PreSignatureTranscriptRef),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaDeliveredPreSignature {
    #[prost(uint64, tag = "1")]
    pub pre_signature_id: u64,
    #[prost(uint64, tag = "2")]
    pub height: u64,
    #[prost(message, optional, tag = "3")]
    pub pre_signature: ::core::option::Option<PreSignatureQuadruple>,
    #[prost(message, optional, tag = "4")]
    pub key_transcript: ::core::option::Option<super::super::registry::subnet::v1::IDkgTranscript>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SchnorrDeliveredPreSignature {
    #[prost(uint64, tag = "1")]
    pub pre_signature_id: u64,
    #[prost(uint64, tag = "2")]
    pub height: u64,
    #[prost(message, optional, tag = "3")]
    pub pre_signature: ::core::option::Option<PreSignatureTranscript>,
    #[prost(message, optional, tag = "4")]
    pub key_transcript: ::core::option::Option<super::super::registry::subnet::v1::IDkgTranscript>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PreSignatureQuadruple {
    #[prost(message, optional, tag = "1")]
    pub kappa_unmasked: ::core::option::Option<super::super::registry::subnet::v1::IDkgTranscript>,
    #[prost(message, optional, tag = "2")]
    pub lambda_masked: ::core::option::Option<super::super::registry::subnet::v1::IDkgTranscript>,
    #[prost(message, optional, tag = "3")]
    pub kappa_times_lambda:
        ::core::option::Option<super::super::registry::subnet::v1::IDkgTranscript>,
    #[prost(message, optional, tag = "4")]
    pub key_times_lambda:
        ::core::option::Option<super::super::registry::subnet::v1::IDkgTranscript>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PreSignatureTranscript {
    #[prost(message, optional, tag = "1")]
    pub blinder_unmasked:
        ::core::option::Option<super::super::registry::subnet::v1::IDkgTranscript>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PreSignature {
    #[prost(oneof = "pre_signature::Msg", tags = "1, 2")]
    pub msg: ::core::option::Option<pre_signature::Msg>,
}
/// Nested message and enum types in `PreSignature`.
pub mod pre_signature {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Msg {
        #[prost(message, tag = "1")]
        Ecdsa(super::PreSignatureQuadruple),
        #[prost(message, tag = "2")]
        Schnorr(super::PreSignatureTranscript),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QuadrupleInCreation {
    #[prost(message, optional, tag = "3")]
    pub lambda_config: ::core::option::Option<RandomTranscriptParams>,
    #[prost(message, optional, tag = "4")]
    pub lambda_masked: ::core::option::Option<MaskedTranscript>,
    #[prost(message, optional, tag = "11")]
    pub kappa_unmasked_config: ::core::option::Option<RandomUnmaskedTranscriptParams>,
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
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TranscriptInCreation {
    #[prost(message, optional, tag = "1")]
    pub key_id: ::core::option::Option<super::super::registry::crypto::v1::SchnorrKeyId>,
    #[prost(message, optional, tag = "2")]
    pub blinder_unmasked_config: ::core::option::Option<RandomUnmaskedTranscriptParams>,
    #[prost(message, optional, tag = "3")]
    pub blinder_unmasked: ::core::option::Option<UnmaskedTranscript>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PreSignatureTranscriptRef {
    #[prost(message, optional, tag = "1")]
    pub key_id: ::core::option::Option<super::super::registry::crypto::v1::SchnorrKeyId>,
    #[prost(message, optional, tag = "2")]
    pub blinder_unmasked_ref: ::core::option::Option<UnmaskedTranscript>,
    #[prost(message, optional, tag = "3")]
    pub key_unmasked_ref: ::core::option::Option<UnmaskedTranscript>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CompletedSignature {
    #[prost(message, optional, tag = "3")]
    pub unreported: ::core::option::Option<ConsensusResponse>,
    #[prost(bytes = "vec", tag = "4")]
    pub pseudo_random_id: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IDkgReshareRequest {
    #[prost(message, repeated, tag = "2")]
    pub receiving_node_ids: ::prost::alloc::vec::Vec<NodeId>,
    #[prost(uint64, tag = "3")]
    pub registry_version: u64,
    #[prost(message, optional, tag = "5")]
    pub master_key_id:
        ::core::option::Option<super::super::registry::crypto::v1::MasterPublicKeyId>,
}
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
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IDkgMessage {
    #[prost(oneof = "i_dkg_message::Msg", tags = "1, 2, 3, 4, 5, 6")]
    pub msg: ::core::option::Option<i_dkg_message::Msg>,
}
/// Nested message and enum types in `IDkgMessage`.
pub mod i_dkg_message {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Msg {
        #[prost(message, tag = "1")]
        SignedDealing(super::super::super::registry::subnet::v1::IDkgSignedDealingTuple),
        #[prost(message, tag = "2")]
        DealingSupport(super::IDkgDealingSupport),
        #[prost(message, tag = "3")]
        EcdsaSigShare(super::EcdsaSigShare),
        #[prost(message, tag = "4")]
        Complaint(super::SignedIDkgComplaint),
        #[prost(message, tag = "5")]
        Opening(super::SignedIDkgOpening),
        #[prost(message, tag = "6")]
        SchnorrSigShare(super::SchnorrSigShare),
    }
}
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
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SchnorrSigShare {
    #[prost(message, optional, tag = "1")]
    pub signer_id: ::core::option::Option<NodeId>,
    #[prost(message, optional, tag = "2")]
    pub request_id: ::core::option::Option<RequestId>,
    #[prost(bytes = "vec", tag = "3")]
    pub sig_share_raw: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignedIDkgComplaint {
    #[prost(message, optional, tag = "1")]
    pub content: ::core::option::Option<IDkgComplaintContent>,
    #[prost(message, optional, tag = "2")]
    pub signature: ::core::option::Option<BasicSignature>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IDkgComplaintContent {
    #[prost(message, optional, tag = "1")]
    pub idkg_complaint: ::core::option::Option<super::super::registry::subnet::v1::IDkgComplaint>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignedIDkgOpening {
    #[prost(message, optional, tag = "1")]
    pub content: ::core::option::Option<IDkgOpeningContent>,
    #[prost(message, optional, tag = "2")]
    pub signature: ::core::option::Option<BasicSignature>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IDkgOpeningContent {
    #[prost(message, optional, tag = "1")]
    pub idkg_opening: ::core::option::Option<super::super::registry::subnet::v1::IDkgOpening>,
}
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
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IDkgPrefix {
    #[prost(uint64, tag = "1")]
    pub group_tag: u64,
    #[prost(uint64, tag = "2")]
    pub meta_hash: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IDkgArtifactIdData {
    #[prost(uint64, tag = "1")]
    pub height: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub subnet_id: ::core::option::Option<SubnetId>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SigShareIdData {
    #[prost(uint64, tag = "1")]
    pub height: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PrefixPairIDkg {
    #[prost(message, optional, tag = "1")]
    pub prefix: ::core::option::Option<IDkgPrefix>,
    #[prost(message, optional, tag = "2")]
    pub id_data: ::core::option::Option<IDkgArtifactIdData>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PrefixPairSigShare {
    #[prost(message, optional, tag = "1")]
    pub prefix: ::core::option::Option<IDkgPrefix>,
    #[prost(message, optional, tag = "2")]
    pub id_data: ::core::option::Option<SigShareIdData>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IDkgArtifactId {
    #[prost(oneof = "i_dkg_artifact_id::Kind", tags = "1, 2, 3, 4, 5, 6")]
    pub kind: ::core::option::Option<i_dkg_artifact_id::Kind>,
}
/// Nested message and enum types in `IDkgArtifactId`.
pub mod i_dkg_artifact_id {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "1")]
        Dealing(super::PrefixPairIDkg),
        #[prost(message, tag = "2")]
        DealingSupport(super::PrefixPairIDkg),
        #[prost(message, tag = "3")]
        EcdsaSigShare(super::PrefixPairSigShare),
        #[prost(message, tag = "4")]
        Complaint(super::PrefixPairIDkg),
        #[prost(message, tag = "5")]
        Opening(super::PrefixPairIDkg),
        #[prost(message, tag = "6")]
        SchnorrSigShare(super::PrefixPairSigShare),
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
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
