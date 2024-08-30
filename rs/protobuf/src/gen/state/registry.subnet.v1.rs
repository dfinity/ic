/// A subnet: A logical group of nodes that run consensus
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetRecord {
    /// The IDs of the nodes that are part of this subnet.
    #[prost(bytes = "vec", repeated, tag = "3")]
    pub membership: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    /// Maximum amount of bytes per message. This is a hard cap, which means
    /// ingress messages greater than the limit will be dropped.
    #[prost(uint64, tag = "5")]
    pub max_ingress_bytes_per_message: u64,
    /// Unit delay for blockmaker (in milliseconds).
    #[prost(uint64, tag = "7")]
    pub unit_delay_millis: u64,
    /// Initial delay for notary (in milliseconds), to give time to rank-0 block
    /// propagation.
    #[prost(uint64, tag = "8")]
    pub initial_notary_delay_millis: u64,
    /// ID of the Replica version to run
    #[prost(string, tag = "9")]
    pub replica_version_id: ::prost::alloc::string::String,
    /// The length of all DKG intervals. The DKG interval length is the number of rounds following the DKG summary.
    #[prost(uint64, tag = "10")]
    pub dkg_interval_length: u64,
    /// If set to yes, the subnet starts as a (new) NNS
    #[prost(bool, tag = "14")]
    pub start_as_nns: bool,
    /// The type of subnet.
    #[prost(enumeration = "SubnetType", tag = "15")]
    pub subnet_type: i32,
    /// The upper bound for the number of dealings we allow in a block.
    #[prost(uint64, tag = "16")]
    pub dkg_dealings_per_block: u64,
    /// If `true`, the subnet will be halted: it will no longer create or execute blocks.
    #[prost(bool, tag = "17")]
    pub is_halted: bool,
    /// Max number of ingress messages per block.
    #[prost(uint64, tag = "18")]
    pub max_ingress_messages_per_block: u64,
    /// The maximum combined size of the ingress and xnet messages that fit into a block.
    #[prost(uint64, tag = "19")]
    pub max_block_payload_size: u64,
    /// Information on whether a feature is supported by this subnet.
    #[prost(message, optional, tag = "23")]
    pub features: ::core::option::Option<SubnetFeatures>,
    /// The maximum number of canisters that may be present on the subnet at any given time.
    ///
    /// A value of 0 is equivalent to setting no limit. This also provides an easy way
    /// to maintain compatibility of different versions of replica and registry.
    #[prost(uint64, tag = "24")]
    pub max_number_of_canisters: u64,
    /// The list of public keys whose owners have "readonly" SSH access to all replicas on this subnet,
    /// in case it is necessary to perform subnet recovery.
    #[prost(string, repeated, tag = "25")]
    pub ssh_readonly_access: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// The list of public keys whose owners have "backup" SSH access to nodes on the NNS subnet
    /// to make sure the NNS can be backed up.
    #[prost(string, repeated, tag = "26")]
    pub ssh_backup_access: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// ECDSA Config. This field cannot be set back to `None` once it has been set
    /// to `Some`. To remove a key, the list of `key_ids` can be set to not include a particular key.
    /// If a removed key is not held by another subnet, it will be lost.
    ///
    /// Deprecated; please use chain_key_config instead.
    #[prost(message, optional, tag = "27")]
    pub ecdsa_config: ::core::option::Option<EcdsaConfig>,
    /// If `true`, the subnet will be halted after reaching the next cup height: it will no longer
    /// create or execute blocks.
    ///
    /// Note: this flag is reset automatically when a new CUP proposal is approved. When that
    /// happens, the `is_halted` flag is set to `true`, so the Subnet remains halted until an
    /// appropriate proposal which sets `is_halted` to `false` is approved.
    #[prost(bool, tag = "28")]
    pub halt_at_cup_height: bool,
    /// Cryptographic key configuration. This field cannot be set back to `None` once it has been set
    /// to `Some`. To remove a key, the list of `key_configs` can be set to not include a particular
    /// key. If the removed key is not held by another subnet, it will be lost.
    #[prost(message, optional, tag = "29")]
    pub chain_key_config: ::core::option::Option<ChainKeyConfig>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaInitialization {
    #[prost(message, optional, tag = "1")]
    pub key_id: ::core::option::Option<super::super::crypto::v1::EcdsaKeyId>,
    #[prost(message, optional, tag = "2")]
    pub dealings: ::core::option::Option<InitialIDkgDealings>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChainKeyInitialization {
    #[prost(message, optional, tag = "1")]
    pub key_id: ::core::option::Option<super::super::crypto::v1::MasterPublicKeyId>,
    #[prost(message, optional, tag = "2")]
    pub dealings: ::core::option::Option<InitialIDkgDealings>,
}
/// Contains the initial DKG transcripts for the subnet and materials to construct a base CUP (i.e.
/// a CUP with no dependencies on previous CUPs or blocks). Such CUP materials can be used to
/// construct the genesis CUP or a recovery CUP in the event of a subnet stall.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CatchUpPackageContents {
    /// Initial non-interactive low-threshold DKG transcript
    #[prost(message, optional, tag = "1")]
    pub initial_ni_dkg_transcript_low_threshold:
        ::core::option::Option<InitialNiDkgTranscriptRecord>,
    /// Initial non-interactive high-threshold DKG transcript
    #[prost(message, optional, tag = "2")]
    pub initial_ni_dkg_transcript_high_threshold:
        ::core::option::Option<InitialNiDkgTranscriptRecord>,
    /// The blockchain height that the CUP should have
    #[prost(uint64, tag = "3")]
    pub height: u64,
    /// Block time for the CUP's block
    #[prost(uint64, tag = "4")]
    pub time: u64,
    /// The hash of the state that the subnet should use
    #[prost(bytes = "vec", tag = "5")]
    pub state_hash: ::prost::alloc::vec::Vec<u8>,
    /// A uri from which data to replace the registry local store should be downloaded
    #[prost(message, optional, tag = "6")]
    pub registry_store_uri: ::core::option::Option<RegistryStoreUri>,
    /// / The initial ECDSA dealings for boot strapping target subnets.
    #[prost(message, repeated, tag = "7")]
    pub ecdsa_initializations: ::prost::alloc::vec::Vec<EcdsaInitialization>,
    /// / The initial IDkg dealings for boot strapping target chain key subnets.
    #[prost(message, repeated, tag = "8")]
    pub chain_key_initializations: ::prost::alloc::vec::Vec<ChainKeyInitialization>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegistryStoreUri {
    /// / The uri at which the registry store data should be retrieved. The data
    /// / must be provided as gzipped tar archive
    #[prost(string, tag = "1")]
    pub uri: ::prost::alloc::string::String,
    /// / A SHA-256, hex encoded hash of the contents of the data stored at the
    /// / provided URI
    #[prost(string, tag = "2")]
    pub hash: ::prost::alloc::string::String,
    /// / The registry version that should be used for the catch up package contents
    #[prost(uint64, tag = "3")]
    pub registry_version: u64,
}
/// Contains information pertaining to all subnets in the IC and their params.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetListRecord {
    /// A list of subnet ids of all subnets present in this instance of the IC.
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub subnets: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
/// Initial non-interactive DKG transcript record
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InitialNiDkgTranscriptRecord {
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<super::super::super::types::v1::NiDkgId>,
    #[prost(uint32, tag = "2")]
    pub threshold: u32,
    #[prost(bytes = "vec", repeated, tag = "3")]
    pub committee: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(uint64, tag = "4")]
    pub registry_version: u64,
    #[prost(bytes = "vec", tag = "5")]
    pub internal_csp_transcript: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IDkgTranscriptId {
    #[prost(uint64, tag = "1")]
    pub id: u64,
    #[prost(message, optional, tag = "2")]
    pub subnet_id: ::core::option::Option<super::super::super::types::v1::SubnetId>,
    #[prost(uint64, tag = "3")]
    pub source_height: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VerifiedIDkgDealing {
    #[prost(uint32, tag = "1")]
    pub dealer_index: u32,
    #[prost(message, optional, tag = "6")]
    pub signed_dealing_tuple: ::core::option::Option<IDkgSignedDealingTuple>,
    #[prost(message, repeated, tag = "7")]
    pub support_tuples: ::prost::alloc::vec::Vec<SignatureTuple>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IDkgTranscript {
    #[prost(message, optional, tag = "1")]
    pub transcript_id: ::core::option::Option<IDkgTranscriptId>,
    #[prost(message, repeated, tag = "2")]
    pub dealers: ::prost::alloc::vec::Vec<super::super::super::types::v1::NodeId>,
    #[prost(message, repeated, tag = "3")]
    pub receivers: ::prost::alloc::vec::Vec<super::super::super::types::v1::NodeId>,
    #[prost(uint64, tag = "4")]
    pub registry_version: u64,
    #[prost(message, repeated, tag = "5")]
    pub verified_dealings: ::prost::alloc::vec::Vec<VerifiedIDkgDealing>,
    /// CBOR serialized IDkgTranscriptType
    #[prost(bytes = "vec", tag = "6")]
    pub transcript_type: ::prost::alloc::vec::Vec<u8>,
    #[prost(enumeration = "super::super::crypto::v1::AlgorithmId", tag = "7")]
    pub algorithm_id: i32,
    /// serialised InternalRawTranscript
    #[prost(bytes = "vec", tag = "8")]
    pub raw_transcript: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DealerTuple {
    #[prost(message, optional, tag = "1")]
    pub dealer_id: ::core::option::Option<super::super::super::types::v1::NodeId>,
    #[prost(uint32, tag = "2")]
    pub dealer_index: u32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignatureTuple {
    #[prost(message, optional, tag = "1")]
    pub signer: ::core::option::Option<super::super::super::types::v1::NodeId>,
    #[prost(bytes = "vec", tag = "2")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IDkgTranscriptParams {
    #[prost(message, optional, tag = "1")]
    pub transcript_id: ::core::option::Option<IDkgTranscriptId>,
    #[prost(message, repeated, tag = "2")]
    pub dealers: ::prost::alloc::vec::Vec<DealerTuple>,
    #[prost(message, repeated, tag = "3")]
    pub receivers: ::prost::alloc::vec::Vec<super::super::super::types::v1::NodeId>,
    #[prost(uint64, tag = "4")]
    pub registry_version: u64,
    #[prost(enumeration = "super::super::crypto::v1::AlgorithmId", tag = "5")]
    pub algorithm_id: i32,
    #[prost(enumeration = "IDkgTranscriptOperation", tag = "6")]
    pub idkg_transcript_operation: i32,
    /// 0, 1, or 2 IDkgTranscripts
    #[prost(message, repeated, tag = "7")]
    pub idkg_transcript_operation_args: ::prost::alloc::vec::Vec<IDkgTranscript>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IDkgDealing {
    #[prost(message, optional, tag = "1")]
    pub transcript_id: ::core::option::Option<IDkgTranscriptId>,
    /// serialised InternalRawDealing
    #[prost(bytes = "vec", tag = "2")]
    pub raw_dealing: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IDkgSignedDealingTuple {
    #[prost(message, optional, tag = "1")]
    pub dealer: ::core::option::Option<super::super::super::types::v1::NodeId>,
    #[prost(message, optional, tag = "2")]
    pub dealing: ::core::option::Option<IDkgDealing>,
    #[prost(bytes = "vec", tag = "3")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InitialIDkgDealings {
    #[prost(uint32, tag = "1")]
    pub version: u32,
    #[prost(message, optional, tag = "2")]
    pub params: ::core::option::Option<IDkgTranscriptParams>,
    #[prost(message, repeated, tag = "4")]
    pub signed_dealings: ::prost::alloc::vec::Vec<IDkgSignedDealingTuple>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IDkgComplaint {
    #[prost(message, optional, tag = "1")]
    pub transcript_id: ::core::option::Option<IDkgTranscriptId>,
    #[prost(message, optional, tag = "2")]
    pub dealer: ::core::option::Option<super::super::super::types::v1::NodeId>,
    #[prost(bytes = "vec", tag = "3")]
    pub raw_complaint: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IDkgOpening {
    #[prost(message, optional, tag = "1")]
    pub transcript_id: ::core::option::Option<IDkgTranscriptId>,
    #[prost(message, optional, tag = "2")]
    pub dealer: ::core::option::Option<super::super::super::types::v1::NodeId>,
    #[prost(bytes = "vec", tag = "3")]
    pub raw_opening: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExtendedDerivationPath {
    #[prost(message, optional, tag = "1")]
    pub caller: ::core::option::Option<super::super::super::types::v1::PrincipalId>,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub derivation_path: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetFeatures {
    /// This feature flag controls whether canister execution happens
    /// in sandboxed process or not. It is disabled by default.
    #[prost(bool, tag = "2")]
    pub canister_sandboxing: bool,
    /// This feature flag controls whether canisters of this subnet are capable of
    /// performing http(s) requests to the web2.
    #[prost(bool, tag = "3")]
    pub http_requests: bool,
    /// Status of the SEV-SNP feature.
    #[prost(bool, optional, tag = "9")]
    pub sev_enabled: ::core::option::Option<bool>,
}
/// Per subnet ECDSA configuration
///
/// Deprecated; please use ChainKeyConfig instead.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaConfig {
    /// Number of quadruples to create in advance.
    #[prost(uint32, tag = "1")]
    pub quadruples_to_create_in_advance: u32,
    /// Identifiers for threshold ECDSA keys held by the subnet.
    #[prost(message, repeated, tag = "3")]
    pub key_ids: ::prost::alloc::vec::Vec<super::super::crypto::v1::EcdsaKeyId>,
    /// The maximum number of signature requests that can be enqueued at once.
    #[prost(uint32, tag = "4")]
    pub max_queue_size: u32,
    /// Signature requests will timeout after the given number of nano seconds.
    #[prost(uint64, optional, tag = "5")]
    pub signature_request_timeout_ns: ::core::option::Option<u64>,
    /// Key rotation period of a single node in milliseconds.
    /// If none is specified key rotation is disabled.
    #[prost(uint64, optional, tag = "6")]
    pub idkg_key_rotation_period_ms: ::core::option::Option<u64>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeyConfig {
    /// The key's identifier.
    #[prost(message, optional, tag = "1")]
    pub key_id: ::core::option::Option<super::super::crypto::v1::MasterPublicKeyId>,
    /// Number of pre-signatures to create in advance.
    #[prost(uint32, optional, tag = "3")]
    pub pre_signatures_to_create_in_advance: ::core::option::Option<u32>,
    /// The maximum number of signature requests that can be enqueued at once.
    #[prost(uint32, optional, tag = "4")]
    pub max_queue_size: ::core::option::Option<u32>,
}
/// Per-subnet chain key configuration
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChainKeyConfig {
    /// Configurations for keys held by the subnet.
    #[prost(message, repeated, tag = "1")]
    pub key_configs: ::prost::alloc::vec::Vec<KeyConfig>,
    /// Signature requests will timeout after the given number of nano seconds.
    #[prost(uint64, optional, tag = "2")]
    pub signature_request_timeout_ns: ::core::option::Option<u64>,
    /// Key rotation period of a single node in milliseconds.
    /// If none is specified key rotation is disabled.
    #[prost(uint64, optional, tag = "3")]
    pub idkg_key_rotation_period_ms: ::core::option::Option<u64>,
}
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, ::prost::Enumeration)]
#[repr(i32)]
pub enum IDkgTranscriptOperation {
    Unspecified = 0,
    Random = 1,
    ReshareOfMasked = 2,
    ReshareOfUnmasked = 3,
    UnmaskedTimesMasked = 4,
    RandomUnmasked = 5,
}
impl IDkgTranscriptOperation {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            IDkgTranscriptOperation::Unspecified => "I_DKG_TRANSCRIPT_OPERATION_UNSPECIFIED",
            IDkgTranscriptOperation::Random => "I_DKG_TRANSCRIPT_OPERATION_RANDOM",
            IDkgTranscriptOperation::ReshareOfMasked => {
                "I_DKG_TRANSCRIPT_OPERATION_RESHARE_OF_MASKED"
            }
            IDkgTranscriptOperation::ReshareOfUnmasked => {
                "I_DKG_TRANSCRIPT_OPERATION_RESHARE_OF_UNMASKED"
            }
            IDkgTranscriptOperation::UnmaskedTimesMasked => {
                "I_DKG_TRANSCRIPT_OPERATION_UNMASKED_TIMES_MASKED"
            }
            IDkgTranscriptOperation::RandomUnmasked => "I_DKG_TRANSCRIPT_OPERATION_RANDOM_UNMASKED",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "I_DKG_TRANSCRIPT_OPERATION_UNSPECIFIED" => Some(Self::Unspecified),
            "I_DKG_TRANSCRIPT_OPERATION_RANDOM" => Some(Self::Random),
            "I_DKG_TRANSCRIPT_OPERATION_RESHARE_OF_MASKED" => Some(Self::ReshareOfMasked),
            "I_DKG_TRANSCRIPT_OPERATION_RESHARE_OF_UNMASKED" => Some(Self::ReshareOfUnmasked),
            "I_DKG_TRANSCRIPT_OPERATION_UNMASKED_TIMES_MASKED" => Some(Self::UnmaskedTimesMasked),
            "I_DKG_TRANSCRIPT_OPERATION_RANDOM_UNMASKED" => Some(Self::RandomUnmasked),
            _ => None,
        }
    }
}
/// Represents the type of subnet. Subnets of different type might exhibit different
/// behavior, e.g. being more restrictive in what operations are allowed or privileged
/// compared to other subnet types.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, ::prost::Enumeration)]
#[repr(i32)]
pub enum SubnetType {
    Unspecified = 0,
    /// A normal subnet where no restrictions are applied.
    Application = 1,
    /// A more privileged subnet where certain restrictions are applied,
    /// like not charging for cycles or restricting who can create and
    /// install canisters on it.
    System = 2,
    /// A subnet type that is like application subnets but can have some
    /// additional features.
    VerifiedApplication = 4,
}
impl SubnetType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            SubnetType::Unspecified => "SUBNET_TYPE_UNSPECIFIED",
            SubnetType::Application => "SUBNET_TYPE_APPLICATION",
            SubnetType::System => "SUBNET_TYPE_SYSTEM",
            SubnetType::VerifiedApplication => "SUBNET_TYPE_VERIFIED_APPLICATION",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "SUBNET_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
            "SUBNET_TYPE_APPLICATION" => Some(Self::Application),
            "SUBNET_TYPE_SYSTEM" => Some(Self::System),
            "SUBNET_TYPE_VERIFIED_APPLICATION" => Some(Self::VerifiedApplication),
            _ => None,
        }
    }
}
