/// A subnet: A logical group of nodes that run consensus
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetRecord {
    #[prost(bytes="vec", repeated, tag="3")]
    pub membership: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    /// Maximum amount of bytes per message. This is a hard cap, which means
    /// ingress messages greater than the limit will be dropped.
    #[prost(uint64, tag="5")]
    pub max_ingress_bytes_per_message: u64,
    /// Unit delay for blockmaker (in milliseconds).
    #[prost(uint64, tag="7")]
    pub unit_delay_millis: u64,
    /// Initial delay for notary (in milliseconds), to give time to rank-0 block
    /// propagation.
    #[prost(uint64, tag="8")]
    pub initial_notary_delay_millis: u64,
    /// ID of the Replica version to run
    #[prost(string, tag="9")]
    pub replica_version_id: ::prost::alloc::string::String,
    /// The length of all DKG intervals. The DKG interval length is the number of rounds following the DKG summary.
    #[prost(uint64, tag="10")]
    pub dkg_interval_length: u64,
    /// Gossip Config
    #[prost(message, optional, tag="13")]
    pub gossip_config: ::core::option::Option<GossipConfig>,
    /// If set to yes, the subnet starts as a (new) NNS
    #[prost(bool, tag="14")]
    pub start_as_nns: bool,
    /// The type of subnet.
    #[prost(enumeration="SubnetType", tag="15")]
    pub subnet_type: i32,
    /// The upper bound for the number of dealings we allow in a block.
    #[prost(uint64, tag="16")]
    pub dkg_dealings_per_block: u64,
    /// If `true`, the subnet will be halted: it will no longer create or execute blocks.
    #[prost(bool, tag="17")]
    pub is_halted: bool,
    /// Max number of ingress messages per block.
    #[prost(uint64, tag="18")]
    pub max_ingress_messages_per_block: u64,
    /// The maximum combined size of the ingress and xnet messages that fit into a block.
    #[prost(uint64, tag="19")]
    pub max_block_payload_size: u64,
    /// The maximum number of instructions a message can execute.
    /// See the comments in `subnet_config.rs` for more details.
    #[prost(uint64, tag="20")]
    pub max_instructions_per_message: u64,
    /// The maximum number of instructions a round can execute.
    /// See the comments in `subnet_config.rs` for more details.
    #[prost(uint64, tag="21")]
    pub max_instructions_per_round: u64,
    /// The maximum number of instructions an `install_code` message can execute.
    /// See the comments in `subnet_config.rs` for more details.
    #[prost(uint64, tag="22")]
    pub max_instructions_per_install_code: u64,
    /// Information on whether a feature is supported by this subnet.
    #[prost(message, optional, tag="23")]
    pub features: ::core::option::Option<SubnetFeatures>,
    /// The number of canisters allowed to be created on this subnet.
    ///
    /// A value of 0 is equivalent to setting no limit. This also provides an easy way
    /// to maintain compatibility of different versions of replica and registry.
    #[prost(uint64, tag="24")]
    pub max_number_of_canisters: u64,
    /// The list of public keys whose owners have "readonly" SSH access to all replicas on this subnet,
    /// in case it is necessary to perform subnet recovery.
    #[prost(string, repeated, tag="25")]
    pub ssh_readonly_access: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// The list of public keys whose owners have "backup" SSH access to nodes on the NNS subnet
    /// to make sure the NNS can be backed up.
    #[prost(string, repeated, tag="26")]
    pub ssh_backup_access: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// ECDSA Config
    #[prost(message, optional, tag="27")]
    pub ecdsa_config: ::core::option::Option<EcdsaConfig>,
}
/// Contains the initial DKG transcripts for the subnet and materials to construct a base CUP (i.e.
/// a CUP with no dependencies on previous CUPs or blocks). Such CUP materials can be used to
/// construct the genesis CUP or a recovery CUP in the event of a subnet stall.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CatchUpPackageContents {
    /// Initial non-interactive low-threshold DKG transcript
    #[prost(message, optional, tag="1")]
    pub initial_ni_dkg_transcript_low_threshold: ::core::option::Option<InitialNiDkgTranscriptRecord>,
    /// Initial non-interactive high-threshold DKG transcript
    #[prost(message, optional, tag="2")]
    pub initial_ni_dkg_transcript_high_threshold: ::core::option::Option<InitialNiDkgTranscriptRecord>,
    /// The blockchain height that the CUP should have
    #[prost(uint64, tag="3")]
    pub height: u64,
    /// Block time for the CUP's block
    #[prost(uint64, tag="4")]
    pub time: u64,
    /// The hash of the state that the subnet should use
    #[prost(bytes="vec", tag="5")]
    pub state_hash: ::prost::alloc::vec::Vec<u8>,
    /// A uri from which data to replace the registry local store should be downloaded
    #[prost(message, optional, tag="6")]
    pub registry_store_uri: ::core::option::Option<RegistryStoreUri>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegistryStoreUri {
    //// The uri at which the registry store data should be retrieved. The data
    //// must be provided as gzipped tar archive
    #[prost(string, tag="1")]
    pub uri: ::prost::alloc::string::String,
    //// A SHA-256, hex encoded hash of the contents of the data stored at the
    //// provided URI
    #[prost(string, tag="2")]
    pub hash: ::prost::alloc::string::String,
    //// The registry version that should be used for the catch up package contents
    #[prost(uint64, tag="3")]
    pub registry_version: u64,
}
/// A list of subnet ids of all subnets present in this instance of the IC.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetListRecord {
    #[prost(bytes="vec", repeated, tag="2")]
    pub subnets: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
/// Initial non-interactive DKG transcript record
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InitialNiDkgTranscriptRecord {
    #[prost(message, optional, tag="1")]
    pub id: ::core::option::Option<super::super::super::types::v1::NiDkgId>,
    #[prost(uint32, tag="2")]
    pub threshold: u32,
    #[prost(bytes="vec", repeated, tag="3")]
    pub committee: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(uint64, tag="4")]
    pub registry_version: u64,
    #[prost(bytes="vec", tag="5")]
    pub internal_csp_transcript: ::prost::alloc::vec::Vec<u8>,
}
/// Per subnet P2P configuration
/// Note: protoc is mangling the name P2PConfig to P2pConfig
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GossipConfig {
    /// max outstanding request per peer MIN/DEFAULT/MAX 1/20/200
    #[prost(uint32, tag="1")]
    pub max_artifact_streams_per_peer: u32,
    /// timeout for a outstanding request 3_000/15_000/180_000
    #[prost(uint32, tag="2")]
    pub max_chunk_wait_ms: u32,
    /// max duplicate requests in underutilized networks 1/28/6000
    #[prost(uint32, tag="3")]
    pub max_duplicity: u32,
    /// maximum chunk size supported on this subnet 1024/4096/131_072
    #[prost(uint32, tag="4")]
    pub max_chunk_size: u32,
    /// history size for receive check 1_000/5_000/30_000
    #[prost(uint32, tag="5")]
    pub receive_check_cache_size: u32,
    /// period for re evaluating the priority function. 1_000/3_000/30_000
    #[prost(uint32, tag="6")]
    pub pfn_evaluation_period_ms: u32,
    /// period for polling the registry for updates 1_000/3_000/30_000
    #[prost(uint32, tag="7")]
    pub registry_poll_period_ms: u32,
    /// period for sending a retransmission request    
    #[prost(uint32, tag="8")]
    pub retransmission_request_ms: u32,
    /// config for advert distribution.
    /// If this field is not specified, the feature is turned off.
    #[prost(message, optional, tag="10")]
    pub advert_config: ::core::option::Option<GossipAdvertConfig>,
}
/// Per subnet config for advert distribution.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GossipAdvertConfig {
    /// The subset of peers to broadcast to, specified in percentage.
    /// This is only  used when the P2P clients mark the advert as
    /// requiring best effort distribution. In future, this fixed
    /// percentage could be replaced by dynamic computation of the
    /// distribution set size, as a function of subnet size.
    /// 0 < best_effort_percentage <= 100
    #[prost(uint32, tag="1")]
    pub best_effort_percentage: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetFeatures {
    #[prost(bool, tag="1")]
    pub ecdsa_signatures: bool,
    /// This feature flag controls whether canister execution happens
    /// in sandboxed process or not. It is disabled by default.
    #[prost(bool, tag="2")]
    pub canister_sandboxing: bool,
}
/// Per subnet P2P configuration
/// Note: protoc is mangling the name P2PConfig to P2pConfig
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaConfig {
    /// Number of quadruples to create in advance.
    #[prost(uint32, tag="1")]
    pub quadruples_to_create_in_advance: u32,
}
/// Represents the type of subnet. Subnets of different type might exhibit different
/// behavior, e.g. being more restrictive in what operations are allowed or privileged
/// compared to other subnet types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
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
