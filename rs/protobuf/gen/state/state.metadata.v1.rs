#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeTopology {
    #[prost(string, tag="1")]
    pub ip_address: ::prost::alloc::string::String,
    #[prost(uint32, tag="2")]
    pub http_port: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetTopologyEntry {
    #[prost(message, optional, tag="1")]
    pub node_id: ::core::option::Option<super::super::super::types::v1::NodeId>,
    #[prost(message, optional, tag="2")]
    pub node_topology: ::core::option::Option<NodeTopology>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetTopology {
    #[prost(message, repeated, tag="1")]
    pub nodes: ::prost::alloc::vec::Vec<SubnetTopologyEntry>,
    /// The public key of the subnet (a DER-encoded BLS key, see
    /// <https://sdk.dfinity.org/docs/interface-spec/index.html#certification>)
    #[prost(bytes="vec", tag="2")]
    pub public_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(enumeration="super::super::super::registry::subnet::v1::SubnetType", tag="3")]
    pub subnet_type: i32,
    #[prost(message, optional, tag="4")]
    pub subnet_features: ::core::option::Option<super::super::super::registry::subnet::v1::SubnetFeatures>,
    #[prost(message, repeated, tag="5")]
    pub ecdsa_keys_held: ::prost::alloc::vec::Vec<super::super::super::registry::crypto::v1::EcdsaKeyId>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetsEntry {
    #[prost(message, optional, tag="1")]
    pub subnet_id: ::core::option::Option<super::super::super::types::v1::SubnetId>,
    #[prost(message, optional, tag="2")]
    pub subnet_topology: ::core::option::Option<SubnetTopology>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaKeyEntry {
    #[prost(message, optional, tag="3")]
    pub key_id: ::core::option::Option<super::super::super::registry::crypto::v1::EcdsaKeyId>,
    #[prost(message, repeated, tag="2")]
    pub subnet_ids: ::prost::alloc::vec::Vec<super::super::super::types::v1::SubnetId>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NetworkTopology {
    #[prost(message, repeated, tag="1")]
    pub subnets: ::prost::alloc::vec::Vec<SubnetsEntry>,
    #[prost(message, optional, tag="2")]
    pub routing_table: ::core::option::Option<super::super::super::registry::routing_table::v1::RoutingTable>,
    #[prost(message, optional, tag="3")]
    pub nns_subnet_id: ::core::option::Option<super::super::super::types::v1::SubnetId>,
    #[prost(message, optional, tag="4")]
    pub canister_migrations: ::core::option::Option<super::super::super::registry::routing_table::v1::CanisterMigrations>,
    #[prost(message, repeated, tag="5")]
    pub ecdsa_keys: ::prost::alloc::vec::Vec<EcdsaKeyEntry>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetupInitialDkgContext {
    #[prost(message, optional, tag="1")]
    pub request: ::core::option::Option<super::super::queues::v1::Request>,
    #[prost(message, repeated, tag="2")]
    pub nodes_in_subnet: ::prost::alloc::vec::Vec<super::super::super::types::v1::NodeId>,
    #[prost(bytes="vec", tag="4")]
    pub target_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag="5")]
    pub registry_version: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetupInitialDkgContextTree {
    #[prost(uint64, tag="1")]
    pub callback_id: u64,
    #[prost(message, optional, tag="2")]
    pub context: ::core::option::Option<SetupInitialDkgContext>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignWithEcdsaContext {
    #[prost(message, optional, tag="1")]
    pub request: ::core::option::Option<super::super::queues::v1::Request>,
    #[prost(bytes="vec", tag="2")]
    pub pseudo_random_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="3")]
    pub message_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag="5")]
    pub batch_time: u64,
    #[prost(bytes="vec", repeated, tag="6")]
    pub derivation_path_vec: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignWithEcdsaContextTree {
    #[prost(uint64, tag="1")]
    pub callback_id: u64,
    #[prost(message, optional, tag="2")]
    pub context: ::core::option::Option<SignWithEcdsaContext>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HttpHeader {
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, tag="2")]
    pub value: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterHttpRequestContext {
    #[prost(message, optional, tag="1")]
    pub request: ::core::option::Option<super::super::queues::v1::Request>,
    #[prost(string, tag="2")]
    pub url: ::prost::alloc::string::String,
    #[prost(message, optional, tag="3")]
    pub body: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(message, optional, tag="4")]
    pub transform_method_name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(enumeration="HttpMethod", tag="8")]
    pub http_method: i32,
    #[prost(uint64, tag="6")]
    pub time: u64,
    #[prost(message, repeated, tag="7")]
    pub headers: ::prost::alloc::vec::Vec<HttpHeader>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterHttpRequestContextTree {
    #[prost(uint64, tag="1")]
    pub callback_id: u64,
    #[prost(message, optional, tag="2")]
    pub context: ::core::option::Option<CanisterHttpRequestContext>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaDealingsContext {
    #[prost(message, optional, tag="1")]
    pub request: ::core::option::Option<super::super::queues::v1::Request>,
    #[prost(message, repeated, tag="3")]
    pub nodes: ::prost::alloc::vec::Vec<super::super::super::types::v1::NodeId>,
    #[prost(uint64, tag="4")]
    pub registry_version: u64,
    #[prost(message, optional, tag="5")]
    pub key_id: ::core::option::Option<super::super::super::registry::crypto::v1::EcdsaKeyId>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaDealingsContextTree {
    #[prost(uint64, tag="1")]
    pub callback_id: u64,
    #[prost(message, optional, tag="2")]
    pub context: ::core::option::Option<EcdsaDealingsContext>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetCallContextManager {
    #[prost(uint64, tag="1")]
    pub next_callback_id: u64,
    #[prost(message, repeated, tag="3")]
    pub setup_initial_dkg_contexts: ::prost::alloc::vec::Vec<SetupInitialDkgContextTree>,
    #[prost(message, repeated, tag="4")]
    pub sign_with_ecdsa_contexts: ::prost::alloc::vec::Vec<SignWithEcdsaContextTree>,
    #[prost(message, repeated, tag="6")]
    pub canister_http_request_contexts: ::prost::alloc::vec::Vec<CanisterHttpRequestContextTree>,
    #[prost(message, repeated, tag="7")]
    pub ecdsa_dealings_contexts: ::prost::alloc::vec::Vec<EcdsaDealingsContextTree>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TimeOfLastAllocationCharge {
    #[prost(uint64, tag="1")]
    pub time_of_last_allocation_charge_nanos: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SystemMetadata {
    #[prost(uint64, tag="1")]
    pub generated_id_counter: u64,
    #[prost(message, optional, tag="2")]
    pub prev_state_hash: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(uint64, tag="3")]
    pub batch_time_nanos: u64,
    #[prost(message, optional, tag="4")]
    pub ingress_history: ::core::option::Option<super::super::ingress::v1::IngressHistoryState>,
    #[prost(message, repeated, tag="5")]
    pub streams: ::prost::alloc::vec::Vec<super::super::queues::v1::StreamEntry>,
    #[prost(message, optional, tag="6")]
    pub network_topology: ::core::option::Option<NetworkTopology>,
    #[prost(message, optional, tag="7")]
    pub own_subnet_id: ::core::option::Option<super::super::super::types::v1::SubnetId>,
    #[prost(message, optional, tag="8")]
    pub subnet_call_context_manager: ::core::option::Option<SubnetCallContextManager>,
    /// Version of the StateSync protocol that should be used to compute
    /// checkpoint manifests and transmit state.
    #[prost(uint32, tag="9")]
    pub state_sync_version: u32,
    /// Version of the certification protocol that should be used to
    /// certify this state.
    #[prost(uint32, tag="10")]
    pub certification_version: u32,
    #[prost(uint64, tag="11")]
    pub heap_delta_estimate: u64,
    #[prost(message, optional, tag="13")]
    pub own_subnet_features: ::core::option::Option<super::super::super::registry::subnet::v1::SubnetFeatures>,
    #[prost(message, optional, tag="14")]
    pub time_of_last_allocation_charge_nanos: ::core::option::Option<TimeOfLastAllocationCharge>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StableMemory {
    #[prost(bytes="vec", tag="1")]
    pub memory: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum HttpMethod {
    Unspecified = 0,
    Get = 1,
}
