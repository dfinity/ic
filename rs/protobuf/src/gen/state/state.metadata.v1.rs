#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Time {
    #[prost(uint64, tag = "1")]
    pub time_nanos: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetTopologyEntry {
    #[prost(message, optional, tag = "1")]
    pub node_id: ::core::option::Option<super::super::super::types::v1::NodeId>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetTopology {
    #[prost(message, repeated, tag = "1")]
    pub nodes: ::prost::alloc::vec::Vec<SubnetTopologyEntry>,
    /// The public key of the subnet (a DER-encoded BLS key, see
    /// <https://internetcomputer.org/docs/current/references/ic-interface-spec#certification>)
    #[prost(bytes = "vec", tag = "2")]
    pub public_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(
        enumeration = "super::super::super::registry::subnet::v1::SubnetType",
        tag = "3"
    )]
    pub subnet_type: i32,
    #[prost(message, optional, tag = "4")]
    pub subnet_features:
        ::core::option::Option<super::super::super::registry::subnet::v1::SubnetFeatures>,
    #[prost(message, repeated, tag = "6")]
    pub idkg_keys_held:
        ::prost::alloc::vec::Vec<super::super::super::registry::crypto::v1::MasterPublicKeyId>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetsEntry {
    #[prost(message, optional, tag = "1")]
    pub subnet_id: ::core::option::Option<super::super::super::types::v1::SubnetId>,
    #[prost(message, optional, tag = "2")]
    pub subnet_topology: ::core::option::Option<SubnetTopology>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IDkgKeyEntry {
    #[prost(message, optional, tag = "1")]
    pub key_id:
        ::core::option::Option<super::super::super::registry::crypto::v1::MasterPublicKeyId>,
    #[prost(message, repeated, tag = "2")]
    pub subnet_ids: ::prost::alloc::vec::Vec<super::super::super::types::v1::SubnetId>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NetworkTopology {
    #[prost(message, repeated, tag = "1")]
    pub subnets: ::prost::alloc::vec::Vec<SubnetsEntry>,
    #[prost(message, optional, tag = "2")]
    pub routing_table:
        ::core::option::Option<super::super::super::registry::routing_table::v1::RoutingTable>,
    #[prost(message, optional, tag = "3")]
    pub nns_subnet_id: ::core::option::Option<super::super::super::types::v1::SubnetId>,
    #[prost(message, optional, tag = "4")]
    pub canister_migrations: ::core::option::Option<
        super::super::super::registry::routing_table::v1::CanisterMigrations,
    >,
    #[prost(message, repeated, tag = "6")]
    pub bitcoin_testnet_canister_ids:
        ::prost::alloc::vec::Vec<super::super::super::types::v1::CanisterId>,
    #[prost(message, repeated, tag = "7")]
    pub bitcoin_mainnet_canister_ids:
        ::prost::alloc::vec::Vec<super::super::super::types::v1::CanisterId>,
    #[prost(message, repeated, tag = "8")]
    pub idkg_signing_subnets: ::prost::alloc::vec::Vec<IDkgKeyEntry>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetupInitialDkgContext {
    #[prost(message, optional, tag = "1")]
    pub request: ::core::option::Option<super::super::queues::v1::Request>,
    #[prost(message, repeated, tag = "2")]
    pub nodes_in_subnet: ::prost::alloc::vec::Vec<super::super::super::types::v1::NodeId>,
    #[prost(bytes = "vec", tag = "4")]
    pub target_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "5")]
    pub registry_version: u64,
    #[prost(message, optional, tag = "6")]
    pub time: ::core::option::Option<Time>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetupInitialDkgContextTree {
    #[prost(uint64, tag = "1")]
    pub callback_id: u64,
    #[prost(message, optional, tag = "2")]
    pub context: ::core::option::Option<SetupInitialDkgContext>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaArguments {
    #[prost(message, optional, tag = "1")]
    pub key_id: ::core::option::Option<super::super::super::registry::crypto::v1::EcdsaKeyId>,
    #[prost(bytes = "vec", tag = "2")]
    pub message_hash: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SchnorrArguments {
    #[prost(message, optional, tag = "1")]
    pub key_id: ::core::option::Option<super::super::super::registry::crypto::v1::SchnorrKeyId>,
    #[prost(bytes = "vec", tag = "2")]
    pub message: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ThresholdArguments {
    #[prost(oneof = "threshold_arguments::ThresholdScheme", tags = "1, 2")]
    pub threshold_scheme: ::core::option::Option<threshold_arguments::ThresholdScheme>,
}
/// Nested message and enum types in `ThresholdArguments`.
pub mod threshold_arguments {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ThresholdScheme {
        #[prost(message, tag = "1")]
        Ecdsa(super::EcdsaArguments),
        #[prost(message, tag = "2")]
        Schnorr(super::SchnorrArguments),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignWithThresholdContext {
    #[prost(message, optional, tag = "1")]
    pub request: ::core::option::Option<super::super::queues::v1::Request>,
    #[prost(message, optional, tag = "2")]
    pub args: ::core::option::Option<ThresholdArguments>,
    #[prost(bytes = "vec", repeated, tag = "3")]
    pub derivation_path_vec: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", tag = "4")]
    pub pseudo_random_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "5")]
    pub batch_time: u64,
    #[prost(uint64, optional, tag = "6")]
    pub pre_signature_id: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag = "7")]
    pub height: ::core::option::Option<u64>,
    #[prost(bytes = "vec", optional, tag = "8")]
    pub nonce: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignWithThresholdContextTree {
    #[prost(uint64, tag = "1")]
    pub callback_id: u64,
    #[prost(message, optional, tag = "2")]
    pub context: ::core::option::Option<SignWithThresholdContext>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HttpHeader {
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub value: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterHttpRequestContext {
    #[prost(message, optional, tag = "1")]
    pub request: ::core::option::Option<super::super::queues::v1::Request>,
    #[prost(string, tag = "2")]
    pub url: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "3")]
    pub body: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(message, optional, tag = "4")]
    pub transform_method_name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(enumeration = "HttpMethod", tag = "8")]
    pub http_method: i32,
    #[prost(uint64, tag = "6")]
    pub time: u64,
    #[prost(message, repeated, tag = "7")]
    pub headers: ::prost::alloc::vec::Vec<HttpHeader>,
    #[prost(uint64, optional, tag = "9")]
    pub max_response_bytes: ::core::option::Option<u64>,
    #[prost(message, optional, tag = "10")]
    pub transform_context: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterHttpRequestContextTree {
    #[prost(uint64, tag = "1")]
    pub callback_id: u64,
    #[prost(message, optional, tag = "2")]
    pub context: ::core::option::Option<CanisterHttpRequestContext>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IDkgDealingsContext {
    #[prost(message, optional, tag = "1")]
    pub request: ::core::option::Option<super::super::queues::v1::Request>,
    #[prost(message, optional, tag = "2")]
    pub key_id:
        ::core::option::Option<super::super::super::registry::crypto::v1::MasterPublicKeyId>,
    #[prost(message, repeated, tag = "3")]
    pub nodes: ::prost::alloc::vec::Vec<super::super::super::types::v1::NodeId>,
    #[prost(uint64, tag = "4")]
    pub registry_version: u64,
    #[prost(message, optional, tag = "5")]
    pub time: ::core::option::Option<Time>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IDkgDealingsContextTree {
    #[prost(uint64, tag = "1")]
    pub callback_id: u64,
    #[prost(message, optional, tag = "2")]
    pub context: ::core::option::Option<IDkgDealingsContext>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BitcoinGetSuccessorsContext {
    #[prost(message, optional, tag = "1")]
    pub request: ::core::option::Option<super::super::queues::v1::Request>,
    #[prost(message, optional, tag = "2")]
    pub payload:
        ::core::option::Option<super::super::super::bitcoin::v1::GetSuccessorsRequestInitial>,
    #[prost(message, optional, tag = "3")]
    pub time: ::core::option::Option<Time>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BitcoinGetSuccessorsContextTree {
    #[prost(uint64, tag = "1")]
    pub callback_id: u64,
    #[prost(message, optional, tag = "2")]
    pub context: ::core::option::Option<BitcoinGetSuccessorsContext>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BitcoinSendTransactionInternalContext {
    #[prost(message, optional, tag = "1")]
    pub request: ::core::option::Option<super::super::queues::v1::Request>,
    #[prost(message, optional, tag = "2")]
    pub payload: ::core::option::Option<super::super::super::bitcoin::v1::SendTransactionRequest>,
    #[prost(message, optional, tag = "3")]
    pub time: ::core::option::Option<Time>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BitcoinSendTransactionInternalContextTree {
    #[prost(uint64, tag = "1")]
    pub callback_id: u64,
    #[prost(message, optional, tag = "2")]
    pub context: ::core::option::Option<BitcoinSendTransactionInternalContext>,
}
/// TODO(EXC-1454): Deprecated.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InstallCodeRequest {
    #[prost(message, optional, tag = "1")]
    pub request: ::core::option::Option<super::super::queues::v1::Request>,
    #[prost(message, optional, tag = "2")]
    pub time: ::core::option::Option<Time>,
    #[prost(message, optional, tag = "3")]
    pub effective_canister_id: ::core::option::Option<super::super::super::types::v1::CanisterId>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InstallCodeCall {
    #[prost(message, optional, tag = "3")]
    pub time: ::core::option::Option<Time>,
    #[prost(message, optional, tag = "4")]
    pub effective_canister_id: ::core::option::Option<super::super::super::types::v1::CanisterId>,
    #[prost(oneof = "install_code_call::CanisterCall", tags = "1, 2")]
    pub canister_call: ::core::option::Option<install_code_call::CanisterCall>,
}
/// Nested message and enum types in `InstallCodeCall`.
pub mod install_code_call {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum CanisterCall {
        #[prost(message, tag = "1")]
        Request(super::super::super::queues::v1::Request),
        #[prost(message, tag = "2")]
        Ingress(super::super::super::ingress::v1::Ingress),
    }
}
/// TODO(EXC-1454): Deprecated.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InstallCodeRequestTree {
    #[prost(uint64, tag = "1")]
    pub request_id: u64,
    #[prost(message, optional, tag = "2")]
    pub request: ::core::option::Option<InstallCodeRequest>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InstallCodeCallTree {
    #[prost(uint64, tag = "1")]
    pub call_id: u64,
    #[prost(message, optional, tag = "2")]
    pub call: ::core::option::Option<InstallCodeCall>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StopCanisterCall {
    #[prost(message, optional, tag = "3")]
    pub time: ::core::option::Option<Time>,
    #[prost(message, optional, tag = "4")]
    pub effective_canister_id: ::core::option::Option<super::super::super::types::v1::CanisterId>,
    #[prost(oneof = "stop_canister_call::CanisterCall", tags = "1, 2")]
    pub canister_call: ::core::option::Option<stop_canister_call::CanisterCall>,
}
/// Nested message and enum types in `StopCanisterCall`.
pub mod stop_canister_call {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum CanisterCall {
        #[prost(message, tag = "1")]
        Request(super::super::super::queues::v1::Request),
        #[prost(message, tag = "2")]
        Ingress(super::super::super::ingress::v1::Ingress),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StopCanisterCallTree {
    #[prost(uint64, tag = "1")]
    pub call_id: u64,
    #[prost(message, optional, tag = "2")]
    pub call: ::core::option::Option<StopCanisterCall>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RawRandContext {
    #[prost(message, optional, tag = "1")]
    pub request: ::core::option::Option<super::super::queues::v1::Request>,
    #[prost(message, optional, tag = "2")]
    pub time: ::core::option::Option<Time>,
    #[prost(uint64, tag = "3")]
    pub execution_round_id: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetCallContextManager {
    #[prost(uint64, tag = "1")]
    pub next_callback_id: u64,
    #[prost(message, repeated, tag = "3")]
    pub setup_initial_dkg_contexts: ::prost::alloc::vec::Vec<SetupInitialDkgContextTree>,
    #[prost(message, repeated, tag = "6")]
    pub canister_http_request_contexts: ::prost::alloc::vec::Vec<CanisterHttpRequestContextTree>,
    #[prost(message, repeated, tag = "8")]
    pub bitcoin_get_successors_contexts: ::prost::alloc::vec::Vec<BitcoinGetSuccessorsContextTree>,
    #[prost(message, repeated, tag = "9")]
    pub bitcoin_send_transaction_internal_contexts:
        ::prost::alloc::vec::Vec<BitcoinSendTransactionInternalContextTree>,
    /// TODO(EXC-1454): Deprecated.
    #[prost(message, repeated, tag = "11")]
    pub install_code_requests: ::prost::alloc::vec::Vec<InstallCodeRequestTree>,
    #[prost(uint64, tag = "12")]
    pub next_install_code_call_id: u64,
    #[prost(message, repeated, tag = "13")]
    pub install_code_calls: ::prost::alloc::vec::Vec<InstallCodeCallTree>,
    #[prost(uint64, tag = "14")]
    pub next_stop_canister_call_id: u64,
    #[prost(message, repeated, tag = "15")]
    pub stop_canister_calls: ::prost::alloc::vec::Vec<StopCanisterCallTree>,
    #[prost(message, repeated, tag = "16")]
    pub raw_rand_contexts: ::prost::alloc::vec::Vec<RawRandContext>,
    #[prost(message, repeated, tag = "17")]
    pub idkg_dealings_contexts: ::prost::alloc::vec::Vec<IDkgDealingsContextTree>,
    #[prost(message, repeated, tag = "18")]
    pub sign_with_threshold_contexts: ::prost::alloc::vec::Vec<SignWithThresholdContextTree>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubnetMetrics {
    #[prost(message, optional, tag = "1")]
    pub consumed_cycles_by_deleted_canisters:
        ::core::option::Option<super::super::super::types::v1::NominalCycles>,
    #[prost(message, optional, tag = "2")]
    pub consumed_cycles_http_outcalls:
        ::core::option::Option<super::super::super::types::v1::NominalCycles>,
    #[prost(message, optional, tag = "3")]
    pub consumed_cycles_ecdsa_outcalls:
        ::core::option::Option<super::super::super::types::v1::NominalCycles>,
    #[prost(message, repeated, tag = "5")]
    pub consumed_cycles_by_use_case:
        ::prost::alloc::vec::Vec<super::super::canister_state_bits::v1::ConsumedCyclesByUseCase>,
    #[prost(uint64, optional, tag = "6")]
    pub num_canisters: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag = "9")]
    pub canister_state_bytes: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag = "10")]
    pub update_transactions_total: ::core::option::Option<u64>,
    #[prost(message, repeated, tag = "11")]
    pub threshold_signature_agreements: ::prost::alloc::vec::Vec<ThresholdSignatureAgreementsEntry>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BitcoinGetSuccessorsFollowUpResponses {
    #[prost(message, optional, tag = "1")]
    pub sender: ::core::option::Option<super::super::super::types::v1::CanisterId>,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub payloads: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodePublicKeyEntry {
    #[prost(message, optional, tag = "1")]
    pub node_id: ::core::option::Option<super::super::super::types::v1::NodeId>,
    #[prost(bytes = "vec", tag = "2")]
    pub public_key: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ApiBoundaryNodeEntry {
    #[prost(message, optional, tag = "1")]
    pub node_id: ::core::option::Option<super::super::super::types::v1::NodeId>,
    #[prost(string, tag = "2")]
    pub domain: ::prost::alloc::string::String,
    #[prost(string, optional, tag = "3")]
    pub ipv4_address: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, tag = "4")]
    pub ipv6_address: ::prost::alloc::string::String,
    #[prost(bytes = "vec", optional, tag = "5")]
    pub pubkey: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ThresholdSignatureAgreementsEntry {
    #[prost(message, optional, tag = "1")]
    pub key_id:
        ::core::option::Option<super::super::super::registry::crypto::v1::MasterPublicKeyId>,
    #[prost(uint64, tag = "2")]
    pub count: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeBlockmakerStats {
    #[prost(message, optional, tag = "1")]
    pub node_id: ::core::option::Option<super::super::super::types::v1::NodeId>,
    #[prost(uint64, tag = "2")]
    pub blocks_proposed_total: u64,
    #[prost(uint64, tag = "3")]
    pub blocks_not_proposed_total: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockmakerStatsMap {
    #[prost(message, repeated, tag = "1")]
    pub node_stats: ::prost::alloc::vec::Vec<NodeBlockmakerStats>,
    #[prost(uint64, tag = "2")]
    pub blocks_proposed_total: u64,
    #[prost(uint64, tag = "3")]
    pub blocks_not_proposed_total: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockmakerMetricsTimeSeries {
    #[prost(btree_map = "uint64, message", tag = "1")]
    pub time_stamp_map: ::prost::alloc::collections::BTreeMap<u64, BlockmakerStatsMap>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SystemMetadata {
    #[prost(message, optional, tag = "2")]
    pub prev_state_hash: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(uint64, tag = "3")]
    pub batch_time_nanos: u64,
    #[prost(message, repeated, tag = "5")]
    pub streams: ::prost::alloc::vec::Vec<super::super::queues::v1::StreamEntry>,
    #[prost(message, optional, tag = "6")]
    pub network_topology: ::core::option::Option<NetworkTopology>,
    #[prost(message, optional, tag = "7")]
    pub own_subnet_id: ::core::option::Option<super::super::super::types::v1::SubnetId>,
    #[prost(message, optional, tag = "8")]
    pub subnet_call_context_manager: ::core::option::Option<SubnetCallContextManager>,
    /// Canister ID ranges allocated (exclusively) to this subnet, to generate
    /// canister IDs from.
    #[prost(message, optional, tag = "16")]
    pub canister_allocation_ranges:
        ::core::option::Option<super::super::super::registry::routing_table::v1::CanisterIdRanges>,
    /// The last generated canister ID; or `None` if no canister ID has yet been
    /// generated by this subnet.
    ///
    /// If present, must be within the first `CanisterIdRange` in
    /// `canister_allocation_ranges` (and the latter may not be empty).
    #[prost(message, optional, tag = "17")]
    pub last_generated_canister_id:
        ::core::option::Option<super::super::super::types::v1::CanisterId>,
    /// Version of the StateSync protocol that should be used to compute
    /// checkpoint manifests and transmit state.
    #[prost(uint32, tag = "9")]
    pub state_sync_version: u32,
    /// Version of the certification protocol that should be used to
    /// certify this state.
    #[prost(uint32, tag = "10")]
    pub certification_version: u32,
    #[prost(uint64, tag = "11")]
    pub heap_delta_estimate: u64,
    #[prost(message, optional, tag = "13")]
    pub own_subnet_features:
        ::core::option::Option<super::super::super::registry::subnet::v1::SubnetFeatures>,
    #[prost(message, optional, tag = "15")]
    pub subnet_metrics: ::core::option::Option<SubnetMetrics>,
    #[prost(message, repeated, tag = "18")]
    pub bitcoin_get_successors_follow_up_responses:
        ::prost::alloc::vec::Vec<BitcoinGetSuccessorsFollowUpResponses>,
    #[prost(message, repeated, tag = "19")]
    pub node_public_keys: ::prost::alloc::vec::Vec<NodePublicKeyEntry>,
    #[prost(message, optional, tag = "20")]
    pub blockmaker_metrics_time_series: ::core::option::Option<BlockmakerMetricsTimeSeries>,
    #[prost(message, repeated, tag = "21")]
    pub api_boundary_nodes: ::prost::alloc::vec::Vec<ApiBoundaryNodeEntry>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StableMemory {
    #[prost(bytes = "vec", tag = "1")]
    pub memory: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SplitFrom {
    /// If present, the subnet is mid-way through a split. Identifies the original
    /// subnet that this was split from.
    #[prost(message, optional, tag = "1")]
    pub subnet_id: ::core::option::Option<super::super::super::types::v1::SubnetId>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum HttpMethod {
    Unspecified = 0,
    Get = 1,
    Post = 2,
    Head = 3,
}
impl HttpMethod {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            HttpMethod::Unspecified => "HTTP_METHOD_UNSPECIFIED",
            HttpMethod::Get => "HTTP_METHOD_GET",
            HttpMethod::Post => "HTTP_METHOD_POST",
            HttpMethod::Head => "HTTP_METHOD_HEAD",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "HTTP_METHOD_UNSPECIFIED" => Some(Self::Unspecified),
            "HTTP_METHOD_GET" => Some(Self::Get),
            "HTTP_METHOD_POST" => Some(Self::Post),
            "HTTP_METHOD_HEAD" => Some(Self::Head),
            _ => None,
        }
    }
}
