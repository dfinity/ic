#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Stats {
    #[prost(message, optional, tag = "1")]
    pub query_stats: ::core::option::Option<QueryStats>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryStats {
    #[prost(uint64, optional, tag = "1")]
    pub highest_aggregated_epoch: ::core::option::Option<u64>,
    #[prost(message, repeated, tag = "2")]
    pub query_stats: ::prost::alloc::vec::Vec<QueryStatsInner>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryStatsInner {
    #[prost(message, optional, tag = "1")]
    pub proposer: ::core::option::Option<super::super::super::types::v1::NodeId>,
    #[prost(uint64, tag = "7")]
    pub epoch: u64,
    #[prost(message, optional, tag = "2")]
    pub canister: ::core::option::Option<super::super::super::types::v1::CanisterId>,
    #[prost(uint32, tag = "3")]
    pub num_calls: u32,
    #[prost(uint64, tag = "4")]
    pub num_instructions: u64,
    #[prost(uint64, tag = "5")]
    pub ingress_payload_size: u64,
    #[prost(uint64, tag = "6")]
    pub egress_payload_size: u64,
}
