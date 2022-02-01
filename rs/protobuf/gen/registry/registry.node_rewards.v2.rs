/// The reward rate for a node
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeRewardRate {
    /// The number of 10,000ths of IMF SDR (currency code XDR) to be rewarded per
    /// node per month.
    #[prost(uint64, tag="1")]
    pub xdr_permyriad_per_node_per_month: u64,
}
/// The reward rates for a set of node types
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeRewardRates {
    /// Maps node types to the reward rate for that node type
    #[prost(btree_map="string, message", tag="1")]
    pub rates: ::prost::alloc::collections::BTreeMap<::prost::alloc::string::String, NodeRewardRate>,
}
/// Contains the node reward rates for each region where IC nodes are operated
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeRewardsTable {
    /// Maps regions to the node reward rates in that region
    #[prost(btree_map="string, message", tag="1")]
    pub table: ::prost::alloc::collections::BTreeMap<::prost::alloc::string::String, NodeRewardRates>,
}
/// The payload of a proposal to update the node rewards table
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdateNodeRewardsTableProposalPayload {
    /// Maps regions to the node reward rates in that region
    #[prost(btree_map="string, message", tag="1")]
    pub new_entries: ::prost::alloc::collections::BTreeMap<::prost::alloc::string::String, NodeRewardRates>,
}
