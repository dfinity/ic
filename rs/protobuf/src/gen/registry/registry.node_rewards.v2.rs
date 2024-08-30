/// The reward rate for a node
#[derive(candid::CandidType, serde::Serialize, candid::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeRewardRate {
    /// The number of 10,000ths of IMF SDR (currency code XDR) to be rewarded per
    /// node per month.
    #[prost(uint64, tag = "1")]
    pub xdr_permyriad_per_node_per_month: u64,
    /// The coefficient of the node rewards the node provider gets
    /// for having more than 1 node, as a percentage of the reward for first node.
    /// A value of 100 means that the same reward is received for all nodes
    /// A value of 0 means that only the first node gets the rewards, 2nd and later nodes get no reward
    /// For values in between, the reward for the n-th node is:
    /// reward(n) = reward(n-1) * reward_coefficient_percent ^ (n-1)
    #[prost(int32, optional, tag = "2")]
    pub reward_coefficient_percent: ::core::option::Option<i32>,
}
/// The reward rates for a set of node types
#[derive(candid::CandidType, serde::Serialize, candid::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeRewardRates {
    /// Maps node types to the reward rate for that node type
    #[prost(btree_map = "string, message", tag = "1")]
    pub rates:
        ::prost::alloc::collections::BTreeMap<::prost::alloc::string::String, NodeRewardRate>,
}
/// Contains the node reward rates for each region where IC nodes are operated
#[derive(candid::CandidType, serde::Serialize, candid::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeRewardsTable {
    /// Maps regions to the node reward rates in that region
    #[prost(btree_map = "string, message", tag = "1")]
    pub table:
        ::prost::alloc::collections::BTreeMap<::prost::alloc::string::String, NodeRewardRates>,
}
/// The payload of a proposal to update the node rewards table
#[derive(candid::CandidType, serde::Serialize, candid::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdateNodeRewardsTableProposalPayload {
    /// Maps regions to the node reward rates in that region
    #[prost(btree_map = "string, message", tag = "1")]
    pub new_entries:
        ::prost::alloc::collections::BTreeMap<::prost::alloc::string::String, NodeRewardRates>,
}
