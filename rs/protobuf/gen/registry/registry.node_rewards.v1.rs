/// The reward rate for a specific node type
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeRewardRate {
    /// The number of 10,000ths of IMF SDR (currency code XDR) to be rewarded per
    /// node per month.
    #[prost(uint64, tag="1")]
    pub xdr_permyriad_per_node_per_month: u64,
    #[prost(enumeration="NodeRewardType", tag="2")]
    pub node_reward_type: i32,
}
/// The reward rates for a set of node types
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeRewardRates {
    #[prost(message, repeated, tag="1")]
    pub rates: ::prost::alloc::vec::Vec<NodeRewardRate>,
}
/// Contains the node reward rates for each region where IC nodes are operated
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeRewardsTable {
    /// Maps regions to the node reward rates in that region
    #[prost(btree_map="string, message", tag="1")]
    pub table: ::prost::alloc::collections::BTreeMap<::prost::alloc::string::String, NodeRewardRates>,
}
/// The payload of a proposal to update the node rewards table
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdateNodeRewardsTableProposalPayload {
    /// Maps regions to the node reward rates in that region
    #[prost(btree_map="string, message", tag="1")]
    pub new_entries: ::prost::alloc::collections::BTreeMap<::prost::alloc::string::String, NodeRewardRates>,
}
/// Some nodes will have different properties (e.g. upgraded storage capacity)
/// that require a unique reward rate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum NodeRewardType {
    /// This field is treated as the default reward type
    Unspecified = 0,
    Small = 1,
    StorageUpgrade = 2,
}
