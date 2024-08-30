/// The reward rate for a specific node type
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeRewardRate {
    /// The number of 10,000ths of IMF SDR (currency code XDR) to be rewarded per
    /// node per month.
    #[prost(uint64, tag = "1")]
    pub xdr_permyriad_per_node_per_month: u64,
    #[prost(enumeration = "NodeRewardType", tag = "2")]
    pub node_reward_type: i32,
}
/// The reward rates for a set of node types
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeRewardRates {
    #[prost(message, repeated, tag = "1")]
    pub rates: ::prost::alloc::vec::Vec<NodeRewardRate>,
}
/// Contains the node reward rates for each region where IC nodes are operated
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeRewardsTable {
    /// Maps regions to the node reward rates in that region
    #[prost(btree_map = "string, message", tag = "1")]
    pub table:
        ::prost::alloc::collections::BTreeMap<::prost::alloc::string::String, NodeRewardRates>,
}
/// The payload of a proposal to update the node rewards table
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdateNodeRewardsTableProposalPayload {
    /// Maps regions to the node reward rates in that region
    #[prost(btree_map = "string, message", tag = "1")]
    pub new_entries:
        ::prost::alloc::collections::BTreeMap<::prost::alloc::string::String, NodeRewardRates>,
}
/// Some nodes will have different properties (e.g. upgraded storage capacity)
/// that require a unique reward rate.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, ::prost::Enumeration)]
#[repr(i32)]
pub enum NodeRewardType {
    /// This field is treated as the default reward type
    Unspecified = 0,
    Small = 1,
    StorageUpgrade = 2,
}
impl NodeRewardType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            NodeRewardType::Unspecified => "NODE_REWARD_TYPE_UNSPECIFIED",
            NodeRewardType::Small => "NODE_REWARD_TYPE_SMALL",
            NodeRewardType::StorageUpgrade => "NODE_REWARD_TYPE_STORAGE_UPGRADE",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "NODE_REWARD_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
            "NODE_REWARD_TYPE_SMALL" => Some(Self::Small),
            "NODE_REWARD_TYPE_STORAGE_UPGRADE" => Some(Self::StorageUpgrade),
            _ => None,
        }
    }
}
