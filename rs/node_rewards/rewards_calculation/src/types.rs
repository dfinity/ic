use ic_base_types::NodeId;
use ic_protobuf::registry::node::v1::NodeRewardType;

pub type UnixTsNanos = u64;
pub type NodesCount = u64;
pub type Region = String;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NodeMetricsDailyRaw {
    pub node_id: NodeId,
    pub num_blocks_proposed: u64,
    pub num_blocks_failed: u64,
}

#[derive(Eq, Hash, PartialEq, Clone, Ord, PartialOrd, Debug)]
pub struct RewardableNode {
    pub node_id: NodeId,
    pub region: Region,
    pub node_reward_type: NodeRewardType,
    pub dc_id: String,
}
