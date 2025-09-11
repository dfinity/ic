use crate::types::Region;
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_protobuf::registry::node::v1::NodeRewardType;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type XDRPermyriad = Decimal;
pub type Percent = Decimal;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NodeMetricsDaily {
    pub subnet_assigned: SubnetId,
    pub subnet_assigned_fr: Percent,
    pub num_blocks_proposed: u64,
    pub num_blocks_failed: u64,
    /// The failure rate before subnet failure rate reduction.
    /// Calculated as `blocks_failed` / (`blocks_proposed` + `blocks_failed`)
    pub original_fr: Percent,
    /// The failure rate reduced by the subnet assigned failure rate.
    /// Calculated as Max(0, `original_fr` - `subnet_assigned_fr`)
    pub relative_fr: Percent,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum NodeStatus {
    Assigned { node_metrics: NodeMetricsDaily },
    Unassigned { extrapolated_fr: Percent },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct NodeResults {
    pub node_id: NodeId,
    pub node_reward_type: NodeRewardType,
    pub region: String,
    pub dc_id: String,
    pub node_status: NodeStatus,
    pub performance_multiplier: Percent,
    pub rewards_reduction: Percent,
    pub base_rewards: XDRPermyriad,
    pub adjusted_rewards: XDRPermyriad,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct BaseRewards {
    pub node_reward_type: NodeRewardType,
    pub region: Region,
    pub monthly: XDRPermyriad,
    pub daily: XDRPermyriad,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct BaseRewardsType3 {
    pub region: Region,
    pub nodes_count: usize,
    pub avg_rewards: XDRPermyriad,
    pub avg_coefficient: Percent,
    pub value: XDRPermyriad,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct NodeProviderRewards {
    pub rewards_total_xdr_permyriad: u64,
    pub base_rewards: Vec<BaseRewards>,
    pub base_rewards_type3: Vec<BaseRewardsType3>,
    pub nodes_results: Vec<NodeResults>,
}

#[derive(Serialize, Deserialize)]
pub struct RewardsCalculatorResults {
    pub subnets_fr: BTreeMap<SubnetId, Percent>,
    pub provider_results: BTreeMap<PrincipalId, NodeProviderRewards>,
}
