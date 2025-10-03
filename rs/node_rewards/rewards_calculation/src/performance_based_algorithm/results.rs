use chrono::NaiveDate;
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_protobuf::registry::node::v1::NodeRewardType;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type XDRPermyriad = Decimal; // Rewards unit in XDR scaled by 1/10,000 (permyriad)
pub type Percent = Decimal;
pub type Region = String;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct NodeMetricsDaily {
    /// The subnet to which this node was assigned on this day
    pub subnet_assigned: SubnetId,
    /// Subnet Assigned Failure Rate
    ///
    /// The failure rate of the entire subnet for this day.
    pub subnet_assigned_fr: Percent,
    /// Number of blocks proposed by this node on this day
    pub num_blocks_proposed: u64,
    /// Number of blocks that failed to be included on this day
    pub num_blocks_failed: u64,
    /// Original Failure Rate
    ///
    /// Calculated as `num_blocks_failed / (num_blocks_proposed + num_blocks_failed)`.
    /// Represents the raw failure rate of the node before any subnet-level adjustments.
    pub original_fr: Percent,
    /// Relative Failure Rate
    ///
    /// Failure rate adjusted for subnet performance.
    /// Calculated as `max(0, original_fr - subnet_assigned_fr)`.
    pub relative_fr: Percent,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum NodeStatus {
    /// Node is assigned to a subnet with recorded metrics
    Assigned { node_metrics: NodeMetricsDaily },
    /// Node is unassigned; only extrapolated failure rate is available
    Unassigned {
        /// Extrapolated Failure Rate (EFR)
        /// Used to estimate the node's performance when unassigned
        extrapolated_fr: Percent,
    },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct NodeResults {
    /// Unique identifier of the node
    pub node_id: NodeId,
    /// NodeRewardType
    pub node_reward_type: NodeRewardType,
    /// Geographical region of the node
    pub region: String,
    /// Data center identifier
    pub dc_id: String,
    /// Node status, assigned or unassigned, with associated metrics
    pub node_status: NodeStatus,
    /// Performance multiplier (1 - rewards_reduction)
    ///
    /// Represents how rewards are adjusted based on node performance
    pub performance_multiplier: Percent,
    /// Rewards reduction applied due to failure rates
    pub rewards_reduction: Percent,
    /// Base rewards before applying performance multipliers
    pub base_rewards: XDRPermyriad,
    /// Rewards adjusted by the performance multiplier
    pub adjusted_rewards: XDRPermyriad,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct BaseRewards {
    /// NodeRewardType
    pub node_reward_type: NodeRewardType,
    /// Region for which base rewards are calculated
    pub region: Region,
    /// Monthly base rewards in XDR permyriad
    pub monthly: XDRPermyriad,
    /// Daily base rewards in XDR permyriad
    pub daily: XDRPermyriad,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct BaseRewardsType3 {
    /// Region for which the rewards are calculated
    pub region: Region,
    /// Number of nodes in the region
    pub nodes_count: usize,
    /// Average rewards for nodes in this region
    pub avg_rewards: XDRPermyriad,
    /// Average performance coefficient applied to nodes
    pub avg_coefficient: Percent,
    /// Base rewards value for Type 3 nodes
    pub value: XDRPermyriad,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct NodeProviderRewards {
    /// Total rewards across all nodes for this provider in XDR permyriad
    pub rewards_total: XDRPermyriad,
    /// Base rewards broken down by node type and region
    pub base_rewards: Vec<BaseRewards>,
    /// Base rewards broken down by "type 3" grouping (region aggregates)
    pub base_rewards_type3: Vec<BaseRewardsType3>,
    /// Results for each node managed by this provider
    pub nodes_results: Vec<NodeResults>,
}

#[derive(Serialize, Deserialize)]
pub struct DailyResults {
    /// Failure rates for all subnets on this day
    pub subnets_fr: BTreeMap<SubnetId, Percent>,
    /// Rewards for all node providers on this day
    pub provider_results: BTreeMap<PrincipalId, NodeProviderRewards>,
}

pub struct RewardsCalculatorResults {
    /// Total rewards for each provider across the entire reward period
    pub total_rewards_xdr_permyriad: BTreeMap<PrincipalId, u64>,
    /// Daily breakdown of results
    pub daily_results: BTreeMap<NaiveDate, DailyResults>,
}
