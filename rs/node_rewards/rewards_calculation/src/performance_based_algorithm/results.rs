use chrono::NaiveDate;
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_protobuf::registry::node::v1::NodeRewardType;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type Region = String;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct NodeMetricsDaily {
    /// The subnet this node was assigned to on the given day.
    /// This is determined by the subnet assigned to the node in the last registry version
    /// before the next day's registry version was generated.
    pub subnet_assigned: SubnetId,

    /// Subnet Assigned Failure Rate
    ///
    /// This is the SUBNET_FAILURE_RATE_PERCENTILE of the original_fr all nodes in the subnet.
    /// It is used to adjust individual node failure rates to account for systematic issues
    /// affecting the whole subnet.
    pub subnet_assigned_failure_rate: Decimal,

    /// Number of blocks successfully proposed by this node on this day
    pub num_blocks_proposed: u64,

    /// Number of blocks that failed to be included on this day
    pub num_blocks_failed: u64,

    /// Original Failure Rate
    ///
    /// Calculated as `num_blocks_failed / (num_blocks_proposed + num_blocks_failed)`.
    /// Represents the failure rate of the node before any subnet-level adjustments.
    pub original_failure_rate: Decimal,

    /// Relative Failure Rate
    ///
    /// Failure rate adjusted for subnet performance.
    /// Calculated as `max(0, original_fr - subnet_assigned_fr_percent)`.
    /// TODO: Link documentation about performance based rewards algorithm
    pub relative_failure_rate: Decimal,
}

// TODO: Link documentation about performance based rewards algorithm
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum DailyNodeFailureRate {
    /// Node is assigned to a subnet with recorded metrics
    SubnetMember { node_metrics: NodeMetricsDaily },

    /// Node is unassigned; only extrapolated failure rate is available
    NonSubnetMember {
        /// Extrapolated Failure Rate (EFR)
        /// Used to estimate the node's performance when unassigned
        extrapolated_failure_rate: Decimal,
    },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct DailyNodeRewards {
    pub node_id: NodeId,

    pub node_reward_type: NodeRewardType,

    /// Geographical region of the node
    /// TODO: Link to documentation about performance based rewards
    pub region: String,

    /// Data center identifier
    /// TODO: Link to documentation about performance based rewards
    pub dc_id: String,

    /// Daily node failure rate
    pub daily_node_failure_rate: DailyNodeFailureRate,

    /// Performance multiplier (1 - rewards_reduction)
    ///
    /// Represents how rewards are adjusted based on node performance
    pub performance_multiplier: Decimal,

    /// Rewards reduction applied due to failure rates
    // TODO: Link to documentation about performance based rewards
    pub rewards_reduction: Decimal,

    /// Base rewards before applying performance multipliers
    pub base_rewards_xdr_permyriad: Decimal,

    /// Rewards adjusted by the performance multiplier
    pub adjusted_rewards_xdr_permyriad: Decimal,
}

/// Base rewards for NON type 3 nodes.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct NodeTypeRegionBaseRewards {
    /// NodeRewardType
    pub node_reward_type: NodeRewardType,

    /// Region for which base rewards are calculated
    pub region: Region,

    /// Monthly base rewards in XDR permyriad
    pub monthly_xdr_permyriad: Decimal,

    /// Daily base rewards in XDR permyriad
    pub daily_xdr_permyriad: Decimal,
}

/// Base rewards for a Type 3 node.
///
/// Type3 nodes are defined [rs/protobuf/src/gen/registry/registry.node.v1.rs]
/// For nodes which are type3 special logic is applied to compute base rewards.
/// Check the documentation of the performance-based rewards algorithm for details.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Type3RegionBaseRewards {
    /// Region for which the rewards are calculated
    pub region: Region,

    /// Number of nodes in the region
    pub nodes_count: usize,

    /// Average rewards for nodes in this region
    pub avg_rewards_xdr_permyriad: Decimal,

    /// Average performance coefficient applied to nodes
    pub avg_coefficient: Decimal,

    /// Base rewards value for Type 3 nodes
    pub daily_xdr_permyriad: Decimal,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct DailyNodeProviderRewards {
    /// Total daily base rewards across all nodes for this provider in XDR permyriad
    pub total_base_rewards_xdr_permyriad: u64,

    /// Total daily rewards adjusted across all nodes for this provider in XDR permyriad
    pub total_adjusted_rewards_xdr_permyriad: u64,

    /// Base rewards broken down by node type and region
    pub base_rewards: Vec<NodeTypeRegionBaseRewards>,

    /// Base rewards broken down by "type 3" grouping (region aggregates)
    pub type3_base_rewards: Vec<Type3RegionBaseRewards>,

    /// Daily rewards for each node managed by this provider
    pub daily_nodes_rewards: Vec<DailyNodeRewards>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct DailyResults {
    /// Failure rates for all subnets on this day
    pub subnets_failure_rate: BTreeMap<SubnetId, Decimal>,

    /// Rewards for all node providers on this day
    pub provider_results: BTreeMap<PrincipalId, DailyNodeProviderRewards>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RewardsCalculatorResults {
    // Algorithm version used to calculate the results.
    pub algorithm_version: u32,

    /// Total rewards for each provider across the entire reward period
    pub total_rewards_xdr_permyriad: BTreeMap<PrincipalId, u64>,

    /// Daily breakdown of results
    pub daily_results: BTreeMap<NaiveDate, DailyResults>,
}
