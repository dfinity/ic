use crate::v1_logs::RewardsLog;
use ic_base_types::PrincipalId;
use ic_management_canister_types::NodeMetricsHistoryResponse;
use num_traits::FromPrimitive;
use rust_decimal::Decimal;
use std::collections::HashMap;
use std::fmt;

pub type RegionNodeTypeCategory = (String, String);
pub type TimestampNanos = u64;
pub type SubnetMetricsHistory = (PrincipalId, Vec<NodeMetricsHistoryResponse>);

#[derive(Clone, Hash, Eq, PartialEq)]
pub struct RewardableNode {
    pub node_id: PrincipalId,
    pub node_provider_id: PrincipalId,
    pub region: String,
    pub node_type: String,
}

#[derive(Clone, Hash, Eq, PartialEq, Debug, Default)]
pub struct DailyNodeMetrics {
    pub ts: u64,
    pub subnet_assigned: PrincipalId,
    pub num_blocks_proposed: u64,
    pub num_blocks_failed: u64,
    pub failure_rate: Decimal,
}

impl fmt::Display for DailyNodeMetrics {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "num_blocks_proposed: {},  num_blocks_failed: {}, failure_rate: {}",
            self.num_blocks_proposed, self.num_blocks_failed, self.failure_rate
        )
    }
}

impl DailyNodeMetrics {
    pub fn new(
        ts: u64,
        subnet_assigned: PrincipalId,
        num_blocks_proposed: u64,
        num_blocks_failed: u64,
    ) -> Self {
        let daily_total = num_blocks_proposed + num_blocks_failed;
        let failure_rate = if daily_total == 0 {
            Decimal::ZERO
        } else {
            Decimal::from_f64(num_blocks_failed as f64 / daily_total as f64).unwrap()
        };
        DailyNodeMetrics {
            ts,
            num_blocks_proposed,
            num_blocks_failed,
            subnet_assigned,
            failure_rate,
        }
    }
}

#[derive(Default)]
pub struct NodeProviderComputationData {
    pub rewards_multiplier: HashMap<PrincipalId, Decimal>,
    pub avg_assigned_failure_rate: HashMap<PrincipalId, Decimal>,
    pub region_nodetype_rewards: HashMap<RegionNodeTypeCategory, Decimal>,
    pub node_provider_rewardables: Vec<RewardableNode>,
    pub assigned_metrics: HashMap<PrincipalId, Vec<DailyNodeMetrics>>,
    pub node_daily_fr: HashMap<PrincipalId, Vec<Decimal>>,
    pub failure_rate_rewarding_period: HashMap<PrincipalId, Decimal>,
    pub unassigned_fr: Decimal,
    pub multiplier_unassigned: Decimal,
    pub rewards_xdr_no_penalty_total: HashMap<PrincipalId, Decimal>,
    pub rewards_xdr: HashMap<PrincipalId, Decimal>,
}
pub struct RewardsPerNodeProvider {
    pub rewards_per_node_provider: HashMap<PrincipalId, Rewards>,
    pub rewards_log_per_node_provider: HashMap<PrincipalId, RewardsLog>,
    pub rewards_data_per_node_provider: HashMap<PrincipalId, NodeProviderComputationData>,
    pub systematic_failure_rates: HashMap<PrincipalId, Vec<(TimestampNanos, Decimal)>>,
}

#[derive(Debug, Clone)]
pub struct Rewards {
    pub xdr_permyriad: u64,
    pub xdr_permyriad_no_reduction: u64,
}
