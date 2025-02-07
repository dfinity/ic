use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_management_canister_types::NodeMetricsHistoryResponse;
use num_traits::FromPrimitive;
use rust_decimal::Decimal;
use std::collections::HashMap;
use std::fmt;

use crate::v1_logs::RewardsLog;

pub type RegionNodeTypeCategory = (String, String);
pub type TimestampNanos = u64;
pub type SubnetMetricsHistory = (PrincipalId, Vec<NodeMetricsHistoryResponse>);

#[derive(Clone, Hash, Eq, PartialEq)]
pub struct RewardableNode {
    pub node_id: NodeId,
    pub node_provider_id: PrincipalId,
    pub region: String,
    pub node_type: String,
}

#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub struct DailyNodeMetrics {
    pub ts: u64,
    pub subnet_assigned: SubnetId,
    pub num_blocks_proposed: u64,
    pub num_blocks_failed: u64,
    pub failure_rate: Decimal,
}

impl Default for DailyNodeMetrics {
    fn default() -> Self {
        DailyNodeMetrics {
            ts: 0,
            subnet_assigned: SubnetId::from(PrincipalId::new_anonymous()),
            num_blocks_proposed: 0,
            num_blocks_failed: 0,
            failure_rate: Decimal::ZERO,
        }
    }
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
        subnet_assigned: SubnetId,
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

#[derive(PartialEq, Eq, Debug)]
pub struct RewardsPerNodeProvider {
    pub rewards_per_node_provider: HashMap<PrincipalId, Rewards>,
    pub rewards_log_per_node_provider: HashMap<PrincipalId, RewardsLog>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rewards {
    pub xdr_permyriad: u64,
    pub xdr_permyriad_no_reduction: u64,
}
