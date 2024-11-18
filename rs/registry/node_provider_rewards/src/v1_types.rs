use std::{
    collections::{HashMap, HashSet},
    hash::BuildHasherDefault,
};

use candid::CandidType;
use ic_base_types::PrincipalId;
use ic_management_canister_types::{NodeMetrics, NodeMetricsHistoryResponse};
use serde::Deserialize;

use crate::v1_logs::RewardsLog;

pub type NodeMultiplierStats = (PrincipalId, MultiplierStats);
pub type RewardablesWithNodesMetrics = (
    AHashMap<RegionNodeTypeCategory, u32>,
    AHashMap<RewardableNode, Vec<DailyNodeMetrics>>,
);
pub type RegionNodeTypeCategory = (String, String);
pub type TimestampNanos = u64;
pub type AHashSet<K> = HashSet<K, BuildHasherDefault<ahash::AHasher>>;
pub type AHashMap<K, V> = HashMap<K, V, BuildHasherDefault<ahash::AHasher>>;

#[derive(Clone, Hash, Eq, PartialEq)]
pub struct RewardableNode {
    pub node_id: PrincipalId,
    pub node_provider_id: PrincipalId,
    pub region: String,
    pub node_type: String,
    pub node_metrics: Option<Vec<DailyNodeMetrics>>,
}

#[derive(Clone, Hash, Eq, PartialEq)]
pub struct DailyNodeMetrics {
    pub num_blocks_proposed: u64,
    pub num_blocks_failed: u64,
}

pub struct NodesMetricsHistory(Vec<NodeMetricsHistoryResponse>);

impl From<NodesMetricsHistory> for AHashMap<PrincipalId, Vec<DailyNodeMetrics>> {
    fn from(nodes_metrics: NodesMetricsHistory) -> Self {
        let mut sorted_metrics = nodes_metrics.0;
        sorted_metrics.sort_by_key(|metrics| metrics.timestamp_nanos);
        let mut sorted_metrics_per_node: AHashMap<PrincipalId, Vec<NodeMetrics>> =
            AHashMap::default();

        for metrics in sorted_metrics {
            for node_metrics in metrics.node_metrics {
                sorted_metrics_per_node
                    .entry(node_metrics.node_id)
                    .or_default()
                    .push(node_metrics);
            }
        }

        sorted_metrics_per_node
            .into_iter()
            .map(|(node_id, metrics)| {
                let mut daily_node_metrics = Vec::new();
                let mut previous_proposed_total = 0;
                let mut previous_failed_total = 0;

                for node_metrics in metrics {
                    let current_proposed_total = node_metrics.num_blocks_proposed_total;
                    let current_failed_total = node_metrics.num_block_failures_total;

                    let (num_blocks_proposed, num_blocks_failed) = if previous_failed_total
                        > current_failed_total
                        || previous_proposed_total > current_proposed_total
                    {
                        // This is the case when node is deployed again
                        (current_proposed_total, current_failed_total)
                    } else {
                        (
                            current_proposed_total - previous_proposed_total,
                            current_failed_total - previous_failed_total,
                        )
                    };

                    daily_node_metrics.push(DailyNodeMetrics {
                        num_blocks_proposed,
                        num_blocks_failed,
                    });

                    previous_proposed_total = num_blocks_proposed;
                    previous_failed_total = num_blocks_failed;
                }
                (node_id, daily_node_metrics)
            })
            .collect()
    }
}

#[derive(Debug, Clone, Deserialize, CandidType)]
pub struct MultiplierStats {
    pub days_assigned: u64,
    pub days_unassigned: u64,
    pub rewards_reduction: f64,
    pub blocks_failed: u64,
    pub blocks_proposed: u64,
    pub blocks_total: u64,
    pub failure_rate: f64,
}

pub struct RewardsPerNodeProvider {
    pub rewards_per_node_provider: AHashMap<PrincipalId, (Rewards, Vec<NodeMultiplierStats>)>,
    pub rewards_log_per_node_provider: AHashMap<PrincipalId, RewardsLog>,
}

#[derive(Debug, Clone)]
pub struct Rewards {
    pub xdr_permyriad: u64,
    pub xdr_permyriad_no_reduction: u64,
}
