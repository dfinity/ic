use candid::Principal;
use chrono_utils::DateTimeRange;
use ic_cdk_macros::*;
use itertools::Itertools;
use std::collections::{btree_map::Entry, BTreeMap};
use types::{
    NodeMetadata, NodeMetrics, NodeMetricsStored, NodeMetricsStoredKey, NodeProviderRewards, NodeProviderRewardsArgs, NodeProviderRewardsAvg, NodeRewardsArgs, NodeRewardsMultiplier, SubnetNodeMetricsArgs, SubnetNodeMetricsResponse, Take
};
mod chrono_utils;
mod computation_logger;
mod metrics_manager;
mod rewards_manager;
mod stable_memory;
mod types;

// Management canisters updates node metrics every day
const TIMER_INTERVAL_SEC: u64 = 60 * 60 * 24;

async fn update_metrics_task() {
    match metrics_manager::update_metrics().await {
        Ok(_) => {
            ic_cdk::println!("Successfully updated metrics");
        }
        Err(e) => {
            ic_cdk::println!("Error updating metrics: {}", e);
        }
    }

    match rewards_manager::update_node_rewards_table().await {
        Ok(_) => {
            ic_cdk::println!("Successfully updated node_rewards_table");
        }
        Err(e) => {
            ic_cdk::println!("Error updating node_rewards_table: {}", e);
        }
    }

    match rewards_manager::update_recent_provider_rewards().await {
        Ok(_) => {
            ic_cdk::println!("Successfully updated recent provider rewards");
        }
        Err(e) => {
            ic_cdk::println!("Error updated recent provider rewards: {}", e);
        }
    }
}

fn setup_timers() {
    ic_cdk_timers::set_timer(std::time::Duration::from_secs(0), || ic_cdk::spawn(update_metrics_task()));
    ic_cdk_timers::set_timer_interval(
        std::time::Duration::from_secs(TIMER_INTERVAL_SEC),
        || ic_cdk::spawn(update_metrics_task()),
    );
}

#[init]
fn init() {
    setup_timers();
}

#[post_upgrade]
fn post_upgrade() {
    setup_timers();
}

#[query]
fn subnet_node_metrics(args: SubnetNodeMetricsArgs) -> Result<Vec<SubnetNodeMetricsResponse>, String> {
    let from_ts = args.ts.unwrap_or_default();
    let mut subnet_node_metrics: BTreeMap<(u64, Principal), Vec<NodeMetrics>> = BTreeMap::new();

    let node_metrics: Vec<(NodeMetricsStoredKey, NodeMetricsStored)> = stable_memory::get_metrics_range(from_ts, None, None);

    for ((ts, node_id), node_metrics_value) in node_metrics {
        if let Some(subnet_id) = args.subnet_id {
            if subnet_id != node_metrics_value.subnet_assigned {
                continue;
            }
        }

        let result_key = (ts, node_metrics_value.subnet_assigned);
        let result_value: NodeMetrics = NodeMetrics {
            node_id,
            num_blocks_proposed_total: node_metrics_value.num_blocks_proposed_total,
            num_blocks_failures_total: node_metrics_value.num_blocks_failures_total,
        };

        match subnet_node_metrics.entry(result_key) {
            Entry::Occupied(mut entry) => {
                let v: &mut Vec<NodeMetrics> = entry.get_mut();
                v.push(result_value)
            }
            Entry::Vacant(entry) => {
                entry.insert(vec![result_value]);
            }
        }
    }

    let result = subnet_node_metrics
        .into_iter()
        .map(|((ts, subnet_id), node_metrics)| SubnetNodeMetricsResponse { ts, subnet_id, node_metrics })
        .collect_vec();

    Ok(result)
}

#[query]
fn nodes_metadata() -> Vec<NodeMetadata> {
    stable_memory::nodes_metadata()
}

#[query]
fn node_rewards(args: NodeRewardsArgs) -> NodeRewardsMultiplier {
    let rewarding_period = DateTimeRange::new(args.from_ts, args.to_ts);
    let node_id = args.node_id;

    let rewards = rewards_manager::node_rewards_multiplier(vec![node_id], rewarding_period);
    rewards.into_iter().next().unwrap()
}

#[query]
fn node_provider_rewards(args: NodeProviderRewardsArgs) -> NodeProviderRewards {
    let rewarding_period = DateTimeRange::new(args.from_ts, args.to_ts);
    let node_provider_id = args.node_provider_id;

    rewards_manager::node_provider_rewards(node_provider_id, rewarding_period)
}
