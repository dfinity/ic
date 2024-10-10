use std::collections::BTreeMap;

use candid::Principal;
use dfn_core::api::PrincipalId;
use futures::FutureExt;
use ic_base_types::NodeId;
use ic_management_canister_types::{NodeMetricsHistoryArgs, NodeMetricsHistoryResponse};
use ic_protobuf::registry::dc::v1::DataCenterRecord;
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_protobuf::registry::subnet::v1::SubnetListRecord;
use ic_registry_keys::{make_data_center_record_key, make_node_operator_record_key, make_node_record_key};

use crate::stable_memory;
use itertools::Itertools;
use trustworthy_node_metrics_types::types::{NodeMetricsGrouped, NodeMetricsStored, NodeMetricsStoredKey};
use trustworthy_node_metrics_types::types::{SubnetNodeMetricsHistory, TimestampNanos};

/// Node metrics storable
///
/// Computes daily proposed/failed blocks from a vector of node metrics
fn node_metrics_storable(
    node_id: PrincipalId,
    node_metrics_grouped: Vec<NodeMetricsGrouped>,
    initial_proposed_total: u64,
    initial_failed_total: u64,
) -> Vec<(NodeMetricsStoredKey, NodeMetricsStored)> {
    let mut metrics_ordered = node_metrics_grouped;
    metrics_ordered.sort_by_key(|(ts, _, _)| *ts);

    let principal = node_id.0;
    let mut node_metrics_storable = Vec::new();

    let mut previous_proposed_total = initial_proposed_total;
    let mut previous_failed_total = initial_failed_total;

    for (ts, subnet_assigned, metrics) in metrics_ordered {
        let key = (ts, principal);
        let current_proposed_total = metrics.num_blocks_proposed_total;
        let current_failed_total = metrics.num_block_failures_total;

        let (daily_proposed, daily_failed) = calculate_daily_metrics(
            previous_proposed_total,
            previous_failed_total,
            metrics.num_blocks_proposed_total,
            metrics.num_block_failures_total,
        );

        let node_metrics_stored = NodeMetricsStored {
            subnet_assigned: subnet_assigned.0,
            num_blocks_proposed_total: current_proposed_total,
            num_blocks_failures_total: current_failed_total,
            num_blocks_proposed: daily_proposed,
            num_blocks_failed: daily_failed,
        };

        node_metrics_storable.push((key, node_metrics_stored));

        previous_proposed_total = current_proposed_total;
        previous_failed_total = current_failed_total;
    }

    node_metrics_storable
}

/// Fetch metrics
///
/// Calls to the node_metrics_history endpoint of the management canister for all the subnets
/// to get updated metrics since refresh_ts.
async fn fetch_metrics(subnets: Vec<PrincipalId>, refresh_ts: TimestampNanos) -> anyhow::Result<Vec<SubnetNodeMetricsHistory>> {
    let mut subnets_node_metrics = Vec::new();

    for subnet_id in subnets {
        let contract = NodeMetricsHistoryArgs {
            subnet_id,
            start_at_timestamp_nanos: refresh_ts,
        };

        let node_metrics = ic_cdk::api::call::call_with_payment128::<_, (Vec<NodeMetricsHistoryResponse>,)>(
            candid::Principal::management_canister(),
            "node_metrics_history",
            (contract,),
            0_u128,
        )
        .map(move |result| {
            result
                .map_err(|(code, msg)| {
                    anyhow::anyhow!(
                        "Error when calling management canister for subnet {}:\n Code:{:?}\nMsg:{}",
                        subnet_id,
                        code,
                        msg
                    )
                })
                .map(|(node_metrics,)| (subnet_id, node_metrics))
        });

        subnets_node_metrics.push(node_metrics);
    }

    let updated_metrics = futures::future::try_join_all(subnets_node_metrics).await?;

    for (subnet, node_metrics) in &updated_metrics {
        ic_cdk::println!("Fetched {} new metrics for subnet: {}", node_metrics.len(), subnet);
    }

    Ok(updated_metrics)
}

/// Fetch subnets
///
/// Fetch subnets from the registry canister
async fn fetch_subnets() -> anyhow::Result<Vec<PrincipalId>> {
    let (registry_subnets, _): (SubnetListRecord, _) = ic_nns_common::registry::get_value("subnet_list".as_bytes(), None).await?;
    let subnets = registry_subnets
        .subnets
        .into_iter()
        .map(|subnet_id: Vec<u8>| PrincipalId::try_from(subnet_id))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(subnets)
}

// Calculates the daily proposed and failed blocks
fn calculate_daily_metrics(last_proposed_total: u64, last_failed_total: u64, current_proposed_total: u64, current_failed_total: u64) -> (u64, u64) {
    if last_failed_total > current_failed_total || last_proposed_total > current_proposed_total {
        // This is the case when node gets redeploied
        (current_proposed_total, current_failed_total)
    } else {
        (current_proposed_total - last_proposed_total, current_failed_total - last_failed_total)
    }
}

fn grouped_by_node(subnet_metrics: Vec<(PrincipalId, Vec<NodeMetricsHistoryResponse>)>) -> BTreeMap<PrincipalId, Vec<NodeMetricsGrouped>> {
    let mut grouped_by_node: BTreeMap<PrincipalId, Vec<NodeMetricsGrouped>> = BTreeMap::new();

    for (subnet_id, history) in subnet_metrics {
        for history_response in history {
            for metrics in history_response.node_metrics {
                grouped_by_node
                    .entry(metrics.node_id)
                    .or_default()
                    .push((history_response.timestamp_nanos, subnet_id, metrics));
            }
        }
    }
    grouped_by_node
}

fn generate_node_type(node_types_count: Option<BTreeMap<String, i32>>, mut rewardable_nodes: BTreeMap<String, u32>) -> String {
    if let Some(node_types) = &node_types_count {
        for (node_type, decrement_value) in node_types.iter() {
            if let Some(reward_count) = rewardable_nodes.get_mut(node_type) {
                *reward_count = reward_count.saturating_sub(*decrement_value as u32);
            }
        }
    }

    if rewardable_nodes.is_empty() {
        "unknown:no_rewardable_nodes_found".to_string()
    } else {
        rewardable_nodes
            .into_iter()
            .find(|(_, v)| *v != 0)
            .map(|(k, _)| k)
            .unwrap_or_else(|| "unknown:rewardable_nodes_used_up".to_string())
    }
}

fn insert_metadata_with_unknown(node_id: Principal, node_operator_id: Principal, node_provider_id: Principal) {
    stable_memory::insert_metadata_v2(
        node_id,
        node_operator_id,
        node_provider_id,
        "unknown".to_string(),
        "unknown".to_string(),
        "unknown".to_string(),
    );
}

async fn update_nodes_metadata(nodes_principal: Vec<&PrincipalId>) {
    for node_principal in nodes_principal {
        if stable_memory::get_node_provider(&node_principal.0).is_some() {
            continue;
        }

        ic_cdk::println!("Fetching metadata for node: {}", node_principal);

        let node_record =
            match ic_nns_common::registry::get_value::<NodeRecord>(make_node_record_key(NodeId::from(*node_principal)).as_bytes(), None).await {
                Ok((node_record, _)) => node_record,
                Err(e) => {
                    ic_cdk::println!("Error fetching node record for {}: {:?}", node_principal, e);
                    insert_metadata_with_unknown(node_principal.0, Principal::anonymous(), Principal::anonymous());
                    continue;
                }
            };

        let node_operator_id = match node_record.node_operator_id.try_into() {
            Ok(id) => id,
            Err(e) => {
                ic_cdk::println!("Error converting node operator ID for {}: {:?}", node_principal, e);
                insert_metadata_with_unknown(node_principal.0, Principal::anonymous(), Principal::anonymous());
                continue;
            }
        };

        let node_operator_record =
            match ic_nns_common::registry::get_value::<NodeOperatorRecord>(make_node_operator_record_key(node_operator_id).as_bytes(), None).await {
                Ok((record, _)) => record,
                Err(e) => {
                    ic_cdk::println!("Error fetching node operator record for {}: {:?}", node_principal, e);
                    insert_metadata_with_unknown(node_principal.0, node_operator_id.0, Principal::anonymous());
                    continue;
                }
            };

        let dc_id = node_operator_record.dc_id;
        let node_types_count: Option<BTreeMap<String, i32>> = stable_memory::node_types_count(node_operator_id.0);
        let node_type = generate_node_type(node_types_count, node_operator_record.rewardable_nodes);

        let node_provider_id: PrincipalId = match node_operator_record.node_provider_principal_id.try_into() {
            Ok(id) => id,
            Err(e) => {
                ic_cdk::println!("Error converting node provider ID for {}: {:?}", node_principal, e);
                stable_memory::insert_metadata_v2(
                    node_principal.0,
                    node_operator_id.0,
                    Principal::anonymous(),
                    dc_id,
                    "unknown".to_string(),
                    node_type,
                );
                continue;
            }
        };

        let data_center_record =
            match ic_nns_common::registry::get_value::<DataCenterRecord>(make_data_center_record_key(&dc_id).as_bytes(), None).await {
                Ok((record, _)) => record,
                Err(e) => {
                    ic_cdk::println!("Error fetching data center record for {}: {:?}", node_principal, e);
                    stable_memory::insert_metadata_v2(
                        node_principal.0,
                        node_operator_id.0,
                        node_provider_id.0,
                        dc_id,
                        "unknown".to_string(),
                        node_type,
                    );
                    continue;
                }
            };

        let region = data_center_record.region;
        stable_memory::insert_metadata_v2(node_principal.0, node_operator_id.0, node_provider_id.0, dc_id, region, node_type);
    }
}

fn update_nodes_metrics(metrics_by_node: BTreeMap<PrincipalId, Vec<NodeMetricsGrouped>>) {
    let principals = metrics_by_node.keys().map(|p| p.0).collect_vec();
    let latest_metrics = stable_memory::latest_metrics(&principals);

    for (node_id, node_metrics_grouped) in metrics_by_node {
        let (initial_proposed_total, initial_failed_total) = latest_metrics
            .get(&node_id.0)
            .map(|metrics| (metrics.num_blocks_proposed_total, metrics.num_blocks_failures_total))
            .unwrap_or((0, 0));
        let node_metrics_storable = node_metrics_storable(node_id, node_metrics_grouped, initial_proposed_total, initial_failed_total);

        for (key, node_metrics) in node_metrics_storable {
            stable_memory::insert_node_metrics(key, node_metrics)
        }
    }
}

/// Update metrics
pub async fn update_metrics() -> anyhow::Result<()> {
    let subnets = fetch_subnets().await?;
    let latest_ts = stable_memory::latest_ts().unwrap_or_default();
    let refresh_ts = latest_ts + 1;

    ic_cdk::println!(
        "Updating node metrics for {} subnets: Latest timestamp persisted: {}  Refreshing metrics from timestamp {}",
        subnets.len(),
        latest_ts,
        refresh_ts
    );
    let subnet_metrics: Vec<(PrincipalId, Vec<NodeMetricsHistoryResponse>)> = fetch_metrics(subnets, refresh_ts).await?;
    let metrics_by_node: BTreeMap<PrincipalId, Vec<NodeMetricsGrouped>> = grouped_by_node(subnet_metrics);
    let nodes_principal: Vec<&PrincipalId> = metrics_by_node.keys().collect_vec();

    update_nodes_metadata(nodes_principal).await;
    update_nodes_metrics(metrics_by_node);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn test_generate_node_type() {
        let mut node_types_count = BTreeMap::new();
        node_types_count.insert("type1".to_string(), 1);
        node_types_count.insert("type2".to_string(), 2);

        // Test Case 1: Normal case with both node types and rewardable nodes
        let mut rewardable_nodes = BTreeMap::new();
        rewardable_nodes.insert("type1".to_string(), 3);
        rewardable_nodes.insert("type2".to_string(), 5);

        let result = generate_node_type(Some(node_types_count.clone()), rewardable_nodes.clone());
        assert_eq!(result, "type1");

        // Test Case 2: Node types that don't match rewardable nodes
        let mut rewardable_nodes = BTreeMap::new();
        rewardable_nodes.insert("type3".to_string(), 4);

        let result = generate_node_type(Some(node_types_count.clone()), rewardable_nodes.clone());
        assert_eq!(result, "type3");

        // Test Case 3: All rewardable nodes are used up
        let mut rewardable_nodes = BTreeMap::new();
        rewardable_nodes.insert("type1".to_string(), 1);
        rewardable_nodes.insert("type2".to_string(), 2);

        let result = generate_node_type(Some(node_types_count.clone()), rewardable_nodes.clone());
        assert_eq!(result, "unknown:rewardable_nodes_used_up");

        // Test Case 4: No rewardable nodes
        let rewardable_nodes = BTreeMap::new();

        let result = generate_node_type(Some(node_types_count.clone()), rewardable_nodes);
        assert_eq!(result, "unknown:no_rewardable_nodes_found");

        // Test Case 3: Normal case with both node types and rewardable nodes
        let mut rewardable_nodes = BTreeMap::new();
        rewardable_nodes.insert("type1".to_string(), 1);
        rewardable_nodes.insert("type2".to_string(), 3);

        let result = generate_node_type(Some(node_types_count), rewardable_nodes.clone());
        assert_eq!(result, "type2");
    }
}
