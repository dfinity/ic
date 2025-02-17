mod stable_mem;

use crate::stable_mem::{
    NodeMetricsStored, NodeMetricsStoredKey, SubnetIdStored, TimestampNanos,
    LAST_TS_STORED_PER_SUBNET, NODES_METRICS_PER_SUBNET, SUBNETS_TO_RETRY,
};
use ic_base_types::{PrincipalId, SubnetId};
use ic_cdk::api::call::CallResult;
use ic_cdk_macros::*;
use ic_management_canister_types::{NodeMetricsHistoryArgs, NodeMetricsHistoryResponse};
use ic_protobuf::registry::subnet::v1::SubnetListRecord;
use ic_registry_keys::make_subnet_list_record_key;
use std::collections::BTreeMap;

// Management canisters updates node metrics every day
const HR_IN_SEC: u64 = 60 * 60;
const DAY_SECONDS: u64 = HR_IN_SEC * 24;

/// Fetch metrics
///
/// Calls to the node_metrics_history endpoint of the management canister for all the subnets
/// to get updated metrics since refresh_ts.
async fn fetch_subnets_metrics(
    last_metrics_ts_per_subnet: BTreeMap<SubnetId, TimestampNanos>,
) -> BTreeMap<SubnetId, CallResult<(Vec<NodeMetricsHistoryResponse>,)>> {
    let mut subnets_node_metrics = Vec::new();

    for (subnet_id, last_metrics_ts) in last_metrics_ts_per_subnet {
        let refresh_ts = last_metrics_ts + 1;
        ic_cdk::println!(
            "Updating node metrics for subnet {}: Latest timestamp persisted: {}  Refreshing metrics from timestamp {}",
            subnet_id,
            last_metrics_ts,
            refresh_ts
        );

        let contract = NodeMetricsHistoryArgs {
            subnet_id: subnet_id.get(),
            start_at_timestamp_nanos: refresh_ts,
        };

        subnets_node_metrics.push(async move {
            let call_result =
                ic_cdk::api::call::call_with_payment128::<_, (Vec<NodeMetricsHistoryResponse>,)>(
                    candid::Principal::management_canister(),
                    "node_metrics_history",
                    (contract,),
                    0_u128,
                )
                .await;

            (subnet_id, call_result)
        });
    }

    futures::future::join_all(subnets_node_metrics)
        .await
        .into_iter()
        .collect()
}

async fn sync_subnets_metrics(subnets: Vec<SubnetId>) {
    let last_metrics_ts_per_subnet =
        LAST_TS_STORED_PER_SUBNET.with_borrow(|last_metrics_per_subnet| {
            let mut last_metrics_ts_per_subnet = BTreeMap::new();
            for subnet in subnets {
                let last_metrics_ts = last_metrics_per_subnet.get(&SubnetIdStored(subnet));
                last_metrics_ts_per_subnet.insert(subnet, last_metrics_ts.unwrap_or_default());
            }
            last_metrics_ts_per_subnet
        });
    let fetched_metrics = fetch_subnets_metrics(last_metrics_ts_per_subnet).await;

    for (subnet_id, call_result) in fetched_metrics {
        match call_result {
            Ok((history,)) => {
                // Update the last timestamp for this subnet.
                let last_timestamp = history
                    .last()
                    .map(|entry| entry.timestamp_nanos)
                    .unwrap_or_default();

                LAST_TS_STORED_PER_SUBNET.with_borrow_mut(|last_map| {
                    last_map.insert(SubnetIdStored(subnet_id), last_timestamp);
                });

                // Insert each fetched metric entry into our node metrics map.
                history.into_iter().for_each(|entry| {
                    let key = NodeMetricsStoredKey {
                        timestamp_nanos: entry.timestamp_nanos,
                        subnet_id,
                    };
                    NODES_METRICS_PER_SUBNET.with_borrow_mut(|metrics_map| {
                        metrics_map.insert(key, NodeMetricsStored(entry.node_metrics));
                    });
                });
            }
            Err((code, msg)) => {
                ic_cdk::println!(
                    "Error fetching metrics for subnet {}: CODE: {:?} MSG: {}. Will retry in 1 hour.",
                    subnet_id, code, msg
                );
                // Add subnet to retry list if not already present.
                SUBNETS_TO_RETRY.with_borrow_mut(|retry_list| {
                    if !retry_list.iter().any(|s| s == SubnetIdStored(subnet_id)) {
                        retry_list
                            .push(&SubnetIdStored(subnet_id))
                            .expect("Failed to add subnet to retry list");
                    }
                });
            }
        }
    }
}

/// Fetch subnets
///
/// Fetch subnets from the registry canister
async fn fetch_subnets() -> anyhow::Result<Vec<SubnetId>> {
    let (registry_subnets, _): (SubnetListRecord, _) =
        ic_nns_common::registry::get_value(make_subnet_list_record_key().as_bytes(), None).await?;
    let subnets = registry_subnets
        .subnets
        .into_iter()
        .map(|subnet_id| PrincipalId::try_from(subnet_id).map(SubnetId::from))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(subnets)
}

/// Update node metrics
async fn sync_all_subnets_metrics() {
    let subnets = match fetch_subnets().await {
        Ok(subnets) => subnets,
        Err(e) => {
            ic_cdk::println!("Error fetching subnets: {}", e);
            return;
        }
    };
    sync_subnets_metrics(subnets).await;

    ic_cdk::println!("Successfully updated trustworthy node metrics");
}

async fn retry_subnets() {
    let subnets: Vec<SubnetId> = SUBNETS_TO_RETRY.with_borrow(|subnets_to_retry| {
        subnets_to_retry
            .iter()
            .map(|subnet| subnet.0)
            .collect::<Vec<_>>()
    });

    if subnets.is_empty() {
        ic_cdk::println!("All the subnets metrics are up to date");
        return;
    }
    sync_subnets_metrics(subnets).await;
}

fn setup_default_timers() {
    ic_cdk_timers::set_timer(
        std::time::Duration::from_secs(
            DAY_SECONDS + HR_IN_SEC - (ic_cdk::api::time() / 1_000_000_000) % DAY_SECONDS,
        ),
        || {
            ic_cdk::spawn(sync_all_subnets_metrics());
            ic_cdk_timers::set_timer_interval(std::time::Duration::from_secs(DAY_SECONDS), || {
                ic_cdk::spawn(sync_all_subnets_metrics())
            });
        },
    );

    ic_cdk_timers::set_timer_interval(std::time::Duration::from_secs(HR_IN_SEC), || {
        ic_cdk::spawn(retry_subnets())
    });
}

#[init]
fn init() {
    ic_cdk_timers::set_timer(std::time::Duration::from_secs(0), || {
        ic_cdk::spawn(sync_all_subnets_metrics());
        setup_default_timers();
    });
}

#[post_upgrade]
fn post_upgrade() {
    setup_default_timers();
}

#[query]
fn node_metrics_history(args: NodeMetricsHistoryArgs) -> Vec<NodeMetricsHistoryResponse> {
    NODES_METRICS_PER_SUBNET.with_borrow(|nodes_metrics| {
        let mut node_metrics = Vec::new();
        let first_key = NodeMetricsStoredKey {
            timestamp_nanos: args.start_at_timestamp_nanos,
            subnet_id: args.subnet_id.into(),
        };

        for (key, node_metrics_stored) in nodes_metrics.range(first_key..) {
            if key.subnet_id == args.subnet_id.into() {
                node_metrics.push(NodeMetricsHistoryResponse {
                    timestamp_nanos: key.timestamp_nanos,
                    node_metrics: node_metrics_stored.0,
                });
            }
        }
        node_metrics
    })
}

fn main() {}
