use crate::pb::v1::{
    NodeMetricsDailyStored, SubnetIdKey, SubnetMetricsDailyKeyStored, SubnetMetricsDailyValueStored,
};
use crate::KeyRange;
use async_trait::async_trait;
use candid::Principal;
use ic_base_types::{PrincipalId, SubnetId};
use ic_cdk::api::call::CallResult;
use ic_management_canister_types::{NodeMetricsHistoryArgs, NodeMetricsHistoryRecord};
use ic_stable_structures::StableBTreeMap;
use rewards_calculation::types::{NodeMetricsDailyRaw, SubnetMetricsDailyKey, UnixTsNanos};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};

pub type RetryCount = u64;

#[async_trait]
pub trait ManagementCanisterClient {
    async fn node_metrics_history(
        &self,
        args: NodeMetricsHistoryArgs,
    ) -> CallResult<Vec<NodeMetricsHistoryRecord>>;
}

/// Used to interact with remote Management canisters.
pub struct ICCanisterClient;

#[async_trait]
impl ManagementCanisterClient for ICCanisterClient {
    /// Queries the `node_metrics_history` endpoint of the management canisters of the subnet specified
    /// in the 'contract' to fetch daily node metrics.
    async fn node_metrics_history(
        &self,
        args: NodeMetricsHistoryArgs,
    ) -> CallResult<Vec<NodeMetricsHistoryRecord>> {
        ic_cdk::api::call::call_with_payment128::<_, (Vec<NodeMetricsHistoryRecord>,)>(
            Principal::management_canister(),
            "node_metrics_history",
            (args,),
            0_u128,
        )
        .await
        .map(|(response,)| response)
    }
}

pub struct MetricsManager<Memory>
where
    Memory: ic_stable_structures::Memory,
{
    pub(crate) client: Box<dyn ManagementCanisterClient>,
    pub(crate) subnets_metrics:
        RefCell<StableBTreeMap<SubnetMetricsDailyKeyStored, SubnetMetricsDailyValueStored, Memory>>,
    pub(crate) subnets_to_retry: RefCell<StableBTreeMap<SubnetIdKey, RetryCount, Memory>>,
    pub(crate) last_timestamp_per_subnet: RefCell<StableBTreeMap<SubnetIdKey, UnixTsNanos, Memory>>,
}

impl<Memory> MetricsManager<Memory>
where
    Memory: ic_stable_structures::Memory + 'static,
{
    pub async fn retry_failed_subnets(&self) {
        let subnets_to_retry: Vec<SubnetId> = self
            .subnets_to_retry
            .borrow()
            .keys()
            .map(|key| key.into())
            .collect();

        if !subnets_to_retry.is_empty() {
            ic_cdk::println!("Retrying metrics for subnets: {:?}", subnets_to_retry);
            self.update_subnets_metrics(subnets_to_retry).await;
        }
    }

    /// Update the daily metrics for each node in the subnet.
    fn update_nodes_metrics_daily(
        &self,
        subnet_id: SubnetId,
        last_stored_ts: Option<UnixTsNanos>,
        mut subnet_update: Vec<NodeMetricsHistoryRecord>,
    ) {
        let mut last_total_metrics: HashMap<_, _> = HashMap::new();

        subnet_update.sort_by_key(|metrics| metrics.timestamp_nanos);
        // Extract initial total metrics for each node in the subnet.
        if let Some(first_metrics) = subnet_update.first() {
            if Some(first_metrics.timestamp_nanos) == last_stored_ts {
                last_total_metrics = subnet_update
                    .remove(0)
                    .node_metrics
                    .iter()
                    .map(|node_metrics| {
                        (
                            node_metrics.node_id,
                            (
                                node_metrics.num_blocks_proposed_total,
                                node_metrics.num_block_failures_total,
                            ),
                        )
                    })
                    .collect();
            }
        };

        for one_day_update in subnet_update {
            let mut current_total_metrics = HashMap::new();

            let daily_nodes_metrics: Vec<_> = one_day_update
                .node_metrics
                .into_iter()
                .map(|node_metrics| {
                    let current_proposed_total = node_metrics.num_blocks_proposed_total;
                    let current_failed_total = node_metrics.num_block_failures_total;

                    let (last_proposed_total, last_failed_total) = last_total_metrics
                        .remove(&node_metrics.node_id)
                        // Default is needed if the node joined the subnet after last_stored_ts.
                        .unwrap_or_default();

                    // Update the total metrics for the next iteration.
                    current_total_metrics.insert(
                        node_metrics.node_id,
                        (current_proposed_total, current_failed_total),
                    );

                    NodeMetricsDailyStored {
                        node_id: Some(PrincipalId::from(node_metrics.node_id)),
                        num_blocks_proposed: current_proposed_total - last_proposed_total,
                        num_blocks_failed: current_failed_total - last_failed_total,
                    }
                })
                .collect();

            self.subnets_metrics.borrow_mut().insert(
                SubnetMetricsDailyKeyStored {
                    subnet_id: Some(subnet_id.get()),
                    ts: one_day_update.timestamp_nanos,
                },
                SubnetMetricsDailyValueStored {
                    nodes_metrics: daily_nodes_metrics,
                },
            );
            last_total_metrics = current_total_metrics;
        }
    }

    /// Fetches subnets metrics for the specified subnets from their last timestamp.
    async fn fetch_subnets_metrics(
        &self,
        last_timestamp_per_subnet: &BTreeMap<SubnetId, Option<UnixTsNanos>>,
    ) -> BTreeMap<(SubnetId, Option<UnixTsNanos>), CallResult<Vec<NodeMetricsHistoryRecord>>> {
        let mut subnets_history = Vec::new();

        for (subnet_id, last_stored_ts) in last_timestamp_per_subnet {
            // For nodes that were part of the subnet before this update, we only store DAILY metrics per node.
            // To compute the daily metrics for the first day of this update, we need the TOTAL metrics at last_stored_ts.
            let refresh_ts = last_stored_ts.unwrap_or_default();

            ic_cdk::println!(
                "Updating node metrics for subnet {}: Refreshing metrics from timestamp {}",
                subnet_id,
                refresh_ts
            );

            let contract = NodeMetricsHistoryArgs {
                subnet_id: subnet_id.get().0,
                start_at_timestamp_nanos: refresh_ts,
            };

            subnets_history.push(async move {
                (
                    (*subnet_id, *last_stored_ts),
                    self.client.node_metrics_history(contract).await,
                )
            });
        }

        futures::future::join_all(subnets_history)
            .await
            .into_iter()
            .collect()
    }

    /// Updates the stored subnets metrics from remote management canisters.
    ///
    /// This function fetches the nodes metrics for the given subnets from the management canisters
    /// updating the local metrics with the fetched metrics.
    pub async fn update_subnets_metrics(&self, subnets: Vec<SubnetId>) {
        let last_timestamp_per_subnet: BTreeMap<SubnetId, _> = subnets
            .into_iter()
            .map(|subnet| {
                let last_timestamp = self.last_timestamp_per_subnet.borrow().get(&subnet.into());

                (subnet, last_timestamp)
            })
            .collect();

        let subnets_metrics = self.fetch_subnets_metrics(&last_timestamp_per_subnet).await;
        for ((subnet_id, last_stored_ts), call_result) in subnets_metrics {
            match call_result {
                Ok(subnet_update) => {
                    if subnet_update.is_empty() {
                        ic_cdk::println!("No updates for subnet {}", subnet_id);
                    } else {
                        // Update the last timestamp for this subnet.
                        let last_timestamp = subnet_update
                            .last()
                            .map(|metrics| metrics.timestamp_nanos)
                            .expect("Not empty");
                        self.last_timestamp_per_subnet
                            .borrow_mut()
                            .insert(subnet_id.into(), last_timestamp);

                        self.update_nodes_metrics_daily(subnet_id, last_stored_ts, subnet_update);
                    }

                    self.subnets_to_retry.borrow_mut().remove(&subnet_id.into());
                }
                Err((_, e)) => {
                    ic_cdk::println!(
                        "Error fetching metrics for subnet {}: ERROR: {}",
                        subnet_id,
                        e
                    );

                    // The call failed, will retry fetching metrics for this subnet.
                    let mut retry_count = self
                        .subnets_to_retry
                        .borrow()
                        .get(&subnet_id.into())
                        .unwrap_or_default();
                    retry_count += 1;

                    self.subnets_to_retry
                        .borrow_mut()
                        .insert(subnet_id.into(), retry_count);
                }
            }
        }
    }
    pub fn daily_metrics_by_subnet(
        &self,
        start_ts: UnixTsNanos,
        end_ts: UnixTsNanos,
    ) -> HashMap<SubnetMetricsDailyKey, Vec<NodeMetricsDailyRaw>> {
        let first_key = SubnetMetricsDailyKeyStored {
            ts: start_ts,
            ..SubnetMetricsDailyKeyStored::min_key()
        };
        let last_key = SubnetMetricsDailyKeyStored {
            ts: end_ts,
            ..SubnetMetricsDailyKeyStored::max_key()
        };

        // Group node metrics by node_id within the given time range
        self.subnets_metrics
            .borrow()
            .range(first_key..=last_key)
            .map(|(key, value)| (key.into(), value.into()))
            .collect()
    }
}

#[cfg(test)]
mod tests;
