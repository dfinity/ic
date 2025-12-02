use crate::KeyRange;
use crate::chrono_utils::{first_unix_timestamp_nanoseconds, last_unix_timestamp_nanoseconds};
use crate::pb::v1::{SubnetIdKey, SubnetMetricsKey, SubnetMetricsValue};
use async_trait::async_trait;
use candid::Principal;
use chrono::{DateTime, NaiveDate};
use ic_base_types::{NodeId, SubnetId};
use ic_cdk::call::CallResult;
use ic_management_canister_types::{NodeMetricsHistoryArgs, NodeMetricsHistoryRecord};
use ic_stable_structures::StableBTreeMap;
use itertools::Itertools;
use rewards_calculation::types::{NodeMetricsDailyRaw, UnixTsNanos};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};

pub type RetryCount = u64;

#[async_trait]
pub trait ManagementCanisterClient {
    async fn node_metrics_history(
        &self,
        args: &NodeMetricsHistoryArgs,
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
        args: &NodeMetricsHistoryArgs,
    ) -> CallResult<Vec<NodeMetricsHistoryRecord>> {
        ic_cdk::management_canister::node_metrics_history(args)
    }
}

pub struct MetricsManager<Memory>
where
    Memory: ic_stable_structures::Memory,
{
    pub(crate) client: Box<dyn ManagementCanisterClient>,
    pub(crate) subnets_metrics:
        RefCell<StableBTreeMap<SubnetMetricsKey, SubnetMetricsValue, Memory>>,
    pub(crate) last_timestamp_per_subnet: RefCell<StableBTreeMap<SubnetIdKey, UnixTsNanos, Memory>>,
}

impl<Memory> MetricsManager<Memory>
where
    Memory: ic_stable_structures::Memory + 'static,
{
    /// Fetches subnets metrics for the specified subnets from their last stored timestamp.
    async fn fetch_subnets_metrics(
        &self,
        last_timestamp_per_subnet: &BTreeMap<SubnetId, UnixTsNanos>,
    ) -> BTreeMap<SubnetId, CallResult<Vec<NodeMetricsHistoryRecord>>> {
        let mut subnets_history = Vec::new();
        ic_cdk::println!(
            "Updating node metrics for {} subnets",
            last_timestamp_per_subnet.keys().count()
        );

        for (subnet_id, last_stored_ts) in last_timestamp_per_subnet {
            let args = NodeMetricsHistoryArgs {
                subnet_id: subnet_id.get().0,
                start_at_timestamp_nanos: *last_stored_ts,
            };

            subnets_history
                .push(async move { (*subnet_id, self.client.node_metrics_history(&args).await) });
        }

        futures::future::join_all(subnets_history)
            .await
            .into_iter()
            .collect()
    }

    fn last_timestamp_per_subnet(&self, subnets: Vec<SubnetId>) -> BTreeMap<SubnetId, UnixTsNanos> {
        subnets
            .into_iter()
            .map(|subnet| {
                let last_timestamp = self
                    .last_timestamp_per_subnet
                    .borrow()
                    .get(&subnet.into())
                    .unwrap_or_default();

                (subnet, last_timestamp)
            })
            .collect()
    }

    /// Updates the stored subnets metrics from remote management canisters.
    ///
    /// This function fetches the nodes metrics for the given subnets from the management canisters
    /// updating the local metrics with the fetched metrics.
    /// If all subnets metrics are fetched successfully, it returns the last date
    /// for which metrics were updated.
    pub async fn update_subnets_metrics(
        &self,
        subnets: Vec<SubnetId>,
    ) -> Result<NaiveDate, String> {
        let mut success = true;
        let last_timestamp_per_subnet = self.last_timestamp_per_subnet(subnets.clone());
        let subnets_metrics = self.fetch_subnets_metrics(&last_timestamp_per_subnet).await;
        for (subnet_id, call_result) in subnets_metrics {
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

                        for NodeMetricsHistoryRecord {
                            timestamp_nanos,
                            node_metrics,
                        } in subnet_update
                        {
                            self.subnets_metrics.borrow_mut().insert(
                                SubnetMetricsKey {
                                    timestamp_nanos,
                                    subnet_id: Some(subnet_id.get()),
                                },
                                SubnetMetricsValue {
                                    nodes_metrics: node_metrics
                                        .into_iter()
                                        .map(|m| m.into())
                                        .collect(),
                                },
                            );
                        }

                        let date =
                            DateTime::from_timestamp_nanos(last_timestamp as i64).date_naive();
                        ic_cdk::println!(
                            "Successfully updated subnet {} metrics for date: {}",
                            subnet_id,
                            date
                        );
                    }
                }
                Err(e) => {
                    success = false;
                    ic_cdk::println!(
                        "Error fetching metrics for subnet {}: ERROR: {}",
                        subnet_id,
                        e
                    );
                }
            }
        }

        if success {
            let max_ts_update = self
                .last_timestamp_per_subnet(subnets)
                .into_values()
                .max()
                .unwrap_or_default();
            let last_day_update = DateTime::from_timestamp_nanos(max_ts_update as i64).date_naive();

            Ok(last_day_update)
        } else {
            Err("Failed to update metrics".to_string())
        }
    }

    /// Computes daily node metrics for a specific date.
    ///
    /// This is done by subtracting the total metrics of the
    /// previous date from those of the current date.
    pub fn metrics_by_subnet(
        &self,
        date: &NaiveDate,
    ) -> BTreeMap<SubnetId, Vec<NodeMetricsDailyRaw>> {
        let mut metrics_by_subnet = BTreeMap::new();
        let first_key = SubnetMetricsKey {
            timestamp_nanos: first_unix_timestamp_nanoseconds(&date.pred_opt().unwrap()),
            ..SubnetMetricsKey::min_key()
        };
        let last_key = SubnetMetricsKey {
            timestamp_nanos: last_unix_timestamp_nanoseconds(date),
            ..SubnetMetricsKey::max_key()
        };

        let mut subnets_metrics_by_date: BTreeMap<NaiveDate, _> = self
            .subnets_metrics
            .borrow()
            .range(first_key..=last_key)
            .into_group_map_by(|(k, _)| {
                DateTime::from_timestamp_nanos(k.timestamp_nanos as i64).date_naive()
            })
            .into_iter()
            .collect();

        let mut initial_total_metrics: HashMap<_, _> = HashMap::new();
        if let Some((stored_date, _)) = subnets_metrics_by_date.first_key_value()
            && stored_date < date
        {
            initial_total_metrics = subnets_metrics_by_date
                .pop_first()
                .unwrap()
                .1
                .into_iter()
                .flat_map(|(k, v)| {
                    v.nodes_metrics.into_iter().map(move |node_metrics| {
                        (
                            (k.subnet_id, node_metrics.node_id),
                            (
                                node_metrics.num_blocks_proposed_total,
                                node_metrics.num_blocks_failed_total,
                            ),
                        )
                    })
                })
                .collect();
        };

        for (_, subnets_metrics) in subnets_metrics_by_date {
            for (k, v) in subnets_metrics {
                let subnet_id = SubnetId::from(k.subnet_id.unwrap());

                let daily_nodes_metrics: Vec<NodeMetricsDailyRaw> = v
                    .nodes_metrics
                    .into_iter()
                    .map(|node| {
                        let (initial_proposed_total, initial_failed_total) = initial_total_metrics
                            .remove(&(k.subnet_id, node.node_id))
                            .unwrap_or_default();
                        NodeMetricsDailyRaw {
                            node_id: NodeId::from(node.node_id.unwrap()),
                            num_blocks_proposed: node.num_blocks_proposed_total
                                - initial_proposed_total,
                            num_blocks_failed: node.num_blocks_failed_total - initial_failed_total,
                        }
                    })
                    .collect();

                metrics_by_subnet.insert(subnet_id, daily_nodes_metrics);
            }
        }

        metrics_by_subnet
    }
}

#[cfg(feature = "test")]
pub mod management_canister_client_test {
    use crate::chrono_utils::last_unix_timestamp_nanoseconds;
    use crate::metrics::ManagementCanisterClient;
    use crate::storage::RegistryStoreStableMemoryBorrower;
    use async_trait::async_trait;
    use candid::Principal;
    use chrono::DateTime;
    use ic_base_types::SubnetId;
    use ic_cdk::call::CallResult;
    use ic_management_canister_types::{NodeMetricsHistoryArgs, NodeMetricsHistoryRecord};
    use ic_nervous_system_canisters::registry::RegistryCanister;
    use ic_registry_canister_client::StableCanisterRegistryClient;
    use std::sync::Arc;

    thread_local! {
        static REGISTRY_STORE_TEST: Arc<StableCanisterRegistryClient<RegistryStoreStableMemoryBorrower>> = {
            let store = StableCanisterRegistryClient::<RegistryStoreStableMemoryBorrower>::new(
                Arc::new(RegistryCanister::new()));
            Arc::new(store)
        };
    }

    /// Used to interact with remote Management canisters.
    pub struct ICCanisterClient;

    #[async_trait]
    impl ManagementCanisterClient for ICCanisterClient {
        async fn node_metrics_history(
            &self,
            args: &NodeMetricsHistoryArgs,
        ) -> CallResult<Vec<NodeMetricsHistoryRecord>> {
            use crate::canister::current_time;
            use crate::registry_querier::RegistryQuerier;
            use ic_base_types::PrincipalId;
            use ic_management_canister_types::NodeMetrics;
            use ic_protobuf::registry::subnet::v1::SubnetRecord;
            use ic_registry_canister_client::CanisterRegistryClient;
            use ic_registry_keys::make_subnet_record_key;
            use prost::Message;

            ic_cdk::println!(
                "Running test implementation of node_metrics_history call to management canister...\
             This will assign 1 block proposed and 0 failures to all nodes assigned to the subnet \
             provided in args everyday!"
            );

            let registry_store = REGISTRY_STORE_TEST.with(|store| store.clone());
            let registry_querier = RegistryQuerier::new(registry_store.clone());

            let subnet_target = SubnetId::from(PrincipalId::from(args.subnet_id));
            let subnet_record_key = make_subnet_record_key(subnet_target);

            let mut node_metrics_history = vec![];

            let start_date =
                DateTime::from_timestamp_nanos(args.start_at_timestamp_nanos as i64).date_naive();
            let end_date =
                DateTime::from_timestamp_nanos(current_time().as_nanos_since_unix_epoch() as i64)
                    .date_naive();

            for date in start_date.iter_days().take_while(|d| *d < end_date) {
                let target_timestamp_nanos = last_unix_timestamp_nanoseconds(&date);
                let mut date_result = NodeMetricsHistoryRecord {
                    timestamp_nanos: target_timestamp_nanos,
                    node_metrics: vec![],
                };

                let version = match registry_querier
                    .version_for_timestamp_nanoseconds(target_timestamp_nanos)
                {
                    Some(version) => version,
                    None => continue,
                };

                let subnet_record = match registry_store
                    .get_value(subnet_record_key.as_str(), version)
                    .expect("Failed to get SubnetRecord")
                    .map(|v| {
                        SubnetRecord::decode(v.as_slice()).expect("Failed to decode SubnetRecord")
                    }) {
                    Some(subnet_record) => subnet_record,
                    None => continue,
                };

                for node in subnet_record.membership {
                    let node_id = Principal::try_from(node).unwrap();

                    date_result.node_metrics.push(NodeMetrics {
                        node_id,
                        num_blocks_proposed_total: 1,
                        num_block_failures_total: 0,
                    });
                }

                node_metrics_history.push(date_result);
            }

            Ok(node_metrics_history)
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
