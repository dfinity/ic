use crate::KeyRange;
use crate::chrono_utils::{first_unix_timestamp_nanoseconds, last_unix_timestamp_nanoseconds};
use crate::pb::v1::{SubnetIdKey, SubnetMetricsKey, SubnetMetricsValue};
use async_trait::async_trait;
use chrono::{DateTime, NaiveDate};
use ic_base_types::{NodeId, SubnetId};
use ic_cdk::call::CallResult;
use ic_cdk_management_canister::{NodeMetricsHistoryArgs, NodeMetricsHistoryRecord};
use ic_stable_structures::StableBTreeMap;
use itertools::Itertools;
use rewards_calculation::types::{NodeMetricsDailyRaw, UnixTsNanos};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};

pub type RetryCount = u64;

/// How many failing subnets to name in the aggregated error log line. Failures
/// are correlated (an unreachable subnet fails on every retry, and exhausted
/// call capacity fails all of them at once), so naming a handful is enough to
/// diagnose without emitting one line per subnet per retry forever.
const MAX_LOGGED_FAILURES: usize = 5;

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
        ic_cdk_management_canister::node_metrics_history(args).await
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
    /// Per subnet, the day it counts as covering for as long as it has never reported any metrics
    /// at all. See [`MetricsManager::record_baseline_for_subnets_without_metrics`].
    pub(crate) baseline_day_per_subnet: RefCell<StableBTreeMap<SubnetIdKey, UnixTsNanos, Memory>>,
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

    /// Where to resume each subnet's fetch from: its last stored timestamp, or the epoch for a
    /// subnet nothing has been stored for yet. Collapsing "no data" to 0 is what belongs here, and
    /// is exactly what must NOT happen in [`Self::last_day_fully_synced`].
    fn last_timestamp_per_subnet(&self, subnets: &[SubnetId]) -> BTreeMap<SubnetId, UnixTsNanos> {
        subnets
            .iter()
            .map(|subnet| {
                let last_timestamp = self
                    .last_timestamp_per_subnet
                    .borrow()
                    .get(&(*subnet).into())
                    .unwrap_or_default();

                (*subnet, last_timestamp)
            })
            .collect()
    }

    /// The day `subnet`'s stored metrics cover: its own last stored timestamp, or — for a subnet
    /// that has never reported any — the baseline it was credited with when first seen.
    ///
    /// Its own timestamp always wins. A subnet that has reported before says exactly how far it
    /// covers, including when it reports an older day than its baseline, which happens when a
    /// long-stalled subnet finally closes a snapshot keyed to the day it stalled on.
    fn day_covered_by(&self, subnet: SubnetId) -> Option<NaiveDate> {
        let key = SubnetIdKey::from(subnet);
        let reported = self.last_timestamp_per_subnet.borrow().get(&key);
        reported
            .or_else(|| self.baseline_day_per_subnet.borrow().get(&key))
            .map(|ts| DateTime::from_timestamp_nanos(ts as i64).date_naive())
    }

    /// The last day the stored metrics cover for *every* subnet in `subnets`: the earliest of the
    /// per-subnet covered days. `None` if not one of them covers any day.
    ///
    /// This is the minimum, not the maximum, because it is what `last_day_synced` — and through it
    /// the reward period validation in the canister — treats as "metrics are complete up to here".
    /// A `node_metrics_history` call can succeed and still return nothing past an older day: the
    /// management canister omits the running (current-day) snapshot, so a subnet that has produced
    /// no block since day D-2 answers with records only through D-3 while healthy subnets answer
    /// through D-1. Reporting the maximum there would declare D-1 synced and let rewards be
    /// computed for two days on which that subnet contributed no metrics at all — its nodes then
    /// read as unassigned and are paid on an extrapolated (or, for a provider with no other
    /// assigned node, a zero) failure rate. Not advancing on partial data is the same stance
    /// [`Self::update_subnets_metrics`] already takes when a call outright fails; the maximum made
    /// that stance depend on which code path the missing data arrived by.
    fn last_day_fully_synced(&self, subnets: &[SubnetId]) -> Option<NaiveDate> {
        subnets
            .iter()
            .filter_map(|subnet| self.day_covered_by(*subnet))
            .min()
    }

    /// Credits every subnet that has never reported any metrics with covering the furthest day the
    /// subnets that have reported have reached, and remembers it.
    ///
    /// Without this, a subnet with no metrics at all had to be left out of the minimum entirely:
    /// counting it as covering nothing would pin the minimum to 1970-01-01 and block every reward
    /// calculation network-wide. But leaving it out is only right for as long as there is genuinely
    /// nothing it owes us, and that is not a state it necessarily grows out of. A subnet that
    /// stalls before closing its first daily snapshot answers with an empty history indefinitely:
    /// the management canister keeps that snapshot as running stats and only closes it once a later
    /// block arrives, and `node_metrics_history` never returns running stats. Such a subnet would
    /// be skipped forever while the healthy ones kept advancing `last_day_synced` — exactly the gap
    /// the minimum is here to close, reopened for its nodes.
    ///
    /// Pinning the baseline at first sight closes that. The days before a subnet showed up are not
    /// its to account for, so it is credited with all of them; every day after is, so the moment
    /// the rest move past its baseline the minimum stops advancing and stays put until the subnet
    /// reports something. The baseline comes from what the other subnets have reached rather than
    /// from the clock, because that is the same quantity `last_day_synced` is measured in: a
    /// wall-clock "today" would have to guess how far behind the metrics normally run.
    ///
    /// Nothing is recorded while no subnet has reported at all — there is no day to credit anyone
    /// with, and `update_subnets_metrics` fails on that below. Nor is an existing baseline ever
    /// moved: it records where a subnet came in, which does not change.
    fn record_baseline_for_subnets_without_metrics(&self, subnets: &[SubnetId]) {
        let furthest_reported = subnets
            .iter()
            .filter_map(|subnet| {
                self.last_timestamp_per_subnet
                    .borrow()
                    .get(&SubnetIdKey::from(*subnet))
            })
            .max();
        let Some(furthest_reported) = furthest_reported else {
            return;
        };

        for subnet in subnets {
            let key = SubnetIdKey::from(*subnet);
            let unseen = self.last_timestamp_per_subnet.borrow().get(&key).is_none()
                && self.baseline_day_per_subnet.borrow().get(&key).is_none();
            if !unseen {
                continue;
            }

            self.baseline_day_per_subnet
                .borrow_mut()
                .insert(key, furthest_reported);
            let baseline = DateTime::from_timestamp_nanos(furthest_reported as i64).date_naive();
            ic_cdk::println!(
                "Subnet {} has no metrics at all; counting it as covering up to {}. Metrics will \
                 not be considered synced past that day until it reports.",
                subnet,
                baseline,
            );
        }
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
        let mut failures: Vec<(SubnetId, String)> = Vec::new();
        let last_timestamp_per_subnet = self.last_timestamp_per_subnet(&subnets);
        let subnets_metrics = self.fetch_subnets_metrics(&last_timestamp_per_subnet).await;
        for (subnet_id, call_result) in subnets_metrics {
            match call_result {
                Ok(subnet_update) => {
                    if let Some(last_timestamp) =
                        subnet_update.last().map(|metrics| metrics.timestamp_nanos)
                    {
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
                    } else {
                        ic_cdk::println!("No updates for subnet {}", subnet_id);
                    }
                }
                Err(e) => {
                    failures.push((subnet_id, e.to_string()));
                }
            }
        }

        // One line per sync rather than one per failing subnet: a subnet that
        // is unreachable fails on every retry, and when the canister runs out
        // of call capacity every subnet fails at once, so per-subnet logging
        // turns a single stuck subnet into millions of NNS log lines an hour.
        if !failures.is_empty() {
            let sample = failures
                .iter()
                .take(MAX_LOGGED_FAILURES)
                .map(|(subnet_id, e)| format!("{subnet_id}: {e}"))
                .join(", ");
            ic_cdk::println!(
                "Error fetching metrics for {} of {} subnets (showing up to {}): {}",
                failures.len(),
                last_timestamp_per_subnet.len(),
                MAX_LOGGED_FAILURES,
                sample,
            );

            return Err("Failed to update metrics".to_string());
        }

        // Before taking the minimum, so that a subnet seen here for the first time is part of it.
        self.record_baseline_for_subnets_without_metrics(&subnets);

        let last_day_update = self.last_day_fully_synced(&subnets).ok_or_else(|| {
            "No subnet has any stored metrics: refusing to record a synced day".to_string()
        })?;

        // A subnet whose data stops short now holds the synced day back for everyone, so say which
        // one and by how much. Without this the only symptom is reward calculation quietly
        // refusing every day past `last_day_update`, with nothing naming the cause.
        self.log_subnets_lagging_behind(&subnets, last_day_update);

        Ok(last_day_update)
    }

    /// Logs which subnets are holding `last_day_update` back, when some subnets have got further
    /// than others. The subnets at the minimum are the ones that decide it, so those are the ones
    /// named — knowing that the rest are further along is no help in fixing it.
    ///
    /// Bounded the same way the failure log above is, and for the same reason: whatever keeps a
    /// subnet behind tends to keep it behind for many syncs in a row.
    fn log_subnets_lagging_behind(&self, subnets: &[SubnetId], last_day_update: NaiveDate) {
        let days: Vec<(SubnetId, NaiveDate)> = subnets
            .iter()
            .filter_map(|subnet| self.day_covered_by(*subnet).map(|day| (*subnet, day)))
            .collect();

        // Every subnet with metrics stopped on the same day, so none of them is behind another and
        // there is nothing to report. This is the healthy case.
        let Some(furthest) = days.iter().map(|(_, day)| *day).max() else {
            return;
        };
        if furthest == last_day_update {
            return;
        }

        let holding_back: Vec<&(SubnetId, NaiveDate)> = days
            .iter()
            .filter(|(_, day)| *day == last_day_update)
            .collect();
        let sample = holding_back
            .iter()
            .take(MAX_LOGGED_FAILURES)
            .map(|(subnet_id, _)| subnet_id.to_string())
            .join(", ");
        ic_cdk::println!(
            "Metrics are synced up to {} rather than {}: {} of {} subnets have nothing stored past \
             {} (showing up to {}): {}. Rewards cannot be computed for any later day until they \
             catch up.",
            last_day_update,
            furthest,
            holding_back.len(),
            subnets.len(),
            last_day_update,
            MAX_LOGGED_FAILURES,
            sample,
        );
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
    use ic_cdk_management_canister::{NodeMetricsHistoryArgs, NodeMetricsHistoryRecord};
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
            use ic_cdk_management_canister::NodeMetrics;
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
