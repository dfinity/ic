use crate::api_conversion::into_rewards_calculation_results;
use crate::metrics::MetricsManager;
use crate::pb::v1::{RewardableNodesKey, RewardableNodesValue};
use crate::registry_querier::RegistryQuerier;
use crate::storage::{REWARDABLE_NODES_CACHE, VM};
use crate::{KeyRange, telemetry};
use ic_base_types::{PrincipalId, SubnetId};
use ic_interfaces_registry::ZERO_REGISTRY_VERSION;
use ic_node_rewards_canister_api::monthly_rewards::{
    GetNodeProvidersMonthlyXdrRewardsRequest, GetNodeProvidersMonthlyXdrRewardsResponse,
    NodeProvidersMonthlyXdrRewards,
};
use ic_node_rewards_canister_api::provider_rewards_calculation::{
    GetNodeProviderRewardsCalculationRequest, GetNodeProviderRewardsCalculationResponse,
};
use ic_node_rewards_canister_api::providers_rewards::{
    GetNodeProvidersRewardsRequest, GetNodeProvidersRewardsResponse, NodeProvidersRewards,
};
use ic_protobuf::registry::dc::v1::DataCenterRecord;
use ic_protobuf::registry::node::v1::NodeRewardType;
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_protobuf::registry::node_rewards::v2::NodeRewardsTable;
use ic_registry_canister_client::{CanisterRegistryClient, get_decoded_value};
use ic_registry_keys::{
    DATA_CENTER_KEY_PREFIX, NODE_OPERATOR_RECORD_KEY_PREFIX, NODE_REWARDS_TABLE_KEY,
};
use ic_registry_node_provider_rewards::{RewardsPerNodeProvider, calculate_rewards_v0};
use ic_types::{RegistryVersion, Time};
use itertools::Itertools;
use rewards_calculation::performance_based_algorithm::DataProvider;
use rewards_calculation::performance_based_algorithm::results::RewardsCalculatorResults;
use rewards_calculation::performance_based_algorithm::v1::RewardsCalculationV1;
use rewards_calculation::types::{DayUtc, NodeMetricsDailyRaw, RewardableNode};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::thread::LocalKey;

#[cfg(test)]
mod test;

#[cfg(target_arch = "wasm32")]
pub fn current_time() -> Time {
    let current_time = ic_cdk::api::time();
    Time::from_nanos_since_unix_epoch(current_time)
}

#[cfg(not(any(target_arch = "wasm32")))]
pub fn current_time() -> Time {
    ic_types::time::current_time()
}

/// This struct represents the API for the canister.  API methods should be implemented in
/// main.rs and defer the important work to the methods in this struct, essentially passing
/// through arguments and responses with almost no logic.
pub struct NodeRewardsCanister {
    registry_client: Arc<dyn CanisterRegistryClient>,
    metrics_manager: Arc<MetricsManager<VM>>,
    registry_querier: Arc<RegistryQuerier>,
    last_metrics_update: RegistryVersion,
}

/// Internal methods
impl NodeRewardsCanister {
    pub fn new(
        registry_client: Arc<dyn CanisterRegistryClient>,
        metrics_manager: Arc<MetricsManager<VM>>,
    ) -> Self {
        Self {
            registry_querier: Arc::new(RegistryQuerier::new(registry_client.clone())),
            last_metrics_update: registry_client.get_latest_version(),
            registry_client,
            metrics_manager,
        }
    }

    /// Gets Arc reference to RegistryClient
    pub fn get_registry_client(&self) -> Arc<dyn CanisterRegistryClient> {
        self.registry_client.clone()
    }

    /// Gets Arc reference to MetricsManager
    pub fn get_metrics_manager(&self) -> Arc<MetricsManager<VM>> {
        self.metrics_manager.clone()
    }

    /// Gets Arc reference to RegistryQuerier
    pub fn get_registry_querier(&self) -> Arc<RegistryQuerier> {
        self.registry_querier.clone()
    }

    fn registry_version_for_day(&self, day_utc: &DayUtc) -> Result<RegistryVersion, String> {
        self.registry_querier
            .version_for_timestamp(day_utc.unix_ts_at_day_end_nanoseconds())
            .map_err(|e| format!("Could not find registry version for day: {:?}", e))
    }

    // Test only methods
    pub fn get_registry_value(&self, key: String) -> Result<Option<Vec<u8>>, String> {
        self.registry_client
            .get_value(key.as_ref(), self.registry_client.get_latest_version())
            .map_err(|e| format!("Failed to get registry value: {:?}", e))
    }

    pub async fn schedule_registry_sync(
        canister: &'static LocalKey<RefCell<NodeRewardsCanister>>,
    ) -> Result<RegistryVersion, String> {
        let registry_client = canister.with(|canister| canister.borrow().get_registry_client());
        registry_client.sync_registry_stored().await
    }

    pub async fn schedule_metrics_sync(canister: &'static LocalKey<RefCell<NodeRewardsCanister>>) {
        let mut subnets_list: HashSet<SubnetId> = HashSet::default();
        let metrics_manager = canister.with_borrow(|canister| canister.get_metrics_manager());
        let post_sync_version = canister.with_borrow(|canister| {
            let pre_sync_version = canister.last_metrics_update;
            let post_sync_version = canister.registry_client.get_latest_version();

            let mut version = if pre_sync_version == ZERO_REGISTRY_VERSION {
                // If the pre-sync version is 0, we consider all subnets from the post-sync version
                post_sync_version
            } else {
                pre_sync_version
            };
            while version <= post_sync_version {
                subnets_list.extend(canister.registry_querier.subnets_list(version));

                // Increment the version to sync the next one
                version = version.increment();
            }
            post_sync_version
        });

        metrics_manager
            .update_subnets_metrics(subnets_list.into_iter().collect())
            .await;
        metrics_manager.retry_failed_subnets().await;
        canister.with_borrow_mut(|canister| {
            canister.last_metrics_update = post_sync_version;
        });
    }

    fn validate_reward_period(from_day: &DayUtc, to_day: &DayUtc) -> Result<(), String> {
        let today: DayUtc = current_time().as_nanos_since_unix_epoch().into();
        if from_day > to_day {
            return Err("from_day must be before to_day".to_string());
        }
        if to_day >= &today {
            return Err("to_day_timestamp_nanos must be earlier than today".to_string());
        }
        Ok(())
    }

    fn calculate_rewards(
        &self,
        request: GetNodeProvidersRewardsRequest,
        provider_filter: Option<PrincipalId>,
    ) -> Result<RewardsCalculatorResults, String> {
        let start_day = DayUtc::from(request.from_day_timestamp_nanos);
        let end_day = DayUtc::from(request.to_day_timestamp_nanos);
        Self::validate_reward_period(&start_day, &end_day)?;

        RewardsCalculationV1::calculate_rewards(&start_day, &end_day, provider_filter, self)
            .map_err(|e| format!("Could not calculate rewards: {e:?}"))
    }
}

// Rewardable nodes methods

const CACHE_BACKFILL_START_DAY: u64 = 1746057600; // 1st May 2025

pub enum BackfillRewardableNodesStatus {
    Completed,
    NotCompleted,
}

impl NodeRewardsCanister {
    pub fn backfill_rewardable_nodes(&self) -> BackfillRewardableNodesStatus {
        let today = DayUtc::from_secs(current_time().as_secs_since_unix_epoch());
        let start_backfill_day = DayUtc::from_secs(CACHE_BACKFILL_START_DAY);
        let end_backfill_day = today.previous_day();

        let all_days = start_backfill_day.days_until(&end_backfill_day).unwrap();
        ic_cdk::println!("Day to backfill: {:?}", all_days);
        let mut days_to_backfill: Vec<DayUtc> = start_backfill_day
            .days_until(&end_backfill_day)
            .expect("Start day always before today")
            .into_iter()
            .filter(|day| self.get_rewardable_nodes(day).is_err())
            .collect_vec();

        if let Some(day) = days_to_backfill.pop() {
            ic_cdk::println!("Backfilling rewardable nodes for day: {}", day);

            self.backfill_rewardable_nodes_single_day(&day)
                .unwrap_or_else(|e| {
                    ic_cdk::println!("Failed to backfill: {:?}", e);
                });
            if !days_to_backfill.is_empty() {
                return BackfillRewardableNodesStatus::NotCompleted;
            }
        }
        BackfillRewardableNodesStatus::Completed
    }

    fn backfill_rewardable_nodes_single_day(&self, day_utc: &DayUtc) -> Result<(), String> {
        let mut rewardable_nodes: BTreeMap<_, Vec<RewardableNode>> = BTreeMap::new();
        let registry_version = self.registry_version_for_day(day_utc)?;

        let nodes = self
            .registry_querier
            .nodes_in_version(registry_version)
            .map_err(|e| format!("Failed to get nodes in version: {:?}", e))?;

        for (node_id, node_record) in nodes {
            let node_operator_id: PrincipalId = node_record
                .node_operator_id
                .try_into()
                .expect("Failed to parse PrincipalId from node operator ID");

            let node_operator = self
                .registry_querier
                .node_operator_data(node_operator_id, registry_version)
                .map_err(|e| format!("Failed to get node operator data: {:?}", e))?
                .ok_or(format!(
                    "Node operator {} has been deleted from registry",
                    node_operator_id
                ))?;

            let Some(some_reward_type) = node_record.node_reward_type else {
                // If the node does not have a node_reward_type, we skip it.
                continue;
            };

            let node_reward_type =
                NodeRewardType::try_from(some_reward_type).expect("Invalid node_reward_type value");

            rewardable_nodes
                .entry(node_operator.node_provider_id)
                .or_default()
                .push(RewardableNode {
                    node_id,
                    node_reward_type,
                    dc_id: node_operator.dc_id.clone(),
                    region: node_operator.region.clone(),
                });
        }
        self.cache_rewardable_nodes(rewardable_nodes, registry_version);
        Ok(())
    }

    fn cache_rewardable_nodes(
        &self,
        rewardable_nodes: BTreeMap<PrincipalId, Vec<RewardableNode>>,
        registry_version: RegistryVersion,
    ) {
        for (provider_id, rewardable_nodes_daily) in rewardable_nodes {
            REWARDABLE_NODES_CACHE.with_borrow_mut(|rewardable_nodes_cache| {
                let key = RewardableNodesKey {
                    registry_version: registry_version.get(),
                    provider_id: Some(provider_id),
                };
                let value = RewardableNodesValue {
                    rewardable_nodes: rewardable_nodes_daily
                        .into_iter()
                        .map(|node| node.into())
                        .collect(),
                };
                rewardable_nodes_cache.insert(key, value);
            });
        }
    }

    fn get_cached_rewardable_nodes(
        &self,
        version: RegistryVersion,
    ) -> Result<BTreeMap<PrincipalId, Vec<RewardableNode>>, String> {
        let key_start = RewardableNodesKey {
            registry_version: version.get(),
            ..RewardableNodesKey::min_key()
        };
        let key_end = RewardableNodesKey {
            registry_version: version.get(),
            ..RewardableNodesKey::max_key()
        };

        let result: BTreeMap<PrincipalId, Vec<RewardableNode>> = REWARDABLE_NODES_CACHE
            .with_borrow(|rewardable_nodes_cache| {
                rewardable_nodes_cache
                    .range(key_start..=key_end)
                    .map(|(key, rewardable_nodes)| {
                        let nodes = rewardable_nodes
                            .rewardable_nodes
                            .into_iter()
                            .map(|value| value.into())
                            .collect::<Vec<_>>();
                        (key.provider_id.unwrap(), nodes)
                    })
                    .collect()
            });

        if result.is_empty() {
            Err(format!(
                "Rewardable nodes not found in cache for registry version: {}",
                version
            ))
        } else {
            Ok(result)
        }
    }
}

impl DataProvider for &NodeRewardsCanister {
    fn get_rewards_table(&self, day: &DayUtc) -> Result<NodeRewardsTable, String> {
        let version = self.registry_version_for_day(day)?;
        self.registry_querier
            .get_rewards_table(version)
            .map_err(|e| format!("Could not find rewards table day {}: {e}", day))
    }

    fn get_daily_metrics_by_subnet(
        &self,
        day: &DayUtc,
    ) -> Result<BTreeMap<SubnetId, Vec<NodeMetricsDailyRaw>>, String> {
        self.metrics_manager.get_metrics_by_subnet(day)
    }

    fn get_rewardable_nodes(
        &self,
        day: &DayUtc,
    ) -> Result<BTreeMap<PrincipalId, Vec<RewardableNode>>, String> {
        let version = self.registry_version_for_day(day)?;
        self.get_cached_rewardable_nodes(version)
            .map_err(|e| format!("Could not find rewardable nodes day {}: {e}", day))
    }
}

// Exposed API Methods
impl NodeRewardsCanister {
    pub async fn get_node_providers_monthly_xdr_rewards(
        canister: &'static LocalKey<RefCell<NodeRewardsCanister>>,
        request: GetNodeProvidersMonthlyXdrRewardsRequest,
    ) -> GetNodeProvidersMonthlyXdrRewardsResponse {
        let registry_client = canister.with(|canister| canister.borrow().get_registry_client());

        // Main impl below
        return match inner_get_node_providers_monthly_xdr_rewards(registry_client, request).await {
            Ok((rewards, latest_version)) => GetNodeProvidersMonthlyXdrRewardsResponse {
                rewards: Some(NodeProvidersMonthlyXdrRewards {
                    rewards: rewards
                        .rewards_per_node_provider
                        .into_iter()
                        .map(|(k, v)| (k.0, v))
                        .collect(),
                    registry_version: Some(latest_version.get()),
                }),
                error: None,
            },
            Err(e) => GetNodeProvidersMonthlyXdrRewardsResponse {
                rewards: None,
                error: Some(e),
            },
        };

        async fn inner_get_node_providers_monthly_xdr_rewards(
            registry_client: Arc<dyn CanisterRegistryClient>,
            request: GetNodeProvidersMonthlyXdrRewardsRequest,
        ) -> Result<(RewardsPerNodeProvider, RegistryVersion), String> {
            registry_client.sync_registry_stored().await.map_err(|e| {
                format!(
                    "Could not sync registry store to latest version, \
                    please try again later: {:?}",
                    e
                )
            })?;

            let version = request
                .registry_version
                .map(RegistryVersion::new)
                .unwrap_or_else(|| registry_client.get_latest_version());

            let rewards_table = get_decoded_value::<NodeRewardsTable>(
                &*registry_client,
                NODE_REWARDS_TABLE_KEY,
                version,
            )
            .map_err(|e| format!("Could not find NodeRewardsTable: {e:?}"))?
            .ok_or_else(|| "Node Rewards Table was not found in the Registry".to_string())?;

            let node_operators = decoded_key_value_pairs_for_prefix::<NodeOperatorRecord>(
                &*registry_client,
                NODE_OPERATOR_RECORD_KEY_PREFIX,
                version,
            )?;

            let data_centers = decoded_key_value_pairs_for_prefix::<DataCenterRecord>(
                &*registry_client,
                DATA_CENTER_KEY_PREFIX,
                version,
            )?
            .into_iter()
            .collect();

            calculate_rewards_v0(&rewards_table, &node_operators, &data_centers)
                .map(|rewards| (rewards, version))
        }
    }

    pub fn get_node_providers_rewards(
        canister: &'static LocalKey<RefCell<NodeRewardsCanister>>,
        request: GetNodeProvidersRewardsRequest,
    ) -> GetNodeProvidersRewardsResponse {
        let result = canister.with_borrow(|canister| canister.calculate_rewards(request, None))?;

        let rewards_xdr_permyriad = result
            .total_rewards_xdr_permyriad
            .into_iter()
            .map(|(k, v)| (k.0, v))
            .collect();

        Ok(NodeProvidersRewards {
            rewards_xdr_permyriad,
        })
    }

    pub fn get_node_provider_rewards_calculation(
        canister: &'static LocalKey<RefCell<NodeRewardsCanister>>,
        request: GetNodeProviderRewardsCalculationRequest,
    ) -> GetNodeProviderRewardsCalculationResponse {
        let provider_id = PrincipalId::from(request.provider_id);
        let request_inner = GetNodeProvidersRewardsRequest {
            from_day_timestamp_nanos: request.from_day_timestamp_nanos,
            to_day_timestamp_nanos: request.to_day_timestamp_nanos,
        };
        let result = canister
            .with_borrow(|canister| canister.calculate_rewards(request_inner, Some(provider_id)))?;
        into_rewards_calculation_results(result, provider_id)
    }
}

/// Get the key value pairs for a given prefix from the registry.
///
/// NOTE: This function strips the prefix, so node_operator_xyz becomes xyz.
fn decoded_key_value_pairs_for_prefix<T: prost::Message + Default>(
    registry_client: &dyn CanisterRegistryClient,
    key_prefix: &str,
    version: RegistryVersion,
) -> Result<Vec<(String, T)>, String> {
    registry_client
        .get_key_family_with_values(key_prefix, version)
        .map_err(|e| format!("Could not get values for prefix {key_prefix}: {e:?}"))?
        .into_iter()
        .map(|(k, v)| {
            T::decode(v.as_slice())
                .map_err(|e| format!("Could not decode prost Message for key {k}: {e:?}"))
                .map(|record| (k.strip_prefix(key_prefix).unwrap().to_string(), record))
        })
        .collect::<Result<Vec<_>, String>>()
}
