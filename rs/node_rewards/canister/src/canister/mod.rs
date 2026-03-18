use crate::chrono_utils::last_unix_timestamp_nanoseconds;
use crate::metrics::MetricsManager;
use crate::registry_querier::RegistryQuerier;
use crate::storage::{NaiveDateStorable, VM};
use chrono::{DateTime, NaiveDate};
use ic_base_types::{PrincipalId, SubnetId};
#[cfg(target_arch = "wasm32")]
use ic_node_rewards_canister_api::DateUtc;
use ic_node_rewards_canister_api::RewardsCalculationAlgorithmVersion;
use ic_node_rewards_canister_api::monthly_rewards::{
    GetNodeProvidersMonthlyXdrRewardsRequest, GetNodeProvidersMonthlyXdrRewardsResponse,
    NodeProvidersMonthlyXdrRewards,
};
use ic_node_rewards_canister_api::provider_rewards_calculation::{
    DailyResults, GetNodeProvidersRewardsCalculationRequest,
    GetNodeProvidersRewardsCalculationResponse,
};
use ic_node_rewards_canister_api::providers_rewards::{
    GetNodeProvidersRewardsRequest, GetNodeProvidersRewardsResponse, NodeProvidersRewards,
};
use ic_node_rewards_canister_api::rewardable_nodes::{
    GetRewardableNodesRequest, GetRewardableNodesResponse, RewardableNodeApi, RewardableNodesResult,
};
use ic_protobuf::registry::dc::v1::DataCenterRecord;
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_protobuf::registry::node_rewards::v2::NodeRewardsTable;
use ic_registry_canister_client::{CanisterRegistryClient, get_decoded_value};
use ic_registry_keys::{
    DATA_CENTER_KEY_PREFIX, NODE_OPERATOR_RECORD_KEY_PREFIX, NODE_REWARDS_TABLE_KEY,
};
use ic_registry_node_provider_rewards::{RewardsPerNodeProvider, calculate_rewards_v0};
use ic_stable_structures::StableCell;
use ic_types::{RegistryVersion, Time};
use rewards_calculation::AlgorithmVersion;
use rewards_calculation::performance_based_algorithm::results::RewardsCalculatorResults;
use rewards_calculation::performance_based_algorithm::{
    v1::RewardsCalculationV1, v2::RewardsCalculationV2,
};
use rewards_calculation::types::{NodeMetricsDailyRaw, RewardableNode};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
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
    metrics_manager: Rc<MetricsManager<VM>>,
    last_day_synced: &'static LocalKey<RefCell<StableCell<Option<NaiveDateStorable>, VM>>>,
}

/// Internal methods
impl NodeRewardsCanister {
    pub fn new(
        registry_client: Arc<dyn CanisterRegistryClient>,
        metrics_manager: Rc<MetricsManager<VM>>,
        last_day_synced: &'static LocalKey<RefCell<StableCell<Option<NaiveDateStorable>, VM>>>,
    ) -> Self {
        Self {
            registry_client,
            metrics_manager,
            last_day_synced,
        }
    }

    /// Gets Arc reference to RegistryClient
    pub fn get_registry_client(&self) -> Arc<dyn CanisterRegistryClient> {
        self.registry_client.clone()
    }

    /// Gets Arc reference to MetricsManager
    pub fn get_metrics_manager(&self) -> Rc<MetricsManager<VM>> {
        self.metrics_manager.clone()
    }

    // Test only methods
    pub fn get_registry_value(&self, key: String) -> Result<Option<Vec<u8>>, String> {
        self.registry_client
            .get_value(key.as_ref(), self.registry_client.get_latest_version())
            .map_err(|e| format!("Failed to get registry value: {:?}", e))
    }

    pub fn get_last_day_synced(&self) -> Option<NaiveDate> {
        self.last_day_synced
            .with_borrow(|last_day_synced| last_day_synced.get().clone().map(|d| d.0))
    }

    pub fn set_last_day_synced(&self, last_day_synced: NaiveDate) {
        self.last_day_synced.with_borrow_mut(|cell| {
            cell.set(Some(NaiveDateStorable(last_day_synced)))
                .expect("Could not set last day synced");
        });
    }

    pub async fn schedule_registry_sync(
        canister: &'static LocalKey<RefCell<NodeRewardsCanister>>,
    ) -> Result<RegistryVersion, String> {
        let registry_client = canister.with(|canister| canister.borrow().get_registry_client());

        registry_client.sync_registry_stored().await
    }

    pub async fn schedule_metrics_sync(
        canister: &'static LocalKey<RefCell<NodeRewardsCanister>>,
    ) -> Result<(), String> {
        let (registry_client, metrics_manager) = canister.with(|canister| {
            (
                canister.borrow().get_registry_client(),
                canister.borrow().get_metrics_manager(),
            )
        });
        let registry_querier = RegistryQuerier::new(registry_client.clone());
        let version = registry_client.get_latest_version();
        let subnets_list = registry_querier.subnets_list(version)?;
        let last_day_synced: NaiveDate =
            metrics_manager.update_subnets_metrics(subnets_list).await?;
        canister.with_borrow(|canister| {
            canister.set_last_day_synced(last_day_synced);
        });

        Ok(())
    }

    fn validate_reward_period(
        &self,
        from_date: NaiveDate,
        to_date: NaiveDate,
    ) -> Result<(), String> {
        let last_day_synced = self
            .get_last_day_synced()
            .ok_or("Metrics and registry are not synced up")?;

        if last_day_synced < to_date {
            return Err("Metrics and registry are not synced up to to_date".to_string());
        }

        if from_date > to_date {
            return Err("from_date must be before to_date".to_string());
        }

        let today =
            DateTime::from_timestamp_nanos(current_time().as_nanos_since_unix_epoch() as i64)
                .date_naive();

        if to_date >= today {
            return Err("to_date must be earlier than today".to_string());
        }

        Ok(())
    }
}

/// Input provider that doesn't hold a RefCell borrow, so it can be used across
/// await points. Reads metrics and rewards table from owned references, and
/// fetches rewardable nodes via a self-call to split registry reads across
/// multiple instruction budgets.
pub struct CanisterInputProvider {
    registry_client: Arc<dyn CanisterRegistryClient>,
    metrics_manager: Rc<MetricsManager<VM>>,
}

impl rewards_calculation::performance_based_algorithm::PerformanceBasedAlgorithmInputProvider
    for CanisterInputProvider
{
    fn get_rewards_table(&self, date: &NaiveDate) -> Result<NodeRewardsTable, String> {
        let registry_querier = RegistryQuerier::new(self.registry_client.clone());
        let version = registry_querier
            .version_for_timestamp_nanoseconds(last_unix_timestamp_nanoseconds(date))
            .ok_or_else(|| "Could not find registry version for timestamp".to_string())?;
        Ok(registry_querier.get_rewards_table(version))
    }

    fn get_daily_metrics_by_subnet(
        &self,
        date: &NaiveDate,
    ) -> Result<BTreeMap<SubnetId, Vec<NodeMetricsDailyRaw>>, String> {
        let metrics = self.metrics_manager.metrics_by_subnet(date);
        if metrics.is_empty() {
            return Err(format!(
                "No metrics found for day {}",
                date.format("%Y-%m-%d")
            ));
        }
        Ok(metrics)
    }

    #[cfg(target_arch = "wasm32")]
    async fn get_rewardable_nodes(
        &self,
        date: &NaiveDate,
    ) -> Result<BTreeMap<PrincipalId, Vec<RewardableNode>>, String> {
        let canister_id = ic_cdk::api::canister_self();
        let req = GetRewardableNodesRequest {
            day: DateUtc::from(*date),
        };

        let response: GetRewardableNodesResponse =
            ic_cdk::call::Call::unbounded_wait(canister_id, "get_rewardable_nodes")
                .with_arg(&req)
                .await
                .map_err(|e| {
                    format!(
                        "Self-call to get_rewardable_nodes failed for {}: {:?}",
                        date.format("%Y-%m-%d"),
                        e
                    )
                })?
                .candid()
                .map_err(|e| {
                    format!(
                        "Failed to decode get_rewardable_nodes response for {}: {:?}",
                        date.format("%Y-%m-%d"),
                        e
                    )
                })?;

        let result = response?;

        result
            .rewardable_nodes
            .into_iter()
            .map(|(principal, api_nodes)| {
                let provider_id = PrincipalId::from(principal);
                let nodes: Result<Vec<RewardableNode>, String> = api_nodes
                    .into_iter()
                    .map(RewardableNode::try_from)
                    .collect();
                nodes.map(|n| (provider_id, n))
            })
            .collect()
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn get_rewardable_nodes(
        &self,
        date: &NaiveDate,
    ) -> Result<BTreeMap<PrincipalId, Vec<RewardableNode>>, String> {
        let registry_querier = RegistryQuerier::new(self.registry_client.clone());
        registry_querier
            .get_rewardable_nodes_per_provider(date, None)
            .map_err(|e| format!("Could not get rewardable nodes: {e:?}"))
    }
}

async fn calculate_rewards(
    input_provider: CanisterInputProvider,
    request: GetNodeProvidersRewardsRequest,
    start_day: NaiveDate,
    end_day: NaiveDate,
) -> Result<RewardsCalculatorResults, String> {
    let rewards_calculator_version = request.algorithm_version.unwrap_or_default();

    match rewards_calculator_version.version {
        RewardsCalculationV1::VERSION => {
            RewardsCalculationV1::calculate_rewards(start_day, end_day, input_provider)
                .await
                .map_err(|e| format!("Could not calculate rewards: {e:?}"))
        }
        RewardsCalculationV2::VERSION => {
            RewardsCalculationV2::calculate_rewards(start_day, end_day, input_provider)
                .await
                .map_err(|e| format!("Could not calculate rewards: {e:?}"))
        }
        _ => Err(format!(
            "Rewards Calculation Version: {rewards_calculator_version:?} is not supported"
        )),
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

    pub async fn get_node_providers_rewards(
        canister: &'static LocalKey<RefCell<NodeRewardsCanister>>,
        request: GetNodeProvidersRewardsRequest,
    ) -> GetNodeProvidersRewardsResponse {
        let (input_provider, start_day, end_day) = canister.with_borrow(|c| {
            let start_day = NaiveDate::try_from(request.from_day)?;
            let end_day = NaiveDate::try_from(request.to_day)?;
            c.validate_reward_period(start_day, end_day)?;
            Ok::<_, String>((
                CanisterInputProvider {
                    registry_client: c.registry_client.clone(),
                    metrics_manager: c.metrics_manager.clone(),
                },
                start_day,
                end_day,
            ))
        })?;

        let result = calculate_rewards(input_provider, request, start_day, end_day).await?;

        let rewards_xdr_permyriad = result
            .total_rewards_xdr_permyriad
            .into_iter()
            .map(|(k, v)| (k.0, v))
            .collect();

        let algorithm_version = RewardsCalculationAlgorithmVersion {
            version: result.algorithm_version,
        };

        Ok(NodeProvidersRewards {
            algorithm_version,
            rewards_xdr_permyriad,
        })
    }

    pub async fn get_node_providers_rewards_calculation(
        canister: &'static LocalKey<RefCell<NodeRewardsCanister>>,
        request: GetNodeProvidersRewardsCalculationRequest,
    ) -> GetNodeProvidersRewardsCalculationResponse {
        let request_inner = GetNodeProvidersRewardsRequest {
            from_day: request.day,
            to_day: request.day,
            algorithm_version: request.algorithm_version,
        };

        let (input_provider, day) = canister.with_borrow(|c| {
            let day = NaiveDate::try_from(request.day)?;
            c.validate_reward_period(day, day)?;
            Ok::<_, String>((
                CanisterInputProvider {
                    registry_client: c.registry_client.clone(),
                    metrics_manager: c.metrics_manager.clone(),
                },
                day,
            ))
        })?;

        let mut result = calculate_rewards(input_provider, request_inner, day, day).await?;

        let daily_results = result
            .daily_results
            .remove(&day)
            .ok_or("Could not find daily results for the requested day")?;
        DailyResults::try_from(daily_results)
    }

    pub fn get_rewardable_nodes(
        canister: &'static LocalKey<RefCell<NodeRewardsCanister>>,
        request: GetRewardableNodesRequest,
    ) -> GetRewardableNodesResponse {
        let day = NaiveDate::try_from(request.day)?;
        let rewardable_nodes = canister.with_borrow(|canister| {
            let registry_querier = RegistryQuerier::new(canister.registry_client.clone());
            registry_querier
                .get_rewardable_nodes_per_provider(&day, None)
                .map_err(|e| format!("Could not get rewardable nodes: {e:?}"))
        })?;

        let rewardable_nodes = rewardable_nodes
            .into_iter()
            .map(|(provider_id, nodes)| {
                let api_nodes = nodes.into_iter().map(RewardableNodeApi::from).collect();
                (provider_id.0, api_nodes)
            })
            .collect();

        Ok(RewardableNodesResult { rewardable_nodes })
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
