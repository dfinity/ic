use crate::api_conversion::into_rewards_calculation_results;
use crate::chrono_utils::last_unix_timestamp_nanoseconds;
use crate::metrics::MetricsManager;
use crate::registry_querier::RegistryQuerier;
use crate::storage::VM;
use chrono::{DateTime, NaiveDate};
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
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_protobuf::registry::node_rewards::v2::NodeRewardsTable;
use ic_registry_canister_client::{CanisterRegistryClient, get_decoded_value};
use ic_registry_keys::{
    DATA_CENTER_KEY_PREFIX, NODE_OPERATOR_RECORD_KEY_PREFIX, NODE_REWARDS_TABLE_KEY,
};
use ic_registry_node_provider_rewards::{RewardsPerNodeProvider, calculate_rewards_v0};
use ic_types::{RegistryVersion, Time};
use rewards_calculation::performance_based_algorithm::results::RewardsCalculatorResults;
use rewards_calculation::performance_based_algorithm::v1::RewardsCalculationV1;
use rewards_calculation::types::{NodeMetricsDailyRaw, RewardableNode};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet};
use std::rc::Rc;
use std::sync::Arc;
use std::thread::LocalKey;

#[cfg(test)]
mod test;

#[cfg(target_arch = "wasm32")]
fn current_time() -> Time {
    let current_time = ic_cdk::api::time();
    Time::from_nanos_since_unix_epoch(current_time)
}

#[cfg(not(any(target_arch = "wasm32")))]
fn current_time() -> Time {
    ic_types::time::current_time()
}

/// This struct represents the API for the canister.  API methods should be implemented in
/// main.rs and defer the important work to the methods in this struct, essentially passing
/// through arguments and responses with almost no logic.
pub struct NodeRewardsCanister {
    registry_client: Arc<dyn CanisterRegistryClient>,
    metrics_manager: Rc<MetricsManager<VM>>,
    last_metrics_update: RegistryVersion,
}

/// Internal methods
impl NodeRewardsCanister {
    pub fn new(
        registry_client: Arc<dyn CanisterRegistryClient>,
        metrics_manager: Rc<MetricsManager<VM>>,
    ) -> Self {
        Self {
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
    pub fn get_metrics_manager(&self) -> Rc<MetricsManager<VM>> {
        self.metrics_manager.clone()
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
        let (registry_client, metrics_manager, pre_sync_version) = canister.with(|canister| {
            (
                canister.borrow().get_registry_client(),
                canister.borrow().get_metrics_manager(),
                canister.borrow().last_metrics_update,
            )
        });
        let post_sync_version = registry_client.get_latest_version();
        let registry_querier = RegistryQuerier::new(registry_client.clone());

        let mut subnets_list: HashSet<SubnetId> = HashSet::default();
        let mut version = if pre_sync_version == ZERO_REGISTRY_VERSION {
            // If the pre-sync version is 0, we consider all subnets from the post-sync version
            post_sync_version
        } else {
            pre_sync_version
        };
        while version <= post_sync_version {
            subnets_list.extend(registry_querier.subnets_list(version));

            // Increment the version to sync the next one
            version = version.increment();
        }

        metrics_manager
            .update_subnets_metrics(subnets_list.into_iter().collect())
            .await;
        metrics_manager.retry_failed_subnets().await;
        canister.with_borrow_mut(|canister| {
            canister.last_metrics_update = post_sync_version;
        });
    }

    fn validate_reward_period(from_date: &NaiveDate, to_date: &NaiveDate) -> Result<(), String> {
        let today =
            DateTime::from_timestamp_nanos(current_time().as_nanos_since_unix_epoch() as i64)
                .date_naive();
        if from_date > to_date {
            return Err("from_date must be before to_date".to_string());
        }
        if to_date >= &today {
            return Err("to_date must be earlier than today".to_string());
        }
        Ok(())
    }

    fn calculate_rewards(
        &self,
        request: GetNodeProvidersRewardsRequest,
        provider_filter: Option<PrincipalId>,
    ) -> Result<RewardsCalculatorResults, String> {
        let start_day = NaiveDate::try_from(request.from_day)?;
        let end_day = NaiveDate::try_from(request.to_day)?;
        Self::validate_reward_period(&start_day, &end_day)?;

        RewardsCalculationV1::calculate_rewards(&start_day, &end_day, provider_filter, self)
            .map_err(|e| format!("Could not calculate rewards: {e:?}"))
    }
}

impl rewards_calculation::performance_based_algorithm::DataProvider for &NodeRewardsCanister {
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

    fn get_rewardable_nodes(
        &self,
        date: &NaiveDate,
    ) -> Result<BTreeMap<PrincipalId, Vec<RewardableNode>>, String> {
        let registry_client = self.get_registry_client();
        let registry_querier = RegistryQuerier::new(registry_client.clone());
        registry_querier
            .get_rewardable_nodes_per_provider(date, None)
            .map_err(|e| format!("Could not get rewardable nodes: {e:?}"))
    }

    fn get_provider_rewardable_nodes(
        &self,
        date: &NaiveDate,
        provider_id: &PrincipalId,
    ) -> Result<Vec<RewardableNode>, String> {
        let mut all_rewardable_nodes = self.get_rewardable_nodes(date)?;
        let rewardable_nodes = all_rewardable_nodes.remove(provider_id).ok_or_else(|| {
            format!(
                "No rewardable nodes found for provider {} for day {}",
                provider_id,
                date.format("%Y-%m-%d")
            )
        })?;
        Ok(rewardable_nodes)
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
        NodeRewardsCanister::schedule_registry_sync(canister)
            .await
            .map_err(|e| {
                format!(
                    "Could not sync registry store to latest version, \
                    please try again later: {:?}",
                    e
                )
            })?;
        NodeRewardsCanister::schedule_metrics_sync(canister).await;
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
            from_day: request.from_day,
            to_day: request.to_day,
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
