use crate::metrics::MetricsManager;
use crate::registry_querier::RegistryQuerier;
use crate::storage::VM;
use crate::telemetry;
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
use ic_registry_canister_client::{
    get_decoded_value, CanisterRegistryClient, RegistryDataStableMemory,
};
use ic_registry_keys::{
    DATA_CENTER_KEY_PREFIX, NODE_OPERATOR_RECORD_KEY_PREFIX, NODE_REWARDS_TABLE_KEY,
};
use ic_registry_node_provider_rewards::{calculate_rewards_v0, RewardsPerNodeProvider};
use ic_types::{RegistryVersion, Time};
use rewards_calculation::rewards_calculator::RewardsCalculatorInput;
use rewards_calculation::rewards_calculator_results::RewardsCalculatorResults;
use rewards_calculation::types::DayUtc;
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

    fn calculate_rewards<S: RegistryDataStableMemory>(
        &self,
        day_utc: DayUtc,
        provider_filter: Option<PrincipalId>,
    ) -> Result<RewardsCalculatorResults, String> {
        // Metrics are collected at the end of the day, so we need to ensure that
        // the end timestamp is not later than the first ts of today.
        let today: DayUtc = current_time().as_nanos_since_unix_epoch().into();
        if day_utc >= today {
            return Err("day_utc must be earlier than today".to_string());
        }
        let registry_querier = RegistryQuerier::new(self.registry_client.clone());
        let version = registry_querier
            .version_for_timestamp(day_utc.unix_ts_at_day_end())
            .ok_or_else(|| "Could not find registry version for timestamp".to_string())?;
        let rewards_table = registry_querier.get_rewards_table(version);
        let metrics_by_subnet = self.metrics_manager.metrics_by_subnet(day_utc);
        let provider_rewardable_nodes = registry_querier
            .get_rewardable_nodes_per_provider(version, provider_filter)
            .map_err(|e| format!("Could not get rewardable nodes: {e:?}"))?;

        let input = RewardsCalculatorInput {
            day_utc,
            rewards_table,
            metrics_by_subnet,
            provider_rewardable_nodes,
        };
        let result = rewards_calculation::rewards_calculator::calculate_daily_rewards(input);
        Ok(result)
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

    pub async fn get_node_providers_rewards<S: RegistryDataStableMemory>(
        canister: &'static LocalKey<RefCell<NodeRewardsCanister>>,
        request: GetNodeProvidersRewardsRequest,
    ) -> GetNodeProvidersRewardsResponse {
        let start_day: DayUtc = request.from_day_timestamp_nanos.into();
        let end_day: DayUtc = request.to_day_timestamp_nanos.into();
        let mut rewards_xdr_permyriad = BTreeMap::new();
        if start_day > end_day {
            return Err(
                "from_day_timestamp_nanos must be before to_day_timestamp_nanos".to_string(),
            );
        }

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

        let mut current_day = start_day;
        while current_day <= end_day {
            let instruction_counter = telemetry::InstructionCounter::default();

            let result = canister
                .with_borrow(|canister| canister.calculate_rewards::<S>(current_day, None))?;
            ic_cdk::println!("day took {} instruction", instruction_counter.sum());
            for (provider_id, provider_rewards) in result.provider_results.into_iter() {
                let daily_rewards = rewards_xdr_permyriad.entry(provider_id.0).or_insert(0);
                *daily_rewards += provider_rewards.rewards_total_xdr_permyriad;
            }
            current_day = current_day.next_day();
        }

        Ok(NodeProvidersRewards {
            rewards_xdr_permyriad,
        })
    }

    pub fn get_node_provider_rewards_calculation<S: RegistryDataStableMemory>(
        canister: &'static LocalKey<RefCell<NodeRewardsCanister>>,
        request: GetNodeProviderRewardsCalculationRequest,
    ) -> GetNodeProviderRewardsCalculationResponse {
        let provider_id = PrincipalId::from(request.provider_id);
        let mut result = canister.with_borrow(|canister| {
            canister.calculate_rewards::<S>(request.day_timestamp_nanos.into(), Some(provider_id))
        })?;
        let node_provider_rewards = result.provider_results.remove(&provider_id).ok_or(format!(
            "No rewards found for node provider {}",
            provider_id
        ))?;

        Ok(node_provider_rewards.into())
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
