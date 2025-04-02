use ic_node_rewards_canister_api::monthly_rewards::{
    GetNodeProvidersMonthlyXdrRewardsRequest, GetNodeProvidersMonthlyXdrRewardsResponse,
    NodeProvidersMonthlyXdrRewards,
};
use ic_protobuf::registry::dc::v1::DataCenterRecord;
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_protobuf::registry::node_rewards::v2::NodeRewardsTable;
use ic_registry_canister_client::{get_decoded_value, CanisterRegistryClient};
use ic_registry_keys::{
    DATA_CENTER_KEY_PREFIX, NODE_OPERATOR_RECORD_KEY_PREFIX, NODE_REWARDS_TABLE_KEY,
};
use ic_registry_node_provider_rewards::{calculate_rewards_v0, RewardsPerNodeProvider};
use ic_types::RegistryVersion;
use prost::Message;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::thread::LocalKey;

pub struct NodeRewardsCanister {
    registry_client: Arc<dyn CanisterRegistryClient>,
}

impl NodeRewardsCanister {
    pub fn new(registry_client: Arc<dyn CanisterRegistryClient>) -> Self {
        Self { registry_client }
    }
}

// Exposed API Methods
impl NodeRewardsCanister {
    pub async fn get_node_providers_monthly_xdr_rewards(
        canister: &LocalKey<RefCell<NodeRewardsCanister>>,
        registry_client: Arc<dyn CanisterRegistryClient>,
        request: GetNodeProvidersMonthlyXdrRewardsRequest,
    ) -> GetNodeProvidersMonthlyXdrRewardsResponse {
        // Main impl below
        return match inner_get_node_providers_monthly_xdr_rewards(
            canister,
            registry_client,
            request,
        )
        .await
        {
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
            canister: &LocalKey<RefCell<NodeRewardsCanister>>,
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

            let latest_version = registry_client.get_latest_version();
            let rewards_table = get_decoded_value::<NodeRewardsTable>(
                &*registry_client,
                NODE_REWARDS_TABLE_KEY,
                latest_version,
            )
            .map_err(|e| format!("Could not find NodeRewardsTable: {e:?}"))?
            .ok_or_else(|| "NodeRewardsTable is missing".to_string())?;

            println!("Rewards Table: {:?}", rewards_table);

            let node_operators = decoded_key_value_pairs_for_prefix::<NodeOperatorRecord>(
                &*registry_client,
                NODE_OPERATOR_RECORD_KEY_PREFIX,
                latest_version,
            )?;

            println!(
                "Before processing, data centers: {:?}",
                registry_client.get_key_family_with_values(DATA_CENTER_KEY_PREFIX, latest_version)
            );

            let data_centers = decoded_key_value_pairs_for_prefix::<DataCenterRecord>(
                &*registry_client,
                DATA_CENTER_KEY_PREFIX,
                latest_version,
            )?
            .into_iter()
            .collect();

            calculate_rewards_v0(&rewards_table, &node_operators, &data_centers)
                .map(|rewards| (rewards, latest_version))
        }
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

/// Internal methods
impl NodeRewardsCanister {
    // Test only methods
    pub fn get_registry_value(&self, key: String) -> Result<Option<Vec<u8>>, String> {
        self.registry_client
            .get_value(key.as_ref(), self.registry_client.get_latest_version())
            .map_err(|e| format!("Failed to get registry value: {:?}", e))
    }
}
