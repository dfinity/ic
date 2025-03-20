use ic_node_rewards_canister_api::monthly_rewards::{
    GetNodeProvidersMonthlyXdrRewardsRequest, GetNodeProvidersMonthlyXdrRewardsResponse,
};
use ic_registry_canister_client::CanisterRegistryClient;
use std::cell::RefCell;
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
    pub fn get_node_providers_monthly_xdr_rewards(
        canister: &LocalKey<RefCell<NodeRewardsCanister>>,
        registry_client: Arc<dyn CanisterRegistryClient>,
        request: GetNodeProvidersMonthlyXdrRewardsRequest,
    ) -> GetNodeProvidersMonthlyXdrRewardsResponse {
        todo!()

        // let result = calculate_rewards_v0(&rewards_table, &node_operators, &data_centers);
    }
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
