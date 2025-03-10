use ic_interfaces_registry::{RegistryClient, RegistryClientResult, RegistryDataProvider};

use std::sync::Arc;

pub struct NodeRewardsCanister {
    registry_client: Arc<dyn RegistryClient>,
}

impl NodeRewardsCanister {
    pub fn new(registry_client: Arc<dyn RegistryClient>) -> Self {
        Self { registry_client }
    }
}

/// API methods
impl NodeRewardsCanister {
    pub fn get_registry_value(&self, key: String) -> Result<Option<Vec<u8>>, String> {
        self.registry_client
            .get_value(key.as_ref(), self.registry_client.get_latest_version())
            .map_err(|e| format!("Failed to get registry value: {:?}", e))
    }
}
