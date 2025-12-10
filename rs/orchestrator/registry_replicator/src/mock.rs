//! Mock implementation of RegistryReplicatorTrait for testing.

use crate::RegistryReplicatorTrait;
use ic_interfaces_registry::{RegistryClient, RegistryDataProvider};
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_local_store::{KeyMutation, LocalStore, LocalStoreImpl, LocalStoreWriter};
use ic_types::RegistryVersion;
use std::sync::Arc;

/// Mock registry replicator that syncs data from a "remote" registry data provider
/// to a local store and registry client.
pub struct MockRegistryReplicator {
    /// The "remote" registry data provider that simulates the NNS registry
    remote_data_provider: Arc<dyn RegistryDataProvider>,
    /// The local store that gets updated during replication
    local_store: Arc<LocalStoreImpl>,
    /// The registry client that reads from the local store
    registry_client: Arc<RegistryClientImpl>,
}

impl MockRegistryReplicator {
    /// Creates a new mock registry replicator.
    ///
    /// # Arguments
    /// * `remote_data_provider` - The "remote" registry that will be replicated from
    /// * `local_store` - The local store that will be updated during replication
    /// * `registry_client` - The registry client that reads from the local store
    pub fn new(
        remote_data_provider: Arc<dyn RegistryDataProvider>,
        local_store: Arc<LocalStoreImpl>,
        registry_client: Arc<RegistryClientImpl>,
    ) -> Self {
        Self {
            remote_data_provider,
            local_store,
            registry_client,
        }
    }
}

#[async_trait::async_trait]
impl RegistryReplicatorTrait for MockRegistryReplicator {
    /// Simulates polling the remote registry by fetching updates from the remote
    /// data provider and applying them to the local store.
    async fn poll(&self) -> Result<(), String> {
        // Get the current latest version in the local store
        let local_latest_version = self.registry_client.get_latest_version();

        // Fetch all updates from the remote data provider since the local version
        let updates = self
            .remote_data_provider
            .get_updates_since(local_latest_version)
            .map_err(|e| format!("Failed to get updates from remote: {:?}", e))?;

        // Group updates by version
        let mut version_mutations: std::collections::BTreeMap<RegistryVersion, Vec<KeyMutation>> =
            std::collections::BTreeMap::new();

        for record in updates {
            version_mutations
                .entry(record.version)
                .or_insert_with(Vec::new)
                .push(KeyMutation {
                    key: record.key,
                    value: record.value,
                });
        }

        // Apply updates to the local store
        for (version, mutations) in version_mutations {
            self.local_store
                .store(version, mutations)
                .map_err(|e| format!("Failed to store updates: {:?}", e))?;
        }

        // Update the registry client to see the new data
        self.registry_client
            .poll_once()
            .map_err(|e| format!("Failed to update registry client: {:?}", e))?;

        Ok(())
    }

    fn get_registry_client(&self) -> Arc<dyn RegistryClient> {
        self.registry_client.clone()
    }

    fn get_local_store(&self) -> Arc<dyn LocalStore> {
        self.local_store.clone()
    }

    async fn stop_polling_and_set_local_registry_data(&self, _new_local_store: &dyn LocalStore) {
        // Mock implementation does nothing - not needed for testing
    }
}

