use ic_interfaces::registry::{
    RegistryDataProvider, RegistryTransportRecord, ZERO_REGISTRY_VERSION,
};
use ic_types::{registry::RegistryDataProviderError, RegistryVersion};
use std::sync::Arc;

pub const INITIAL_REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(1);

/// Fetches the first version (V1) from an initial data provider and all greater
/// versions from another data provider. This data provider is used to bootstrap
/// the NNS subnetwork.
pub struct BootstrapRegistryDataProvider {
    initial_data_provider: Arc<dyn RegistryDataProvider>,
    data_provider: Arc<dyn RegistryDataProvider>,
}

impl BootstrapRegistryDataProvider {
    pub fn new(
        initial_data_provider: Arc<dyn RegistryDataProvider>,
        data_provider: Arc<dyn RegistryDataProvider>,
    ) -> Self {
        Self {
            initial_data_provider,
            data_provider,
        }
    }
}

impl RegistryDataProvider for BootstrapRegistryDataProvider {
    fn get_updates_since(
        &self,
        version: RegistryVersion,
    ) -> Result<(Vec<RegistryTransportRecord>, RegistryVersion), RegistryDataProviderError> {
        if version == ZERO_REGISTRY_VERSION {
            let update = self.initial_data_provider.get_updates_since(version)?;
            if !is_valid_initial_update(&update) {
                panic!("Bootstrap: Invalid initial update from initial data provider.")
            }
            Ok(update)
        } else {
            self.data_provider.get_updates_since(version)
        }
    }
}

/// Tests whether the update received from the initial data provider is a legal
/// first version of the registry, i.e. only contains records with version 1 and
/// the latest version is 1.
pub fn is_valid_initial_update(update: &(Vec<RegistryTransportRecord>, RegistryVersion)) -> bool {
    let only_v1 = update
        .0
        .iter()
        .map(|r| r.version)
        .all(|v| v == INITIAL_REGISTRY_VERSION);
    let last_version = update.1;
    only_v1 && last_version == INITIAL_REGISTRY_VERSION
}
