use ic_interfaces_registry::{RegistryDataProvider, RegistryRecord};
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_types::{
    RegistryVersion, crypto::threshold_sig::ThresholdSigPublicKey,
    registry::RegistryDataProviderError,
};
use std::sync::Arc;
use url::Url;

/// `ThresholdSigPublicKey` can be provided to verify certified updates provided
/// by the registry canister.
pub fn create_nns_data_provider(
    rt_handle: tokio::runtime::Handle,
    urls: Vec<Url>,
    optional_nns_public_key: Option<ThresholdSigPublicKey>,
) -> Arc<dyn RegistryDataProvider> {
    match optional_nns_public_key {
        Some(nns_pk) => Arc::new(CertifiedNnsDataProvider::new(rt_handle, urls, nns_pk)),
        None => Arc::new(NnsDataProvider::new(rt_handle, urls)),
    }
}

pub struct NnsDataProvider {
    registry_canister: Arc<RegistryCanister>,
    rt_handle: tokio::runtime::Handle,
}

pub struct CertifiedNnsDataProvider {
    registry_canister: Arc<RegistryCanister>,
    nns_public_key: Arc<ThresholdSigPublicKey>,
    rt_handle: tokio::runtime::Handle,
}

impl NnsDataProvider {
    pub fn new(rt_handle: tokio::runtime::Handle, urls: Vec<Url>) -> NnsDataProvider {
        NnsDataProvider {
            rt_handle,
            registry_canister: Arc::new(RegistryCanister::new(urls)),
        }
    }
}

impl RegistryDataProvider for NnsDataProvider {
    fn get_updates_since(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<RegistryRecord>, RegistryDataProviderError> {
        let rt_handle = self.rt_handle.clone();
        let registry_canister = self.registry_canister.clone();
        #[allow(clippy::disallowed_methods)]
        tokio::task::block_in_place(|| {
            rt_handle.block_on(async move {
                registry_canister
                    .get_changes_since_as_registry_records(version.get())
                    .await
                    .map(|v| v.0)
                    .map_err(|source| RegistryDataProviderError::Transfer {
                        source: source.to_string(),
                    })
            })
        })
    }
}

impl CertifiedNnsDataProvider {
    pub fn new(
        rt_handle: tokio::runtime::Handle,
        urls: Vec<Url>,
        nns_public_key: ThresholdSigPublicKey,
    ) -> Self {
        Self {
            rt_handle,
            registry_canister: Arc::new(RegistryCanister::new(urls)),
            nns_public_key: Arc::new(nns_public_key),
        }
    }
}

impl RegistryDataProvider for CertifiedNnsDataProvider {
    fn get_updates_since(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<RegistryRecord>, RegistryDataProviderError> {
        let rt_handle = self.rt_handle.clone();
        let registry_canister = self.registry_canister.clone();
        let nns_public_key = self.nns_public_key.clone();
        #[allow(clippy::disallowed_methods)]
        tokio::task::block_in_place(|| {
            rt_handle.block_on(async move {
                registry_canister
                    .get_certified_changes_since(version.get(), &nns_public_key)
                    .await
                    .map(|v| v.0)
                    .map_err(|source| RegistryDataProviderError::Transfer {
                        source: source.to_string(),
                    })
            })
        })
    }
}
