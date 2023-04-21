use ic_interfaces_registry::{RegistryDataProvider, RegistryTransportRecord};
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_types::{
    crypto::threshold_sig::ThresholdSigPublicKey, registry::RegistryDataProviderError,
    RegistryVersion,
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
    let registry_canister = RegistryCanister::new(urls);
    match optional_nns_public_key {
        Some(nns_pk) => Arc::new(CertifiedNnsDataProvider::new(
            rt_handle,
            registry_canister,
            nns_pk,
        )),
        None => Arc::new(NnsDataProvider::new(rt_handle, registry_canister)),
    }
}

pub struct NnsDataProvider {
    registry_canister: Arc<RegistryCanister>,
    rt_handle: tokio::runtime::Handle,
}

pub(crate) struct CertifiedNnsDataProvider {
    registry_canister: Arc<RegistryCanister>,
    nns_public_key: Arc<ThresholdSigPublicKey>,
    rt_handle: tokio::runtime::Handle,
}

impl NnsDataProvider {
    pub fn new(
        rt_handle: tokio::runtime::Handle,
        registry_canister: RegistryCanister,
    ) -> NnsDataProvider {
        NnsDataProvider {
            rt_handle,
            registry_canister: Arc::new(registry_canister),
        }
    }
}

impl RegistryDataProvider for NnsDataProvider {
    fn get_updates_since(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<RegistryTransportRecord>, RegistryDataProviderError> {
        let rt_handle = self.rt_handle.clone();
        let registry_canister = self.registry_canister.clone();
        #[allow(clippy::disallowed_methods)]
        tokio::task::block_in_place(|| {
            rt_handle.block_on(async move {
                registry_canister
                    .get_changes_since_as_transport_records(version.get())
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
    pub(crate) fn new(
        rt_handle: tokio::runtime::Handle,
        registry_canister: RegistryCanister,
        nns_public_key: ThresholdSigPublicKey,
    ) -> Self {
        Self {
            rt_handle,
            registry_canister: Arc::new(registry_canister),
            nns_public_key: Arc::new(nns_public_key),
        }
    }
}

impl RegistryDataProvider for CertifiedNnsDataProvider {
    fn get_updates_since(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<RegistryTransportRecord>, RegistryDataProviderError> {
        let rt_handle = self.rt_handle.clone();
        let registry_canister = self.registry_canister.clone();
        let nns_public_key = self.nns_public_key.clone();
        rt_handle.block_on(async move {
            registry_canister
                .get_certified_changes_since(version.get(), &nns_public_key)
                .await
                .map(|v| v.0)
                .map_err(|source| RegistryDataProviderError::Transfer {
                    source: source.to_string(),
                })
        })
    }
}
