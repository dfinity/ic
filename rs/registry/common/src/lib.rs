pub mod certification;
pub mod data_provider;
pub mod registry;

use ic_interfaces::registry::RegistryDataProvider;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use std::sync::Arc;
use url::Url;

/// `ThresholdSigPublicKey` can be provided to verify certified updates provided
/// by the registry canister.
pub fn create_nns_data_provider(
    rt_handle: tokio::runtime::Handle,
    urls: Vec<Url>,
    optional_nns_public_key: Option<ThresholdSigPublicKey>,
) -> Arc<dyn RegistryDataProvider> {
    let registry_canister = registry::RegistryCanister::new(urls);
    match optional_nns_public_key {
        Some(nns_pk) => Arc::new(data_provider::CertifiedNnsDataProvider::new(
            rt_handle,
            registry_canister,
            nns_pk,
        )),
        None => Arc::new(data_provider::NnsDataProvider::new(
            rt_handle,
            registry_canister,
        )),
    }
}
