use crate::args::SourceSpec;
use anyhow::Result;
use ic_registry_client::client::{
    RegistryDataProvider, RegistryTransportRecord, RegistryVersion, ZERO_REGISTRY_VERSION,
};
use ic_registry_local_store::LocalStoreImpl;
use ic_registry_nns_data_provider::create_nns_data_provider;
use std::sync::Arc;

pub type Changelog = (Vec<RegistryTransportRecord>, RegistryVersion);

pub fn get_changelog(source_spec: SourceSpec) -> Result<Changelog> {
    let data_provider = source_to_dataprovider(tokio::runtime::Handle::current(), source_spec);

    let records = data_provider.get_updates_since(ZERO_REGISTRY_VERSION)?;
    let version = records
        .iter()
        .max_by_key(|r| r.version)
        .map(|r| r.version)
        .unwrap_or(ZERO_REGISTRY_VERSION);
    Ok((records, version))
}

fn source_to_dataprovider(
    rt_handle: tokio::runtime::Handle,
    source_spec: SourceSpec,
) -> Arc<dyn RegistryDataProvider> {
    match source_spec {
        SourceSpec::LocalStore(path) => Arc::new(LocalStoreImpl::new(path)) as Arc<_>,
        SourceSpec::Canister(url) => create_nns_data_provider(rt_handle, vec![url], None),
    }
}
