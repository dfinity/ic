use crate::args::SourceSpec;
use anyhow::Result;
use ic_registry_client::client::{
    create_data_provider, DataProviderConfig, RegistryDataProvider, RegistryTransportRecord,
    RegistryVersion, ZERO_REGISTRY_VERSION,
};
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
    let cfg = match source_spec {
        SourceSpec::LocalStore(path) => DataProviderConfig::LocalStore(path),
        SourceSpec::Canister(url) => DataProviderConfig::RegistryCanisterUrl(vec![url]),
    };

    create_data_provider(rt_handle, &cfg, None)
}
