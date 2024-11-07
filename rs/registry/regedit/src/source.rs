use crate::args::SourceSpec;
use anyhow::Result;
use ic_registry_client::client::{
    RegistryDataProvider,
    RegistryTransportRecord,
    RegistryVersion,
    ZERO_REGISTRY_VERSION,
};
use ic_registry_local_store::LocalStoreImpl;
use ic_registry_nns_data_provider_wrappers::create_nns_data_provider;
use std::sync::Arc;

pub type Changelog = (Vec<RegistryTransportRecord>, RegistryVersion);

pub fn get_changelog(source_spec: SourceSpec) -> Result<Changelog> {
    let data_provider = source_to_dataprovider(source_spec);

    let mut version = ZERO_REGISTRY_VERSION;
    let mut records = vec![];

    loop {
        let mut batch = data_provider.get_updates_since(version)?;
        if batch.is_empty() {
            break;
        }
        version = batch
            .iter()
            .max_by_key(|r| r.version)
            .map(|r| r.version)
            .unwrap_or(ZERO_REGISTRY_VERSION);
        records.append(&mut batch);
    }

    Ok((records, version))
}

fn source_to_dataprovider(source_spec: SourceSpec) -> Arc<dyn RegistryDataProvider> {
    match source_spec {
        SourceSpec::LocalStore(path) => Arc::new(LocalStoreImpl::new(path)) as Arc<_>,
        SourceSpec::Canister(url, nns_pk) => {
            create_nns_data_provider(tokio::runtime::Handle::current(), vec![url], nns_pk)
        }
    }
}
