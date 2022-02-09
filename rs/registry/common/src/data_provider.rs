use ic_interfaces::registry::{RegistryDataProvider, RegistryTransportRecord};

use crate::registry::RegistryCanister;
use ic_types::{
    crypto::threshold_sig::ThresholdSigPublicKey, registry::RegistryDataProviderError,
    RegistryVersion,
};
use std::sync::Arc;

pub struct NnsDataProvider {
    registry_canister: Arc<RegistryCanister>,
}

pub struct CertifiedNnsDataProvider {
    registry_canister: Arc<RegistryCanister>,
    nns_public_key: Arc<ThresholdSigPublicKey>,
}

impl NnsDataProvider {
    pub fn new(registry_canister: RegistryCanister) -> NnsDataProvider {
        NnsDataProvider {
            registry_canister: Arc::new(registry_canister),
        }
    }
}

impl RegistryDataProvider for NnsDataProvider {
    fn get_updates_since(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<RegistryTransportRecord>, RegistryDataProviderError> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on({
                let registry_canister = Arc::clone(&self.registry_canister);
                async move {
                    match registry_canister.get_changes_since(version.get()).await {
                        Ok((deltas, _last_version)) => {
                            let mut changes: Vec<RegistryTransportRecord> = vec![];

                            for delta in &deltas {
                                let key: String =
                                    std::str::from_utf8(&delta.key).unwrap().to_string();

                                for value in &delta.values {
                                    let version = RegistryVersion::from(value.version);
                                    let record = RegistryTransportRecord {
                                        key: key.clone(),
                                        version,
                                        value: if value.deletion_marker {
                                            None
                                        } else {
                                            Some(value.value.clone())
                                        },
                                    };

                                    changes.push(record);
                                }
                            }

                            Ok(changes)
                        }
                        Err(source) => Err(RegistryDataProviderError::Transfer { source }),
                    }
                }
            })
        })
    }
}

impl CertifiedNnsDataProvider {
    pub fn new(registry_canister: RegistryCanister, nns_public_key: ThresholdSigPublicKey) -> Self {
        Self {
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
        let (records, _version, _time) = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on({
                let registry_canister = Arc::clone(&self.registry_canister);
                let nns_public_key = Arc::clone(&self.nns_public_key);
                async move {
                    registry_canister
                        .get_certified_changes_since(version.get(), &nns_public_key)
                        .await
                        .map_err(|source| RegistryDataProviderError::Transfer { source })
                }
            })
        })?;
        Ok(records)
    }
}
