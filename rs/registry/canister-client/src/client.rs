use crate::stable_memory::{RegistryStoreStableMemory, StorableRegistryKey, StorableRegistryValue};
use crate::CanisterRegistryClient;
use async_trait::async_trait;
use ic_interfaces_registry::{
    empty_zero_registry_record, RegistryClient, RegistryClientResult,
    RegistryClientVersionedResult, RegistryDataProvider, RegistryTransportRecord,
    ZERO_REGISTRY_VERSION,
};
use ic_nervous_system_canisters::registry::Registry;
use ic_registry_transport::pb::v1::RegistryDelta;
use ic_types::registry::RegistryClientError;
#[cfg(not(target_arch = "wasm32"))]
use ic_types::time::current_time as system_current_time;
use ic_types::{RegistryVersion, Time};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::{Arc, RwLock, RwLockReadGuard};

type CacheState = (
    RegistryVersion,
    BTreeMap<RegistryVersion, Time>,
    Vec<RegistryTransportRecord>,
);

pub struct CanisterRegistryStore<S: RegistryStoreStableMemory> {
    _stable_memory: PhantomData<S>,
    // TODO DO NOT MERGE make this cache work (where at)
    latest_version: RegistryVersion,

    registry: Box<dyn Registry>,
}

#[cfg(target_arch = "wasm32")]
pub fn current_time() -> Time {
    let current_time = ic_cdk::api::time();
    Time::from_nanos_since_unix_epoch(current_time)
}

#[cfg(not(any(target_arch = "wasm32")))]
pub fn current_time() -> Time {
    system_current_time()
}

impl<S: RegistryStoreStableMemory> CanisterRegistryStore<S> {
    pub fn new(registry: Box<dyn Registry>) -> Self {
        Self {
            _stable_memory: PhantomData,
            latest_version: ZERO_REGISTRY_VERSION,
            registry,
        }
    }

    fn add_deltas(&self, deltas: Vec<RegistryDelta>) -> Result<(), String> {
        for delta in deltas {
            let string_key = std::str::from_utf8(&delta.key[..]).map_err(|e| format!("{e:?}"))?;

            S::with_registry_map_mut(|local_registry| {
                for v in delta.values {
                    let registry_version = RegistryVersion::from(v.version);
                    let key =
                        StorableRegistryKey::new(string_key.to_string(), registry_version.get());
                    let value = StorableRegistryValue(if v.deletion_marker {
                        None
                    } else {
                        Some(v.value)
                    });

                    local_registry.insert(key, value);
                }
            });
        }
        Ok(())
    }
}

#[async_trait]
impl<S: RegistryStoreStableMemory> CanisterRegistryClient for CanisterRegistryStore<S> {
    fn get_versioned_value(
        &self,
        key: &str,
        version: RegistryVersion,
    ) -> RegistryClientVersionedResult<Vec<u8>> {
        if version == ZERO_REGISTRY_VERSION {
            return Ok(empty_zero_registry_record(key));
        }
        if self.get_latest_version() < version {
            return Err(RegistryClientError::VersionNotAvailable { version });
        }

        let start_range = StorableRegistryKey::new(key.to_string(), Default::default());
        let end_range = StorableRegistryKey::new(key.to_string(), version.get());

        let result = S::with_registry_map(|map| {
            map.range(start_range..=end_range)
                // TODO DO NOT MERGE change this to use stable-structures' reverse after upgrade
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .find(|(stored_key, _)| stored_key.key == key)
                .map(|(_, value)| RegistryTransportRecord {
                    key: key.to_string(),
                    version,
                    value: value.0,
                })
                .unwrap_or_else(|| empty_zero_registry_record(key))
        });
        Ok(result)
    }

    fn get_key_family(
        &self,
        key_prefix: &str,
        version: RegistryVersion,
    ) -> Result<Vec<String>, RegistryClientError> {
        if version == ZERO_REGISTRY_VERSION {
            return Ok(vec![]);
        }

        if self.get_latest_version() < version {
            return Err(RegistryClientError::VersionNotAvailable { version });
        }

        let start_range = StorableRegistryKey::new(key_prefix.to_string(), Default::default());

        let mut effective_records = BTreeMap::new();
        S::with_registry_map(|map| {
            let version = version.get();
            for (key, value) in map
                .range(start_range..)
                .filter(|(k, _)| k.version <= version)
                .take_while(|(k, _)| k.key.starts_with(key_prefix))
            {
                // For each key, keep only the record values for the latest record versions. We rely upon
                // the fact that for a fixed key, the records are sorted by version.
                effective_records.insert(key.key, value.0);
            }
        });

        let result = effective_records
            .into_iter()
            .filter_map(|(key, value)| value.is_some().then_some(key))
            .collect();
        Ok(result)
    }

    fn get_latest_version(&self) -> RegistryVersion {
        // TODO add cache for this, as it could be quite expensive.
        S::with_registry_map(|map| {
            map.range(..)
                .map(|(k, _)| k.version)
                .max()
                .map(RegistryVersion::new)
                .unwrap_or(ZERO_REGISTRY_VERSION)
        })
    }

    fn get_value(&self, key: &str, version: RegistryVersion) -> RegistryClientResult<Vec<u8>> {
        self.get_versioned_value(key, version).map(|vr| vr.value)
    }

    async fn sync_registry_stored(&self) -> Result<RegistryVersion, String> {
        let mut current_local_version = self.get_latest_version();

        loop {
            let remote_latest_version = self.registry.get_latest_version().await;

            match current_local_version.cmp(&remote_latest_version) {
                Ordering::Less => {
                    ic_cdk::println!(
                        "Registry version local {} < remote {}",
                        current_local_version,
                        remote_latest_version
                    );
                }
                Ordering::Equal => {
                    ic_cdk::println!(
                        "Local Registry version {} is up to date",
                        current_local_version
                    );
                    break;
                }
                Ordering::Greater => {
                    return Err(format!(
                        "Registry version local {} > remote {}, this should never happen",
                        current_local_version, remote_latest_version
                    ));
                }
            }

            let remote_deltas = self
                .registry
                .registry_changes_since(current_local_version)
                .await
                .map_err(|e| format!("{:?}", e))?;

            // Update the local version to the latest remote version for this iteration.
            current_local_version = RegistryVersion::new(
                remote_deltas
                    .iter()
                    .flat_map(|delta| delta.values.iter().map(|v| v.version))
                    .max()
                    .unwrap_or(current_local_version.get()),
            );

            self.add_deltas(remote_deltas)?;
        }
        Ok(current_local_version)
    }
}

#[cfg(test)]
mod tests;
