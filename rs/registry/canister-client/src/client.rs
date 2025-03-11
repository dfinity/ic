use crate::stable_memory::{RegistryStoreStableMemory, StorableRegistryKey};
use crate::CanisterRegistryClient;
use ic_interfaces_registry::{
    empty_zero_registry_record, RegistryClient, RegistryClientResult,
    RegistryClientVersionedResult, RegistryDataProvider, RegistryTransportRecord,
    ZERO_REGISTRY_VERSION,
};
use ic_types::registry::RegistryClientError;
#[cfg(not(target_arch = "wasm32"))]
use ic_types::time::current_time as system_current_time;
use ic_types::{RegistryVersion, Time};
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
    // TODO make this cache work (where at)
    latest_version: RegistryVersion,
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
    pub fn new() -> Self {
        Self {
            _stable_memory: PhantomData,
            latest_version: 0,
        }
    }

    pub fn update_to_latest_version(&self) {
        let mut cache = self.cache.write().unwrap();
        let latest_version = cache.0;

        let new_records = match self.data_provider.get_updates_since(latest_version) {
            Ok(records) if !records.is_empty() => records,
            Ok(_) => return,
            Err(e) => panic!("Failed to query data provider: {}", e),
        };

        assert!(!new_records.is_empty());
        let mut timestamps = cache.1.clone();
        let mut new_version = ZERO_REGISTRY_VERSION;
        for record in new_records {
            assert!(record.version > latest_version);
            timestamps.insert(new_version, current_time());
            new_version = new_version.max(record.version);
            let search_key = (&record.key, &record.version);
            match cache
                .2
                .binary_search_by_key(&search_key, |r| (&r.key, &r.version))
            {
                Ok(_) => (),
                Err(i) => {
                    cache.2.insert(i, record);
                }
            };
        }
        *cache = (new_version, timestamps, cache.2.clone())
    }

    pub fn reload(&self) {
        let mut cache = self.cache.write().unwrap();
        cache.0 = ZERO_REGISTRY_VERSION;
        cache.1.clear();
        drop(cache);
        self.update_to_latest_version();
    }

    fn check_version(
        &self,
        version: RegistryVersion,
    ) -> Result<RwLockReadGuard<CacheState>, RegistryClientError> {
        let latest_version = self.get_latest_version();
        if version > latest_version {
            return Err(RegistryClientError::VersionNotAvailable { version });
        }
        Ok(cache_state)
    }
}

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

        let search_key = StorableRegistryKey::new(key.to_string(), version.get());

        let result = S::with_registry_map(|map| {
            map.range(..=search_key)
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
            map.keys()
                .map(|k| k.version)
                .max()
                .map(RegistryVersion::new)
                .unwrap_or(ZERO_REGISTRY_VERSION)
        })
    }

    fn get_value(&self, key: String, version: RegistryVersion) -> RegistryClientResult<Vec<u8>> {
        if version > self.get_latest_version() {
            return Err(RegistryClientError::VersionNotAvailable { version });
        }

        Ok(S::with_registry_map(|map| {
            map.get(&StorableRegistryKey::new(key, version.get()))
                .and_then(|v| v.0)
        }))
    }

    async fn sync_registry_stored(&self) -> Result<RegistryVersion, String> {
        todo!()
    }
}

#[cfg(test)]
mod tests;
