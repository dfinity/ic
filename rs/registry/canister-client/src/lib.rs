//! An implementation of RegistryClient intended to be used in canister
//! where polling in the background is not required because handed over to a timer.
//! The code is entirely copied from `ic-registry-client-fake` and more tests added.

use ic_interfaces_registry::{
    empty_zero_registry_record, RegistryClient, RegistryClientVersionedResult,
    RegistryDataProvider, RegistryTransportRecord, ZERO_REGISTRY_VERSION,
};
use ic_types::{
    registry::RegistryClientError, time::current_time as system_current_time, RegistryVersion, Time,
};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock, RwLockReadGuard};

type CacheState = (
    RegistryVersion,
    BTreeMap<RegistryVersion, Time>,
    Vec<RegistryTransportRecord>,
);

pub struct CanisterRegistryClient {
    data_provider: Arc<dyn RegistryDataProvider>,
    cache: Arc<RwLock<CacheState>>,
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

impl CanisterRegistryClient {
    pub fn new(data_provider: Arc<dyn RegistryDataProvider>) -> Self {
        Self {
            data_provider,
            cache: Arc::new(RwLock::new(Default::default())),
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
        let cache_state = self.cache.read().unwrap();
        let (latest_version, _, _) = &*cache_state;
        if &version > latest_version {
            return Err(RegistryClientError::VersionNotAvailable { version });
        }
        Ok(cache_state)
    }
}

impl RegistryClient for CanisterRegistryClient {
    fn get_versioned_value(
        &self,
        key: &str,
        version: RegistryVersion,
    ) -> RegistryClientVersionedResult<Vec<u8>> {
        if version == ZERO_REGISTRY_VERSION {
            return Ok(empty_zero_registry_record(key));
        }
        let cache_state = self.check_version(version)?;
        let (_, _, records) = &*cache_state;

        let search_key = &(key, &version);
        let record = match records.binary_search_by_key(search_key, |r| (&r.key, &r.version)) {
            Ok(idx) => records[idx].clone(),
            Err(idx) if idx > 0 && records[idx - 1].key == key => records[idx - 1].clone(),
            _ => empty_zero_registry_record(key),
        };

        Ok(record)
    }

    fn get_key_family(
        &self,
        key_prefix: &str,
        version: RegistryVersion,
    ) -> Result<Vec<String>, RegistryClientError> {
        if version == ZERO_REGISTRY_VERSION {
            return Ok(vec![]);
        }
        let cache_state = self.check_version(version)?;
        let (_, _, records) = &*cache_state;

        let first_registry_version = RegistryVersion::from(1);
        let search_key = &(key_prefix, &first_registry_version);

        let first_match_index =
            match records.binary_search_by_key(search_key, |r| (&r.key, &r.version)) {
                Ok(idx) => idx,
                Err(idx) => {
                    if !records[idx].key.starts_with(key_prefix) {
                        return Ok(vec![]);
                    }
                    idx
                }
            };

        let records = records
            .iter()
            .skip(first_match_index) // (1)
            .filter(|r| r.version <= version) // (2)
            .take_while(|r| r.key.starts_with(key_prefix)); // (3)

        let mut effective_records = BTreeMap::new();
        for record in records {
            effective_records.insert(record.key.clone(), &record.value);
        }
        let result = effective_records
            .into_iter()
            .filter_map(|(key, value)| value.is_some().then_some(key))
            .collect();
        Ok(result)
    }

    fn get_latest_version(&self) -> RegistryVersion {
        self.cache.read().unwrap().0
    }

    fn get_version_timestamp(&self, registry_version: RegistryVersion) -> Option<Time> {
        self.cache.read().unwrap().1.get(&registry_version).cloned()
    }
}

#[cfg(test)]
mod tests;
