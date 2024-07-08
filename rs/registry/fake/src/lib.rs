//! A fake implementation of RegistryClient intended to be used in component
//! tests and utility functions where a real registry that polls in the
//! background is not required.

use ic_interfaces_registry::{
    empty_zero_registry_record, RegistryClient, RegistryClientVersionedResult,
    RegistryDataProvider, RegistryTransportRecord, ZERO_REGISTRY_VERSION,
};
use ic_types::{registry::RegistryClientError, time::current_time, RegistryVersion, Time};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock, RwLockReadGuard};

type CacheState = (
    RegistryVersion,
    BTreeMap<RegistryVersion, Time>,
    Vec<RegistryTransportRecord>,
);

pub struct FakeRegistryClient {
    data_provider: Arc<dyn RegistryDataProvider>,
    cache: Arc<RwLock<CacheState>>,
}

impl FakeRegistryClient {
    /// After creation, the cache is empty.
    pub fn new(data_provider: Arc<dyn RegistryDataProvider>) -> Self {
        Self {
            data_provider,
            cache: Arc::new(RwLock::new(Default::default())),
        }
    }

    /// Calls `get_updates_since()` on the data provider and updates the cache
    /// accordingly.
    pub fn update_to_latest_version(&self) {
        let mut cache = self.cache.write().unwrap();
        let latest_version = cache.0;

        let new_records = match self
            .data_provider
            .get_updates_since(latest_version)
        {
            Ok(records) if !records.is_empty() => records,
            Ok(_) /*if version == cache_state.latest_version*/ => return,
            Err(e) => panic!("Failed to query data provider: {}", e),
        };

        // perform update
        assert!(!new_records.is_empty());
        let mut timestamps = cache.1.clone();
        let mut new_version = ZERO_REGISTRY_VERSION;
        for record in new_records {
            assert!(record.version > latest_version);
            new_version = new_version.max(record.version);
            timestamps.insert(new_version, current_time());
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

    /// Resets the registry to version 0 and reloads all data from the attached
    /// data provider.
    ///
    /// Useful to pick up data that were added at an existing version in the
    /// test data provider.
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

impl RegistryClient for FakeRegistryClient {
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
            // We have an exact match
            Ok(idx) => records[idx].clone(),
            // A record with the same key and record version < version
            Err(idx) if idx > 0 && records[idx - 1].key == key => records[idx - 1].clone(),
            // No entry found, key does not exist
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
        // The pair (k, version) is unique and no entry exists with version 0. Thus, the
        // first entry of interest is at the insertion point of (prefix, 1).
        let search_key = &(key_prefix, &first_registry_version);

        let first_match_index =
            match records.binary_search_by_key(search_key, |r| (&r.key, &r.version)) {
                // An exact match just means the key family will have size 1.
                Ok(idx) => idx,
                // The entry at idx cannot be lexicographically less than key_prefix, otherwise the
                // correctness assumption about bin search would not hold.
                Err(idx) => {
                    if !records[idx].key.starts_with(key_prefix) {
                        // If the key at this position does not start with `key_prefix`, the set of keys
                        // starting with `key_prefix` is empty.
                        return Ok(vec![]);
                    }
                    idx
                }
            };

        // 1. Skip all entries up to the first_match_index
        // 2. Filter out all versions newer than the one we are interested in
        // 3. Only consider the subsequence that starts with the given prefix
        let records = records
            .iter()
            .skip(first_match_index) // (1)
            .filter(|r| r.version <= version) // (2)
            .take_while(|r| r.key.starts_with(key_prefix)); // (3)

        // For each key, keep only the record values for the latest record versions. We rely upon
        // the fact that for a fixed key, the records are sorted by version.
        let mut effective_records = BTreeMap::new();
        for record in records {
            effective_records.insert(record.key.clone(), &record.value);
        }
        // Finally, remove empty records, i.e., those for which `value` is `None`.
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
