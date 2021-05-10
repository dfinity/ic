//! A fake implementation of RegistryClient intended to be used in component
//! tests and utility functions where a real registry that polls in the
//! background is not required.

use ic_interfaces::registry::{
    empty_zero_registry_record, RegistryClient, RegistryClientVersionedResult,
    RegistryDataProvider, RegistryTransportRecord, ZERO_REGISTRY_VERSION,
};
use ic_types::registry::RegistryClientError;
use ic_types::RegistryVersion;
use std::sync::{Arc, RwLock, RwLockReadGuard};

type CacheState = (RegistryVersion, Vec<RegistryTransportRecord>);

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

        let (new_records, new_version) = match self
            .data_provider
            .get_updates_since(latest_version)
        {
            Ok((records, version)) if version > latest_version => {
                (records, version)
            }
            Ok(_) /*if version == cache_state.latest_version*/ => return,
            Err(e) => panic!(format!("Failed to query data provider: {}", e)),
        };

        // perform update
        assert!(new_version > latest_version);
        for record in new_records {
            assert!(record.version > latest_version);
            let search_key = (&record.key, &record.version);
            match cache
                .1
                .binary_search_by_key(&search_key, |r| (&r.key, &r.version))
            {
                Ok(_) => (),
                Err(i) => {
                    cache.1.insert(i, record);
                }
            };
        }
        *cache = (new_version, cache.1.clone())
    }

    /// Resets the registry to version 0 and reloads all data from the attached
    /// data provider.
    ///
    /// Useful to pick up data that were added at an existing version in the
    /// test data provider.
    #[allow(dead_code)]
    fn reload(&self) {
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
        let (latest_version, _) = &*cache_state;
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
        let (_, records) = &*cache_state;

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
        let (_, records) = &*cache_state;

        let first_registry_version = RegistryVersion::from(1);
        // The pair (k, version) is unique and no entry exists with version 0. Thus, the
        // first entry of interest is at the insertion point of (prefix, 1).
        let search_key = &(key_prefix, &first_registry_version);

        let i = match records.binary_search_by_key(search_key, |r| (&r.key, &r.version)) {
            // An exact match just means the key family will have size 1.
            Ok(idx) => idx,
            // The entry at idx cannot be lexicographically less than key_prefix, otherwise the
            // correctness assumption about bin search would not hold.
            Err(idx) if records[idx].key.starts_with(key_prefix) => idx,
            // No entry found, key does not exist
            _ => return Ok(vec![]),
        };

        let res = records
            .iter()
            .skip(i)
            .filter(|r| r.version <= version)
            .take_while(|r| r.key.starts_with(key_prefix))
            .fold(vec![], |mut acc, r| {
                let is_present = r.value.is_some();
                if acc.last().map(|k| k == &r.key).unwrap_or(false) && !is_present {
                    acc.pop();
                } else if is_present {
                    acc.push(r.key.clone());
                }
                acc
            });
        Ok(res)
    }

    fn get_latest_version(&self) -> RegistryVersion {
        self.cache.read().unwrap().0
    }
}
