use crate::stable_memory::{RegistryDataStableMemory, StorableRegistryKey, StorableRegistryValue};
use crate::CanisterRegistryClient;
use async_trait::async_trait;
use ic_interfaces_registry::{
    empty_zero_registry_record, RegistryClientResult, RegistryClientVersionedResult,
    RegistryTransportRecord, RegistryVersionedRecord, ZERO_REGISTRY_VERSION,
};
use ic_nervous_system_canisters::registry::Registry;
use ic_registry_transport::pb::v1::RegistryDelta;
use ic_types::registry::RegistryClientError;
use ic_types::RegistryVersion;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering as AtomicOrdering;

/// This implementation of CanisterRegistryClient uses StableMemory to store a copy of the
/// Registry data in the canister.  An implementation of RegistryDataStableMemory trait that
/// provides the StableBTreeMap is required to use it.
pub struct StableCanisterRegistryClient<S: RegistryDataStableMemory> {
    // The type of the accessor for StableBTreeMap that holds the registry data.
    _stable_memory: PhantomData<S>,
    // cache of latest_version
    latest_version: AtomicU64,
    // Registry client to interact with the canister
    registry: Box<dyn Registry>,
}

impl<S: RegistryDataStableMemory> StableCanisterRegistryClient<S> {
    pub fn new(registry: Box<dyn Registry>) -> Self {
        Self {
            _stable_memory: PhantomData,
            latest_version: AtomicU64::new(0),
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
impl<S: RegistryDataStableMemory> CanisterRegistryClient for StableCanisterRegistryClient<S> {
    fn get_versioned_value(
        &self,
        key: &str,
        version: RegistryVersion,
    ) -> RegistryClientVersionedResult<Vec<u8>> {
        if self.get_latest_version() < version {
            return Err(RegistryClientError::VersionNotAvailable { version });
        }

        let start_range = StorableRegistryKey::new(key.to_string(), Default::default());
        let end_range = StorableRegistryKey::new(key.to_string(), version.get());

        let result = S::with_registry_map(|map| {
            map.range(start_range..=end_range)
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

    fn get_value(&self, key: &str, version: RegistryVersion) -> RegistryClientResult<Vec<u8>> {
        self.get_versioned_value(key, version).map(|vr| vr.value)
    }

    fn get_latest_version(&self) -> RegistryVersion {
        let mut latest = self.latest_version.load(AtomicOrdering::SeqCst);
        if latest == 0 {
            latest = S::with_registry_map(|map| {
                map.range(..)
                    .map(|(k, _)| k.version)
                    .max()
                    .unwrap_or(ZERO_REGISTRY_VERSION.get())
            });
            self.latest_version.store(latest, AtomicOrdering::SeqCst);
        }
        RegistryVersion::new(latest)
    }

    async fn sync_registry_stored(&self) -> Result<RegistryVersion, String> {
        let mut current_local_version = self.get_latest_version();

        loop {
            let remote_latest_version = self.registry.get_latest_version().await?;

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

            self.latest_version
                .store(current_local_version.get(), AtomicOrdering::SeqCst);
            self.add_deltas(remote_deltas)?;
        }
        Ok(current_local_version)
    }

    fn get_effective_records_between(
        &self,
        key_prefix: &str,
        lower_bound: RegistryVersion,
        upper_bound: RegistryVersion,
    ) -> Result<Vec<RegistryVersionedRecord<Vec<u8>>>, RegistryClientError> {
        // Lower bound has to be within accessible range
        if self.get_latest_version() < lower_bound {
            return Err(RegistryClientError::VersionNotAvailable {
                version: lower_bound,
            });
        }

        // Upper bound has to be within accessible range
        if self.get_latest_version() < upper_bound {
            return Err(RegistryClientError::VersionNotAvailable {
                version: upper_bound,
            });
        }

        let start_range = StorableRegistryKey::new(key_prefix.to_string(), Default::default());
        let lower_bound = lower_bound.get();
        let upper_bound = upper_bound.get();

        let mut first_effective_records = BTreeMap::new();

        let mut effective_records = BTreeMap::new();
        S::with_registry_map(|map| {
            for (key, value) in map
                .range(start_range.clone()..)
                .filter(|(k, _)| k.version <= upper_bound)
                .take_while(|(k, _)| k.key.starts_with(key_prefix))
            {
                // The first change before `lower_bound` A is also
                // effective in the period [A, B].
                //
                //         A           B
                //
                // +----*--|--*--*--*--|----+
                //
                //      x     y  z  h
                // Legend:
                // - [x,y,z,h] - change (version when the change happened)
                // - A - `lower_bound` requested to this function
                // - B - `upper_bound` request to this function
                //
                // Effective versions in range [A-B] are:
                // - x - valid from A up to y
                // - y - valid from y up to z
                // - z - valid from z up to h
                // - h - valid from h to B (and after)
                //
                // If there was a change exactly on A then all of the
                // versions before wouldn't be effective.
                //
                //         A           B
                //
                // +----*--#-----*--*--|----+
                //
                //      x  y     z  h
                // Legend:
                // - [x,y,z,h] - change (version when the change happened)
                // - A - `lower_bound` requested to this function
                // - B - `upper_bound` request to this function
                //
                // Effective versions in range [A-B] are:
                // - y - valid from A to z
                // - z - valid from z to h
                // - h - valid from h to B (and after)
                if key.version <= lower_bound {
                    // Here we keep updating the same key with the latest version.
                    // We rely on the fact that for the same key, versions
                    // will be sorted in an ascending order.
                    first_effective_records.insert(key.key, (key.version, value));
                } else {
                    // For each key, keep only the record values for the latest record versions. We rely upon
                    // the fact that for a fixed key, the records are sorted by version.
                    effective_records.insert(key, value);
                }
            }
            for (key, (version, value)) in first_effective_records {
                effective_records.insert(StorableRegistryKey { key, version }, value);
            }
        });

        Ok(effective_records
            .into_iter()
            .map(|(key, value)| RegistryVersionedRecord {
                key: key.key,
                version: RegistryVersion::new(key.version),
                value: value.0,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests;
