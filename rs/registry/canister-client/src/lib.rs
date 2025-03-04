use candid::Principal;
use ic_interfaces_registry::{
    empty_zero_registry_record, RegistryClient, RegistryClientVersionedResult,
    RegistryTransportRecord, ZERO_REGISTRY_VERSION,
};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_registry_transport::pb::v1::RegistryDelta;
use ic_registry_transport::{
    deserialize_get_changes_since_response, serialize_get_changes_since_request,
};
use ic_stable_structures::memory_manager::VirtualMemory;
use ic_stable_structures::storable::Bound;
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, Storable};
use ic_types::registry::RegistryClientError;
use ic_types::{RegistryVersion, Time};
use itertools::Itertools;
use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};
use std::marker::PhantomData;

mod tests;

type Memory = VirtualMemory<DefaultMemoryImpl>;

// This value is set as 2 times the max key size present in the registry
const MAX_REGISTRY_KEY_SIZE: u32 = 200;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Default, Debug)]
pub struct StorableRegistryKey {
    pub key: String,
    pub version: RegistryVersion,
}
impl StorableRegistryKey {
    pub fn new(key: String, version: RegistryVersion) -> Self {
        Self { key, version }
    }
}

impl Storable for StorableRegistryKey {
    fn to_bytes(&self) -> Cow<[u8]> {
        let mut storable_key = vec![];
        let version_b = self.version.get().to_be_bytes().to_vec();
        let key_b = self.key.as_bytes().to_vec();

        storable_key.extend_from_slice(&version_b);
        storable_key.extend_from_slice(&key_b);

        Cow::Owned(storable_key)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let bytes = bytes.as_ref();
        let (version_bytes, key_bytes) = bytes.split_at(8);

        let version_u64 =
            u64::from_be_bytes(version_bytes.try_into().expect("Invalid version bytes"));
        let version = RegistryVersion::new(version_u64.into());
        let key = String::from_utf8(key_bytes.to_vec()).expect("Invalid UTF-8 in key");
        Self { key, version }
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: MAX_REGISTRY_KEY_SIZE + size_of::<u64>() as u32,
        is_fixed_size: false,
    };
}

#[derive(Clone, Debug)]
pub struct StorableRegistryValue(pub Option<Vec<u8>>);

impl Storable for StorableRegistryValue {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self(Option::from_bytes(bytes))
    }

    const BOUND: Bound = Bound::Unbounded;
}

pub trait StableMemoryBorrower: Send + Sync {
    fn with_borrow<R>(
        f: impl FnOnce(&StableBTreeMap<StorableRegistryKey, StorableRegistryValue, Memory>) -> R,
    ) -> R;
    fn with_borrow_mut<R>(
        f: impl FnOnce(&mut StableBTreeMap<StorableRegistryKey, StorableRegistryValue, Memory>) -> R,
    ) -> R;
}

/// This registry data provider is designed to work with the `ic-registry-canister-client`
/// in canisters, enabling the retrieval and storage of a registry copy in stable memory.
///
/// - If `keys_to_keep` is `Some(keys)`, only the specified `keys` will be stored in stable memory,
///   while all other keys from the registry will be discarded.
/// - If `keys_to_keep` is `None`, all keys from the registry will be retained in stable memory.
pub struct CanisterRegistryReplicator<S: StableMemoryBorrower> {
    keys_to_keep: Option<HashSet<String>>,
    _store: PhantomData<S>,
}

impl<S: StableMemoryBorrower> CanisterRegistryReplicator<S> {
    pub fn new(keys_to_retain: Option<HashSet<String>>) -> Self {
        Self {
            keys_to_keep: keys_to_retain,
            _store: PhantomData,
        }
    }

    async fn get_registry_changes_since(&self, version: u64) -> anyhow::Result<Vec<RegistryDelta>> {
        let buff = serialize_get_changes_since_request(version)?;
        let response = ic_cdk::api::call::call_raw(
            Principal::from(REGISTRY_CANISTER_ID),
            "get_changes_since",
            buff,
            0,
        )
        .await
        .map_err(|(code, msg)| (code as i32, msg))
        .unwrap();
        let (registry_delta, _) = deserialize_get_changes_since_response(response)?;
        Ok(registry_delta)
    }

    fn add_deltas(&self, deltas: Vec<RegistryDelta>) -> anyhow::Result<()> {
        for delta in deltas {
            let string_key = std::str::from_utf8(&delta.key[..])
                .map_err(|_| anyhow::anyhow!("Failed to convert key {:?} to string", delta.key))?;

            if let Some(keys) = &self.keys_to_keep {
                if keys.iter().all(|prefix| !string_key.starts_with(prefix)) {
                    continue;
                }
            }

            for value in delta.values.into_iter() {
                S::with_borrow_mut(|local_registry| {
                    local_registry.insert(
                        StorableRegistryKey {
                            key: string_key.to_string(),
                            version: RegistryVersion::from(value.version),
                        },
                        StorableRegistryValue(if value.deletion_marker {
                            None
                        } else {
                            Some(value.value)
                        }),
                    );
                })
            }
        }
        Ok(())
    }

    pub async fn sync_registry_stored(&self) -> anyhow::Result<()> {
        let mut update_registry_version = self.get_latest_version().get();

        loop {
            let remote_latest_version = ic_nns_common::registry::get_latest_version().await;

            ic_cdk::println!(
                "local version: {} remote version: {}",
                update_registry_version,
                remote_latest_version
            );

            match update_registry_version.cmp(&remote_latest_version) {
                Ordering::Less => {
                    ic_cdk::println!(
                        "Registry version local {} < remote {}",
                        update_registry_version,
                        remote_latest_version
                    );
                }
                Ordering::Equal => {
                    ic_cdk::println!(
                        "Local Registry version {} is up to date",
                        update_registry_version
                    );
                    break;
                }
                Ordering::Greater => {
                    let message = format!(
                        "Registry version local {} > remote {}, this should never happen",
                        update_registry_version, remote_latest_version
                    );

                    ic_cdk::trap(message.as_str());
                }
            }

            if let Ok(deltas) = self
                .get_registry_changes_since(update_registry_version)
                .await
            {
                update_registry_version = deltas
                    .iter()
                    .flat_map(|delta| delta.values.iter().map(|v| v.version))
                    .max()
                    .unwrap_or(update_registry_version);
                self.add_deltas(deltas)?;
            };
        }
        Ok(())
    }
}

impl<S: StableMemoryBorrower> RegistryClient for CanisterRegistryReplicator<S> {
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

        let search_key = StorableRegistryKey::new(key.to_string(), version);

        let result = S::with_borrow(|local_registry| {
            local_registry
                .range(..=search_key)
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

        let first_matching_key = StorableRegistryKey {
            key: key_prefix.to_string(),
            ..Default::default()
        };

        let results = S::with_borrow(|local_registry| {
            let records_history = local_registry
                .range(first_matching_key..)
                .filter(|(storable_key, _)| storable_key.version <= version)
                .take_while(|(storable_key, _)| storable_key.key.starts_with(key_prefix));

            let mut effective_records = BTreeMap::new();

            for (stored_key, value) in records_history {
                effective_records.insert(stored_key.key, value.0);
            }

            effective_records
                .into_iter()
                .filter_map(|(key, value)| value.is_some().then_some(key))
                .collect()
        });

        Ok(results)
    }

    fn get_latest_version(&self) -> RegistryVersion {
        S::with_borrow(|local_registry| {
            local_registry
                .keys()
                .map(|k| k.version)
                .max()
                .unwrap_or(ZERO_REGISTRY_VERSION)
        })
    }

    fn get_version_timestamp(&self, _registry_version: RegistryVersion) -> Option<Time> {
        // Just used in cached version of the registry client
        None
    }
}
