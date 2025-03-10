use candid::Principal;
use ic_interfaces_registry::{
    RegistryDataProvider, RegistryTransportRecord, ZERO_REGISTRY_VERSION,
};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_registry_transport::pb::v1::RegistryDelta;
use ic_registry_transport::{
    deserialize_get_changes_since_response, serialize_get_changes_since_request,
};
use ic_stable_structures::memory_manager::VirtualMemory;
use ic_stable_structures::storable::Bound;
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, Storable};
use ic_types::registry::RegistryDataProviderError;
use ic_types::RegistryVersion;
use itertools::Itertools;
use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::marker::PhantomData;

pub struct StorableRegistryValue(Option<Vec<u8>>);

impl Storable for StorableRegistryValue {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self(Option::from_bytes(bytes))
    }

    const BOUND: Bound = Bound::Unbounded;
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Default)]
pub struct StorableRegistryKey {
    version: u64,
    key: String,
}

// This value is set as 2 times the max key size present in the registry
const MAX_REGISTRY_KEY_SIZE: u32 = 200;

impl Storable for StorableRegistryKey {
    fn to_bytes(&self) -> Cow<[u8]> {
        let mut storable_key = vec![];
        let version_b = self.version.to_be_bytes().to_vec();
        let key_b = self.key.as_bytes().to_vec();

        storable_key.extend_from_slice(&version_b);
        storable_key.extend_from_slice(&key_b);

        Cow::Owned(storable_key)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let bytes = bytes.as_ref();
        let (version_bytes, key_bytes) = bytes.split_at(8);
        let version = u64::from_be_bytes(version_bytes.try_into().expect("Invalid version bytes"));
        let key = String::from_utf8(key_bytes.to_vec()).expect("Invalid UTF-8 in key");

        Self { version, key }
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: MAX_REGISTRY_KEY_SIZE + size_of::<u64>() as u32,
        is_fixed_size: false,
    };
}

type VM = VirtualMemory<DefaultMemoryImpl>;

pub trait StableMemoryBorrower: Send + Sync {
    fn with_borrow<R>(
        f: impl FnOnce(&StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>) -> R,
    ) -> R;
    fn with_borrow_mut<R>(
        f: impl FnOnce(&mut StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>) -> R,
    ) -> R;
}

/// This registry data provider is designed to work with the `ic-registry-canister-client`
/// in canisters, enabling the retrieval and storage of a registry copy in stable memory.
///
/// - If `keys_to_keep` is `Some(keys)`, only the specified `keys` will be stored in stable memory,
///   while all other keys from the registry will be discarded.
/// - If `keys_to_keep` is `None`, all keys from the registry will be retained in stable memory.
pub struct CanisterDataProvider<S: StableMemoryBorrower> {
    keys_to_keep: Option<HashSet<String>>,
    _store: PhantomData<S>,
}

impl<S: StableMemoryBorrower> CanisterDataProvider<S> {
    pub fn new(keys_to_retain: Option<HashSet<String>>) -> Self {
        Self {
            keys_to_keep: keys_to_retain,
            _store: PhantomData,
        }
    }

    async fn get_registry_changes_since(&self, version: u64) -> Result<Vec<RegistryDelta>, String> {
        let buff = serialize_get_changes_since_request(version).map_err(|e| format!("{:?}", e))?;
        let response = ic_cdk::api::call::call_raw(
            Principal::from(REGISTRY_CANISTER_ID),
            "get_changes_since",
            buff,
            0,
        )
        .await
        .map_err(|(code, msg)| (code as i32, msg))
        .unwrap();
        let (registry_delta, _) =
            deserialize_get_changes_since_response(response).map_err(|e| format!("{:?}", e))?;
        Ok(registry_delta)
    }

    fn get_latest_version(&self) -> Option<u64> {
        S::with_borrow(|local_registry| local_registry.last_key_value().map(|(k, _)| k.version))
    }

    fn add_deltas(&self, deltas: Vec<RegistryDelta>) -> Result<(), String> {
        for delta in deltas {
            let string_key = std::str::from_utf8(&delta.key[..])
                .map_err(|_| format!("Failed to convert key {:?} to string", delta.key))?;

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
                            version: value.version,
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

    // This function can be called in a timer to periodically update the registry stored
    pub async fn sync_registry_stored(&self) -> Result<(), String> {
        let mut update_registry_version = self
            .get_latest_version()
            .unwrap_or(ZERO_REGISTRY_VERSION.get());

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

impl<S: StableMemoryBorrower> RegistryDataProvider for CanisterDataProvider<S> {
    fn get_updates_since(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<RegistryTransportRecord>, RegistryDataProviderError> {
        S::with_borrow(|local_registry| {
            let start_key = StorableRegistryKey {
                version: version.get(),
                ..Default::default()
            };

            let from_start_key = local_registry
                .range(start_key..)
                .map(|(storable_key, value)| RegistryTransportRecord {
                    version: RegistryVersion::from(storable_key.version),
                    key: storable_key.key,
                    value: value.0,
                })
                .collect_vec();

            Ok(from_start_key)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_provider::{
        CanisterDataProvider, StableMemoryBorrower, StorableRegistryKey, StorableRegistryValue,
    };
    use ic_registry_transport::pb::v1::RegistryDelta;
    use ic_stable_structures::memory_manager::MemoryId;
    use ic_stable_structures::memory_manager::MemoryManager;
    use ic_stable_structures::StableBTreeMap;
    use std::cell::RefCell;
    use std::collections::HashSet;

    type VM = VirtualMemory<DefaultMemoryImpl>;

    thread_local! {
        static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
            RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

        static DUMMY_REGISTRY: RefCell<StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VirtualMemory<DefaultMemoryImpl>>>  =
        RefCell::new(StableBTreeMap::init(
                MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0)))
        ));

    }

    #[derive(Default)]
    pub struct DummyStore;
    impl StableMemoryBorrower for DummyStore {
        fn with_borrow<R>(
            f: impl FnOnce(&StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>) -> R,
        ) -> R {
            DUMMY_REGISTRY.with_borrow(|registry_stored| f(registry_stored))
        }

        fn with_borrow_mut<R>(
            f: impl FnOnce(&mut StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>) -> R,
        ) -> R {
            DUMMY_REGISTRY.with_borrow_mut(|registry_stored| f(registry_stored))
        }
    }

    fn generate_deltas(num: usize) -> Vec<RegistryDelta> {
        (1..=num)
            .map(|i| RegistryDelta {
                key: format!("test_key{}", i).into_bytes(),
                values: vec![ic_registry_transport::pb::v1::RegistryValue {
                    version: i as u64,
                    value: format!("value{}", i).into_bytes(),
                    deletion_marker: false,
                }],
            })
            .collect()
    }

    #[test]
    fn test_add_deltas_correctly() {
        let provider = CanisterDataProvider::<DummyStore>::new(None);
        let deltas = generate_deltas(10);

        provider.add_deltas(deltas).unwrap();
        let len = DUMMY_REGISTRY.with_borrow(|registry_stored| registry_stored.len());

        assert_eq!(len, 10);
        // Test `get_updates_since`
        let updates_since = provider
            .get_updates_since(RegistryVersion::from(5))
            .unwrap();

        // Verify that only updates with version >= 5 are returned
        assert_eq!(updates_since.len(), 6); // 5 through 10

        for (i, update) in updates_since.iter().enumerate() {
            let expected_version = (5 + i) as u64;

            assert_eq!(update.version.get(), expected_version);
            assert_eq!(update.key, format!("test_key{}", expected_version));
            assert_eq!(
                update.value,
                Some(format!("value{}", expected_version).into_bytes())
            );
        }
    }

    #[test]
    fn test_add_deltas_with_keys_to_retain() {
        let keys_to_retain = HashSet::from(["test_key1".to_string(), "test_key3".to_string()]);
        let provider = CanisterDataProvider::<DummyStore>::new(Some(keys_to_retain));
        let deltas = self::generate_deltas(5);

        provider.add_deltas(deltas).unwrap();

        let updates_since = provider
            .get_updates_since(RegistryVersion::from(0))
            .unwrap();

        assert_eq!(updates_since.len(), 2);
        assert_eq!(updates_since[0].version.get(), 1);
        assert_eq!(updates_since[0].key.as_str(), "test_key1");
        assert_eq!(
            updates_since[0].value,
            Some("value1".to_string().into_bytes())
        );

        assert_eq!(updates_since[1].version.get(), 3);
        assert_eq!(updates_since[1].key.as_str(), "test_key3");
        assert_eq!(
            updates_since[1].value,
            Some("value3".to_string().into_bytes())
        );

        let updates_since = provider
            .get_updates_since(RegistryVersion::from(2))
            .unwrap();

        assert_eq!(updates_since[0].version.get(), 3);
        assert_eq!(updates_since[0].key.as_str(), "test_key3");
        assert_eq!(
            updates_since[0].value,
            Some("value3".to_string().into_bytes())
        );
    }
}
