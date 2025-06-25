use ic_stable_structures::memory_manager::VirtualMemory;
use ic_stable_structures::storable::Bound;
use ic_stable_structures::{BTreeMap as StableBTreeMap, DefaultMemoryImpl, Storable};
use std::borrow::Cow;

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

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Default)]
pub struct StorableRegistryKey {
    pub key: String,
    pub version: u64,
}

impl StorableRegistryKey {
    pub fn new(key: String, version: u64) -> Self {
        Self { key, version }
    }
}

// This value is set as 2 times the max key size present in the registry
const MAX_REGISTRY_KEY_SIZE: u32 = 200;

impl Storable for StorableRegistryKey {
    fn to_bytes(&self) -> Cow<[u8]> {
        let mut storable_key = vec![];
        let key_b = self.key.as_bytes().to_vec();
        let version_b = self.version.to_be_bytes().to_vec();

        storable_key.extend_from_slice(&key_b);
        storable_key.extend_from_slice(&version_b);

        Cow::Owned(storable_key)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let bytes = bytes.as_ref();
        let len = bytes.len();
        let (key_bytes, version_bytes) = bytes.split_at(len - 8);

        let key = String::from_utf8(key_bytes.to_vec()).expect("Invalid UTF-8 in key");
        let version = u64::from_be_bytes(version_bytes.try_into().expect("Invalid version bytes"));

        Self { key, version }
    }
    const BOUND: Bound = Bound::Bounded {
        max_size: MAX_REGISTRY_KEY_SIZE + size_of::<u64>() as u32,
        is_fixed_size: false,
    };
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Default)]
pub struct TimestampKey(pub u64);

impl Storable for TimestampKey {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.0.to_be_bytes().to_vec())
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self(u64::from_be_bytes(
            bytes.try_into().expect("Invalid version bytes"),
        ))
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: size_of::<u64>() as u32,
        is_fixed_size: false,
    };
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Default)]
pub struct RegistryVersionsValue(pub Vec<u64>);

impl Storable for RegistryVersionsValue {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let versions_b: Vec<u8> = self.0.iter().flat_map(|x| x.to_be_bytes()).collect();
        Cow::Owned(versions_b)
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        let mut versions = Vec::new();
        for chunk in bytes.chunks_exact(8) {
            let arr: [u8; 8] = chunk.try_into().expect("Invalid version bytes");
            versions.push(u64::from_be_bytes(arr));
        }

        Self(versions)
    }

    const BOUND: Bound = Bound::Unbounded;
}

type VM = VirtualMemory<DefaultMemoryImpl>;

pub trait RegistryDataStableMemory: Send + Sync {
    fn with_registry_map<R>(
        f: impl FnOnce(&StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>) -> R,
    ) -> R;

    fn with_registry_map_mut<R>(
        f: impl FnOnce(&mut StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>) -> R,
    ) -> R;

    fn with_timestamp_to_registry_versions_map<R>(
        f: impl FnOnce(&StableBTreeMap<TimestampKey, RegistryVersionsValue, VM>) -> R,
    ) -> R;

    fn with_timestamp_to_registry_versions_map_mut<R>(
        f: impl FnOnce(&mut StableBTreeMap<TimestampKey, RegistryVersionsValue, VM>) -> R,
    ) -> R;
}

/// Usage: test_stable_memory_thread_local!(DummyState, &LOCAL_KEY_BTREE_MAP);
///
/// Example:
///
/// thread_local! {
///     static LOCAL_KEY_BTREE_MAP: RefCell<StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>> = RefCell::new({
///         let mgr = MemoryManager::init(DefaultMemoryImpl::default());
///         StableBTreeMap::init(mgr.get(MemoryId::new(0)))
///     });
/// }
///
///  test_registry_data_stable_memory_impl!(TestState, LOCAL_KEY_BTREE_MAP);
///
/// That will produce an empty struct with RegistryDataStableMemory implemented for the
/// LOCAL_KEY_BTREE_MAP.
/// This is useful for testing, but it's recommended to implement more explicitly in production
/// code.
#[macro_export]
macro_rules! test_registry_data_stable_memory_impl {
    ($state_struct:ident, $local_key_btree_map:expr) => {

        struct $state_struct;

        impl RegistryDataStableMemory for $state_struct {
            fn with_registry_map<R>(
                f: impl FnOnce(&StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>) -> R,
            ) -> R {
                $local_key_btree_map.with_borrow(f)
            }

            fn with_registry_map_mut<R>(
                f: impl FnOnce(&mut StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>) -> R,
            ) -> R {
                $local_key_btree_map.with_borrow_mut(f)
            }
        }
    };
}
