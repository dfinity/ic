use super::*;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager};
use std::cell::RefCell;

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
        f: impl FnOnce(&StableBTreeMap<StorableRegistryKey, StorableRegistryValue, Memory>) -> R,
    ) -> R {
        DUMMY_REGISTRY.with_borrow(|registry_stored| f(registry_stored))
    }

    fn with_borrow_mut<R>(
        f: impl FnOnce(&mut StableBTreeMap<StorableRegistryKey, StorableRegistryValue, Memory>) -> R,
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
