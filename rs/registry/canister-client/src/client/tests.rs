use super::*;
use crate::stable_memory::{StorableRegistryKey, StorableRegistryValue};
use ic_interfaces_registry::RegistryVersionedRecord;
use ic_registry_keys::NODE_RECORD_KEY_PREFIX;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use ic_types::{registry::RegistryDataProviderError, PrincipalId};
use std::cell::RefCell;
use std::collections::HashSet;

const DELETED_KEY: &str = "\
    node_record_\
    2hkvg-f3qgx-b5zoa-nz4k4-7q5v2-fiohf-x7o45-v6hds-5gf6w-o6lf6-gae";

struct DummyRegistryDataProvider {
    data: Arc<RwLock<Vec<RegistryTransportRecord>>>,
}

pub type VM = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static STATE: RefCell<StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>> = RefCell::new({
        let mgr = MemoryManager::init(DefaultMemoryImpl::default());
            StableBTreeMap::init(mgr.get(MemoryId::new(0)))
    });
}
struct DummyState;

impl RegistryStoreStableMemory for DummyState {
    fn with_registry_map<R>(
        f: impl FnOnce(&StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>) -> R,
    ) -> R {
        STATE.with_borrow(|state| f(&state))
    }

    fn with_registry_map_mut<R>(
        f: impl FnOnce(&mut StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>) -> R,
    ) -> R {
        STATE.with_borrow_mut(|state| f(state))
    }
}

pub fn add_record_helper(key: &str, version: u64, value: Option<u64>) {
    STATE.with_borrow_mut(|map| {
        map.insert(
            StorableRegistryKey::new(key.to_string(), version),
            StorableRegistryValue(value.map(|v| vec![v as u8])),
        );
    });
}

fn add_dummy_data() {
    add_record_helper(DELETED_KEY, 39662, Some(42));
    add_record_helper(DELETED_KEY, 39663, None);
    add_record_helper(DELETED_KEY, 39664, Some(42));
    add_record_helper(DELETED_KEY, 39779, Some(42));
    add_record_helper(DELETED_KEY, 39801, None);
    add_record_helper(
        &format!(
            "{}{}",
            NODE_RECORD_KEY_PREFIX,
            PrincipalId::new_user_test_id(42),
        ),
        39_972,
        Some(50),
    );
}

#[derive(PartialEq, Eq, Debug)]
struct TestValue {
    test_value: Vec<u8>,
}

fn value(value: u64) -> TestValue {
    TestValue {
        test_value: vec![value as u8],
    }
}

fn v(v: u64) -> RegistryVersion {
    RegistryVersion::new(v)
}

#[test]
fn test_absent_after_delete() {
    let client = CanisterRegistryStore::<DummyState>::new();
    add_dummy_data();

    let result = client.get_key_family(NODE_RECORD_KEY_PREFIX, RegistryVersion::new(39_972));

    assert_eq!(
        result,
        Ok(vec![format!(
            "{}{}",
            NODE_RECORD_KEY_PREFIX,
            PrincipalId::new_user_test_id(42)
        )]),
    );
}

#[test]
fn empty_registry_should_report_zero_as_latest_version() {
    let client = CanisterRegistryStore::<DummyState>::new();

    assert_eq!(client.get_latest_version(), ZERO_REGISTRY_VERSION);
}

#[test]
fn can_retrieve_entries_correctly() {
    let client = CanisterRegistryStore::<DummyState>::new();

    let set = |key: &str, ver: u64| add_record_helper(key, ver, Some(ver));
    let rem = |key: &str, ver: u64| add_record_helper(key, ver, None);
    let get_versioned = |key: &str, ver: u64| -> RegistryClientVersionedResult<Vec<u8>> {
        client.get_versioned_value(key, v(ver))
    };
    let get = |key: &str, ver: u64| client.get_value(key, v(ver));
    let family = |key_prefix: &str, t: u64| client.get_key_family(key_prefix, v(t));

    let test_getter_value_not_err = |key: &str, ver: u64, expected_value: Option<u64>| {
        let get_value = get(key, ver);
        let versioned = get_versioned(key, ver).unwrap();
        assert_eq!(
            versioned.version,
            v(ver),
            "get_versioned_value version did not match: \
                key: {}, expected_ver: {}, actual_ver: {}",
            key,
            ver,
            versioned.version
        );
        assert_eq!(versioned.key, key.to_string());
        let versioned_value = versioned.value;
        assert_eq!(
            versioned_value,
            expected_value.map(|expected| value(expected).test_value),
            "get_versioned_value: key: {}, version: {}, expected: {:?}, actual: {:?}",
            key,
            ver,
            expected_value,
            versioned_value
        );

        assert_eq!(
            get_value,
            Ok(expected_value.map(|expected| value(expected).test_value)),
            "get_value: key: {}, version: {}, expected: {:?}, actual: {:?}",
            key,
            ver,
            expected_value,
            get_value
        );
    };

    set("A", 1);
    set("A", 3);
    set("A", 6);
    set("B", 6);
    set("B2", 4);
    set("B2", 5);
    rem("B2", 6);
    set("B3", 5);
    set("C", 6);

    set("F0_1", 1);
    for v in (1..8).step_by(2) {
        set("FA_1", v);
        rem("FA_1", v + 1);
    }
    for v in (1..8).step_by(4) {
        set("FA_2", v);
        set("FA_2", v + 1);
        rem("FA_2", v + 2);
    }
    set("FA_3", 1);
    rem("FA_3", 5);
    for v in 1..=8 {
        set("FB_1", v);
    }

    let latest_version = 8;
    assert_eq!(client.get_latest_version(), v(latest_version));

    test_getter_value_not_err("A", 0, None);
    test_getter_value_not_err("A", 1, Some(1));
    // assert_eq!(get_versioned("A", 2).unwrap().as_ref().unwrap(), &value(1));
    test_getter_value_not_err("A", 2, Some(1));
    // assert_eq!(get_versioned("A", 3).unwrap().as_ref().unwrap(), &value(3));
    test_getter_value_not_err("A", 3, Some(3));
    // assert_eq!(get_versioned("A", 4).unwrap().as_ref().unwrap(), &value(3));
    test_getter_value_not_err("A", 4, Some(3));
    // assert_eq!(get_versioned("A", 5).unwrap().as_ref().unwrap(), &value(3));
    test_getter_value_not_err("A", 5, Some(3));
    // assert_eq!(get_versioned("A", 6).unwrap().as_ref().unwrap(), &value(6));
    test_getter_value_not_err("A", 6, Some(6));
    assert!(get_versioned("A", latest_version + 1).is_err());
    assert!(get("A", latest_version + 1).is_err());

    for t in 0..6 {
        assert!(get_versioned("B", t).unwrap().is_none());
    }
    test_getter_value_not_err("B", 6, Some(6));
    assert!(get_versioned("B", latest_version + 1).is_err());

    for t in 0..4 {
        assert!(get_versioned("B2", t).unwrap().is_none());
    }
    test_getter_value_not_err("B2", 4, Some(4));
    test_getter_value_not_err("B2", 5, Some(5));
    test_getter_value_not_err("B2", 6, None);
    assert!(get_versioned("B2", latest_version + 1).is_err());

    let test_family = |key_prefix: &str, version: u64, exp_result: &[&str]| {
        let actual_res = family(key_prefix, version).unwrap();
        let actual_set = actual_res
            .iter()
            .map(ToString::to_string)
            .collect::<HashSet<_>>();
        assert_eq!(actual_res.len(), actual_set.len());
        assert_eq!(
            actual_set,
            exp_result
                .iter()
                .map(ToString::to_string)
                .collect::<HashSet<_>>()
        );
    };

    test_family("B", 6, &["B", "B3"]);
    test_family("F", 1, &["F0_1", "FA_1", "FA_2", "FA_3", "FB_1"]);
    test_family("FA_", 1, &["FA_1", "FA_2", "FA_3"]);
    test_family("FA_", 2, &["FA_2", "FA_3"]);
    test_family("FA_", 3, &["FA_1", "FA_3"]);
    test_family("FA_", 4, &["FA_3"]);
    test_family("FA_", 5, &["FA_1", "FA_2"]);
    test_family("FA_", 6, &["FA_2"]);
    test_family("FA_", 7, &["FA_1"]);
    test_family("FA_", 8, &[]);
}

#[test]
fn test_sync_registry_stored() {}
