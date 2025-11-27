use super::*;
use crate::stable_memory::{StorableRegistryKey, StorableRegistryValue};
use crate::test_registry_data_stable_memory_impl;
use futures::FutureExt;
use ic_nervous_system_canisters::registry::fake::FakeRegistry;
use ic_registry_keys::NODE_RECORD_KEY_PREFIX;
use ic_registry_transport::pb::v1::{RegistryDelta, RegistryValue};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use ic_types::PrincipalId;
use std::cell::RefCell;
use std::collections::HashSet;

pub type VM = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static STATE: RefCell<StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>> = RefCell::new({
        let mgr = MemoryManager::init(DefaultMemoryImpl::default());
        StableBTreeMap::init(mgr.get(MemoryId::new(0)))
    });
}

test_registry_data_stable_memory_impl!(DummyState, STATE);

pub fn add_record_helper(key: &str, version: u64, value: Option<u64>, timestamp_nanoseconds: u64) {
    STATE.with_borrow_mut(|map| {
        map.insert(
            StorableRegistryKey::new(key.to_string(), version, timestamp_nanoseconds),
            StorableRegistryValue(value.map(|v| vec![v as u8])),
        );
    });
}

const DELETED_KEY: &str = "\
    node_record_\
    2hkvg-f3qgx-b5zoa-nz4k4-7q5v2-fiohf-x7o45-v6hds-5gf6w-o6lf6-gae";

fn add_dummy_data() {
    let user42_key = format!(
        "{}{}",
        NODE_RECORD_KEY_PREFIX,
        PrincipalId::new_user_test_id(42),
    );
    add_record_helper(DELETED_KEY, 39662, Some(42), 1);
    add_record_helper(DELETED_KEY, 39663, None, 1);
    add_record_helper(DELETED_KEY, 39664, Some(42), 2);
    add_record_helper(DELETED_KEY, 39779, Some(42), 2);
    add_record_helper(&user42_key, 39779, Some(40), 2);
    add_record_helper(DELETED_KEY, 39801, None, 5);
    add_record_helper(&user42_key, 39972, Some(50), 6);
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

fn client_for_tests() -> (StableCanisterRegistryClient<DummyState>, Arc<FakeRegistry>) {
    let fake_registry = Arc::new(FakeRegistry::new());
    let client = StableCanisterRegistryClient::<DummyState>::new(fake_registry.clone());

    (client, fake_registry)
}

#[test]
fn test_absent_after_delete() {
    add_dummy_data();
    let (client, _) = client_for_tests();

    // Version before it was deleted, it should show up.
    let result = client.get_key_family(NODE_RECORD_KEY_PREFIX, RegistryVersion::new(39800));
    assert_eq!(
        result,
        Ok(vec![
            DELETED_KEY.to_string(),
            format!(
                "{}{}",
                NODE_RECORD_KEY_PREFIX,
                PrincipalId::new_user_test_id(42)
            )
        ])
    );

    let result = client.get_key_family(NODE_RECORD_KEY_PREFIX, RegistryVersion::new(39_972));
    // DELETED_KEY should not be present in result, only principal 42.
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
fn test_correctly_maps_timestamp_to_registry_versions() {
    add_dummy_data();
    let (client, _) = client_for_tests();

    let expected: BTreeMap<u64, HashSet<RegistryVersion>> = BTreeMap::from_iter(vec![
        (1, vec![v(39662), v(39663)]),
        (2, vec![v(39664), v(39779)]),
        (5, vec![v(39801)]),
        (6, vec![v(39972)]),
    ])
    .into_iter()
    .map(|(k, v)| (k, v.into_iter().collect()))
    .collect();
    let actual = client.timestamp_to_versions_map().clone();

    assert_eq!(actual, expected);
}

#[test]
fn empty_registry_should_report_zero_as_latest_version() {
    let (client, _) = client_for_tests();

    assert_eq!(client.get_latest_version(), ZERO_REGISTRY_VERSION);
}

#[test]
fn can_retrieve_entries_correctly() {
    let (client, _) = client_for_tests();

    let set = |key: &str, ver: u64| add_record_helper(key, ver, Some(ver), 0);
    let rem = |key: &str, ver: u64| add_record_helper(key, ver, None, 0);
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
            "get_versioned_value: key: {key}, version: {ver}, expected: {expected_value:?}, actual: {versioned_value:?}"
        );

        assert_eq!(
            get_value,
            Ok(expected_value.map(|expected| value(expected).test_value)),
            "get_value: key: {key}, version: {ver}, expected: {expected_value:?}, actual: {get_value:?}"
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
    test_getter_value_not_err("A", 2, Some(1));
    test_getter_value_not_err("A", 3, Some(3));
    test_getter_value_not_err("A", 4, Some(3));
    test_getter_value_not_err("A", 5, Some(3));
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

    let test_family_values =
        |key_prefix: &str, version: u64, exp_result: Vec<(String, Vec<u8>)>| {
            let actual_res = client
                .get_key_family_with_values(key_prefix, v(version))
                .unwrap();
            assert_eq!(actual_res.len(), actual_res.len());
            assert_eq!(actual_res, exp_result);
        };

    test_family_values(
        "B",
        6,
        vec![("B".to_string(), vec![6]), ("B3".to_string(), vec![5])],
    );
    test_family_values(
        "F",
        1,
        vec![
            ("F0_1".to_string(), vec![1]),
            ("FA_1".to_string(), vec![1]),
            ("FA_2".to_string(), vec![1]),
            ("FA_3".to_string(), vec![1]),
            ("FB_1".to_string(), vec![1]),
        ],
    );
    test_family_values(
        "FA_",
        3,
        vec![("FA_1".to_string(), vec![3]), ("FA_3".to_string(), vec![1])],
    );
}

#[test]
fn test_sync_registry_stored() {
    let (client, fake_registry) = client_for_tests();
    fake_registry.set_value_at_version_with_timestamp("Foo", 1, 1, Some(vec![1]));
    fake_registry.set_value_at_version_with_timestamp("Foo", 2, 1, Some(vec![2]));
    fake_registry.set_value_at_version_with_timestamp("Foo", 3, 2, Some(vec![3]));
    fake_registry.set_value_at_version_with_timestamp("Foo", 4, 2, Some(vec![4]));
    fake_registry.set_value_at_version_with_timestamp("Foo", 5, 3, None);
    fake_registry.set_value_at_version_with_timestamp("Bar", 5, 3, Some(vec![50]));

    let current_latest = client.get_latest_version();
    assert_eq!(current_latest, ZERO_REGISTRY_VERSION);

    client
        .sync_registry_stored()
        .now_or_never()
        .unwrap()
        .expect("TODO: panic message");

    let current_latest = client.get_latest_version();
    assert_eq!(current_latest, RegistryVersion::new(5));

    for version in 1..=4u8 {
        let value = client.get_value("Foo", v(version as u64)).unwrap().unwrap();
        assert_eq!(value, vec![version]);
    }

    assert!(client.get_value("Foo", v(5)).unwrap().is_none());

    assert_eq!(client.get_value("Bar", v(5)).unwrap().unwrap(), vec![50u8]);

    let expected_timestamp_to_registry_versions: BTreeMap<u64, HashSet<RegistryVersion>> =
        BTreeMap::from_iter(vec![
            (1, vec![v(1), v(2)]),
            (2, vec![v(3), v(4)]),
            (3, vec![v(5)]),
        ])
        .into_iter()
        .map(|(k, v)| (k, v.into_iter().collect()))
        .collect();
    let actual = client.timestamp_to_versions_map().clone();

    assert_eq!(expected_timestamp_to_registry_versions, actual);
}

#[test]
fn test_error_on_local_too_large() {
    let (client, fake_registry) = client_for_tests();
    // These values will cause the current_local version to be greater than 1
    fake_registry.set_value_at_version("Foo", 1, Some(vec![1]));
    fake_registry.set_value_at_version("Foo", 2, Some(vec![2]));

    // This gets called 2x, and we want to give 2 bad responses to it so we get the error.
    fake_registry.add_fake_response_for_get_latest_version(Ok(1));
    fake_registry.add_fake_response_for_get_latest_version(Ok(1));

    let current_latest = client.get_latest_version();
    assert_eq!(current_latest, ZERO_REGISTRY_VERSION);

    let error = client
        .sync_registry_stored()
        .now_or_never()
        .unwrap()
        .unwrap_err();

    // This can only happen if the Registry returns an invalid response, like in the test setup.
    assert_eq!(
        error,
        "Registry version local 2 > remote 1, this should never happen"
    );
}

#[test]
fn test_caching_behavior_of_get_latest_version() {
    let (client, _) = client_for_tests();

    let current_latest = client.get_latest_version();
    assert_eq!(current_latest, ZERO_REGISTRY_VERSION);

    client
        .add_deltas(vec![RegistryDelta {
            key: "Foo".as_bytes().to_vec(),
            values: vec![
                RegistryValue {
                    value: vec![1],
                    version: 1,
                    deletion_marker: false,
                    timestamp_nanoseconds: 0,
                },
                RegistryValue {
                    value: vec![2],
                    version: 2,
                    deletion_marker: false,
                    timestamp_nanoseconds: 0,
                },
            ],
        }])
        .expect("Couldn't add deltas");

    let current_latest = client.get_latest_version();
    assert_eq!(current_latest, RegistryVersion::new(2));

    // Now we reset the client so it has no cached version
    let (client, fake_registry) = client_for_tests();
    fake_registry.set_value_at_version("Foo", 4, Some(vec![4]));

    let cached_version = client.latest_version.load(AtomicOrdering::SeqCst);
    assert_eq!(cached_version, ZERO_REGISTRY_VERSION.get());

    let latest_version = client.get_latest_version();
    assert_eq!(latest_version, RegistryVersion::new(2));
    // Cache should now be updated.
    let cached_version = client.latest_version.load(AtomicOrdering::SeqCst);
    assert_eq!(cached_version, latest_version.get());

    // Add a random delta, cache should be updated
    client
        .add_deltas(vec![RegistryDelta {
            key: "Foo".as_bytes().to_vec(),
            values: vec![RegistryValue {
                value: vec![3],
                version: 3,
                deletion_marker: false,
                timestamp_nanoseconds: 0,
            }],
        }])
        .expect("Couldn't add deltas");

    // Cache is not updated (b/c we didn't run sync
    let current_latest = client.get_latest_version();
    assert_eq!(current_latest, RegistryVersion::new(3));

    client
        .sync_registry_stored()
        .now_or_never()
        .unwrap()
        .expect("syncing failed");

    // Cache is updated
    let current_latest = client.get_latest_version();
    assert_eq!(current_latest, RegistryVersion::new(4));
}
