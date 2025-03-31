use super::*;
use crate::stable_memory::{StorableRegistryKey, StorableRegistryValue};
use assert_matches::assert_matches;
use futures::FutureExt;
use ic_nervous_system_canisters::registry::{FakeRegistry, FakeRegistryResponses};
use ic_registry_keys::NODE_RECORD_KEY_PREFIX;
use ic_registry_transport::pb::v1::{RegistryDelta, RegistryValue};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use ic_types::PrincipalId;
use itertools::Itertools;
use std::cell::RefCell;
use std::collections::HashSet;

pub type VM = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static STATE: RefCell<StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>> = RefCell::new({
        let mgr = MemoryManager::init(DefaultMemoryImpl::default());
            StableBTreeMap::init(mgr.get(MemoryId::new(0)))
    });
}
struct DummyState;

impl RegistryDataStableMemory for DummyState {
    fn with_registry_map<R>(
        f: impl FnOnce(&StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>) -> R,
    ) -> R {
        STATE.with_borrow(f)
    }

    fn with_registry_map_mut<R>(
        f: impl FnOnce(&mut StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>) -> R,
    ) -> R {
        STATE.with_borrow_mut(f)
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

const DELETED_KEY: &str = "\
    node_record_\
    2hkvg-f3qgx-b5zoa-nz4k4-7q5v2-fiohf-x7o45-v6hds-5gf6w-o6lf6-gae";

fn add_dummy_data() {
    let user42_key = format!(
        "{}{}",
        NODE_RECORD_KEY_PREFIX,
        PrincipalId::new_user_test_id(42),
    );
    add_record_helper(DELETED_KEY, 39662, Some(42));
    add_record_helper(DELETED_KEY, 39663, None);
    add_record_helper(DELETED_KEY, 39664, Some(42));
    add_record_helper(DELETED_KEY, 39779, Some(42));
    add_record_helper(&user42_key, 39779, Some(40));
    add_record_helper(DELETED_KEY, 39801, None);
    add_record_helper(&user42_key, 39972, Some(50));
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

fn client_for_tests(
    latest_version: u64,
    responses: FakeRegistryResponses,
) -> StableCanisterRegistryClient<DummyState> {
    StableCanisterRegistryClient::<DummyState>::new(Box::new(FakeRegistry::new(
        RegistryVersion::new(latest_version),
        responses,
    )))
}

fn registry_value(version: u64, value: &[u8]) -> RegistryValue {
    RegistryValue {
        value: value.to_vec(),
        version,
        deletion_marker: value.is_empty(),
    }
}

fn registry_delta(key: &str, values: &[RegistryValue]) -> RegistryDelta {
    RegistryDelta {
        key: key.as_bytes().to_vec(),
        values: values.to_vec(),
    }
}

#[test]
fn test_absent_after_delete() {
    let client = client_for_tests(0, Default::default());
    add_dummy_data();

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
fn empty_registry_should_report_zero_as_latest_version() {
    let client = client_for_tests(0, Default::default());

    assert_eq!(client.get_latest_version(), ZERO_REGISTRY_VERSION);
}

#[test]
fn can_retrieve_entries_correctly() {
    let client = client_for_tests(0, Default::default());

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
}

#[test]
fn test_sync_registry_stored() {
    let mut responses = FakeRegistryResponses::new();
    responses.insert(
        0,
        Ok(vec![
            registry_delta(
                "Foo",
                &[
                    registry_value(1, &[1]),
                    registry_value(2, &[2]),
                    registry_value(3, &[3]),
                    registry_value(4, &[4]),
                    registry_value(5, &[]),
                ],
            ),
            registry_delta("Bar", &[registry_value(5, &[50])]),
        ]),
    );
    let client = client_for_tests(5, responses);

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
}

#[test]
fn test_error_on_local_too_large() {
    let mut responses = FakeRegistryResponses::new();
    responses.insert(
        0,
        Ok(vec![registry_delta(
            "Foo",
            &[registry_value(1, &[1]), registry_value(2, &[2])],
        )]),
    );
    let client = client_for_tests(1, responses);

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
    let mut responses = FakeRegistryResponses::new();
    responses.insert(
        2, // The version it will make the request about
        Ok(vec![registry_delta("Foo", &[registry_value(4, &[4])])]),
    );
    let client = client_for_tests(4, responses);

    let current_latest = client.get_latest_version();
    assert_eq!(current_latest, ZERO_REGISTRY_VERSION);

    client
        .add_deltas(vec![registry_delta(
            "Foo",
            &[registry_value(1, &[1]), registry_value(2, &[2])],
        )])
        .expect("Couldn't add deltas");

    let current_latest = client.get_latest_version();
    assert_eq!(current_latest, RegistryVersion::new(2));

    // This is not a code path that should be utilized in production but for testing
    // we are going around the sync so we can test the caching behavior
    client
        .add_deltas(vec![registry_delta("Foo", &[registry_value(3, &[3])])])
        .expect("Couldn't add deltas");

    // Cache is not updated (b/c we didn't run sync
    let current_latest = client.get_latest_version();
    assert_eq!(current_latest, RegistryVersion::new(2));

    client
        .sync_registry_stored()
        .now_or_never()
        .unwrap()
        .expect("syncing failed");

    // Cache is updated
    let current_latest = client.get_latest_version();
    assert_eq!(current_latest, RegistryVersion::new(4));
}

#[test]
fn test_get_values_between() {
    let client = client_for_tests(0, BTreeMap::new());

    // Add some deltas
    client
        .add_deltas(vec![
            registry_delta(
                "common_prefix_foo",
                &[
                    registry_value(0, &[1, 2, 3, 4]),
                    registry_value(1, &[4, 5, 6, 7]),
                    registry_value(10, &[4, 5, 6, 8]),
                    registry_value(15, &[]),
                ],
            ),
            registry_delta(
                "common_prefix_bar",
                &[
                    registry_value(4, &[1, 2, 3, 4]),
                    registry_value(6, &[2, 3, 4, 5]),
                ],
            ),
            registry_delta(
                "different_prefix_foo",
                &[
                    registry_value(3, &[1, 2, 3, 4]),
                    registry_value(6, &[2, 3, 4, 5]),
                ],
            ),
        ])
        .expect("Couldn't add deltas");

    let changes_between = client
        .get_effective_records_between(
            "common_prefix",
            RegistryVersion::new(1),
            RegistryVersion::new(15),
        )
        .unwrap();

    assert_eq!(changes_between.len(), 5);

    let values_for_foo = changes_between
        .into_iter()
        .filter(|record| record.key == "common_prefix_foo")
        .collect_vec();

    assert_eq!(values_for_foo.len(), 3);

    let last = values_for_foo.last().unwrap();

    assert_eq!(last.version.get(), 15);
    assert_eq!(last.value, None);
}

#[test]
fn test_get_values_between_invalid_lower_bound() {
    let client = client_for_tests(0, BTreeMap::new());

    let err = client
        .get_effective_records_between(
            "common_prefix",
            RegistryVersion::new(10),
            RegistryVersion::new(15),
        )
        .err()
        .expect("Should have been an 'Invalid version' error");

    assert_matches!(
        err,
        RegistryClientError::VersionNotAvailable { version } if version.get() == 10
    )
}

#[test]
fn test_get_values_between_invalid_upper_bound() {
    let client = client_for_tests(0, BTreeMap::new());

    client
        .add_deltas(vec![registry_delta(
            "common_prefix_foo",
            &[registry_value(12, &[1, 2, 3, 4])],
        )])
        .unwrap();

    let err = client
        .get_effective_records_between(
            "common_prefix",
            RegistryVersion::new(10),
            RegistryVersion::new(15),
        )
        .err()
        .expect("Should have been an 'Invalid version' error");

    assert_matches!(
        err,
        RegistryClientError::VersionNotAvailable { version } if version.get() == 15
    )
}

#[test]
fn test_get_values_between_allow_invalid_range() {
    let client = client_for_tests(0, BTreeMap::new());

    client
        .add_deltas(vec![registry_delta(
            "common_prefix_foo",
            &[registry_value(12, &[1, 2, 3, 4])],
        )])
        .unwrap();

    let range = client
        .get_effective_records_between(
            "common_prefix",
            RegistryVersion::new(10),
            RegistryVersion::new(5),
        )
        .unwrap();

    assert!(range.is_empty())
}

// This usecase tests the following scenario
//            A    B
//
// +-----*----#----#-----+
//
//       x    y    z
//
// Since the period [A-B] perfectly
// aligns with the versions `y` and
// `z`, there are no effective versions
// for [A-B] before `z`, meaning that
// `x` shouldn't be in the scope
#[test]
fn test_get_effective_values_between_has_no_effective_versions_outside_requested_range() {
    let client = client_for_tests(0, BTreeMap::new());

    client
        .add_deltas(vec![registry_delta(
            "foo",
            &[
                registry_value(5, &[0, 1, 2, 3]),
                registry_value(10, &[1, 2, 3, 4]),
                registry_value(15, &[1, 2, 3, 4]),
            ],
        )])
        .unwrap();

    let range = client
        .get_effective_records_between("foo", RegistryVersion::new(10), RegistryVersion::new(15))
        .unwrap();

    assert_eq!(range.len(), 2);

    let mut range_iter = range.iter();
    let first = range_iter.next().unwrap();
    assert_eq!(first.version.get(), 10);

    let second = range_iter.next().unwrap();
    assert_eq!(second.version.get(), 15);
}

// This usecase tests the following scenario
//         A       B
//
// +-----*-|--*----#-----+
//
//       x    y    z
//
// In the range [A, B] we have changes
// `y` and `z` but since `y` happened
// after `A` we have to account for the
// version `x` which was effective from
// A-y period
#[test]
fn test_get_effective_values_between_has_effective_versions_outside_requested_range() {
    let client = client_for_tests(0, BTreeMap::new());

    client
        .add_deltas(vec![registry_delta(
            "foo",
            &[
                registry_value(5, &[0, 1, 2, 3]),
                registry_value(10, &[1, 2, 3, 4]),
                registry_value(15, &[1, 2, 3, 4]),
            ],
        )])
        .unwrap();

    let range = client
        .get_effective_records_between("foo", RegistryVersion::new(7), RegistryVersion::new(15))
        .unwrap();

    assert_eq!(range.len(), 3);

    let mut range_iter = range.iter();
    let first = range_iter.next().unwrap();
    assert_eq!(first.version.get(), 5);

    let second = range_iter.next().unwrap();
    assert_eq!(second.version.get(), 10);

    let third = range_iter.next().unwrap();
    assert_eq!(third.version.get(), 15)
}

// This usecase tests the following scenario
//             A B
//
// +-----*----*|-|-*-----+
//
//       x    y    z
// There are no changes to key "foo" in the
// range [A, B] but so the effective version
// comes from before, which is version `y`
#[test]
fn test_get_effective_values_between_no_effective_values_inside_range_only_before() {
    let client = client_for_tests(0, BTreeMap::new());

    client
        .add_deltas(vec![registry_delta(
            "foo",
            &[
                registry_value(5, &[0, 1, 2, 3]),
                registry_value(10, &[1, 2, 3, 4]),
                registry_value(15, &[1, 2, 3, 4]),
            ],
        )])
        .unwrap();

    let range = client
        .get_effective_records_between("foo", RegistryVersion::new(11), RegistryVersion::new(13))
        .unwrap();

    assert_eq!(range.len(), 1);

    let mut range_iter = range.iter();
    let first = range_iter.next().unwrap();
    assert_eq!(first.version.get(), 10);
}

// This usecase tests the following scenario
//   A  B
//
// +-|--|*----*----*-----+
//
//       x    y    z
//
// Since the first occurence of the key "foo" is
// present on version higher than `upper_bound`
// there are no effective versions of this
// key.
#[test]
fn test_get_effective_values_between_values_after_upper_bound() {
    let client = client_for_tests(0, BTreeMap::new());

    client
        .add_deltas(vec![registry_delta(
            "foo",
            &[
                registry_value(5, &[0, 1, 2, 3]),
                registry_value(10, &[1, 2, 3, 4]),
                registry_value(15, &[1, 2, 3, 4]),
            ],
        )])
        .unwrap();

    let range = client
        .get_effective_records_between("foo", RegistryVersion::new(1), RegistryVersion::new(4))
        .unwrap();

    assert!(range.is_empty());
}

#[test]
fn test_get_effective_values_between_multiple_keys() {
    let client = client_for_tests(0, BTreeMap::new());

    client
        .add_deltas(vec![
            registry_delta(
                "common_prefix_foo",
                &[
                    registry_value(5, &[0, 1, 2, 3]),
                    registry_value(10, &[1, 2, 3, 4]),
                    registry_value(15, &[1, 2, 3, 4]),
                ],
            ),
            registry_delta(
                "common_prefix_bar",
                &[
                    registry_value(3, &[0, 1, 2, 3]),
                    registry_value(8, &[1, 2, 3, 4]),
                    registry_value(10, &[1, 2, 3, 4]),
                    registry_value(18, &[1, 2, 3, 4]),
                ],
            ),
            registry_delta(
                "common_prefix_baz",
                &[
                    registry_value(14, &[0, 1, 2, 3]),
                    registry_value(19, &[1, 2, 3, 4]),
                    registry_value(22, &[1, 2, 3, 4]),
                    registry_value(25, &[1, 2, 3, 4]),
                ],
            ),
        ])
        .unwrap();

    let range = client
        .get_effective_records_between(
            "common_prefix",
            RegistryVersion::new(8),
            RegistryVersion::new(20),
        )
        .unwrap();

    assert_eq!(range.len(), 8);

    let all_foo = range
        .iter()
        .filter(|record| record.key == "common_prefix_foo")
        .collect_vec();
    assert_eq!(all_foo.len(), 3);
    let foo_first = all_foo.first().unwrap();
    assert_eq!(foo_first.version.get(), 5);
    let foo_last = all_foo.last().unwrap();
    assert_eq!(foo_last.version.get(), 15);

    let all_bar = range
        .iter()
        .filter(|record| record.key == "common_prefix_bar")
        .collect_vec();
    assert_eq!(all_bar.len(), 3);
    let first_bar = all_bar.first().unwrap();
    assert_eq!(first_bar.version.get(), 8);
    let last_bar = all_bar.last().unwrap();
    assert_eq!(last_bar.version.get(), 18);

    let all_baz = range
        .iter()
        .filter(|record| record.key == "common_prefix_baz")
        .collect_vec();
    assert_eq!(all_baz.len(), 2);
    let first_baz = all_baz.first().unwrap();
    assert_eq!(first_baz.version.get(), 14);
    let last_baz = all_baz.last().unwrap();
    assert_eq!(last_baz.version.get(), 19);
}
