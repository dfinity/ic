use std::collections::HashSet;

use super::*;
use ic_interfaces_registry::RegistryVersionedRecord;
use ic_registry_keys::NODE_RECORD_KEY_PREFIX;
use ic_types::{registry::RegistryDataProviderError, PrincipalId};

const DELETED_KEY: &str = "\
    node_record_\
    2hkvg-f3qgx-b5zoa-nz4k4-7q5v2-fiohf-x7o45-v6hds-5gf6w-o6lf6-gae";

struct DummyRegistryDataProvider {
    data: Arc<RwLock<Vec<RegistryTransportRecord>>>,
}

impl DummyRegistryDataProvider {
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(vec![])),
        }
    }

    pub fn add_dummy_data(&self) {
        let mut data_mut = self.data.write().unwrap();
        *data_mut = vec![
            RegistryVersionedRecord {
                key: DELETED_KEY.to_string(),
                version: RegistryVersion::new(39662),
                value: Some(vec![42]),
            },
            RegistryVersionedRecord {
                key: DELETED_KEY.to_string(),
                version: RegistryVersion::new(39663),
                value: None,
            },
            RegistryVersionedRecord {
                key: DELETED_KEY.to_string(),
                version: RegistryVersion::new(39664),
                value: Some(vec![42]),
            },
            RegistryVersionedRecord {
                key: DELETED_KEY.to_string(),
                version: RegistryVersion::new(39779),
                value: Some(vec![42]),
            },
            RegistryVersionedRecord {
                key: DELETED_KEY.to_string(),
                version: RegistryVersion::new(39801),
                value: None,
            },
            // Just so that the result set is not empty.
            RegistryVersionedRecord {
                key: format!(
                    "{}{}",
                    NODE_RECORD_KEY_PREFIX,
                    PrincipalId::new_user_test_id(42),
                ),
                version: RegistryVersion::new(39_972),
                value: Some(vec![0xCA, 0xFE]),
            },
        ];
    }

    pub fn add(&self, key: &str, version: u64, value: Option<u64>) {
        let mut data_mut = self.data.write().unwrap();

        data_mut.push(RegistryVersionedRecord {
            key: key.to_string(),
            version: RegistryVersion::new(version),
            value: value.map(|v| vec![v as u8]),
        });
    }
}

impl RegistryDataProvider for DummyRegistryDataProvider {
    fn get_updates_since(
        &self,
        registry_version: RegistryVersion,
    ) -> Result<Vec<RegistryTransportRecord>, RegistryDataProviderError> {
        let records = self.data.read().unwrap();

        let records = records
            .iter()
            .filter(|r| r.version > registry_version)
            .map(|r| RegistryTransportRecord {
                key: r.key.clone(),
                version: r.version,
                value: r.value.to_owned(),
            })
            .collect();

        Ok(records)
    }
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
    let dummy_registry = Arc::new(DummyRegistryDataProvider::new());
    let client = CanisterRegistryClient::new(dummy_registry.clone());
    dummy_registry.add_dummy_data();
    client.update_to_latest_version();

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
    let client = CanisterRegistryClient::new(Arc::new(DummyRegistryDataProvider::new()));

    assert_eq!(client.get_latest_version(), ZERO_REGISTRY_VERSION);
}

#[test]
fn can_retrieve_entries_correctly() {
    let dummy_registry = Arc::new(DummyRegistryDataProvider::new());
    let client = CanisterRegistryClient::new(dummy_registry.clone());

    let set = |key: &str, ver: u64| dummy_registry.add(key, ver, Some(ver));
    let rem = |key: &str, ver: u64| dummy_registry.add(key, ver, None);
    let get = |key: &str, ver: u64| {
        client
            .get_versioned_value(key, v(ver))
            .map(|ok_record| ok_record.map(|test_value| TestValue { test_value }))
    };
    let family = |key_prefix: &str, t: u64| client.get_key_family(key_prefix, v(t));

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

    client.update_to_latest_version();
    let latest_version = 8;
    assert_eq!(client.get_latest_version(), v(latest_version));

    assert!(get("A", 0).unwrap().is_none());
    assert_eq!(get("A", 1).unwrap().as_ref().unwrap(), &value(1));
    assert_eq!(get("A", 2).unwrap().as_ref().unwrap(), &value(1));
    assert_eq!(get("A", 3).unwrap().as_ref().unwrap(), &value(3));
    assert_eq!(get("A", 4).unwrap().as_ref().unwrap(), &value(3));
    assert_eq!(get("A", 5).unwrap().as_ref().unwrap(), &value(3));
    assert_eq!(get("A", 6).unwrap().as_ref().unwrap(), &value(6));
    assert!(get("A", latest_version + 1).is_err());

    for t in 0..6 {
        assert!(get("B", t).unwrap().is_none());
    }
    assert_eq!(get("B", 6).unwrap().as_ref().unwrap(), &value(6));
    assert!(get("B", latest_version + 1).is_err());

    for t in 0..4 {
        assert!(get("B2", t).unwrap().is_none());
    }
    assert_eq!(get("B2", 4).unwrap().as_ref().unwrap(), &value(4));
    assert_eq!(get("B2", 5).unwrap().as_ref().unwrap(), &value(5));
    assert!(get("B2", 6).unwrap().is_none());
    assert!(get("B2", latest_version + 1).is_err());

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
