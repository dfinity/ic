use super::*;
use assert_matches::assert_matches;
use ic_interfaces_registry::ZERO_REGISTRY_VERSION;
use ic_registry_client_helpers::test_proto::TestProtoHelper;
use ic_registry_common_proto::pb::test_protos::v1::TestProto;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[test]
fn empty_registry_should_report_zero_as_latest_version() {
    let data_provider = Arc::new(ProtoRegistryDataProvider::new());
    let registry = RegistryClientImpl::new(data_provider, None);

    // test whether the empty registry is actually empty
    assert_eq!(registry.get_latest_version(), ZERO_REGISTRY_VERSION);
}

#[test]
fn empty_registry_reports_none_for_zero_version() {
    let data_provider = Arc::new(ProtoRegistryDataProvider::new());
    let registry = RegistryClientImpl::new(data_provider, None);

    assert!(
        registry
            .get_test_proto("any_key", RegistryVersion::new(0))
            .unwrap()
            .is_none()
    );
}

#[test]
fn can_retrieve_entries_correctly() {
    // In this test, for a bunch of keys, we insert a number of records where the
    // test_value is equal to the version at which the record was inserted. For each
    // key, the test then runs through all versions in order up to
    // get_latest_version().
    let data_provider = Arc::new(ProtoRegistryDataProvider::new());
    let registry = RegistryClientImpl::new(data_provider.clone(), None);
    let get = |key: &str, t: u64| registry.get_test_proto(key, RegistryVersion::new(t));
    let family =
        |key_prefix: &str, t: u64| registry.get_key_family(key_prefix, RegistryVersion::new(t));
    let set = |key: &str, ver: u64| data_provider.add(key, v(ver), Some(value(ver))).unwrap();
    let rem = |key: &str, ver: u64| data_provider.add::<TestProto>(key, v(ver), None).unwrap();

    set("A", 1);
    set("A", 3);
    set("A", 6);
    set("B", 6);
    set("B2", 4);
    set("B2", 5);
    rem("B2", 6);
    set("B3", 5);
    set("C", 6);

    // test key families
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

    assert!(registry.get_test_proto("A", v(1)).is_err());

    // Poll the data_provider.
    registry.poll_once().unwrap();

    let latest_version = 8;
    assert_eq!(registry.get_latest_version(), v(latest_version));

    assert!(get("A", 0).unwrap().is_none());
    assert_eq!(get("A", 1).unwrap(), Some(value(1)));
    assert_eq!(get("A", 2).unwrap(), Some(value(1)));
    assert_eq!(get("A", 3).unwrap(), Some(value(3)));
    assert_eq!(get("A", 4).unwrap(), Some(value(3)));
    assert_eq!(get("A", 5).unwrap(), Some(value(3)));
    assert_eq!(get("A", 6).unwrap(), Some(value(6)));
    assert!(get("A", latest_version + 1).is_err());

    for t in 0..6 {
        assert!(get("B", t).unwrap().is_none());
    }
    assert_eq!(get("B", 6).unwrap(), Some(value(6)));
    assert!(get("B", latest_version + 1).is_err());

    for t in 0..4 {
        assert!(get("B2", t).unwrap().is_none());
    }
    assert_eq!(get("B2", 4).unwrap(), Some(value(4)));
    assert_eq!(get("B2", 5).unwrap(), Some(value(5)));
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

#[test]
fn can_poll_new_versions_from_data_provider() {
    let data_provider = Arc::new(ProtoRegistryDataProvider::new());
    let registry = RegistryClientImpl::new(data_provider.clone(), None);
    let get = |key: &str, t: u64| registry.get_test_proto(key, RegistryVersion::new(t));

    data_provider.add("A", v(1), Some(value(1))).unwrap();

    registry.poll_once().unwrap();
    assert_eq!(registry.get_latest_version(), v(1));
    assert!(get("A", 0).unwrap().is_none());
    assert_eq!(get("A", 1).unwrap(), Some(value(1)));
    assert!(get("B2", 1).unwrap().is_none());
    assert!(get("B2", 2).is_err());

    data_provider.add("A", v(3), Some(value(3))).unwrap();
    data_provider.add("B2", v(5), Some(value(5))).unwrap();
    data_provider.add::<TestProto>("B2", v(6), None).unwrap();

    registry.poll_once().unwrap();
    assert_eq!(registry.get_latest_version(), v(6));
    assert_eq!(get("A", 3).unwrap(), Some(value(3)));
    assert_eq!(get("A", 4).unwrap(), Some(value(3)));
    assert_eq!(get("A", 5).unwrap(), Some(value(3)));
    assert_eq!(get("A", 6).unwrap(), Some(value(3)));
    assert!(get("A", 7).is_err());

    for t in 0..5 {
        assert!(get("B2", t).unwrap().is_none());
    }
    assert_eq!(get("B2", 5).unwrap(), Some(value(5)));
    assert!(get("B2", 6).unwrap().is_none());
    assert!(get("B2", 7).is_err());
}

#[test]
fn start_polling_actually_polls_data_provider() {
    let data_provider = Arc::new(FakeDataProvider {
        poll_counter: Arc::new(AtomicUsize::new(0)),
    });
    let registry = RegistryClientImpl::new(data_provider.clone(), None);

    if let Err(e) = registry.fetch_and_start_polling() {
        panic!("fetch_and_start_polling failed: {e}");
    }
    std::thread::sleep(Duration::from_secs(1));
    std::mem::drop(registry);

    assert!(data_provider.poll_counter.load(Ordering::Relaxed) > 0);
}

#[test]
fn polling_for_latest_version_fails_for_insufficient_retries() {
    let data_provider = Arc::new(ProtoRegistryDataProvider::new());
    let changelog_size_limit = RegistryVersion::from(2);
    let limiting_data_provider = Arc::new(LimitingDataProvider::new(
        changelog_size_limit,
        data_provider.clone(),
    ));
    let registry = RegistryClientImpl::new(limiting_data_provider, None);
    // let get = |key: &str, t: u64| registry.get_test_proto(key,
    // RegistryVersion::new(t));
    let set = |key: &str, ver: u64| data_provider.add(key, v(ver), Some(value(ver))).unwrap();
    let rem = |key: &str, ver: u64| data_provider.add::<TestProto>(key, v(ver), None).unwrap();

    set("A", 1);
    set("A", 3);
    set("A", 6);
    set("B", 6);
    set("B2", 5);
    rem("B2", 6);
    set("B3", 5);
    set("C", 6);
    set("D", 7);

    let try_poll_res = registry.try_polling_latest_version(3);
    assert_matches!(
        try_poll_res,
        Err(RegistryClientError::PollingLatestVersionFailed { .. })
    )
}

#[test]
fn polling_for_latest_version_succeeds() {
    let data_provider = Arc::new(ProtoRegistryDataProvider::new());
    let changelog_size_limit = RegistryVersion::from(2);
    let limiting_data_provider = Arc::new(LimitingDataProvider::new(
        changelog_size_limit,
        data_provider.clone(),
    ));
    let registry = RegistryClientImpl::new(limiting_data_provider, None);
    let get = |key: &str, t: u64| registry.get_test_proto(key, RegistryVersion::new(t));
    let set = |key: &str, ver: u64| data_provider.add(key, v(ver), Some(value(ver))).unwrap();
    let rem = |key: &str, ver: u64| data_provider.add::<TestProto>(key, v(ver), None).unwrap();

    set("A", 1);
    set("A", 3);
    set("A", 6);
    set("B", 6);
    set("B2", 5);
    rem("B2", 6);
    set("C", 7);

    assert!(registry.try_polling_latest_version(5).is_ok());
    let latest_version = registry.get_latest_version().get();

    assert!(get("A", 0).unwrap().is_none());
    assert_eq!(get("A", 1).unwrap(), Some(value(1)));
    assert_eq!(get("A", 2).unwrap(), Some(value(1)));
    assert_eq!(get("A", 3).unwrap(), Some(value(3)));
    assert_eq!(get("A", 4).unwrap(), Some(value(3)));
    assert_eq!(get("A", 5).unwrap(), Some(value(3)));
    assert_eq!(get("A", 6).unwrap(), Some(value(6)));
    assert_eq!(get("A", 7).unwrap(), Some(value(6)));
    assert!(get("A", latest_version + 1).is_err());

    for t in 0..6 {
        assert!(get("B", t).unwrap().is_none());
    }
    assert_eq!(get("B", 6).unwrap(), Some(value(6)));
    assert!(get("B", latest_version + 1).is_err());

    for t in 0..5 {
        assert!(get("B2", t).unwrap().is_none());
    }
    assert_eq!(get("B2", 5).unwrap(), Some(value(5)));
    assert!(get("B2", 6).unwrap().is_none());
    assert!(get("B2", latest_version + 1).is_err());

    assert_eq!(get("C", 7).unwrap(), Some(value(7)));
}

fn v(v: u64) -> RegistryVersion {
    RegistryVersion::new(v)
}

fn value(v: u64) -> TestProto {
    TestProto { test_value: v }
}

struct FakeDataProvider {
    pub poll_counter: Arc<AtomicUsize>,
}

impl RegistryDataProvider for FakeDataProvider {
    fn get_updates_since(
        &self,
        _version: RegistryVersion,
    ) -> Result<Vec<RegistryRecord>, RegistryDataProviderError> {
        self.poll_counter.fetch_add(1, Ordering::Relaxed);
        Ok(vec![])
    }
}

struct LimitingDataProvider {
    changelog_size: RegistryVersion,
    data_provider: Arc<dyn RegistryDataProvider>,
}

impl LimitingDataProvider {
    fn new(
        changelog_size: RegistryVersion,
        data_provider: Arc<dyn RegistryDataProvider>,
    ) -> Self {
        Self {
            changelog_size,
            data_provider,
        }
    }
}

impl RegistryDataProvider for LimitingDataProvider {
    fn get_updates_since(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<RegistryRecord>, RegistryDataProviderError> {
        let mut res = self.data_provider.get_updates_since(version)?;
        res.retain(|r| r.version <= version + self.changelog_size);
        Ok(res)
    }
}
#[cfg(test)]
mod metrics {
    use ic_test_utilities_metrics::fetch_int_gauge;

    use super::*;

    #[test]
    fn ic_registry_client_registry_version_updates() {
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());
        let metrics_registry = MetricsRegistry::new();
        let registry = RegistryClientImpl::new(data_provider.clone(), Some(&metrics_registry));

        data_provider.add("A", v(1), Some(value(1))).unwrap();

        registry.poll_once().unwrap();
        assert_eq!(registry.get_latest_version(), v(1));
        assert_eq!(
            fetch_int_gauge(&metrics_registry, "ic_registry_client_registry_version"),
            Some(1)
        );

        data_provider.add("A", v(3), Some(value(3))).unwrap();

        registry.poll_once().unwrap();
        assert_eq!(registry.get_latest_version(), v(3));
        assert_eq!(
            fetch_int_gauge(&metrics_registry, "ic_registry_client_registry_version"),
            Some(3)
        );
    }
}
