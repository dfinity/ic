use super::*;
use ic_interfaces_registry::RegistryVersionedRecord;
use ic_registry_keys::NODE_RECORD_KEY_PREFIX;
use ic_types::{PrincipalId, registry::RegistryDataProviderError};

/// This is a regression test.
#[test]
fn test_absent_after_delete() {
    // Step 1: Prepare the world.

    const DELETED_KEY: &str = "\
        node_record_\
        2hkvg-f3qgx-b5zoa-nz4k4-7q5v2-fiohf-x7o45-v6hds-5gf6w-o6lf6-gae";

    struct DummyRegistryDataProvider {}
    impl RegistryDataProvider for DummyRegistryDataProvider {
        fn get_updates_since(
            &self,
            _registry_version: RegistryVersion,
        ) -> Result<Vec<RegistryVersionedRecord<Vec<u8>>>, RegistryDataProviderError> {
            Ok(vec![
                // This data is copied from observed values, except the value field is abridged,
                // since it's not used by the code under test.
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
            ])
        }
    }

    let fake_registry_client = FakeRegistryClient::new(Arc::new(DummyRegistryDataProvider {}));
    fake_registry_client.update_to_latest_version();

    // Step 2: Call code under test.
    let result =
        fake_registry_client.get_key_family(NODE_RECORD_KEY_PREFIX, RegistryVersion::new(39_972));

    // Step 3: Inspect results.
    assert_eq!(
        result,
        // DELETED_KEY should not be present in result, only principal 42.
        Ok(vec![format!(
            "{}{}",
            NODE_RECORD_KEY_PREFIX,
            PrincipalId::new_user_test_id(42)
        )]),
    );
}
