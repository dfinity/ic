use super::*;
use ic_registry_transport::{pb::v1::LargeValueChunkKeys, upsert};

fn new_upsert(key: &str, value: &str) -> RegistryMutation {
    let value = LargeValueChunkKeys {
        chunk_content_sha256s: vec![value.bytes().collect()],
    }
    .encode_to_vec();

    upsert(key, value)
}

#[test]
fn test_get_key_family_iter_at_version() {
    let mut registry = Registry::new();

    registry.apply_mutations_for_test(vec![
        new_upsert("red_herring_1", "boeoeg"),
        new_upsert("name_1", "Daniel"),
        new_upsert("name_2", "Wong"),
        new_upsert("delicious_red_herring_1", "fish"),
    ]);

    let result =
        get_key_family_iter(&registry, "name_").collect::<Vec<(String, LargeValueChunkKeys)>>();

    assert_eq!(
        result,
        vec![
            (
                "1".to_string(),
                LargeValueChunkKeys {
                    chunk_content_sha256s: vec![b"Daniel".to_vec()],
                },
            ),
            (
                "2".to_string(),
                LargeValueChunkKeys {
                    chunk_content_sha256s: vec![b"Wong".to_vec()],
                },
            ),
        ],
    );
}
