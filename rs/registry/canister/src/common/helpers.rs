use std::default::Default;

use crate::{registry::Registry, storage::with_chunks};
use ic_registry_canister_chunkify::decode_high_capacity_registry_value;
use ic_registry_transport::pb::v1::HighCapacityRegistryValue;

/// Similar to `get_key_family` on the `RegistryClient`, return a list of
/// tuples, (ID, value).  This strips the prefix from the key and returns the
/// value as a decoded struct.
///
/// This function must return keys in order of their bytes, which should
/// also be the same order as the string representations.
pub(crate) fn get_key_family<T: prost::Message + Default>(
    registry: &Registry,
    prefix: &str,
) -> Vec<(String, T)> {
    get_key_family_iter(registry, prefix).collect()
}

/// This function must return keys in order of their bytes, which should
/// also be the same order as the string representations.
pub(crate) fn get_key_family_iter<'a, T: prost::Message + Default>(
    registry: &'a Registry,
    prefix: &'a str,
) -> impl Iterator<Item = (String, T)> + 'a {
    get_key_family_iter_at_version(registry, prefix, registry.latest_version())
}

/// This function must return keys in order of their bytes, which should
/// also be the same order as the string representations.
pub(crate) fn get_key_family_iter_at_version<'a, T: prost::Message + Default>(
    registry: &'a Registry,
    prefix: &'a str,
    version: u64,
) -> impl Iterator<Item = (String, T)> + 'a {
    get_key_family_raw_iter_at_version(registry, prefix, version).filter_map(|(id, value)| {
        let latest_value: Option<T> =
            with_chunks(|chunks| decode_high_capacity_registry_value::<T, _>(value, chunks));

        let latest_value = latest_value?;

        Some((id, latest_value))
    })
}

/// This function must return keys in order of their bytes, which should
/// also be the same order as the string representations.
pub(crate) fn get_key_family_raw_iter_at_version<'a>(
    registry: &'a Registry,
    prefix: &'a str,
    version: u64,
) -> impl Iterator<Item = (String, &'a HighCapacityRegistryValue)> + 'a {
    let prefix_bytes = prefix.as_bytes();
    let start = prefix_bytes.to_vec();

    // Note, using the 'store' which is a BTreeMap is what guarantees the order of keys.
    registry
        .store
        .range(start..)
        .take_while(|(k, _)| k.starts_with(prefix_bytes))
        .filter_map(move |(key, values)| {
            let latest_value: &HighCapacityRegistryValue =
                values.iter().rev().find(|value| value.version <= version)?;

            if !latest_value.is_present() {
                return None; // Deleted or otherwise empty value.
            }

            let id = key
                .strip_prefix(prefix_bytes)
                .and_then(|v| std::str::from_utf8(v).ok())
                .unwrap()
                .to_string();

            Some((id, latest_value))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    use ic_registry_transport::{
        pb::v1::{LargeValueChunkKeys, RegistryMutation},
        upsert,
    };
    use prost::Message;

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
}
