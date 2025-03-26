use ic_interfaces_registry::ZERO_REGISTRY_VERSION;
use ic_registry_local_store::{ChangelogEntry, KeyMutation, LocalStoreImpl, LocalStoreReader};
use ic_registry_transport::{delete, pb::v1::RegistryAtomicMutateRequest, upsert};
use std::path::Path;

/// Reads the initial content to inject into the registry in the "local store"
/// format.
///
/// `local_store_dir` is expected to be a directory containing specially-named
/// files following the schema implemented in local_store.rs.
pub(crate) fn read_initial_mutations_from_local_store_dir(
    local_store_dir: &Path,
) -> Vec<RegistryAtomicMutateRequest> {
    let store = LocalStoreImpl::new(local_store_dir);
    let changelog = store
        .get_changelog_since_version(ZERO_REGISTRY_VERSION)
        .unwrap_or_else(|e| {
            panic!(
                "Could not read the content of the local store at {} due to: {}",
                local_store_dir.display(),
                e
            )
        });
    changelog
        .into_iter()
        .map(|cle: ChangelogEntry| RegistryAtomicMutateRequest {
            mutations: cle
                .into_iter()
                .map(|km: KeyMutation| match km.value {
                    Some(bytes) => upsert(km.key.as_bytes(), bytes),
                    None => delete(km.key),
                })
                .collect(),
            preconditions: vec![],
        })
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;
    use ic_registry_client::client::RegistryVersion;
    use ic_registry_local_store::{Changelog, LocalStoreWriter};
    use tempfile::TempDir;

    /// In this test, a directory written by the `LocalStore::store` function is
    /// read, and we assert that the mutations being read are as expected.
    #[test]
    fn can_read_local_store() {
        let tempdir = TempDir::new().unwrap();
        let store = LocalStoreImpl::new(tempdir.path());
        let changelog: Changelog = vec![
            vec![
                KeyMutation {
                    key: "rapper's delight".to_string(),
                    value: Some(b"1980".to_vec()),
                },
                KeyMutation {
                    key: "the message".to_string(),
                    value: Some(b"1982".to_vec()),
                },
            ],
            vec![KeyMutation {
                key: "212".to_string(),
                value: Some(b"2011".to_vec()),
            }],
            vec![KeyMutation {
                key: "some key to delete".to_string(),
                value: None,
            }],
        ];
        changelog.iter().enumerate().for_each(|(i, c)| {
            store
                .store(RegistryVersion::from((i + 1) as u64), c.clone())
                .unwrap()
        });

        let path = tempdir.path().to_path_buf();
        let mutation_requests = read_initial_mutations_from_local_store_dir(&path);
        assert_eq!(
            mutation_requests,
            vec![
                RegistryAtomicMutateRequest {
                    mutations: vec![
                        upsert(b"rapper's delight", "1980"),
                        upsert(b"the message", "1982")
                    ],
                    preconditions: vec![]
                },
                RegistryAtomicMutateRequest {
                    mutations: vec![upsert(b"212", "2011"),],
                    preconditions: vec![]
                },
                RegistryAtomicMutateRequest {
                    mutations: vec![delete(b"some key to delete"),],
                    preconditions: vec![]
                },
            ]
        );
    }
}
