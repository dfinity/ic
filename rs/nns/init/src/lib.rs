//! Shared code between ic-nns-init and ic-admin and utility to generate the
//! initial payloads and install nns canisters in a fresh IC.
//! Was used at genesis, but now only used to install the nns in testnets.

use canister_test::Wasm;
use ic_canister_client::Sender;
use ic_interfaces::registry::{RegistryDataProvider, ZERO_REGISTRY_VERSION};
use ic_nns_constants::NNS_CANISTER_WASMS;
use ic_registry_common::local_store::{
    ChangelogEntry, KeyMutation, LocalStoreImpl, LocalStoreReader,
};
use ic_registry_common::proto_registry_data_provider::ProtoRegistryDataProvider;
use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation};
use ic_registry_transport::{delete, upsert};
use ic_sys::utility_command::{UtilityCommand, UtilityCommandError};
use std::path::Path;

/// Reads mutations from a file in the format corresponding to what ic-prep
/// outputs
pub fn read_initial_registry_mutations<P: AsRef<Path>>(path: P) -> Vec<RegistryMutation> {
    let initial_registry = ProtoRegistryDataProvider::load_from_file(path.as_ref());
    // Because we use the ProtoRegistryDataProvider, we are guaranteed to get
    // the entire registry in one chunk when calling `get_updates_since()`.
    let update = initial_registry
        .get_updates_since(ZERO_REGISTRY_VERSION)
        .expect("Could not load records from initial registry.");

    update
        .into_iter()
        .filter(|r| r.value.is_some())
        .map(|r| {
            let mut mutation = RegistryMutation::default();
            mutation.set_mutation_type(registry_mutation::Type::Insert);
            mutation.key = r.key.as_bytes().to_vec();
            mutation.value = r.value.unwrap();
            mutation
        })
        .collect()
}

/// Reads the initial content to inject into the registry in the "ic-prep"
/// format.
///
/// `ic_prep_file` is expected to be a file written by ic-prep.
pub fn read_initial_mutations_from_ic_prep(
    ic_prep_file: &Path,
) -> Vec<RegistryAtomicMutateRequest> {
    vec![RegistryAtomicMutateRequest {
        mutations: read_initial_registry_mutations(ic_prep_file),
        preconditions: vec![],
    }]
}

/// Reads the initial content to inject into the registry in the "local store"
/// format.
///
/// `local_store_dir` is expected to be a directory containing specially-named
/// files following the schema implemented in local_store.rs.
pub fn read_initial_mutations_from_local_store_dir(
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
    use ic_base_types::RegistryVersion;
    use ic_registry_common::local_store::Changelog;
    use ic_registry_common::local_store::LocalStoreWriter;
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

/// Given params to read a HSM, return a `Sender` that uses this HSM to sign
/// requests.
pub fn make_hsm_sender(hsm_slot: &str, key_id: &str, pin: &str) -> Sender {
    // Set up the agent using an HSM, first perform a simple test for correctness of
    // the PIN.
    UtilityCommand::try_to_attach_hsm();
    let res = UtilityCommand::new(
        "pkcs11-tool".to_string(),
        vec![
            "--read-object",
            "--slot",
            hsm_slot,
            "--type",
            "pubkey",
            "--id",
            key_id,
            "--pin",
            pin,
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>(),
    )
    .execute();

    if let Err(UtilityCommandError::Failed(err, _status)) = res {
        // The key id is not found.
        if err.contains("object not found") {
            panic!("Cannot find key with id {}", key_id);
        }
        // The pin is incorrect.
        if err.contains("CKR_PIN_INCORRECT") {
            panic!("The PIN that was given is incorrect");
        }
    }

    let pub_key = UtilityCommand::read_public_key(Some(hsm_slot), Some(key_id))
        .execute()
        .unwrap_or_else(|e| {
            panic!(
                "Error while trying to read the public key from the HSM. Underlying error: {}",
                e
            )
        });

    let key_id = key_id.to_string();
    let pin = pin.to_string();
    let hsm_slot = hsm_slot.to_string();
    let sender = Sender::from_external_hsm(
        pub_key,
        std::sync::Arc::new(move |input| {
            UtilityCommand::sign_message(input.to_vec(), Some(&hsm_slot), Some(&pin), Some(&key_id))
                .execute()
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
        }),
    );
    UtilityCommand::try_to_detach_hsm();

    sender
}

/// Verifies that `wasm_dir` contains all of the wasm files corresponding to the
/// NNS canisters, and sets an environment variable pointing at each of them so
/// that they can be found later.
pub fn set_up_env_vars_for_all_canisters<P: AsRef<Path>>(wasm_dir: P) {
    for canister in &NNS_CANISTER_WASMS {
        // Can it be found?
        let file_part = format!("{}.wasm", canister);
        let mut path = wasm_dir.as_ref().to_path_buf();
        path.push(file_part.as_str());
        assert!(
            path.is_file(),
            "The provided --wasm-dir, '{}', must contain all NNS canister wasms, but it misses {}",
            wasm_dir.as_ref().display(),
            file_part
        );

        // Sets up the env var following the pattern expected by
        // WASM::from_location_specified_by_env_var
        std::env::set_var(Wasm::env_var_name(canister), path.to_str().unwrap());
    }
}
