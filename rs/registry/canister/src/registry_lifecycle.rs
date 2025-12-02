use crate::certification::recertify_registry;
use crate::{pb::v1::RegistryCanisterStableStorage, registry::Registry};
use prost::Message;

pub fn canister_post_upgrade(
    registry: &mut Registry,
    registry_storage: RegistryCanisterStableStorage,
) {
    // Purposefully fail the upgrade if we can't find authz information.
    // Best to have a broken canister, which we can reinstall, than a
    // canister without authz information.

    registry.from_serializable_form(
        registry_storage
            .registry
            .expect("Error decoding from stable"),
    );

    // Registry data migrations should be implemented as follows:
    let mutation_batches_due_to_data_migrations = {
        let mutations = vec![];
        if mutations.is_empty() {
            0 // No mutations required for this data migration.
        } else {
            registry.maybe_apply_mutation_internal(mutations);
            1 // Single batch of mutations due to this data migration.
        }
    };
    //
    // When there are no migrations, `mutation_batches_due_to_data_migrations` should be set to `0`.
    // let mutation_batches_due_to_data_migrations = 0;

    registry.check_global_state_invariants(&[]);
    // Registry::from_serializable_from guarantees this always passes in this function
    // because it fills in missing versions to maintain that invariant
    registry.check_changelog_version_invariants();

    // This is no-op outside Canister environment, and is therefore not under unit-test coverage
    recertify_registry(registry);

    // ANYTHING BELOW THIS LINE SHOULD NOT MUTATE STATE

    if registry_storage.pre_upgrade_version.is_some() {
        let pre_upgrade_version = registry_storage.pre_upgrade_version.unwrap();

        assert_eq!(
            pre_upgrade_version + mutation_batches_due_to_data_migrations,
            registry.latest_version(),
            "The serialized last version watermark doesn't match what's found in the records. \
                     Watermark: {:?}, Last version: {:?}",
            pre_upgrade_version,
            registry.latest_version()
        );
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        common::test_helpers::{empty_mutation, invariant_compliant_registry},
        registry::{EncodedVersion, Version},
        registry_lifecycle::Registry,
    };

    fn stable_storage_from_registry(
        registry: &Registry,
        override_version: Option<Version>,
    ) -> Vec<u8> {
        let mut serialized = Vec::new();
        let ss = RegistryCanisterStableStorage {
            registry: Some(registry.serializable_form()),
            pre_upgrade_version: override_version.or_else(|| Some(registry.latest_version())),
        };
        ss.encode(&mut serialized)
            .expect("Error serializing to stable.");
        serialized
    }

    #[test]
    fn post_upgrade_succeeds_with_valid_registry() {
        // given valid registry state encoded for stable storage
        let registry = invariant_compliant_registry(0);
        let stable_storage_bytes = stable_storage_from_registry(&registry, None);

        // we can use canister_post_upgrade to initialize a new registry correctly
        let mut new_registry = Registry::new();
        let registry_storage =
            RegistryCanisterStableStorage::decode(stable_storage_bytes.as_slice())
                .expect("Error decoding from stable.");
        canister_post_upgrade(&mut new_registry, registry_storage);

        // and the version is right
        assert_eq!(new_registry.latest_version(), 1);
    }

    #[test]
    #[should_panic(expected = "Error decoding from stable.")]
    fn post_upgrade_fails_when_stable_storage_fails_decoding() {
        let mut registry = Registry::new();
        // try with garbage to check first error condition
        let stable_storage_bytes = [1, 2, 3];
        let registry_storage =
            RegistryCanisterStableStorage::decode(stable_storage_bytes.as_slice())
                .expect("Error decoding from stable.");
        canister_post_upgrade(&mut registry, registry_storage);
    }

    #[test]
    #[should_panic(expected = "Error decoding from stable")]
    fn post_upgrade_fails_when_registry_missing_from_storage() {
        // Given stable storage that's missing a registry
        let mut serialized = Vec::new();
        let ss = RegistryCanisterStableStorage {
            registry: None,
            pre_upgrade_version: Some(1u64),
        };
        ss.encode(&mut serialized)
            .expect("Error serializing to stable.");

        let mut registry = Registry::new();

        // When we try to run canister_post_upgrade
        // Then we panic
        let registry_storage = RegistryCanisterStableStorage::decode(serialized.as_slice())
            .expect("Error decoding from stable.");
        canister_post_upgrade(&mut registry, registry_storage);
    }

    #[test]
    #[should_panic(expected = "[Registry] invariant check failed with message: no system subnet")]
    fn post_upgrade_fails_on_global_state_invariant_check_failure() {
        // We only check a single failure mode here,
        // since the rest should be under other test coverage
        let registry = Registry::new();
        let stable_storage_bytes = stable_storage_from_registry(&registry, None);

        // with our bad mutation, this should throw
        let mut new_registry = Registry::new();
        let registry_storage =
            RegistryCanisterStableStorage::decode(stable_storage_bytes.as_slice())
                .expect("Error decoding from stable.");
        canister_post_upgrade(&mut new_registry, registry_storage);
    }

    #[test]
    fn post_upgrade_fills_in_missing_versions_to_maintain_invariant() {
        // We only check a single failure mode, since the rest should be under other test coverage
        let mut registry = invariant_compliant_registry(0);
        registry
            .changelog
            .insert(EncodedVersion::from(7), empty_mutation());
        let stable_storage_bytes = stable_storage_from_registry(&registry, Some(7u64));

        let mut new_registry = Registry::new();
        let registry_storage =
            RegistryCanisterStableStorage::decode(stable_storage_bytes.as_slice())
                .expect("Error decoding from stable.");
        canister_post_upgrade(&mut new_registry, registry_storage);

        // missing versions are added by the deserializer
        let mut sorted_changelog_versions = new_registry
            .changelog()
            .iter()
            .map(|(encoded_version, _)| encoded_version.as_version())
            .collect::<Vec<u64>>();
        sorted_changelog_versions.sort_unstable();
        // we expect all intermediate versions to be present
        assert_eq!(sorted_changelog_versions, vec![1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    #[should_panic(
        expected = "The serialized last version watermark doesn't match what's found in the records. \
                     Watermark: 100, Last version: 1"
    )]
    fn post_upgrade_fails_when_registry_decodes_different_version() {
        // Given a mismatched stable storage version from the registry
        let registry = invariant_compliant_registry(0);
        let stable_storage_bytes = stable_storage_from_registry(&registry, Some(100u64));
        // then we panic when decoding
        let mut new_registry = Registry::new();
        let registry_storage =
            RegistryCanisterStableStorage::decode(stable_storage_bytes.as_slice())
                .expect("Error decoding from stable.");
        canister_post_upgrade(&mut new_registry, registry_storage);
    }
}
