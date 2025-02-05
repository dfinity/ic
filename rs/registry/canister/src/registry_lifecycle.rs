use crate::{
    certification::recertify_registry, missing_node_types_map::MISSING_NODE_TYPES_MAP,
    mutations::node_management::common::get_key_family, pb::v1::RegistryCanisterStableStorage,
    registry::Registry,
};
use ic_base_types::{NodeId, PrincipalId};
use ic_protobuf::registry::node::v1::{NodeRecord, NodeRewardType};
use ic_registry_keys::{make_node_record_key, NODE_RECORD_KEY_PREFIX};
use ic_registry_transport::{pb::v1::RegistryMutation, update};
use prost::Message;
use std::str::FromStr;

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
        let mutations = add_missing_node_types_to_nodes(registry);
        if mutations.is_empty() {
            0 // No mutations required for this data migration.
        } else {
            registry.maybe_apply_mutation_internal(mutations);
            1 // Single batch of mutations due to this data migration.
        }
    };

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

fn add_missing_node_types_to_nodes(registry: &Registry) -> Vec<RegistryMutation> {
    let missing_node_types_map = &MISSING_NODE_TYPES_MAP;

    let mut mutations = Vec::new();

    for (id, record) in get_key_family::<NodeRecord>(registry, NODE_RECORD_KEY_PREFIX).into_iter() {
        if record.node_reward_type.is_none() {
            let reward_type = missing_node_types_map
                .get(id.as_str())
                .map(|t| NodeRewardType::from(t.to_string()));

            if let Some(reward_type) = reward_type {
                if reward_type != NodeRewardType::Unspecified {
                    let mut record = record;
                    record.node_reward_type = Some(reward_type as i32);
                    let node_id = NodeId::from(PrincipalId::from_str(&id).unwrap());
                    mutations.push(update(
                        make_node_record_key(node_id),
                        record.encode_to_vec(),
                    ));
                }
            }
        }
    }

    mutations
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        common::test_helpers::{empty_mutation, invariant_compliant_registry},
        registry::{EncodedVersion, Version},
        registry_lifecycle::Registry,
    };
    use ic_base_types::{NodeId, PrincipalId};
    use ic_registry_keys::make_node_record_key;
    use ic_registry_transport::insert;

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
    #[should_panic(expected = "No routing table in snapshot")]
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

    #[test]
    fn test_migration_works_correctly() {
        use std::str::FromStr;
        let mut registry = invariant_compliant_registry(0);

        let mut node_additions = Vec::new();
        for (id, _) in MISSING_NODE_TYPES_MAP.iter() {
            let record = NodeRecord {
                xnet: None,
                http: None,
                node_operator_id: PrincipalId::new_anonymous().to_vec(),
                chip_id: None,
                hostos_version_id: None,
                public_ipv4_config: None,
                domain: None,
                node_reward_type: None,
            };

            node_additions.push(insert(
                make_node_record_key(NodeId::new(PrincipalId::from_str(id).unwrap())),
                record.encode_to_vec(),
            ));
        }

        let nodes_expected = node_additions.len();
        assert_eq!(nodes_expected, 1418);

        registry.apply_mutations_for_test(node_additions);

        let mutations = add_missing_node_types_to_nodes(&registry);
        assert_eq!(mutations.len(), nodes_expected);

        registry.apply_mutations_for_test(mutations);

        for (id, reward_type) in MISSING_NODE_TYPES_MAP.iter() {
            let record =
                registry.get_node_or_panic(NodeId::from(PrincipalId::from_str(id).unwrap()));

            let expected_reward_type = NodeRewardType::from(reward_type.clone());
            assert_eq!(
                record.node_reward_type,
                Some(expected_reward_type as i32),
                "Assertion for Node {} failed",
                id
            );
        }
    }
}
