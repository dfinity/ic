use crate::{
    certification::recertify_registry, mutations::node_management::common::get_key_family,
    pb::v1::RegistryCanisterStableStorage, registry::Registry,
};
use ic_base_types::{NodeId, PrincipalId};
use ic_protobuf::registry::node::v1::{NodeRecord, NodeRewardType};
use ic_registry_keys::{NODE_RECORD_KEY_PREFIX, make_node_record_key};
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
        let mutations = migrate_node_reward_type1_type0_to_type1dot1(registry);
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

fn migrate_node_reward_type1_type0_to_type1dot1(registry: &Registry) -> Vec<RegistryMutation> {
    let mut mutations = Vec::new();

    for (id, mut record) in
        get_key_family::<NodeRecord>(registry, NODE_RECORD_KEY_PREFIX).into_iter()
    {
        let Some(some_reward_type) = record.node_reward_type else {
            // If the node does not have a node_reward_type, we skip it.
            continue;
        };

        let node_reward_type =
            NodeRewardType::try_from(some_reward_type).expect("Invalid node_reward_type value");

        if node_reward_type == NodeRewardType::Type1 || node_reward_type == NodeRewardType::Type0 {
            record.node_reward_type = Some(NodeRewardType::Type1dot1 as i32);
            let node_id = NodeId::from(PrincipalId::from_str(&id).unwrap());
            mutations.push(update(
                make_node_record_key(node_id),
                record.encode_to_vec(),
            ));
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
    use itertools::enumerate;

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

    #[test]
    fn test_migrate_node_reward_type1_type0_to_type1dot1_works_correctly() {
        let mut registry = invariant_compliant_registry(0);

        let mut node_additions = Vec::new();
        for (idx, test_id) in enumerate(0..10) {
            let node_reward_type = if idx < 5 {
                NodeRewardType::Type0
            } else {
                NodeRewardType::Type1
            };
            let record = NodeRecord {
                node_operator_id: PrincipalId::new_user_test_id(test_id).to_vec(),
                hostos_version_id: Some(format!("dummy_version_{}", test_id)),
                domain: Some(format!("dummy_domain_{}", test_id)),
                node_reward_type: Some(node_reward_type as i32),
                ..NodeRecord::default()
            };

            node_additions.push(insert(
                make_node_record_key(NodeId::new(PrincipalId::new_node_test_id(test_id))),
                record.encode_to_vec(),
            ));
        }

        registry.apply_mutations_for_test(node_additions);
        let mutations = migrate_node_reward_type1_type0_to_type1dot1(&registry);
        assert_eq!(mutations.len(), 10);

        registry.apply_mutations_for_test(mutations);

        for test_id in 0..10 {
            let record =
                registry.get_node_or_panic(NodeId::from(PrincipalId::new_node_test_id(test_id)));

            let expected_record = NodeRecord {
                xnet: None,
                http: None,
                node_operator_id: PrincipalId::new_user_test_id(test_id).to_vec(),
                chip_id: None,
                hostos_version_id: Some(format!("dummy_version_{}", test_id)),
                public_ipv4_config: None,
                domain: Some(format!("dummy_domain_{}", test_id)),
                node_reward_type: Some(NodeRewardType::Type1dot1 as i32),
            };

            assert_eq!(
                record, expected_record,
                "Assertion for Node {} failed",
                test_id
            );
        }
    }
}
