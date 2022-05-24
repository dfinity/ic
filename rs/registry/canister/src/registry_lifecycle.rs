use crate::certification::recertify_registry;
use crate::mutations::node_management::common::make_remove_node_registry_mutations;
use crate::pb::v1::RegistryCanisterStableStorage;
use crate::registry::{Registry, Version};
use ic_base_types::{NodeId, PrincipalId};
use ic_registry_keys::{
    CRYPTO_RECORD_KEY_PREFIX, CRYPTO_TLS_CERT_KEY_PREFIX, NODE_RECORD_KEY_PREFIX,
};
use prost::Message;
use std::collections::HashSet;
use std::str::{from_utf8, FromStr};

pub fn canister_post_upgrade(registry: &mut Registry, stable_storage: &[u8]) {
    // Purposefully fail the upgrade if we can't find authz information.
    // Best to have a broken canister, which we can reinstall, than a
    // canister without authz information.
    let registry_storage =
        RegistryCanisterStableStorage::decode(stable_storage).expect("Error decoding from stable.");
    registry.from_serializable_form(
        registry_storage
            .registry
            .expect("Error decoding from stable"),
    );

    // TODO remove this after enabling CRP-1449 invariants and upgrading with this code in place
    let did_execute_cleanup = cleanup_orphaned_node_keys_and_certs(registry);

    registry.check_global_state_invariants(&[]);
    // Registry::from_serializable_from guarantees this always passes in this function
    // because it fills in missing versions to maintain that invariant
    registry.check_changelog_version_invariants();

    // This is no-op outside Canister environment, and is therefore not under unit-test coverage
    recertify_registry(registry);

    // ANYTHING BELOW THIS LINE SHOULD NOT MUTATE STATE

    if registry_storage.pre_upgrade_version.is_some() {
        let pre_upgrade_version = registry_storage.pre_upgrade_version.unwrap()
           // TODO remove this after enabling CRP-1449 invariants and upgrading with this code in place
            + (if did_execute_cleanup { 1 } else { 0 });

        assert_eq!(
            pre_upgrade_version,
            registry.latest_version(),
            "The serialized last version watermark doesn't match what's found in the records. \
                     Watermark: {:?}, Last version: {:?}",
            pre_upgrade_version,
            registry.latest_version()
        );
    }
}

// TODO remove this after enabling CRP-1449 invariants and upgrading with this code in place
/// This function removes all "orphaned" crypto_record_[NODEID]_[KEY_PURPOSE] and crypto_tls_cert_[NODEID]
/// records (meaning any records without a corresponding node_record_[NODEID] record.
fn cleanup_orphaned_node_keys_and_certs(registry: &mut Registry) -> bool {
    let crypto_records =
        registry.get_key_family(CRYPTO_RECORD_KEY_PREFIX, registry.latest_version());

    let nodes_with_keys = crypto_records
        .into_iter()
        .map(|key| {
            let stripped = key.strip_prefix(CRYPTO_RECORD_KEY_PREFIX).unwrap();
            let node_id = stripped.split('_').next().unwrap();
            node_id.to_string()
        })
        .collect::<HashSet<_>>();

    let crypto_tls_certs =
        registry.get_key_family(CRYPTO_TLS_CERT_KEY_PREFIX, registry.latest_version());

    let nodes_with_certs = crypto_tls_certs
        .into_iter()
        .map(|key| {
            key.strip_prefix(CRYPTO_TLS_CERT_KEY_PREFIX)
                .unwrap()
                .to_string()
        })
        .collect::<HashSet<_>>();

    let remove_orphaned_nodes_mutations: Vec<_> = nodes_with_keys
        .union(&nodes_with_certs)
        .flat_map(|node_id| {
            let node_key = format!("{}{}", NODE_RECORD_KEY_PREFIX, node_id).into_bytes();
            // Collect the IDs that do not have a node entry
            if registry.get(&node_key, registry.latest_version()).is_none() {
                make_remove_node_registry_mutations(
                    registry,
                    NodeId::new(PrincipalId::from_str(node_id).unwrap()),
                )
            } else {
                Vec::new()
            }
        })
        .collect();

    let mutations_executed = !remove_orphaned_nodes_mutations.is_empty();
    registry.maybe_apply_mutation_internal(remove_orphaned_nodes_mutations);

    mutations_executed
}

// TODO remove or migrate this after enabling CRP-1449 invariants and upgrading with this code in place
impl Registry {
    /// Returns all keys that start with `key_prefix` and are present at version
    /// `version`.  
    fn get_key_family(&self, key_prefix: &str, version: Version) -> Vec<String> {
        let search_bytes = key_prefix.to_string().into_bytes();

        let mut results = Vec::new();
        for (key_u8, _) in self.store.range(search_bytes.clone()..) {
            // Stop iterating when we reach the end of the range
            if !key_u8.starts_with(&search_bytes) {
                break;
            }
            // Return keys that both match and exist at the specified version
            if self.get(key_u8, version).is_some() {
                if let Ok(key_string) = from_utf8(key_u8.as_slice()).map(|s| s.to_string()) {
                    results.push(key_string);
                }
            }
        }

        results
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::test_helpers::{empty_mutation, invariant_compliant_registry};
    use crate::mutations::node_management::common::make_add_node_registry_mutations;
    use crate::mutations::node_management::do_add_node::connection_endpoint_from_string;
    use crate::mutations::node_management::do_add_node::flow_endpoint_from_string;
    use crate::registry::{EncodedVersion, Version};
    use crate::registry_lifecycle::Registry;
    use ic_base_types::NodeId;
    use ic_crypto::utils::get_node_keys_or_generate_if_missing;
    use ic_crypto_node_key_validation::ValidNodePublicKeys;
    use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_PRINCIPAL;
    use ic_protobuf::registry::node::v1::NodeRecord;
    use ic_registry_keys::{make_crypto_node_key, make_node_record_key};
    use ic_registry_transport::pb::v1::RegistryMutation;
    use ic_test_utilities::crypto::temp_dir::temp_dir;
    use ic_types::crypto::KeyPurpose;

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
        let registry = invariant_compliant_registry();
        let stable_storage_bytes = stable_storage_from_registry(&registry, None);

        // we can use canister_post_upgrade to initialize a new registry correctly
        let mut new_registry = Registry::new();
        canister_post_upgrade(&mut new_registry, &stable_storage_bytes);

        // and the version is right
        assert_eq!(new_registry.latest_version(), 1);
    }

    #[test]
    #[should_panic(expected = "Error decoding from stable.")]
    fn post_upgrade_fails_when_stable_storage_fails_decoding() {
        let mut registry = Registry::new();
        // try with garbage to check first error condition
        let stable_storage_bytes = [1, 2, 3];
        canister_post_upgrade(&mut registry, &stable_storage_bytes);
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
        canister_post_upgrade(&mut registry, &serialized);
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
        canister_post_upgrade(&mut new_registry, &stable_storage_bytes);
    }

    #[test]
    fn post_upgrade_fills_in_missing_versions_to_maintain_invariant() {
        // We only check a single failure mode, since the rest should be under other test coverage
        let mut registry = invariant_compliant_registry();
        registry
            .changelog
            .insert(EncodedVersion::from(7), empty_mutation());
        let stable_storage_bytes = stable_storage_from_registry(&registry, Some(7u64));

        let mut new_registry = Registry::new();
        canister_post_upgrade(&mut new_registry, &stable_storage_bytes);

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
        let registry = invariant_compliant_registry();
        let stable_storage = stable_storage_from_registry(&registry, Some(100u64));
        // then we panic when decoding
        let mut new_registry = Registry::new();
        canister_post_upgrade(&mut new_registry, &stable_storage);
    }

    fn new_node_mutations() -> (NodeId, Vec<RegistryMutation>) {
        let temp_dir = temp_dir();
        let (keys, node_id) = get_node_keys_or_generate_if_missing(temp_dir.path());
        let valid_pks = ValidNodePublicKeys::try_from(&keys, node_id).unwrap();
        let node_record = NodeRecord {
            node_operator_id: (*TEST_NEURON_1_OWNER_PRINCIPAL).to_vec(),
            xnet: Some(connection_endpoint_from_string("128.0.0.1:1234")),
            http: Some(connection_endpoint_from_string("128.0.0.1:1234")),
            p2p_flow_endpoints: vec![flow_endpoint_from_string("123,128.0.0.1:10000")],
            ..Default::default()
        };
        (
            node_id,
            make_add_node_registry_mutations(node_id, node_record, valid_pks),
        )
    }

    fn registry_with_one_node_and_orphaned_keys() -> (Registry, NodeId, NodeId) {
        let mut registry = invariant_compliant_registry();
        let (node_1_id, node_1_mutations) = new_node_mutations();
        let (orphaned_id, mut orphaned_keys_mutations) = new_node_mutations();
        // Remove the mutation that adds the node, so that the records will be orphaned.
        orphaned_keys_mutations.remove(0);
        registry.maybe_apply_mutation_internal(node_1_mutations);
        registry.maybe_apply_mutation_internal(orphaned_keys_mutations);

        (registry, node_1_id, orphaned_id)
    }

    // TODO remove this after enabling CRP-1449 invariants and upgrading with this code in place
    #[test]
    fn post_upgrade_cleans_up_orphaned_node_keys_and_certs_and_nothing_else() {
        let (registry, node_id, orphaned_node_id) = registry_with_one_node_and_orphaned_keys();

        assert!(registry
            .get(
                &make_node_record_key(node_id).into_bytes(),
                registry.latest_version()
            )
            .is_some());
        assert!(registry
            .get(
                &make_crypto_node_key(node_id, KeyPurpose::NodeSigning).into_bytes(),
                registry.latest_version()
            )
            .is_some());

        assert!(registry
            .get(
                &make_node_record_key(orphaned_node_id).into_bytes(),
                registry.latest_version()
            )
            .is_none());
        assert!(registry
            .get(
                &make_crypto_node_key(orphaned_node_id, KeyPurpose::NodeSigning).into_bytes(),
                registry.latest_version()
            )
            .is_some());
        assert_eq!(
            registry
                .get_key_family(CRYPTO_RECORD_KEY_PREFIX, registry.latest_version())
                .len(),
            8
        );
        assert_eq!(
            registry
                .get_key_family(CRYPTO_TLS_CERT_KEY_PREFIX, registry.latest_version())
                .len(),
            2
        );

        let stable_storage = stable_storage_from_registry(&registry, None);

        let mut new_registry = Registry::new();
        canister_post_upgrade(&mut new_registry, &stable_storage);

        assert!(new_registry
            .get(
                &make_node_record_key(node_id).into_bytes(),
                new_registry.latest_version()
            )
            .is_some());
        assert!(new_registry
            .get(
                &make_crypto_node_key(node_id, KeyPurpose::NodeSigning).into_bytes(),
                new_registry.latest_version()
            )
            .is_some());

        assert!(new_registry
            .get(
                &make_node_record_key(orphaned_node_id).into_bytes(),
                new_registry.latest_version()
            )
            .is_none());

        assert!(new_registry
            .get(
                &make_crypto_node_key(orphaned_node_id, KeyPurpose::NodeSigning).into_bytes(),
                new_registry.latest_version()
            )
            .is_none());

        assert_eq!(
            new_registry
                .get_key_family(CRYPTO_RECORD_KEY_PREFIX, new_registry.latest_version())
                .len(),
            4
        );
        assert_eq!(
            new_registry
                .get_key_family(CRYPTO_TLS_CERT_KEY_PREFIX, new_registry.latest_version())
                .len(),
            1
        );
    }

    // TODO remove this after enabling CRP-1449 invariants and upgrading with this code in place
    #[test]
    fn post_upgrade_makes_no_changes_with_no_orphaned_certs_or_keys() {
        fn registry_with_two_nodes() -> (Registry, NodeId, NodeId) {
            let mut registry = invariant_compliant_registry();
            let (node_1_id, node_1_mutations) = new_node_mutations();
            let (node_id_2, node_2_mutations) = new_node_mutations();
            // Remove the mutation that adds the node, so that the records will be orphaned.
            registry.maybe_apply_mutation_internal(node_1_mutations);
            registry.maybe_apply_mutation_internal(node_2_mutations);

            (registry, node_1_id, node_id_2)
        }

        let (registry, node_id_1, node_id_2) = registry_with_two_nodes();

        assert!(registry
            .get(
                &make_node_record_key(node_id_1).into_bytes(),
                registry.latest_version()
            )
            .is_some());
        assert!(registry
            .get(
                &make_crypto_node_key(node_id_1, KeyPurpose::NodeSigning).into_bytes(),
                registry.latest_version()
            )
            .is_some());

        assert!(registry
            .get(
                &make_node_record_key(node_id_2).into_bytes(),
                registry.latest_version()
            )
            .is_some());
        assert!(registry
            .get(
                &make_crypto_node_key(node_id_2, KeyPurpose::NodeSigning).into_bytes(),
                registry.latest_version()
            )
            .is_some());
        assert_eq!(
            registry
                .get_key_family(CRYPTO_RECORD_KEY_PREFIX, registry.latest_version())
                .len(),
            8
        );
        assert_eq!(
            registry
                .get_key_family(CRYPTO_TLS_CERT_KEY_PREFIX, registry.latest_version())
                .len(),
            2
        );

        let stable_storage = stable_storage_from_registry(&registry, None);

        let mut new_registry = Registry::new();
        canister_post_upgrade(&mut new_registry, &stable_storage);

        assert!(new_registry
            .get(
                &make_node_record_key(node_id_1).into_bytes(),
                new_registry.latest_version()
            )
            .is_some());
        assert!(new_registry
            .get(
                &make_crypto_node_key(node_id_1, KeyPurpose::NodeSigning).into_bytes(),
                new_registry.latest_version()
            )
            .is_some());

        assert!(new_registry
            .get(
                &make_node_record_key(node_id_2).into_bytes(),
                new_registry.latest_version()
            )
            .is_some());

        assert!(new_registry
            .get(
                &make_crypto_node_key(node_id_2, KeyPurpose::NodeSigning).into_bytes(),
                new_registry.latest_version()
            )
            .is_some());

        assert_eq!(
            new_registry
                .get_key_family(CRYPTO_RECORD_KEY_PREFIX, new_registry.latest_version())
                .len(),
            8
        );
        assert_eq!(
            new_registry
                .get_key_family(CRYPTO_TLS_CERT_KEY_PREFIX, new_registry.latest_version())
                .len(),
            2
        );
    }
}
