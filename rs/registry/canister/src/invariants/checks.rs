use crate::{
    common::LOG_PREFIX,
    invariants::{
        common::RegistrySnapshot, crypto::check_node_crypto_keys_invariants,
        endpoint::check_endpoint_invariants, node_operator::check_node_operator_invariants,
        replica_version::check_replica_version_invariants,
        routing_table::check_routing_table_invariants, subnet::check_subnet_invariants,
        unassigned_nodes_config::check_unassigned_nodes_config_invariants,
    },
    registry::Registry,
};

use ic_registry_transport::pb::v1::{registry_mutation::Type, RegistryMutation};

impl Registry {
    pub fn check_changelog_version_invariants(&self) {
        println!("{}check_changelog_version_invariants", LOG_PREFIX);

        let mut sorted_changelog_versions = self
            .changelog()
            .iter()
            .map(|(encoded_version, _)| encoded_version.as_version())
            .collect::<Vec<u64>>();
        sorted_changelog_versions.sort_unstable();

        // Check that the 1st version exists
        assert_eq!(
            sorted_changelog_versions[0], 1,
            "No version 1 found in the Registry changelog"
        );

        // Check that changelog versions form an ordered sequence with no missing values
        for (version_a, version_b) in sorted_changelog_versions
            .iter()
            .zip(sorted_changelog_versions.iter().skip(1))
        {
            assert_eq!(
                *version_a,
                version_b - 1,
                "Found a non-sequential version in the Registry changelog, between versions {} and {}",
                version_a,
                version_b
            );
        }
    }

    pub fn check_global_state_invariants(&self, mutations: &[RegistryMutation]) {
        println!(
            "{}check_global_state_invariants: {:?}",
            LOG_PREFIX, mutations
        );

        let snapshot = self.take_latest_snapshot_with_mutations(mutations);

        // Node invariants
        // TODO(NNS1-202): re-enable this check when cd hourly test issues are sorted
        // out.
        // Note that for now, once a node record has been added, it MUST not be
        // modified, as P2P and Transport rely on this data to stay the same

        // Node Operator invariants
        let mut result = check_node_operator_invariants(&snapshot, false);

        // Crypto invariants
        result = result.and(check_node_crypto_keys_invariants(&snapshot));

        // Routing Table invariants
        result = result.and(check_routing_table_invariants(&snapshot));

        // Subnet invariants
        result = result.and(check_subnet_invariants(&snapshot));

        // Replica version invariants
        result = result.and(check_replica_version_invariants(&snapshot, false));

        // Endpoint invariants
        result = result.and(check_endpoint_invariants(&snapshot, false));

        // Unassigned node invariants
        result = result.and(check_unassigned_nodes_config_invariants(&snapshot));

        if let Err(e) = result {
            panic!(
                "{} invariant check failed with message:{}",
                LOG_PREFIX, e.msg
            );
        }
    }

    fn take_latest_snapshot_with_mutations(
        &self,
        mutations: &[RegistryMutation],
    ) -> RegistrySnapshot {
        let mut snapshot = self.take_latest_snapshot();
        for mutation in mutations.iter() {
            let key = &mutation.key;
            match Type::from_i32(mutation.mutation_type).unwrap() {
                Type::Insert | Type::Update | Type::Upsert => {
                    snapshot.insert(key.to_vec(), mutation.value.clone());
                }
                Type::Delete => {
                    snapshot.remove(key);
                }
            }
        }
        snapshot
    }

    fn take_latest_snapshot(&self) -> RegistrySnapshot {
        let mut snapshot = RegistrySnapshot::new();

        for (key, values) in self.store.iter() {
            let registry_value = values.back().unwrap();
            if !registry_value.deletion_marker {
                snapshot.insert(key.to_vec(), registry_value.value.clone());
            }
        }
        snapshot
    }
}

#[cfg(test)]
mod tests {
    use crate::registry::EncodedVersion;

    use super::*;
    use ic_nns_common::registry::encode_or_panic;
    use ic_nns_test_keys::TEST_USER1_PRINCIPAL;
    use ic_protobuf::registry::{
        node_operator::v1::NodeOperatorRecord, routing_table::v1::RoutingTable,
    };
    use ic_registry_keys::{make_node_operator_record_key, make_routing_table_record_key};
    use ic_registry_transport::{
        delete, insert,
        pb::v1::{RegistryAtomicMutateRequest, RegistryMutation},
    };
    use std::collections::BTreeMap;

    fn empty_mutation() -> Vec<u8> {
        encode_or_panic(&RegistryAtomicMutateRequest {
            mutations: vec![RegistryMutation {
                mutation_type: Type::Upsert as i32,
                key: "_".into(),
                value: "".into(),
            }],
            preconditions: vec![],
        })
    }

    #[test]
    fn registry_version_invariants_succeeds_on_sequential_ordering() {
        let mut registry = Registry::new();
        registry
            .changelog
            .insert(EncodedVersion::from(1), empty_mutation());

        registry.check_changelog_version_invariants();

        registry
            .changelog
            .insert(EncodedVersion::from(2), empty_mutation());
        registry
            .changelog
            .insert(EncodedVersion::from(3), empty_mutation());

        registry.check_changelog_version_invariants();
    }

    #[test]
    #[should_panic(expected = "No version 1 found in the Registry changelog")]
    fn registry_version_invariants_panics_on_no_version_1() {
        let mut registry = Registry::new();
        registry
            .changelog
            .insert(EncodedVersion::from(2), empty_mutation());
        registry
            .changelog
            .insert(EncodedVersion::from(3), empty_mutation());
        registry
            .changelog
            .insert(EncodedVersion::from(4), empty_mutation());

        registry.check_changelog_version_invariants();
    }

    #[test]
    #[should_panic(
        expected = "Found a non-sequential version in the Registry changelog, \
                     between versions 2 and 4"
    )]
    fn registry_version_invariants_panics_on_missing_versions() {
        let mut registry = Registry::new();
        registry
            .changelog
            .insert(EncodedVersion::from(1), empty_mutation());
        registry
            .changelog
            .insert(EncodedVersion::from(2), empty_mutation());
        registry
            .changelog
            .insert(EncodedVersion::from(4), empty_mutation());

        registry.check_changelog_version_invariants();
    }

    #[test]
    #[should_panic(expected = "No routing table in snapshot")]
    fn routing_table_invariants_do_not_hold() {
        let key = make_node_operator_record_key(*TEST_USER1_PRINCIPAL);
        let value = encode_or_panic(&NodeOperatorRecord {
            node_operator_principal_id: (*TEST_USER1_PRINCIPAL).to_vec(),
            node_allowance: 0,
            node_provider_principal_id: (*TEST_USER1_PRINCIPAL).to_vec(),
            dc_id: "".into(),
            rewardable_nodes: BTreeMap::new(),
        });
        let registry = Registry::new();
        let mutation = vec![insert(key.as_bytes(), &value)];
        registry.check_global_state_invariants(&mutation);
    }

    #[test]
    fn snapshot_reflects_latest_registry_state() {
        let key1 = make_routing_table_record_key();
        let value1 = encode_or_panic(&RoutingTable { entries: vec![] });

        let key2 = make_node_operator_record_key(*TEST_USER1_PRINCIPAL);
        let value2 = encode_or_panic(&NodeOperatorRecord {
            node_operator_principal_id: (*TEST_USER1_PRINCIPAL).to_vec(),
            node_allowance: 0,
            node_provider_principal_id: (*TEST_USER1_PRINCIPAL).to_vec(),
            dc_id: "".into(),
            rewardable_nodes: BTreeMap::new(),
        });

        let mutations = vec![
            insert(key1.as_bytes(), &value1),
            insert(key2.as_bytes(), &value2),
        ];
        let snapshot = Registry::new().take_latest_snapshot_with_mutations(&mutations);

        let snapshot_data = snapshot.get(key1.as_bytes());
        assert!(snapshot_data.is_some());
        assert_eq!(snapshot_data.unwrap(), &value1);

        let snapshot_data = snapshot.get(key2.as_bytes());
        assert!(snapshot_data.is_some());
        assert_eq!(snapshot_data.unwrap(), &value2);
    }

    #[test]
    fn snapshot_data_are_updated() {
        let key = make_node_operator_record_key(*TEST_USER1_PRINCIPAL);
        let value = encode_or_panic(&NodeOperatorRecord {
            node_operator_principal_id: (*TEST_USER1_PRINCIPAL).to_vec(),
            node_allowance: 0,
            node_provider_principal_id: (*TEST_USER1_PRINCIPAL).to_vec(),
            dc_id: "".into(),
            rewardable_nodes: BTreeMap::new(),
        });
        let mut mutations = vec![insert(key.as_bytes(), &value)];

        let registry = Registry::new();
        let snapshot = registry.take_latest_snapshot_with_mutations(&mutations);

        let snapshot_data = snapshot.get(key.as_bytes());
        assert!(snapshot_data.is_some());
        assert_eq!(snapshot_data.unwrap(), &value);

        mutations.append(&mut vec![delete(key.as_bytes())]);
        let snapshot = registry.take_latest_snapshot_with_mutations(&mutations);
        let snapshot_data = snapshot.get(key.as_bytes());
        assert!(snapshot_data.is_none());
    }
}
