use crate::{
    common::LOG_PREFIX,
    invariants::{
        api_boundary_node::check_api_boundary_node_invariants,
        assignment::check_node_assignment_invariants,
        common::RegistrySnapshot,
        crypto::check_node_crypto_keys_invariants,
        endpoint::check_endpoint_invariants,
        firewall::check_firewall_invariants,
        hostos_version::check_hostos_version_invariants,
        node_operator::check_node_operator_invariants,
        node_record::check_node_record_invariants,
        replica_version::check_replica_version_invariants,
        routing_table::{check_canister_migrations_invariants, check_routing_table_invariants},
        subnet::check_subnet_invariants,
        unassigned_nodes_config::check_unassigned_nodes_config_invariants,
    },
    registry::Registry,
    storage::with_chunks,
};

#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_nervous_system_string::clamp_debug_len;
use ic_registry_canister_chunkify::dechunkify;
use ic_registry_transport::pb::v1::{
    RegistryMutation, high_capacity_registry_value, registry_mutation::Type,
};

impl Registry {
    pub fn check_changelog_version_invariants(&self) {
        println!("{LOG_PREFIX}check_changelog_version_invariants");

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
                "Found a non-sequential version in the Registry changelog, between versions {version_a} and {version_b}"
            );
        }
    }

    pub fn check_global_state_invariants(&self, mutations: &[RegistryMutation]) {
        println!(
            "{}check_global_state_invariants: {}",
            LOG_PREFIX,
            clamp_debug_len(
                &(mutations
                    .iter()
                    .map(RegistryMutation::to_string)
                    .collect::<Vec<_>>()),
                /* max_len = */ 2000
            )
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

        // Node assignment invariants
        result = result.and(check_node_assignment_invariants(&snapshot));

        // Routing Table invariants
        result = result.and(check_routing_table_invariants(&snapshot));

        // Canister migrations invariants
        result = result.and(check_canister_migrations_invariants(&snapshot));

        // Subnet invariants
        result = result.and(check_subnet_invariants(&snapshot));

        // Replica version invariants
        result = result.and(check_replica_version_invariants(&snapshot));

        // API Boundary Node invariant
        result = result.and(check_api_boundary_node_invariants(&snapshot));

        // HostOS version invariants
        result = result.and(check_hostos_version_invariants(&snapshot));

        // Endpoint invariants
        result = result.and(check_endpoint_invariants(&snapshot, false));

        // Firewall invariants
        result = result.and(check_firewall_invariants(&snapshot));

        // Unassigned node invariants
        result = result.and(check_unassigned_nodes_config_invariants(&snapshot));

        // NodeRecord invariants.
        result = result.and(check_node_record_invariants(&snapshot));

        if let Err(e) = result {
            panic!(
                "{}invariant check failed with message: {}",
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
            match Type::try_from(mutation.mutation_type).unwrap() {
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

            let content = match registry_value.content.clone() {
                Some(ok) => ok,
                None => high_capacity_registry_value::Content::Value(vec![]),
            };

            let value: Vec<u8> = match content {
                high_capacity_registry_value::Content::DeletionMarker(deletion_marker) => {
                    if deletion_marker {
                        continue;
                    }
                    // Treat deletion_marker = false the same as Value(vec![]).
                    vec![]
                }

                high_capacity_registry_value::Content::Value(value) => value,

                high_capacity_registry_value::Content::LargeValueChunkKeys(
                    large_value_chunk_keys,
                ) => with_chunks(|chunks| dechunkify(&large_value_chunk_keys, chunks)),
            };

            snapshot.insert(key.to_vec(), value);
        }

        snapshot
    }
}

#[cfg(test)]
mod tests {
    use crate::registry::EncodedVersion;

    use super::*;
    use ic_base_types::CanisterId;
    use ic_nervous_system_common_test_keys::TEST_USER1_PRINCIPAL;
    use ic_protobuf::registry::{
        node_operator::v1::NodeOperatorRecord,
        routing_table::v1::{
            CanisterMigrations as PbCanisterMigrations, RoutingTable as PbRoutingTable,
        },
    };
    use ic_registry_keys::{
        make_canister_migrations_record_key, make_canister_ranges_key,
        make_node_operator_record_key,
    };
    use ic_registry_routing_table::{CanisterIdRange, CanisterMigrations, RoutingTable};
    use ic_registry_transport::{
        delete, insert,
        pb::v1::{RegistryAtomicMutateRequest, RegistryMutation},
    };
    use ic_test_utilities_types::ids::subnet_test_id;
    use maplit::btreemap;
    use prost::Message;
    use std::collections::BTreeMap;
    use std::convert::TryFrom;

    fn empty_mutation() -> Vec<u8> {
        RegistryAtomicMutateRequest {
            mutations: vec![RegistryMutation {
                mutation_type: Type::Upsert as i32,
                key: "_".into(),
                value: "".into(),
            }],
            preconditions: vec![],
        }
        .encode_to_vec()
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
    #[should_panic(expected = "not hosted by any subnet")]
    fn invalid_canister_migrations_invariants_check_panic() {
        let routing_table = RoutingTable::try_from(btreemap! {
            CanisterIdRange{ start: CanisterId::from(0x0), end: CanisterId::from(0xff) } => subnet_test_id(1),
            CanisterIdRange{ start: CanisterId::from(0x100), end: CanisterId::from(0x1ff) } => subnet_test_id(2),
            CanisterIdRange{ start: CanisterId::from(0x200), end: CanisterId::from(0x2ff) } => subnet_test_id(3),
        }).unwrap();

        let routing_table = PbRoutingTable::from(routing_table);
        let routing_table_shard_key = make_canister_ranges_key(CanisterId::from(0));
        let routing_table_value = routing_table.encode_to_vec();

        // The canister ID range {0x200:0x2ff} in `canister_migrations` is not hosted by any subnet in trace according to the routing table.
        let canister_migrations = CanisterMigrations::try_from(btreemap! {
            CanisterIdRange{ start: CanisterId::from(0x200), end: CanisterId::from(0x2ff) } => vec![subnet_test_id(1), subnet_test_id(2)],
        }).unwrap();

        let canister_migrations = PbCanisterMigrations::from(canister_migrations);
        let canister_migrations_key = make_canister_migrations_record_key();
        let canister_migrations_value = canister_migrations.encode_to_vec();

        let mutations = vec![
            insert(routing_table_shard_key.as_bytes(), &routing_table_value),
            insert(
                canister_migrations_key.as_bytes(),
                &canister_migrations_value,
            ),
        ];

        let registry = Registry::new();
        registry.check_global_state_invariants(&mutations);
    }

    #[test]
    fn snapshot_reflects_latest_registry_state() {
        let routing_table_shard_key = make_canister_ranges_key(CanisterId::from(0));
        let routing_table_value = PbRoutingTable { entries: vec![] }.encode_to_vec();

        let node_operator_key = make_node_operator_record_key(*TEST_USER1_PRINCIPAL);
        let node_operator_value = NodeOperatorRecord {
            node_operator_principal_id: (*TEST_USER1_PRINCIPAL).to_vec(),
            node_allowance: 0,
            node_provider_principal_id: (*TEST_USER1_PRINCIPAL).to_vec(),
            dc_id: "".into(),
            rewardable_nodes: BTreeMap::new(),
            ipv6: None,
            max_rewardable_nodes: BTreeMap::new(),
        }
        .encode_to_vec();

        let mutations = vec![
            insert(routing_table_shard_key.as_bytes(), &routing_table_value),
            insert(node_operator_key.as_bytes(), &node_operator_value),
        ];
        let snapshot = Registry::new().take_latest_snapshot_with_mutations(&mutations);

        let snapshot_data = snapshot.get(routing_table_shard_key.as_bytes());
        assert!(snapshot_data.is_some());
        assert_eq!(snapshot_data.unwrap(), &routing_table_value);

        let snapshot_data = snapshot.get(node_operator_key.as_bytes());
        assert!(snapshot_data.is_some());
        assert_eq!(snapshot_data.unwrap(), &node_operator_value);
    }

    #[test]
    fn snapshot_data_are_updated() {
        let key = make_node_operator_record_key(*TEST_USER1_PRINCIPAL);
        let value = NodeOperatorRecord {
            node_operator_principal_id: (*TEST_USER1_PRINCIPAL).to_vec(),
            node_allowance: 0,
            node_provider_principal_id: (*TEST_USER1_PRINCIPAL).to_vec(),
            dc_id: "".into(),
            rewardable_nodes: BTreeMap::new(),
            ipv6: None,
            max_rewardable_nodes: BTreeMap::new(),
        }
        .encode_to_vec();
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

#[cfg(feature = "canbench-rs")]
mod benches;
