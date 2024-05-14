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
        replica_version::check_replica_version_invariants,
        routing_table::{check_canister_migrations_invariants, check_routing_table_invariants},
        subnet::check_subnet_invariants,
        unassigned_nodes_config::check_unassigned_nodes_config_invariants,
    },
    registry::Registry,
};

#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_registry_transport::pb::v1::{registry_mutation::Type, RegistryMutation};

use super::subnet::{
    subnet_record_mutations_from_ecdsa_configs_to_chain_key_configs,
    subnet_record_mutations_from_ecdsa_to_master_public_key_signing_subnet_list,
};

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

    // TODO[NNS1-2986]: Remove this function after the migration has been performed.
    pub fn subnet_record_mutations_from_ecdsa_to_chain_key(&self) -> Vec<RegistryMutation> {
        let snapshot = self.take_latest_snapshot();
        let mut mutations = vec![];
        mutations
            .extend(subnet_record_mutations_from_ecdsa_configs_to_chain_key_configs(&snapshot));
        mutations.extend(
            subnet_record_mutations_from_ecdsa_to_master_public_key_signing_subnet_list(&snapshot),
        );
        mutations
    }

    pub fn check_global_state_invariants(&self, mutations: &[RegistryMutation]) {
        println!(
            "{}check_global_state_invariants: {:?}",
            LOG_PREFIX,
            mutations
                .iter()
                .map(RegistryMutation::to_string)
                .collect::<Vec<_>>()
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

        if let Err(e) = result {
            panic!(
                "{} invariant check failed with message: {}",
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
            if !registry_value.deletion_marker {
                snapshot.insert(key.to_vec(), registry_value.value.clone());
            }
        }
        snapshot
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        common::test_helpers::{
            add_fake_subnet, get_invariant_compliant_subnet_record, invariant_compliant_registry,
            prepare_registry_with_nodes,
        },
        invariants::common::{
            get_all_chain_key_signing_subnet_list_records,
            get_all_ecdsa_signing_subnet_list_records, get_value_from_snapshot,
        },
        registry::EncodedVersion,
    };

    use super::*;
    use ic_base_types::CanisterId;
    use ic_nervous_system_common_test_keys::TEST_USER1_PRINCIPAL;
    use ic_nns_common::registry::encode_or_panic;
    use ic_protobuf::registry::{
        crypto::v1::{
            master_public_key_id, ChainKeySigningSubnetList, EcdsaKeyId, EcdsaSigningSubnetList,
            MasterPublicKeyId,
        },
        node_operator::v1::NodeOperatorRecord,
        routing_table::v1::{
            CanisterMigrations as PbCanisterMigrations, RoutingTable as PbRoutingTable,
        },
        subnet::v1::{ChainKeyConfig, EcdsaConfig, KeyConfig, SubnetListRecord, SubnetRecord},
    };
    use ic_registry_keys::{
        make_canister_migrations_record_key, make_chain_key_signing_subnet_list_key,
        make_ecdsa_signing_subnet_list_key, make_node_operator_record_key,
        make_routing_table_record_key, make_subnet_list_record_key, make_subnet_record_key,
    };
    use ic_registry_routing_table::{CanisterIdRange, CanisterMigrations, RoutingTable};
    use ic_registry_transport::{
        delete, insert,
        pb::v1::{RegistryAtomicMutateRequest, RegistryMutation},
        update, upsert,
    };
    use ic_test_utilities_types::ids::subnet_test_id;
    use ic_types::{subnet_id_into_protobuf, PrincipalId, SubnetId};
    use maplit::btreemap;
    use std::collections::BTreeMap;
    use std::convert::TryFrom;

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
            ipv6: None,
        });
        let registry = Registry::new();
        let mutation = vec![insert(key.as_bytes(), value)];
        registry.check_global_state_invariants(&mutation);
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
        let key1 = make_routing_table_record_key();
        let value1 = encode_or_panic(&routing_table);

        // The canister ID range {0x200:0x2ff} in `canister_migrations` is not hosted by any subnet in trace according to the routing table.
        let canister_migrations = CanisterMigrations::try_from(btreemap! {
        CanisterIdRange{ start: CanisterId::from(0x200), end: CanisterId::from(0x2ff) } => vec![subnet_test_id(1), subnet_test_id(2)],
    }).unwrap();

        let canister_migrations = PbCanisterMigrations::from(canister_migrations);
        let key2 = make_canister_migrations_record_key();
        let value2 = encode_or_panic(&canister_migrations);

        let mutations = vec![
            insert(key1.as_bytes(), value1),
            insert(key2.as_bytes(), value2),
        ];

        let registry = Registry::new();
        registry.check_global_state_invariants(&mutations);
    }

    #[test]
    fn snapshot_reflects_latest_registry_state() {
        let key1 = make_routing_table_record_key();
        let value1 = encode_or_panic(&PbRoutingTable { entries: vec![] });

        let key2 = make_node_operator_record_key(*TEST_USER1_PRINCIPAL);
        let value2 = encode_or_panic(&NodeOperatorRecord {
            node_operator_principal_id: (*TEST_USER1_PRINCIPAL).to_vec(),
            node_allowance: 0,
            node_provider_principal_id: (*TEST_USER1_PRINCIPAL).to_vec(),
            dc_id: "".into(),
            rewardable_nodes: BTreeMap::new(),
            ipv6: None,
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
            ipv6: None,
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

    fn get_subnet_list_record(snapshot: &RegistrySnapshot) -> SubnetListRecord {
        get_value_from_snapshot(snapshot, make_subnet_list_record_key())
            .unwrap_or_else(|| panic!("Could not get subnet list record."))
    }

    fn get_subnet_ids_from_subnet_list_record(snapshot: &RegistrySnapshot) -> Vec<SubnetId> {
        let subnet_list_record = get_subnet_list_record(snapshot);
        subnet_list_record
            .subnets
            .into_iter()
            .map(|s| SubnetId::new(PrincipalId::try_from(s.as_slice()).unwrap()))
            .collect()
    }

    fn get_subnet_record(snapshot: &RegistrySnapshot, subnet_id: SubnetId) -> SubnetRecord {
        get_value_from_snapshot(snapshot, make_subnet_record_key(subnet_id))
            .unwrap_or_else(|| panic!("Could not get subnet record for subnet: {subnet_id}."))
    }

    // TODO[NNS1-2986]: Remove this test after the migration has been performed.
    #[test]
    fn test_subnet_record_ecdsa_to_chain_key_migration_no_ecdsa_config_no_chain_key_config() {
        // Start with an invariant-compliant registry.
        let mut registry = invariant_compliant_registry(0);

        // Get an ID of a subnet.
        let subnet_id = {
            let snapshot = registry.take_latest_snapshot();
            // Assume we have at least one subnet, pick the first one WLOG.
            get_subnet_ids_from_subnet_list_record(&snapshot)[0]
        };

        // Ensure the corresponding subnet record specifies `ecdsa_config` and `chain_key_config`
        // as per Spec A and Spec B.
        let original_subnet_record = {
            let snapshot = registry.take_latest_snapshot();
            let mut subnet_record = get_subnet_record(&snapshot, subnet_id);

            // Spec A: ecdsa_config is unset.
            subnet_record.ecdsa_config = None;

            // Spec B: chain_key_config is unset.
            subnet_record.chain_key_config = None;

            subnet_record
        };

        // Apply the initial mutations.
        let mut registry = {
            let mutation = update(
                make_subnet_record_key(subnet_id).as_bytes(),
                encode_or_panic(&original_subnet_record),
            );
            registry.maybe_apply_mutation_internal(vec![mutation]);
            registry
        };

        // Precondition: Invariants hold initially.
        registry.check_global_state_invariants(&[]);

        // --- Run code under test ---
        {
            let mutations = registry.subnet_record_mutations_from_ecdsa_to_chain_key();
            registry.maybe_apply_mutation_internal(mutations);
        }

        // Postcondition I: Invariants still hold.
        registry.check_global_state_invariants(&[]);

        let subnet_record = {
            let snapshot = registry.take_latest_snapshot();
            get_subnet_record(&snapshot, subnet_id)
        };

        // Postcondition II: The migration worked as expected.
        assert_eq!(
            subnet_record,
            SubnetRecord {
                ecdsa_config: None,
                chain_key_config: None,
                ..original_subnet_record
            }
        );
    }

    // TODO[NNS1-2986]: Remove this test after the migration has been performed.
    #[test]
    fn test_subnet_record_ecdsa_to_chain_key_migration_with_ecdsa_config_no_chain_key_config() {
        // Start with an invariant-complient registry.
        let mut registry = invariant_compliant_registry(0);

        // Get an ID of a subnet.
        let subnet_id = {
            let snapshot = registry.take_latest_snapshot();
            // Assume we have at least one subnet, pick the first one WLOG.
            get_subnet_ids_from_subnet_list_record(&snapshot)[0]
        };

        // Ensure the corresponding subnet record specifies `ecdsa_config` and `chain_key_config`
        // as per Spec A and Spec B.
        let original_subnet_record = {
            let snapshot = registry.take_latest_snapshot();
            let mut subnet_record = get_subnet_record(&snapshot, subnet_id);

            // Spec A: ecdsa_config is set to some non-trivial value.
            subnet_record.ecdsa_config = Some(EcdsaConfig {
                quadruples_to_create_in_advance: 456,
                key_ids: vec![EcdsaKeyId {
                    curve: 1,
                    name: "test_curve".to_string(),
                }],
                max_queue_size: 100,
                signature_request_timeout_ns: Some(10_000),
                idkg_key_rotation_period_ms: Some(20_000),
            });

            // Spec B: chain_key_config is unset.
            subnet_record.chain_key_config = None;

            subnet_record
        };

        // Apply the initial mutations.
        let mut registry = {
            let mutation = update(
                make_subnet_record_key(subnet_id).as_bytes(),
                encode_or_panic(&original_subnet_record),
            );
            registry.maybe_apply_mutation_internal(vec![mutation]);
            registry
        };

        // Precondition: Invariants hold initially.
        registry.check_global_state_invariants(&[]);

        // --- Run code under test ---
        {
            let mutations = registry.subnet_record_mutations_from_ecdsa_to_chain_key();
            registry.maybe_apply_mutation_internal(mutations);
        }

        let subnet_record = get_subnet_record(&registry.take_latest_snapshot(), subnet_id);

        // Postcondition II: The migration worked as expected.
        assert_eq!(
            subnet_record,
            SubnetRecord {
                // This field is the same as before.
                ecdsa_config: Some(EcdsaConfig {
                    quadruples_to_create_in_advance: 456,
                    key_ids: vec![EcdsaKeyId {
                        curve: 1,
                        name: "test_curve".to_string(),
                    }],
                    max_queue_size: 100,
                    signature_request_timeout_ns: Some(10_000),
                    idkg_key_rotation_period_ms: Some(20_000),
                }),
                // This field is set to expected values.
                chain_key_config: Some(ChainKeyConfig {
                    key_configs: vec![KeyConfig {
                        key_id: Some(MasterPublicKeyId {
                            key_id: Some(master_public_key_id::KeyId::Ecdsa(EcdsaKeyId {
                                curve: 1,
                                name: "test_curve".to_string(),
                            })),
                        }),
                        pre_signatures_to_create_in_advance: Some(456),
                        max_queue_size: Some(100),
                    }],
                    signature_request_timeout_ns: Some(10_000),
                    idkg_key_rotation_period_ms: Some(20_000),
                }),
                ..original_subnet_record
            }
        );
    }

    // TODO[NNS1-2986]: Remove this test after the migration has been performed.
    #[test]
    fn test_subnet_record_ecdsa_to_chain_key_migration_with_ecdsa_config_with_matching_chain_key_config(
    ) {
        // Start with an invariant-complient registry.
        let mut registry = invariant_compliant_registry(0);

        // Get an ID of a subnet.
        let subnet_id = {
            let snapshot = registry.take_latest_snapshot();
            // Assume we have at least one subnet, pick the first one WLOG.
            get_subnet_ids_from_subnet_list_record(&snapshot)[0]
        };

        // Ensure the corresponding subnet record specifies `ecdsa_config` and `chain_key_config`
        // as per Spec A and Spec B.
        let original_subnet_record = {
            let snapshot = registry.take_latest_snapshot();
            let mut subnet_record = get_subnet_record(&snapshot, subnet_id);

            // Spec A: ecdsa_config is set to some non-trivial value.
            subnet_record.ecdsa_config = Some(EcdsaConfig {
                quadruples_to_create_in_advance: 456,
                key_ids: vec![EcdsaKeyId {
                    curve: 1,
                    name: "test_curve".to_string(),
                }],
                max_queue_size: 100,
                signature_request_timeout_ns: Some(10_000),
                idkg_key_rotation_period_ms: Some(20_000),
            });

            // Spec B: chain_key_config is set to a non-trivial value that maps to ecdsa_config.
            subnet_record.chain_key_config = Some(ChainKeyConfig {
                key_configs: vec![KeyConfig {
                    key_id: Some(MasterPublicKeyId {
                        key_id: Some(master_public_key_id::KeyId::Ecdsa(EcdsaKeyId {
                            curve: 1,
                            name: "test_curve".to_string(),
                        })),
                    }),
                    pre_signatures_to_create_in_advance: Some(456),
                    max_queue_size: Some(100),
                }],
                signature_request_timeout_ns: Some(10_000),
                idkg_key_rotation_period_ms: Some(20_000),
            });

            subnet_record
        };

        // Apply the initial mutations.
        let mut registry = {
            let mutation = update(
                make_subnet_record_key(subnet_id).as_bytes(),
                encode_or_panic(&original_subnet_record),
            );
            registry.maybe_apply_mutation_internal(vec![mutation]);
            registry
        };

        // Precondition: Invariants hold initially.
        registry.check_global_state_invariants(&[]);

        // --- Run code under test ---
        {
            let mutations = registry.subnet_record_mutations_from_ecdsa_to_chain_key();
            registry.maybe_apply_mutation_internal(mutations);
        }

        let subnet_record = get_subnet_record(&registry.take_latest_snapshot(), subnet_id);

        // Postcondition II: The migration worked as expected (no changes).
        assert_eq!(subnet_record, original_subnet_record);
    }

    // TODO[NNS1-2986]: Remove this test after the migration has been performed.
    #[test]
    #[should_panic(
        expected = "Inconsistency detected between already-present chain_key_config and data from ecdsa_config."
    )]
    fn test_subnet_record_ecdsa_to_chain_key_migration_with_ecdsa_config_with_mismatching_chain_key_config(
    ) {
        // Start with an invariant-complient registry.
        let mut registry = invariant_compliant_registry(0);

        // Get an ID of a subnet.
        let subnet_id = {
            let snapshot = registry.take_latest_snapshot();
            // Assume we have at least one subnet, pick the first one WLOG.
            get_subnet_ids_from_subnet_list_record(&snapshot)[0]
        };

        // Ensure the corresponding subnet record specifies `ecdsa_config` and `chain_key_config`
        // as per Spec A and Spec B.
        let original_subnet_record = {
            let snapshot = registry.take_latest_snapshot();
            let mut subnet_record = get_subnet_record(&snapshot, subnet_id);

            // Spec A: ecdsa_config is set to some non-trivial value.
            subnet_record.ecdsa_config = Some(EcdsaConfig {
                quadruples_to_create_in_advance: 456,
                key_ids: vec![EcdsaKeyId {
                    curve: 1,
                    name: "test_curve".to_string(),
                }],
                max_queue_size: 100,
                signature_request_timeout_ns: Some(10_000),
                idkg_key_rotation_period_ms: Some(20_000),
            });

            // Spec B: chain_key_config is set to a value that does not map to ecdsa_config.
            subnet_record.chain_key_config = Some(ChainKeyConfig {
                key_configs: vec![KeyConfig {
                    key_id: Some(MasterPublicKeyId {
                        key_id: Some(master_public_key_id::KeyId::Ecdsa(EcdsaKeyId {
                            curve: 0,
                            name: "test_curve_1".to_string(),
                        })),
                    }),
                    pre_signatures_to_create_in_advance: Some(455),
                    max_queue_size: Some(99),
                }],
                signature_request_timeout_ns: Some(9_999),
                idkg_key_rotation_period_ms: Some(19_999),
            });

            subnet_record
        };

        // Apply the initial mutations.
        let mut registry = {
            let mutation = update(
                make_subnet_record_key(subnet_id).as_bytes(),
                encode_or_panic(&original_subnet_record),
            );
            registry.maybe_apply_mutation_internal(vec![mutation]);
            registry
        };

        // Precondition: Invariants hold initially.
        registry.check_global_state_invariants(&[]);

        // --- Run code under test ---
        {
            let mutations = registry.subnet_record_mutations_from_ecdsa_to_chain_key();
            registry.maybe_apply_mutation_internal(mutations);
        }
    }

    // TODO[NNS1-2986]: Remove this test after the migration has been performed.
    #[test]
    #[should_panic(
        expected = "ecdsa_config not specified, but chain_key_config is specified in subnet"
    )]
    fn test_subnet_record_ecdsa_to_chain_key_migration_no_ecdsa_config_with_chain_key_config() {
        // Start with an invariant-complient registry.
        let mut registry = invariant_compliant_registry(0);

        // Get an ID of a subnet.
        let subnet_id = {
            let snapshot = registry.take_latest_snapshot();
            // Assume we have at least one subnet, pick the first one WLOG.
            get_subnet_ids_from_subnet_list_record(&snapshot)[0]
        };

        // Ensure the corresponding subnet record specifies `ecdsa_config` and `chain_key_config`
        // as per Spec A and Spec B.
        let original_subnet_record = {
            let snapshot = registry.take_latest_snapshot();
            let mut subnet_record = get_subnet_record(&snapshot, subnet_id);

            // Spec A: ecdsa_config is unset.
            subnet_record.ecdsa_config = None;

            // Spec B: chain_key_config is set to some value.
            subnet_record.chain_key_config = Some(ChainKeyConfig {
                key_configs: vec![KeyConfig {
                    key_id: Some(MasterPublicKeyId {
                        key_id: Some(master_public_key_id::KeyId::Ecdsa(EcdsaKeyId {
                            curve: 1,
                            name: "test_curve".to_string(),
                        })),
                    }),
                    pre_signatures_to_create_in_advance: Some(456),
                    max_queue_size: Some(100),
                }],
                signature_request_timeout_ns: Some(10_000),
                idkg_key_rotation_period_ms: Some(20_000),
            });

            subnet_record
        };

        // Apply the initial mutations.
        let mut registry = {
            let mutation = update(
                make_subnet_record_key(subnet_id).as_bytes(),
                encode_or_panic(&original_subnet_record),
            );
            registry.maybe_apply_mutation_internal(vec![mutation]);
            registry
        };

        // Precondition: Invariants hold initially.
        registry.check_global_state_invariants(&[]);

        // --- Run code under test ---
        {
            let mutations = registry.subnet_record_mutations_from_ecdsa_to_chain_key();
            registry.maybe_apply_mutation_internal(mutations);
        }
    }

    /// Template for test runs
    ///
    /// Creates a registry, then calls `initialize` to let user make changes to it,
    /// evaluates invariants, calls `check` to allow user to make custom checks then
    /// applies the migrations and finally gives the resulting registry back to the user
    // TODO[NNS1-2986]: Remove this test after the migration has been performed.
    fn initialize_then_migrate<F, C>(initialize: F, check: C) -> Registry
    where
        F: FnOnce(SubnetId, &RegistrySnapshot) -> Vec<RegistryMutation>,
        C: FnOnce(SubnetId, &RegistrySnapshot),
    {
        // Start with an invariant-compliant registry.
        let mut registry = invariant_compliant_registry(0);

        // Add another subnet, which is needed for some tests
        {
            let subnet_id = subnet_test_id(1);
            let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 1);
            registry.maybe_apply_mutation_internal(mutate_request.mutations);
            let mut subnet_list_record = registry.get_subnet_list_record();
            let subnet_record = get_invariant_compliant_subnet_record(
                node_ids_and_dkg_pks.keys().copied().collect(),
            );

            let fake_subnet_mutation = add_fake_subnet(
                subnet_id,
                &mut subnet_list_record,
                subnet_record,
                &node_ids_and_dkg_pks,
            );
            registry.maybe_apply_mutation_internal(fake_subnet_mutation);
        }

        // Get an ID of a subnet.
        let subnet_id = {
            let snapshot = registry.take_latest_snapshot();
            // Assume we have at least one subnet, pick the first one WLOG.
            get_subnet_ids_from_subnet_list_record(&snapshot)[0]
        };

        // Execute the initial mutations, i.e. create a state that represents the registry
        // before the migrations
        let mutations = initialize(subnet_id, &mut registry.take_latest_snapshot());
        registry.maybe_apply_mutation_internal(mutations);

        // Precondition: Invariants hold initially.
        registry.check_global_state_invariants(&[]);

        // Do some custom checks, if desired
        check(subnet_id, &mut registry.take_latest_snapshot());

        // --- Run code under test ---
        {
            let mutations = registry.subnet_record_mutations_from_ecdsa_to_chain_key();
            registry.maybe_apply_mutation_internal(mutations);
        }

        // Postcondition I: Invariants still hold.
        registry.check_global_state_invariants(&[]);

        registry
    }

    fn apply_to_subnet_record<F: FnOnce(&mut SubnetRecord)>(
        snapshot: &RegistrySnapshot,
        subnet_id: SubnetId,
        config: F,
    ) -> RegistryMutation {
        let mut subnet_record = get_subnet_record(snapshot, subnet_id);
        config(&mut subnet_record);
        update(
            make_subnet_record_key(subnet_id).as_bytes(),
            encode_or_panic(&subnet_record),
        )
    }

    fn test_ecdsa_config(num_keys: usize) -> EcdsaConfig {
        let key_ids = (0..num_keys)
            .map(|key_num| EcdsaKeyId {
                curve: 1,
                name: format!("test_curve_{}", key_num),
            })
            .collect();

        EcdsaConfig {
            quadruples_to_create_in_advance: 456,
            key_ids,
            max_queue_size: 100,
            signature_request_timeout_ns: Some(10_000),
            idkg_key_rotation_period_ms: Some(20_000),
        }
    }

    /// Add the `subnet_ids` as signing ecdsa subnets of `key`
    fn upsert_ecdsa(key: String, subnet_ids: &[SubnetId]) -> RegistryMutation {
        upsert(
            key,
            encode_or_panic(&EcdsaSigningSubnetList {
                subnets: subnet_ids
                    .iter()
                    .cloned()
                    .map(subnet_id_into_protobuf)
                    .collect(),
            }),
        )
    }

    /// Add the `subnet_ids` as signing chainkey subnets of `key`
    fn upsert_ck(key: String, subnet_ids: &[SubnetId]) -> RegistryMutation {
        upsert(
            key,
            encode_or_panic(&ChainKeySigningSubnetList {
                subnets: subnet_ids
                    .iter()
                    .cloned()
                    .map(subnet_id_into_protobuf)
                    .collect(),
            }),
        )
    }

    /// Check that a signing subnet list present in the ecdsa_subnet_signing_list
    /// will be transfered correctly to the chain_key_signing_list
    // TODO[NNS1-2986]: Remove this test after the migration has been performed.
    #[test]
    fn test_subnet_record_ecdsa_signing_subnet_list_to_chain_key_signing_list() {
        let config = test_ecdsa_config(1);
        let key_id = config.key_ids[0].clone();
        let key_id = ic_management_canister_types::EcdsaKeyId::try_from(key_id).unwrap();

        let ecdsa_key_id = make_ecdsa_signing_subnet_list_key(&key_id);
        let ck_key_id = make_chain_key_signing_subnet_list_key(
            &ic_management_canister_types::MasterPublicKeyId::Ecdsa(key_id),
        );

        let registry = initialize_then_migrate(
            |subnet_id, snapshot| {
                vec![
                    apply_to_subnet_record(snapshot, subnet_id, |record| {
                        record.ecdsa_config = Some(config);
                    }),
                    upsert_ecdsa(ecdsa_key_id.clone(), &[subnet_id]),
                ]
            },
            |_, _| {},
        );

        let snapshot = registry.take_latest_snapshot();
        let ecdsa_signing_subnet_list = get_all_ecdsa_signing_subnet_list_records(&snapshot);
        let ecdsa_entry = ecdsa_signing_subnet_list.get(&ecdsa_key_id).unwrap();

        let ck_signing_subnet_list = get_all_chain_key_signing_subnet_list_records(&snapshot);
        let ck_entry = ck_signing_subnet_list.get(&ck_key_id).unwrap();

        assert_eq!(ecdsa_entry.subnets, ck_entry.subnets);
    }

    /// Check that an entry in the chain key signing subnet list is removed, if no
    /// corresponding entry is present in the ecdsa signing subnet list
    // TODO[NNS1-2986]: Remove this test after the migration has been performed.
    #[test]
    fn test_subnet_record_ecdsa_signing_subnet_list_to_chain_key_signing_list_removal() {
        let config = test_ecdsa_config(1);

        let key_id = config.key_ids[0].clone();
        let key_id = ic_management_canister_types::EcdsaKeyId::try_from(key_id).unwrap();

        let ecdsa_key_id = make_ecdsa_signing_subnet_list_key(&key_id);
        let ck_key_id = make_chain_key_signing_subnet_list_key(
            &ic_management_canister_types::MasterPublicKeyId::Ecdsa(key_id),
        );

        let registry = initialize_then_migrate(
            |subnet_id, snapshot| {
                vec![
                    apply_to_subnet_record(snapshot, subnet_id, |record| {
                        record.ecdsa_config = Some(config);
                    }),
                    upsert_ck(ck_key_id.clone(), &[subnet_id]),
                ]
            },
            |_, snapshot| {
                let ck_signing_subnet_list =
                    get_all_chain_key_signing_subnet_list_records(snapshot);
                assert!(ck_signing_subnet_list.get(&ck_key_id).is_some());
            },
        );

        let snapshot = registry.take_latest_snapshot();
        let ecdsa_signing_subnet_list = get_all_ecdsa_signing_subnet_list_records(&snapshot);
        assert!(ecdsa_signing_subnet_list.get(&ecdsa_key_id).is_none());

        let ck_signing_subnet_list = get_all_chain_key_signing_subnet_list_records(&snapshot);
        assert!(ck_signing_subnet_list.get(&ck_key_id).is_none());
    }

    /// Check that if an entry is present in the both signing subnet lists, the chain_key one gets overwritten
    /// by the ecdsa list
    // TODO[NNS1-2986]: Remove this test after the migration has been performed.
    #[test]
    fn test_subnet_record_ecdsa_signing_subnet_list_to_chain_key_signing_list_override() {
        let config = test_ecdsa_config(1);

        let key_id = config.key_ids[0].clone();
        let key_id = ic_management_canister_types::EcdsaKeyId::try_from(key_id).unwrap();

        let ecdsa_key_id = make_ecdsa_signing_subnet_list_key(&key_id);
        let ck_key_id = make_chain_key_signing_subnet_list_key(
            &ic_management_canister_types::MasterPublicKeyId::Ecdsa(key_id),
        );

        let registry = initialize_then_migrate(
            |subnet_id, snapshot| {
                vec![
                    apply_to_subnet_record(snapshot, subnet_id, |record| {
                        record.ecdsa_config = Some(config.clone());
                    }),
                    apply_to_subnet_record(snapshot, subnet_test_id(1), |record| {
                        record.ecdsa_config = Some(config);
                    }),
                    upsert_ecdsa(ecdsa_key_id.clone(), &[subnet_test_id(1)]),
                    upsert_ck(ck_key_id.clone(), &[subnet_id, subnet_test_id(1)]),
                ]
            },
            |_, snapshot| {
                let ecdsa_subnet_list = get_all_ecdsa_signing_subnet_list_records(snapshot);
                let ck_subnet_list = get_all_chain_key_signing_subnet_list_records(snapshot);

                let ecdsa_subnets = &ecdsa_subnet_list.get(&ecdsa_key_id).unwrap().subnets;
                let ck_subnets = &ck_subnet_list.get(&ck_key_id).unwrap().subnets;
                assert!(ecdsa_subnets != ck_subnets);

                assert_eq!(ecdsa_subnets.len(), 1);
                assert_eq!(ecdsa_subnets[0], subnet_id_into_protobuf(subnet_test_id(1)));

                assert_eq!(ck_subnets.len(), 2);
                assert_eq!(ck_subnets[1], subnet_id_into_protobuf(subnet_test_id(1)));
            },
        );

        let snapshot = registry.take_latest_snapshot();
        let ecdsa_subnet_list = get_all_ecdsa_signing_subnet_list_records(&snapshot);
        let ck_subnet_list = get_all_chain_key_signing_subnet_list_records(&snapshot);

        let ecdsa_subnets = &ecdsa_subnet_list.get(&ecdsa_key_id).unwrap().subnets;
        let ck_subnets = &ck_subnet_list.get(&ck_key_id).unwrap().subnets;

        assert!(ecdsa_subnets == ck_subnets);
        assert_eq!(ecdsa_subnets.len(), 1);
        assert_eq!(ecdsa_subnets[0], subnet_id_into_protobuf(subnet_test_id(1)));

        assert_eq!(ck_subnets.len(), 1);
        assert_eq!(ck_subnets[0], subnet_id_into_protobuf(subnet_test_id(1)));
    }
}
