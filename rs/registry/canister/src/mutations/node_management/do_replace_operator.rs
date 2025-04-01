use crate::{common::LOG_PREFIX, registry::Registry};

#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_protobuf::registry::{node::v1::NodeRecord, node_operator::v1::NodeOperatorRecord};
use ic_registry_canister_api::ReplaceNodeOperatorPayload;
use ic_registry_keys::{make_node_operator_record_key, make_node_record_key};
use ic_registry_transport::update;
use ic_types::PrincipalId;
use prost::Message;

impl Registry {
    /// Replaces the node's operator id with a new operator id
    /// that is in the same data center and is related to the
    /// same node provider.
    pub fn do_replace_operator(
        &mut self,
        payload: ReplaceNodeOperatorPayload,
    ) -> Result<(), String> {
        let caller_id = dfn_core::api::caller();
        println!(
            "{}do_replace_operator: {:?} caller: {:?}",
            LOG_PREFIX, payload, caller_id
        );

        self.do_replace_operator_(payload, caller_id)
    }

    fn do_replace_operator_(
        &mut self,
        payload: ReplaceNodeOperatorPayload,
        caller_id: PrincipalId,
    ) -> Result<(), String> {
        // 0. Ensure there are some nodes sent
        if payload.node_ids.is_empty() {
            return Err(format!(
                "{}do_replace_operator: No nodes to update supplied.",
                LOG_PREFIX
            ));
        }

        // 0. Ensure the node operators are different
        if payload.new_operator_id == payload.old_operator_id {
            return Err(format!(
                "{}do_replace_operator: Old and new operator ids have to differ.",
                LOG_PREFIX
            ));
        }

        // 1. Fetch all node operators related to the caller
        // which is a node provider.
        let operators: Vec<_> = self
            .get_node_operators_and_dcs_of_node_provider(caller_id)
            .map(|operators_and_dcs| operators_and_dcs.into_iter().map(|(_, o)| o).collect())
            .map_err(|e| format!("{}do_replace_operator: {:?}", LOG_PREFIX, e))?;

        if operators.is_empty() {
            return Err(format!(
                "{}do_replace_operator: Unknown node provider {}",
                LOG_PREFIX, caller_id
            ));
        }

        let new_operator_record = find_node_operator_record_for_provider(
            &operators,
            &payload.new_operator_id,
            &caller_id,
        )?;
        let old_operator_record = find_node_operator_record_for_provider(
            &operators,
            &payload.old_operator_id,
            &caller_id,
        )?;

        if new_operator_record.dc_id != old_operator_record.dc_id {
            return Err(format!("{}do_replace_operator: Old node operator and new node operator are in different data centers. Old node operator {} is in {} but the new node operator {} is in {}", LOG_PREFIX,
            payload.old_operator_id, old_operator_record.dc_id, payload.new_operator_id, new_operator_record.dc_id));
        }

        let mut required_node_allowance = 0;
        let mut mutations = vec![];

        for node_id in &payload.node_ids {
            // 1. Check that the node exists in the registry
            let node_record = self.get_node(*node_id).ok_or_else(|| {
                format!(
                    "{}do_replace_operator: Node not found: {}",
                    LOG_PREFIX, node_id
                )
            })?;

            if node_record.node_operator_id == new_operator_record.node_operator_principal_id {
                println!(
                    "{}do_replace_operator: Node {} already belongs to node operator {}",
                    LOG_PREFIX, node_id, payload.new_operator_id
                );
                continue;
            }

            if node_record.node_operator_id != old_operator_record.node_operator_principal_id {
                return Err(format!(
                    "{}do_replace_operator: Node {} does not belong to node operator {}",
                    LOG_PREFIX, node_id, payload.old_operator_id
                ));
            }

            required_node_allowance += 1;
            // Update the node record itself
            let node_key = make_node_record_key(*node_id);
            let updated_node_record = NodeRecord {
                node_operator_id: new_operator_record.node_operator_principal_id.clone(),
                ..node_record
            };
            mutations.push(update(node_key, updated_node_record.encode_to_vec()));
        }

        // Nothing should be done.
        if mutations.is_empty() {
            return Ok(());
        }

        if required_node_allowance > new_operator_record.node_allowance {
            return Err(format!("{}do_replace_operator: Adding {} nodes would overflow node allowance for node operator {} who has {} remaining", LOG_PREFIX, required_node_allowance, payload.new_operator_id, new_operator_record.node_allowance));
        }

        // Update new node operator record to decrease node allowance
        let new_node_operator_key = make_node_operator_record_key(payload.new_operator_id);
        let updated_new_operator_record = NodeOperatorRecord {
            node_allowance: new_operator_record.node_allowance - required_node_allowance,
            ..new_operator_record.clone()
        };
        mutations.push(update(
            new_node_operator_key,
            updated_new_operator_record.encode_to_vec(),
        ));

        // Update old node operator record to increase node allowance
        let old_node_operator_key = make_node_operator_record_key(payload.old_operator_id);
        let updated_old_operator_record = NodeOperatorRecord {
            node_allowance: old_operator_record.node_allowance + required_node_allowance,
            ..old_operator_record.clone()
        };
        mutations.push(update(
            old_node_operator_key,
            updated_old_operator_record.encode_to_vec(),
        ));

        #[cfg(test)]
        self.apply_mutations_for_test(mutations);
        #[cfg(not(test))]
        self.maybe_apply_mutation_internal(mutations);

        println!(
            "{}do_replace_operator: Finished executing payload: {:?}",
            LOG_PREFIX, payload
        );

        Ok(())
    }
}

fn find_node_operator_record_for_provider<'a>(
    operators: &'a [NodeOperatorRecord],
    operator_id: &'a PrincipalId,
    provider: &'a PrincipalId,
) -> Result<&'a NodeOperatorRecord, String> {
    operators
        .iter()
        .find(|o| o.node_operator_principal_id == operator_id.0.as_slice())
        .ok_or_else(|| {
            format!(
                "{}do_replace_operator: Operator {} not found for provider {}",
                LOG_PREFIX, operator_id, provider
            )
        })
}

#[cfg(test)]
mod tests {
    use ic_config::crypto::CryptoConfig;
    use ic_crypto_node_key_generation::generate_node_keys_once;
    use ic_crypto_node_key_validation::ValidNodePublicKeys;
    use ic_protobuf::{
        registry::{
            crypto::v1::{AlgorithmId, PublicKey, X509PublicKeyCert},
            dc::v1::DataCenterRecord,
            node::v1::NodeRecord,
            node_operator::v1::NodeOperatorRecord,
            replica_version::v1::{BlessedReplicaVersions, ReplicaVersionRecord},
            routing_table::v1::{routing_table::Entry, CanisterIdRange, RoutingTable},
            subnet::v1::{SubnetListRecord, SubnetRecord, SubnetType},
        },
        types::v1::SubnetId,
    };
    use ic_registry_canister_api::ReplaceNodeOperatorPayload;
    use ic_registry_keys::{
        make_blessed_replica_versions_key, make_crypto_node_key, make_crypto_tls_cert_key,
        make_data_center_record_key, make_node_operator_record_key, make_node_record_key,
        make_replica_version_key, make_routing_table_record_key, make_subnet_list_record_key,
        make_subnet_record_key,
    };
    use ic_registry_transport::pb::v1::{registry_mutation::Type, RegistryMutation};
    use ic_stable_structures::Storable;
    use ic_types::{crypto::KeyPurpose, CanisterId, NodeId, PrincipalId};

    use crate::{common::test_helpers::invariant_compliant_registry, registry::Registry};
    use prost::Message;

    fn operator(n: u64) -> PrincipalId {
        PrincipalId::new_user_test_id(n)
    }

    // To differentiate between `operator(1)` and `provider(1)`.
    fn provider(n: u64) -> PrincipalId {
        PrincipalId::new_user_test_id(u64::MAX - n)
    }

    // Convenience function for readability of
    // the test.
    fn caller(n: u64) -> PrincipalId {
        provider(n)
    }

    fn node(n: u64) -> NodeId {
        NodeId::new(PrincipalId::new_node_test_id(n))
    }

    fn payload(
        old_operator_id: PrincipalId,
        new_operator_id: PrincipalId,
        node_ids: &[NodeId],
    ) -> ReplaceNodeOperatorPayload {
        ReplaceNodeOperatorPayload {
            node_ids: node_ids.to_vec(),
            new_operator_id,
            old_operator_id,
        }
    }

    trait AssertHelpers {
        #[track_caller]
        fn assert_err_contains(self, expected: &str);

        #[track_caller]
        fn assert_ok(self);
    }

    impl<T> AssertHelpers for Result<T, String> {
        #[track_caller]
        fn assert_err_contains(self, expected: &str) {
            match self {
                Ok(_) => panic!("Expected error, but got Ok."),
                Err(e) => assert!(
                    e.contains(expected),
                    "Expected error containing '{expected}', but got '{e}'"
                ),
            }
        }

        #[track_caller]
        fn assert_ok(self) {
            assert!(
                self.is_ok(),
                "Expected Ok, but got Err: {}",
                self.err().unwrap()
            )
        }
    }

    fn mutation(key: Vec<u8>, value: Vec<u8>) -> RegistryMutation {
        RegistryMutation {
            mutation_type: Type::Upsert as i32,
            key,
            value,
        }
    }

    fn operator_mutation(
        operator: PrincipalId,
        provider: PrincipalId,
        node_allowance: u64,
        dc_id: &str,
    ) -> RegistryMutation {
        let operator_record = NodeOperatorRecord {
            node_operator_principal_id: operator.as_slice().to_vec(),
            node_allowance,
            node_provider_principal_id: provider.as_slice().to_vec(),
            dc_id: dc_id.to_string(),
            ..Default::default()
        };

        mutation(
            make_node_operator_record_key(operator).as_bytes().to_vec(),
            operator_record.encode_to_vec(),
        )
    }

    fn node_mutation(node_id: NodeId, operator: PrincipalId) -> RegistryMutation {
        let node_record = NodeRecord {
            node_operator_id: operator.as_slice().to_vec(),
            ..Default::default()
        };

        mutation(
            make_node_record_key(node_id).as_bytes().to_vec(),
            node_record.encode_to_vec(),
        )
    }

    fn dc_mutation(dc_id: &str) -> RegistryMutation {
        let dc_record = DataCenterRecord {
            id: dc_id.to_string(),
            ..Default::default()
        };

        mutation(
            make_data_center_record_key(dc_id).as_bytes().to_vec(),
            dc_record.encode_to_vec(),
        )
    }

    fn routing_table_mutation() -> RegistryMutation {
        let routing_table = RoutingTable {
            entries: vec![Entry {
                range: Some(CanisterIdRange {
                    start_canister_id: Some(CanisterId::from(0).into()),
                    end_canister_id: Some(CanisterId::from(100).into()),
                }),
                subnet_id: Some(SubnetId {
                    principal_id: Some(PrincipalId::new_subnet_test_id(0).into()),
                }),
            }],
        };

        mutation(
            make_routing_table_record_key().as_bytes().to_vec(),
            routing_table.encode_to_vec(),
        )
    }

    fn generate_valid_node_id() -> ValidNodePublicKeys {
        let (config, _tmp_dir) = CryptoConfig::new_in_temp_dir();
        generate_node_keys_once(&config, None).unwrap()
    }

    fn key_mutation(node: NodeId, key: Vec<u8>, purpose: KeyPurpose) -> RegistryMutation {
        let key = PublicKey {
            version: 0,
            algorithm: AlgorithmId::Ed25519 as i32,
            key_value: key,
            proof_data: None,
            timestamp: Some(42),
        };

        mutation(
            make_crypto_node_key(node, purpose).as_bytes().to_vec(),
            key.encode_to_vec(),
        )
    }

    fn certificate_mutation(node_id: NodeId, certificate: X509PublicKeyCert) -> RegistryMutation {
        mutation(
            make_crypto_tls_cert_key(node_id).as_bytes().to_vec(),
            certificate.encode_to_vec(),
        )
    }

    fn nns() -> RegistryMutation {
        let subnet_record = SubnetRecord {
            start_as_nns: true,
            subnet_type: SubnetType::System as i32,
            membership: vec![PrincipalId::new_node_test_id(0).to_vec()],
            replica_version_id: "123".to_string(),
            ..Default::default()
        };

        mutation(
            make_subnet_record_key(PrincipalId::new_subnet_test_id(0).into())
                .as_bytes()
                .to_vec(),
            subnet_record.encode_to_vec(),
        )
    }

    fn replica_version_mutation() -> RegistryMutation {
        let replica_version_record = ReplicaVersionRecord {
            release_package_sha256_hex:
                "1816ff15e4f9a4937b246699ba9e72e59494eb6e29a71ee1757fb63f9f4ca3bd".to_string(),
            release_package_urls: vec!["https://package.download".to_string()],
            guest_launch_measurement_sha256_hex: None,
        };

        mutation(
            make_replica_version_key("123").to_bytes().to_vec(),
            replica_version_record.encode_to_vec(),
        )
    }

    fn blessed_replica_versions_mutation() -> RegistryMutation {
        let blessed_versions_record = BlessedReplicaVersions {
            blessed_version_ids: vec!["123".to_string()],
        };

        mutation(
            make_blessed_replica_versions_key().to_bytes().to_vec(),
            blessed_versions_record.encode_to_vec(),
        )
    }

    fn subnet_list_record() -> RegistryMutation {
        let subnet_list_record = SubnetListRecord {
            subnets: vec![PrincipalId::new_subnet_test_id(0).as_slice().to_vec()],
        };

        mutation(
            make_subnet_list_record_key().as_bytes().to_vec(),
            subnet_list_record.encode_to_vec(),
        )
    }

    #[test]
    fn disallow_empty_node_ids() {
        let mut registry = Registry::new();

        registry
            .do_replace_operator_(payload(operator(1), operator(2), &[]), caller(99))
            .assert_err_contains("No nodes to update supplied");
    }

    #[test]
    fn disallow_same_operator_ids() {
        let mut registry = Registry::new();

        registry
            .do_replace_operator_(payload(operator(1), operator(1), &[node(1)]), caller(99))
            .assert_err_contains("Old and new operator ids have to differ.");
    }

    #[test]
    fn disallow_unknown_provider() {
        let mut registry = Registry::new();

        registry.apply_mutations_for_test(vec![
            dc_mutation("dc1"),
            operator_mutation(operator(1), provider(1), 10, "dc1"),
            operator_mutation(operator(2), provider(1), 10, "dc1"),
            node_mutation(node(1), operator(1)),
        ]);

        registry
            .do_replace_operator_(payload(operator(1), operator(2), &[node(1)]), caller(99))
            .assert_err_contains("Unknown node provider");
    }

    #[test]
    fn disallow_unknown_operators() {
        let mut registry = Registry::new();

        registry.apply_mutations_for_test(vec![
            dc_mutation("dc1"),
            operator_mutation(operator(1), provider(1), 10, "dc1"),
            operator_mutation(operator(2), provider(1), 10, "dc1"),
            node_mutation(node(1), operator(1)),
        ]);

        // Old operator should not be found in the registry
        registry
            .do_replace_operator_(payload(operator(3), operator(2), &[node(1)]), caller(1))
            .assert_err_contains(&format!(
                "Operator {} not found for provider {}",
                operator(3),
                caller(1)
            ));

        // New operator should not be found in the registry
        registry
            .do_replace_operator_(payload(operator(1), operator(4), &[node(1)]), caller(1))
            .assert_err_contains(&format!(
                "Operator {} not found for provider {}",
                operator(4),
                caller(1)
            ));
    }

    #[test]
    fn disallow_different_dcs_for_operators() {
        let mut registry = Registry::new();

        registry.apply_mutations_for_test(vec![
            dc_mutation("dc1"),
            dc_mutation("dc2"),
            operator_mutation(operator(1), provider(1), 10, "dc1"),
            operator_mutation(operator(2), provider(1), 10, "dc2"),
            node_mutation(node(1), operator(1)),
        ]);

        registry
            .do_replace_operator_(payload(operator(1), operator(2), &[node(1)]), caller(1))
            .assert_err_contains(&format!(
                "Old node operator and new node operator are in different data centers. Old node operator {} is in {} but the new node operator {} is in {}",
                operator(1),
                "dc1",
                operator(2),
                "dc2"
        ));
    }

    #[test]
    fn disallow_unknown_nodes() {
        let mut registry = Registry::new();

        registry.apply_mutations_for_test(vec![
            dc_mutation("dc1"),
            operator_mutation(operator(1), provider(1), 10, "dc1"),
            operator_mutation(operator(2), provider(1), 10, "dc1"),
            node_mutation(node(1), operator(1)),
        ]);

        registry
            .do_replace_operator_(
                payload(operator(1), operator(2), &[node(1), node(2)]),
                caller(1),
            )
            .assert_err_contains(&format!("Node not found: {}", node(2)));
    }

    #[test]
    fn all_nodes_already_on_new_operator() {
        let mut registry = Registry::new();

        registry.apply_mutations_for_test(vec![
            dc_mutation("dc1"),
            operator_mutation(operator(1), provider(1), 10, "dc1"),
            operator_mutation(operator(2), provider(1), 10, "dc1"),
            node_mutation(node(1), operator(2)),
            node_mutation(node(2), operator(2)),
            node_mutation(node(3), operator(2)),
        ]);

        let version_before_replacement = registry.latest_version();
        registry
            .do_replace_operator_(
                payload(operator(1), operator(2), &[node(1), node(2), node(3)]),
                caller(1),
            )
            .assert_ok();

        assert_eq!(registry.latest_version(), version_before_replacement);
    }

    #[test]
    fn disallow_node_not_belonging_to_either_operator() {
        let mut registry = Registry::new();

        registry.apply_mutations_for_test(vec![
            dc_mutation("dc1"),
            operator_mutation(operator(1), provider(1), 10, "dc1"),
            operator_mutation(operator(2), provider(1), 10, "dc1"),
            operator_mutation(operator(3), provider(1), 10, "dc1"),
            node_mutation(node(1), operator(1)),
            node_mutation(node(2), operator(3)),
        ]);

        registry
            .do_replace_operator_(
                payload(operator(1), operator(2), &[node(1), node(2)]),
                caller(1),
            )
            .assert_err_contains(&format!(
                "Node {} does not belong to node operator {}",
                node(2),
                operator(1)
            ));
    }

    #[test]
    fn insufficient_node_allowance() {
        let mut registry = Registry::new();

        registry.apply_mutations_for_test(vec![
            dc_mutation("dc1"),
            operator_mutation(operator(1), provider(1), 10, "dc1"),
            operator_mutation(operator(2), provider(1), 2, "dc1"),
            node_mutation(node(1), operator(1)),
            node_mutation(node(2), operator(1)),
            node_mutation(node(3), operator(1)),
        ]);

        registry
            .do_replace_operator_(
                payload(operator(1), operator(2), &[node(1), node(2), node(3)]),
                caller(1),
            )
            .assert_err_contains(&format!("Adding 3 nodes would overflow node allowance for node operator {} who has 2 remaining", operator(2)));
    }

    #[test]
    fn update_all_records_correctly() {
        let mut registry = invariant_compliant_registry(0);

        registry.apply_mutations_for_test(vec![
            dc_mutation("dc1"),
            operator_mutation(operator(1), provider(1), 10, "dc1"),
            operator_mutation(operator(2), provider(1), 10, "dc1"),
            node_mutation(node(1), operator(1)),
            node_mutation(node(2), operator(1)),
            node_mutation(node(3), operator(1)),
        ]);

        let version_before = registry.latest_version();
        registry
            .do_replace_operator_(
                payload(operator(1), operator(2), &[node(1), node(2), node(3)]),
                caller(1),
            )
            .assert_ok();

        assert!(
            registry.latest_version() == version_before + 1,
            "Expected registry version to increase. Before execution: {}, after execution: {}",
            version_before,
            registry.latest_version()
        );

        for node_id in &[node(1), node(2), node(3)] {
            let node = registry
                .get(
                    make_node_record_key(*node_id).as_bytes(),
                    registry.latest_version(),
                )
                .unwrap();

            let decoded = NodeRecord::decode(node.value.as_slice()).unwrap();
            assert_eq!(node.version, version_before + 1);
            assert_eq!(decoded.node_operator_id, operator(2).as_slice())
        }

        for (operator, allowance) in &[(operator(1), 13), (operator(2), 7)] {
            let operator_record = registry
                .get(
                    make_node_operator_record_key(operator.clone()).as_bytes(),
                    registry.latest_version(),
                )
                .unwrap();

            let decoded = NodeOperatorRecord::decode(operator_record.value.as_slice()).unwrap();
            assert_eq!(operator_record.version, version_before + 1);
            assert_eq!(decoded.node_allowance, *allowance);
        }
    }
}
