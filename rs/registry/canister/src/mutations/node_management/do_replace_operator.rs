use std::collections::BTreeMap;

use crate::{common::LOG_PREFIX, registry::Registry};

#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_protobuf::registry::{node::v1::NodeRecord, node_operator::v1::NodeOperatorRecord};
use ic_registry_canister_api::UpdateNodeOperatorPayload;
use ic_registry_keys::{make_node_operator_record_key, make_node_record_key};
use ic_registry_transport::update;
use ic_types::{NodeId, PrincipalId};
use prost::Message;

impl Registry {
    /// Replaces the node's operator id with a new operator id
    /// that is in the same data center and is related to the
    /// same node provider.
    ///
    /// Expected caller of this function has to be a principal
    /// related to a node provider. All other principals will
    /// be rejected.
    ///
    /// It is expected that all the nodes currently have set
    /// `old_node_operator` as their node operator.
    ///
    /// Both `old_node_operator` and `new_node_operator` must
    /// belong to the same node provider, who is the caller,
    /// and must be within the same data center.
    pub fn do_replace_operator(
        &mut self,
        payload: UpdateNodeOperatorPayload,
    ) -> Result<(), String> {
        let caller_id = dfn_core::api::caller();
        println!(
            "{}do_replace_operator: {:?} caller: {:?}",
            LOG_PREFIX, payload, caller_id
        );

        self.do_replace_operator_with_caller(payload, caller_id)
    }

    fn do_replace_operator_with_caller(
        &mut self,
        payload: UpdateNodeOperatorPayload,
        caller_id: PrincipalId,
    ) -> Result<(), String> {
        payload
            .validate()
            .map_err(|e| format!("{}do_replace_operator: {}", LOG_PREFIX, e))?;

        let node_ids = payload.node_ids.clone().unwrap();
        let old_operator_id = payload.old_operator_id.unwrap();
        let new_operator_id = payload.new_operator_id.unwrap();

        // Fetch operator records and extract
        // the records related to the provided
        // payload.
        let operators = self.maybe_fetch_operators_for_provider(&caller_id)?;

        let (old_operator_record, new_operator_record) = self.maybe_find_operator_records(
            operators,
            &caller_id,
            &old_operator_id,
            &new_operator_id,
        )?;

        let mut valid_mutations: Vec<_> = self
            .maybe_fetch_nodes_to_update(&node_ids, &new_operator_id, &old_operator_id)?
            .into_iter()
            .map(|(node_id, node_record)| {
                let node_key = make_node_record_key(node_id);
                let updated_node_record = NodeRecord {
                    node_operator_id: new_operator_id.as_slice().to_vec(),
                    ..node_record
                };
                update(node_key, updated_node_record.encode_to_vec())
            })
            .collect();

        // Nothing should be done.
        if valid_mutations.is_empty() {
            return Ok(());
        }

        let node_mutations = valid_mutations.len() as u64;

        if node_mutations > new_operator_record.node_allowance {
            return Err(format!("{}do_replace_operator: New operator cannot accept {} nodes due to remaining allowance {}", LOG_PREFIX, node_mutations, new_operator_record.node_allowance));
        }

        // Decrement new operator allowance.
        let new_node_operator_key = make_node_operator_record_key(new_operator_id);
        let updated_new_operator_record = NodeOperatorRecord {
            node_allowance: new_operator_record.node_allowance - node_mutations,
            ..new_operator_record.clone()
        };
        valid_mutations.push(update(
            new_node_operator_key,
            updated_new_operator_record.encode_to_vec(),
        ));

        // Increment old operator allowance.
        let old_node_operator_key = make_node_operator_record_key(old_operator_id);
        let updated_old_operator_record = NodeOperatorRecord {
            node_allowance: old_operator_record.node_allowance + node_mutations,
            ..old_operator_record.clone()
        };
        valid_mutations.push(update(
            old_node_operator_key,
            updated_old_operator_record.encode_to_vec(),
        ));

        self.maybe_apply_mutation_internal(valid_mutations);

        println!(
            "{}do_replace_operator: Finished executing payload: {:?}",
            LOG_PREFIX, payload
        );

        Ok(())
    }

    /// Return the set of node records that belong to `old_operator_id`.
    ///
    /// If the node record is linked to the `new_operator_id`, it will
    /// be filtered from the results, meaning that not all nodes from
    /// `provided_node_ids` have to be returned.
    fn maybe_fetch_nodes_to_update(
        &self,
        provided_node_ids: &Vec<NodeId>,
        new_operator_id: &PrincipalId,
        old_operator_id: &PrincipalId,
    ) -> Result<BTreeMap<NodeId, NodeRecord>, String> {
        let mut node_records = BTreeMap::new();

        for node_id in provided_node_ids {
            let node_record = self.get_node(*node_id).ok_or_else(|| {
                format!(
                    "{}do_replace_operator: Node not found: {}",
                    LOG_PREFIX, node_id
                )
            })?;

            if node_record.node_operator_id.eq(new_operator_id.as_slice()) {
                println!(
                    "{}do_replace_operator: Node {} already belongs to node operator {}",
                    LOG_PREFIX, node_id, new_operator_id
                );
                continue;
            }

            if node_record.node_operator_id.ne(old_operator_id.as_slice()) {
                return Err(format!(
                    "{}do_replace_operator: Node {} does not belong to node operator {}",
                    LOG_PREFIX, node_id, old_operator_id
                ));
            }

            node_records.insert(*node_id, node_record);
        }

        Ok(node_records)
    }

    /// Fetches all the node operator records for a single
    /// node provider.
    fn maybe_fetch_operators_for_provider(
        &self,
        provider_id: &PrincipalId,
    ) -> Result<Vec<NodeOperatorRecord>, String> {
        let operators: Vec<_> = self
            .get_node_operators_and_dcs_of_node_provider(*provider_id)
            .map(|operators_and_dcs| operators_and_dcs.into_iter().map(|(_, o)| o).collect())
            .map_err(|e| format!("{}do_replace_operator: {:?}", LOG_PREFIX, e))?;

        if operators.is_empty() {
            return Err(format!(
                "{}do_replace_operator: Unknown node provider {}",
                LOG_PREFIX, provider_id
            ));
        }

        Ok(operators)
    }

    /// Tries to find node operator records for `old_operator_id` and `new_operator_id` that
    /// have to be within `operators`.
    ///
    /// Function will error out if the node operator records are not within the same data
    /// center which is requred for replacing node operator functionality.
    fn maybe_find_operator_records(
        &self,
        operators: Vec<NodeOperatorRecord>,
        provider: &PrincipalId,
        old_operator_id: &PrincipalId,
        new_operator_id: &PrincipalId,
    ) -> Result<(NodeOperatorRecord, NodeOperatorRecord), String> {
        match (
            find_node_operator_record_for_provider(&operators, old_operator_id, provider),
            find_node_operator_record_for_provider(&operators, new_operator_id, provider),
        ) {
            (Ok(old_operator_record), Ok(new_operator_record))
                if old_operator_record.dc_id != new_operator_record.dc_id =>
            {
                Err(format!("{}do_replace_operator: Old node operator and new node operator are in different data centers. Old node operator {} is in {} but the new node operator {} is in {}", LOG_PREFIX, old_operator_id, old_operator_record.dc_id, new_operator_id, new_operator_record.dc_id))
            }
            (Ok(old_operator_record), Ok(new_operator_record)) => {
                Ok((old_operator_record.clone(), new_operator_record.clone()))
            }
            (Err(e), _) => Err(e),
            (_, Err(e)) => Err(e),
        }
    }
}

/// Helper function which tries to find find a single node operator record
/// within an array of `operators`, returning either a reference to the found
/// record or an error.
fn find_node_operator_record_for_provider<'a>(
    operators: &'a [NodeOperatorRecord],
    operator_id: &'a PrincipalId,
    provider: &'a PrincipalId,
) -> Result<&'a NodeOperatorRecord, String> {
    let operator = operator_id.0.as_slice();

    operators
        .iter()
        .find(|o| o.node_operator_principal_id == operator)
        .ok_or_else(|| {
            format!(
                "{}do_replace_operator: Operator {} not found for provider {}",
                LOG_PREFIX, operator_id, provider
            )
        })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use ic_config::crypto::CryptoConfig;
    use ic_crypto_node_key_generation::generate_node_keys_once;
    use ic_crypto_node_key_validation::ValidNodePublicKeys;
    use ic_nns_test_utils::registry::create_subnet_threshold_signing_pubkey_and_cup_mutations;
    use ic_protobuf::{
        registry::{
            crypto::v1::{AlgorithmId, PublicKey, X509PublicKeyCert},
            dc::v1::DataCenterRecord,
            node::v1::{ConnectionEndpoint, NodeRecord},
            node_operator::v1::NodeOperatorRecord,
            replica_version::v1::{BlessedReplicaVersions, ReplicaVersionRecord},
            routing_table::v1::{routing_table::Entry, CanisterIdRange, RoutingTable},
            subnet::v1::{SubnetListRecord, SubnetRecord, SubnetType},
            unassigned_nodes_config::v1::UnassignedNodesConfigRecord,
        },
        types::v1::SubnetId,
    };
    use ic_registry_canister_api::UpdateNodeOperatorPayload;
    use ic_registry_keys::{
        make_blessed_replica_versions_key, make_crypto_node_key, make_crypto_tls_cert_key,
        make_data_center_record_key, make_node_operator_record_key, make_node_record_key,
        make_replica_version_key, make_routing_table_record_key, make_subnet_list_record_key,
        make_subnet_record_key, make_unassigned_nodes_config_record_key,
    };
    use ic_registry_transport::{pb::v1::RegistryMutation, upsert};
    use ic_stable_structures::Storable;
    use ic_types::{crypto::KeyPurpose, CanisterId, NodeId, PrincipalId, ReplicaVersion};

    use crate::registry::Registry;
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
    ) -> UpdateNodeOperatorPayload {
        UpdateNodeOperatorPayload {
            node_ids: Some(node_ids.to_vec()),
            new_operator_id: Some(new_operator_id),
            old_operator_id: Some(old_operator_id),
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

    fn upsert_node_operator_mutation(
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

        upsert(
            make_node_operator_record_key(operator).as_bytes(),
            operator_record.encode_to_vec(),
        )
    }

    thread_local! {
        /// Needed for invariant checks of each node
        /// because each node has to have unique xnet
        /// and http endpoints
        static NEXT_NODE_NUMBER: RefCell<u8> = const { RefCell::new(0) };
    }

    fn upsert_node_mutation(node_id: NodeId, operator: PrincipalId) -> RegistryMutation {
        let current_node_number = NEXT_NODE_NUMBER.with_borrow_mut(|next_node_number| {
            *next_node_number += 1;
            *next_node_number
        });
        let node_record = NodeRecord {
            node_operator_id: operator.as_slice().to_vec(),
            xnet: Some(ConnectionEndpoint {
                ip_addr: format!("192.{current_node_number}.0.1"),
                port: 8080,
            }),
            http: Some(ConnectionEndpoint {
                ip_addr: format!("192.{current_node_number}.0.2"),
                port: 8080,
            }),
            ..Default::default()
        };

        upsert(
            make_node_record_key(node_id).as_bytes(),
            node_record.encode_to_vec(),
        )
    }

    fn upsert_dc_mutation(dc_id: &str) -> RegistryMutation {
        let dc_record = DataCenterRecord {
            id: dc_id.to_string(),
            ..Default::default()
        };

        upsert(
            make_data_center_record_key(dc_id).as_bytes(),
            dc_record.encode_to_vec(),
        )
    }

    #[test]
    fn disallow_unknown_provider() {
        let mut registry = Registry::new();

        registry.apply_mutations_for_test(vec![
            upsert_dc_mutation("dc1"),
            upsert_node_operator_mutation(operator(1), provider(1), 10, "dc1"),
            upsert_node_operator_mutation(operator(2), provider(1), 10, "dc1"),
            upsert_node_mutation(node(1), operator(1)),
        ]);

        registry
            .do_replace_operator_with_caller(
                payload(operator(1), operator(2), &[node(1)]),
                caller(99),
            )
            .assert_err_contains("Unknown node provider");
    }

    #[test]
    fn disallow_unknown_operators() {
        let mut registry = Registry::new();

        registry.apply_mutations_for_test(vec![
            upsert_dc_mutation("dc1"),
            upsert_node_operator_mutation(operator(1), provider(1), 10, "dc1"),
            upsert_node_operator_mutation(operator(2), provider(1), 10, "dc1"),
            upsert_node_mutation(node(1), operator(1)),
        ]);

        // Old operator should not be found in the registry
        registry
            .do_replace_operator_with_caller(
                payload(operator(3), operator(2), &[node(1)]),
                caller(1),
            )
            .assert_err_contains(&format!(
                "Operator {} not found for provider {}",
                operator(3),
                caller(1)
            ));

        // New operator should not be found in the registry
        registry
            .do_replace_operator_with_caller(
                payload(operator(1), operator(4), &[node(1)]),
                caller(1),
            )
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
            upsert_dc_mutation("dc1"),
            upsert_dc_mutation("dc2"),
            upsert_node_operator_mutation(operator(1), provider(1), 10, "dc1"),
            upsert_node_operator_mutation(operator(2), provider(1), 10, "dc2"),
            upsert_node_mutation(node(1), operator(1)),
        ]);

        registry
            .do_replace_operator_with_caller(payload(operator(1), operator(2), &[node(1)]), caller(1))
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
            upsert_dc_mutation("dc1"),
            upsert_node_operator_mutation(operator(1), provider(1), 10, "dc1"),
            upsert_node_operator_mutation(operator(2), provider(1), 10, "dc1"),
            upsert_node_mutation(node(1), operator(1)),
        ]);

        registry
            .do_replace_operator_with_caller(
                payload(operator(1), operator(2), &[node(1), node(2)]),
                caller(1),
            )
            .assert_err_contains(&format!("Node not found: {}", node(2)));
    }

    #[test]
    fn all_nodes_already_on_new_operator() {
        let mut registry = Registry::new();

        registry.apply_mutations_for_test(vec![
            upsert_dc_mutation("dc1"),
            upsert_node_operator_mutation(operator(1), provider(1), 10, "dc1"),
            upsert_node_operator_mutation(operator(2), provider(1), 10, "dc1"),
            upsert_node_mutation(node(1), operator(2)),
            upsert_node_mutation(node(2), operator(2)),
            upsert_node_mutation(node(3), operator(2)),
        ]);

        let version_before_replacement = registry.latest_version();
        registry
            .do_replace_operator_with_caller(
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
            upsert_dc_mutation("dc1"),
            upsert_node_operator_mutation(operator(1), provider(1), 10, "dc1"),
            upsert_node_operator_mutation(operator(2), provider(1), 10, "dc1"),
            upsert_node_operator_mutation(operator(3), provider(1), 10, "dc1"),
            upsert_node_mutation(node(1), operator(1)),
            upsert_node_mutation(node(2), operator(3)),
        ]);

        registry
            .do_replace_operator_with_caller(
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
            upsert_dc_mutation("dc1"),
            upsert_node_operator_mutation(operator(1), provider(1), 10, "dc1"),
            upsert_node_operator_mutation(operator(2), provider(1), 2, "dc1"),
            upsert_node_mutation(node(1), operator(1)),
            upsert_node_mutation(node(2), operator(1)),
            upsert_node_mutation(node(3), operator(1)),
        ]);

        registry
            .do_replace_operator_with_caller(
                payload(operator(1), operator(2), &[node(1), node(2), node(3)]),
                caller(1),
            )
            .assert_err_contains("New operator cannot accept 3 nodes due to remaining allowance 2");
    }

    #[test]
    fn update_all_records_correctly() {
        let mut registry = Registry::new();

        let first_node = generate_valid_node_id();
        let second_node = generate_valid_node_id();
        let third_node = generate_valid_node_id();
        registry.apply_mutations_for_test(
            vec![
                upsert_dc_mutation("dc1"),
                upsert_node_operator_mutation(operator(1), provider(1), 10, "dc1"),
                upsert_node_operator_mutation(operator(2), provider(1), 10, "dc1"),
                upsert_node_mutation(first_node.node_id(), operator(1)),
                upsert_node_mutation(second_node.node_id(), operator(1)),
                upsert_node_mutation(third_node.node_id(), operator(1)),
            ]
            .into_iter()
            // These are the mutations required to have a compliant registry
            .chain(get_mutations_to_achieve_invariancy(&[
                &first_node,
                &second_node,
                &third_node,
            ]))
            .collect(),
        );

        let version_before = registry.latest_version();
        registry
            .do_replace_operator_with_caller(
                payload(
                    operator(1),
                    operator(2),
                    &[first_node.node_id(), second_node.node_id()],
                ),
                caller(1),
            )
            .assert_ok();

        assert!(
            registry.latest_version() == version_before + 1,
            "Expected registry version to increase. Before execution: {}, after execution: {}",
            version_before,
            registry.latest_version()
        );

        for node_id in &[first_node.node_id(), second_node.node_id()] {
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

        let third_untouched_node = registry
            .get(
                make_node_record_key(third_node.node_id()).as_bytes(),
                registry.latest_version(),
            )
            .unwrap();
        let third_untouched_decoded_node =
            NodeRecord::decode(third_untouched_node.value.as_slice()).unwrap();
        assert_eq!(third_untouched_node.version, version_before);
        assert_eq!(
            third_untouched_decoded_node.node_operator_id,
            operator(1).as_slice()
        );

        for (operator, allowance) in &[(operator(1), 12), (operator(2), 8)] {
            let operator_record = registry
                .get(
                    make_node_operator_record_key(*operator).as_bytes(),
                    registry.latest_version(),
                )
                .unwrap();

            let decoded = NodeOperatorRecord::decode(operator_record.value.as_slice()).unwrap();
            assert_eq!(operator_record.version, version_before + 1);
            assert_eq!(decoded.node_allowance, *allowance);
        }
    }

    // Functions below are used to create an invariant
    // registry. They are not important for the tests above
    fn get_mutations_to_achieve_invariancy(
        nodes: &[&ValidNodePublicKeys],
    ) -> Vec<RegistryMutation> {
        let one_more_nns_node = generate_valid_node_id();
        let mut mutations = vec![
            upsert_routing_table_mutation(),
            upsert_subnet_list_record(),
            upsert_nns(one_more_nns_node.node_id()),
            upsert_replica_version_mutation(),
            upsert_blessed_replica_versions_mutation(),
            upsert_node_mutation(one_more_nns_node.node_id(), operator(150)),
        ];

        let threshold_pk_and_cup_mutations =
            create_subnet_threshold_signing_pubkey_and_cup_mutations(
                PrincipalId::new_subnet_test_id(0).into(),
                &vec![(
                    one_more_nns_node.node_id(),
                    one_more_nns_node.dkg_dealing_encryption_key().clone(),
                )]
                .into_iter()
                .collect(),
            );
        mutations.extend(threshold_pk_and_cup_mutations);

        // One more node is required for
        for node in nodes.iter().chain(&[&one_more_nns_node]) {
            mutations.extend(vec![
                upsert_key_mutation(
                    node.node_id(),
                    node.node_signing_key().key_value.clone(),
                    KeyPurpose::NodeSigning,
                ),
                upsert_key_mutation(
                    node.node_id(),
                    node.committee_signing_key().key_value.clone(),
                    KeyPurpose::CommitteeSigning,
                ),
                upsert_key_mutation(
                    node.node_id(),
                    node.dkg_dealing_encryption_key().key_value.clone(),
                    KeyPurpose::DkgDealingEncryption,
                ),
                upsert_key_mutation(
                    node.node_id(),
                    node.idkg_dealing_encryption_key().key_value.clone(),
                    KeyPurpose::IDkgMEGaEncryption,
                ),
                upsert_certificate_mutation(node.node_id(), node.tls_certificate().clone()),
                upsert_unassigned_nodes_record(),
            ]);
        }

        mutations
    }

    fn upsert_routing_table_mutation() -> RegistryMutation {
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

        upsert(
            make_routing_table_record_key().as_bytes(),
            routing_table.encode_to_vec(),
        )
    }

    fn generate_valid_node_id() -> ValidNodePublicKeys {
        let (config, _tmp_dir) = CryptoConfig::new_in_temp_dir();
        generate_node_keys_once(&config, None).unwrap()
    }

    fn upsert_key_mutation(node: NodeId, key: Vec<u8>, purpose: KeyPurpose) -> RegistryMutation {
        let key = PublicKey {
            version: 0,
            algorithm: AlgorithmId::Ed25519 as i32,
            key_value: key,
            proof_data: None,
            timestamp: Some(42),
        };

        upsert(
            make_crypto_node_key(node, purpose).as_bytes(),
            key.encode_to_vec(),
        )
    }

    fn upsert_certificate_mutation(
        node_id: NodeId,
        certificate: X509PublicKeyCert,
    ) -> RegistryMutation {
        upsert(
            make_crypto_tls_cert_key(node_id).as_bytes(),
            certificate.encode_to_vec(),
        )
    }

    fn upsert_nns(node_id: NodeId) -> RegistryMutation {
        let bytes = node_id.get().into_vec();
        let replica_version = ReplicaVersion::default();
        let subnet_record = SubnetRecord {
            start_as_nns: true,
            subnet_type: SubnetType::System as i32,
            membership: vec![bytes],
            replica_version_id: replica_version.to_string(),
            ..Default::default()
        };

        upsert(
            make_subnet_record_key(PrincipalId::new_subnet_test_id(0).into()).as_bytes(),
            subnet_record.encode_to_vec(),
        )
    }

    fn upsert_replica_version_mutation() -> RegistryMutation {
        let replica_version_record = ReplicaVersionRecord {
            release_package_sha256_hex:
                "1816ff15e4f9a4937b246699ba9e72e59494eb6e29a71ee1757fb63f9f4ca3bd".to_string(),
            release_package_urls: vec!["https://package.download".to_string()],
            guest_launch_measurement_sha256_hex: None,
        };
        let replica_version = ReplicaVersion::default();

        upsert(
            make_replica_version_key(&replica_version).to_bytes(),
            replica_version_record.encode_to_vec(),
        )
    }

    fn upsert_blessed_replica_versions_mutation() -> RegistryMutation {
        let replica_version = ReplicaVersion::default();
        let blessed_versions_record = BlessedReplicaVersions {
            blessed_version_ids: vec![replica_version.to_string()],
        };

        upsert(
            make_blessed_replica_versions_key().to_bytes(),
            blessed_versions_record.encode_to_vec(),
        )
    }

    fn upsert_subnet_list_record() -> RegistryMutation {
        let subnet_list_record = SubnetListRecord {
            subnets: vec![PrincipalId::new_subnet_test_id(0).as_slice().to_vec()],
        };

        upsert(
            make_subnet_list_record_key().as_bytes(),
            subnet_list_record.encode_to_vec(),
        )
    }

    fn upsert_unassigned_nodes_record() -> RegistryMutation {
        let replica_version = ReplicaVersion::default();
        let unassigned_record = UnassignedNodesConfigRecord {
            ssh_readonly_access: vec![],
            replica_version: replica_version.to_string(),
        };

        upsert(
            make_unassigned_nodes_config_record_key().as_bytes(),
            unassigned_record.encode_to_vec(),
        )
    }
}
