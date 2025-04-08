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
    /// Expected caller of this function has to be a node provider.
    /// All other principals will be rejected.
    ///
    /// It is expected that all the nodes currently have set
    /// `old_node_operator` as their node operator.
    ///
    /// Both `old_node_operator` and `new_node_operator` must
    /// belong to the same node provider, who is the caller,
    /// and must be within the same data center.
    pub fn do_update_node_operator(
        &mut self,
        payload: UpdateNodeOperatorPayload,
    ) -> Result<(), String> {
        let caller_id = dfn_core::api::caller();
        println!(
            "{}do_update_node_operator: {:?} caller: {:?}",
            LOG_PREFIX, payload, caller_id
        );

        self.do_update_node_operator_with_caller(payload, caller_id)
    }

    fn do_update_node_operator_with_caller(
        &mut self,
        payload: UpdateNodeOperatorPayload,
        caller_id: PrincipalId,
    ) -> Result<(), String> {
        payload
            .validate()
            .map_err(|e| format!("{}do_update_node_operator: {}", LOG_PREFIX, e))?;

        let UpdateNodeOperatorPayload {
            node_ids: Some(ref node_ids),
            new_operator_id: Some(new_operator_id),
            old_operator_id: Some(old_operator_id),
        } = payload
        else {
            unreachable!("After validation this should not happen.")
        };

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

        // This is the main source of mutations in this operation, where we update all
        // node records that need to reference the new node operator ID. Each affected
        // node results in a mutation to update its corresponding record.
        //
        // In total, there are only two other mutations outside of this:
        //   1. Incrementing the allowance of the old node operator.
        //   2. Decrementing the allowance of the new node operator.
        //
        // Together, these changes form the complete set of mutations required for
        // reassigning nodes from one operator to another.
        let mut valid_mutations: Vec<_> = self
            .maybe_fetch_nodes_to_update(node_ids, &new_operator_id, &old_operator_id)?
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
            return Err(format!(
                "{}do_update_node_operator: New operator cannot accept {} \
                 nodes due to remaining allowance {}",
                LOG_PREFIX, node_mutations, new_operator_record.node_allowance
            ));
        }

        // Decrement new operator allowance.
        let new_node_operator_key = make_node_operator_record_key(new_operator_id);
        let updated_new_operator_record = NodeOperatorRecord {
            node_allowance: new_operator_record
                .node_allowance
                .saturating_sub(node_mutations),
            ..new_operator_record.clone()
        };
        valid_mutations.push(update(
            new_node_operator_key,
            updated_new_operator_record.encode_to_vec(),
        ));

        // Increment old operator allowance.
        let old_node_operator_key = make_node_operator_record_key(old_operator_id);
        let updated_old_operator_record = NodeOperatorRecord {
            node_allowance: old_operator_record
                .node_allowance
                .saturating_add(node_mutations),
            ..old_operator_record.clone()
        };
        valid_mutations.push(update(
            old_node_operator_key,
            updated_old_operator_record.encode_to_vec(),
        ));

        self.maybe_apply_mutation_internal(valid_mutations);

        println!(
            "{}do_update_node_operator: Finished executing payload: {:?}",
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
        let mut result = BTreeMap::new();

        for node_id in provided_node_ids {
            let node_record = self.get_node(*node_id).ok_or_else(|| {
                format!(
                    "{}do_update_node_operator: Node not found: {}",
                    LOG_PREFIX, node_id
                )
            })?;

            if node_record.node_operator_id == new_operator_id.as_slice() {
                // Skip nodes that are already under the new node operator.
                println!(
                    "{}do_update_node_operator: Node {} already belongs to node operator {}",
                    LOG_PREFIX, node_id, new_operator_id
                );
                continue;
            }

            if node_record.node_operator_id != old_operator_id.as_slice() {
                return Err(format!(
                    "{}do_update_node_operator: Node {} does not belong to node operator {}",
                    LOG_PREFIX, node_id, old_operator_id
                ));
            }

            result.insert(*node_id, node_record);
        }

        Ok(result)
    }

    /// Fetches all the node operator records for a single
    /// node provider.
    fn maybe_fetch_operators_for_provider(
        &self,
        provider_id: &PrincipalId,
    ) -> Result<Vec<NodeOperatorRecord>, String> {
        let operators: Vec<_> = self
            .get_node_operators_and_dcs_of_node_provider(*provider_id)
            .map_err(|e| format!("{}do_update_node_operator: {:?}", LOG_PREFIX, e))?
            .into_iter()
            .map(|(_, o)| o)
            .collect();

        if operators.is_empty() {
            return Err(format!(
                "{}do_update_node_operator: Unknown node provider {}",
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
        let old_operator_record =
            find_node_operator_record_for_provider(&operators, old_operator_id, provider)?;
        let new_operator_record =
            find_node_operator_record_for_provider(&operators, new_operator_id, provider)?;

        if old_operator_record.dc_id != new_operator_record.dc_id {
            return Err(format!(
                "{}do_update_node_operator: Old node operator and new node operator \
                    are in different data centers. Old node operator {} is \
                    in {} but the new node operator {} is in {}",
                LOG_PREFIX,
                old_operator_id,
                old_operator_record.dc_id,
                new_operator_id,
                new_operator_record.dc_id
            ));
        }

        Ok((old_operator_record.clone(), new_operator_record.clone()))
    }
}

/// Helper function which tries to find find a single node operator record
/// within an array of `operators`, returning either a reference to the found
/// record or an error.
fn find_node_operator_record_for_provider<'a>(
    operators: &'a [NodeOperatorRecord],
    operator_id: &PrincipalId,
    provider: &PrincipalId,
) -> Result<&'a NodeOperatorRecord, String> {
    let operator = operator_id.0.as_slice();

    operators
        .iter()
        .find(|o| o.node_operator_principal_id == operator)
        .ok_or_else(|| {
            format!(
                "{}do_update_node_operator: Operator {} not found for provider {}",
                LOG_PREFIX, operator_id, provider
            )
        })
}

#[cfg(test)]
mod tests {
    use ic_protobuf::registry::{
        dc::v1::DataCenterRecord, node::v1::NodeRecord, node_operator::v1::NodeOperatorRecord,
    };
    use ic_registry_canister_api::UpdateNodeOperatorPayload;
    use ic_registry_keys::{
        make_data_center_record_key, make_node_operator_record_key, make_node_record_key,
    };
    use ic_registry_transport::{pb::v1::RegistryMutation, upsert};
    use ic_types::{NodeId, PrincipalId};

    use crate::{
        common::test_helpers::{
            invariant_compliant_registry, prepare_registry_with_nodes_and_node_operator_id,
        },
        registry::Registry,
    };
    use prost::Message;

    fn operator(operator_index: u64) -> PrincipalId {
        PrincipalId::new_user_test_id(operator_index)
    }

    // To differentiate between `operator(1)` and `provider(1)`.
    fn provider(provider_index: u64) -> PrincipalId {
        PrincipalId::new_user_test_id(u64::MAX - provider_index)
    }

    // Convenience function for readability of
    // the test.
    fn caller(provider_index: u64) -> PrincipalId {
        provider(provider_index)
    }

    fn node(node_index: u64) -> NodeId {
        NodeId::new(PrincipalId::new_node_test_id(node_index))
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

    fn upsert_node_mutation(node_id: NodeId, operator: PrincipalId) -> RegistryMutation {
        let node_record = NodeRecord {
            node_operator_id: operator.as_slice().to_vec(),
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
            .do_update_node_operator_with_caller(
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
            .do_update_node_operator_with_caller(
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
            .do_update_node_operator_with_caller(
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
            .do_update_node_operator_with_caller(payload(operator(1), operator(2), &[node(1)]), caller(1))
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
            .do_update_node_operator_with_caller(
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
            .do_update_node_operator_with_caller(
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
            .do_update_node_operator_with_caller(
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
            .do_update_node_operator_with_caller(
                payload(operator(1), operator(2), &[node(1), node(2), node(3)]),
                caller(1),
            )
            .assert_err_contains("New operator cannot accept 3 nodes due to remaining allowance 2");
    }

    #[test]
    fn update_all_records_correctly() {
        let mut registry = invariant_compliant_registry(0);

        let (atomic_request, mut node_ids) =
            prepare_registry_with_nodes_and_node_operator_id(1, 3, operator(1));

        registry.maybe_apply_mutation_internal(atomic_request.mutations);
        let nodes_latest_version = registry.latest_version();

        registry.maybe_apply_mutation_internal(vec![
            upsert_dc_mutation("dc1"),
            upsert_node_operator_mutation(operator(1), provider(1), 10, "dc1"),
            upsert_node_operator_mutation(operator(2), provider(1), 10, "dc1"),
        ]);

        let first_node = node_ids.pop_first().map(|(key, _)| key).unwrap();
        let second_node = node_ids.pop_first().map(|(key, _)| key).unwrap();
        let third_node = node_ids.pop_first().map(|(key, _)| key).unwrap();

        let version_before = registry.latest_version();
        registry
            .do_update_node_operator_with_caller(
                payload(operator(1), operator(2), &[first_node, second_node]),
                caller(1),
            )
            .assert_ok();

        assert!(
            registry.latest_version() == version_before + 1,
            "Expected registry version to increase. Before execution: {}, after execution: {}",
            version_before,
            registry.latest_version()
        );

        for node_id in &[first_node, second_node] {
            let node = registry
                .get(
                    make_node_record_key(*node_id).as_bytes(),
                    registry.latest_version(),
                )
                .unwrap();

            let decoded = NodeRecord::decode(node.value.as_slice()).unwrap();
            assert_eq!(
                node.version,
                version_before + 1,
                "Node {} version didn't progress",
                node_id
            );
            assert_eq!(
                decoded.node_operator_id,
                operator(2).as_slice(),
                "Node {} doesn't have expected node operator id: It has {} but should have {}",
                node_id,
                PrincipalId::new_self_authenticating(&decoded.node_operator_id),
                operator(2)
            )
        }

        let third_untouched_node = registry
            .get(
                make_node_record_key(third_node).as_bytes(),
                registry.latest_version(),
            )
            .unwrap();
        let third_untouched_decoded_node =
            NodeRecord::decode(third_untouched_node.value.as_slice()).unwrap();
        assert_eq!(
            third_untouched_node.version, nodes_latest_version,
            "Node {} has version {} but should have version {} since its node operator shouldn't have been updated",
            third_node, third_untouched_node.version, nodes_latest_version
        );
        assert_eq!(
            third_untouched_decoded_node.node_operator_id,
            operator(1).as_slice(),
            "Node {} has operator updated to {} but it should be {}",
            third_node,
            PrincipalId::new_self_authenticating(&third_untouched_decoded_node.node_operator_id),
            operator(1)
        );

        for (operator, allowance) in &[(operator(1), 12), (operator(2), 8)] {
            let operator_record = registry
                .get(
                    make_node_operator_record_key(*operator).as_bytes(),
                    registry.latest_version(),
                )
                .unwrap();

            let decoded = NodeOperatorRecord::decode(operator_record.value.as_slice()).unwrap();
            assert_eq!(operator_record.version, version_before + 1, "Node operator version remained unchanged: Operator {} has version {} but it should be {}", operator, operator_record.version, version_before + 1);
            assert_eq!(
                decoded.node_allowance, *allowance,
                "Node operator doesn't have correct allowance: Operator {} has {} but should be {}",
                operator, decoded.node_allowance, allowance
            );
        }
    }
}
