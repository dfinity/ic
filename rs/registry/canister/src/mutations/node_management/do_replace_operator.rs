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

        if required_node_allowance > new_operator_record.node_allowance {
            return Err(format!("{}do_replace_operator: Adding {} nodes would overflow node allowance for node operator {} who has {} remaining", LOG_PREFIX, required_node_allowance, payload.new_operator_id, new_operator_record.node_allowance));
        }

        // Update new node operator record to decrease node allowance
        let new_node_operator_key = make_node_operator_record_key(payload.new_operator_id);
        let updated_node_operator_record = NodeOperatorRecord {
            node_allowance: new_operator_record.node_allowance - required_node_allowance,
            ..new_operator_record.clone()
        };
        mutations.push(update(
            new_node_operator_key,
            updated_node_operator_record.encode_to_vec(),
        ));

        // Update old node operator record to increase node allowance
        let old_node_operator_key = make_node_operator_record_key(payload.old_operator_id);
        let updated_current_node_operator_record = NodeOperatorRecord {
            node_allowance: old_operator_record.node_allowance + required_node_allowance,
            ..old_operator_record.clone()
        };
        mutations.push(update(
            old_node_operator_key,
            updated_current_node_operator_record.encode_to_vec(),
        ));

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
    use ic_registry_canister_api::ReplaceNodeOperatorPayload;
    use ic_types::{NodeId, PrincipalId};

    use crate::registry::Registry;

    fn operator(n: u64) -> PrincipalId {
        PrincipalId::new_user_test_id(n)
    }

    // Convenience function for readability of
    // the test.
    fn caller(n: u64) -> PrincipalId {
        operator(n)
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

    trait AssertErrContains {
        fn assert_err_contains(self, expected: &str);
    }

    impl<T> AssertErrContains for Result<T, String> {
        fn assert_err_contains(self, expected: &str) {
            match self {
                Ok(_) => panic!("Expected error, but got Ok."),
                Err(e) => assert!(
                    e.contains(expected),
                    "Expected error containing '{expected}', but got '{e}'"
                ),
            }
        }
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
}
