use crate::common::key_family::get_key_family_iter;
use crate::{common::LOG_PREFIX, registry::Registry};
use std::convert::TryFrom;
use std::time::SystemTime;

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use serde::Serialize;

use ic_base_types::PrincipalId;
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_registry_keys::{NODE_OPERATOR_RECORD_KEY_PREFIX, make_node_operator_record_key};
use ic_registry_transport::pb::v1::{RegistryMutation, registry_mutation};

use ic_nervous_system_time_helpers::now_system_time;
use prost::Message;

impl Registry {
    /// Update an existing Node Operator's config without going through the proposal process.
    /// Only the current NP specified in a record can make changes to that record's NP field.
    ///
    /// The new NP must already be the NP of some node operator record. NP principals enter the
    /// registry only through NNS proposals (`AddNodeOperator` and `UpdateNodeOperatorConfig`), so
    /// this method can move a node operator between NPs the NNS has approved, but cannot
    /// introduce a new NP.
    pub fn do_update_node_operator_config_directly(
        &mut self,
        payload: UpdateNodeOperatorConfigDirectlyPayload,
    ) {
        self.do_update_node_operator_config_directly_(
            payload,
            dfn_core::api::caller(),
            now_system_time(),
        )
        .unwrap()
    }

    fn do_update_node_operator_config_directly_(
        &mut self,
        payload: UpdateNodeOperatorConfigDirectlyPayload,
        caller: PrincipalId,
        now: SystemTime,
    ) -> Result<(), String> {
        println!("{LOG_PREFIX}do_update_node_operator_config_directly: {payload:?}");

        // 1. Look up the record of the requested target NodeOperatorRecord.
        let node_operator_id = payload
            .node_operator_id
            .ok_or("No Node Operator specified in the payload".to_string())?;

        let node_operator_record_key = make_node_operator_record_key(node_operator_id).into_bytes();
        let node_operator_record_vec = &self
            .get(&node_operator_record_key, self.latest_version())
            .ok_or(format!(
                "Node Operator record with ID {node_operator_id} not found in the registry."
            ))?
            .value;

        let mut node_operator_record =
            NodeOperatorRecord::decode(node_operator_record_vec.as_slice())
                .map_err(|e| format!("{e:?}"))?;

        // 2. Make sure that the caller is authorized to make the requested changes to node_operator_record.
        if caller
            != PrincipalId::try_from(&node_operator_record.node_provider_principal_id).unwrap()
        {
            return Err(format!(
                "Caller {caller} not equal to the node_provider_princpal_id for this record."
            ));
        }

        // 3. Check Rate Limits
        let current_node_provider = caller;
        let reservation =
            self.try_reserve_capacity_for_node_provider_operation(now, current_node_provider, 1)?;

        // 4. Check that the Node Provider is not being set with the same ID as the Node Operator
        let node_provider_id = payload
            .node_provider_id
            .ok_or("No Node Provider specified in the payload".to_string())?;

        if node_provider_id == node_operator_id {
            return Err(format!(
                "The Node Operator ID cannot be the same as the Node Provider ID: {node_operator_id}"
            ));
        }

        // 5. Check that the new Node Provider is already the Node Provider of some node operator
        //    record. Such principals only enter the registry through NNS proposals, so this keeps
        //    the direct path from introducing a Node Provider the NNS never approved. This also
        //    matters for node rewards, which attribute each node's daily performance to the Node
        //    Provider of its node operator: a Node Provider must not be able to move that
        //    attribution to a principal of its own choosing without the NNS.
        if !self.is_node_provider_of_some_node_operator(node_provider_id) {
            return Err(format!(
                "Node Provider {node_provider_id} is not the node provider of any node operator \
                 record. A node operator can only be reassigned directly to a principal that is \
                 already a node provider in the registry. To assign it to a new node provider, \
                 submit an UpdateNodeOperatorConfig proposal instead."
            ));
        }

        node_operator_record.node_provider_principal_id = node_provider_id.to_vec();

        // 6. Set and execute the mutation
        let mutations = vec![RegistryMutation {
            mutation_type: registry_mutation::Type::Update as i32,
            key: node_operator_record_key,
            value: node_operator_record.encode_to_vec(),
        }];

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);

        if let Err(e) = self.commit_used_capacity_for_node_provider_operation(now, reservation) {
            println!("{LOG_PREFIX}Error committing Rate Limit usage: {e}");
        }

        Ok(())
    }

    /// Whether `principal` is the Node Provider of at least one node operator record at the
    /// latest registry version.
    fn is_node_provider_of_some_node_operator(&self, principal: PrincipalId) -> bool {
        let principal = principal.to_vec();
        get_key_family_iter::<NodeOperatorRecord>(self, NODE_OPERATOR_RECORD_KEY_PREFIX).any(
            |(_node_operator_id, node_operator)| {
                node_operator.node_provider_principal_id == principal
            },
        )
    }
}

/// The payload of a proposal to update an existing Node Operator (without going through the proposal process)
///
/// See /rs/protobuf/def/registry/node_operator/v1/node_operator.proto
#[derive(Clone, Eq, PartialEq, CandidType, Deserialize, Message, Serialize)]
pub struct UpdateNodeOperatorConfigDirectlyPayload {
    /// The principal id of the node operator. This principal is the entity that
    /// is able to add and remove nodes.
    #[prost(message, optional, tag = "1")]
    pub node_operator_id: Option<PrincipalId>,

    /// The principal id of this node's provider.
    #[prost(message, optional, tag = "2")]
    pub node_provider_id: Option<PrincipalId>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::test_helpers::invariant_compliant_registry;
    use crate::mutations::do_add_node_operator::AddNodeOperatorPayload;
    use crate::mutations::node_management::common::get_node_operator_record;
    use maplit::btreemap;

    /// Adds a node operator record with the given principals, the way an `AddNodeOperator`
    /// proposal would.
    fn add_node_operator(
        registry: &mut Registry,
        node_operator_id: PrincipalId,
        node_provider_id: PrincipalId,
    ) {
        let payload = AddNodeOperatorPayload {
            node_operator_principal_id: Some(node_operator_id),
            node_provider_principal_id: Some(node_provider_id),
            node_allowance: 1,
            dc_id: "DC1".to_string(),
            rewardable_nodes: btreemap! { "type1.1".to_string() => 1 },
            ipv6: Some("bar".to_string()),
            max_rewardable_nodes: Some(btreemap! { "type1.2".to_string() => 1 }),
        };

        registry.do_add_node_operator(payload);
    }

    fn node_provider_of(registry: &Registry, node_operator_id: PrincipalId) -> PrincipalId {
        PrincipalId::try_from(
            get_node_operator_record(registry, node_operator_id)
                .unwrap()
                .node_provider_principal_id,
        )
        .unwrap()
    }

    #[test]
    fn test_update_node_operator_config_directly_happy_path() {
        let mut registry = invariant_compliant_registry(0);

        let now = now_system_time();

        let node_operator_id = PrincipalId::new_user_test_id(1_000);
        let node_provider_id = PrincipalId::new_user_test_id(10_000);
        add_node_operator(&mut registry, node_operator_id, node_provider_id);

        // The new node provider is already the node provider of another node operator, i.e. the
        // NNS has approved it before.
        let new_np_id = PrincipalId::new_user_test_id(10_001);
        let other_node_operator_id = PrincipalId::new_user_test_id(1_001);
        add_node_operator(&mut registry, other_node_operator_id, new_np_id);

        let request = UpdateNodeOperatorConfigDirectlyPayload {
            node_operator_id: Some(node_operator_id),
            node_provider_id: Some(new_np_id),
        };

        // The original node provider should be able to change the node operator configuration.
        let caller = node_provider_id;

        registry
            .do_update_node_operator_config_directly_(request, caller, now)
            .unwrap();

        assert_eq!(node_provider_of(&registry, node_operator_id), new_np_id);
        // The other node operator is untouched.
        assert_eq!(
            node_provider_of(&registry, other_node_operator_id),
            new_np_id
        );
    }

    #[test]
    fn test_update_node_operator_config_directly_rejects_unknown_node_provider() {
        let mut registry = invariant_compliant_registry(0);

        let now = now_system_time();

        let node_operator_id = PrincipalId::new_user_test_id(1_000);
        let node_provider_id = PrincipalId::new_user_test_id(10_000);
        add_node_operator(&mut registry, node_operator_id, node_provider_id);

        // No node operator record names this principal as its node provider.
        let unknown_np_id = PrincipalId::new_user_test_id(10_001);

        let request = UpdateNodeOperatorConfigDirectlyPayload {
            node_operator_id: Some(node_operator_id),
            node_provider_id: Some(unknown_np_id),
        };

        // Even the current node provider cannot hand the node operator to an unknown principal.
        let caller = node_provider_id;
        let available_before = registry.get_available_node_provider_op_capacity(caller, now);

        let error = registry
            .do_update_node_operator_config_directly_(request, caller, now)
            .unwrap_err();

        assert!(
            error.contains("not the node provider of any node operator"),
            "unexpected error: {error}"
        );
        assert!(error.contains(&unknown_np_id.to_string()), "{error}");

        // The record is unchanged, and the rejected call did not use up rate limit capacity.
        assert_eq!(
            node_provider_of(&registry, node_operator_id),
            node_provider_id
        );
        assert_eq!(
            registry.get_available_node_provider_op_capacity(caller, now),
            available_before
        );
    }

    #[test]
    fn test_update_node_operator_config_directly_accepts_current_node_provider() {
        let mut registry = invariant_compliant_registry(0);

        let now = now_system_time();

        let node_operator_id = PrincipalId::new_user_test_id(1_000);
        let node_provider_id = PrincipalId::new_user_test_id(10_000);
        add_node_operator(&mut registry, node_operator_id, node_provider_id);

        // Reassigning to the node provider the record already has is a no-op that must still be
        // accepted: that principal is known through this very record.
        let request = UpdateNodeOperatorConfigDirectlyPayload {
            node_operator_id: Some(node_operator_id),
            node_provider_id: Some(node_provider_id),
        };

        registry
            .do_update_node_operator_config_directly_(request, node_provider_id, now)
            .unwrap();

        assert_eq!(
            node_provider_of(&registry, node_operator_id),
            node_provider_id
        );
    }

    #[test]
    fn test_update_node_operator_config_directly_affects_rate_limits() {
        let mut registry = invariant_compliant_registry(0);

        let now = now_system_time();

        let node_operator_id = PrincipalId::new_user_test_id(1_000);
        let node_provider_id = PrincipalId::new_user_test_id(10_000);
        add_node_operator(&mut registry, node_operator_id, node_provider_id);

        let request = UpdateNodeOperatorConfigDirectlyPayload {
            node_operator_id: Some(node_operator_id),
            node_provider_id: Some(node_provider_id),
        };

        // The original node provider should be able to change the node operator configuration.
        let caller = node_provider_id;

        let available = registry.get_available_node_provider_op_capacity(caller, now);

        registry
            .do_update_node_operator_config_directly_(request, caller, now)
            .unwrap();

        let next_available = registry.get_available_node_provider_op_capacity(caller, now);
        assert_eq!(available - 1, next_available);
    }

    #[test]
    fn test_update_node_operator_config_directly_fails_when_rate_limits_exceeded() {
        let mut registry = invariant_compliant_registry(0);

        let now = now_system_time();

        let node_operator_id = PrincipalId::new_user_test_id(1_000);
        let node_provider_id = PrincipalId::new_user_test_id(10_000);
        add_node_operator(&mut registry, node_operator_id, node_provider_id);

        let request = UpdateNodeOperatorConfigDirectlyPayload {
            node_operator_id: Some(node_operator_id),
            node_provider_id: Some(node_provider_id),
        };

        // Max out node provider operations
        let available = registry.get_available_node_provider_op_capacity(node_provider_id, now);
        let reservation = registry
            .try_reserve_capacity_for_node_provider_operation(now, node_provider_id, available)
            .unwrap();
        registry
            .commit_used_capacity_for_node_provider_operation(now, reservation)
            .unwrap();

        // The original node provider should be able to change the node operator configuration.
        let caller = node_provider_id;
        let error = registry
            .do_update_node_operator_config_directly_(request, caller, now)
            .unwrap_err();

        assert_eq!(
            error,
            "Rate Limit Capacity exceeded. Please wait and try again later."
        );
    }
}
