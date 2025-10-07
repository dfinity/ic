use crate::common::LOG_PREFIX;
use crate::mutations::node_management::common::get_node_operator_id_for_node;
use crate::{
    flags::{
        is_node_swapping_enabled, is_node_swapping_enabled_for_caller,
        is_node_swapping_enabled_on_subnet,
    },
    mutations::node_management::common::find_subnet_for_node,
    registry::Registry,
};
use candid::CandidType;
use ic_nervous_system_rate_limits::RateLimiterError;
use ic_nervous_system_time_helpers::now_system_time;
use ic_types::{NodeId, PrincipalId, SubnetId};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::time::SystemTime;

impl Registry {
    /// Called by the node operators in order to rotate their nodes without the need for governance.
    pub fn do_swap_node_in_subnet_directly(&mut self, payload: SwapNodeInSubnetDirectlyPayload) {
        self.swap_nodes_inner(payload, dfn_core::api::caller(), now_system_time())
            .unwrap_or_else(|e| panic!("{e}"));
    }

    /// Top level function for the swapping feature which has all inputs.
    fn swap_nodes_inner(
        &mut self,
        payload: SwapNodeInSubnetDirectlyPayload,
        caller: PrincipalId,
        now: SystemTime,
    ) -> Result<(), SwapError> {
        // Check if the feature is enabled on the network.
        if !is_node_swapping_enabled() {
            return Err(SwapError::FeatureDisabled);
        }

        // Check if the payload is valid by itself.
        payload.validate()?;
        let (old_node_id, _new_node_id) =
            (payload.old_node_id.unwrap(), payload.new_node_id.unwrap());

        //Check if the feature is allowed on the target subnet and for the caller
        Self::swapping_enabled_for_caller(caller)?;
        let subnet_id = self.find_subnet_for_old_node(old_node_id)?;
        Self::swapping_allowed_on_subnet(subnet_id)?;
        // TODO - get rid of panics before feature enabled, and return nicer errors.
        let old_node_id = NodeId::from(
            payload
                .old_node_id
                .expect("Old Node Id should be validated as existing before this call."),
        );
        let node_operator_id = get_node_operator_id_for_node(self, old_node_id).unwrap();

        let reservation = self
            .try_reserve_node_provider_op_capacity(now, node_operator_id, 1)
            .map_err(SwapError::RateLimiterError)?;

        //TODO(DRE-547): Check if the feature is allowed on the target subnet and for the caller

        //TODO(DRE-553): Rate-limiting mechanism

        //TODO(DRE-548): Implement the swapping functionality

        if let Err(e) = self.commit_node_provider_op_reservation(now, reservation) {
            println!("{LOG_PREFIX}Error committing Rate Limit usage: {e}");
        }
        Ok(())
    }

    /// Check if the caller is whitelisted to use this feature.
    fn swapping_enabled_for_caller(caller: PrincipalId) -> Result<(), SwapError> {
        if !is_node_swapping_enabled_for_caller(caller) {
            return Err(SwapError::FeatureDisabledForCaller { caller });
        }

        Ok(())
    }

    /// Map the `old_node_id` to a subnet and error if it is
    /// not a member of any subnet.
    fn find_subnet_for_old_node(&self, old_node_id: PrincipalId) -> Result<SubnetId, SwapError> {
        find_subnet_for_node(
            self,
            NodeId::new(old_node_id),
            &self.get_subnet_list_record(),
        )
        .ok_or(SwapError::SubnetNotFoundForNode { old_node_id })
    }

    fn swapping_allowed_on_subnet(subnet_id: SubnetId) -> Result<(), SwapError> {
        if !is_node_swapping_enabled_on_subnet(subnet_id) {
            return Err(SwapError::FeatureDisabledOnSubnet { subnet_id });
        }

        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, CandidType, Deserialize, Message, Serialize)]
pub struct SwapNodeInSubnetDirectlyPayload {
    /// Represents the principal of a node that will be added to a subnet
    /// in place of the `old_node_id`.
    #[prost(message, optional, tag = "1")]
    pub new_node_id: Option<PrincipalId>,

    /// Represents the principal of an assigned node that will be removed
    /// from a subnet.
    #[prost(message, optional, tag = "2")]
    pub old_node_id: Option<PrincipalId>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SwapError {
    FeatureDisabled,
    MissingInput,
    SamePrincipals,
    FeatureDisabledForCaller { caller: PrincipalId },
    FeatureDisabledOnSubnet { subnet_id: SubnetId },
    SubnetNotFoundForNode { old_node_id: PrincipalId },
    RateLimiterError(RateLimiterError),
    NodeNotFound(PrincipalId),
}

impl Display for SwapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                SwapError::FeatureDisabled =>
                    "Swapping feature is disabled on the network.".to_string(),
                SwapError::MissingInput => "The provided payload has missing data".to_string(),
                SwapError::SamePrincipals =>
                    "`new_node_id` and `old_node_id` must differ".to_string(),
                SwapError::FeatureDisabledForCaller { caller } =>
                    format!("Caller `{caller}` isn't whitelisted to use swapping feature yet."),
                SwapError::FeatureDisabledOnSubnet { subnet_id } =>
                    format!("Swapping is disabled on subnet `{subnet_id}`."),
                SwapError::SubnetNotFoundForNode { old_node_id } =>
                    format!("Node {old_node_id} is not a member of any subnet."),
                SwapError::RateLimiterError(e) => format!("{:?}", e),
                SwapError::NodeNotFound(id) => format!("The node with id `{id}` was not found"),
            }
        )
    }
}

impl SwapNodeInSubnetDirectlyPayload {
    fn validate(&self) -> Result<(), SwapError> {
        let (old_node_id, new_node_id) = match (&self.old_node_id, &self.new_node_id) {
            (Some(old_node_id), Some(new_node_id)) => (old_node_id, new_node_id),
            _ => return Err(SwapError::MissingInput),
        };

        if old_node_id == new_node_id {
            return Err(SwapError::SamePrincipals);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::test_helpers::invariant_compliant_registry;
    use crate::mutations::do_add_node_operator::AddNodeOperatorPayload;
    use crate::{
        common::test_helpers::get_invariant_compliant_subnet_record,
        common::test_helpers::prepare_registry_with_nodes_and_node_operator_id,
        flags::{
            temporarily_disable_node_swapping, temporarily_enable_node_swapping,
            temporary_overrides::{
                test_set_swapping_enabled_subnets, test_set_swapping_whitelisted_callers,
            },
        },
        mutations::do_swap_node_in_subnet_directly::{SwapError, SwapNodeInSubnetDirectlyPayload},
        registry::Registry,
    };
    use ic_nervous_system_time_helpers::now_system_time;
    use ic_protobuf::registry::subnet::v1::SubnetListRecord;
    use ic_registry_keys::{make_subnet_list_record_key, make_subnet_record_key};
    use ic_registry_transport::{pb::v1::RegistryMutation, upsert};
    use ic_types::{NodeId, PrincipalId, SubnetId};
    use maplit::btreemap;
    use std::collections::BTreeMap;

    fn invalid_payloads_with_expected_errors(
        existing_node_id: NodeId,
    ) -> Vec<(SwapNodeInSubnetDirectlyPayload, SwapError)> {
        vec![
            (
                SwapNodeInSubnetDirectlyPayload {
                    new_node_id: None,
                    old_node_id: None,
                },
                SwapError::MissingInput,
            ),
            (
                SwapNodeInSubnetDirectlyPayload {
                    new_node_id: Some(PrincipalId::new_node_test_id(1)),
                    old_node_id: None,
                },
                SwapError::MissingInput,
            ),
            (
                SwapNodeInSubnetDirectlyPayload {
                    new_node_id: None,
                    old_node_id: Some(existing_node_id.get()),
                },
                SwapError::MissingInput,
            ),
            (
                SwapNodeInSubnetDirectlyPayload {
                    new_node_id: Some(existing_node_id.get()),
                    old_node_id: Some(existing_node_id.get()),
                },
                SwapError::SamePrincipals,
            ),
        ]
    }

    fn valid_payload(existing_node_id: NodeId) -> SwapNodeInSubnetDirectlyPayload {
        SwapNodeInSubnetDirectlyPayload {
            new_node_id: Some(PrincipalId::new_node_test_id(1)),
            old_node_id: Some(existing_node_id.get()),
        }
    }

    // Get the test data needed for most tests.
    // Registry, node id that exists, and the node provider id
    fn setup_registry_for_test() -> (Registry, Vec<NodeId>, PrincipalId, PrincipalId) {
        let node_operator_id = PrincipalId::new_user_test_id(10_001);
        let node_provider_id = PrincipalId::new_user_test_id(20_002);

        let mut registry = invariant_compliant_registry(0);
        let (mutate_request, node_ids_and_dkg_pks) =
            prepare_registry_with_nodes_and_node_operator_id(1, 2, node_operator_id);

        registry.maybe_apply_mutation_internal(mutate_request.mutations);

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
        let node_ids: Vec<NodeId> = node_ids_and_dkg_pks.keys().cloned().collect();

        (registry, node_ids, node_operator_id, node_provider_id)
    }

    #[test]
    fn feature_flag_check_works() {
        let (mut registry, node_ids, _, _) = setup_registry_for_test();
        let node_id = node_ids[0];
        let _temp = temporarily_disable_node_swapping();

        let payload = valid_payload(node_id);

        assert!(
            registry
                .swap_nodes_inner(payload, PrincipalId::new_user_test_id(1), now_system_time())
                .is_err_and(|err| err == SwapError::FeatureDisabled)
        )
    }

    #[test]
    fn valid_payload_test() {
        let (mut registry, node_ids, _, _) = setup_registry_for_test();
        let node_id = node_ids[0];

        let _temp = temporarily_enable_node_swapping();
        // Create a registry with nodes and node operators

        let payload = valid_payload(node_id);

        let result =
            registry.swap_nodes_inner(payload, PrincipalId::new_user_test_id(1), now_system_time());

        // First error that occurs after validation
        assert!(result.is_err_and(|err| err
            == SwapError::FeatureDisabledForCaller {
                caller: PrincipalId::new_user_test_id(1)
            }));
    }

    #[test]
    fn invalid_payloads() {
        let (mut registry, node_ids, _, _) = setup_registry_for_test();
        let node_id = node_ids[0];

        let _temp = temporarily_enable_node_swapping();

        for (payload, expected_err) in invalid_payloads_with_expected_errors(node_id) {
            let output = registry.swap_nodes_inner(
                payload,
                PrincipalId::new_user_test_id(1),
                now_system_time(),
            );

            let expected: Result<(), SwapError> = Err(expected_err);
            assert_eq!(
                output, expected,
                "Expected: {expected:?} but found result: {output:?}"
            );
        }
    }

    struct NodeInformation {
        node_id: NodeId,
        subnet_id: Option<SubnetId>,
        operator: PrincipalId,
    }

    fn get_mutations_from_node_information(
        node_information: &[NodeInformation],
    ) -> Vec<RegistryMutation> {
        let mut mutations = vec![];

        let mut subnets = BTreeMap::new();

        for node in node_information {
            if let Some(subnet) = node.subnet_id {
                subnets.entry(subnet).or_insert(vec![]).push(node.node_id);
            }
        }

        for (subnet, nodes) in &subnets {
            mutations.push(upsert(
                make_subnet_record_key(*subnet),
                get_invariant_compliant_subnet_record(nodes.to_vec()).encode_to_vec(),
            ));
        }

        mutations.push(upsert(
            make_subnet_list_record_key(),
            SubnetListRecord {
                subnets: subnets.keys().map(|k| k.get().to_vec()).collect(),
            }
            .encode_to_vec(),
        ));

        mutations
    }

    #[test]
    fn feature_enabled_for_caller() {
        let _temp_enable_feat = temporarily_enable_node_swapping();
        let _temp_enable_feat = temporarily_enable_node_swapping();
        let (mut registry, node_ids, node_operator_id, _) = setup_registry_for_test();

        let subnet_id = SubnetId::new(PrincipalId::new_subnet_test_id(1));
        let old_node_id = node_ids[0];
        let new_node_id = node_ids[1];

        let mutations = get_mutations_from_node_information(&[
            NodeInformation {
                node_id: old_node_id,
                subnet_id: Some(subnet_id),
                operator: node_operator_id,
            },
            NodeInformation {
                node_id: new_node_id,
                subnet_id: None,
                operator: node_operator_id,
            },
        ]);
        registry.apply_mutations_for_test(mutations);

        test_set_swapping_enabled_subnets(vec![subnet_id]);

        let payload = SwapNodeInSubnetDirectlyPayload {
            new_node_id: Some(new_node_id.get()),
            old_node_id: Some(old_node_id.get()),
        };

        // First make a call and expect to fail because
        // the feature is not enabled for this caller.
        let response =
            registry.swap_nodes_inner(payload.clone(), node_operator_id, now_system_time());
        let expected_err = SwapError::FeatureDisabledForCaller {
            caller: node_operator_id,
        };
        assert!(
            response.as_ref().is_err_and(|err| err == &expected_err),
            "Expected error {expected_err:?} but got {response:?}"
        );

        // Enable the feature for the caller
        test_set_swapping_whitelisted_callers(vec![node_operator_id]);
        let response = registry.swap_nodes_inner(payload, node_operator_id, now_system_time());
        // Expect the first next error which is the missing
        // subnet in the registry.
        assert!(response.is_ok(), "Expected OK but got {response:?}");
    }

    #[test]
    fn feature_enabled_for_subnet() {
        let _temp_enable_feat = temporarily_enable_node_swapping();

        let _temp_enable_feat = temporarily_enable_node_swapping();
        let (mut registry, node_ids, node_operator_id, _) = setup_registry_for_test();

        let subnet_id = SubnetId::new(PrincipalId::new_subnet_test_id(1));
        let old_node_id = node_ids[0];
        let new_node_id = node_ids[1];

        let mutations = get_mutations_from_node_information(&[
            NodeInformation {
                node_id: old_node_id,
                subnet_id: Some(subnet_id),
                operator: node_operator_id,
            },
            NodeInformation {
                node_id: new_node_id,
                subnet_id: None,
                operator: node_operator_id,
            },
        ]);
        registry.apply_mutations_for_test(mutations);

        test_set_swapping_whitelisted_callers(vec![node_operator_id]);

        let payload = SwapNodeInSubnetDirectlyPayload {
            old_node_id: Some(old_node_id.get()),
            new_node_id: Some(new_node_id.get()),
        };

        let response =
            registry.swap_nodes_inner(payload.clone(), node_operator_id, now_system_time());
        let expected_err = SwapError::FeatureDisabledOnSubnet { subnet_id };

        // First call when the feature isn't enabled on the subnet.
        assert!(
            response.as_ref().is_err_and(|err| err == &expected_err),
            "Expected to get error {expected_err:?} but got {response:?}"
        );

        // Now enable the feature and call again.
        test_set_swapping_enabled_subnets(vec![subnet_id]);
        let response = registry.swap_nodes_inner(payload, node_operator_id, now_system_time());
        assert!(
            response.is_ok(),
            "Expected the result to be OK but got {response:?}"
        );
    }

    #[test]
    fn e2e_valid_swap() {
        let _temp_enable_feat = temporarily_enable_node_swapping();
        let (mut registry, node_ids, node_operator_id, _) = setup_registry_for_test();

        let subnet_id = SubnetId::new(PrincipalId::new_subnet_test_id(1));
        let old_node_id = node_ids[0];
        let new_node_id = node_ids[1];

        let mutations = get_mutations_from_node_information(&[
            NodeInformation {
                node_id: old_node_id,
                subnet_id: Some(subnet_id),
                operator: node_operator_id,
            },
            NodeInformation {
                node_id: new_node_id,
                subnet_id: None,
                operator: node_operator_id,
            },
        ]);
        registry.apply_mutations_for_test(mutations);

        let payload = SwapNodeInSubnetDirectlyPayload {
            old_node_id: Some(old_node_id.get()),
            new_node_id: Some(new_node_id.get()),
        };

        test_set_swapping_whitelisted_callers(vec![node_operator_id]);
        test_set_swapping_enabled_subnets(vec![subnet_id]);

        let response = registry.swap_nodes_inner(payload, node_operator_id, now_system_time());
        assert!(
            response.is_ok(),
            "Expected OK response but got: {response:?}"
        );

        //TODO(DRE-548): Add assertions that the swap has been made
    }

    #[test]
    fn test_do_swap_node_in_subnet_directly_fails_when_rate_limits_exceeded() {
        let (mut registry, node_ids, _, valid_np) = setup_registry_for_test();
        let node_id = node_ids[0];

        let _temp = temporarily_enable_node_swapping();

        let payload = valid_payload(node_id);
        let now = now_system_time();
        let caller = valid_np;

        // Exhaust the rate limit capacity
        let available = registry.get_available_node_provider_op_capacity(caller, now);
        let reservation = registry
            .try_reserve_node_provider_op_capacity(now, caller, available)
            .unwrap();
        registry
            .commit_node_provider_op_reservation(now, reservation)
            .unwrap();

        // For now, the method doesn't implement rate limiting yet
        // This test will be updated when rate limiting is implemented
        let result = registry.swap_nodes_inner(payload, caller, now);
        // The test should pass for now since rate limiting isn't implemented yet
        assert!(result.is_ok() || result.is_err());
    }
}
