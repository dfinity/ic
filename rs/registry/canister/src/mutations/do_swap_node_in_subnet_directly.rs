use std::fmt::Display;

use candid::CandidType;
use ic_types::{NodeId, PrincipalId, SubnetId};
use prost::Message;
use serde::{Deserialize, Serialize};

use crate::{
    flags::{
        is_node_swapping_enabled, is_node_swapping_enabled_for_caller,
        is_node_swapping_enabled_on_subnet,
    },
    mutations::node_management::common::find_subnet_for_node,
    registry::Registry,
};

impl Registry {
    /// Called by the node operators in order to rotate their nodes without the need for governance.
    pub fn do_swap_node_in_subnet_directly(&mut self, payload: SwapNodeInSubnetDirectlyPayload) {
        self.swap_nodes_inner(payload, dfn_core::api::caller())
            .unwrap_or_else(|e| panic!("{e}"));
    }

    /// Top level function for the swapping feature which has all inputs.
    fn swap_nodes_inner(
        &mut self,
        payload: SwapNodeInSubnetDirectlyPayload,
        caller: PrincipalId,
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

        //TODO(DRE-553): Rate-limiting mechanism

        //TODO(DRE-548): Implement the swapping functionality
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
    use std::collections::BTreeMap;

    use ic_protobuf::registry::{node::v1::NodeRecord, subnet::v1::SubnetListRecord};
    use ic_registry_keys::{
        make_node_record_key, make_subnet_list_record_key, make_subnet_record_key,
    };
    use ic_registry_transport::{pb::v1::RegistryMutation, upsert};
    use ic_types::{NodeId, PrincipalId, SubnetId};

    use crate::{
        common::test_helpers::get_invariant_compliant_subnet_record,
        flags::{
            temporarily_disable_node_swapping, temporarily_enable_node_swapping,
            temporary_overrides::{
                test_set_swapping_enabled_subnets, test_set_swapping_whitelisted_callers,
            },
        },
        mutations::do_swap_node_in_subnet_directly::{SwapError, SwapNodeInSubnetDirectlyPayload},
        registry::Registry,
    };

    fn invalid_payloads_with_expected_errors() -> Vec<(SwapNodeInSubnetDirectlyPayload, SwapError)>
    {
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
                    old_node_id: Some(PrincipalId::new_user_test_id(2)),
                },
                SwapError::MissingInput,
            ),
            (
                SwapNodeInSubnetDirectlyPayload {
                    new_node_id: Some(PrincipalId::new_node_test_id(1)),
                    old_node_id: Some(PrincipalId::new_node_test_id(1)),
                },
                SwapError::SamePrincipals,
            ),
        ]
    }

    fn valid_payload() -> SwapNodeInSubnetDirectlyPayload {
        SwapNodeInSubnetDirectlyPayload {
            new_node_id: Some(PrincipalId::new_node_test_id(1)),
            old_node_id: Some(PrincipalId::new_node_test_id(2)),
        }
    }

    #[test]
    fn feature_flag_check_works() {
        let mut registry = Registry::new();

        let _temp = temporarily_disable_node_swapping();

        let payload = valid_payload();

        assert!(
            registry
                .swap_nodes_inner(payload, PrincipalId::new_user_test_id(1))
                .is_err_and(|err| err == SwapError::FeatureDisabled)
        )
    }

    #[test]
    fn valid_payload_test() {
        let mut registry = Registry::new();

        let _temp = temporarily_enable_node_swapping();

        let payload = valid_payload();

        let result = registry.swap_nodes_inner(payload, PrincipalId::new_user_test_id(1));

        // First error that occurs after validation
        assert!(result.is_err_and(|err| err
            == SwapError::FeatureDisabledForCaller {
                caller: PrincipalId::new_user_test_id(1)
            }));
    }

    #[test]
    fn invalid_payloads() {
        let mut registry = Registry::new();

        let _temp = temporarily_enable_node_swapping();

        for (payload, expected_err) in invalid_payloads_with_expected_errors() {
            let output = registry.swap_nodes_inner(payload, PrincipalId::new_user_test_id(1));

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

            mutations.push(upsert(
                make_node_record_key(node.node_id),
                NodeRecord {
                    node_operator_id: node.operator.to_vec(),
                    ..Default::default()
                }
                .encode_to_vec(),
            ));
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
        let mut registry = Registry::new();

        let subnet_id = SubnetId::new(PrincipalId::new_subnet_test_id(1));
        let old_node_id = NodeId::new(PrincipalId::new_node_test_id(1));
        let new_node_id = NodeId::new(PrincipalId::new_node_test_id(2));
        let operator_id = PrincipalId::new_user_test_id(1);

        let mutations = get_mutations_from_node_information(&[
            NodeInformation {
                node_id: old_node_id,
                subnet_id: Some(subnet_id),
                operator: operator_id,
            },
            NodeInformation {
                node_id: new_node_id,
                subnet_id: None,
                operator: operator_id,
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
        let response = registry.swap_nodes_inner(payload.clone(), operator_id);
        let expected_err = SwapError::FeatureDisabledForCaller {
            caller: operator_id,
        };
        assert!(
            response.as_ref().is_err_and(|err| err == &expected_err),
            "Expected error {expected_err:?} but got {response:?}"
        );

        // Enable the feature for the caller
        test_set_swapping_whitelisted_callers(vec![operator_id]);
        let response = registry.swap_nodes_inner(payload, operator_id);
        // Expect the first next error which is the missing
        // subnet in the registry.
        assert!(response.is_ok(), "Expected OK but got {response:?}");
    }

    #[test]
    fn feature_enabled_for_subnet() {
        let _temp_enable_feat = temporarily_enable_node_swapping();

        let mut registry = Registry::new();

        let subnet_id = SubnetId::new(PrincipalId::new_subnet_test_id(1));
        let old_node_id = NodeId::new(PrincipalId::new_node_test_id(1));
        let new_node_id = NodeId::new(PrincipalId::new_node_test_id(2));
        let operator_id = PrincipalId::new_user_test_id(1);

        let mutations = get_mutations_from_node_information(&[
            NodeInformation {
                node_id: old_node_id,
                subnet_id: Some(subnet_id),
                operator: operator_id,
            },
            NodeInformation {
                node_id: new_node_id,
                subnet_id: None,
                operator: operator_id,
            },
        ]);
        registry.apply_mutations_for_test(mutations);

        test_set_swapping_whitelisted_callers(vec![operator_id]);

        let payload = SwapNodeInSubnetDirectlyPayload {
            old_node_id: Some(old_node_id.get()),
            new_node_id: Some(new_node_id.get()),
        };

        let response = registry.swap_nodes_inner(payload.clone(), operator_id);
        let expected_err = SwapError::FeatureDisabledOnSubnet { subnet_id };

        // First call when the feature isn't enabled on the subnet.
        assert!(
            response.as_ref().is_err_and(|err| err == &expected_err),
            "Expected to get error {expected_err:?} but got {response:?}"
        );

        // Now enable the feature and call again.
        test_set_swapping_enabled_subnets(vec![subnet_id]);
        let response = registry.swap_nodes_inner(payload, operator_id);
        assert!(
            response.is_ok(),
            "Expected the result to be OK but got {response:?}"
        );
    }

    #[test]
    fn e2e_valid_swap() {
        let _temp_enable_feat = temporarily_enable_node_swapping();
        let mut registry = Registry::new();

        let subnet_id = SubnetId::new(PrincipalId::new_subnet_test_id(1));
        let old_node_id = NodeId::new(PrincipalId::new_node_test_id(1));
        let new_node_id = NodeId::new(PrincipalId::new_node_test_id(2));
        let operator_id = PrincipalId::new_user_test_id(1);

        let mutations = get_mutations_from_node_information(&[
            NodeInformation {
                node_id: old_node_id,
                subnet_id: Some(subnet_id),
                operator: operator_id,
            },
            NodeInformation {
                node_id: new_node_id,
                subnet_id: None,
                operator: operator_id,
            },
        ]);
        registry.apply_mutations_for_test(mutations);

        let payload = SwapNodeInSubnetDirectlyPayload {
            old_node_id: Some(old_node_id.get()),
            new_node_id: Some(new_node_id.get()),
        };

        test_set_swapping_whitelisted_callers(vec![operator_id]);
        test_set_swapping_enabled_subnets(vec![subnet_id]);

        let response = registry.swap_nodes_inner(payload, operator_id);
        assert!(
            response.is_ok(),
            "Expected OK response but got: {response:?}"
        );

        //TODO(DRE-548): Add assertions that the swap has been made
    }
}
