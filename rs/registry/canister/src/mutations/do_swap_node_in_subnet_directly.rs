use std::fmt::Display;

use candid::CandidType;
use ic_types::{PrincipalId, SubnetId};
use prost::Message;
use serde::{Deserialize, Serialize};

use crate::{
    flags::{
        is_node_swapping_enabled, is_node_swapping_enabled_for_caller,
        is_node_swapping_enabled_on_subnet,
    },
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
        let subnet_id = self.find_subnet_for_node(old_node_id)?;
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
    fn find_subnet_for_node(&self, old_node_id: PrincipalId) -> Result<SubnetId, SwapError> {
        for (subnet, id) in self
            .get_subnet_list_record()
            .subnets
            .into_iter()
            // This unwrap should never happen if the registry is invariant compliant.
            .map(|bytes| SubnetId::new(PrincipalId::try_from(bytes).unwrap()))
            // This unwrap should never happen if the registry is invariant compliant.
            .map(|subnet_id| (self.get_subnet_or_panic(subnet_id), subnet_id))
        {
            if !subnet
                .membership
                .iter()
                .map(|bytes| PrincipalId::try_from(bytes).unwrap())
                .any(|node| node == old_node_id)
            {
                // Node is not a member of this subnet so skip it.
                continue;
            }

            return Ok(id);
        }

        Err(SwapError::SubnetNotFoundForNode { old_node_id })
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

    use ic_types::PrincipalId;

    use crate::{
        flags::{temporarily_disable_node_swapping, temporarily_enable_node_swapping},
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

        assert!(registry
            .swap_nodes_inner(payload, PrincipalId::new_user_test_id(1))
            .is_err_and(|err| err == SwapError::FeatureDisabled))
    }

    #[test]
    fn valid_payload_test() {
        let mut registry = Registry::new();

        let _temp = temporarily_enable_node_swapping();

        let payload = valid_payload();

        assert!(registry
            .swap_nodes_inner(payload, PrincipalId::new_user_test_id(1))
            .is_ok())
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
}
