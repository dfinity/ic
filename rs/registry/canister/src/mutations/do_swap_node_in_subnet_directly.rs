use std::fmt::Display;

use candid::CandidType;
use ic_types::PrincipalId;
use prost::Message;
use serde::{Deserialize, Serialize};

use crate::registry::Registry;

/// Feature flag used to enable/disable the swapping feature on the whole network.
const ENABLED: bool = false;

impl Registry {
    /// Called by the node operators in order to rotate their nodes without the need for governance.
    pub fn do_swap_node_in_subnet_directly(&mut self, payload: SwapNodeInSubnetDirectlyPayload) {
        self.swap_nodes_inner(ENABLED, payload, dfn_core::api::caller())
            .unwrap_or_else(|e| panic!("{e}"));
    }

    /// Top level function for the swapping feature which has all inputs.
    fn swap_nodes_inner(
        &mut self,
        enabled: bool,
        _payload: SwapNodeInSubnetDirectlyPayload,
        _caller: PrincipalId,
    ) -> Result<(), SwapError> {
        if !enabled {
            return Err(SwapError::FeatureDisabled);
        }

        //TODO(DRE-547): Check if the feature is allowed on the target subnet and for the caller

        //TODO(DRE-553): Rate-limiting mechanism

        //TODO(DRE-548): Implement the swapping functionality
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
            }
        )
    }
}

impl SwapNodeInSubnetDirectlyPayload {
    #[allow(dead_code)]
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
    mod payload_validation_tests {
        use ic_types::PrincipalId;

        use crate::mutations::do_swap_node_in_subnet_directly::{
            SwapError, SwapNodeInSubnetDirectlyPayload,
        };

        #[test]
        fn valid_payload() {
            let payload = SwapNodeInSubnetDirectlyPayload {
                new_node_id: Some(PrincipalId::new_node_test_id(1)),
                old_node_id: Some(PrincipalId::new_node_test_id(2)),
            };

            assert!(payload.validate().is_ok())
        }

        #[test]
        fn invalid_payloads() {
            for (payload, expected_err) in [
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
            ] {
                let output = payload.validate();
                let expected: Result<(), SwapError> = Err(expected_err);
                assert_eq!(
                    output, expected,
                    "Expected: {expected:?} but found result: {output:?}"
                );
            }
        }
    }
}
