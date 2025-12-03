use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    fmt::Display,
};

use candid::CandidType;
use ic_types::PrincipalId;
use prost::Message;
use serde::{Deserialize, Serialize};

use crate::registry::Registry;

struct NodeApprovalManager {
    _approved: HashMap<PrincipalId, VecDeque<PrincipalId>>,
}

impl NodeApprovalManager {
    fn new() -> Self {
        Self {
            _approved: HashMap::new(),
        }
    }
}

thread_local! {
    static NODE_APPROVAL_MANAGER: RefCell<NodeApprovalManager> = RefCell::new(NodeApprovalManager::new());
}

impl Registry {
    /// Called by the node operators in order to approve nodes for onboarding.
    pub fn do_approve_add_node_payload(&mut self, payload: ApproveAddNodePayload) {
        NODE_APPROVAL_MANAGER.with_borrow_mut(|manager| {
            self.do_approve_add_node_payload_inner(payload, dfn_core::api::caller(), manager)
                .unwrap_or_else(|e| panic!("{e}"));
        })
    }

    // TODO: Implement a way to fetch a node operator id for a given node id.
    //
    // This will be used from `do_add_node` to verify the following things:
    // * Is the node that is trying to onboard to the network approved to do so?
    // * If it is, to what node operator should it be linked to?
    //
    // NOTE: This function should hold an invariant check that will check if
    // somehow the given node is approved with multiple node operators and error
    // out if it is. If the whole feature is implemented properly, this shouldn't
    // happen, but assuming that the first occurance of the node id in any of the
    // node operators approved node may be faulty.

    // TODO: Implement a way to remove a node id from the queue of approved nodes
    // for the node operator.
    //
    // NOTE: This should be called as the very last step of the `do_add_node`,
    // after the registry verified all other invariant checks since this call
    // is irreversible and if the node registration process fails later, that
    // node operator would have inaccurate approved nodes for onboarding.

    fn do_approve_add_node_payload_inner(
        &mut self,
        payload: ApproveAddNodePayload,
        _caller: PrincipalId,
        _node_approval_manager: &mut NodeApprovalManager,
    ) -> Result<(), ApprovePayloadError> {
        // Verify payload integrity
        payload.validate()?;

        // TODO: Prevent approving a node that has already been queued for registration.

        // TODO: Duplication Check: Ensure node is not already in the registry or
        // already queued.

        // TODO: Ensure `caller` is a registered node operator.

        // TODO: Calculate the remaining spare capacity the node operator and
        // update the approved nodes for onboarding for the node operator.
        //
        // NOTICE: Keep in mind that this code will be used by UTOPIA and capacity
        // calculations are done differently there and on a regular IC.
        //
        // Spare capacity (in this context) is calculated as follows:
        //    spare = total_capacity - (nodes_in_registry + nodes_currently_approved)
        //
        // Two scenarios are possible here:
        // * If spare > 0: Prepend new ID to the queue.
        // * If spare == 0: Prepend new ID and pop the back (remove stale approval).
        //
        // This approach is deemed acceptable because the window between
        // approving a node for registration and its actual registration
        // will be small. This approach also removes the need for a cron
        // job that will clean the approved node ids that were queued due to
        // an error or just won't ever complete.

        // TODO: Enforce a hard cap on the number of nodes a node operator
        // is onboarding.
        //
        // This is a safety measure regardless of the theoretical maximum.

        // TODO: Handle edge case for calculating spares.
        //
        // It is possible that total_capacity gets changed over time, i.e.
        // with `do_update_node_operator` which happens via proposals. While
        // increasing the total_capacity (by increasing max_rewardable_nodes)
        // is not a problem, decreasing the total_capacity could cause an
        // underflow and the capacity formula could allow having more
        // approved nodes for onboarding than possible.

        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub enum ApprovePayloadError {
    MissingNodeId,
}

impl Display for ApprovePayloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ApprovePayloadError::MissingNodeId =>
                    "Received invalid payload. `node_id` must be specified.".to_string(),
            }
        )
    }
}

#[derive(Clone, Eq, PartialEq, CandidType, Deserialize, Message, Serialize)]
pub struct ApproveAddNodePayload {
    /// Represents the expected node ID sent by the
    /// node operator that will be used to map an incoming
    /// request from the node to register itself.
    #[prost(message, optional, tag = "1")]
    pub node_id: Option<PrincipalId>,
}

impl ApproveAddNodePayload {
    pub fn validate(&self) -> Result<(), ApprovePayloadError> {
        if self.node_id.is_none() {
            return Err(ApprovePayloadError::MissingNodeId);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disallow_empty_payload() {
        let payload = ApproveAddNodePayload { node_id: None };
        let caller = PrincipalId::new_user_test_id(1);
        let mut node_approval_manager = NodeApprovalManager::new();

        let mut registry = Registry::new();

        let result =
            registry.do_approve_add_node_payload_inner(payload, caller, &mut node_approval_manager);

        let expected_err = ApprovePayloadError::MissingNodeId;
        assert_eq!(result, Err(expected_err))
    }

    #[test]
    fn valid_payload() {
        let payload = ApproveAddNodePayload {
            node_id: Some(PrincipalId::new_node_test_id(1)),
        };

        let result = payload.validate();

        assert!(result.is_ok());
    }

    #[test]
    fn e2e_test() {
        let payload = ApproveAddNodePayload {
            node_id: Some(PrincipalId::new_node_test_id(1)),
        };
        let caller = PrincipalId::new_user_test_id(1);
        let mut node_approval_manager = NodeApprovalManager::new();

        let mut registry = Registry::new();

        let response =
            registry.do_approve_add_node_payload_inner(payload, caller, &mut node_approval_manager);

        assert!(response.is_ok());
    }
}
