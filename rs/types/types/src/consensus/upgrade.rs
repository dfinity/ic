//! Phase-2 quick-upgrade permit types.
//!
//! The permit flow works in three stages:
//!
//! 1. **Request**: A block maker includes `UpgradePayloadContent::Request` in
//!    its block when it wants to reboot. Validators check outstanding requests
//!    don't exceed P (max parallel reboots).
//!
//! 2. **Authorize**: After the request block is finalized, each node gossips an
//!    [`crate::consensus::UpgradePermitAuthorizationShare`]. When a block maker
//!    collects ≥ N−P shares, it includes
//!    `UpgradePayloadContent::Authorize` in its block. Execution applies it to
//!    `SystemMetadata`.
//!
//! 3. **Return**: After rebooting, the node includes
//!    `UpgradePayloadContent::Return` to release the slot.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{Height, NodeId, ReplicaVersion};

/// If a Request is not Authorize'd within this many blocks, it expires and the
/// slot is freed for the next block maker to issue a new Request.
pub const REQUEST_TIMEOUT_BLOCKS: Height = Height::new(20);

/// The content carried in a block's upgrade payload section.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub enum UpgradePayloadContent {
    /// Request permission to reboot. The block maker requests for itself.
    /// `request_height` is the height of the block containing this request,
    /// used for timeout tracking.
    Request {
        node: NodeId,
        request_height: Height,
    },
    /// Authorize a node to reboot — includes the collected signature shares.
    Authorize(UpgradePermitShares),
    /// Release a previously authorized permit (reboot complete).
    Return { node: NodeId },
}

/// The collected authorization shares for a permit request.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub struct UpgradePermitShares {
    pub node: NodeId,
    pub shares: Vec<crate::consensus::UpgradePermitAuthorizationShare>,
}

/// The response to the `/_/upgrade_state` HTTP endpoint.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct UpgradeStateResponse {
    /// Whether this node is authorized to reboot.
    pub has_permit: bool,
}

/// The upgrade section carried in a block's `BatchPayload`.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub struct UpgradePayload {
    pub content: Option<UpgradePayloadContent>,
}

impl Default for UpgradePayload {
    fn default() -> Self {
        Self { content: None }
    }
}

/// The agreed Phase-2 upgrade state, stored in `SystemMetadata`.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct UpgradeState {
    /// Nodes that have requested a reboot permit but not yet been authorized,
    /// mapped to the height at which they requested (for timeout expiry).
    pub requested: BTreeMap<NodeId, Height>,
    /// Nodes that have been authorized to reboot (collected enough shares).
    pub authorized: BTreeSet<NodeId>,
}

/// The current subnet target GuestOS version, derived from the registry.
pub type TargetVersion = Option<ReplicaVersion>;

impl UpgradeState {
    /// Apply a block's upgrade section to this state. Also prunes expired
    /// requests (older than `REQUEST_TIMEOUT_BLOCKS`) and permits for nodes
    /// that left the membership.
    ///
    /// `current_height` is the height of the block being applied (used for
    /// request timeout expiry). `members` is the current subnet membership.
    pub fn apply(
        &mut self,
        payload: &UpgradePayload,
        current_height: Height,
        members: &BTreeSet<NodeId>,
    ) {
        // Apply the payload action.
        if let Some(content) = &payload.content {
            match content {
                UpgradePayloadContent::Request {
                    node,
                    request_height,
                } => {
                    self.requested.insert(*node, *request_height);
                }
                UpgradePayloadContent::Authorize(shares) => {
                    self.requested.remove(&shares.node);
                    self.authorized.insert(shares.node);
                }
                UpgradePayloadContent::Return { node } => {
                    self.authorized.remove(node);
                }
            }
        }

        // Expire stale requests and prune departed members.
        self.requested.retain(|node, req_height| {
            *req_height + REQUEST_TIMEOUT_BLOCKS >= current_height && members.contains(node)
        });

        // Prune departed members.
        self.authorized.retain(|node| members.contains(node));
    }

    /// Number of reboot slots in use: outstanding requests + authorized nodes
    /// that haven't returned yet.
    pub fn slots_in_use(&self) -> usize {
        self.requested.len() + self.authorized.len()
    }

    /// The fault tolerance: `f = ⌊(N−1)/3⌋`.
    pub fn faults_tolerated(num_members: usize) -> usize {
        (num_members.max(1) - 1) / 3
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_base_types::PrincipalId;

    fn node(node_index: u64) -> NodeId {
        NodeId::from(PrincipalId::new_node_test_id(node_index))
    }

    fn members() -> BTreeSet<NodeId> {
        [node(1), node(2), node(3), node(4)].into_iter().collect()
    }

    #[test]
    fn test_authorize_and_return() {
        let m = members();
        let mut state = UpgradeState::default();

        state.apply(
            &UpgradePayload {
                content: Some(UpgradePayloadContent::Authorize(UpgradePermitShares {
                    node: node(1),
                    shares: vec![],
                })),
            },
            Height::from(0),
            &m,
        );
        assert!(state.authorized.contains(&node(1)));

        state.apply(
            &UpgradePayload {
                content: Some(UpgradePayloadContent::Return { node: node(1) }),
            },
            Height::from(1),
            &m,
        );
        assert!(!state.authorized.contains(&node(1)));
    }

    #[test]
    fn test_permit_retired_on_leave() {
        let m = members();
        let mut state = UpgradeState::default();

        state.apply(
            &UpgradePayload {
                content: Some(UpgradePayloadContent::Authorize(UpgradePermitShares {
                    node: node(1),
                    shares: vec![],
                })),
            },
            Height::from(0),
            &m,
        );
        assert!(state.authorized.contains(&node(1)));

        // Node 1 leaves the subnet.
        let m_after: BTreeSet<NodeId> = [node(2), node(3), node(4)].into_iter().collect();
        state.apply(&UpgradePayload::default(), Height::from(1), &m_after);
        assert!(!state.authorized.contains(&node(1)));
    }

    #[test]
    fn test_request_times_out() {
        let m = members();
        let mut state = UpgradeState::default();

        // Node 1 requests at height 10.
        state.apply(
            &UpgradePayload {
                content: Some(UpgradePayloadContent::Request {
                    node: node(1),
                    request_height: Height::from(10),
                }),
            },
            Height::from(10),
            &m,
        );
        assert_eq!(state.requested.len(), 1);

        // At height 10 + REQUEST_TIMEOUT_BLOCKS, the request is still valid.
        state.apply(
            &UpgradePayload::default(),
            Height::from(10) + REQUEST_TIMEOUT_BLOCKS,
            &m,
        );
        assert_eq!(state.requested.len(), 1, "request should still be valid");

        // One block later, it expires.
        state.apply(
            &UpgradePayload::default(),
            Height::from(10) + REQUEST_TIMEOUT_BLOCKS + Height::from(1),
            &m,
        );
        assert!(state.requested.is_empty(), "request should have expired");
    }
}
