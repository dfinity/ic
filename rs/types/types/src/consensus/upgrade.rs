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

use serde::{Deserialize, Serialize};

use crate::{Height, NodeId, RegistryVersion};

/// A single action in a block's upgrade payload section. A block may carry
/// multiple actions (e.g. `Request` for the block maker and `Authorize` for
/// another node).
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub enum UpgradePermitAction {
    /// Request permission to reboot. The block maker requests for itself.
    /// `request_height` is the height of the block containing this request,
    /// used for timeout tracking.
    ///
    /// `registry_version` is the registry version of the block carrying the
    /// request, i.e. a version at which the requester is still a subnet member.
    /// It is pinned as the oldest registry version in use by the replicated
    /// state for as long as the permit is outstanding, which keeps every node
    /// that was a member at that version from unassigning itself while another
    /// node is rebooting.
    Request {
        node: NodeId,
        request_height: Height,
        registry_version: RegistryVersion,
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
