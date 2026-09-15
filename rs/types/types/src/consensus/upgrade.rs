//! Phase-2 quick-upgrade permit types.
//!
//! The permit flow works in three stages:
//!
//! 1. **Request**: A block maker includes `UpgradePermitAction::Request` in
//!    its block when it wants to reboot. Validators check outstanding requests
//!    the allowed max parallel reboots.
//!
//! 2. **Authorize**: After the request block is finalized, each node gossips an
//!    [`crate::consensus::UpgradePermitAuthorizationShare`]. When a block maker
//!    collects enough shares, it includes `UpgradePermitAction::Authorize` in its block.
//!
//! 3. **Return**: After rebooting, the node includes
//!    `UpgradePermitAction::Return` to release the slot.

use serde::{Deserialize, Serialize};

use crate::NodeId;
use crate::consensus::UpgradePermitAuthorizationRequest;
use crate::signature::BasicSignatureBatch;

/// A single action in a block's upgrade payload section. A block may carry
/// multiple actions (e.g. `Request` for the block maker and `Authorize` for
/// another node).
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub enum UpgradePermitAction {
    /// Request permission to reboot. The block maker requests for itself.
    /// `request_height` is the height of the block containing this request,
    /// used for timeout tracking.
    Request(UpgradePermitAuthorizationRequest),
    /// Authorize a node to reboot — the signed request and the basic
    /// signatures over it collected from the staying members.
    Authorize {
        request: UpgradePermitAuthorizationRequest,
        signatures: BasicSignatureBatch<UpgradePermitAuthorizationRequest>,
    },
    /// Release a previously authorized permit (reboot complete).
    Return { node: NodeId },
}
