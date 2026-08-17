//! The upgrade permit protocol for the Phase-2 rolling GuestOS reboots.
//!
//! Reboot permits are requested in blocks, authorized by threshold share
//! collections gossiped between replicas, and returned after the reboot.
//!
//! This crate root holds the kernel shared by the payload section
//! (builder/validator) and the share signer (the pool manager): membership
//! views and share validation. Membership distinguishes the committee
//! (registry at the CUP/summary version for the block height, changing only
//! at DKG interval boundaries) from the current members staying even at the
//! new CUP (still present at the block's registry version).

use ic_consensus_utils::crypto::ConsensusCrypto;
use ic_consensus_utils::membership::Membership;
use ic_interfaces::upgrade::InvalidUpgradePayloadReason;
use ic_logger::{ReplicaLogger, warn};
use ic_replicated_state::metadata_state::UpgradeState;
use ic_types::consensus::UpgradePermitAuthorizationShare;
use ic_types::{Height, NodeId, RegistryVersion};
use std::collections::BTreeSet;

pub mod payload_builder;
pub mod pool_manager;

pub(crate) struct SubnetMembership {
    /// The actual current members: registry membership at the CUP/summary
    /// version for the block height (changes only at DKG interval boundaries).
    pub(crate) current_members: BTreeSet<NodeId>,
    /// Current members staying even at the new CUP: still present at the
    /// block's registry version.
    pub(crate) staying_members: BTreeSet<NodeId>,
}

impl SubnetMembership {
    /// Is the node a current member staying even at the new CUP?
    pub(crate) fn staying(&self, node: &NodeId) -> bool {
        self.staying_members.contains(node)
    }

    /// Capacity quantities derived from the current subnet size.
    pub(crate) fn limits(&self) -> PermitLimits {
        let subnet_size = self.current_members.len();
        let max_parallel_reboots = UpgradeState::max_parallel_reboots(subnet_size);
        PermitLimits {
            subnet_size,
            max_parallel_reboots,
            authorization_threshold: subnet_size.saturating_sub(max_parallel_reboots),
        }
    }
}

pub(crate) struct PermitLimits {
    /// The number of current subnet members (N).
    pub(crate) subnet_size: usize,
    /// The maximum number of nodes that may reboot in parallel (P ≤ f).
    pub(crate) max_parallel_reboots: usize,
    /// The number of distinct shares required to authorize a reboot (N−P).
    pub(crate) authorization_threshold: usize,
}

/// Subnet membership at the block height and registry version.
pub(crate) fn subnet_membership(
    membership: &Membership,
    block_height: Height,
    block_registry_version: RegistryVersion,
    logger: &ReplicaLogger,
) -> SubnetMembership {
    let registry_at_height: BTreeSet<NodeId> = membership
        .get_nodes_at_version(block_registry_version)
        .map(|nodes| nodes.into_iter().collect())
        .unwrap_or_default();
    let current_members: BTreeSet<NodeId> = match membership.get_nodes(block_height) {
        Ok(nodes) => nodes.into_iter().collect(),
        Err(e) => {
            warn!(
                logger,
                "upgrade_payload: couldn't determine the committee at height {:?}: {:?}",
                block_height,
                e
            );
            registry_at_height.clone()
        }
    };
    let staying_members = current_members
        .intersection(&registry_at_height)
        .cloned()
        .collect();
    SubnetMembership {
        current_members,
        staying_members,
    }
}

/// Check one share: the content must match `(requestor_node, request_height)`,
/// the signer must be a staying member, and the signature must verify against
/// the signer's node key at `registry_version`. Returns the signer.
pub(crate) fn validate_share(
    share: &UpgradePermitAuthorizationShare,
    requestor_node: NodeId,
    request_height: Height,
    staying: &BTreeSet<NodeId>,
    registry_version: RegistryVersion,
    crypto: &dyn ConsensusCrypto,
) -> Result<NodeId, InvalidUpgradePayloadReason> {
    let signer = share.signature.signer;
    if share.content.node != requestor_node || share.content.request_height != request_height {
        return Err(InvalidUpgradePayloadReason::AuthorizeInvalidShare { signer });
    }
    if !staying.contains(&signer) {
        return Err(InvalidUpgradePayloadReason::AuthorizeInvalidShare { signer });
    }
    crypto
        .verify_basic_sig(&share.signature.signature, &share.content, signer, registry_version)
        .map_err(|_| InvalidUpgradePayloadReason::AuthorizeInvalidShare { signer })?;
    Ok(signer)
}
