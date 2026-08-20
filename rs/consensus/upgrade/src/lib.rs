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
use ic_types::consensus::UpgradePermitAuthorizationShare;
use ic_types::{Height, NodeId, RegistryVersion};
use std::collections::BTreeSet;

pub mod payload_builder;
pub mod pool_manager;

pub struct SubnetMembership {
    /// The actual current members: registry membership at the CUP/summary
    /// version for the block height (changes only at DKG interval boundaries).
    pub current_members: BTreeSet<NodeId>,
    /// Current members staying even at the new CUP: still present at the
    /// block's registry version.
    pub staying_members: BTreeSet<NodeId>,
}

impl SubnetMembership {
    /// Is the node a current member staying even at the new CUP?
    pub fn staying(&self, node: &NodeId) -> bool {
        self.staying_members.contains(node)
    }
}

pub struct PermitLimits {
    /// The maximum number of rebooting nodes (staying minus the threshold).
    pub permits: usize,
    /// The number of distinct staying signers required to authorize a
    /// reboot: the nodes that must be there (quorum + margin).
    pub authorization_threshold: usize,
}

/// The permit limits for a membership:
///
/// * `authorization_threshold` — distinct staying signers confirming a
///   reboot: the nodes that must be there — quorum (N − f) plus the
///   margin m = ⌈log₂ N⌉ − 2. Leaving members cannot sign, so their
///   absence is already accounted for;
/// * `permits` — the maximum number of rebooting nodes: the staying
///   members minus the threshold. A leaver reserves a permit without
///   rebooting; with all leavers down and every permit rebooting, the
///   staying members still hold quorum plus the margin.
pub fn permit_limits(membership: &SubnetMembership) -> PermitLimits {
    let committee = membership.current_members.len();
    let faults = ic_types::consensus::get_faults_tolerated(committee);
    let margin = (committee.next_power_of_two().ilog2() as usize).saturating_sub(2);
    let authorization_threshold = committee - faults + margin;
    PermitLimits {
        permits: membership
            .staying_members
            .len()
            .saturating_sub(authorization_threshold),
        authorization_threshold,
    }
}

/// Subnet membership at the block height and registry version.
pub fn subnet_membership(
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

/// Check a share's content, staying signer, and signature. Returns the
/// signer.
pub fn validate_share(
    share: &UpgradePermitAuthorizationShare,
    requestor_node: NodeId,
    request_height: Height,
    staying: &BTreeSet<NodeId>,
    registry_version: RegistryVersion,
    crypto: &dyn ConsensusCrypto,
) -> Result<NodeId, InvalidUpgradePayloadReason> {
    let signer = share.signature.signer;
    if share.content.requestor_node != requestor_node
        || share.content.request_height != request_height
    {
        return Err(InvalidUpgradePayloadReason::AuthorizeInvalidShare { signer });
    }
    if !staying.contains(&signer) {
        return Err(InvalidUpgradePayloadReason::AuthorizeInvalidShare { signer });
    }
    crypto
        .verify_basic_sig(
            &share.signature.signature,
            &share.content,
            signer,
            registry_version,
        )
        .map_err(|_| InvalidUpgradePayloadReason::AuthorizeInvalidShare { signer })?;
    Ok(signer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_types::PrincipalId;

    fn limits(committee: usize, staying: usize) -> PermitLimits {
        let members = |n: usize| {
            (0..n as u64)
                .map(|i| NodeId::from(PrincipalId::new_node_test_id(i)))
                .collect()
        };
        permit_limits(&SubnetMembership {
            current_members: members(committee),
            staying_members: members(staying),
        })
    }

    /// The (permits, threshold) pairs of the design document's table.
    #[test]
    fn test_permits_match_the_documented_table() {
        for (n, permits, threshold) in [
            (4, 1, 3),
            (7, 1, 6),
            (10, 1, 9),
            (13, 2, 11),
            (28, 6, 22),
            (40, 9, 31),
        ] {
            assert_eq!(limits(n, n).permits, permits, "permits for N={n}");
            assert_eq!(
                limits(n, n).authorization_threshold,
                threshold,
                "threshold for N={n}"
            );
        }
    }

    /// Each leaver takes one permit, down to zero; the threshold is
    /// unchanged — leavers cannot sign, so their absence is already
    /// accounted for.
    #[test]
    fn test_leavers_reduce_permits() {
        for (leaving, permits, threshold) in [(0, 2, 11), (1, 1, 11), (2, 0, 11), (3, 0, 11)] {
            assert_eq!(
                limits(13, 13 - leaving).permits,
                permits,
                "permits with {leaving} leavers"
            );
            assert_eq!(
                limits(13, 13 - leaving).authorization_threshold,
                threshold,
                "threshold with {leaving} leavers"
            );
        }
        assert_eq!(limits(40, 37).permits, 6);
    }
}
