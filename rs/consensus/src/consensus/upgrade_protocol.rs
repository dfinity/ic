//! Pure upgrade-permit protocol logic shared by the share signer (the pool
//! manager), the payload builder, and the payload validator.
//!
//! Membership distinguishes the committee (registry at the CUP/summary
//! version for the block height, changing only at DKG interval boundaries)
//! from the current members staying even at the new CUP (still present at the
//! block's registry version).

use ic_consensus_utils::crypto::ConsensusCrypto;
use ic_consensus_utils::membership::Membership;
use ic_interfaces::batch_payload::PastPayload;
use ic_interfaces::consensus::{InvalidPayloadReason, PayloadValidationError};
use ic_interfaces::upgrade::InvalidUpgradePayloadReason;
use ic_logger::{ReplicaLogger, info, warn};
use ic_replicated_state::metadata_state::{REQUEST_TIMEOUT_BLOCKS, UpgradeState};
use ic_types::batch::bytes_to_upgrade_payload;
use ic_types::consensus::upgrade::{UpgradePermitAction, UpgradePermitShares};
use ic_types::consensus::UpgradePermitAuthorizationShare;
use ic_types::{Height, NodeId, RegistryVersion};
use num_traits::SaturatingSub;
use std::collections::{BTreeMap, BTreeSet};

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

/// Reconstruct the upgrade state at `height` from the certified anchor and
/// the certification-gap payloads, pruning expired requests and departed
/// members.
pub(crate) fn reconstruct_state(
    anchor: &UpgradeState,
    past_payloads: &[PastPayload],
    staying: &BTreeSet<NodeId>,
    height: Height,
) -> UpgradeState {
    let mut state = anchor.clone();
    for pp in past_payloads {
        if let Ok(actions) = bytes_to_upgrade_payload(pp.payload) {
            let prune_below = pp.height.saturating_sub(&REQUEST_TIMEOUT_BLOCKS);
            state.apply(&actions, prune_below, staying);
        }
    }
    let prune_below = height.saturating_sub(&REQUEST_TIMEOUT_BLOCKS);
    state.apply(&[], prune_below, staying);
    state
}

/// Check one share: the content must match `(requestor_node, request_height)`, the
/// signer must be a staying member, and the signature must verify against
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

/// The block maker's actions at `height`: return its permit if no reboot is
/// needed, request one if a slot is free, and authorize outstanding requests
/// that have collected enough shares, up to P.
pub(crate) fn build_actions(
    node_id: NodeId,
    needs_reboot: bool,
    height: Height,
    membership: &SubnetMembership,
    upgrade_state: &UpgradeState,
    pool_shares: &[UpgradePermitAuthorizationShare],
    logger: &ReplicaLogger,
) -> Vec<UpgradePermitAction> {
    let limits = membership.limits();
    let mut actions = vec![];

    if upgrade_state.authorized.contains(&node_id) && !needs_reboot {
        actions.push(UpgradePermitAction::Return { node: node_id });
    }

    if needs_reboot
        && !upgrade_state.authorized.contains(&node_id)
        && upgrade_state.slots_in_use() < limits.max_parallel_reboots
    {
        actions.push(UpgradePermitAction::Request {
            node: node_id,
            request_height: height,
        });
    }

    // Authorize outstanding requests with enough collected shares, up to P.
    // Shares are keyed by signer, so the group size is the number of
    // distinct signers; the validator re-checks every share.
    let mut collected: BTreeMap<
        (NodeId, Height),
        BTreeMap<NodeId, UpgradePermitAuthorizationShare>,
    > = BTreeMap::new();
    for share in pool_shares {
        collected
            .entry((share.content.node, share.content.request_height))
            .or_default()
            .insert(share.signature.signer, share.clone());
    }
    info!(
        logger,
        "upgrade_payload: authorize check: n={} p={} threshold={} validated_shares={} collected_keys={:?} requested={:?}",
        limits.subnet_size,
        limits.max_parallel_reboots,
        limits.authorization_threshold,
        pool_shares.len(),
        collected.keys().collect::<Vec<_>>(),
        upgrade_state.requested,
    );
    let mut authorized_after = upgrade_state.authorized.len();
    for (&req_node, &req_height) in &upgrade_state.requested {
        if authorized_after >= limits.max_parallel_reboots {
            break;
        }
        if upgrade_state.authorized.contains(&req_node) {
            continue;
        }
        if let Some(shares) = collected.get(&(req_node, req_height)) {
            if shares.len() >= limits.authorization_threshold {
                actions.push(UpgradePermitAction::Authorize(UpgradePermitShares {
                    node: req_node,
                    shares: shares.values().cloned().collect(),
                }));
                authorized_after += 1;
            }
        }
    }
    actions
}

/// Validate a block's upgrade actions: requests and returns must come from
/// the proposer, slots in use must not exceed P, and authorizations must
/// reference an outstanding request with ≥ N−P valid share signatures from
/// distinct staying members. Actions are folded so that later actions in the
/// same block see the effects of earlier ones.
pub(crate) fn validate_actions(
    height: Height,
    proposer: NodeId,
    membership: &SubnetMembership,
    anchor: &UpgradeState,
    past_payloads: &[PastPayload],
    actions: &[UpgradePermitAction],
    registry_version: RegistryVersion,
    crypto: &dyn ConsensusCrypto,
) -> Result<(), PayloadValidationError> {
    let staying = &membership.staying_members;
    let limits = membership.limits();
    let mut upgrade_state = reconstruct_state(anchor, past_payloads, staying, height);

    for action in actions {
        match action {
            UpgradePermitAction::Request { node, .. } => {
                if *node != proposer {
                    return Err(invalid_upgrade(
                        InvalidUpgradePayloadReason::RequestNodeMismatch {
                            node: *node,
                            proposer,
                        },
                    ));
                }
                if upgrade_state.slots_in_use() >= limits.max_parallel_reboots {
                    return Err(invalid_upgrade(
                        InvalidUpgradePayloadReason::SlotsExhausted {
                            slots_in_use: upgrade_state.slots_in_use(),
                            capacity: limits.max_parallel_reboots,
                        },
                    ));
                }
                // Fold so subsequent actions in the same block see its effect.
                let prune_below = height.saturating_sub(&REQUEST_TIMEOUT_BLOCKS);
                upgrade_state.apply(&[action.clone()], prune_below, staying);
            }
            UpgradePermitAction::Return { node } => {
                if *node != proposer {
                    return Err(invalid_upgrade(
                        InvalidUpgradePayloadReason::ReturnNodeMismatch {
                            node: *node,
                            proposer,
                        },
                    ));
                }
            }
            UpgradePermitAction::Authorize(shares) => {
                let Some(&request_height) = upgrade_state.requested.get(&shares.node) else {
                    return Err(invalid_upgrade(
                        InvalidUpgradePayloadReason::AuthorizeNoOutstandingRequest {
                            node: shares.node,
                        },
                    ));
                };
                let mut signers = BTreeSet::new();
                for share in &shares.shares {
                    let signer = validate_share(
                        share,
                        shares.node,
                        request_height,
                        staying,
                        registry_version,
                        crypto,
                    )
                    .map_err(invalid_upgrade)?;
                    signers.insert(signer);
                }
                if signers.len() < limits.authorization_threshold {
                    return Err(invalid_upgrade(
                        InvalidUpgradePayloadReason::AuthorizeInsufficientShares {
                            collected: signers.len(),
                            threshold: limits.authorization_threshold,
                        },
                    ));
                }
                // Fold so subsequent actions see the updated state.
                let prune_below = height.saturating_sub(&REQUEST_TIMEOUT_BLOCKS);
                upgrade_state.apply(&[action.clone()], prune_below, staying);
            }
        }
    }
    Ok(())
}

pub(crate) fn invalid_upgrade(reason: InvalidUpgradePayloadReason) -> PayloadValidationError {
    ic_interfaces::validation::ValidationError::InvalidArtifact(
        InvalidPayloadReason::InvalidUpgradePayload(reason),
    )
}
