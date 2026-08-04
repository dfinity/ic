//! Upgrade section builder for the Phase-2 rolling reboot.
//!
//! Produces the `upgrade` bytes in each data block's `BatchPayload`.
//! Three actions:
//! - `Request`: block maker requests reboot permission for itself
//! - `Authorize`: block maker includes collected auth shares (≥ N−P) to authorize a node
//! - `Return`: block maker releases its slot after rebooting
//!
//! Validators check that outstanding requests don't exceed P.
//!
//! The committed upgrade state and subnet membership are read from the state
//! manager (certified replicated state). The certification-gap blocks are
//! folded via `past_payloads`.

use ic_consensus_utils::crypto::ConsensusCrypto;
use ic_interfaces::batch_payload::{BatchPayloadBuilder, PastPayload, ProposalContext};
use ic_interfaces::consensus::{InvalidPayloadReason, PayloadValidationError};
use ic_interfaces::upgrade::InvalidUpgradePayloadReason;
use ic_interfaces::upgrade_permit_auth::UpgradePermitAuthPool;
use ic_interfaces_state_manager::StateReader;
use ic_logger::{ReplicaLogger, info, warn};
use ic_replicated_state::ReplicatedState;
use ic_types::consensus::upgrade::{
    UpgradePayload, UpgradePayloadContent, UpgradePermitShares, UpgradeState,
};
use ic_types::consensus::UpgradePermitAuthorizationContent;
use ic_types::batch::{bytes_to_upgrade_payload, upgrade_payload_to_bytes};
use ic_types::{Height, NodeId, NumBytes};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};

/// Builds the upgrade section of a data block's `BatchPayload`.
pub struct UpgradePayloadBuilder {
    node_id: NodeId,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    pool: Arc<RwLock<dyn UpgradePermitAuthPool>>,
    crypto: Arc<dyn ConsensusCrypto>,
    logger: ReplicaLogger,
}

impl UpgradePayloadBuilder {
    /// Create a new builder.
    pub fn new(
        node_id: NodeId,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        pool: Arc<RwLock<dyn UpgradePermitAuthPool>>,
        crypto: Arc<dyn ConsensusCrypto>,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            node_id,
            state_reader,
            pool,
            crypto,
            logger,
        }
    }

    /// Read subnet membership from certified replicated state.
    fn read_node_ids(&self) -> BTreeSet<NodeId> {
        self.state_reader
            // TODO: can we read from certified state?
            .get_latest_certified_state()
            .and_then(|s| {
                let metadata = s.get_ref().system_metadata();
                metadata
                    .network_topology
                    .subnets()
                    .get(&metadata.own_subnet_id)
                    .map(|topology| topology.nodes.clone())
            })
            .unwrap_or_default()
    }

    /// Read the upgrade state from certified replicated state, then fold in the
    /// certification-gap payloads for the true current view. Each past payload
    /// is applied at its own height so that request timeouts are computed
    /// correctly (not collapsed to the current block height).
    fn read_upgrade_state(
        &self,
        past_payloads: &[PastPayload],
        members: &BTreeSet<NodeId>,
    ) -> UpgradeState {
        let mut state = self
            .state_reader
            .get_latest_certified_state()
            .map(|s| s.get_ref().system_metadata().upgrade_state.clone())
            .unwrap_or_default();
        for pp in past_payloads {
            if let Ok(payload) = bytes_to_upgrade_payload(pp.payload) {
                state.apply(&payload, pp.height, members);
            }
        }
        state
    }

    /// Validate an `Authorize` payload: the node must have an outstanding
    /// request, and the included shares must be ≥ threshold (N−P) valid
    /// signatures from distinct subnet members over `(node, request_height)`.
    fn validate_authorize(
        &self,
        shares: &UpgradePermitShares,
        upgrade_state: &UpgradeState,
        members: &BTreeSet<NodeId>,
        proposal_context: &ProposalContext,
    ) -> Result<(), PayloadValidationError> {
        // The node must have an outstanding (non-expired) request.
        let Some(&request_height) = upgrade_state.requested.get(&shares.node) else {
            return Err(invalid_upgrade(
                InvalidUpgradePayloadReason::AuthorizeNoOutstandingRequest { node: shares.node },
            ));
        };

        let n = members.len();
        let p = UpgradeState::faults_tolerated(n);
        let threshold = n.saturating_sub(p);

        // Deduplicate shares by signer; each share must reference the same
        // (node, request_height) and the signer must be a current member.
        let registry_version = proposal_context.validation_context.registry_version;
        let mut seen_signers: BTreeMap<NodeId, ()> = BTreeMap::new();
        for share in &shares.shares {
            // The share content must match the authorized node + its request height.
            if share.content.node != shares.node
                || share.content.request_height != request_height
            {
                warn!(
                    self.logger,
                    "upgrade_payload: authorize share content mismatch: \
                     expected node={:?} height={:?}, got node={:?} height={:?}",
                    shares.node, request_height, share.content.node, share.content.request_height,
                );
                return Err(invalid_upgrade(
                    InvalidUpgradePayloadReason::AuthorizeInvalidShare {
                        signer: share.signature.signer,
                    },
                ));
            }
            if !members.contains(&share.signature.signer) {
                return Err(invalid_upgrade(
                    InvalidUpgradePayloadReason::AuthorizeInvalidShare {
                        signer: share.signature.signer,
                    },
                ));
            }
            // Verify the signature against the registry version pinned to the
            // request block.
            let content = UpgradePermitAuthorizationContent {
                node: share.content.node,
                request_height: share.content.request_height,
            };
            if self
                .crypto
                .verify_basic_sig(
                    &share.signature.signature,
                    &content,
                    share.signature.signer,
                    registry_version,
                )
                .is_err()
            {
                return Err(invalid_upgrade(
                    InvalidUpgradePayloadReason::AuthorizeInvalidShare {
                        signer: share.signature.signer,
                    },
                ));
            }
            seen_signers.insert(share.signature.signer, ());
        }

        if seen_signers.len() < threshold {
            return Err(invalid_upgrade(
                InvalidUpgradePayloadReason::AuthorizeInsufficientShares {
                    collected: seen_signers.len(),
                    threshold,
                },
            ));
        }
        Ok(())
    }
}

impl BatchPayloadBuilder for UpgradePayloadBuilder {
    fn build_payload(
        &self,
        height: Height,
        max_size: NumBytes,
        past_payloads: &[PastPayload],
        _context: &ic_types::batch::ValidationContext,
    ) -> Vec<u8> {
        let members = self.read_node_ids();

        // Determine if this node still needs to reboot: compare the GuestOS
        // version (version.txt) with the replica binary version
        // (replica_version.txt). After Phase 1 overlay, they differ (V1 vs V2).
        // After Phase 2 reboot, they match again.
        let needs_reboot =
            ic_types::GuestOsVersion::default() != ic_types::ReplicaVersion::default();

        let upgrade_state = self.read_upgrade_state(past_payloads, &members);

        // Determine the content for this block.
        let content = if upgrade_state.authorized.contains(&self.node_id) {
            // Already authorized: if we've rebooted (versions match), return.
            if !needs_reboot {
                Some(UpgradePayloadContent::Return { node: self.node_id })
            } else {
                None // still rebooting
            }
        } else if needs_reboot
            && upgrade_state.slots_in_use() < UpgradeState::faults_tolerated(members.len())
        {
            // Phase 2 needed and slots available → request.
            Some(UpgradePayloadContent::Request {
                node: self.node_id,
                request_height: height,
            })
        } else {
            // Not requesting ourselves: check if we can authorize someone else.
            let n = members.len();
            let p = UpgradeState::faults_tolerated(n);
            let threshold = n.saturating_sub(p);
            let pool = self.pool.read().unwrap();
            let collected: std::collections::BTreeMap<
                (NodeId, ic_types::Height),
                std::collections::BTreeMap<NodeId, ic_types::consensus::UpgradePermitAuthorizationShare>,
            > = {
                let mut map = std::collections::BTreeMap::new();
                for share in pool.get_validated_shares() {
                    let key = (share.content.node, share.content.request_height);
                    map.entry(key)
                        .or_insert_with(std::collections::BTreeMap::new)
                        .insert(share.signature.signer, share.clone());
                }
                map
            };
            // Find the first outstanding request with enough shares that hasn't
            // been authorized yet.
            upgrade_state
                .requested
                .iter()
                .find_map(|(&req_node, &req_height)| {
                    if upgrade_state.authorized.contains(&req_node) {
                        return None;
                    }
                    let shares_map = collected.get(&(req_node, req_height))?;
                    if shares_map.len() >= threshold {
                        Some(UpgradePayloadContent::Authorize(
                            ic_types::consensus::upgrade::UpgradePermitShares {
                                node: req_node,
                                shares: shares_map.values().cloned().collect(),
                            },
                        ))
                    } else {
                        None
                    }
                })
        };

        info!(
            self.logger,
            "upgrade_payload: height={} n={} p={} slots={} requested={} authorized={} content={:?}",
            height,
            members.len(),
            UpgradeState::faults_tolerated(members.len()),
            upgrade_state.slots_in_use(),
            upgrade_state.requested.len(),
            upgrade_state.authorized.len(),
            content,
        );

        let payload = UpgradePayload { content };
        upgrade_payload_to_bytes(payload, max_size)
    }

    fn validate_payload(
        &self,
        _height: Height,
        proposal_context: &ProposalContext,
        payload: &[u8],
        past_payloads: &[PastPayload],
    ) -> Result<(), PayloadValidationError> {
        if payload.is_empty() {
            return Ok(());
        }
        let parsed = bytes_to_upgrade_payload(payload)
            .map_err(|e| invalid_upgrade(InvalidUpgradePayloadReason::DecodeFailed(e.to_string())))?;

        let members = self.read_node_ids();
        let upgrade_state = self.read_upgrade_state(past_payloads, &members);

        if let Some(content) = &parsed.content {
            match content {
                UpgradePayloadContent::Request { node, .. } => {
                    if *node != proposal_context.proposer {
                        return Err(invalid_upgrade(
                            InvalidUpgradePayloadReason::RequestNodeMismatch {
                                node: *node,
                                proposer: proposal_context.proposer,
                            },
                        ));
                    }
                    let p = UpgradeState::faults_tolerated(members.len());
                    if upgrade_state.slots_in_use() >= p {
                        return Err(invalid_upgrade(
                            InvalidUpgradePayloadReason::SlotsExhausted {
                                slots_in_use: upgrade_state.slots_in_use(),
                                capacity: p,
                            },
                        ));
                    }
                }
                UpgradePayloadContent::Return { node } => {
                    if *node != proposal_context.proposer {
                        return Err(invalid_upgrade(
                            InvalidUpgradePayloadReason::ReturnNodeMismatch {
                                node: *node,
                                proposer: proposal_context.proposer,
                            },
                        ));
                    }
                }
                UpgradePayloadContent::Authorize(shares) => {
                    return self.validate_authorize(
                        shares,
                        &upgrade_state,
                        &members,
                        proposal_context,
                    );
                }
            }
        }
        Ok(())
    }
}

fn invalid_upgrade(reason: InvalidUpgradePayloadReason) -> PayloadValidationError {
    ic_interfaces::validation::ValidationError::InvalidArtifact(
        InvalidPayloadReason::InvalidUpgradePayload(reason),
    )
}

/// A stub builder for tests/state-machine-tests that produces empty upgrade sections.
pub struct UpgradePayloadBuilderStub;

impl UpgradePayloadBuilderStub {
    /// Create a new stub builder.
    pub fn new() -> Self {
        Self
    }
}

impl Default for UpgradePayloadBuilderStub {
    fn default() -> Self {
        Self::new()
    }
}

impl BatchPayloadBuilder for UpgradePayloadBuilderStub {
    fn build_payload(
        &self,
        _height: Height,
        _max_size: NumBytes,
        _past_payloads: &[PastPayload],
        _context: &ic_types::batch::ValidationContext,
    ) -> Vec<u8> {
        vec![]
    }

    fn validate_payload(
        &self,
        _height: Height,
        _proposal_context: &ProposalContext,
        payload: &[u8],
        _past_payloads: &[PastPayload],
    ) -> Result<(), PayloadValidationError> {
        if !payload.is_empty() {
            bytes_to_upgrade_payload(payload)
                .map_err(|e| invalid_upgrade(InvalidUpgradePayloadReason::DecodeFailed(e.to_string())))?;
        }
        Ok(())
    }
}
