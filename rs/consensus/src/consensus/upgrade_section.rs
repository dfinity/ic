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
use ic_types::consensus::upgrade::{UpgradePermitAction, UpgradePermitShares};
use ic_replicated_state::metadata_state::{REQUEST_TIMEOUT_BLOCKS, UpgradeState};
use ic_types::consensus::UpgradePermitAuthorizationContent;
use ic_types::batch::{bytes_to_upgrade_payload, upgrade_payload_to_bytes};
use ic_types::{Height, NodeId, NumBytes, PlatformVersion};
use num_traits::SaturatingSub;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};

/// Builds the upgrade section of a data block's `BatchPayload`.
pub struct UpgradePayloadBuilder {
    node_id: NodeId,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    pool: Arc<RwLock<dyn UpgradePermitAuthPool>>,
    crypto: Arc<dyn ConsensusCrypto>,
    platform_version: PlatformVersion,
    logger: ReplicaLogger,
}

impl UpgradePayloadBuilder {
    /// Create a new builder.
    pub fn new(
        node_id: NodeId,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        pool: Arc<RwLock<dyn UpgradePermitAuthPool>>,
        crypto: Arc<dyn ConsensusCrypto>,
        platform_version: PlatformVersion,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            node_id,
            state_reader,
            pool,
            crypto,
            platform_version,
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
            if let Ok(actions) = bytes_to_upgrade_payload(pp.payload) {
                let prune_below = pp.height.saturating_sub(&REQUEST_TIMEOUT_BLOCKS);
                state.apply(&actions, prune_below, members);
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

        let mut signers: BTreeMap<NodeId, ()> = BTreeMap::new();
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
            signers.insert(share.signature.signer, ());
        }

        if signers.len() < threshold {
            return Err(invalid_upgrade(
                InvalidUpgradePayloadReason::AuthorizeInsufficientShares {
                    collected: signers.len(),
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
            self.platform_version.guestos_version != self.platform_version.binary_version;

        let upgrade_state = self.read_upgrade_state(past_payloads, &members);

        info!(
            self.logger,
            "upgrade_payload: height={} needs_reboot={} authorized_contains_self={} authorized={:?} requested={:?} slots={}",
            height,
            needs_reboot,
            upgrade_state.authorized.contains(&self.node_id),
            upgrade_state.authorized,
            upgrade_state.requested,
            upgrade_state.slots_in_use(),
        );

        // Collect upgrade actions for this block. A block maker may produce
        // multiple actions — e.g. Request for itself and Authorize for another
        // node — as long as each is independently valid.
        let mut actions = vec![];

        // 1. If we are authorized and have finished rebooting, Return.
        if upgrade_state.authorized.contains(&self.node_id) && !needs_reboot {
            actions.push(UpgradePermitAction::Return { node: self.node_id });
        }

        // 2. If we need a reboot and slots are available, Request.
        if needs_reboot
            && !upgrade_state.authorized.contains(&self.node_id)
            && upgrade_state.slots_in_use() < UpgradeState::faults_tolerated(members.len())
        {
            actions.push(UpgradePermitAction::Request {
                node: self.node_id,
                request_height: height,
            });
        }

        // 3. Authorize all outstanding requests that have collected enough
        //    shares, up to the slot capacity.
        {
            let n = members.len();
            let p = UpgradeState::faults_tolerated(n);
            let threshold = n.saturating_sub(p);
            let pool = self.pool.read().unwrap();
            let validated_count = pool.get_validated_shares().count();
            let collected = {
                let mut map: BTreeMap<
                    (NodeId, ic_types::Height),
                    BTreeMap<NodeId, ic_types::consensus::UpgradePermitAuthorizationShare>,
                > = BTreeMap::new();
                for share in pool.get_validated_shares() {
                    let key = (share.content.node, share.content.request_height);
                    map.entry(key)
                        .or_default()
                        .insert(share.signature.signer, share.clone());
                }
                map
            };
            info!(
                self.logger,
                "upgrade_payload: authorize check: n={} threshold={} validated_shares={} collected_keys={:?} requested={:?}",
                n,
                threshold,
                validated_count,
                collected.keys().collect::<Vec<_>>(),
                upgrade_state.requested,
            );
            // Limit the number of simultaneously authorized (rebooting) nodes
            // to P. Authorizing a node transitions it from `requested` to
            // `authorized`, so we count authorized nodes plus any Authorize
            // actions already added in this block.
            let mut authorized_after = upgrade_state.authorized.len();
            for (&req_node, &req_height) in &upgrade_state.requested {
                if authorized_after >= p {
                    break;
                }
                if upgrade_state.authorized.contains(&req_node) {
                    continue;
                }
                if let Some(shares_map) = collected.get(&(req_node, req_height)) {
                    if shares_map.len() >= threshold {
                        actions.push(UpgradePermitAction::Authorize(UpgradePermitShares {
                            node: req_node,
                            shares: shares_map.values().cloned().collect(),
                        }));
                        authorized_after += 1;
                    }
                }
            }
        }

        info!(
            self.logger,
            "upgrade_payload: height={} n={} p={} slots={} requested={} authorized={} actions={:?}",
            height,
            members.len(),
            UpgradeState::faults_tolerated(members.len()),
            upgrade_state.slots_in_use(),
            upgrade_state.requested.len(),
            upgrade_state.authorized.len(),
            actions,
        );

        upgrade_payload_to_bytes(actions, max_size)
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
        let actions = bytes_to_upgrade_payload(payload)
            .map_err(|e| invalid_upgrade(InvalidUpgradePayloadReason::DecodeFailed(e.to_string())))?;

        let members = self.read_node_ids();
        let mut upgrade_state = self.read_upgrade_state(past_payloads, &members);

        for action in &actions {
            match action {
                UpgradePermitAction::Request { node, request_height } => {
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
                    // Fold this action into the state so subsequent actions in
                    // the same block see its effect (e.g. a Request then
                    // Authorize for the same node).
                    let prune_below = request_height.saturating_sub(&REQUEST_TIMEOUT_BLOCKS);
                    upgrade_state.apply(&[action.clone()], prune_below, &members);
                }
                UpgradePermitAction::Return { node } => {
                    if *node != proposal_context.proposer {
                        return Err(invalid_upgrade(
                            InvalidUpgradePayloadReason::ReturnNodeMismatch {
                                node: *node,
                                proposer: proposal_context.proposer,
                            },
                        ));
                    }
                }
                UpgradePermitAction::Authorize(shares) => {
                    self.validate_authorize(
                        shares,
                        &upgrade_state,
                        &members,
                        proposal_context,
                    )?;
                    // Fold so subsequent actions see the updated state.
                    let prune_below = proposal_context
                        .validation_context
                        .certified_height
                        .saturating_sub(&REQUEST_TIMEOUT_BLOCKS);
                    upgrade_state.apply(&[action.clone()], prune_below, &members);
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
