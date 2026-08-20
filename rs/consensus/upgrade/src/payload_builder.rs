//! Builds and validates the `upgrade` bytes of each data block's
//! `BatchPayload` for the Phase-2 rolling reboot. The kernel shared with
//! the share signer (membership views, share validation) is in the crate
//! root.

use crate::{permit_limits, subnet_membership, validate_share};
use ic_consensus_utils::crypto::ConsensusCrypto;
use ic_consensus_utils::membership::Membership;
use ic_interfaces::batch_payload::{BatchPayloadBuilder, PastPayload, ProposalContext};
use ic_interfaces::consensus::{InvalidPayloadReason, PayloadValidationError};
use ic_interfaces::upgrade::InvalidUpgradePayloadReason;
use ic_interfaces::upgrade_permit_auth::UpgradePermitAuthPool;
use ic_interfaces_state_manager::StateReader;
use ic_logger::ReplicaLogger;
use ic_replicated_state::ReplicatedState;
use ic_replicated_state::metadata_state::UpgradeState;
use ic_types::batch::{bytes_to_upgrade_payload, upgrade_payload_to_bytes};
use ic_types::consensus::UpgradePermitAuthorizationShare;
use ic_types::consensus::upgrade::{UpgradePermitAction, UpgradePermitShares};
use ic_types::{Height, NodeId, NumBytes, PlatformVersion};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};
use ic_interfaces::validation::ValidationError;

/// Builds the upgrade section of a data block's `BatchPayload`.
pub struct UpgradePayloadBuilder {
    node_id: NodeId,
    membership: Arc<Membership>,
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
        membership: Arc<Membership>,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        pool: Arc<RwLock<dyn UpgradePermitAuthPool>>,
        crypto: Arc<dyn ConsensusCrypto>,
        platform_version: PlatformVersion,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            node_id,
            membership,
            state_reader,
            pool,
            crypto,
            platform_version,
            logger,
        }
    }

    /// The upgrade state at `height`: the committed anchor folded with the
    /// certification-gap payloads.
    fn upgrade_state_at(
        &self,
        past_payloads: &[PastPayload],
        members: &BTreeSet<NodeId>,
        height: Height,
    ) -> UpgradeState {
        let mut state = self
            .state_reader
            .get_latest_certified_state()
            .map(|s| s.get_ref().system_metadata().upgrade_state.clone())
            .unwrap_or_default();
        for pp in past_payloads {
            if let Ok(actions) = bytes_to_upgrade_payload(pp.payload) {
                state.apply(&actions, pp.height, members);
            }
        }
        state.apply(&[], height, members);
        state
    }
}

impl BatchPayloadBuilder for UpgradePayloadBuilder {
    fn build_payload(
        &self,
        height: Height,
        max_size: NumBytes,
        past_payloads: &[PastPayload],
        context: &ic_types::batch::ValidationContext,
    ) -> Vec<u8> {
        let membership = subnet_membership(
            &self.membership,
            height,
            context.registry_version,
            &self.logger,
        );
        let limits = permit_limits(&membership);
        let needs_reboot =
            self.platform_version.guestos_version != self.platform_version.binary_version;
        let upgrade_state =
            self.upgrade_state_at(past_payloads, &membership.current_members, height);

        let mut actions = vec![];

        if upgrade_state.authorized.contains(&self.node_id) && !needs_reboot {
            actions.push(UpgradePermitAction::Return { node: self.node_id });
        }

        let request_fits = upgrade_state.slots_in_use_after(
            &[UpgradePermitAction::Request {
                requestor_node: self.node_id,
                request_height: height,
            }],
            height,
            &membership.current_members,
        ) <= limits.permits;
        if needs_reboot && !upgrade_state.authorized.contains(&self.node_id) && request_fits {
            actions.push(UpgradePermitAction::Request {
                requestor_node: self.node_id,
                request_height: height,
            });
        }

        // Authorize every request with enough shares
        let mut collected: BTreeMap<(NodeId, Height), Vec<UpgradePermitAuthorizationShare>> =
            BTreeMap::new();
        {
            let pool = self.pool.read().unwrap();
            for share in pool.get_validated_shares() {
                // Perhaps a node signed a permit before it knew that it was
                // going to leave, ignore its permit.
                if !membership.staying(&share.signature.signer) {
                    continue;
                }
                collected
                    .entry((share.content.requestor_node, share.content.request_height))
                    .or_default()
                    .push(share.clone());
            }
        }
        for (&req_node, &req_height) in &upgrade_state.requested {
            if upgrade_state.authorized.contains(&req_node) {
                continue;
            }
            if let Some(shares) = collected.get(&(req_node, req_height)) {
                if shares.len() >= limits.authorization_threshold {
                    actions.push(UpgradePermitAction::Authorize(UpgradePermitShares {
                        node: req_node,
                        shares: shares.clone(),
                    }));
                }
            }
        }

        upgrade_payload_to_bytes(actions, max_size)
    }

    fn validate_payload(
        &self,
        height: Height,
        proposal_context: &ProposalContext,
        payload: &[u8],
        past_payloads: &[PastPayload],
    ) -> Result<(), PayloadValidationError> {
        if payload.is_empty() {
            return Ok(());
        }
        let actions = bytes_to_upgrade_payload(payload).map_err(|e| {
            invalid_upgrade(InvalidUpgradePayloadReason::DecodeFailed(e.to_string()))
        })?;
        let registry_version = proposal_context.validation_context.registry_version;
        let membership =
            subnet_membership(&self.membership, height, registry_version, &self.logger);
        let limits = permit_limits(&membership);
        let upgrade_state =
            self.upgrade_state_at(past_payloads, &membership.current_members, height);

        for action in &actions {
            match action {
                UpgradePermitAction::Request { requestor_node: node, .. } => {
                    if *node != proposal_context.proposer {
                        return Err(invalid_upgrade(
                            InvalidUpgradePayloadReason::RequestNodeMismatch {
                                node: *node,
                                proposer: proposal_context.proposer,
                            },
                        ));
                    }
                    // The permit limit binds at request time;
                    // authorizations are slot-neutral.
                    let slots_in_use = upgrade_state.slots_in_use_after(
                        &actions,
                        height,
                        &membership.current_members,
                    );
                    if slots_in_use > limits.permits {
                        return Err(invalid_upgrade(
                            InvalidUpgradePayloadReason::SlotsExhausted {
                                slots_in_use,
                                permits: limits.permits,
                            },
                        ));
                    }
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
                            &membership.staying_members,
                            registry_version,
                            self.crypto.as_ref(),
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
                }
            }
        }

        Ok(())
    }
}

fn invalid_upgrade(reason: InvalidUpgradePayloadReason) -> PayloadValidationError {
    ValidationError::InvalidArtifact(
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
            bytes_to_upgrade_payload(payload).map_err(|e| {
                invalid_upgrade(InvalidUpgradePayloadReason::DecodeFailed(e.to_string()))
            })?;
        }
        Ok(())
    }
}

