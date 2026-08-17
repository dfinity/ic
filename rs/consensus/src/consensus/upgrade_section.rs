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
//! The committed upgrade state is read from the state manager (certified
//! replicated state). Membership distinguishes the committee (registry at the
//! CUP/summary version for the block height, changing only at DKG interval
//! boundaries) from the future subnet (registry at the block's registry
//! version). The certification-gap blocks are folded via `past_payloads`.

use ic_consensus_utils::crypto::ConsensusCrypto;
use ic_consensus_utils::membership::Membership;
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
use ic_types::{Height, NodeId, NumBytes, PlatformVersion, RegistryVersion};
use num_traits::SaturatingSub;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};

pub(crate) struct SubnetMembership {
    /// The actual current members: registry membership at the CUP/summary
    /// version for the block height (changes only at DKG interval boundaries).
    pub(crate) current_members: BTreeSet<NodeId>,
    /// Current members staying even at the new CUP: still present at the
    /// block's registry version (the foreseeable future).
    pub(crate) members_for_foreseeable_future: BTreeSet<NodeId>,
}

impl SubnetMembership {
    /// Is the node a current member staying even at the new CUP?
    pub(crate) fn staying(&self, node: &NodeId) -> bool {
        self.members_for_foreseeable_future.contains(node)
    }
}

/// Subnet membership at the block height and registry version.
/// `current_members` is the registry view at the CUP/summary version for
/// the height, which only changes at DKG interval boundaries;
/// `members_for_foreseeable_future` are the current members still present
/// at the block's registry version. Falls back to the registry view if no
/// summary covers the height.
pub(crate) fn subnet_membership(
    membership: &Membership,
    height: Height,
    registry_version: RegistryVersion,
    logger: &ReplicaLogger,
) -> SubnetMembership {
    let future_registry: BTreeSet<NodeId> = membership
        .get_nodes_at_version(registry_version)
        .map(|nodes| nodes.into_iter().collect())
        .unwrap_or_default();
    let current_members: BTreeSet<NodeId> = match membership.get_nodes(height) {
        Ok(nodes) => nodes.into_iter().collect(),
        Err(e) => {
            warn!(
                logger,
                "upgrade_payload: couldn't determine the committee at height {:?}: {:?}",
                height,
                e
            );
            future_registry.clone()
        }
    };
    let members_for_foreseeable_future = current_members
        .intersection(&future_registry)
        .cloned()
        .collect();
    SubnetMembership {
        current_members,
        members_for_foreseeable_future,
    }
}

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

    /// Subnet membership at the block height and registry version.
    fn read_membership(&self, height: Height, registry_version: RegistryVersion) -> SubnetMembership {
        subnet_membership(&self.membership, height, registry_version, &self.logger)
    }

    /// Read the upgrade state from certified replicated state, then fold in the
    /// certification-gap payloads for the true current view.
    fn read_upgrade_state(
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
                let prune_below = pp.height.saturating_sub(&REQUEST_TIMEOUT_BLOCKS);
                state.apply(&actions, prune_below, members);
            }
        }
        let prune_below = height.saturating_sub(&REQUEST_TIMEOUT_BLOCKS);
        state.apply(&[], prune_below, members);
        state
    }

    /// Validate an `Authorize` payload: the node must have an outstanding
    /// request, and the included shares must be ≥ threshold (N−P) valid
    /// signatures from distinct members over `(node, request_height)`.
    /// N is the current subnet size; signers must be future members.
    fn validate_authorize(
        &self,
        shares: &UpgradePermitShares,
        upgrade_state: &UpgradeState,
        membership: &SubnetMembership,
        proposal_context: &ProposalContext,
    ) -> Result<(), PayloadValidationError> {
        let Some(&request_height) = upgrade_state.requested.get(&shares.node) else {
            return Err(invalid_upgrade(
                InvalidUpgradePayloadReason::AuthorizeNoOutstandingRequest { node: shares.node },
            ));
        };

        let n = membership.current_members.len();
        let p = UpgradeState::max_parallel_reboots(n);
        let threshold = n.saturating_sub(p);

        let registry_version = proposal_context.validation_context.registry_version;

        let mut signers: BTreeMap<NodeId, ()> = BTreeMap::new();
        for share in &shares.shares {
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
            if !membership.members_for_foreseeable_future.contains(&share.signature.signer) {
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
        context: &ic_types::batch::ValidationContext,
    ) -> Vec<u8> {
        let membership = self.read_membership(height, context.registry_version);
        let n = membership.current_members.len();
        let p = UpgradeState::max_parallel_reboots(n);
        let threshold = n.saturating_sub(p);

        let needs_reboot =
            self.platform_version.guestos_version != self.platform_version.binary_version;

        let upgrade_state = self.read_upgrade_state(
            past_payloads,
            &membership.members_for_foreseeable_future,
            height,
        );

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

        let mut actions = vec![];

        if upgrade_state.authorized.contains(&self.node_id) && !needs_reboot {
            actions.push(UpgradePermitAction::Return { node: self.node_id });
        }

        if needs_reboot
            && !upgrade_state.authorized.contains(&self.node_id)
            && upgrade_state.slots_in_use() < p
        {
            actions.push(UpgradePermitAction::Request {
                node: self.node_id,
                request_height: height,
            });
        }

        // Authorize outstanding requests with enough collected shares, up to P.
        {
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
                "upgrade_payload: authorize check: n={} p={} threshold={} validated_shares={} collected_keys={:?} requested={:?}",
                n,
                p,
                threshold,
                validated_count,
                collected.keys().collect::<Vec<_>>(),
                upgrade_state.requested,
            );
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
            "upgrade_payload: height={} staying={} n={} p={} slots={} requested={} authorized={} actions={:?}",
            height,
            membership.members_for_foreseeable_future.len(),
            n,
            p,
            upgrade_state.slots_in_use(),
            upgrade_state.requested.len(),
            upgrade_state.authorized.len(),
            actions,
        );

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
        let actions = bytes_to_upgrade_payload(payload)
            .map_err(|e| invalid_upgrade(InvalidUpgradePayloadReason::DecodeFailed(e.to_string())))?;

        let membership = self.read_membership(
            height,
            proposal_context.validation_context.registry_version,
        );
        let mut upgrade_state = self.read_upgrade_state(
            past_payloads,
            &membership.members_for_foreseeable_future,
            height,
        );

        for action in &actions {
            match action {
                UpgradePermitAction::Request { node, .. } => {
                    if *node != proposal_context.proposer {
                        return Err(invalid_upgrade(
                            InvalidUpgradePayloadReason::RequestNodeMismatch {
                                node: *node,
                                proposer: proposal_context.proposer,
                            },
                        ));
                    }
                    let p = UpgradeState::max_parallel_reboots(
                        membership.current_members.len(),
                    );
                    if upgrade_state.slots_in_use() >= p {
                        return Err(invalid_upgrade(
                            InvalidUpgradePayloadReason::SlotsExhausted {
                                slots_in_use: upgrade_state.slots_in_use(),
                                capacity: p,
                            },
                        ));
                    }
                    // Fold so subsequent actions in the same block see its effect.
                    let prune_below = height.saturating_sub(&REQUEST_TIMEOUT_BLOCKS);
                    upgrade_state.apply(
                        &[action.clone()],
                        prune_below,
                        &membership.members_for_foreseeable_future,
                    );
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
                        &membership,
                        proposal_context,
                    )?;
                    // Fold so subsequent actions see the updated state.
                    let prune_below = height.saturating_sub(&REQUEST_TIMEOUT_BLOCKS);
                    upgrade_state.apply(
                        &[action.clone()],
                        prune_below,
                        &membership.members_for_foreseeable_future,
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

#[cfg(test)]
mod tests {
    use super::*;
    use ic_consensus_mocks::dependencies_with_subnet_records_with_raw_state_manager;
    use ic_interfaces_state_manager::Labeled;
    use ic_logger::replica_logger::no_op_logger;
    use ic_protobuf::registry::subnet::v1::SubnetRecord;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_registry_subnet_type::SubnetType;
    use ic_test_utilities::artifact_pool_config::with_test_pool_config;
    use ic_test_utilities_registry::{SubnetRecordBuilder, add_subnet_record};
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::batch::ValidationContext;
    use ic_types::consensus::UpgradePermitAuthorizationShare;
    use ic_types::crypto::{BasicSig, BasicSigOf, CryptoHash, CryptoHashOf};
    use ic_types::signature::BasicSignature;
    use ic_types::time::UNIX_EPOCH;

    const MAX_SIZE: NumBytes = NumBytes::new(1024 * 1024);

    fn subnet_record(nodes: Vec<NodeId>) -> SubnetRecord {
        SubnetRecordBuilder::from(&nodes).build()
    }

    struct TestSetup {
        builder: UpgradePayloadBuilder,
        registry_data_provider: Arc<ProtoRegistryDataProvider>,
        registry: Arc<FakeRegistryClient>,
    }

    fn test_setup(records: Vec<(u64, SubnetRecord)>) -> TestSetup {
        with_test_pool_config(|pool_config| {
            let deps = dependencies_with_subnet_records_with_raw_state_manager(
                pool_config,
                subnet_test_id(0),
                records,
            );
            let state = Arc::new(ReplicatedState::new(subnet_test_id(0), SubnetType::Application));
            deps.state_manager
                .get_mut()
                .expect_get_latest_certified_state()
                .times(1..)
                .return_const(Some(Labeled::new(Height::new(0), state)));
            TestSetup {
                builder: UpgradePayloadBuilder::new(
                    node_test_id(0),
                    deps.membership,
                    deps.state_manager,
                    deps.upgrade_permit_auth_pool as Arc<RwLock<dyn UpgradePermitAuthPool>>,
                    deps.crypto,
                    PlatformVersion::default(),
                    no_op_logger(),
                ),
                registry_data_provider: deps.registry_data_provider,
                registry: deps.registry,
            }
        })
    }

    /// Applies a membership delta after pool creation, so the committee
    /// (frozen in the genesis CUP at the initial version) stays behind the
    /// registry.
    fn apply_membership_delta(setup: &TestSetup, version: u64, nodes: Vec<NodeId>) {
        add_subnet_record(
            &setup.registry_data_provider,
            version,
            subnet_test_id(0),
            subnet_record(nodes),
        );
        setup.registry.update_to_latest_version();
    }

    fn share(signer: u64, node: u64, request_height: Height) -> UpgradePermitAuthorizationShare {
        UpgradePermitAuthorizationShare {
            content: UpgradePermitAuthorizationContent {
                node: node_test_id(node),
                request_height,
            },
            signature: BasicSignature {
                signature: BasicSigOf::new(BasicSig(vec![])),
                signer: node_test_id(signer),
            },
        }
    }

    fn validation_context(registry_version: RegistryVersion) -> ValidationContext {
        ValidationContext {
            certified_height: Height::new(0),
            registry_version,
            time: UNIX_EPOCH,
        }
    }

    fn validate(
        builder: &UpgradePayloadBuilder,
        height: Height,
        registry_version: RegistryVersion,
        proposer: u64,
        payload: &[u8],
        past_payloads: &[PastPayload],
    ) -> Result<(), PayloadValidationError> {
        let context = validation_context(registry_version);
        builder.validate_payload(
            height,
            &ProposalContext {
                proposer: node_test_id(proposer),
                validation_context: &context,
            },
            payload,
            past_payloads,
        )
    }

    /// A validator whose local registry already contains a newer version with
    /// a node removal must still accept a block whose context pins the older
    /// version: the staying set is resolved against the block's version, not
    /// the tip, and the committee only changes at DKG interval boundaries.
    #[test]
    fn test_validator_with_newer_registry_accepts_block_at_context_version() {
        // Committee frozen at V1 with 4 nodes; the removal delta lands at V2
        // afterwards. N=4 -> P=1, threshold=3.
        let setup = test_setup(vec![(1, subnet_record((0..4).map(node_test_id).collect()))]);
        apply_membership_delta(&setup, 2, (0..3).map(node_test_id).collect());

        let request_height = Height::new(10);
        let payload = upgrade_payload_to_bytes(
            vec![
                UpgradePermitAction::Request {
                    node: node_test_id(0),
                    request_height,
                },
                UpgradePermitAction::Authorize(UpgradePermitShares {
                    node: node_test_id(0),
                    shares: vec![share(1, 0, request_height), share(2, 0, request_height), share(3, 0, request_height)],
                }),
            ],
            MAX_SIZE,
        );

        // At the block's version V1 all three signers are staying members: accept.
        assert!(validate(&setup.builder, Height::new(10), RegistryVersion::new(1), 0, &payload, &[]).is_ok());
        // At V2 node 3 is not staying even though the committee still
        // contains it: reject.
        assert!(validate(&setup.builder, Height::new(10), RegistryVersion::new(2), 0, &payload, &[]).is_err());
    }

    /// The committee only changes at DKG interval boundaries (CUP/summary
    /// version); a removal is reflected in the staying set once the block's
    /// registry version includes it.
    #[test]
    fn test_read_membership_at_pinned_version() {
        let setup = test_setup(vec![(1, subnet_record((0..4).map(node_test_id).collect()))]);

        let v1 = setup.builder.read_membership(Height::new(10), RegistryVersion::new(1));
        assert_eq!(v1.current_members.len(), 4);
        assert_eq!(v1.members_for_foreseeable_future.len(), 4);

        apply_membership_delta(&setup, 2, (0..3).map(node_test_id).collect());
        let v2 = setup.builder.read_membership(Height::new(10), RegistryVersion::new(2));
        assert_eq!(v2.current_members.len(), 4);
        assert_eq!(v2.members_for_foreseeable_future.len(), 3);
        assert!(!v2.members_for_foreseeable_future.contains(&node_test_id(3)));
    }

    /// Requests older than REQUEST_TIMEOUT_BLOCKS are folded out before the
    /// slot-capacity check, matching read_upgrade_state and execution.
    #[test]
    fn test_stale_request_expires_via_fold() {
        let setup = test_setup(vec![(1, subnet_record((0..4).map(node_test_id).collect()))]);

        let past_bytes = upgrade_payload_to_bytes(
            vec![UpgradePermitAction::Request {
                node: node_test_id(0),
                request_height: Height::new(5),
            }],
            MAX_SIZE,
        );
        let past_payloads = vec![PastPayload {
            height: Height::new(5),
            time: UNIX_EPOCH,
            block_hash: CryptoHashOf::from(CryptoHash(vec![])),
            payload: &past_bytes,
        }];
        let request_at = |height: Height| {
            upgrade_payload_to_bytes(
                vec![UpgradePermitAction::Request {
                    node: node_test_id(0),
                    request_height: height,
                }],
                MAX_SIZE,
            )
        };

        // At height 30 the request from height 5 has expired (30 - 20 > 5):
        // the slot is free again.
        let payload = request_at(Height::new(30));
        assert!(validate(&setup.builder, Height::new(30), RegistryVersion::new(1), 0, &payload, &past_payloads).is_ok());
        // At height 24 (24 - 20 <= 5) it still holds the only slot.
        let payload = request_at(Height::new(24));
        assert!(validate(&setup.builder, Height::new(24), RegistryVersion::new(1), 0, &payload, &past_payloads).is_err());
    }
}
