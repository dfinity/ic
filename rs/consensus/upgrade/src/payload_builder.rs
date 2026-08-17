//! Upgrade section builder for the Phase-2 rolling reboot.
//!
//! Produces the `upgrade` bytes in each data block's `BatchPayload`.
//! Three actions:
//! - `Request`: block maker requests reboot permission for itself
//! - `Authorize`: block maker includes collected auth shares (≥ N−P) to authorize a node
//! - `Return`: block maker releases its slot after rebooting
//!
//! Holds the block-facing protocol logic: state reconstruction (certified
//! anchor folded with the certification-gap payloads), action building, and
//! action validation. The kernel shared with the share signer (membership
//! views, share validation) lives in the crate root.

use crate::{subnet_membership, validate_share};
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

    /// The upgrade state at `height`: the committed anchor from the latest
    /// certified replicated state, folded with the certification-gap
    /// payloads and pruned of expired requests and departed members
    /// (`members`: nodes still in the committee).
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
        let limits = membership.limits();
        let needs_reboot =
            self.platform_version.guestos_version != self.platform_version.binary_version;
        let upgrade_state =
            self.upgrade_state_at(past_payloads, &membership.current_members, height);

        let mut actions = vec![];

        if upgrade_state.authorized.contains(&self.node_id) && !needs_reboot {
            actions.push(UpgradePermitAction::Return { node: self.node_id });
        }

        if needs_reboot
            && !upgrade_state.authorized.contains(&self.node_id)
            && upgrade_state.slots_in_use() < limits.max_parallel_reboots
        {
            actions.push(UpgradePermitAction::Request {
                node: self.node_id,
                request_height: height,
            });
        }

        // Authorize outstanding requests with enough collected shares, up to
        // P. The pool holds one share per (signer, content), so the group
        // size is the number of distinct signers; the validator re-checks
        // every share.
        let mut collected: BTreeMap<(NodeId, Height), Vec<UpgradePermitAuthorizationShare>> =
            BTreeMap::new();
        {
            let pool = self.pool.read().unwrap();
            for share in pool.get_validated_shares() {
                collected
                    .entry((share.content.node, share.content.request_height))
                    .or_default()
                    .push(share.clone());
            }
        }
        let mut budget = limits
            .max_parallel_reboots
            .saturating_sub(upgrade_state.authorized.len());
        for (&req_node, &req_height) in &upgrade_state.requested {
            if budget == 0 {
                break;
            }
            if upgrade_state.authorized.contains(&req_node) {
                continue;
            }
            if let Some(shares) = collected.get(&(req_node, req_height)) {
                if shares.len() >= limits.authorization_threshold {
                    actions.push(UpgradePermitAction::Authorize(UpgradePermitShares {
                        node: req_node,
                        shares: shares.clone(),
                    }));
                    budget -= 1;
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
        let limits = membership.limits();
        let upgrade_state =
            self.upgrade_state_at(past_payloads, &membership.current_members, height);
        let mut slots_used = upgrade_state.slots_in_use();

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
                    if slots_used >= limits.max_parallel_reboots {
                        return Err(invalid_upgrade(
                            InvalidUpgradePayloadReason::SlotsExhausted {
                                slots_in_use: slots_used,
                                capacity: limits.max_parallel_reboots,
                            },
                        ));
                    }
                    slots_used += 1;
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
            bytes_to_upgrade_payload(payload).map_err(|e| {
                invalid_upgrade(InvalidUpgradePayloadReason::DecodeFailed(e.to_string()))
            })?;
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
    use ic_types::RegistryVersion;
    use ic_types::batch::ValidationContext;
    use ic_types::consensus::UpgradePermitAuthorizationContent;
    use ic_types::consensus::UpgradePermitAuthorizationShare;
    use ic_types::consensus::upgrade::{UpgradePermitAction, UpgradePermitShares};
    use ic_types::crypto::{BasicSig, BasicSigOf, CryptoHash, CryptoHashOf};
    use ic_types::signature::BasicSignature;
    use ic_types::time::UNIX_EPOCH;

    const MAX_SIZE: NumBytes = NumBytes::new(1024 * 1024);

    fn subnet_record(nodes: Vec<NodeId>) -> SubnetRecord {
        SubnetRecordBuilder::from(&nodes).build()
    }

    struct TestSetup {
        builder: UpgradePayloadBuilder,
        membership: Arc<Membership>,
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
            let state = Arc::new(ReplicatedState::new(
                subnet_test_id(0),
                SubnetType::Application,
            ));
            deps.state_manager
                .get_mut()
                .expect_get_latest_certified_state()
                .times(1..)
                .return_const(Some(Labeled::new(Height::new(0), state)));
            TestSetup {
                builder: UpgradePayloadBuilder::new(
                    node_test_id(0),
                    deps.membership.clone(),
                    deps.state_manager,
                    deps.upgrade_permit_auth_pool as Arc<RwLock<dyn UpgradePermitAuthPool>>,
                    deps.crypto,
                    PlatformVersion::default(),
                    no_op_logger(),
                ),
                membership: deps.membership,
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
        let past_bytes = upgrade_payload_to_bytes(
            vec![UpgradePermitAction::Request {
                node: node_test_id(0),
                request_height,
            }],
            MAX_SIZE,
        );
        let past_payloads = vec![PastPayload {
            height: request_height,
            time: UNIX_EPOCH,
            block_hash: CryptoHashOf::from(CryptoHash(vec![])),
            payload: &past_bytes,
        }];
        let payload = upgrade_payload_to_bytes(
            vec![UpgradePermitAction::Authorize(UpgradePermitShares {
                node: node_test_id(0),
                shares: vec![
                    share(1, 0, request_height),
                    share(2, 0, request_height),
                    share(3, 0, request_height),
                ],
            })],
            MAX_SIZE,
        );

        // At the block's version V1 all three signers are staying members: accept.
        assert!(
            validate(
                &setup.builder,
                Height::new(11),
                RegistryVersion::new(1),
                0,
                &payload,
                &past_payloads
            )
            .is_ok()
        );
        // At V2 node 3 is not staying even though the committee still
        // contains it: reject.
        assert!(
            validate(
                &setup.builder,
                Height::new(11),
                RegistryVersion::new(2),
                0,
                &payload,
                &past_payloads
            )
            .is_err()
        );

        // A request from the block itself cannot be authorized in the same
        // block: shares only exist for requests in earlier blocks.
        let same_block = upgrade_payload_to_bytes(
            vec![
                UpgradePermitAction::Request {
                    node: node_test_id(0),
                    request_height: Height::new(11),
                },
                UpgradePermitAction::Authorize(UpgradePermitShares {
                    node: node_test_id(0),
                    shares: vec![
                        share(1, 0, Height::new(11)),
                        share(2, 0, Height::new(11)),
                        share(3, 0, Height::new(11)),
                    ],
                }),
            ],
            MAX_SIZE,
        );
        assert!(
            validate(
                &setup.builder,
                Height::new(11),
                RegistryVersion::new(1),
                0,
                &same_block,
                &[]
            )
            .is_err()
        );
    }

    /// The committee only changes at DKG interval boundaries (CUP/summary
    /// version); a removal is reflected in the staying set once the block's
    /// registry version includes it.
    #[test]
    fn test_read_membership_at_pinned_version() {
        let setup = test_setup(vec![(1, subnet_record((0..4).map(node_test_id).collect()))]);

        let v1 = subnet_membership(
            &setup.membership,
            Height::new(10),
            RegistryVersion::new(1),
            &no_op_logger(),
        );
        assert_eq!(v1.current_members.len(), 4);
        assert_eq!(v1.staying_members.len(), 4);

        apply_membership_delta(&setup, 2, (0..3).map(node_test_id).collect());
        let v2 = subnet_membership(
            &setup.membership,
            Height::new(10),
            RegistryVersion::new(2),
            &no_op_logger(),
        );
        assert_eq!(v2.current_members.len(), 4);
        assert_eq!(v2.staying_members.len(), 3);
        assert!(!v2.staying_members.contains(&node_test_id(3)));
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
        assert!(
            validate(
                &setup.builder,
                Height::new(30),
                RegistryVersion::new(1),
                0,
                &payload,
                &past_payloads
            )
            .is_ok()
        );
        // At height 24 (24 - 20 <= 5) it still holds the only slot.
        let payload = request_at(Height::new(24));
        assert!(
            validate(
                &setup.builder,
                Height::new(24),
                RegistryVersion::new(1),
                0,
                &payload,
                &past_payloads
            )
            .is_err()
        );
    }
}
