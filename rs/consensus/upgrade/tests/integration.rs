//! Integration tests for the upgrade permit protocol: the pool manager
//! (signer), the share pools with simulated gossip, the payload builder, and
//! the validator, driven through a test consensus pool via the [`TestFixture`].

use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};

use ic_artifact_pool::upgrade_permit_auth_pool::UpgradePermitAuthPoolImpl;
use ic_config::artifact_pool::ArtifactPoolConfig;
use ic_consensus_mocks::dependencies_with_subnet_records_with_raw_state_manager;
use ic_consensus_upgrade::payload_builder::UpgradePayloadBuilder;
use ic_consensus_upgrade::pool_manager::UpgradePermitAuthPoolManager;
use ic_consensus_upgrade::subnet_membership;
use ic_consensus_utils::crypto::ConsensusCrypto;
use ic_consensus_utils::membership::Membership;
use ic_interfaces::batch_payload::{BatchPayloadBuilder, PastPayload, ProposalContext};
use ic_interfaces::consensus::{InvalidPayloadReason, PayloadValidationError};
use ic_interfaces::p2p::consensus::{MutablePool, PoolMutationsProducer, UnvalidatedArtifact};
use ic_interfaces::upgrade::InvalidUpgradePayloadReason;
use ic_interfaces::upgrade_permit_auth::UpgradePermitAuthPool;
use ic_interfaces::validation::ValidationError;
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::Labeled;
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_replicated_state::metadata_state::UpgradeState;
use ic_test_artifact_pool::consensus_pool::TestConsensusPool;
use ic_test_utilities::artifact_pool_config::with_test_pool_config;
use ic_test_utilities::state_manager::RefMockStateManager;
use ic_test_utilities_consensus::fake::FakeContentSigner;
use ic_test_utilities_registry::{SubnetRecordBuilder, add_subnet_record};
use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
use ic_types::batch::{
    BatchPayload, ValidationContext, bytes_to_upgrade_payload, upgrade_payload_to_bytes,
};
use ic_types::consensus::upgrade::{UpgradePermitAction, UpgradePermitShares};
use ic_types::consensus::{
    BlockPayload, BlockProposal, DataPayload, Payload, UpgradePermitAuthorizationContent,
    UpgradePermitAuthorizationShare,
};
use ic_types::crypto::{BasicSig, BasicSigOf, CryptoHash, CryptoHashOf};
use ic_types::signature::BasicSignature;
use ic_types::time::UNIX_EPOCH;
use ic_types::{Height, NodeId, NumBytes, PlatformVersion, RegistryVersion, ReplicaVersion};

const MAX_SIZE: NumBytes = NumBytes::new(1024 * 1024);

/// A simulated subnet: per node a share pool and a signing pool manager,
/// plus one payload builder per `(node, needs_reboot)` and a test consensus
/// pool whose finalized blocks drive everything. The committed
/// [`UpgradeState`] is folded as the blocks finalize.
struct TestFixture {
    nodes: Vec<NodeId>,
    pool: TestConsensusPool,
    membership: Arc<Membership>,
    state_manager: Arc<RefMockStateManager>,
    crypto: Arc<dyn ConsensusCrypto>,
    registry_data_provider: Arc<ProtoRegistryDataProvider>,
    registry: Arc<FakeRegistryClient>,
    needs_reboot: PlatformVersion,
    rebooted: PlatformVersion,
    pools: Vec<Arc<RwLock<UpgradePermitAuthPoolImpl>>>,
    managers: Vec<UpgradePermitAuthPoolManager>,
    committed: UpgradeState,
    /// Finalized blocks: `(height, upgrade payload bytes)`.
    blocks: Vec<(Height, Vec<u8>)>,
}

impl TestFixture {
    fn new(num_nodes: u64, pool_config: ArtifactPoolConfig) -> Self {
        let nodes: Vec<NodeId> = (0..num_nodes).map(node_test_id).collect();
        let deps = dependencies_with_subnet_records_with_raw_state_manager(
            pool_config,
            subnet_test_id(0),
            vec![(1, SubnetRecordBuilder::from(&nodes).build())],
        );
        let ic_consensus_mocks::Dependencies {
            crypto,
            membership,
            state_manager,
            registry_data_provider,
            registry,
            pool,
            ..
        } = deps;
        let state = Arc::new(ReplicatedState::new(
            subnet_test_id(0),
            SubnetType::Application,
        ));
        // `get_state_at` is called by the DKG payload builder when the pool
        // fabricates blocks; `get_latest_certified_state` by the upgrade
        // payload builder. Tests that only resolve membership or validate
        // synthetic payloads may call neither.
        state_manager
            .get_mut()
            .expect_get_state_at()
            .times(0..)
            .return_const(Ok(Labeled::new(Height::new(0), state.clone())));
        state_manager
            .get_mut()
            .expect_get_latest_certified_state()
            .times(0..)
            .return_const(Some(Labeled::new(Height::new(0), state)));

        let block_cache = pool.get_block_cache();
        let pools: Vec<_> = (0..num_nodes)
            .map(|_| {
                Arc::new(RwLock::new(UpgradePermitAuthPoolImpl::new(
                    MetricsRegistry::new(),
                    no_op_logger(),
                )))
            })
            .collect();
        let managers: Vec<_> = nodes
            .iter()
            .map(|node| {
                UpgradePermitAuthPoolManager::new(
                    *node,
                    crypto.clone(),
                    block_cache.clone(),
                    membership.clone(),
                    no_op_logger(),
                )
            })
            .collect();
        let old = ReplicaVersion::try_from("0.1").unwrap();
        let new = ReplicaVersion::try_from("0.2").unwrap();
        Self {
            needs_reboot: PlatformVersion {
                guestos_version: old,
                binary_version: new.clone(),
            },
            rebooted: PlatformVersion {
                guestos_version: new.clone(),
                binary_version: new,
            },
            nodes,
            pool,
            membership,
            state_manager,
            crypto,
            registry_data_provider,
            registry,
            pools,
            managers,
            committed: UpgradeState::default(),
            blocks: vec![],
        }
    }

    fn node(&self, i: usize) -> NodeId {
        self.nodes[i]
    }

    fn committed(&self) -> &UpgradeState {
        &self.committed
    }

    /// Assert the committed state respects the subnet's reboot capacity:
    /// staying members holding a request or permit never exceed it.
    fn assert_capacity(&self) {
        let membership = subnet_membership(
            &self.membership,
            self.next_height(),
            self.registry.get_latest_version(),
            &no_op_logger(),
        );
        let limits = membership.limits();
        let holders = self
            .committed
            .active_slots_in_use(&membership.staying_members);
        assert!(
            holders <= limits.max_parallel_reboots,
            "capacity violated: {} staying permit holders, capacity is {}",
            holders,
            limits.max_parallel_reboots
        );
    }

    fn validated_shares(&self, node: usize) -> usize {
        self.pools[node]
            .read()
            .unwrap()
            .get_validated_shares()
            .count()
    }

    fn unvalidated_shares(&self, node: usize) -> usize {
        self.pools[node]
            .read()
            .unwrap()
            .get_unvalidated_shares()
            .count()
    }

    fn next_height(&self) -> Height {
        self.pool
            .get_block_cache()
            .finalized_chain()
            .tip()
            .height
            .increment()
    }

    fn builder(&self, node: usize, platform_version: PlatformVersion) -> UpgradePayloadBuilder {
        UpgradePayloadBuilder::new(
            self.nodes[node],
            self.membership.clone(),
            self.state_manager.clone(),
            self.pools[node].clone() as Arc<RwLock<dyn UpgradePermitAuthPool>>,
            self.crypto.clone(),
            platform_version,
            no_op_logger(),
        )
    }

    /// The node's actions for its next block, given the finalized blocks so
    /// far.
    fn build(&self, node: usize, platform_version: PlatformVersion) -> Vec<UpgradePermitAction> {
        let past: Vec<_> = self
            .blocks
            .iter()
            .map(|(height, payload)| past_payload(*height, payload))
            .collect();
        let payload = self.builder(node, platform_version).build_payload(
            self.next_height(),
            MAX_SIZE,
            &past,
            &context(),
        );
        bytes_to_upgrade_payload(&payload).expect("built upgrade payload must decode")
    }

    /// Finalize a block carrying the given actions and fold them into the
    /// committed state.
    fn finalize(&mut self, actions: Vec<UpgradePermitAction>) {
        let payload = upgrade_payload_to_bytes(actions, MAX_SIZE);
        let (height, block) = finalize_upgrade_block(&mut self.pool, payload);
        let members: BTreeSet<NodeId> = self.nodes.iter().cloned().collect();
        self.committed.apply(
            &bytes_to_upgrade_payload(&block).expect("finalized upgrade payload must decode"),
            height,
            &members,
        );
        self.blocks.push((height, block));
    }

    /// Validate the actions as the block of `proposer` at the given
    /// registry version, from the perspective of every node.
    fn validation_results(
        &self,
        proposer: usize,
        actions: &[UpgradePermitAction],
        registry_version: RegistryVersion,
    ) -> Vec<(NodeId, Result<(), PayloadValidationError>)> {
        let payload = upgrade_payload_to_bytes(actions.to_vec(), MAX_SIZE);
        let past: Vec<_> = self
            .blocks
            .iter()
            .map(|(height, payload)| past_payload(*height, payload))
            .collect();
        let context = ValidationContext {
            certified_height: Height::new(0),
            registry_version,
            time: UNIX_EPOCH,
        };
        (0..self.nodes.len())
            .map(|validator| {
                let result = self
                    .builder(validator, self.rebooted.clone())
                    .validate_payload(
                        self.next_height(),
                        &ProposalContext {
                            proposer: self.nodes[proposer],
                            validation_context: &context,
                        },
                        &payload,
                        &past,
                    );
                (self.nodes[validator], result)
            })
            .collect()
    }

    /// Validate the actions as the block of `proposer` at the given
    /// registry version. All validators must return the same verdict, which
    /// is returned.
    fn validates_all(
        &self,
        proposer: usize,
        actions: &[UpgradePermitAction],
        registry_version: RegistryVersion,
    ) -> Result<(), PayloadValidationError> {
        let mut results = self.validation_results(proposer, actions, registry_version);
        let (_, first) = results.pop().unwrap();
        for (node, result) in &results {
            match (result, &first) {
                (Ok(_), Ok(_)) => {}
                (
                    Err(PayloadValidationError::InvalidArtifact(
                        InvalidPayloadReason::InvalidUpgradePayload(reason1),
                    )),
                    Err(PayloadValidationError::InvalidArtifact(
                        InvalidPayloadReason::InvalidUpgradePayload(reason2),
                    )),
                ) => {
                    assert_eq!(
                        reason1, reason2,
                        "node {:?} disagrees with the other validators",
                        node
                    );
                }
                (a, b) => panic!("Unexpected validation outcome: {a:?} {b:?}"),
            }
        }
        first
    }

    /// Apply a registry delta after pool creation, so the committee (frozen
    /// in the genesis CUP) stays behind the registry.
    fn apply_membership_delta(&self, version: u64, nodes: Vec<NodeId>) {
        add_subnet_record(
            &self.registry_data_provider,
            version,
            subnet_test_id(0),
            SubnetRecordBuilder::from(&nodes).build(),
        );
        self.registry.update_to_latest_version();
    }

    /// Deliver all validated shares to the other nodes' pools, and let the
    /// receiving managers verify them. (Signing happens in
    /// [`TestFixture::run_managers`]; between the two, share collection
    /// spans a block time as it does on a real subnet.)
    fn gossip_shares(&self) {
        for i in 0..self.nodes.len() {
            let shares: Vec<_> = self.pools[i]
                .read()
                .unwrap()
                .get_validated_shares()
                .cloned()
                .collect();
            for (j, pool) in self.pools.iter().enumerate() {
                if i != j {
                    for share in &shares {
                        pool.write().unwrap().insert(UnvalidatedArtifact {
                            message: share.clone(),
                            peer_id: self.nodes[i],
                            timestamp: UNIX_EPOCH,
                        });
                    }
                }
            }
        }
        self.run_managers();
    }

    /// Let every manager process the finalized blocks: sign shares for new
    /// requests and validate gossiped ones.
    fn run_managers(&self) {
        for node in 0..self.nodes.len() {
            self.run_manager(node);
        }
    }

    /// Let a single node's manager process the finalized blocks and its
    /// pool's unvalidated shares.
    fn run_manager(&self, node: usize) {
        let change_set = self.managers[node].on_state_change(&*self.pools[node].read().unwrap());
        self.pools[node].write().unwrap().apply(change_set);
    }
}

/// Finalize the pool's next block carrying the given upgrade bytes;
/// returns `(height, upgrade payload bytes)`.
fn finalize_upgrade_block(pool: &mut TestConsensusPool, upgrade: Vec<u8>) -> (Height, Vec<u8>) {
    let proposal = pool.make_next_block();
    let signer = proposal.signature.signer;
    let mut block = proposal.content.get_value().clone();
    let data = block.payload.as_ref().as_data().clone();
    block.payload = Payload::new(
        ic_types::crypto::crypto_hash,
        BlockPayload::Data(DataPayload {
            batch: BatchPayload {
                upgrade,
                ..data.batch
            },
            dkg: data.dkg,
            idkg: data.idkg,
        }),
    );
    let height = block.height;
    let proposal = BlockProposal::fake(block, signer);
    pool.advance_round_with_block(&proposal);
    let upgrade = proposal
        .content
        .get_value()
        .payload
        .as_ref()
        .as_data()
        .batch
        .upgrade
        .clone();
    (height, upgrade)
}

fn past_payload<'a>(height: Height, payload: &'a [u8]) -> PastPayload<'a> {
    PastPayload {
        height,
        time: UNIX_EPOCH,
        block_hash: CryptoHashOf::from(CryptoHash(vec![])),
        payload,
    }
}

fn context() -> ValidationContext {
    ValidationContext {
        certified_height: Height::new(0),
        registry_version: RegistryVersion::new(1),
        time: UNIX_EPOCH,
    }
}

fn assert_request(actions: &[UpgradePermitAction], node: NodeId) {
    assert!(
        matches!(
            actions,
            [UpgradePermitAction::Request { node: n, .. }] if *n == node
        ),
        "expected a Request from {:?}, got {:?}",
        node,
        actions
    );
}

fn assert_authorize(actions: &[UpgradePermitAction], node: NodeId, min_shares: usize) {
    match actions {
        [UpgradePermitAction::Authorize(shares)] if shares.node == node => {
            assert!(shares.shares.len() >= min_shares);
        }
        other => panic!("expected an Authorize for {:?}, got {:?}", node, other),
    }
}

fn assert_return(actions: &[UpgradePermitAction], node: NodeId) {
    assert!(
        matches!(
            actions,
            [UpgradePermitAction::Return { node: n }] if *n == node
        ),
        "expected a Return from {:?}, got {:?}",
        node,
        actions
    );
}

/// A share `signer` has signed for `node`'s request at `request_height`.
/// Signatures are not verified by the test crypto.
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

/// Assert that the common validation verdict is a rejection carrying the
/// given [`InvalidUpgradePayloadReason`] pattern.
macro_rules! assert_invalid_upgrade {
    ($result:expr, $variant:pat) => {
        assert!(
            matches!(
                $result,
                Err(ValidationError::InvalidArtifact(
                    InvalidPayloadReason::InvalidUpgradePayload($variant)
                ))
            ),
            "unexpected verdict: {:?}",
            $result
        );
    };
}

/// End-to-end permit lifecycle with realistic block-maker rotation: the
/// requester never authorizes itself — the next block maker is still
/// collecting shares, and the one after carries the authorization.
#[test]
fn test_permit_lifecycle() {
    with_test_pool_config(|pool_config| {
        let mut fx = TestFixture::new(4, pool_config);

        // Block 1 (maker: node 0): node 0's binary is ahead of its GuestOS,
        // so it requests a reboot permit.
        let actions = fx.build(0, fx.needs_reboot.clone());
        assert_request(&actions, fx.node(0));
        fx.finalize(actions);

        // The managers observe the finalized request and sign; the shares
        // are still spreading while the next blocks are made.
        fx.run_managers();
        // Block 2 (maker: node 1): too early to authorize (shares in
        // flight), and with the only slot taken node 1 cannot request
        // either.
        let actions = fx.build(1, fx.needs_reboot.clone());
        assert!(actions.is_empty());
        fx.finalize(actions);

        // The shares reach the other nodes; the next block maker now holds
        // all four (threshold is N−P = 3).
        fx.gossip_shares();
        assert_eq!(fx.validated_shares(2), 4);
        // Block 3 (maker: node 2): authorizes node 0's request; node 1
        // (cross-node) validates the block.
        let actions = fx.build(2, fx.rebooted.clone());
        assert_authorize(&actions, fx.node(0), 3);
        fx.validates_all(2, &actions, RegistryVersion::new(1))
            .expect("all nodes must validate the authorize block");
        fx.finalize(actions);
        assert!(fx.committed().authorized.contains(&fx.node(0)));

        // Node 0 reboots into the new GuestOS (versions match again) and,
        // once it is the block maker again, returns its permit.
        let actions = fx.build(0, fx.rebooted.clone());
        assert_return(&actions, fx.node(0));
        fx.validates_all(0, &actions, RegistryVersion::new(1))
            .expect("all nodes must validate the return block");
        fx.finalize(actions);
        assert!(fx.committed().authorized.is_empty());

        // With the slot freed, node 1's request goes through.
        let actions = fx.build(1, fx.needs_reboot.clone());
        assert_request(&actions, fx.node(1));
    });
}

/// A request that never collects enough shares expires after
/// `REQUEST_TIMEOUT_BLOCKS` and the slot is freed.
#[test]
fn test_request_expires() {
    with_test_pool_config(|pool_config| {
        let mut fx = TestFixture::new(4, pool_config);

        let actions = fx.build(0, fx.needs_reboot.clone());
        assert_request(&actions, fx.node(0));
        fx.finalize(actions);
        assert!(fx.committed().requested.contains_key(&fx.node(0)));

        // While the request still holds the only slot, every validator
        // rejects a second request.
        let second = vec![UpgradePermitAction::Request {
            node: fx.node(0),
            request_height: fx.next_height(),
        }];
        assert_invalid_upgrade!(
            fx.validates_all(0, &second, RegistryVersion::new(1)),
            InvalidUpgradePayloadReason::SlotsExhausted { .. }
        );

        // No shares are gathered; empty blocks pass the timeout.
        for _ in 0..21 {
            fx.finalize(vec![]);
        }
        assert!(fx.committed().requested.is_empty());

        // The slot is free again, so node 0 can re-request.
        let actions = fx.build(0, fx.needs_reboot.clone());
        assert_request(&actions, fx.node(0));
    });
}

/// The block's registry version pins the membership: validators with a
/// newer registry (a node removal landed) still accept a block whose context
/// pins the older version, and reject it at the newer one.
#[test]
fn test_block_registry_version_pins_membership() {
    with_test_pool_config(|pool_config| {
        let mut fx = TestFixture::new(4, pool_config);
        // Committee frozen at V1 with 4 nodes; the removal lands at V2.
        fx.apply_membership_delta(2, (0..3).map(node_test_id).collect());

        // A request from the block itself cannot be authorized in the same
        // block: shares only exist for requests in earlier blocks. (Checked
        // first, while no slot is in use — otherwise the request would fail
        // the slot check instead.)
        let h1 = fx.next_height();
        let same_block = vec![
            UpgradePermitAction::Request {
                node: fx.node(0),
                request_height: h1,
            },
            UpgradePermitAction::Authorize(UpgradePermitShares {
                node: fx.node(0),
                shares: vec![share(1, 0, h1), share(2, 0, h1), share(3, 0, h1)],
            }),
        ];
        assert_invalid_upgrade!(
            fx.validates_all(0, &same_block, RegistryVersion::new(1)),
            InvalidUpgradePayloadReason::AuthorizeNoOutstandingRequest { .. }
        );

        // A request from node 0 finalized at V1.
        let h2 = fx.next_height();
        let request = vec![UpgradePermitAction::Request {
            node: fx.node(0),
            request_height: h2,
        }];
        fx.validates_all(0, &request, RegistryVersion::new(1))
            .expect("all nodes must validate the request at V1");
        fx.finalize(request);

        let authorize = vec![UpgradePermitAction::Authorize(UpgradePermitShares {
            node: fx.node(0),
            shares: vec![share(1, 0, h2), share(2, 0, h2), share(3, 0, h2)],
        })];
        // At the block's version V1 all three signers are staying: accept.
        fx.validates_all(0, &authorize, RegistryVersion::new(1))
            .expect("all nodes must validate the authorize at V1");
        // At V2 node 3 is not staying even though the committee still
        // contains it: everyone rejects.
        assert_invalid_upgrade!(
            fx.validates_all(0, &authorize, RegistryVersion::new(2)),
            InvalidUpgradePayloadReason::AuthorizeInvalidShare { .. }
        );
    });
}

/// The committee only changes at DKG interval boundaries (CUP/summary
/// version); a removal is reflected in the staying set once the block's
/// registry version includes it.
#[test]
fn test_membership_at_pinned_version() {
    with_test_pool_config(|pool_config| {
        let fx = TestFixture::new(4, pool_config);

        let v1 = subnet_membership(
            &fx.membership,
            Height::new(10),
            RegistryVersion::new(1),
            &no_op_logger(),
        );
        assert_eq!(v1.current_members.len(), 4);
        assert_eq!(v1.staying_members.len(), 4);

        fx.apply_membership_delta(2, (0..3).map(node_test_id).collect());
        let v2 = subnet_membership(
            &fx.membership,
            Height::new(10),
            RegistryVersion::new(2),
            &no_op_logger(),
        );
        assert_eq!(v2.current_members.len(), 4);
        assert_eq!(v2.staying_members.len(), 3);
        assert!(!v2.staying_members.contains(&fx.node(3)));
    });
}

#[test]
fn test_validator_rejections() {
    with_test_pool_config(|pool_config| {
        let mut fx = TestFixture::new(4, pool_config);

        // A request for another node must come from that node.
        let actions = vec![UpgradePermitAction::Request {
            node: fx.node(1),
            request_height: fx.next_height(),
        }];
        assert_invalid_upgrade!(
            fx.validates_all(0, &actions, RegistryVersion::new(1)),
            InvalidUpgradePayloadReason::RequestNodeMismatch { .. }
        );

        // Likewise for returns.
        let actions = vec![UpgradePermitAction::Return { node: fx.node(1) }];
        assert_invalid_upgrade!(
            fx.validates_all(0, &actions, RegistryVersion::new(1)),
            InvalidUpgradePayloadReason::ReturnNodeMismatch { .. }
        );

        // An authorization needs an outstanding request.
        let actions = vec![UpgradePermitAction::Authorize(UpgradePermitShares {
            node: fx.node(1),
            shares: vec![
                share(0, 1, Height::new(1)),
                share(2, 1, Height::new(1)),
                share(3, 1, Height::new(1)),
            ],
        })];
        assert_invalid_upgrade!(
            fx.validates_all(0, &actions, RegistryVersion::new(1)),
            InvalidUpgradePayloadReason::AuthorizeNoOutstandingRequest { .. }
        );

        // ... and enough distinct signers (threshold is N−P = 3).
        let h1 = fx.next_height();
        let request = vec![UpgradePermitAction::Request {
            node: fx.node(0),
            request_height: h1,
        }];
        fx.validates_all(0, &request, RegistryVersion::new(1))
            .expect("all nodes must validate the request");
        fx.finalize(request);
        let actions = vec![UpgradePermitAction::Authorize(UpgradePermitShares {
            node: fx.node(0),
            shares: vec![share(1, 0, h1), share(2, 0, h1)],
        })];
        assert_invalid_upgrade!(
            fx.validates_all(0, &actions, RegistryVersion::new(1)),
            InvalidUpgradePayloadReason::AuthorizeInsufficientShares { .. }
        );
    });
}

/// A Return from a node that holds no permit is a benign no-op: removing a
/// non-existent entry changes no state, and rejecting it would couple Return
/// validity to folded-state details without buying any safety.
#[test]
fn test_return_without_permit_is_noop() {
    with_test_pool_config(|pool_config| {
        let mut fx = TestFixture::new(4, pool_config);

        let actions = vec![UpgradePermitAction::Return { node: fx.node(0) }];
        fx.validates_all(0, &actions, RegistryVersion::new(1))
            .expect("return without a permit must be accepted");
        fx.finalize(actions);
        assert!(fx.committed().authorized.is_empty());
        assert!(fx.committed().requested.is_empty());
    });
}

/// A gossiped share whose request height has no finalized block is dropped
/// as invalid.
#[test]
fn test_gossiped_share_without_request_block_is_dropped() {
    with_test_pool_config(|pool_config| {
        let fx = TestFixture::new(4, pool_config);

        // A share arrives at node 1 referencing a height with no finalized
        // block.
        fx.pools[1].write().unwrap().insert(UnvalidatedArtifact {
            message: share(2, 0, Height::new(10_000)),
            peer_id: fx.node(2),
            timestamp: UNIX_EPOCH,
        });
        assert_eq!(fx.unvalidated_shares(1), 1);

        fx.run_manager(1);
        assert_eq!(fx.unvalidated_shares(1), 0);
        assert_eq!(fx.validated_shares(1), 0);
    });
}

/// A gossiped share from a node that is not a staying member fails
/// validation and is dropped.
#[test]
fn test_gossiped_share_from_non_staying_signer_is_dropped() {
    with_test_pool_config(|pool_config| {
        let mut fx = TestFixture::new(4, pool_config);

        // A request from node 0 finalizes, so a block exists at its height.
        let h1 = fx.next_height();
        let request = vec![UpgradePermitAction::Request {
            node: fx.node(0),
            request_height: h1,
        }];
        fx.finalize(request);

        // Node 9 is not a member of the subnet: its share for node 0's
        // request fails validation even though the request block exists.
        fx.pools[1].write().unwrap().insert(UnvalidatedArtifact {
            message: share(9, 0, h1),
            peer_id: node_test_id(9),
            timestamp: UNIX_EPOCH,
        });
        assert_eq!(fx.unvalidated_shares(1), 1);

        fx.run_manager(1);
        assert_eq!(fx.unvalidated_shares(1), 0);
        // The bogus share is gone; only node 1's own signature for the
        // request remains (the manager signs while validating gossip).
        let signers: Vec<_> = fx.pools[1]
            .read()
            .unwrap()
            .get_validated_shares()
            .map(|share| share.signature.signer)
            .collect();
        assert_eq!(signers, vec![fx.node(1)]);
    });
}

/// A leaving node (still in the committee, removed from the registry) counts
/// towards the reboot capacity whether or not it is rebooting — it could go
/// down at any minute — but it doesn't consume budget for its own permit and
/// can be authorized like anyone else. What it cannot do is vote: it counts
/// as inactive for permits, so a share it signed invalidates the whole
/// `Authorize` action.
#[test]
fn test_leaving_node_may_be_authorized_but_cannot_vote() {
    with_test_pool_config(|pool_config| {
        let mut fx = TestFixture::new(4, pool_config);
        // The committee still has 4 nodes; the registry removes node 3.
        fx.apply_membership_delta(2, (0..3).map(node_test_id).collect());

        // The leaving node may propose itself for an upgrade: its builder
        // emits the request and every validator accepts it — even at the
        // version where node 3 is no longer staying.
        let actions = fx.build(3, fx.needs_reboot.clone());
        assert_request(&actions, fx.node(3));
        fx.validates_all(3, &actions, RegistryVersion::new(2))
            .expect("a leaving node may request a permit");
        fx.finalize(actions);

        // The staying members sign for it; the leaving node itself signs
        // nothing (its vote doesn't count).
        fx.run_managers();
        for node in 0..3 {
            assert_eq!(fx.validated_shares(node), 1, "node {}", node);
        }
        assert_eq!(fx.validated_shares(3), 0, "the leaving node signs nothing");

        // With the shares collected, the leaving node is authorized — from
        // staying signers only.
        fx.gossip_shares();
        let actions = fx.build(1, fx.rebooted.clone());
        assert_authorize(&actions, fx.node(3), 3);
        fx.validates_all(1, &actions, RegistryVersion::new(2))
            .expect("the leaving node may be authorized");
        fx.finalize(actions);
        assert!(fx.committed().authorized.contains(&fx.node(3)));

        // The leaving node's authorization doesn't consume budget: a
        // staying node can take the floor slot in parallel.
        let actions = fx.build(0, fx.needs_reboot.clone());
        assert_request(&actions, fx.node(0));
        fx.validates_all(0, &actions, RegistryVersion::new(2))
            .expect("the floor slot is still free");
        let h0 = fx.next_height();
        fx.finalize(actions);
        fx.run_managers();
        fx.gossip_shares();

        // A share signed by the leaving node doesn't count: including one
        // invalidates the whole Authorize action, even with enough other
        // signers.
        let authorize = vec![UpgradePermitAction::Authorize(UpgradePermitShares {
            node: fx.node(0),
            shares: vec![share(0, 0, h0), share(1, 0, h0), share(3, 0, h0)],
        })];
        assert_invalid_upgrade!(
            fx.validates_all(1, &authorize, RegistryVersion::new(2)),
            InvalidUpgradePayloadReason::AuthorizeInvalidShare { .. }
        );

        // Without the leaving node's share, node 0 is authorized.
        let actions = fx.build(1, fx.rebooted.clone());
        assert_authorize(&actions, fx.node(0), 3);
        fx.validates_all(1, &actions, RegistryVersion::new(2))
            .expect("the staying node may be authorized");
        fx.finalize(actions);
        assert!(fx.committed().authorized.contains(&fx.node(0)));
        assert!(fx.committed().authorized.contains(&fx.node(3)));
        // The leaving request is gone; both nodes hold permits at once
        // under a raw budget of one.
        assert!(fx.committed().requested.is_empty());
    });
}

/// With a raw budget of two (N=10), two nodes can normally upgrade in
/// parallel. One already-upgraded node being decommissioned reserves one
/// unit of the budget — even though it holds no permit and is not
/// rebooting — so only one of the two upgrades can proceed.
#[test]
fn test_leaving_node_reservation_limits_parallel_upgrades() {
    // Baseline: without a leaving node, two upgrades fit.
    with_test_pool_config(|pool_config| {
        let mut fx = TestFixture::new(10, pool_config);

        for node in 0..2 {
            let actions = fx.build(node, fx.needs_reboot.clone());
            assert_request(&actions, fx.node(node));
            fx.validates_all(node, &actions, RegistryVersion::new(1))
                .expect("the raw budget is two");
            fx.finalize(actions);
        }
        fx.assert_capacity();
    });

    // Node 9 has finished upgrading (its versions match) and is being
    // removed from the subnet: its reservation reduces the capacity to one.
    with_test_pool_config(|pool_config| {
        let mut fx = TestFixture::new(10, pool_config);
        fx.apply_membership_delta(2, (0..9).map(node_test_id).collect());

        // The first upgrade takes the only remaining slot.
        let actions = fx.build(0, fx.needs_reboot.clone());
        assert_request(&actions, fx.node(0));
        fx.validates_all(0, &actions, RegistryVersion::new(2))
            .expect("one slot remains after the reservation");
        fx.finalize(actions);

        // Node 1's request doesn't fit — the leaving node's reservation
        // consumes the other slot even though it is not rebooting — so its
        // block contributes nothing; the capacity is asserted on the
        // committed state below.
        let actions = fx.build(1, fx.needs_reboot.clone());
        fx.finalize(actions);

        // The one upgrade completes (threshold is N−P = 8 shares; the
        // leaving node's manager signs nothing).
        fx.run_managers();
        fx.gossip_shares();
        let actions = fx.build(2, fx.rebooted.clone());
        assert_authorize(&actions, fx.node(0), 8);
        fx.validates_all(2, &actions, RegistryVersion::new(2))
            .expect("the single upgrade completes");
        fx.finalize(actions);
        assert!(fx.committed().authorized.contains(&fx.node(0)));

        // The leaving node doesn't consume budget: even though node 0
        // (staying) holds the only slot, node 9 may still request and be
        // authorized.
        let actions = fx.build(9, fx.needs_reboot.clone());
        assert_request(&actions, fx.node(9));
        fx.validates_all(9, &actions, RegistryVersion::new(2))
            .expect("the leaving node doesn't consume budget");
        fx.finalize(actions);
        fx.run_managers();
        fx.gossip_shares();
        let actions = fx.build(2, fx.rebooted.clone());
        assert_authorize(&actions, fx.node(9), 8);
        fx.validates_all(2, &actions, RegistryVersion::new(2))
            .expect("the leaving node may be authorized");
        fx.finalize(actions);

        // End state: exactly one staying member (node 0) holds a permit —
        // node 1's request never made it in — plus the leaving node, which
        // doesn't count towards the capacity.
        fx.assert_capacity();
        assert!(fx.committed().authorized.contains(&fx.node(0)));
        assert!(fx.committed().authorized.contains(&fx.node(9)));
        assert!(!fx.committed().authorized.contains(&fx.node(1)));
        assert!(fx.committed().requested.is_empty());
    });
}
