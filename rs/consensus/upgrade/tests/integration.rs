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
use ic_consensus_utils::crypto::ConsensusCrypto;
use ic_consensus_utils::membership::Membership;
use ic_interfaces::batch_payload::{BatchPayloadBuilder, PastPayload, ProposalContext};
use ic_interfaces::p2p::consensus::{MutablePool, PoolMutationsProducer, UnvalidatedArtifact};
use ic_interfaces::upgrade_permit_auth::UpgradePermitAuthPool;
use ic_interfaces_state_manager::Labeled;
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::metadata_state::UpgradeState;
use ic_replicated_state::ReplicatedState;
use ic_test_artifact_pool::consensus_pool::TestConsensusPool;
use ic_test_utilities::artifact_pool_config::with_test_pool_config;
use ic_test_utilities::state_manager::RefMockStateManager;
use ic_test_utilities_consensus::fake::FakeContentSigner;
use ic_test_utilities_registry::SubnetRecordBuilder;
use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
use ic_types::batch::{
    bytes_to_upgrade_payload, upgrade_payload_to_bytes, BatchPayload, ValidationContext,
};
use ic_types::consensus::upgrade::UpgradePermitAction;
use ic_types::consensus::{BlockPayload, BlockProposal, DataPayload, Payload};
use ic_types::crypto::{CryptoHash, CryptoHashOf};
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
            pool,
            ..
        } = deps;
        let state = Arc::new(ReplicatedState::new(subnet_test_id(0), SubnetType::Application));
        // `get_state_at` is called by the DKG payload builder when the pool
        // fabricates blocks; `get_latest_certified_state` by the upgrade
        // payload builder.
        state_manager
            .get_mut()
            .expect_get_state_at()
            .times(1..)
            .return_const(Ok(Labeled::new(Height::new(0), state.clone())));
        state_manager
            .get_mut()
            .expect_get_latest_certified_state()
            .times(1..)
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

    fn validated_shares(&self, node: usize) -> usize {
        self.pools[node].read().unwrap().get_validated_shares().count()
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

    /// Validate the actions as the block of `proposer` from the perspective
    /// of every node; all must accept.
    fn validates_all(&self, proposer: usize, actions: &[UpgradePermitAction]) {
        let payload = upgrade_payload_to_bytes(actions.to_vec(), MAX_SIZE);
        let past: Vec<_> = self
            .blocks
            .iter()
            .map(|(height, payload)| past_payload(*height, payload))
            .collect();
        let context = context();
        for validator in 0..self.nodes.len() {
            self.builder(validator, self.rebooted.clone())
                .validate_payload(
                    self.next_height(),
                    &ProposalContext {
                        proposer: self.nodes[proposer],
                        validation_context: &context,
                    },
                    &payload,
                    &past,
                )
                .unwrap_or_else(|e| {
                    panic!(
                        "node {:?} must validate node {:?}'s block: {:?}",
                        self.nodes[validator],
                        self.nodes[proposer],
                        e
                    )
                });
        }
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
        for (i, manager) in self.managers.iter().enumerate() {
            let change_set = manager.on_state_change(&*self.pools[i].read().unwrap());
            self.pools[i].write().unwrap().apply(change_set);
        }
    }
}

/// Make the pool's next block, carry the given upgrade bytes in its batch
/// payload, and finalize it. Returns `(height, upgrade payload bytes)`.
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
    let upgrade = proposal.content.get_value().payload.as_ref().as_data().batch.upgrade.clone();
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
        fx.validates_all(2, &actions);
        fx.finalize(actions);
        assert!(fx.committed().authorized.contains(&fx.node(0)));

        // Node 0 reboots into the new GuestOS (versions match again) and,
        // once it is the block maker again, returns its permit.
        let actions = fx.build(0, fx.rebooted.clone());
        assert_return(&actions, fx.node(0));
        fx.validates_all(0, &actions);
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
