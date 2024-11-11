use ic_artifact_pool::consensus_pool::ConsensusPoolImpl;
use ic_artifact_pool::dkg_pool::DkgPoolImpl;
use ic_config::artifact_pool::ArtifactPoolConfig;
use ic_consensus_utils::{membership::Membership, pool_reader::PoolReader};
use ic_interfaces::{
    consensus_pool::{
        ChangeAction, ConsensusBlockCache, ConsensusBlockChain, ConsensusPool, ConsensusPoolCache,
        Mutations, PoolSection, UnvalidatedConsensusArtifact, ValidatedConsensusArtifact,
    },
    crypto::{MultiSigner, ThresholdSigner},
    dkg::DkgPool,
    p2p::consensus::{ArtifactTransmits, MutablePool},
    time_source::TimeSource,
};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateManager;
use ic_logger::replica_logger::no_op_logger;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_replicated_state::ReplicatedState;
use ic_test_utilities::crypto::CryptoReturningOk;
use ic_test_utilities_consensus::fake::*;
use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
use ic_types::signature::*;
use ic_types::{artifact::ConsensusMessageId, batch::ValidationContext};
use ic_types::{consensus::*, crypto::*, *};
use ic_types::{
    crypto::threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetSubnet},
    time::UNIX_EPOCH,
};
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Instant;

#[allow(clippy::type_complexity)]
pub struct TestConsensusPool {
    subnet_id: SubnetId,
    registry_client: Arc<dyn RegistryClient>,
    pool: ConsensusPoolImpl,
    time_source: Arc<dyn TimeSource>,
    dkg_payload_builder:
        Box<dyn Fn(&dyn ConsensusPool, Block, &ValidationContext) -> consensus::dkg::Payload>,
    membership: Membership,
}

pub struct Round<'a> {
    max_replicas: u32,
    new_blocks: u32,
    blocks_to_notarize: u32,
    add_catch_up_package_if_needed: bool,
    should_finalize: bool,
    should_add_random_tape: bool,
    n_shares: u32,
    rb_shares: u32,
    f_shares: u32,
    certified_height: Option<Height>,
    pool: &'a mut TestConsensusPool,
}

impl<'a> Round<'a> {
    pub fn new(pool: &'a mut TestConsensusPool) -> Self {
        Self {
            pool,
            max_replicas: 1,
            new_blocks: 1,
            blocks_to_notarize: 1,
            should_finalize: true,
            add_catch_up_package_if_needed: true,
            should_add_random_tape: true,
            n_shares: 0,
            rb_shares: 0,
            f_shares: 0,
            certified_height: None,
        }
    }

    pub fn dont_add_random_tape(mut self) -> Self {
        self.should_add_random_tape = false;
        self
    }

    pub fn dont_add_catch_up_package(mut self) -> Self {
        self.add_catch_up_package_if_needed = false;
        self
    }

    pub fn dont_finalize(mut self) -> Self {
        self.should_finalize = false;
        self
    }

    pub fn with_replicas(mut self, n: u32) -> Self {
        self.max_replicas = n;
        self
    }

    pub fn with_new_block_proposals(mut self, n: u32) -> Self {
        self.new_blocks = n;
        self
    }

    pub fn with_random_beacon_shares(mut self, n: u32) -> Self {
        self.rb_shares = n;
        self
    }

    pub fn with_finalization_shares(mut self, n: u32) -> Self {
        self.f_shares = n;
        self
    }

    pub fn with_notarization_shares(mut self, n: u32) -> Self {
        self.n_shares = n;
        self
    }

    pub fn with_certified_height(mut self, height: Height) -> Self {
        self.certified_height = Some(height);
        self
    }

    pub fn advance(&mut self) -> Height {
        self.pool.advance_round(
            self.max_replicas,
            self.new_blocks,
            self.blocks_to_notarize,
            self.add_catch_up_package_if_needed,
            self.should_finalize,
            self.should_add_random_tape,
            self.n_shares,
            self.rb_shares,
            self.f_shares,
            self.certified_height,
        )
    }
}

// Return a closure building DKG payloads. Used in tests only.
#[allow(clippy::type_complexity)]
fn dkg_payload_builder_fn(
    subnet_id: SubnetId,
    registry_client: Arc<dyn RegistryClient>,
    crypto: Arc<CryptoReturningOk>,
    state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
    dkg_pool: Arc<RwLock<dyn DkgPool>>,
) -> Box<dyn Fn(&dyn ConsensusPool, Block, &ValidationContext) -> consensus::dkg::Payload> {
    Box::new(move |cons_pool, parent, validation_context| {
        ic_consensus::dkg::create_payload(
            subnet_id,
            &*registry_client,
            &*crypto,
            &PoolReader::new(cons_pool),
            dkg_pool.clone(),
            &parent,
            &*state_manager,
            validation_context,
            no_op_logger(),
            10, // at most dealings per block
        )
        .unwrap_or_else(|err| panic!("Couldn't create the payload: {:?}", err))
    })
}

impl TestConsensusPool {
    /// Creates a new test pool. `registry_version_for_genesis` is used to
    /// create the genesis block with data from the provided registry.
    pub fn new(
        node_id: NodeId,
        subnet_id: SubnetId,
        pool_config: ArtifactPoolConfig,
        time_source: Arc<dyn TimeSource>,
        registry_client: Arc<dyn RegistryClient>,
        crypto: Arc<CryptoReturningOk>,
        state_manager: Arc<dyn StateManager<State = ReplicatedState>>,
        dkg_pool: Option<Arc<RwLock<DkgPoolImpl>>>,
    ) -> Self {
        let dkg_payload_builder = Box::new(dkg_payload_builder_fn(
            subnet_id,
            registry_client.clone(),
            crypto,
            state_manager.clone(),
            dkg_pool.unwrap_or_else(|| {
                Arc::new(std::sync::RwLock::new(
                    ic_artifact_pool::dkg_pool::DkgPoolImpl::new(
                        ic_metrics::MetricsRegistry::new(),
                        no_op_logger(),
                    ),
                ))
            }),
        ));
        let summary = ic_consensus::dkg::make_genesis_summary(&*registry_client, subnet_id, None);
        let pool = ConsensusPoolImpl::new(
            node_id,
            subnet_id,
            (&ic_test_utilities_consensus::make_genesis(summary)).into(),
            pool_config,
            ic_metrics::MetricsRegistry::new(),
            no_op_logger(),
            time_source.clone(),
        );
        let membership = Membership::new(pool.get_cache(), registry_client.clone(), subnet_id);
        TestConsensusPool {
            subnet_id,
            registry_client,
            pool,
            time_source,
            dkg_payload_builder,
            membership,
        }
    }

    /// Utility function to determine the identity of the block maker with the
    /// specified rank at a given height. Panics if this rank does not exist.
    pub fn get_block_maker_by_rank(&self, height: Height, rank: Rank) -> NodeId {
        let pool_reader = PoolReader::new(&self.pool);
        let prev_beacon = pool_reader.get_random_beacon(height.decrement()).unwrap();
        *self
            .membership
            .get_nodes(height)
            .unwrap()
            .iter()
            .find(|node| {
                self.membership
                    .get_block_maker_rank(height, &prev_beacon, **node)
                    == Ok(Some(rank))
            })
            .unwrap()
    }

    pub fn make_next_block(&self) -> BlockProposal {
        self.make_next_block_with_rank(Rank(0))
    }

    pub fn make_next_block_with_rank(&self, rank: Rank) -> BlockProposal {
        if let Some(parent) = self.latest_notarized_blocks().next() {
            self.make_next_block_from_parent(&parent, rank)
        } else {
            panic!("Pool contains a valid notarization on a block that is not in the pool");
        }
    }

    pub fn make_next_block_from_parent(&self, parent: &Block, rank: Rank) -> BlockProposal {
        let mut block = Block::from_parent(parent);
        block.rank = rank;
        let registry_version = self.registry_client.get_latest_version();

        // Increase time monotonically by at least initial_notary_delay
        let monotonic_block_increment = self
            .registry_client
            .get_notarization_delay_settings(self.subnet_id, registry_version)
            .unwrap()
            .expect("subnet record should be available")
            .initial_notary_delay
            + core::time::Duration::from_nanos(1);
        block.context.time += monotonic_block_increment;

        block.context.registry_version = registry_version;
        let dkg_payload = (self.dkg_payload_builder)(self, parent.clone(), &block.context);
        block.payload = Payload::new(ic_types::crypto::crypto_hash, dkg_payload.into());
        let signer = self.get_block_maker_by_rank(block.height(), rank);
        BlockProposal::fake(block, signer)
    }

    pub fn make_next_beacon(&self) -> RandomBeacon {
        let beacon = self.validated().random_beacon().get_highest().unwrap();
        RandomBeacon::from_parent(&beacon)
    }

    pub fn make_next_tape(&self) -> RandomTape {
        let finalized_height = self.validated().finalization().max_height().unwrap();
        RandomTape::fake(RandomTapeContent::new(finalized_height))
    }

    /// Creates an equivocation proof for the given height and rank. Make sure
    /// the rank is valid, otherwise this function panics.
    pub fn make_equivocation_proof(&self, rank: Rank, height: Height) -> EquivocationProof {
        let signer = self.get_block_maker_by_rank(height, rank);
        EquivocationProof {
            signer,
            version: self
                .pool
                .validated()
                .highest_catch_up_package()
                .content
                .version,
            height,
            subnet_id: self.subnet_id,
            hash1: CryptoHashOf::new(CryptoHash(vec![1, 2, 3])),
            signature1: BasicSigOf::new(BasicSig(vec![])),
            hash2: CryptoHashOf::new(CryptoHash(vec![4, 5, 6])),
            signature2: BasicSigOf::new(BasicSig(vec![])),
        }
    }

    pub fn make_catch_up_package(&self, height: Height) -> CatchUpPackage {
        let finalization = self
            .pool
            .validated()
            .finalization()
            .get_by_height(height)
            .next()
            .unwrap_or_else(|| panic!("Finalization does not exist at height {}", height));
        let catchup_height = self
            .pool
            .validated()
            .catch_up_package()
            .height_range()
            .unwrap()
            .max;
        assert!(height > catchup_height);
        let block: Block = self
            .pool
            .validated()
            .block_proposal()
            .get_by_height(height)
            .find(|proposal| proposal.content.get_hash() == &finalization.content.block)
            .map(|proposal| proposal.into())
            .unwrap_or_else(|| panic!("Finalized block not found at height {}", height));
        if !block.payload.as_ref().is_summary() {
            panic!("Attempt to make catch up package from block that is not a dkg summary");
        }
        let random_beacon = self
            .pool
            .validated()
            .random_beacon()
            .get_by_height(height)
            .next()
            .unwrap();
        CatchUpPackage {
            content: CatchUpContent::new(
                HashedBlock::new(ic_types::crypto::crypto_hash, block),
                HashedRandomBeacon::new(ic_types::crypto::crypto_hash, random_beacon.clone()),
                CryptoHashOf::from(CryptoHash(Vec::new())),
                None,
            ),
            signature: ThresholdSignature {
                signer: random_beacon.signature.signer,
                signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![])),
            },
        }
    }

    pub fn latest_notarized_blocks(&self) -> Box<dyn Iterator<Item = Block>> {
        if let Some(h) = self
            .validated()
            .notarization()
            .height_range()
            .map(|x| x.max)
        {
            let hashes: std::collections::BTreeSet<CryptoHashOf<Block>> = self
                .validated()
                .notarization()
                .get_by_height(h)
                .map(|n| n.content.block)
                .collect();
            Box::new(
                self.validated()
                    .block_proposal()
                    .get_by_height(h)
                    .filter(move |x| hashes.contains(x.content.get_hash()))
                    .map(|x| x.into()),
            )
        } else {
            Box::new(
                self.validated()
                    .catch_up_package()
                    .get_highest_iter()
                    .map(|c| c.content.block.into_inner()),
            )
        }
    }

    pub fn advance_round_with_block(&mut self, block: &BlockProposal) {
        self.insert_validated(block.clone());
        self.insert_validated(self.make_next_beacon());
        self.notarize(block);
        self.finalize(block);
        self.insert_validated(self.make_next_tape());
    }

    pub fn advance_round_normal_operation_n(&mut self, steps: u64) -> Height {
        assert!(steps > 0, "Cannot advance for 0 steps.");
        let mut height = Height::from(0);
        for _ in 0..steps {
            height = self.advance_round_normal_operation();
        }
        height
    }

    pub fn advance_round_normal_operation_no_cup_n(&mut self, steps: u64) -> Height {
        assert!(steps > 0, "Cannot advance for 0 steps.");
        let mut height = Height::from(0);
        for _ in 0..steps {
            height = self.advance_round_normal_operation_no_cup();
        }
        height
    }

    // Advances the pool mimicking an idealized situation: 1 notarized and finalized
    // block in every round, and creating a CUP for summary heights.
    pub fn advance_round_normal_operation(&mut self) -> Height {
        let max_replicas = 10;
        let new_blocks = 1;
        let blocks_to_notarize = 1;
        let should_finalize = true;
        let add_catch_up_package_if_needed = true;
        let should_add_random_tape = true;
        let n_shares = 0;
        let rb_shares = 0;
        let f_shares = 0;
        let certified_height = None;
        self.advance_round(
            max_replicas,
            new_blocks,
            blocks_to_notarize,
            add_catch_up_package_if_needed,
            should_finalize,
            should_add_random_tape,
            n_shares,
            rb_shares,
            f_shares,
            certified_height,
        )
    }

    // Advances the pool mimicking an idealized situation: 1 notarized and finalized
    // block in every round. However, no CUPs are created.
    pub fn advance_round_normal_operation_no_cup(&mut self) -> Height {
        let max_replicas = 10;
        let new_blocks = 1;
        let blocks_to_notarize = 1;
        let should_finalize = true;
        let add_catch_up_package_if_needed = false;
        let should_add_random_tape = true;
        let n_shares = 0;
        let rb_shares = 0;
        let f_shares = 0;
        let certified_height = None;
        self.advance_round(
            max_replicas,
            new_blocks,
            blocks_to_notarize,
            add_catch_up_package_if_needed,
            should_finalize,
            should_add_random_tape,
            n_shares,
            rb_shares,
            f_shares,
            certified_height,
        )
    }

    /// Returns a round, which can be granularly configured before it's
    /// executed.
    pub fn prepare_round(&mut self) -> Round {
        Round::new(self)
    }

    // This functions advances the pool in a parameterized manner as follows.
    // * Create a new random beacon.
    // * Add `new_blocks` new block proposals to the proposals from the previous
    //   rounds (ranked in their order).
    // * Notarize first `blocks_to_notarize` blocks or finalize (and notarize) the
    //   first one if `should_finalize` is true.
    // * Add notarization, random beacon and finalization shares to the new blocks
    //   pseudo-randomly.
    #[allow(clippy::too_many_arguments)]
    fn advance_round(
        &mut self,
        max_replicas: u32,
        new_blocks: u32,
        mut blocks_to_notarize: u32,
        mut add_catch_up_package_if_needed: bool,
        mut should_finalize: bool,
        should_add_random_tape: bool,
        n_shares: u32,
        rb_shares: u32,
        f_shares: u32,
        // this is a vector of 32-element arrays with random usize numbers
        certified_height: Option<Height>,
    ) -> Height {
        let notarized_height = self
            .pool
            .validated()
            .notarization()
            .height_range()
            .map(|n| n.max)
            .unwrap_or_else(|| Height::from(0));
        let random_beacon_height = self
            .pool
            .validated()
            .random_beacon()
            .height_range()
            .map(|r| r.max)
            .unwrap();
        let finalized_height = self
            .pool
            .validated()
            .finalization()
            .height_range()
            .map(|n| n.max)
            .unwrap_or_else(|| Height::from(0));

        assert_eq!(
            notarized_height, random_beacon_height,
            "advance_round expects that notarized height is equal to random beacon height"
        );
        let mut rand_num = [0; 32].iter().cycle();
        let node_id = node_test_id(0);
        let dkg_id = NiDkgId {
            start_block_height: Height::from(0),
            dealer_subnet: subnet_test_id(0),
            dkg_tag: NiDkgTag::HighThreshold,
            target_subnet: NiDkgTargetSubnet::Local,
        };
        let crypto = CryptoReturningOk::default();

        // create the next beacon
        let beacon = self.make_next_beacon();
        let height = beacon.content.height;
        self.insert_beacon_chain(&beacon, height);

        // get the list of all proposals from the highest height
        let candidates: Vec<Block> = self.latest_notarized_blocks().collect();
        assert!(
            !candidates.is_empty(),
            "there is at least one candidate block"
        );

        // generate new proposals
        let mut blocks = Vec::new();
        for i in 0..new_blocks {
            let parent = &candidates[rand_num.next().unwrap() % candidates.len()];
            let mut block: Block = self
                .make_next_block_from_parent(parent, Rank(i as u64))
                .into();
            // if it is a dkg summary block and catch up package is required, we must
            // finalize this round too.
            if block.payload.as_ref().is_summary() && add_catch_up_package_if_needed {
                should_finalize = true;
            } else {
                add_catch_up_package_if_needed = false;
            }
            if let Some(height) = certified_height {
                block.context.certified_height = height;
            }
            let block_proposal = BlockProposal::fake(
                block.clone(),
                node_test_id((*rand_num.next().unwrap() % max_replicas as usize) as u64),
            );
            if i % 2 == 0 {
                self.insert_validated(block_proposal.clone());
            } else {
                self.insert_unvalidated(block_proposal.clone());
            }
            // if we should finalize one, skip notarizing other blocks
            if should_finalize {
                self.notarize(&block_proposal);
                self.finalize(&block_proposal);
                should_finalize = false;
                blocks_to_notarize = 0;

                if add_catch_up_package_if_needed {
                    add_catch_up_package_if_needed = false;
                    let catch_up_package = self.make_catch_up_package(height);
                    self.insert_validated(catch_up_package);
                }

                // add the random tape values for the finalized heights
                if should_add_random_tape {
                    for h in finalized_height.get() + 1..=block_proposal.height().get() {
                        self.insert_random_tape(Height::from(h));
                    }
                }
            } else if blocks_to_notarize > 0 {
                self.notarize(&block_proposal);
                blocks_to_notarize -= 1;
            }
            blocks.push(block_proposal);
        }

        // create RB shares for new blocks
        for i in 0..rb_shares {
            let content = RandomBeaconContent::new(height, ic_types::crypto::crypto_hash(&beacon));
            let share = RandomBeaconShare {
                signature: crypto
                    .sign_threshold(&content, dkg_id)
                    .map(|signature| ThresholdSignatureShare {
                        signature,
                        signer: node_id,
                    })
                    .unwrap(),
                content,
            };
            if i % 2 == 0 {
                self.insert_validated(share);
            } else {
                self.insert_unvalidated(share);
            }
        }

        // create notarization shares for new blocks
        for i in 0..n_shares {
            let block = &blocks[rand_num.next().unwrap() % blocks.len()];
            let content = NotarizationContent::new(height, block.content.get_hash().clone());
            let share = NotarizationShare {
                signature: crypto
                    .sign_multi(&content, node_id, RegistryVersion::from(1))
                    .map(|signature| MultiSignatureShare {
                        signature,
                        signer: node_id,
                    })
                    .unwrap(),
                content,
            };
            if i % 2 == 0 {
                self.insert_validated(share);
            } else {
                self.insert_unvalidated(share);
            }
        }

        // create finalization shares for new blocks
        for i in 0..f_shares {
            let block = &blocks[rand_num.next().unwrap() % blocks.len()];
            let content = FinalizationContent::new(height, block.content.get_hash().clone());
            let share = FinalizationShare {
                signature: crypto
                    .sign_multi(&content, node_id, RegistryVersion::from(1))
                    .map(|signature| MultiSignatureShare {
                        signature,
                        signer: node_id,
                    })
                    .unwrap(),
                content,
            };
            if i % 2 == 0 {
                self.insert_validated(share);
            } else {
                self.insert_unvalidated(share);
            }
        }
        height
    }

    pub fn notarize(&mut self, block: &BlockProposal) -> Notarization {
        let content = NotarizationContent::new(block.height(), block.content.get_hash().clone());
        let notarization = Notarization::fake(content);
        self.insert_validated(notarization.clone());

        notarization
    }

    pub fn finalize(&mut self, block: &BlockProposal) -> Finalization {
        let content = FinalizationContent::new(block.height(), block.content.get_hash().clone());
        let finalization = Finalization::fake(content);
        self.insert_validated(finalization.clone());

        finalization
    }

    pub fn finalize_block(&mut self, block: &Block) {
        let content =
            FinalizationContent::new(block.height(), ic_types::crypto::crypto_hash(block));
        self.insert_validated(Finalization::fake(content))
    }

    pub fn make_beacon_chain(start: RandomBeacon, to: Height) -> Vec<RandomBeacon> {
        let mut beacons = Vec::new();
        let mut last = start;
        while last.content.height <= to {
            let next = RandomBeacon::from_parent(&last);
            beacons.push(last);
            last = next;
        }
        beacons
    }

    pub fn insert_beacon_chain(&mut self, start: &RandomBeacon, to: Height) {
        let beacons = Self::make_beacon_chain(start.clone(), to);
        self.insert_many(beacons, true);
    }

    pub fn insert_many<T: ConsensusMessageHashable + Clone>(
        &mut self,
        items: Vec<T>,
        validated: bool,
    ) {
        items.into_iter().for_each(|item| {
            if validated {
                self.insert_validated(item)
            } else {
                self.insert_unvalidated(item)
            }
        })
    }

    pub fn insert_block_chain_with(
        &mut self,
        start: BlockProposal,
        to: Height,
    ) -> Vec<BlockProposal> {
        let mut result = Vec::new();
        let mut last = start;
        while last.height() <= to {
            let next = self.make_next_block_from_parent(last.as_ref(), Rank(0));
            result.push(last.clone());
            self.insert_validated(last.clone());
            self.notarize(&last);
            last = next;
        }
        result
    }

    pub fn insert_block_chain(&mut self, to: Height) -> Vec<BlockProposal> {
        self.insert_block_chain_with(self.make_next_block(), to)
    }

    pub fn insert_random_tape(&mut self, height: Height) {
        let msg = RandomTape::fake(RandomTapeContent::new(height)).into_message();
        let time_source = self.time_source.clone();
        self.apply(vec![ChangeAction::AddToValidated(
            ValidatedConsensusArtifact {
                msg,
                timestamp: time_source.get_relative_time(),
            },
        )]);
    }

    pub fn purge_validated_below<T: ConsensusMessageHashable + HasHeight>(&mut self, value: T) {
        let msg = value.into_message();
        self.apply(vec![ChangeAction::PurgeValidatedBelow(msg.height())]);
    }

    pub fn insert_validated<T: ConsensusMessageHashable>(&mut self, value: T) {
        let msg = value.into_message();
        let time_source = self.time_source.clone();
        self.apply(vec![ChangeAction::AddToValidated(
            ValidatedConsensusArtifact {
                msg,
                timestamp: time_source.get_relative_time(),
            },
        )]);
    }

    pub fn remove_unvalidated<T: ConsensusMessageHashable>(&mut self, value: T) {
        let msg = value.into_message();
        self.apply(vec![ChangeAction::RemoveFromUnvalidated(msg)]);
    }

    pub fn insert_unvalidated<T: ConsensusMessageHashable>(&mut self, value: T) {
        self.insert(UnvalidatedConsensusArtifact {
            message: value.into_message(),
            peer_id: node_test_id(0),
            timestamp: UNIX_EPOCH,
        });
    }

    pub fn get_cache(&self) -> Arc<dyn ConsensusPoolCache> {
        self.pool.get_cache()
    }

    pub fn get_block_cache(&self) -> Arc<dyn ConsensusBlockCache> {
        self.pool.get_block_cache()
    }
}

impl ConsensusPool for TestConsensusPool {
    fn validated(&self) -> &dyn PoolSection<ValidatedConsensusArtifact> {
        self.pool.validated()
    }

    fn unvalidated(&self) -> &dyn PoolSection<UnvalidatedConsensusArtifact> {
        self.pool.unvalidated()
    }

    fn as_cache(&self) -> &dyn ConsensusPoolCache {
        self.pool.as_cache()
    }

    fn as_block_cache(&self) -> &dyn ConsensusBlockCache {
        self.pool.as_block_cache()
    }

    fn build_block_chain(&self, start: &Block, end: &Block) -> Arc<dyn ConsensusBlockChain> {
        self.pool.build_block_chain(start, end)
    }

    fn block_instant(&self, hash: &CryptoHashOf<Block>) -> Option<Instant> {
        self.pool.block_instant(hash)
    }

    fn message_instant(&self, id: &ConsensusMessageId) -> Option<Instant> {
        self.pool.message_instant(id)
    }
}

impl MutablePool<ConsensusMessage> for TestConsensusPool {
    type Mutations = Mutations;

    fn insert(&mut self, unvalidated_artifact: UnvalidatedConsensusArtifact) {
        self.pool.insert(unvalidated_artifact)
    }

    fn remove(&mut self, id: &ConsensusMessageId) {
        self.pool.remove(id)
    }

    fn apply(&mut self, change_set: Mutations) -> ArtifactTransmits<ConsensusMessage> {
        self.pool.apply(change_set)
    }
}
