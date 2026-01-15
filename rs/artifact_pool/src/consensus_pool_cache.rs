//! We define a cache for consensus objects/values that is updated whenever
//! consensus updates the consensus pool.
use ic_interfaces::consensus_pool::{
    ChainIterator, ChangeAction, ConsensusBlockCache, ConsensusBlockChain, ConsensusBlockChainErr,
    ConsensusPool, ConsensusPoolCache, ConsensusTime,
};
use ic_protobuf::types::v1 as pb;
use ic_types::{
    Height, Time,
    consensus::{Block, CatchUpPackage, ConsensusMessage, Finalization, HasHeight, HashedBlock},
};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

/// Implementation of [`ConsensusBlockCache`] and [`ConsensusPoolCache`].
pub(crate) struct ConsensusCacheImpl {
    cache: RwLock<CachedData>,
}

/// Things that can be updated in the consensus cache.
#[derive(Eq, PartialEq, Debug)]
pub(crate) enum CacheUpdateAction {
    Finalization,
    CatchUpPackage,
}

/// Internal cached data held by the [`ConsensusCacheImpl`].
struct CachedData {
    finalized_block: Block,
    summary_block: Block,
    catch_up_package: CatchUpPackage,
    catch_up_package_proto: pb::CatchUpPackage,
    finalized_chain: ConsensusBlockChainImpl,
}

impl CachedData {
    fn check_finalization(&self, finalization: &Finalization) -> Option<CacheUpdateAction> {
        if finalization.height() > self.finalized_block.height() {
            Some(CacheUpdateAction::Finalization)
        } else {
            None
        }
    }

    fn check_catch_up_package(
        &self,
        catch_up_package: &CatchUpPackage,
    ) -> Option<CacheUpdateAction> {
        if catch_up_package.height() > self.catch_up_package.height() {
            Some(CacheUpdateAction::CatchUpPackage)
        } else {
            None
        }
    }
}

/// A cached iterator for block ancestors.
struct CachedChainIterator<'a> {
    consensus_pool: &'a dyn ConsensusPool,
    finalized_chain: Arc<dyn ConsensusBlockChain>,
    to_block: Option<HashedBlock>,
    cursor: Option<Block>,
}

impl<'a> CachedChainIterator<'a> {
    fn new(
        consensus_pool: &'a dyn ConsensusPool,
        finalized_chain: Arc<dyn ConsensusBlockChain>,
        from_block: Block,
        to_block: Option<HashedBlock>,
    ) -> Self {
        CachedChainIterator {
            consensus_pool,
            finalized_chain,
            to_block,
            cursor: Some(from_block),
        }
    }

    fn get_parent_block(&self, block: &Block) -> Option<Block> {
        let height = block.height();
        if height == Height::from(0) {
            return None;
        }
        let parent_height = height.decrement();
        let parent_hash = &block.parent;
        if let Some(to_block) = &self.to_block {
            match parent_height.cmp(&to_block.height()) {
                std::cmp::Ordering::Less => {
                    return None;
                }
                std::cmp::Ordering::Equal => {
                    if parent_hash == to_block.get_hash() {
                        return Some(to_block.as_ref().clone());
                    } else {
                        return None;
                    }
                }
                _ => (),
            }
        }
        // Use cached blocks if the height is finalized
        if parent_height <= self.finalized_chain.tip().height()
            && let Ok(block) = self.finalized_chain.get_block_by_height(parent_height)
        {
            return Some(block.clone());
        }

        for proposal in self
            .consensus_pool
            .validated()
            .block_proposal()
            .get_by_height(parent_height)
        {
            if proposal.content.get_hash() == parent_hash {
                return Some(proposal.content.into_inner());
            }
        }

        if let Ok(cup) = self
            .consensus_pool
            .validated()
            .catch_up_package()
            .get_only_by_height(parent_height)
        {
            let (hash, block) = cup.content.block.decompose();
            if hash == *parent_hash {
                return Some(block);
            }
        }

        None
    }
}

impl Iterator for CachedChainIterator<'_> {
    type Item = Block;

    fn next(&mut self) -> Option<Self::Item> {
        let parent = self
            .cursor
            .as_ref()
            .and_then(|block| self.get_parent_block(block));
        std::mem::replace(&mut self.cursor, parent)
    }
}

impl ConsensusTime for ConsensusCacheImpl {
    fn consensus_time(&self) -> Option<Time> {
        let cache = &*self.cache.read().unwrap();
        if cache.finalized_block.height() == Height::from(0) {
            None
        } else {
            Some(cache.finalized_block.context.time)
        }
    }
}

impl ConsensusPoolCache for ConsensusCacheImpl {
    fn finalized_block(&self) -> Block {
        self.cache.read().unwrap().finalized_block.clone()
    }

    fn catch_up_package(&self) -> CatchUpPackage {
        self.cache.read().unwrap().catch_up_package.clone()
    }

    fn cup_as_protobuf(&self) -> pb::CatchUpPackage {
        self.cache.read().unwrap().catch_up_package_proto.clone()
    }

    fn summary_block(&self) -> Block {
        self.cache.read().unwrap().summary_block.clone()
    }

    fn chain_iterator<'a>(
        &self,
        pool: &'a dyn ConsensusPool,
        block: Block,
    ) -> Box<dyn Iterator<Item = Block> + 'a> {
        Box::new(CachedChainIterator::new(
            pool,
            self.finalized_chain(),
            block,
            Some(self.catch_up_package().content.block),
        ))
    }
}

impl ConsensusBlockCache for ConsensusCacheImpl {
    fn finalized_chain(&self) -> Arc<dyn ConsensusBlockChain> {
        Arc::new(self.cache.read().unwrap().finalized_chain.clone())
    }
}

impl ConsensusCacheImpl {
    /// Initialize and return a new ConsensusCache with data from the given
    /// ConsensusPool.
    pub(crate) fn new(pool: &dyn ConsensusPool) -> Self {
        let cup_proto = pool.validated().highest_catch_up_package_proto();
        let catch_up_package = (&cup_proto).try_into().expect("deserializing CUP failed");
        let finalized_block = get_highest_finalized_block(pool, &catch_up_package);
        let mut summary_block = catch_up_package.content.block.as_ref().clone();
        update_summary_block(pool, &mut summary_block, &finalized_block);
        let finalized_chain = ConsensusBlockChainImpl::new(pool, &summary_block, &finalized_block);

        Self {
            cache: RwLock::new(CachedData {
                finalized_block,
                summary_block,
                catch_up_package,
                catch_up_package_proto: cup_proto,
                finalized_chain,
            }),
        }
    }

    pub(crate) fn prepare(&self, change_set: &[ChangeAction]) -> Vec<CacheUpdateAction> {
        if change_set.is_empty() {
            return Vec::new();
        }
        let cache = &*self.cache.read().unwrap();
        change_set
            .iter()
            .filter_map(|change_action| match change_action {
                ChangeAction::AddToValidated(validated_consensus_artifact) => {
                    match &validated_consensus_artifact.msg {
                        ConsensusMessage::Finalization(x) => cache.check_finalization(x),
                        ConsensusMessage::CatchUpPackage(x) => cache.check_catch_up_package(x),
                        _ => None,
                    }
                }
                ChangeAction::MoveToValidated(ConsensusMessage::Finalization(x)) => {
                    cache.check_finalization(x)
                }
                ChangeAction::MoveToValidated(ConsensusMessage::CatchUpPackage(x)) => {
                    cache.check_catch_up_package(x)
                }
                _ => None,
            })
            .collect()
    }

    pub(crate) fn update(&self, pool: &dyn ConsensusPool, updates: Vec<CacheUpdateAction>) {
        let cache = &mut *self.cache.write().unwrap();
        updates.iter().for_each(|update| {
            if let CacheUpdateAction::CatchUpPackage = update {
                cache.catch_up_package_proto = pool.validated().highest_catch_up_package_proto();
                cache.catch_up_package = CatchUpPackage::try_from(&cache.catch_up_package_proto)
                    .expect("deserializing CUP from protobuf artifact");
                if cache.catch_up_package.height() > cache.finalized_block.height() {
                    cache.finalized_block = cache.catch_up_package.content.block.as_ref().clone()
                }
            }
        });
        updates.iter().for_each(|update| {
            if let CacheUpdateAction::Finalization = update {
                cache.finalized_block = get_highest_finalized_block(pool, &cache.catch_up_package);
            }
        });
        update_summary_block(pool, &mut cache.summary_block, &cache.finalized_block);
        cache
            .finalized_chain
            .update(pool, &cache.summary_block, &cache.finalized_block);
    }
}

pub(crate) fn get_highest_finalized_block(
    pool: &dyn ConsensusPool,
    catch_up_package: &CatchUpPackage,
) -> Block {
    match pool.validated().finalization().get_highest() {
        Ok(finalization) => {
            let h = finalization.height();
            if h <= catch_up_package.height() {
                catch_up_package.content.block.as_ref().clone()
            } else {
                let block_hash = &finalization.content.block;
                for proposal in pool.validated().block_proposal().get_by_height(h) {
                    if proposal.content.get_hash() == block_hash {
                        return proposal.content.into_inner();
                    }
                }
                panic!("Missing validated block proposal matching finalization {finalization:?}")
            }
        }
        Err(_) => catch_up_package.content.block.as_ref().clone(),
    }
}

/// Find the DKG summary block that is between the given 'summary_block' and a
/// finalized tip 'block' (inclusive), and update the given summary_block to it.
pub(crate) fn update_summary_block(
    consensus_pool: &dyn ConsensusPool,
    summary_block: &mut Block,
    finalized_tip: &Block,
) {
    let summary_height = summary_block.height();
    let start_height = finalized_tip.payload.as_ref().dkg_interval_start_height();
    match start_height.cmp(&summary_height) {
        Ordering::Less => {
            panic!(
                "DKG start_height {} of the given finalized block at height {} is less than summary block height {}",
                start_height,
                finalized_tip.height(),
                summary_height
            );
        }
        Ordering::Equal => (),
        Ordering::Greater => {
            // Update if we have a finalization at start_height
            if let Ok(finalization) = consensus_pool
                .validated()
                .finalization()
                .get_only_by_height(start_height)
            {
                let block = consensus_pool
                    .validated()
                    .block_proposal()
                    .get_by_height(start_height)
                    .find_map(|proposal| {
                        if proposal.content.get_hash() == &finalization.content.block {
                            Some(proposal.content.into_inner())
                        } else {
                            None
                        }
                    });
                *summary_block = block.unwrap_or_else(|| {
                    panic!(
                        "Consensus pool has finalization {finalization:?}, but its referenced block is not found"
                    )
                });
                return;
            }

            // Otherwise, find the parent block at start_height
            *summary_block = ChainIterator::new(consensus_pool, finalized_tip.clone(), None)
                .take_while(|block| block.height() >= start_height)
                .find(|block| block.height() == start_height)
                .unwrap_or_else(|| {
                    panic!(
                        "No DKG summary block found between summary block at height {} and finalized tip at height {}",
                        summary_height,
                        finalized_tip.height(),
                    )
                });
            assert!(
                summary_block.payload.is_summary(),
                "Block at DKG start height {} does not have a DKG summary payload {:?}",
                start_height,
                summary_block.payload.as_ref()
            );
        }
    }
}

#[derive(Clone)]
pub(crate) struct ConsensusBlockChainImpl {
    /// Blocks in the chain between [summary_block, tip], ends inclusive. So this can never be empty.
    blocks: BTreeMap<Height, Block>,
}

impl ConsensusBlockChainImpl {
    pub(crate) fn new(
        consensus_pool: &dyn ConsensusPool,
        summary_block: &Block,
        tip: &Block,
    ) -> Self {
        let mut blocks = BTreeMap::new();
        match summary_block.height().cmp(&tip.height()) {
            Ordering::Less | Ordering::Equal => Self::add_blocks(
                consensus_pool,
                summary_block.height(),
                summary_block,
                tip,
                &mut blocks,
            ),
            Ordering::Greater => {
                panic!(
                    "ConsensusBlockChainImpl::new(): summary height {} > tip height {}",
                    summary_block.height(),
                    tip.height()
                );
            }
        }

        Self { blocks }
    }

    pub(crate) fn new_from_cache(
        consensus_pool: &dyn ConsensusPool,
        start_height: Height,
        tip: Block,
    ) -> Self {
        let iter = CachedChainIterator::new(
            consensus_pool,
            consensus_pool.as_block_cache().finalized_chain(),
            tip,
            None,
        )
        .take_while(|block| block.height() >= start_height)
        .map(|block| (block.height(), block));

        Self {
            blocks: BTreeMap::from_iter(iter),
        }
    }

    /// Updates the blocks based on the new summary_block/tip.
    fn update(&mut self, consensus_pool: &dyn ConsensusPool, summary_block: &Block, tip: &Block) {
        // The map can never be empty, hence these unwraps are safe.
        let cur_summary_height = *self.blocks.keys().next().unwrap();
        let cur_tip_height = *self.blocks.keys().next_back().unwrap();

        let start_height = if cur_summary_height == summary_block.height() {
            match cur_tip_height.cmp(&tip.height()) {
                Ordering::Less => {
                    // Common case: only the tip moved. Just append the new blocks
                    cur_tip_height.increment()
                }
                Ordering::Equal => return,
                Ordering::Greater => {
                    panic!(
                        "ConsensusBlockChainImpl::update(): current tip {} > new tip {}",
                        cur_tip_height,
                        tip.height(),
                    );
                }
            }
        } else {
            // Summary block changed. Rebuild the chain with the new range.
            self.blocks.clear();
            summary_block.height()
        };

        assert!(
            start_height <= tip.height(),
            "ConsensusBlockChainImpl::update(): start_height {} > new tip {}, \
            cur_tip = {}, cur_summary = {}, new_summary = {}",
            start_height,
            tip.height(),
            cur_tip_height,
            cur_summary_height,
            summary_block.height(),
        );
        Self::add_blocks(
            consensus_pool,
            start_height,
            summary_block,
            tip,
            &mut self.blocks,
        )
    }

    /// Adds the blocks in the range [start_height, tip.height()] to the
    /// chain(ends inclusive).
    fn add_blocks(
        consensus_pool: &dyn ConsensusPool,
        start_height: Height,
        summary_block: &Block,
        tip: &Block,
        blocks: &mut BTreeMap<Height, Block>,
    ) {
        // ChainIterator may miss the summary block if it only exists
        // as part of the CUP in the pool. We make sure it is included here.
        let summary_height = summary_block.height();
        if summary_height >= start_height && summary_height <= tip.height() {
            blocks.insert(summary_height, summary_block.clone());
        }
        ChainIterator::new(consensus_pool, tip.clone(), None)
            .take_while(|block| block.height() >= start_height)
            .for_each(|block| {
                blocks.insert(block.height(), block);
            })
    }
}

impl ConsensusBlockChain for ConsensusBlockChainImpl {
    fn tip(&self) -> &Block {
        let (_, block) = self.blocks.iter().next_back().unwrap();
        block
    }

    fn get_block_by_height(&self, height: Height) -> Result<&Block, ConsensusBlockChainErr> {
        self.blocks
            .get(&height)
            .ok_or(ConsensusBlockChainErr::BlockNotFound(height))
    }

    fn len(&self) -> usize {
        self.blocks.len()
    }

    fn iter_above(&self, height: Height) -> Box<dyn Iterator<Item = &Block> + '_> {
        Box::new(
            self.blocks
                .range(height.increment()..)
                .map(|(_, block)| block),
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::fake_block_proposal;
    use ic_crypto_test_utils_crypto_returning_ok::CryptoReturningOk;
    use ic_interfaces::consensus_pool::{HEIGHT_CONSIDERED_BEHIND, ValidatedConsensusArtifact};
    use ic_test_artifact_pool::consensus_pool::{Round, TestConsensusPool};
    use ic_test_utilities::state_manager::FakeStateManager;
    use ic_test_utilities_consensus::fake::*;
    use ic_test_utilities_registry::{SubnetRecordBuilder, setup_registry};
    use ic_test_utilities_time::FastForwardTimeSource;
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_types::consensus::*;
    use ic_types::crypto::crypto_hash;
    use ic_types::time::UNIX_EPOCH;
    use std::sync::Arc;
    use std::time::Duration;

    // Verifies that the finalized chain has the specified blocks
    fn check_finalized_chain(consensus_cache: &ConsensusCacheImpl, expected: &[Height]) {
        let finalized_chain = consensus_cache.finalized_chain();
        assert_eq!(finalized_chain.len(), expected.len());

        for height in expected {
            assert!(finalized_chain.get_block_by_height(*height).is_ok());
        }

        assert_eq!(
            finalized_chain.tip().height(),
            *expected.iter().next_back().unwrap()
        );
    }

    #[test]
    fn test_consensus_cache() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let time_source = FastForwardTimeSource::new();
            let subnet_id = subnet_test_id(1);
            let committee = vec![node_test_id(0)];
            let dkg_interval_length = 3;
            let subnet_records = vec![(
                1,
                SubnetRecordBuilder::from(&committee)
                    .with_dkg_interval_length(dkg_interval_length)
                    .build(),
            )];
            let registry = setup_registry(subnet_id, subnet_records);
            let state_manager = FakeStateManager::new();
            let state_manager = Arc::new(state_manager);
            let mut pool = TestConsensusPool::new(
                node_test_id(0),
                subnet_id,
                pool_config,
                time_source,
                registry,
                Arc::new(CryptoReturningOk::default()),
                state_manager,
                None,
            );

            // 1. Cache is properly initialized
            let consensus_cache = ConsensusCacheImpl::new(&pool);
            assert_eq!(consensus_cache.finalized_block().height(), Height::from(0));
            // No consensus time when there is only genesis block
            assert_eq!(consensus_cache.consensus_time(), None);
            check_finalized_chain(&consensus_cache, &[Height::from(0)]);

            assert_eq!(pool.advance_round_normal_operation_n(2), Height::from(2));
            let mut block = pool.make_next_block();
            let time = UNIX_EPOCH + Duration::from_secs(10);
            block.content.as_mut().context.time = time;
            // recompute the hash to make sure it's still correct
            block.update_content();
            pool.insert_validated(block.clone());
            pool.notarize(&block);
            let finalization = Finalization::fake(FinalizationContent::new(
                block.height(),
                block.content.get_hash().clone(),
            ));

            // 2. Cache can be updated by finalization
            let updates = consensus_cache.prepare(&[ChangeAction::AddToValidated(
                ValidatedConsensusArtifact {
                    msg: finalization.clone().into_message(),
                    timestamp: time,
                },
            )]);
            assert_eq!(updates, vec![CacheUpdateAction::Finalization]);
            pool.insert_validated(finalization);
            consensus_cache.update(&pool, updates);
            assert_eq!(consensus_cache.finalized_block().height(), Height::from(3));
            assert_eq!(consensus_cache.consensus_time(), Some(time));
            pool.insert_validated(pool.make_next_beacon());
            pool.insert_validated(pool.make_next_tape());
            check_finalized_chain(
                &consensus_cache,
                &[
                    Height::from(0),
                    Height::from(1),
                    Height::from(2),
                    Height::from(3),
                ],
            );

            // 3. Cache can be updated by CatchUpPackage
            assert_eq!(
                pool.prepare_round().dont_add_catch_up_package().advance(),
                Height::from(4)
            );
            let catch_up_package = pool.make_catch_up_package(Height::from(4));
            let updates = consensus_cache.prepare(&[ChangeAction::AddToValidated(
                ValidatedConsensusArtifact {
                    msg: catch_up_package.clone().into_message(),
                    timestamp: time,
                },
            )]);
            assert_eq!(updates, vec![CacheUpdateAction::CatchUpPackage]);
            pool.insert_validated(catch_up_package.clone());
            consensus_cache.update(&pool, updates);
            assert_eq!(consensus_cache.catch_up_package(), catch_up_package);
            assert_eq!(consensus_cache.finalized_block().height(), Height::from(4));
            check_finalized_chain(&consensus_cache, &[Height::from(4)]);
        })
    }

    /// Tests that `is_replica_behind` (trait method of [`ConsensusPoolCache`]) works as expected
    #[test]
    fn test_is_replica_behind() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let subnet_records = vec![(
                1,
                SubnetRecordBuilder::from(&[node_test_id(0)])
                    .with_dkg_interval_length(3)
                    .build(),
            )];

            let mut pool = TestConsensusPool::new(
                node_test_id(0),
                subnet_test_id(1),
                pool_config,
                FastForwardTimeSource::new(),
                setup_registry(subnet_test_id(1), subnet_records),
                Arc::new(CryptoReturningOk::default()),
                Arc::new(FakeStateManager::new()),
                None,
            );

            let consensus_cache = ConsensusCacheImpl::new(&pool);

            // Initially the replica is not behind
            assert!(!consensus_cache.is_replica_behind(Height::new(0)));

            // Advance and set the certified height to one below where the replica would be considered behind
            pool.advance_round_normal_operation_n(HEIGHT_CONSIDERED_BEHIND.get() - 1);
            Round::new(&mut pool)
                .with_certified_height(HEIGHT_CONSIDERED_BEHIND)
                .advance();
            consensus_cache.update(&pool, vec![CacheUpdateAction::Finalization]);

            // Check that the replica is still not considered behind
            assert!(!consensus_cache.is_replica_behind(Height::new(0)));

            // Advance one more round
            Round::new(&mut pool)
                .with_certified_height(HEIGHT_CONSIDERED_BEHIND + Height::new(1))
                .advance();
            consensus_cache.update(&pool, vec![CacheUpdateAction::Finalization]);

            // At this height, the replica should be considered behind
            assert!(consensus_cache.is_replica_behind(Height::new(0)))
        })
    }

    #[test]
    fn test_block_chain() {
        let mut chain = ConsensusBlockChainImpl {
            blocks: BTreeMap::new(),
        };

        let height = Height::new(100);
        assert_eq!(chain.len(), 0);
        assert_eq!(
            chain.get_block_by_height(height).err().unwrap(),
            ConsensusBlockChainErr::BlockNotFound(height)
        );
        let block = fake_block_proposal(height).as_ref().clone();
        chain.blocks.insert(height, block);
        assert_eq!(chain.len(), 1);
        assert!(chain.get_block_by_height(height).is_ok());

        let height = Height::new(200);
        let block = fake_block_proposal(height).as_ref().clone();
        chain.blocks.insert(height, block);
        assert_eq!(chain.len(), 2);
        assert!(chain.get_block_by_height(height).is_ok());
    }

    #[test]
    fn test_new_block_chain_from_cache() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let subnet_size = 7;
            let subnet_records = vec![(
                1,
                SubnetRecordBuilder::from(
                    &(0..subnet_size).map(node_test_id).collect::<Vec<_>>()[..],
                )
                .with_dkg_interval_length(9)
                .build(),
            )];

            let mut pool = TestConsensusPool::new(
                node_test_id(0),
                subnet_test_id(1),
                pool_config,
                FastForwardTimeSource::new(),
                setup_registry(subnet_test_id(1), subnet_records),
                Arc::new(CryptoReturningOk::default()),
                Arc::new(FakeStateManager::new()),
                None,
            );

            // Finalize a couple rounds
            pool.advance_round_normal_operation_n(3);

            // Advance a couple rounds without finalization
            let mut round = pool
                .prepare_round()
                .dont_finalize()
                .with_replicas(subnet_size as u32)
                .with_new_block_proposals(3)
                .with_blocks_to_notarize(2);
            for _ in 0..3 {
                round.advance();
            }

            let next_block_proposal = pool.make_next_block();
            let next_block = next_block_proposal.content.get_value().clone();
            assert_eq!(next_block.height().get(), 7);

            let chain =
                ConsensusBlockChainImpl::new_from_cache(&pool, Height::from(0), next_block.clone());
            assert_eq!(chain.blocks.len(), 8);
            assert_valid_chain(&chain, &next_block, 0);

            // Advance past the summary without creating a CUP
            pool.advance_round_with_block(&next_block_proposal);
            pool.advance_round_normal_operation_no_cup_n(3);

            let next_block_proposal = pool.make_next_block();
            let next_block = next_block_proposal.content.get_value().clone();
            assert_eq!(next_block.height().get(), 11);

            // The genesis block should still be part of the chain, even if we have a newer summary
            let chain =
                ConsensusBlockChainImpl::new_from_cache(&pool, Height::from(0), next_block.clone());
            assert_eq!(chain.blocks.len(), 12);
            assert_valid_chain(&chain, &next_block, 0);

            // Test a start height != 0
            let chain =
                ConsensusBlockChainImpl::new_from_cache(&pool, Height::from(4), next_block.clone());
            assert_eq!(chain.blocks.len(), 8);
            assert_valid_chain(&chain, &next_block, 4);
        })
    }

    fn assert_valid_chain(
        chain: &ConsensusBlockChainImpl,
        expected_tip: &Block,
        start_height: u64,
    ) {
        let tip = chain.tip();
        assert_eq!(tip, expected_tip);

        let mut expected_hash = tip.parent.clone();
        for height in (start_height..tip.height().get()).rev() {
            let next = chain.get_block_by_height(height.into()).unwrap();
            assert_eq!(crypto_hash(next), expected_hash);
            expected_hash = next.parent.clone();
        }
    }
}
