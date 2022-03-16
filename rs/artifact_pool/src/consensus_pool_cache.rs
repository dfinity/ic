//! We define a cache for consensus objects/values that is updated whenever
//! consensus updates the consensus pool.
use crate::consensus_pool::BlockChainIterator;
use ic_interfaces::consensus_pool::{
    ChainIterator, ChangeAction, ConsensusBlockCache, ConsensusBlockChain, ConsensusPool,
    ConsensusPoolCache,
};
use ic_types::{
    consensus::{
        catchup::CUPWithOriginalProtobuf, Block, CatchUpPackage, ConsensusMessage, Finalization,
        HasHeight,
    },
    Height, Time,
};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::sync::{Arc, RwLock};

/// Implementation of ConsensusCache and ConsensusPoolCache.
pub(crate) struct ConsensusCacheImpl {
    cache: RwLock<CachedData>,
}

/// Things that can be updated in the consensus cache.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CacheUpdateAction {
    Finalization,
    CatchUpPackage,
}

// Internal cached data held by the the ConsensusCache.
struct CachedData {
    finalized_block: Block,
    summary_block: Block,
    catch_up_package: CUPWithOriginalProtobuf,
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
        if catch_up_package.height() > self.catch_up_package.cup.height() {
            Some(CacheUpdateAction::CatchUpPackage)
        } else {
            None
        }
    }
}

impl ConsensusPoolCache for ConsensusCacheImpl {
    fn finalized_block(&self) -> Block {
        self.cache.read().unwrap().finalized_block.clone()
    }

    fn consensus_time(&self) -> Option<Time> {
        let cache = &*self.cache.read().unwrap();
        if cache.finalized_block.height() == Height::from(0) {
            None
        } else {
            Some(cache.finalized_block.context.time)
        }
    }

    fn catch_up_package(&self) -> CatchUpPackage {
        self.cache.read().unwrap().catch_up_package.cup.clone()
    }

    fn cup_with_protobuf(&self) -> CUPWithOriginalProtobuf {
        self.cache.read().unwrap().catch_up_package.clone()
    }

    fn summary_block(&self) -> Block {
        self.cache.read().unwrap().summary_block.clone()
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
        let catch_up_package = get_highest_catch_up_package(pool);
        let finalized_block = get_highest_finalized_block(pool, &catch_up_package.cup);
        let mut summary_block = catch_up_package.cup.content.block.as_ref().clone();
        update_summary_block(pool, &mut summary_block, &finalized_block);
        let finalized_chain = ConsensusBlockChainImpl::new(pool, &summary_block, &finalized_block);

        Self {
            cache: RwLock::new(CachedData {
                finalized_block,
                summary_block,
                catch_up_package,
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
                ChangeAction::AddToValidated(ConsensusMessage::Finalization(x)) => {
                    cache.check_finalization(x)
                }
                ChangeAction::MoveToValidated(ConsensusMessage::Finalization(x)) => {
                    cache.check_finalization(x)
                }
                ChangeAction::AddToValidated(ConsensusMessage::CatchUpPackage(x)) => {
                    cache.check_catch_up_package(x)
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
                cache.catch_up_package = get_highest_catch_up_package(pool);
                if cache.catch_up_package.cup.height() > cache.finalized_block.height() {
                    cache.finalized_block =
                        cache.catch_up_package.cup.content.block.as_ref().clone()
                }
            }
        });
        updates.iter().for_each(|update| {
            if let CacheUpdateAction::Finalization = update {
                cache.finalized_block =
                    get_highest_finalized_block(pool, &cache.catch_up_package.cup);
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
                panic!(
                    "Missing validated block proposal matching finalization {:?}",
                    finalization
                )
            }
        }
        Err(_) => catch_up_package.content.block.as_ref().clone(),
    }
}

pub(crate) fn get_highest_catch_up_package(pool: &dyn ConsensusPool) -> CUPWithOriginalProtobuf {
    let protobuf = pool.validated().highest_catch_up_package_proto();
    let cup = CatchUpPackage::try_from(&protobuf).expect("CUP should be retrievable from protobuf");
    CUPWithOriginalProtobuf { cup, protobuf }
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
                start_height, finalized_tip.height(), summary_height
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
                        "Consensus pool has finalization {:?}, but its referenced block is not found",
                        finalization
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
    /// The blocks in the chain between [summary_block, tip],
    /// ends inclusive. So this can never be empty.
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
            Ordering::Less | Ordering::Equal => {
                Self::add_blocks(consensus_pool, summary_block.height(), tip, &mut blocks)
            }
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
        Self::add_blocks(consensus_pool, start_height, tip, &mut self.blocks)
    }

    /// Adds the blocks in the range [start_height, tip.height()] to the
    /// chain(ends inclusive).
    fn add_blocks(
        consensus_pool: &dyn ConsensusPool,
        start_height: Height,
        tip: &Block,
        blocks: &mut BTreeMap<Height, Block>,
    ) {
        BlockChainIterator::new(consensus_pool, tip.clone())
            .take_while(|block| block.height() >= start_height)
            .for_each(|block| {
                blocks.insert(block.height(), block);
            })
    }
}

impl ConsensusBlockChain for ConsensusBlockChainImpl {
    fn tip(&self) -> Block {
        let (_, last_block) = self.blocks.iter().next_back().unwrap();
        last_block.clone()
    }

    fn block(&self, height: Height) -> Option<Block> {
        self.blocks.get(&height).cloned()
    }

    fn len(&self) -> usize {
        self.blocks.len()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ic_consensus_message::ConsensusMessageHashable;
    use ic_test_artifact_pool::consensus_pool::TestConsensusPool;
    use ic_test_utilities::{
        consensus::fake::*,
        crypto::CryptoReturningOk,
        mock_time,
        registry::{setup_registry, SubnetRecordBuilder},
        state_manager::FakeStateManager,
        types::ids::{node_test_id, subnet_test_id},
        FastForwardTimeSource,
    };
    use ic_types::consensus::*;
    use std::sync::Arc;
    use std::time::Duration;

    // Verifies that the finalized chain has the specified blocks
    fn check_finalized_chain(consensus_cache: &ConsensusCacheImpl, expected: &[Height]) {
        let finalized_chain = consensus_cache.finalized_chain();
        assert_eq!(finalized_chain.len(), expected.len());
        for height in expected {
            assert!(finalized_chain.block(*height).is_some());
        }
        let last = *expected.iter().next_back().unwrap();
        assert_eq!(finalized_chain.tip().height(), last);
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
            let time = mock_time() + Duration::from_secs(10);
            block.content.as_mut().context.time = time;
            pool.insert_validated(block.clone());
            pool.notarize(&block);
            let finalization = Finalization::fake(FinalizationContent::new(
                block.height(),
                block.content.get_hash().clone(),
            ));

            // 2. Cache can be updated by finalization
            let updates = consensus_cache.prepare(&[ChangeAction::AddToValidated(
                finalization.clone().into_message(),
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
                catch_up_package.clone().into_message(),
            )]);
            assert_eq!(updates, vec![CacheUpdateAction::CatchUpPackage]);
            pool.insert_validated(catch_up_package.clone());
            consensus_cache.update(&pool, updates);
            assert_eq!(consensus_cache.catch_up_package(), catch_up_package);
            assert_eq!(consensus_cache.finalized_block().height(), Height::from(4));
            check_finalized_chain(&consensus_cache, &[Height::from(4)]);
        })
    }
}
