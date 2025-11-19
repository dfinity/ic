//! Wrapper to read the consensus pool

use crate::{range_len, registry_version_at_height};
use ic_interfaces::batch_payload::PastPayload;
use ic_interfaces::consensus_pool::*;
use ic_types::{
    Height, RegistryVersion, Time, consensus::catchup::*, consensus::*, crypto::CryptoHashOf,
};
use std::cmp::Ordering;
use std::time::Instant;

/// An error to be returned if the number of payloads found in the pool
/// doesn't match the expected amount.
#[derive(Debug)]
pub struct UnexpectedChainLength {
    pub expected: usize,
    pub returned: usize,
}
/// A struct and corresponding impl with helper methods to obtain particular
/// artifacts/messages from the artifact pool.
///
/// An important invariant is that the validated pool always has at least one
/// valid random beacon and one valid block that is considered finalized.
pub struct PoolReader<'a> {
    pool: &'a dyn ConsensusPool,
    pub(crate) cache: &'a dyn ConsensusPoolCache,
    pub(crate) block_cache: &'a dyn ConsensusBlockCache,
}

impl<'a> PoolReader<'a> {
    /// Create a PoolReader for a ConsensusPool.
    pub fn new(pool: &'a dyn ConsensusPool) -> Self {
        Self {
            pool,
            cache: pool.as_cache(),
            block_cache: pool.as_block_cache(),
        }
    }

    /// Return a ConsensusPoolCache reference.
    pub fn as_cache(&self) -> &dyn ConsensusPoolCache {
        self.cache
    }

    /// Return a ConsensusBlockCache reference.
    pub fn as_block_cache(&self) -> &dyn ConsensusBlockCache {
        self.block_cache
    }

    /// Return the registry version to be used for the given height.
    /// Note that this can only look up for height that is greater than or equal
    /// to the latest catch-up package height, otherwise an error is returned.
    pub fn registry_version(&self, height: Height) -> Option<RegistryVersion> {
        registry_version_at_height(self.cache, height)
    }

    /// Follow `block`'s ancestors until a block with `height` is found.
    pub fn follow_to_height(&self, block: Block, height: Height) -> Option<Block> {
        self.chain_iterator(block)
            .take_while(|block| block.height >= height)
            .last()
            .filter(|block| block.height == height)
    }

    /// Find ancestor blocks of `block`, and return an iterator that starts
    /// from `block` and ends when a parent is not found (e.g. genesis).
    pub fn chain_iterator(&self, block: Block) -> Box<dyn Iterator<Item = Block> + 'a> {
        self.cache.chain_iterator(self.pool, block)
    }

    /// Get the range of ancestor blocks of `block` specified (inclusively) by
    /// `min` and `max`. This assumes the correctness of the state of the pool.
    pub fn get_range(
        &self,
        block: Block,
        min: Height,
        max: Height,
    ) -> impl Iterator<Item = Block> + '_ {
        self.chain_iterator(block)
            .skip_while(move |block| block.height > max)
            .take_while(move |block| block.height >= min)
    }

    /// Return a `Vec` of all of the `Payload` between the provided `start`
    /// height and the `target` block. The result is empty if `target` block
    /// height < `start`.
    ///
    /// Note that the returned payloads are in reverse order (with decreasing
    /// heights).
    pub fn get_payloads_from_height(
        &self,
        start: Height,
        target: Block,
    ) -> Result<Vec<(Height, Time, Payload)>, UnexpectedChainLength> {
        let expected_len = range_len(start, target.height);
        let payloads = self
            .chain_iterator(target)
            .take_while(|block| block.height >= start)
            .map(|block| (block.height, block.context.time, block.payload))
            .collect::<Vec<_>>();
        let payloads_len = payloads.len();

        if payloads_len != expected_len {
            return Err(UnexpectedChainLength {
                expected: expected_len,
                returned: payloads_len,
            });
        }

        Ok(payloads)
    }

    /// Returns the parent of the given block if there exists one.
    pub fn get_parent(&self, child: &HashedBlock) -> Option<HashedBlock> {
        match child.height().cmp(&self.get_catch_up_height()) {
            Ordering::Greater => match self
                .get_block(&child.as_ref().parent, child.height().decrement())
            {
                Ok(block) => Some(block),
                Err(OnlyError::NoneAvailable) => None,
                Err(OnlyError::MultipleValues) => panic!("Multiple parents found for {child:?}"),
            },
            _ => None,
        }
    }

    /// Return a valid block with the matching hash and height if it exists.
    pub fn get_block(
        &self,
        hash: &CryptoHashOf<Block>,
        h: Height,
    ) -> Result<HashedBlock, OnlyError> {
        match h.cmp(&self.get_catch_up_height()) {
            Ordering::Less => Err(OnlyError::NoneAvailable),
            Ordering::Equal => {
                let cup = self.get_highest_catch_up_package();
                if cup.content.block.get_hash() != hash {
                    Err(OnlyError::NoneAvailable)
                } else {
                    Ok(cup.content.block)
                }
            }
            Ordering::Greater => {
                let mut blocks: Vec<BlockProposal> = self
                    .pool
                    .validated()
                    .block_proposal()
                    .get_by_height(h)
                    .filter(|x| x.content.get_hash() == hash)
                    .collect();
                match blocks.len() {
                    0 => Err(OnlyError::NoneAvailable),
                    1 => Ok(blocks.remove(0).content),
                    _ => Err(OnlyError::MultipleValues),
                }
            }
        }
    }

    /// Return a valid notarized block with the matching hash and height if it
    /// exists.
    pub fn get_notarized_block(
        &self,
        hash: &CryptoHashOf<Block>,
        h: Height,
    ) -> Result<HashedBlock, OnlyError> {
        self.get_block(hash, h).and_then(|block| {
            if h > self.get_catch_up_height() {
                if self
                    .pool
                    .validated()
                    .notarization()
                    .get_by_height(h)
                    .any(|x| &x.content.block == hash)
                {
                    Ok(block)
                } else {
                    Err(OnlyError::NoneAvailable)
                }
            } else {
                Ok(block)
            }
        })
    }

    /// Return the the first instant at which a block with the given hash was inserted
    /// into the consensus pool. Returns None if no timestamp was found.
    pub fn get_block_instant(&self, hash: &CryptoHashOf<Block>) -> Option<Instant> {
        self.pool.block_instant(hash)
    }

    /// Return the finalized block of a given height which is either the genesis
    /// (or CatchUpPackage) block, or the parent of another finalized block,
    /// or one with a valid finalization signature. Or return None if not
    /// found.
    pub fn get_finalized_block(&self, h: Height) -> Option<Block> {
        // Use a couple fast paths to speed up lookup
        match h.cmp(&self.get_catch_up_height()) {
            Ordering::Less => None,
            Ordering::Equal => Some(
                self.get_highest_catch_up_package()
                    .content
                    .block
                    .into_inner(),
            ),
            Ordering::Greater if h > self.get_finalized_height() => None,
            // If `h` is below or equal to the finalized height, we fetch
            // notarized blocks at this height.
            Ordering::Greater => {
                let mut iterator = self.get_notarized_blocks(h);
                match (iterator.next(), iterator.next()) {
                    (None, None) => panic!(
                        "No notarized blocks at height {h:?} found, which is below the finalization tip"
                    ),
                    // If we have exactly one notarized block, return it. This
                    // always works, because we know that we have validated
                    // blocks up to the finalized height, which means that the
                    // finalized chain up to the current finalized height is in
                    // the pool. Since there is only one block at this height,
                    // we know that this block must be a part of that finalized
                    // chain.
                    (Some(block), None) => Some(block.into_inner()),
                    // If we have multiple notarized blocks, create a finalization height range,
                    // starting from `h`, then get the next finalization above `h`, and walk the chain
                    // back to `h`.
                    _ => {
                        let height_range = HeightRange::new(
                            h,
                            self.pool
                                .validated()
                                .finalization()
                                .max_height()
                                .unwrap_or(h),
                        );
                        self.pool
                            .validated()
                            .finalization()
                            .get_by_height_range(height_range)
                            .next()
                            .and_then(|f| {
                                self.get_block(&f.content.block, f.content.height)
                                    .ok()
                                    .map(|block| block.into_inner())
                            })
                            .and_then(|block| self.follow_to_height(block, h))
                    }
                }
            }
        }
    }

    /// Return all valid notarized blocks of a given height.
    pub fn get_notarized_blocks(&'a self, h: Height) -> Box<dyn Iterator<Item = HashedBlock> + 'a> {
        match h.cmp(&self.get_catch_up_height()) {
            Ordering::Less => Box::new(std::iter::empty()),
            Ordering::Equal => Box::new(std::iter::once(
                self.get_highest_catch_up_package().content.block,
            )),
            Ordering::Greater => Box::new(
                self.pool
                    .validated()
                    .notarization()
                    .get_by_height(h)
                    .map(move |x| self.get_block(&x.content.block, h).unwrap()),
            ),
        }
    }

    /// Return all valid blocks at a given height.
    pub fn get_valid_blocks(&self, h: Height) -> Box<dyn Iterator<Item = Block> + 'a> {
        match h.cmp(&self.get_catch_up_height()) {
            Ordering::Less => Box::new(std::iter::empty()),
            Ordering::Equal => Box::new(std::iter::once(
                self.get_highest_catch_up_package()
                    .content
                    .block
                    .into_inner(),
            )),
            Ordering::Greater => Box::new(
                self.pool
                    .validated()
                    .block_proposal()
                    .get_by_height(h)
                    .map(|b| b.into()),
            ),
        }
    }

    /// Get the max height of all valid random beacons.
    pub fn get_random_beacon_height(&self) -> Height {
        let catch_up_height = self.get_catch_up_height();
        self.pool
            .validated()
            .random_beacon()
            .max_height()
            .unwrap_or(catch_up_height)
            .max(catch_up_height)
    }

    /// Get max height of valid notarized blocks. Note that this is different
    /// than the max height of valid notarization signatures, because the
    /// notarization signature may not exist at the height of CatchUpPackage
    /// or genesis.
    pub fn get_notarized_height(&self) -> Height {
        let catch_up_height = self.get_catch_up_height();
        self.pool
            .validated()
            .notarization()
            .max_height()
            .unwrap_or(catch_up_height)
            .max(catch_up_height)
    }

    /// Get max height of valid finalized blocks. Note that this is different
    /// than the max height of valid finalization signatures, because the
    /// finalization signature may not exist at the height of CatchUpPackage
    /// or genesis.
    pub fn get_finalized_height(&self) -> Height {
        self.get_finalized_tip().height()
    }

    /// Get the finalized block with greatest height.
    pub fn get_finalized_tip(&self) -> Block {
        self.cache.finalized_block()
    }

    /// Get the CatchUpPackage with greatest height.
    pub fn get_highest_catch_up_package(&self) -> CatchUpPackage {
        self.cache.catch_up_package()
    }

    /// Get the finalized DKG summary block with greatest height.
    pub fn get_highest_finalized_summary_block(&self) -> Block {
        self.cache.summary_block()
    }

    /// Get the height of highest CatchUpPackage.
    pub fn get_catch_up_height(&self) -> Height {
        self.get_highest_catch_up_package().height()
    }

    /// Get a valid random beacon at the given height if it exists. Note that we would also return
    /// the random beacons below the CUP height if they still exists. This should help slower
    /// nodes to deliver batches even if they have already received the new CUP. This helps because
    /// purging keeps a couple of heights below the latest CUP.
    pub fn get_random_beacon(&self, height: Height) -> Option<RandomBeacon> {
        if height == self.get_catch_up_height() {
            Some(
                self.get_highest_catch_up_package()
                    .content
                    .random_beacon
                    .as_ref()
                    .clone(),
            )
        } else {
            self.pool
                .validated()
                .random_beacon()
                .get_only_by_height(height)
                .ok()
        }
    }

    /// Get the random beacon with greatest height.
    pub fn get_random_beacon_tip(&self) -> RandomBeacon {
        let height = self.get_random_beacon_height();
        self.get_random_beacon(height)
            .unwrap_or_else(|| panic!("Can't find latest random beacon at height {height}"))
    }

    /// Get the round start time of a given height, which is the max timestamp
    /// of first notarization and random beacon of the previous height. Return
    /// `None` if no suitable artifact indicating a round start has been found.
    pub fn get_round_start_time(&self, height: Height) -> Option<Time> {
        let validated = self.pool.validated();
        let catch_up_height = self.get_catch_up_height();

        if height <= catch_up_height {
            return None;
        }

        let get_notarization_time = |h| {
            validated
                .notarization()
                .get_by_height(h)
                .flat_map(|x| validated.get_timestamp(&x.get_id()))
                .min()
        };

        let prev_height = height.decrement();
        // Here we stop early if random beacon time is not available, to avoid doing
        // a redundant lookup on notarizations.
        self.get_random_beacon(prev_height)
            .and_then(|x| validated.get_timestamp(&x.get_id()))
            .and_then(|random_beacon_time| {
                get_notarization_time(prev_height)
                    .map(|notarization_time| notarization_time.max(random_beacon_time))
            })
            .or_else(|| {
                // If notarization and random beacon have already been purged at
                // catch_up_height, we use the time of the CatchUpPackage instead.
                if prev_height == catch_up_height {
                    validated.get_timestamp(&self.get_highest_catch_up_package().get_id())
                } else {
                    None
                }
            })
    }

    /// Get the round start instant of a given height, which is the max instant
    /// of first notarization and random beacon of the previous height. If either
    /// of the messages don't have instants, we use the given fallback instance.
    /// Return `None` if no suitable artifact indicating a round start has been found.
    ///
    /// The reason we have a fallback for instants is because they are not persisted
    /// on disk, so we could lose instants when e.g. the replica restarts due to
    /// updates or crashes. We also don't collect instants in the uncached pool during
    /// genesis.
    pub fn get_round_start_instant(&self, height: Height, fallback: Instant) -> Option<Instant> {
        let validated = self.pool.validated();
        let catch_up_height = self.get_catch_up_height();

        if height <= catch_up_height {
            return None;
        }

        let get_notarization_instant = |h| {
            validated
                .notarization()
                .get_by_height(h)
                .map(|x| self.pool.message_instant(&x.get_id()).unwrap_or(fallback))
                .min()
        };

        let prev_height = height.decrement();
        // Here we stop early if random beacon time is not available, to avoid doing
        // a redundant lookup on notarizations.
        self.get_random_beacon(prev_height)
            .map(|x| self.pool.message_instant(&x.get_id()).unwrap_or(fallback))
            .and_then(|random_beacon_time| {
                get_notarization_instant(prev_height)
                    .map(|notarization_time| notarization_time.max(random_beacon_time))
            })
            .or_else(|| {
                // If notarization and random beacon have already been purged at
                // catch_up_height, we use the time of the CatchUpPackage instead.
                (prev_height == catch_up_height).then(|| {
                    self.pool
                        .message_instant(&self.get_highest_catch_up_package().get_id())
                        .unwrap_or(fallback)
                })
            })
    }

    /// Get all valid random beacon shares at the given height.
    pub fn get_random_beacon_shares(
        &self,
        h: Height,
    ) -> Box<dyn Iterator<Item = RandomBeaconShare>> {
        self.pool.validated().random_beacon_share().get_by_height(h)
    }

    /// Get all valid notarization shares at the given height.
    pub fn get_notarization_shares(
        &self,
        h: Height,
    ) -> Box<dyn Iterator<Item = NotarizationShare>> {
        self.pool.validated().notarization_share().get_by_height(h)
    }

    /// Get all valid finalization shares in the given height range, inclusive.
    pub fn get_finalization_shares(
        &self,
        from: Height,
        to: Height,
    ) -> Box<dyn Iterator<Item = FinalizationShare>> {
        self.pool
            .validated()
            .finalization_share()
            .get_by_height_range(HeightRange::new(from, to))
    }

    /// Get the valid random tape at the given height if it exists.
    pub fn get_random_tape(&self, h: Height) -> Option<RandomTape> {
        self.pool
            .validated()
            .random_tape()
            .get_only_by_height(h)
            .ok()
    }

    /// Get all valid random tape shares at the given height.
    pub fn get_random_tape_shares(
        &self,
        from: Height,
        to: Height,
    ) -> Box<dyn Iterator<Item = RandomTapeShare>> {
        self.pool
            .validated()
            .random_tape_share()
            .get_by_height_range(HeightRange::new(from, to))
    }

    /// Get all valid CatchUpPackageShares at the given height.
    pub fn get_catch_up_package_shares(
        &self,
        h: Height,
    ) -> Box<dyn Iterator<Item = CatchUpPackageShare>> {
        self.pool
            .validated()
            .catch_up_package_share()
            .get_by_height(h)
    }

    /// Get the underlying pool.
    pub fn pool(&self) -> &dyn ConsensusPool {
        self.pool
    }

    /// Returns the DKG summary block for the given *valid* block (which means
    /// it extends a notarized chain). Returns None if the DKG summary block
    /// cannot be found.
    pub fn dkg_summary_block(&self, block: &Block) -> Option<Block> {
        if block.payload.is_summary() {
            return Some(block.clone());
        }

        let summary_block = self.cache.summary_block();
        let start_height = block.payload.as_ref().dkg_interval_start_height();

        match summary_block.height().cmp(&start_height) {
            Ordering::Equal => {
                // Since block is extending a notarized chain, by our safety assumption it must
                // extend the finalized chain, so the finalized block in the cache is the
                // correct summary.
                Some(summary_block)
            }
            Ordering::Less => {
                // summary block is not finalized yet, so we search the chain for the summary
                // block
                self.chain_iterator(block.clone())
                    .find(|b| b.height == start_height)
            }
            Ordering::Greater => None,
        }
    }

    /// Returns the DKG summary block for the given *finalized* height. Returns None
    /// if the height isn't finalized, a higher CUP exists, or the DKG summary block
    /// cannot be found.
    pub fn dkg_summary_block_for_finalized_height(&self, height: Height) -> Option<Block> {
        let cup = self.cache.catch_up_package();
        if height < cup.height() || height > self.get_finalized_height() {
            return None;
        }

        let mut current_summary = Some(cup.content.block.into_inner());
        while let Some(block) = current_summary.as_ref() {
            let summary = block.payload.as_ref().as_summary();
            if summary.dkg.current_interval_includes(height) {
                return current_summary;
            }
            current_summary = self.get_finalized_block(summary.dkg.get_next_start_height());
        }
        None
    }

    /// Returns the height of the next CUP.
    pub fn get_next_cup_height(&self) -> Height {
        self.get_highest_catch_up_package()
            .content
            .block
            .as_ref()
            .payload
            .as_ref()
            .as_summary()
            .dkg
            .get_next_start_height()
    }
}

/// Take a slice returned by [`PoolReader::get_payloads_from_height`]
/// and return it in the [`PastPayload`] format that is used by the batch payload builders
///
/// The returned vector contains only the values for which the supplied closure `filter`
/// returns Some(value).
pub fn filter_past_payloads<'a, P>(
    input: &'a [(Height, Time, Payload)],
    filter: P,
) -> Vec<PastPayload<'a>>
where
    P: Fn(&'a Height, &'a Time, &'a Payload) -> Option<&'a [u8]>,
{
    input
        .iter()
        .filter_map(|(height, time, payload)| {
            filter(height, time, payload).map(|data| PastPayload {
                height: *height,
                time: *time,
                block_hash: payload.get_hash().clone(),
                payload: data,
            })
        })
        .collect()
}

#[cfg(test)]
pub mod test {
    use super::*;
    use ic_consensus_mocks::{Dependencies, dependencies, dependencies_with_subnet_params};
    use ic_interfaces_registry::RegistryClient;
    use ic_test_utilities_registry::{SubnetRecordBuilder, add_subnet_record};
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};

    #[test]
    fn test_get_dkg_summary_block() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let interval_length = 3;
            let Dependencies { mut pool, .. } = dependencies_with_subnet_params(
                pool_config,
                subnet_test_id(0),
                vec![(
                    1,
                    SubnetRecordBuilder::from(
                        (0..1).map(node_test_id).collect::<Vec<_>>().as_slice(),
                    )
                    .with_dkg_interval_length(interval_length)
                    .build(),
                )],
            );

            // Get the finalized block after skipping exactly one DKG interval.
            let height = pool.advance_round_normal_operation_n(interval_length + 1);
            assert_eq!(height, Height::from(interval_length).increment());
            let block = pool.get_cache().finalized_block();
            // This block is expected to be the summary of the next block, so we'll get it
            // back.
            assert!(block.payload.is_summary());
            let pool_reader = PoolReader::new(&pool);
            assert_eq!(Some(block.clone()), pool_reader.dkg_summary_block(&block));
            assert_eq!(
                Some(block.clone()),
                pool_reader.dkg_summary_block_for_finalized_height(block.height)
            );

            // Now, we'll capture the next block after the current summary block.
            pool.advance_round_normal_operation();
            let block2 = pool.get_cache().finalized_block();

            // Skip one DKG interval.
            pool.advance_round_normal_operation_n(interval_length);
            let pool_reader = PoolReader::new(&pool);
            // Make sure we do not get summaries for too old blocks.
            assert_eq!(None, pool_reader.dkg_summary_block(&block2));
            assert_eq!(
                None,
                pool_reader.dkg_summary_block_for_finalized_height(block2.height)
            );

            // Get the new summary block and make sure it's a summary.
            let block3 = pool.get_cache().finalized_block();
            assert!(block3.payload.is_summary());
            // Advance the pool, but stay within the current DKG interval.
            pool.advance_round_normal_operation_n(interval_length - 1);
            let block4 = pool.get_cache().finalized_block();
            // Make sure block4 points to the latest summary.
            let pool_reader = PoolReader::new(&pool);
            assert_eq!(Some(block3.clone()), pool_reader.dkg_summary_block(&block4));
            assert_eq!(
                Some(block3.clone()),
                pool_reader.dkg_summary_block_for_finalized_height(block4.height)
            );

            // Advance the pool into the next interval, but don't create a CUP yet.
            pool.advance_round_normal_operation_no_cup_n(interval_length + 1);
            let block5 = pool.get_cache().finalized_block();
            // A summary block higher than block4 exists. While `dkg_summary_block` should return `None`,
            // `dkg_summary_block_for_finalized_height` should continue to return block3.
            let pool_reader = PoolReader::new(&pool);
            assert_eq!(None, pool_reader.dkg_summary_block(&block4));
            assert_eq!(
                Some(block3),
                pool_reader.dkg_summary_block_for_finalized_height(block4.height)
            );
            // The summary of block5 should be the highest summary block eventhough no CUP was created at that height.
            let summary = pool_reader.get_highest_finalized_summary_block();
            assert_eq!(
                Some(summary.clone()),
                pool_reader.dkg_summary_block(&block5)
            );
            assert_eq!(
                Some(summary),
                pool_reader.dkg_summary_block_for_finalized_height(block5.height)
            );

            // `dkg_summary_block_for_finalized_height` should return none for blocks below a CUP and non-finalized blocks.
            assert_eq!(
                None,
                pool_reader.dkg_summary_block_for_finalized_height(
                    pool_reader.get_finalized_height().increment()
                )
            );
            assert_eq!(
                None,
                pool_reader.dkg_summary_block_for_finalized_height(
                    pool_reader.get_catch_up_height().decrement()
                )
            );
        })
    }

    #[test]
    fn test_get_finalized_block_at_height_without_finalization() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let Dependencies { mut pool, .. } = dependencies(pool_config, 1);
            let start = pool.make_next_block();
            pool.insert_beacon_chain(&pool.make_next_beacon(), Height::from(10));
            pool.insert_block_chain_with(start.clone(), Height::from(10));
            let ten_block = pool
                .validated()
                .block_proposal()
                .get_only_by_height(Height::from(10))
                .unwrap();
            pool.finalize(&ten_block);

            let pool_reader = PoolReader::new(&pool);
            pool_reader
                .get_finalized_block(Height::from(10))
                .expect("Can't find finalized block at 10");
            assert_eq!(
                &pool_reader.get_finalized_block(Height::from(1)).unwrap(),
                start.as_ref()
            );
        })
    }

    #[test]
    fn test_get_notarized_finalized_height() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let committee = vec![node_test_id(0)];
            let interval_length = 4;
            let Dependencies { mut pool, .. } = dependencies_with_subnet_params(
                pool_config,
                subnet_test_id(0),
                vec![(
                    1,
                    SubnetRecordBuilder::from(&committee)
                        .with_dkg_interval_length(interval_length)
                        .build(),
                )],
            );
            pool.advance_round_normal_operation_n(4);
            pool.prepare_round().dont_add_catch_up_package().advance();
            let block = pool.latest_notarized_blocks().next().unwrap();
            pool.finalize_block(&block);
            let notarization = pool.validated().notarization().get_highest().unwrap();
            let catch_up_package = pool.make_catch_up_package(notarization.height());
            pool.insert_validated(catch_up_package);
            pool.purge_validated_below(notarization);
            let pool_reader = PoolReader::new(&pool);
            // notarized/finalized height are still 3, same as catchup height
            assert_eq!(pool_reader.get_notarized_height(), Height::from(5));
            assert_eq!(pool_reader.get_finalized_height(), Height::from(5));
            assert_eq!(pool_reader.get_catch_up_height(), Height::from(5));
        })
    }

    #[test]
    // Tests that both the in-memory and the persisted pool return artifacts
    // sorted in ascending order.
    fn test_get_by_height_range() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let rounds = 30;
            let replicas = 10;
            let f = 3;
            let block_proposals_per_round = f + 1;
            let Dependencies { mut pool, .. } = dependencies(pool_config, replicas);

            // Because `TestConsensusPool::advance_round` alternates between
            // putting blocks in validated and unvalidated pools for each rank,
            // we expect `block_proposals_per_round`/2 blocks in the unvalidated pool per round.
            let mut round = pool
                .prepare_round()
                .with_replicas(replicas as u32)
                .with_new_block_proposals(block_proposals_per_round)
                .with_random_beacon_shares(replicas as u32)
                .with_notarization_shares(replicas as u32)
                .with_finalization_shares(replicas as u32);
            // Grow the artifact pool for `rounds`.
            for _ in 0..rounds {
                round.advance();
            }
            let artifacts = pool
                .validated()
                .finalization()
                .get_by_height_range(HeightRange::new(Height::from(0), Height::from(100)))
                .collect::<Vec<_>>();
            // We expect to see `rounds` new finalizations sorted by height in
            // ascending order.
            assert_eq!(artifacts.len(), rounds);
            for i in 0..artifacts.len() - 1 {
                // All heights are expected to be unique, because we have exactly
                // one finalization per round.
                assert!(artifacts[i].content.height < artifacts[i + 1].content.height);
            }
            let artifacts = pool
                .unvalidated()
                .block_proposal()
                .get_by_height_range(HeightRange::new(
                    Height::from(0),
                    Height::from((rounds * 2) as u64),
                ))
                .collect::<Vec<_>>();
            // We expect to see `rounds * (block_proposals_per_round/2)` unvalidated block proposals sorted by
            // height in ascending order.
            assert_eq!(
                artifacts.len(),
                rounds * ((block_proposals_per_round as usize) / 2)
            );
            for i in 0..artifacts.len() - 1 {
                // Heights are ascending, but NOT unique.
                assert!(artifacts[i].content.height() <= artifacts[i + 1].content.height());
            }
        })
    }

    #[test]
    fn test_registry_version() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            let interval_length = 3;
            let total_length = interval_length + 1; // account for the summary block
            let record = SubnetRecordBuilder::from(&[node_test_id(0)])
                .with_dkg_interval_length(interval_length)
                .build();
            let Dependencies {
                mut pool,
                registry_data_provider,
                registry,
                replica_config,
                ..
            } = dependencies_with_subnet_params(
                pool_config,
                subnet_test_id(0),
                vec![(1, record.clone())],
            );
            let subnet_id = replica_config.subnet_id;
            let pool_reader = PoolReader::new(&pool);
            // Right now we only have the genesis block. For the genesis interval and the
            // interval behind it, we will use the RegistryVersion = 1, as it is
            // currently used in genesis generation inside the summary and
            // inside the block validation context.
            for h in 0..(2 * total_length) {
                assert_eq!(
                    pool_reader.registry_version(Height::from(h)).unwrap(),
                    RegistryVersion::from(1)
                );
            }

            // However the height outside of the next interval, is not going to
            // work.
            assert!(
                pool_reader
                    .registry_version(Height::from(2 * total_length + 1))
                    .is_none()
            );

            // Let's advance the pool for one round, update the registry,
            // and advance the pool till the next DKG start.
            pool.advance_round_normal_operation();

            // Before we update the registry, make sure we agree on the latest version.
            assert_eq!(registry.get_latest_version(), RegistryVersion::from(1),);

            // We update the registry and expect, that the validation context of the next
            // dkg summary will pick it up.
            add_subnet_record(&registry_data_provider, 2, subnet_id, record.clone());
            registry.update_to_latest_version();

            // Make sure changes were picked up.
            assert_eq!(registry.get_latest_version(), RegistryVersion::from(2),);

            pool.advance_round_normal_operation_n(total_length);

            // Now the the next summary block should pick up the next version in its context
            // validation.

            // Advance the pool to the start of the third interval and upgrade the registry
            // in between.
            pool.advance_round_normal_operation();
            add_subnet_record(&registry_data_provider, 3, subnet_id, record);
            registry.update_to_latest_version();
            pool.advance_round_normal_operation_n(total_length);

            // Now all heights, abobe the 3rd DKG round should use registry version 2
            let pool_reader = PoolReader::new(&pool);
            for h in (2 * total_length)..(3 * total_length) {
                assert_eq!(
                    pool_reader.registry_version(Height::from(h)).unwrap(),
                    RegistryVersion::from(2),
                );
            }

            // In the forth interval, we would see the version 3
            for h in (3 * total_length)..(4 * total_length) {
                assert_eq!(
                    pool_reader.registry_version(Height::from(h)).unwrap(),
                    RegistryVersion::from(3),
                );
            }

            // For the height from the 4th round there is no version.
            assert!(
                pool_reader
                    .registry_version(Height::from(4 * total_length + 1))
                    .is_none()
            );

            // However, all old versions are not available as they are below the latest CUP.
            for h in 0..(2 * total_length) {
                assert!(pool_reader.registry_version(Height::from(h)).is_none(),);
            }
        })
    }
}
