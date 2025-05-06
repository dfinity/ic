use crate::consensus_pool::{
    ConsensusBlockCache, ConsensusPool, ConsensusPoolCache, HeightRange, OnlyError,
};
use ic_types::{
    consensus::{
        Block, BlockProposal, CatchUpPackage, CatchUpPackageShare, ConsensusMessageHashable,
        FinalizationShare, HasHeight, HashedBlock, NotarizationShare, Payload, RandomBeacon,
        RandomBeaconShare, RandomTape, RandomTapeShare,
    },
    crypto::CryptoHashOf,
    Height, RegistryVersion, Time,
};
use std::{cmp::Ordering, time::Instant};

pub trait PoolReader<'a> {
    /// Return a ConsensusPoolCache reference.
    fn as_cache(&self) -> &dyn ConsensusPoolCache;

    /// Return a ConsensusBlockCache reference.
    fn as_block_cache(&self) -> &dyn ConsensusBlockCache;

    /// Get the underlying pool.
    fn pool(&self) -> &dyn ConsensusPool;

    /// Return the registry version to be used for the given height.
    /// Note that this can only look up for height that is greater than or equal
    /// to the latest catch-up package height, otherwise an error is returned.
    fn registry_version(&self, height: Height) -> Option<RegistryVersion>;

    /// Follow `block`'s ancestors until a block with `height` is found.
    fn follow_to_height(&'a self, block: Block, height: Height) -> Option<Block> {
        self.chain_iterator(block)
            .take_while(|block| block.height >= height)
            .last()
            .filter(|block| block.height == height)
    }

    /// Find ancestor blocks of `block`, and return an iterator that starts
    /// from `block` and ends when a parent is not found (e.g. genesis).
    fn chain_iterator(&'a self, block: Block) -> Box<dyn Iterator<Item = Block> + 'a> {
        self.as_cache().chain_iterator(self.pool(), block)
    }

    /// Get the range of ancestor blocks of `block` specified (inclusively) by
    /// `min` and `max`. This assumes the correctness of the state of the pool.
    fn get_range(
        &'a self,
        block: Block,
        min: Height,
        max: Height,
    ) -> impl Iterator<Item = Block> + 'a {
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
    fn get_payloads_from_height(
        &'a self,
        start: Height,
        target: Block,
    ) -> Vec<(Height, Time, Payload)> {
        self.chain_iterator(target)
            .take_while(|block| block.height >= start)
            .map(|block| (block.height, block.context.time, block.payload))
            .collect()
    }

    /// Returns the parent of the given block if there exists one.
    fn get_parent(&self, child: &HashedBlock) -> Option<HashedBlock> {
        match child.height().cmp(&self.get_catch_up_height()) {
            Ordering::Greater => match self
                .get_block(&child.as_ref().parent, child.height().decrement())
            {
                Ok(block) => Some(block),
                Err(OnlyError::NoneAvailable) => None,
                Err(OnlyError::MultipleValues) => panic!("Multiple parents found for {:?}", child),
            },
            _ => None,
        }
    }

    /// Return a valid block with the matching hash and height if it exists.
    fn get_block(&self, hash: &CryptoHashOf<Block>, h: Height) -> Result<HashedBlock, OnlyError> {
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
                    .pool()
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
    fn get_notarized_block(
        &self,
        hash: &CryptoHashOf<Block>,
        h: Height,
    ) -> Result<HashedBlock, OnlyError> {
        self.get_block(hash, h).and_then(|block| {
            if h > self.get_catch_up_height() {
                if self
                    .pool()
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
    fn get_block_instant(&self, hash: &CryptoHashOf<Block>) -> Option<Instant> {
        self.pool().block_instant(hash)
    }

    /// Return the finalized block of a given height which is either the genesis
    /// (or CatchUpPackage) block, or the parent of another finalized block,
    /// or one with a valid finalization signature. Or return None if not
    /// found.
    fn get_finalized_block(&'a self, h: Height) -> Option<Block> {
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
                        "No notarized blocks at height {:?} found, which is below the finalization tip",
                        h
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
                            self.pool()
                            .validated()
                            .finalization()
                            .max_height()
                            .unwrap_or(h),
                        );
                        self.pool()
                            .validated()
                            .finalization()
                            .get_by_height_range(height_range)
                            .next()
                            .and_then(|f| self.get_block(&f.content.block, f.content.height).ok().map(|block| block.into_inner()))
                            .and_then(|block| self.follow_to_height(block, h))
                    }
                }
            }
        }
    }

    /// Return all valid notarized blocks of a given height.
    fn get_notarized_blocks(&'a self, h: Height) -> Box<dyn Iterator<Item = HashedBlock> + 'a> {
        match h.cmp(&self.get_catch_up_height()) {
            Ordering::Less => Box::new(std::iter::empty()),
            Ordering::Equal => Box::new(std::iter::once(
                self.get_highest_catch_up_package().content.block,
            )),
            Ordering::Greater => Box::new(
                self.pool()
                    .validated()
                    .notarization()
                    .get_by_height(h)
                    .map(move |x| self.get_block(&x.content.block, h).unwrap()),
            ),
        }
    }

    /// Return all valid blocks at a given height.
    fn get_valid_blocks(&self, h: Height) -> Box<dyn Iterator<Item = Block> + 'a> {
        match h.cmp(&self.get_catch_up_height()) {
            Ordering::Less => Box::new(std::iter::empty()),
            Ordering::Equal => Box::new(std::iter::once(
                self.get_highest_catch_up_package()
                    .content
                    .block
                    .into_inner(),
            )),
            Ordering::Greater => Box::new(
                self.pool()
                    .validated()
                    .block_proposal()
                    .get_by_height(h)
                    .map(|b| b.into()),
            ),
        }
    }

    /// Get the max height of all valid random beacons.
    fn get_random_beacon_height(&self) -> Height {
        let catch_up_height = self.get_catch_up_height();
        self.pool()
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
    fn get_notarized_height(&self) -> Height {
        let catch_up_height = self.get_catch_up_height();
        self.pool()
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
    fn get_finalized_height(&self) -> Height {
        self.get_finalized_tip().height()
    }

    /// Get the finalized block with greatest height.
    fn get_finalized_tip(&self) -> Block {
        self.as_cache().finalized_block()
    }

    /// Get the CatchUpPackage with greatest height.
    fn get_highest_catch_up_package(&self) -> CatchUpPackage {
        self.as_cache().catch_up_package()
    }

    /// Get the finalized DKG summary block with greatest height.
    fn get_highest_finalized_summary_block(&self) -> Block {
        self.as_cache().summary_block()
    }

    /// Get the height of highest CatchUpPackage.
    fn get_catch_up_height(&self) -> Height {
        self.get_highest_catch_up_package().height()
    }

    /// Get a valid random beacon at the given height if it exists. Note that we would also return
    /// the random beacons below the CUP height if they still exists. This should help slower
    /// nodes to deliver batches even if they have already received the new CUP. This helps because
    /// purging keeps a couple of heights below the latest CUP.
    fn get_random_beacon(&self, height: Height) -> Option<RandomBeacon> {
        if height == self.get_catch_up_height() {
            Some(
                self.get_highest_catch_up_package()
                    .content
                    .random_beacon
                    .as_ref()
                    .clone(),
            )
        } else {
            self.pool()
                .validated()
                .random_beacon()
                .get_only_by_height(height)
                .ok()
        }
    }

    /// Get the random beacon with greatest height.
    fn get_random_beacon_tip(&self) -> RandomBeacon {
        let height = self.get_random_beacon_height();
        self.get_random_beacon(height)
            .unwrap_or_else(|| panic!("Can't find latest random beacon at height {}", height))
    }

    /// Get the round start time of a given height, which is the max timestamp
    /// of first notarization and random beacon of the previous height. Return
    /// `None` if no suitable artifact indicating a round start has been found.
    fn get_round_start_time(&self, height: Height) -> Option<Time> {
        let validated = self.pool().validated();
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
    fn get_round_start_instant(&self, height: Height, fallback: Instant) -> Option<Instant> {
        let validated = self.pool().validated();
        let catch_up_height = self.get_catch_up_height();

        if height <= catch_up_height {
            return None;
        }

        let get_notarization_instant = |h| {
            validated
                .notarization()
                .get_by_height(h)
                .map(|x| self.pool().message_instant(&x.get_id()).unwrap_or(fallback))
                .min()
        };

        let prev_height = height.decrement();
        // Here we stop early if random beacon time is not available, to avoid doing
        // a redundant lookup on notarizations.
        self.get_random_beacon(prev_height)
            .map(|x| self.pool().message_instant(&x.get_id()).unwrap_or(fallback))
            .and_then(|random_beacon_time| {
                get_notarization_instant(prev_height)
                    .map(|notarization_time| notarization_time.max(random_beacon_time))
            })
            .or_else(|| {
                // If notarization and random beacon have already been purged at
                // catch_up_height, we use the time of the CatchUpPackage instead.
                (prev_height == catch_up_height).then(|| {
                    self.pool()
                        .message_instant(&self.get_highest_catch_up_package().get_id())
                        .unwrap_or(fallback)
                })
            })
    }

    /// Get all valid random beacon shares at the given height.
    fn get_random_beacon_shares(&self, h: Height) -> Box<dyn Iterator<Item = RandomBeaconShare>> {
        self.pool()
            .validated()
            .random_beacon_share()
            .get_by_height(h)
    }

    /// Get all valid notarization shares at the given height.
    fn get_notarization_shares(&self, h: Height) -> Box<dyn Iterator<Item = NotarizationShare>> {
        self.pool()
            .validated()
            .notarization_share()
            .get_by_height(h)
    }

    /// Get all valid finalization shares in the given height range, inclusive.
    fn get_finalization_shares(
        &self,
        from: Height,
        to: Height,
    ) -> Box<dyn Iterator<Item = FinalizationShare>> {
        self.pool()
            .validated()
            .finalization_share()
            .get_by_height_range(HeightRange::new(from, to))
    }

    /// Get the valid random tape at the given height if it exists.
    fn get_random_tape(&self, h: Height) -> Option<RandomTape> {
        self.pool()
            .validated()
            .random_tape()
            .get_only_by_height(h)
            .ok()
    }

    /// Get all valid random tape shares at the given height.
    fn get_random_tape_shares(
        &self,
        from: Height,
        to: Height,
    ) -> Box<dyn Iterator<Item = RandomTapeShare>> {
        self.pool()
            .validated()
            .random_tape_share()
            .get_by_height_range(HeightRange::new(from, to))
    }

    /// Get all valid CatchUpPackageShares at the given height.
    fn get_catch_up_package_shares(
        &self,
        h: Height,
    ) -> Box<dyn Iterator<Item = CatchUpPackageShare>> {
        self.pool()
            .validated()
            .catch_up_package_share()
            .get_by_height(h)
    }

    /// Returns the DKG summary block for the given *valid* block (which means
    /// it extends a notarized chain). Returns None if the DKG summary block
    /// cannot be found.
    fn dkg_summary_block(&'a self, block: &Block) -> Option<Block> {
        if block.payload.is_summary() {
            return Some(block.clone());
        }

        let summary_block = self.as_cache().summary_block();
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
    fn dkg_summary_block_for_finalized_height(&'a self, height: Height) -> Option<Block> {
        let cup = self.as_cache().catch_up_package();
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
    fn get_next_cup_height(&self) -> Height {
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
