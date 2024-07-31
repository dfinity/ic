use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::Arc;

use core::ops::Deref;
use std::time::Instant;

use ic_ledger_core::block::{BlockIndex, BlockType, EncodedBlock};
use ic_ledger_hash_of::HashOf;
use icp_ledger::{Block, TipOfChainRes};
use tokio::sync::RwLock;
use tracing::{debug, error, info, trace, warn};

use crate::blocks::BlockStoreError;
use crate::blocks::{Blocks, HashedBlock};
use crate::blocks_access::BlocksAccess;
use crate::certification::{verify_block_hash, VerificationInfo};
use crate::errors::Error;

// If pruning is enabled, instead of pruning after each new block
// we'll wait for PRUNE_DELAY blocks to accumulate and prune them in one go
const PRUNE_DELAY: u64 = 100000;

const PRINT_SYNC_PROGRESS_THRESHOLD: u64 = 1000;

const DATABASE_WRITE_BLOCKS_BATCH_SIZE: u64 = 500000;
// Max number of retry in case of query failure while retrieving blocks.
const MAX_RETRY: u8 = 5;

struct BlockWithIndex {
    block: Block,
    index: BlockIndex,
}

/// The LedgerBlocksSynchronizer will use this to output the metrics while
/// synchronizing with the Ledger
pub trait LedgerBlocksSynchronizerMetrics {
    fn set_target_height(&self, height: u64);
    fn set_synced_height(&self, height: u64);
    fn set_verified_height(&self, height: u64);
}

/// Downloads the blocks of the Ledger to either an in-memory store or to
/// a local sqlite store
pub struct LedgerBlocksSynchronizer<B>
where
    B: BlocksAccess,
{
    pub blockchain: RwLock<Blocks>,
    blocks_access: Option<Arc<B>>,
    // TODO: move store_max_blocks in sync or move up_to_block here
    store_max_blocks: Option<u64>,
    verification_info: Option<VerificationInfo>,
    metrics: Box<dyn LedgerBlocksSynchronizerMetrics + Send + Sync>,
}

impl<B: BlocksAccess> LedgerBlocksSynchronizer<B> {
    pub async fn new(
        blocks_access: Option<Arc<B>>,
        store_location: Option<&std::path::Path>,
        store_max_blocks: Option<u64>,
        verification_info: Option<VerificationInfo>,
        metrics: Box<dyn LedgerBlocksSynchronizerMetrics + Send + Sync>,
        enable_rosetta_blocks: bool,
    ) -> Result<LedgerBlocksSynchronizer<B>, Error> {
        let mut blocks = match store_location {
            Some(loc) => Blocks::new_persistent(loc, enable_rosetta_blocks)?,
            None => Blocks::new_in_memory(enable_rosetta_blocks)?,
        };

        if let Some(blocks_access) = &blocks_access {
            Self::verify_store(&blocks, blocks_access).await?;
            if let Some(verification_info) = &verification_info {
                // verify if we have the right certificate/we are connecting to the right
                // canister
                Self::verify_tip_of_chain(blocks_access, verification_info).await?;
            }
        }

        info!("Loading blocks from store");
        let first_block = blocks.get_first_hashed_block();
        let last_block = blocks.get_latest_hashed_block();
        if let (Ok(first), Ok(last)) = (&first_block, &last_block) {
            info!(
                "Ledger client is up. Loaded {} blocks from store. First block at {}, last at {}",
                (last.index - first.index).to_string(),
                first.index.to_string(),
                last.index.to_string()
            );
        } else {
            info!(
                "Ledger client is up. Loaded {} blocks from store. First block at {}, last at {}",
                0, "None", "None"
            );
        }

        if let Ok(x) = last_block {
            metrics.set_synced_height(x.index);
        }
        if let Ok(x) = blocks.get_latest_verified_hashed_block() {
            metrics.set_verified_height(x.index);
        }

        blocks.try_prune(&store_max_blocks, PRUNE_DELAY)?;

        Ok(Self {
            blockchain: RwLock::new(blocks),
            blocks_access,
            store_max_blocks,
            verification_info,
            metrics,
        })
    }

    async fn verify_store(blocks: &Blocks, canister_access: &B) -> Result<(), Error> {
        debug!("Verifying store...");
        let first_block = blocks.get_first_hashed_block().ok();
        match blocks.get_hashed_block(&0) {
            Ok(store_genesis) => {
                let genesis = canister_access
                    .query_raw_block(0)
                    .await
                    .map_err(Error::InternalError)?
                    .expect("Blockchain in the ledger canister is empty");

                if store_genesis.hash != Block::block_hash(&genesis) {
                    let msg = format!(
                        "Genesis block from the store is different than \
                        in the ledger canister. Store hash: {}, canister hash: {}",
                        store_genesis.hash,
                        Block::block_hash(&genesis)
                    );
                    error!("{}", msg);
                    return Err(Error::InternalError(msg));
                }
            }
            Err(BlockStoreError::NotFound(0)) => {
                if first_block.is_some() {
                    let msg = "Snapshot found, but genesis block not present in the store";
                    error!("{}", msg);
                    return Err(Error::InternalError(msg.to_string()));
                }
            }
            Err(e) => {
                let msg = format!("Error loading genesis block: {:?}", e);
                error!("{}", msg);
                return Err(Error::InternalError(msg));
            }
        }

        // https://github.com/rust-lang/rust-clippy/issues/4530
        #[allow(clippy::unnecessary_unwrap)]
        if first_block.is_some() && first_block.as_ref().unwrap().index > 0 {
            let first_block = first_block.unwrap();
            let queried_block = canister_access
                .query_raw_block(first_block.index)
                .await
                .map_err(Error::InternalError)?;
            if queried_block.is_none() {
                let msg = format!(
                    "Oldest block snapshot does not match the block on \
                    the blockchain. Block with this index not found: {}",
                    first_block.index
                );
                error!("{}", msg);
                return Err(Error::InternalError(msg));
            }
            let queried_block = queried_block.unwrap();
            if first_block.hash != Block::block_hash(&queried_block) {
                let msg = format!(
                    "Oldest block snapshot does not match the block on \
                    the blockchain. Index: {}, snapshot hash: {}, canister hash: {}",
                    first_block.index,
                    first_block.hash,
                    Block::block_hash(&queried_block)
                );
                error!("{}", msg);
                return Err(Error::InternalError(msg));
            }
        }

        debug!("Verifying store done");
        Ok(())
    }

    async fn verify_tip_of_chain(
        canister_access: &B,
        verification_info: &VerificationInfo,
    ) -> Result<(), Error> {
        let TipOfChainRes {
            tip_index,
            certification,
        } = canister_access
            .query_tip()
            .await
            .map_err(Error::InternalError)?;
        let tip_block = canister_access
            .query_raw_block(tip_index)
            .await
            .map_err(Error::InternalError)?
            .expect("Blockchain in the ledger canister is empty");
        verify_block_hash(
            &certification,
            Block::block_hash(&tip_block),
            verification_info,
        )
        .map_err(Error::InternalError)?;
        Ok(())
    }

    pub async fn read_blocks(&self) -> Box<dyn Deref<Target = Blocks> + '_> {
        Box::new(self.blockchain.read().await)
    }

    /// Return the tip of the chain with its index or error if the tip cannot be verified
    ///
    /// Note that self.verification_info must be set in order to verify the tip. If it's
    /// not set then this method will return the tip without verifying it.
    async fn query_verified_tip(&self) -> Result<BlockWithIndex, String> {
        let canister = self.blocks_access.as_ref().unwrap();
        let TipOfChainRes {
            tip_index,
            certification,
        } = canister.query_tip().await?;
        let encoded_block = canister.query_raw_block(tip_index).await?.ok_or(format!(
            "Tip of the chain has index {} but no block found at that index!",
            tip_index
        ))?;
        let block = Block::decode(encoded_block.clone())?;
        if let Some(info) = &self.verification_info {
            let hash = HashedBlock::hash_block(
                encoded_block,
                block.parent_hash,
                tip_index,
                block.timestamp,
            )
            .hash;
            verify_block_hash(&certification, hash, info)?;
        }
        Ok(BlockWithIndex {
            block,
            index: tip_index,
        })
    }

    pub async fn sync_blocks(
        &self,
        stopped: Arc<AtomicBool>,
        up_to_block_included: Option<BlockIndex>,
    ) -> Result<(), Error> {
        let tip = self
            .query_verified_tip()
            .await
            .map_err(Error::InternalError)?;
        if tip.index == u64::MAX {
            error!("Bogus value of tip index: {}", tip.index);
            return Err(Error::InternalError(
                "Received tip_index == u64::MAX".to_string(),
            ));
        }
        self.metrics.set_target_height(tip.index);

        let mut blockchain = self.blockchain.write().await;

        let latest_hb_opt = blockchain.get_latest_hashed_block();
        let (last_block_hash, next_block_index) = match latest_hb_opt {
            Ok(hb) => (Some(hb.hash), hb.index + 1),
            Err(_) => (None, 0),
        };

        if next_block_index == tip.index + 1 {
            return Ok(());
        }
        if next_block_index > tip.index + 1 {
            trace!(
                "Tip received from the Ledger is lower than what we already have (queried lagging replica?),
                Ledger tip index: {}, local copy tip index+1: {}",
                tip.index,
                next_block_index
            );
            return Ok(());
        }

        let up_to_block_included = tip.index.min(up_to_block_included.unwrap_or(u64::MAX - 1));

        if next_block_index > up_to_block_included {
            return Ok(()); // nothing to do nor report, local copy has enough blocks
        }

        trace!(
            "Sync {} blocks from index: {}, ledger tip index: {}",
            up_to_block_included + 1 - next_block_index,
            next_block_index,
            tip.index
        );

        let tip_index = tip.index;

        self.sync_range_of_blocks(
            Range {
                start: next_block_index,
                end: up_to_block_included + 1,
            },
            last_block_hash,
            stopped,
            tip,
            &mut blockchain,
        )
        .await?;

        blockchain.make_rosetta_blocks_if_enabled(tip_index)?;

        info!(
            "You are all caught up to block {}",
            blockchain.get_latest_hashed_block()?.index
        );

        blockchain
            .try_prune(&self.store_max_blocks, PRUNE_DELAY)
            .map_err(|_| Error::InternalError("Failed to prune store".to_string()))
    }

    async fn sync_range_of_blocks(
        &self,
        range: Range<BlockIndex>,
        first_block_parent_hash: Option<HashOf<EncodedBlock>>,
        stopped: Arc<AtomicBool>,
        tip: BlockWithIndex,
        blockchain: &mut Blocks,
    ) -> Result<(), Error> {
        let t_total = Instant::now();
        if range.is_empty() {
            return Ok(());
        }
        let print_progress = if range.end - range.start >= PRINT_SYNC_PROGRESS_THRESHOLD {
            info!(
                "Syncing {} blocks. New tip will be {}",
                range.end - range.start,
                range.end - 1,
            );
            true
        } else {
            false
        };

        let canister = self.blocks_access.as_ref().unwrap();
        let mut i = range.start;
        let mut last_block_hash = first_block_parent_hash;
        let mut block_batch: Vec<HashedBlock> = Vec::new();
        while i < range.end {
            if stopped.load(Relaxed) {
                return Err(Error::InternalError("Interrupted".to_string()));
            }

            debug!("Asking for blocks [{},{})", i, range.end);
            let retry = 0;
            let batch = loop {
                let batch = canister
                    .clone()
                    .multi_query_blocks(Range {
                        start: i,
                        end: range.end,
                    })
                    .await
                    .map_err(Error::InternalError);
                if batch.is_ok() || retry == MAX_RETRY {
                    break batch;
                }
                let retry = retry + 1;
                warn!(
                    "Failed query while retrieving blocks, retry {}/{} (error: {:?})",
                    retry,
                    MAX_RETRY,
                    batch.unwrap_err()
                );
            }?;

            debug!("Got batch of len: {}", batch.len());
            if batch.is_empty() {
                return Err(Error::InternalError(format!(
                    "Couldn't fetch blocks [{},{}) (batch result empty)",
                    i, range.end
                )));
            }
            for raw_block in batch {
                let block = Block::decode(raw_block.clone())
                    .map_err(|err| Error::InternalError(format!("Cannot decode block: {}", err)))?;
                if block.parent_hash != last_block_hash {
                    let err_msg = format!(
                        "Block at {}: parent hash mismatch. Expected: {:?}, got: {:?}",
                        i, last_block_hash, block.parent_hash
                    );
                    error!("{}", err_msg);
                    return Err(Error::InternalError(err_msg));
                }
                if i == tip.index && block != tip.block {
                    return Err(Error::invalid_tip_of_chain(tip.index, tip.block, block));
                }
                let hb = HashedBlock::hash_block(raw_block, last_block_hash, i, block.timestamp);
                last_block_hash = Some(hb.hash);
                block_batch.push(hb);
                i += 1;
            }
            self.metrics.set_synced_height(i - 1);
            if (i - range.start) % DATABASE_WRITE_BLOCKS_BATCH_SIZE == 0 {
                blockchain.push_batch(block_batch)?;
                if print_progress {
                    info!("Synced up to {}", i - 1);
                }
                block_batch = Vec::new();
            }
        }
        blockchain.push_batch(block_batch)?;
        info!("Synced took {} seconds", t_total.elapsed().as_secs_f64());
        blockchain.set_hashed_block_to_verified(&(range.end - 1))?;
        self.metrics.set_verified_height(range.end - 1);
        Ok(())
    }
}

#[cfg(test)]
mod test {

    use std::ops::Range;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    use async_trait::async_trait;
    use ic_ledger_core::block::{BlockType, EncodedBlock};
    use ic_ledger_core::timestamp::TimeStamp;
    use ic_ledger_core::Tokens;
    use ic_ledger_hash_of::HashOf;
    use ic_types::PrincipalId;
    use icp_ledger::{
        AccountIdentifier, Block, BlockIndex, Memo, TipOfChainRes, DEFAULT_TRANSFER_FEE,
    };

    use crate::blocks_access::BlocksAccess;
    use crate::ledger_blocks_sync::LedgerBlocksSynchronizer;

    use super::LedgerBlocksSynchronizerMetrics;

    struct NopMetrics {}

    impl LedgerBlocksSynchronizerMetrics for NopMetrics {
        fn set_target_height(&self, _height: u64) {}
        fn set_synced_height(&self, _height: u64) {}
        fn set_verified_height(&self, _height: u64) {}
    }

    struct RangeOfBlocks {
        pub blocks: Vec<EncodedBlock>,
    }

    impl RangeOfBlocks {
        pub fn new(blocks: Vec<EncodedBlock>) -> Self {
            Self { blocks }
        }
    }

    #[async_trait]
    impl BlocksAccess for RangeOfBlocks {
        async fn query_raw_block(
            &self,
            height: BlockIndex,
        ) -> Result<Option<EncodedBlock>, String> {
            Ok(self.blocks.get(height as usize).cloned())
        }

        async fn query_tip(&self) -> Result<TipOfChainRes, String> {
            if self.blocks.is_empty() {
                Err("Not tip".to_string())
            } else {
                Ok(TipOfChainRes {
                    certification: None,
                    tip_index: (self.blocks.len() - 1) as u64,
                })
            }
        }

        async fn multi_query_blocks(
            self: Arc<Self>,
            range: Range<BlockIndex>,
        ) -> Result<Vec<EncodedBlock>, String> {
            Ok(self.blocks[range.start as usize..range.end as usize].to_vec())
        }
    }

    async fn new_ledger_blocks_synchronizer(
        blocks: Vec<EncodedBlock>,
    ) -> LedgerBlocksSynchronizer<RangeOfBlocks> {
        LedgerBlocksSynchronizer::new(
            Some(Arc::new(RangeOfBlocks::new(blocks))),
            /* store_location = */ None,
            /* store_max_blocks = */ None,
            /* verification_info = */ None,
            Box::new(NopMetrics {}),
            false,
        )
        .await
        .unwrap()
    }

    fn dummy_block(parent_hash: Option<HashOf<EncodedBlock>>) -> EncodedBlock {
        let operation = match parent_hash {
            Some(_) => {
                let from = AccountIdentifier::new(PrincipalId::new_anonymous(), None);
                let to = AccountIdentifier::new(PrincipalId::new_node_test_id(1), None);
                let amount = Tokens::from_e8s(100_000);
                let fee = Tokens::from_e8s(10_000);
                icp_ledger::Operation::Transfer {
                    from,
                    to,
                    spender: None,
                    amount,
                    fee,
                }
            }
            None => {
                let to = AccountIdentifier::new(PrincipalId::new_anonymous(), None);
                let amount = Tokens::from_e8s(100_000_000_000_000);
                icp_ledger::Operation::Mint { amount, to }
            }
        };
        let timestamp = TimeStamp::from_nanos_since_unix_epoch(
            1656347498000000000, /* 27 June 2022 18:31:38 GMT+02:00 DST */
        );
        Block::new(
            parent_hash,
            operation,
            Memo(0),
            timestamp,
            timestamp,
            DEFAULT_TRANSFER_FEE,
        )
        .unwrap()
        .encode()
    }

    fn dummy_blocks(n: usize) -> Vec<EncodedBlock> {
        let mut res = vec![];
        let mut parent_hash = None;
        for _i in 0..n {
            let block = dummy_block(parent_hash);
            parent_hash = Some(Block::block_hash(&block));
            res.push(block);
        }
        res
    }

    #[tokio::test]
    async fn sync_empty_range_of_blocks() {
        let blocks_sync = new_ledger_blocks_synchronizer(vec![]).await;
        assert_eq!(
            None,
            blocks_sync
                .read_blocks()
                .await
                .get_first_hashed_block()
                .ok()
        );
    }

    #[tokio::test]
    async fn sync_all_blocks() {
        let blocks = dummy_blocks(2);
        let blocks_sync = new_ledger_blocks_synchronizer(blocks.clone()).await;
        blocks_sync
            .sync_blocks(Arc::new(AtomicBool::new(false)), None)
            .await
            .unwrap();
        let actual_blocks = blocks_sync.read_blocks().await;
        // there isn't a blocks.len() to use, so we check that the last index + 1 gives error and then we check the blocks
        for (idx, eb) in blocks.iter().enumerate() {
            let hb = actual_blocks.get_hashed_block(&(idx as u64)).unwrap();
            assert!(actual_blocks.is_verified_by_idx(&(idx as u64)).unwrap());
            assert_eq!(Block::block_hash(eb), Block::block_hash(&hb.block));
        }
    }

    #[tokio::test]
    async fn sync_blocks_in_2_steps() {
        let blocks = dummy_blocks(2);
        let blocks_sync = new_ledger_blocks_synchronizer(blocks.clone()).await;

        // sync 1
        blocks_sync
            .sync_blocks(Arc::new(AtomicBool::new(false)), Some(0))
            .await
            .unwrap();
        {
            let actual_blocks = blocks_sync.read_blocks().await;
            let hashed_blocks = actual_blocks.get_hashed_block(&0).unwrap();
            assert!(actual_blocks.is_verified_by_idx(&0).unwrap());
            assert_eq!(
                Block::block_hash(&blocks[0]),
                Block::block_hash(&hashed_blocks.block)
            );
        }

        // sync 2
        blocks_sync
            .sync_blocks(Arc::new(AtomicBool::new(false)), Some(1))
            .await
            .unwrap();
        {
            let actual_blocks = blocks_sync.read_blocks().await;
            let hashed_blocks = actual_blocks.get_hashed_block(&1).unwrap();
            assert!(actual_blocks.is_verified_by_idx(&1).unwrap());
            assert_eq!(
                Block::block_hash(&blocks[1]),
                Block::block_hash(&hashed_blocks.block)
            );
        }
    }
}
