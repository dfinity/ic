use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::Arc;

use core::ops::Deref;
use dfn_core::CanisterId;
use ic_canister_client::HttpClient;
use ic_ledger_core::block::BlockType;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use ledger_canister::{Block, TipOfChainRes};
use log::{debug, error, info, trace};
use tokio::sync::RwLock;
use url::Url;

use crate::certification::verify_block_hash;
use crate::errors::ApiError;
use crate::ledger_client::blocks::Blocks;
use crate::ledger_client::canister_access::CanisterAccess;
use crate::store::{BlockStoreError, HashedBlock};

// If pruning is enabled, instead of pruning after each new block
// we'll wait for PRUNE_DELAY blocks to accumulate and prune them in one go
const PRUNE_DELAY: u64 = 10000;

/// The LedgerBlocksSynchronizer will use this to output the metrics while
/// synchronizing with the Leddger
pub trait LedgerBlocksSynchronizerMetrics {
    fn set_target_height(&self, height: u64);
    fn set_synced_height(&self, height: u64);
    fn set_verified_height(&self, height: u64);
}

/// Downloads the blocks of the Ledger to either an in-memory store or to
/// a local sqlite store
pub struct LedgerBlocksSynchronizer {
    pub blockchain: RwLock<Blocks>,
    pub ledger_canister_id: CanisterId,
    pub ledger_canister_access: Option<Arc<CanisterAccess>>,
    store_max_blocks: Option<u64>,
    root_key: Option<ThresholdSigPublicKey>,
    metrics: Box<dyn LedgerBlocksSynchronizerMetrics + Send + Sync>,
}

impl LedgerBlocksSynchronizer {
    pub async fn new(
        ic_url: Url,
        ledger_canister_id: CanisterId,
        store_location: Option<&std::path::Path>,
        store_max_blocks: Option<u64>,
        offline: bool,
        root_key: Option<ThresholdSigPublicKey>,
        metrics: Box<dyn LedgerBlocksSynchronizerMetrics + Send + Sync>,
    ) -> Result<LedgerBlocksSynchronizer, ApiError> {
        let mut blocks = match store_location {
            Some(loc) => Blocks::new_persistent(loc),
            None => Blocks::new_in_memory(),
        };

        let ledger_canister_access = if offline {
            None
        } else {
            let http_client = HttpClient::new();
            let canister_access = Arc::new(CanisterAccess::new(
                ic_url.clone(),
                ledger_canister_id,
                http_client,
            ));
            Self::verify_store(&blocks, &canister_access).await?;

            if root_key.is_some() {
                // verify if we have the right certificate/we are connecting to the right
                // canister
                let TipOfChainRes {
                    tip_index,
                    certification,
                } = canister_access.query_tip().await?;

                let tip_block = canister_access
                    .query_raw_block(tip_index)
                    .await?
                    .expect("Blockchain in the ledger canister is empty");

                verify_block_hash(
                    &certification,
                    Block::block_hash(&tip_block),
                    &root_key,
                    &ledger_canister_id,
                )
                .map_err(ApiError::internal_error)?;
            }
            Some(canister_access)
        };

        info!("Loading blocks from store");
        let num_loaded = blocks.load_from_store()?;

        info!(
            "Ledger client is up. Loaded {} blocks from store. First block at {}, last at {}",
            num_loaded,
            blocks
                .first()?
                .map(|x| format!("{}", x.index))
                .unwrap_or_else(|| "None".to_string()),
            blocks
                .last()?
                .map(|x| format!("{}", x.index))
                .unwrap_or_else(|| "None".to_string())
        );
        if let Some(x) = blocks.last()? {
            metrics.set_synced_height(x.index);
        }
        if let Some(x) = blocks.block_store.last_verified() {
            metrics.set_verified_height(x);
        }

        blocks.try_prune(&store_max_blocks, PRUNE_DELAY)?;

        Ok(Self {
            blockchain: RwLock::new(blocks),
            ledger_canister_id,
            ledger_canister_access,
            store_max_blocks,
            root_key,
            metrics,
        })
    }

    async fn verify_store(
        blocks: &Blocks,
        canister_access: &CanisterAccess,
    ) -> Result<(), ApiError> {
        debug!("Verifying store...");
        let first_block = blocks.block_store.first()?;

        match blocks.block_store.get_at(0) {
            Ok(store_genesis) => {
                let genesis = canister_access
                    .query_raw_block(0)
                    .await?
                    .expect("Blockchain in the ledger canister is empty");

                if store_genesis.hash != Block::block_hash(&genesis) {
                    let msg = format!(
                        "Genesis block from the store is different than \
                        in the ledger canister. Store hash: {}, canister hash: {}",
                        store_genesis.hash,
                        Block::block_hash(&genesis)
                    );
                    error!("{}", msg);
                    return Err(ApiError::internal_error(msg));
                }
            }
            Err(BlockStoreError::NotFound(0)) => {
                if first_block.is_some() {
                    let msg = "Snapshot found, but genesis block not present in the store";
                    error!("{}", msg);
                    return Err(ApiError::internal_error(msg));
                }
            }
            Err(e) => {
                let msg = format!("Error loading genesis block: {:?}", e);
                error!("{}", msg);
                return Err(ApiError::internal_error(msg));
            }
        }

        if first_block.is_some() && first_block.as_ref().unwrap().index > 0 {
            let first_block = first_block.unwrap();
            let queried_block = canister_access.query_raw_block(first_block.index).await?;
            if queried_block.is_none() {
                let msg = format!(
                    "Oldest block snapshot does not match the block on \
                    the blockchain. Block with this index not found: {}",
                    first_block.index
                );
                error!("{}", msg);
                return Err(ApiError::internal_error(msg));
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
                return Err(ApiError::internal_error(msg));
            }
        }
        debug!("Verifying store done");
        Ok(())
    }

    pub async fn read_blocks(&self) -> Box<dyn Deref<Target = Blocks> + '_> {
        Box::new(self.blockchain.read().await)
    }

    pub async fn sync_blocks(&self, stopped: Arc<AtomicBool>) -> Result<(), ApiError> {
        let canister = self.ledger_canister_access.as_ref().unwrap();
        let TipOfChainRes {
            tip_index,
            certification,
        } = canister.query_tip().await?;
        self.metrics.set_target_height(tip_index);

        let chain_length = tip_index + 1;

        if chain_length == 0 {
            return Ok(());
        }

        let mut blockchain = self.blockchain.write().await;

        let (mut last_block_hash, next_block_index) = match blockchain.synced_to() {
            Some((hash, index)) => (Some(hash), index + 1),
            None => (None, 0),
        };

        if next_block_index < chain_length {
            trace!(
                "Sync from: {}, chain_length: {}",
                next_block_index,
                chain_length
            );
        } else {
            if next_block_index > chain_length {
                trace!("Tip received from IC lower than what we already have (queried lagging replica?),
                 new chain length: {}, our {}", chain_length, next_block_index);
            }
            return Ok(());
        }

        let print_progress = if chain_length - next_block_index >= 1000 {
            info!(
                "Syncing {} blocks. New tip at {}",
                chain_length - next_block_index,
                chain_length - 1
            );
            true
        } else {
            false
        };

        let mut i = next_block_index;
        while i < chain_length {
            if stopped.load(Relaxed) {
                return Err(ApiError::internal_error("Interrupted"));
            }

            debug!("Asking for blocks {}-{}", i, chain_length);
            let batch = canister.multi_query_blocks(i, chain_length).await?;

            debug!("Got batch of len: {}", batch.len());
            if batch.is_empty() {
                return Err(ApiError::internal_error(
                    "Couldn't fetch new blocks (batch result empty)".to_string(),
                ));
            }

            let mut hashed_batch = Vec::new();
            hashed_batch.reserve_exact(batch.len());
            for raw_block in batch {
                let block = Block::decode(raw_block.clone()).map_err(|err| {
                    ApiError::internal_error(format!("Cannot decode block: {}", err))
                })?;
                if block.parent_hash != last_block_hash {
                    let err_msg = format!(
                        "Block at {}: parent hash mismatch. Expected: {:?}, got: {:?}",
                        i, last_block_hash, block.parent_hash
                    );
                    error!("{}", err_msg);
                    return Err(ApiError::internal_error(err_msg));
                }
                let hb = HashedBlock::hash_block(raw_block, last_block_hash, i);
                if i == chain_length - 1 {
                    verify_block_hash(
                        &certification,
                        hb.hash,
                        &self.root_key,
                        &self.ledger_canister_id,
                    )
                    .map_err(ApiError::internal_error)?;
                }
                last_block_hash = Some(hb.hash);
                hashed_batch.push(hb);
                i += 1;
            }

            blockchain.add_blocks_batch(hashed_batch)?;
            self.metrics.set_synced_height(i - 1);

            if print_progress && (i - next_block_index) % 10000 == 0 {
                info!("Synced up to {}", i - 1);
            }
        }

        blockchain
            .block_store
            .mark_last_verified(chain_length - 1)?;
        self.metrics.set_verified_height(chain_length - 1);

        if next_block_index != chain_length {
            info!(
                "You are all caught up to block {}",
                blockchain.last()?.unwrap().index
            );
        }

        blockchain.try_prune(&self.store_max_blocks, PRUNE_DELAY)?;
        Ok(())
    }
}
