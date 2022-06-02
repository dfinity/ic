use crate::balance_book::BalanceBook;
use crate::errors::ApiError;
use crate::store::{BlockStoreError, HashedBlock, SQLiteStore};
use ic_ledger_core::block::{BlockType, EncodedBlock, HashOf};
use ledger_canister::{AccountIdentifier, Block, BlockHeight, Tokens, Transaction};
use log::{error, info};
use std::collections::HashMap;

pub struct Blocks {
    pub balance_book: BalanceBook,
    hash_location: HashMap<HashOf<EncodedBlock>, BlockHeight>,
    pub tx_hash_location: HashMap<HashOf<Transaction>, BlockHeight>,
    pub block_store: SQLiteStore,
    last_hash: Option<HashOf<EncodedBlock>>,
}

impl Blocks {
    const LOAD_FROM_STORE_BLOCK_BATCH_LEN: u64 = 10000;

    pub fn new_persistent(store_location: &std::path::Path) -> Self {
        let block_store = SQLiteStore::new_on_disk(store_location)
            .expect("Failed to initialize sql store for ledger");
        Self {
            balance_book: BalanceBook::default(),
            hash_location: HashMap::default(),
            tx_hash_location: HashMap::default(),
            block_store,
            last_hash: None,
        }
    }

    pub fn new_in_memory() -> Self {
        let block_store =
            SQLiteStore::new_in_memory().expect("Failed to initialize sql store for ledger");
        Self {
            balance_book: BalanceBook::default(),
            hash_location: HashMap::default(),
            tx_hash_location: HashMap::default(),
            block_store,
            last_hash: None,
        }
    }

    pub fn load_from_store(&mut self) -> Result<u64, ApiError> {
        assert!(self.last()?.is_none(), "Blocks is not empty");
        assert!(
            self.balance_book.store.acc_to_hist.is_empty(),
            "Blocks is not empty"
        );
        assert!(self.hash_location.is_empty(), "Blocks is not empty");
        assert!(self.tx_hash_location.is_empty(), "Blocks is not empty");

        if let Ok(genesis) = self.block_store.get_at(0) {
            self.process_block(genesis)?;
        } else {
            return Ok(0);
        }

        if let Some((first, balances_snapshot)) = self.block_store.first_snapshot() {
            self.balance_book = balances_snapshot;

            self.hash_location.insert(first.hash, first.index);

            let tx = Block::decode(first.block).unwrap().transaction;
            self.tx_hash_location.insert(tx.hash(), first.index);
            self.last_hash = Some(first.hash);
        }

        let mut n = 1; // one block loaded so far (genesis or first from snapshot)
        let mut next_idx = self.last()?.map(|hb| hb.index + 1).unwrap();
        loop {
            let batch = self
                .block_store
                .get_range(next_idx..next_idx + Self::LOAD_FROM_STORE_BLOCK_BATCH_LEN)?;
            if batch.is_empty() {
                break;
            }
            for hb in batch {
                self.process_block(hb).map_err(|e| {
                    error!(
                        "Processing block retrieved from store failed. Block idx: {}, error: {:?}",
                        next_idx, e
                    );
                    e
                })?;

                next_idx += 1;
                n += 1;
                if n % 30000 == 0 {
                    info!("Loading... {} blocks processed", n);
                }
            }
        }

        Ok(n)
    }

    fn get_at(&self, index: BlockHeight) -> Result<HashedBlock, ApiError> {
        Ok(self.block_store.get_at(index)?)
    }

    pub fn get_verified_at(&self, index: BlockHeight) -> Result<HashedBlock, ApiError> {
        let last_verified_idx = self
            .block_store
            .last_verified()
            .map(|x| x as i128)
            .unwrap_or(-1);
        if index as i128 > last_verified_idx {
            Err(BlockStoreError::NotFound(index).into())
        } else {
            self.get_at(index)
        }
    }

    pub fn get_balance(&self, acc: &AccountIdentifier, h: BlockHeight) -> Result<Tokens, ApiError> {
        if let Ok(Some(b)) = self.first_verified() {
            if h < b.index {
                return Err(ApiError::invalid_block_id(format!(
                    "Block at height: {} not available for query",
                    h
                )));
            }
        }
        let last_verified_idx = self
            .block_store
            .last_verified()
            .map(|x| x as i128)
            .unwrap_or(-1);
        if h as i128 > last_verified_idx {
            Err(ApiError::invalid_block_id(format!(
                "Block not found at height: {}",
                h
            )))
        } else {
            self.balance_book.store.get_at(*acc, h)
        }
    }

    fn get(&self, hash: HashOf<EncodedBlock>) -> Result<HashedBlock, ApiError> {
        let index = *self
            .hash_location
            .get(&hash)
            .ok_or_else(|| ApiError::invalid_block_id(format!("Block not found {}", hash)))?;
        self.get_at(index)
    }

    pub fn get_verified(&self, hash: HashOf<EncodedBlock>) -> Result<HashedBlock, ApiError> {
        let index = *self
            .hash_location
            .get(&hash)
            .ok_or_else(|| ApiError::invalid_block_id(format!("Block not found {}", hash)))?;
        self.get_verified_at(index)
    }

    /// Add a block to the block_store data structure, the parent_hash must
    /// match the end of the chain
    pub fn add_block(&mut self, hb: HashedBlock) -> Result<(), ApiError> {
        self.block_store.push(hb.clone())?;
        self.process_block(hb)?;
        Ok(())
    }

    pub fn add_blocks_batch(&mut self, batch: Vec<HashedBlock>) -> Result<(), ApiError> {
        self.block_store.push_batch(batch.clone())?;
        for hb in batch {
            self.process_block(hb)?;
        }
        Ok(())
    }

    pub fn process_block(&mut self, hb: HashedBlock) -> Result<(), ApiError> {
        let HashedBlock {
            block,
            hash,
            parent_hash,
            index,
        } = hb.clone();
        let last = self.last()?;
        let last_hash = last.clone().map(|hb| hb.hash);
        let last_index = last.map(|hb| hb.index);
        assert_eq!(
            &parent_hash, &last_hash,
            "When adding a block the parent_hash must match the last added block"
        );

        let block = Block::decode(block).unwrap();

        match last_index {
            Some(i) => assert_eq!(i + 1, index),
            None => assert_eq!(0, index),
        }

        let mut bb = &mut self.balance_book;
        bb.store.transaction_context = Some(index);
        bb.add_payment(&block.transaction.operation).unwrap();
        bb.store.transaction_context = None;

        self.hash_location.insert(hash, index);

        let tx = block.transaction;
        self.tx_hash_location.insert(tx.hash(), index);

        self.last_hash = Some(hb.hash);

        Ok(())
    }

    pub(crate) fn first(&self) -> Result<Option<HashedBlock>, ApiError> {
        Ok(self.block_store.first()?)
    }

    pub fn first_verified(&self) -> Result<Option<HashedBlock>, ApiError> {
        let last_verified_idx = self
            .block_store
            .last_verified()
            .map(|x| x as i128)
            .unwrap_or(-1);
        let first_block = self.block_store.first()?;
        if let Some(fb) = first_block.as_ref() {
            if fb.index as i128 > last_verified_idx {
                return Ok(None);
            }
        }
        Ok(first_block)
    }

    pub(crate) fn last(&self) -> Result<Option<HashedBlock>, ApiError> {
        match self.last_hash {
            Some(last_hash) => {
                let last = self.get(last_hash)?;
                Ok(Some(last))
            }
            None => Ok(None),
        }
    }

    pub fn last_verified(&self) -> Result<Option<HashedBlock>, ApiError> {
        match self.block_store.last_verified() {
            Some(h) => Ok(Some(self.block_store.get_at(h)?)),
            None => Ok(None),
        }
    }

    pub(crate) fn synced_to(&self) -> Option<(HashOf<EncodedBlock>, u64)> {
        self.last().ok().flatten().map(|hb| (hb.hash, hb.index))
    }

    pub fn try_prune(
        &mut self,
        max_blocks: &Option<u64>,
        prune_delay: u64,
    ) -> Result<(), ApiError> {
        if let Some(block_limit) = max_blocks {
            let first_idx = self.first()?.map(|hb| hb.index).unwrap_or(0);
            let last_idx = self.last()?.map(|hb| hb.index).unwrap_or(0);
            if first_idx + block_limit + prune_delay < last_idx {
                let new_first_idx = last_idx - block_limit;
                let prune_start_idx = first_idx.max(1).min(new_first_idx);
                for i in prune_start_idx..new_first_idx {
                    let hb = self.block_store.get_at(i)?;
                    self.hash_location
                        .remove(&hb.hash)
                        .expect("failed to remove block by hash");
                    let tx_hash = Block::decode(hb.block)
                        .expect("failed to decode block")
                        .transaction
                        .hash();
                    self.tx_hash_location
                        .remove(&tx_hash)
                        .expect("failed to remove transaction by hash");
                }

                let hb = self.block_store.get_at(new_first_idx)?;
                self.balance_book.store.prune_at(hb.index);
                self.block_store
                    .prune(&hb, &self.balance_book)
                    .map_err(ApiError::internal_error)?
            }
        }
        Ok(())
    }
}
