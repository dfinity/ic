use crate::balance_book::BalanceBook;
use crate::errors::Error;
use crate::store::{BlockStoreError, HashedBlock, SQLiteStore};
use ic_ledger_core::block::{BlockIndex, BlockType, EncodedBlock, HashOf};
use icp_ledger::{apply_operation, AccountIdentifier, Block, Tokens};
use log::{error, info};

pub struct Blocks {
    pub balance_book: BalanceBook,
    pub block_store: SQLiteStore,
}

impl Blocks {
    const LOAD_FROM_STORE_BLOCK_BATCH_LEN: u64 = 10000;

    pub fn new_persistent(store_location: &std::path::Path) -> Self {
        let block_store = SQLiteStore::new_on_disk(store_location)
            .expect("Failed to initialize sql store for ledger");
        Self {
            balance_book: BalanceBook::default(),
            block_store,
        }
    }

    pub fn new_in_memory() -> Self {
        let block_store =
            SQLiteStore::new_in_memory().expect("Failed to initialize sql store for ledger");
        Self {
            balance_book: BalanceBook::default(),
            block_store,
        }
    }

    pub fn load_from_store(&mut self) -> Result<u64, Error> {
        assert!(
            self.balance_book.store.acc_to_hist.is_empty(),
            "Blocks is not empty"
        );
        match self.block_store.get_hashed_block(&0) {
            Ok(genesis) => {
                self.process_block(genesis)?;
            }
            Err(_) => return Ok(0),
        }

        if let Some((_, balance_book)) = self.block_store.first_snapshot() {
            self.balance_book = balance_book;
        }

        let mut n = 1; // one block loaded so far (genesis or first from snapshot)
        let mut next_idx = self
            .get_first_hashed_block()
            .map(|hb| hb.index + 1)
            .unwrap();
        loop {
            let batch = self
                .block_store
                .get_hashed_block_range(next_idx..next_idx + Self::LOAD_FROM_STORE_BLOCK_BATCH_LEN);

            match batch {
                Ok(b) => {
                    for hb in b {
                        self.process_block(hb.clone()).map_err(|e| {
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
                Err(_) => break,
            };
        }

        Ok(n)
    }

    pub fn is_verified_by_hash(
        &self,
        hash: &HashOf<EncodedBlock>,
    ) -> Result<bool, BlockStoreError> {
        self.block_store.is_verified_by_hash(hash)
    }

    pub fn is_verified_by_idx(&self, idx: &u64) -> Result<bool, BlockStoreError> {
        self.block_store.is_verified_by_idx(idx)
    }

    /// Add a block to the block_store data structure, the parent_hash must
    /// match the end of the chain
    pub fn push(&mut self, hb: HashedBlock) -> Result<(), BlockStoreError> {
        self.block_store.push(&hb)?;
        self.process_block(hb)?;
        Ok(())
    }

    pub fn push_batch(&mut self, batch: Vec<HashedBlock>) -> Result<(), BlockStoreError> {
        self.block_store.push_batch(batch.clone())?;
        for hb in batch {
            self.process_block(hb)?;
        }
        Ok(())
    }

    pub fn process_block(&mut self, hb: HashedBlock) -> Result<(), BlockStoreError> {
        let HashedBlock {
            block,
            hash: _,
            parent_hash: _,
            index,
        } = hb;

        let block = Block::decode(block).unwrap();
        let mut bb = &mut self.balance_book;
        bb.store.transaction_context = Some(index);
        apply_operation(bb, &block.transaction.operation).unwrap();
        bb.store.transaction_context = None;
        Ok(())
    }

    pub(crate) fn get_first_hashed_block(&self) -> Result<HashedBlock, BlockStoreError> {
        self.block_store.get_first_hashed_block()
    }

    pub fn get_first_verified_hashed_block(&self) -> Result<HashedBlock, BlockStoreError> {
        self.block_store.get_first_verified_hashed_block()
    }

    pub(crate) fn get_latest_hashed_block(&self) -> Result<HashedBlock, BlockStoreError> {
        self.block_store.get_latest_hashed_block()
    }

    pub fn get_latest_verified_hashed_block(&self) -> Result<HashedBlock, BlockStoreError> {
        self.block_store.get_latest_verified_hashed_block()
    }
    pub fn get_account_balance(
        &self,
        acc: &AccountIdentifier,
        h: &BlockIndex,
    ) -> Result<Tokens, Error> {
        let first_verified = self.get_first_verified_hashed_block();
        if let Ok(b) = first_verified {
            if *h < b.index {
                return Err(Error::InvalidBlockId(format!(
                    "Block at height: {} not available for query",
                    h
                )));
            }
        }
        let last_verified = self.block_store.get_latest_verified_hashed_block()?;
        if *h > last_verified.index {
            Err(Error::InvalidBlockId(format!(
                "Block not found at height: {}",
                h
            )))
        } else {
            self.balance_book.store.get_at(*acc, *h)
        }
    }

    pub fn try_prune(&mut self, max_blocks: &Option<u64>, prune_delay: u64) -> Result<(), Error> {
        if let Some(block_limit) = max_blocks {
            let first_idx = self
                .block_store
                .get_first_hashed_block()
                .map(|hb| hb.index)
                .unwrap_or(0);
            let last_idx = self
                .get_latest_hashed_block()
                .map(|hb| hb.index)
                .unwrap_or(0);
            if first_idx + block_limit + prune_delay < last_idx {
                let new_first_idx = last_idx - block_limit;
                let hb = self.block_store.get_hashed_block(&new_first_idx);
                match hb {
                    Ok(b) => {
                        self.balance_book.store.prune_at(b.index);
                        self.block_store
                            .prune(&b, &self.balance_book)
                            .map_err(Error::InternalError)?;
                    }
                    Err(_) => {
                        return Err(Error::InternalError(format!(
                            "Block ist not stored {}",
                            new_first_idx
                        )))
                    }
                }
            }
        }
        Ok(())
    }
}
