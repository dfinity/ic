use log::debug;
use std::convert::TryInto;
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use ledger_canister::{AccountIdentifier, BlockHeight, EncodedBlock, HashOf, Tokens};

use crate::balance_book::BalanceBook;
use crate::errors::ApiError;

#[derive(candid::CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct HashedBlock {
    pub block: EncodedBlock,
    pub hash: HashOf<EncodedBlock>,
    pub parent_hash: Option<HashOf<EncodedBlock>>,
    pub index: u64,
}

impl HashedBlock {
    pub fn hash_block(
        block: EncodedBlock,
        parent_hash: Option<HashOf<EncodedBlock>>,
        index: BlockHeight,
    ) -> HashedBlock {
        HashedBlock {
            hash: block.hash(),
            block,
            parent_hash,
            index,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum BlockStoreError {
    NotFound(BlockHeight),
    NotAvailable(BlockHeight),
    Other(String),
}

impl From<BlockStoreError> for ApiError {
    fn from(e: BlockStoreError) -> Self {
        match e {
            BlockStoreError::NotFound(idx) => {
                ApiError::invalid_block_id(format!("Block not found: {}", idx))
            }
            BlockStoreError::NotAvailable(idx) => {
                ApiError::invalid_block_id(format!("Block not available for query: {}", idx))
            }
            BlockStoreError::Other(msg) => ApiError::internal_error(msg),
        }
    }
}

fn vec_into_array(v: Vec<u8>) -> [u8; 32] {
    let ba: Box<[u8; 32]> = match v.into_boxed_slice().try_into() {
        Ok(ba) => ba,
        Err(v) => panic!("Expected a Vec of length 32 but it was {}", v.len()),
    };
    *ba
}

pub struct SQLiteStore {
    connection: Mutex<rusqlite::Connection>,
    base_idx: u64,
    first_block: Option<HashedBlock>,
    last_verified_idx: Option<BlockHeight>,
}

impl SQLiteStore {
    /// Constructs a new SQLite on-disk store.
    pub fn new_on_disk(location: &Path) -> Result<Self, BlockStoreError> {
        std::fs::create_dir_all(location)
            .expect("Unable to create directory for SQLite on-disk store.");
        let path = location.join("db.sqlite");
        let connection =
            rusqlite::Connection::open(&path).expect("Unable to open SQLite database connection");
        Self::new(connection)
    }

    /// Constructs a new SQLite in-memory store.
    pub fn new_in_memory() -> Result<Self, BlockStoreError> {
        let connection = rusqlite::Connection::open_in_memory()
            .expect("Unable to open SQLite in-memory database connection");
        Self::new(connection)
    }

    fn new(connection: rusqlite::Connection) -> Result<Self, BlockStoreError> {
        let mut store = Self {
            connection: Mutex::new(connection),
            base_idx: 0,
            first_block: None,
            last_verified_idx: None,
        };
        store
            .connection
            .lock()
            .unwrap()
            .execute("PRAGMA foreign_keys = 1", [])
            .unwrap();
        store.create_tables().map_err(|e| {
            BlockStoreError::Other(format!("Failed to initialize SQLite database: {}", e))
        })?;
        store.first_block = store
            .read_oldest_block_snapshot()
            .map_err(BlockStoreError::Other)?
            .map(|x| x.0);

        if let Some(first_block) = &store.first_block {
            store.base_idx = first_block.index;
            store.get_at(first_block.index).and_then(|b| {
                if *first_block != b {
                    Err(BlockStoreError::Other("Corrupted snapshot".to_string()))
                } else {
                    Ok(())
                }
            })?;
        }

        // Read last verified index (if any).
        {
            let connection = store.connection.lock().unwrap();
            let mut stmt = connection
                .prepare("SELECT idx FROM blocks WHERE verified = TRUE ORDER BY idx DESC LIMIT 1")
                .map_err(|e| BlockStoreError::Other(e.to_string()))?;
            let mut rows = stmt
                .query([])
                .map_err(|e| BlockStoreError::Other(e.to_string()))?;
            store.last_verified_idx = rows
                .next()
                .map_err(|e| BlockStoreError::Other(e.to_string()))?
                .map(|row| row.get(0).unwrap());
        }

        Ok(store)
    }

    pub fn create_tables(&self) -> Result<(), rusqlite::Error> {
        let connection = self.connection.lock().unwrap();
        connection.execute(
            r#"
            CREATE TABLE IF NOT EXISTS blocks (
                hash BLOB NOT NULL,
                block BLOB NOT NULL,
                parent_hash BLOB,
                idx INTEGER NOT NULL PRIMARY KEY,
                verified BOOLEAN)
            "#,
            [],
        )?;
        // Table of pool balance on each block, used for sanity checks.
        connection.execute(
            r#"
            CREATE TABLE IF NOT EXISTS balances (
                block_idx INTEGER NOT NULL PRIMARY KEY,
                icpt_pool BLOB NOT NULL,
                FOREIGN KEY(block_idx) REFERENCES blocks(idx)
            )
            "#,
            [],
        )?;
        // Table of account book balances on each block.
        connection.execute(
            r#"
            CREATE TABLE IF NOT EXISTS books (
                block_idx INTEGER NOT NULL,
                account VARCHAR(64) NOT NULL,
                icpt INTEGER NOT NULL,
                num_pruned_transactions INTEGER NOT NULL,
                PRIMARY KEY(block_idx,account),
                FOREIGN KEY(block_idx) REFERENCES blocks(idx)
            )
            "#,
            [],
        )?;
        Ok(())
    }

    fn execute_push(connection: &mut Connection, hb: HashedBlock) -> Result<(), BlockStoreError> {
        let hash = hb.hash.into_bytes().to_vec();
        let parent_hash = hb.parent_hash.map(|ph| ph.into_bytes().to_vec());
        connection
            .execute(
                "INSERT INTO blocks (hash, block, parent_hash, idx, verified) VALUES (?1, ?2, ?3, ?4, FALSE)",
                params![hash, hb.block.into_vec(), parent_hash, hb.index],
            )
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        Ok(())
    }

    fn read_oldest_block_snapshot(&self) -> Result<Option<(HashedBlock, BalanceBook)>, String> {
        let mut balance_book = BalanceBook::default();
        let last_index;
        {
            let mut con = self.connection.lock().unwrap();
            let tx = con.transaction().expect("Cannot open transaction");

            // Read last balance.
            {
                let mut stmt = tx
                    .prepare(
                        "SELECT block_idx,icpt_pool FROM balances ORDER BY block_idx DESC LIMIT 1",
                    )
                    .map_err(|e| e.to_string())?;
                let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
                let next = rows.next().map_err(|e| e.to_string())?;
                if next.is_none() {
                    // No existing snapshot.
                    return Ok(None);
                }
                let row = next.unwrap();
                last_index = row.get(0).expect("Expected index.");

                // Convert back pool from i64 to u64.
                let pool: i64 = row.get(1).expect("Expected icpt pool.");
                let pool = pool as u64;
                balance_book.token_pool = Tokens::from_e8s(pool);
            }

            // Read last books.
            {
                let mut stmt = tx
                    .prepare("SELECT block_idx,account,icpt,num_pruned_transactions FROM books WHERE block_idx=?")
                    .map_err(|e| e.to_string())?;
                let mut rows = stmt.query(params![last_index]).map_err(|e| e.to_string())?;
                while let Some(row) = rows.next().unwrap() {
                    let acc_hex: String = row.get(1).expect("Expected account identifier.");
                    let acc_id = AccountIdentifier::from_hex(&acc_hex).unwrap();
                    let icpt = row.get(2).expect("Expected tokens.");
                    balance_book
                        .store
                        .insert(acc_id, last_index, Tokens::from_e8s(icpt));
                    balance_book
                        .store
                        .acc_to_hist
                        .get_mut(&acc_id)
                        .expect("Expected history for account.")
                        .num_pruned_transactions = row.get(3).unwrap();
                }

                SQLiteStore::sanity_check(&balance_book).map_err(|e| e)?;
            }
        }

        let last_block = self.get_at(last_index);
        Ok(Some((last_block.unwrap(), balance_book)))
    }

    /// Sanity check (sum of tokens equal pool size).
    fn sanity_check(balance_book: &BalanceBook) -> Result<(), String> {
        let mut sum_icpt = Tokens::ZERO;
        for acc in balance_book.store.acc_to_hist.keys() {
            sum_icpt += balance_book.account_balance(acc);
        }
        let expected_icpt_pool = (Tokens::MAX - sum_icpt).unwrap();
        if expected_icpt_pool != balance_book.token_pool {
            return Err(format!(
                "Incorrect ICPT pool value in the snapshot (expected: {}, got: {})",
                expected_icpt_pool, balance_book.token_pool
            ));
        }
        Ok(())
    }

    fn write_oldest_block_snapshot(
        &mut self,
        hb: &HashedBlock,
        balances: &BalanceBook,
    ) -> Result<(), String> {
        if let Ok(Some(b)) = self.first() {
            // this check is made in upper levels, but for readability:
            assert!(
                b.index <= hb.index,
                "Oldest: {}, new oldest: {}",
                b.index,
                hb.index
            );
        }

        debug!("Writing oldest block snapshot ({})", hb.index);

        // NB: storing the index of block should be enough, no need to store the
        // hashedblock itself.

        let mut con = self.connection.lock().unwrap();
        let tx = con.transaction().expect("Cannot open transaction");

        // Build balances.
        let mut balances_snapshot = BalanceBook::default();
        for (acc, hist) in balances.store.acc_to_hist.iter() {
            // It's safe to unwrap here: this can only fail if hb.index is below the index
            // of the first block. We validate this invariant in the beginning
            // of this function.
            let amount = hist.get_at(hb.index).unwrap();
            balances_snapshot.token_pool -= amount;
            balances_snapshot.store.insert(*acc, hb.index, amount);
        }

        // We need to convert to i64 because SQLite only supports signed integers,
        // and Rusqlite doesn't like overflows when converting u64 to i64.
        let pool = balances_snapshot.token_pool.get_e8s() as i64;

        tx.execute(
            "INSERT INTO balances(block_idx,icpt_pool) VALUES (?1,?2)",
            params![hb.index, pool],
        )
        .map_err(|e| e.to_string())?;

        {
            let mut stmt = tx.prepare("INSERT INTO books(block_idx,account,icpt,num_pruned_transactions) VALUES (?1,?2,?3,?4)")
                .expect("Couldn't prepare statement");
            for (acc, history) in balances.store.acc_to_hist.iter() {
                let icpts = history.get_at(hb.index).unwrap();
                let num_pruned = history.num_pruned_transactions;
                stmt.execute(params![hb.index, acc.to_hex(), icpts.get_e8s(), num_pruned])
                    .map_err(|e| e.to_string())?;
            }
        }

        tx.commit().map_err(|e| e.to_string())?;

        self.first_block = Option::Some(hb.clone());
        Ok(())
    }

    pub fn get_at(&self, index: BlockHeight) -> Result<HashedBlock, BlockStoreError> {
        if 0 < index && index < self.base_idx {
            return Err(BlockStoreError::NotAvailable(index));
        }

        let connection = self.connection.lock().unwrap();
        let mut stmt = connection
            .prepare("SELECT hash, block, parent_hash, idx FROM blocks WHERE idx = ?")
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        let mut blocks = stmt
            .query_map(params![index], |row| {
                Ok(HashedBlock {
                    hash: row.get(0).map(|bytes| HashOf::new(vec_into_array(bytes)))?,
                    block: row.get(1).map(EncodedBlock::from_vec)?,
                    parent_hash: row.get(2).map(|opt_bytes: Option<Vec<u8>>| {
                        opt_bytes.map(|bytes| HashOf::new(vec_into_array(bytes)))
                    })?,
                    index: row.get(3)?,
                })
            })
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        blocks
            .next()
            .ok_or(BlockStoreError::NotFound(index))
            .map(|block| block.unwrap())
    }

    pub fn get_range(
        &self,
        range: std::ops::Range<BlockHeight>,
    ) -> Result<Vec<HashedBlock>, BlockStoreError> {
        if 0 < range.start && range.start < self.base_idx {
            return Err(BlockStoreError::NotAvailable(range.start));
        }
        let connection = self.connection.lock().unwrap();
        let mut stmt = connection
            .prepare("SELECT hash, block, parent_hash, idx FROM blocks WHERE idx >= ? AND idx < ?")
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        let mut blocks = stmt
            .query_map(params![range.start, range.end], |row| {
                Ok(HashedBlock {
                    hash: row.get(0).map(|bytes| HashOf::new(vec_into_array(bytes)))?,
                    block: row.get(1).map(EncodedBlock::from_vec)?,
                    parent_hash: row.get(2).map(|opt_bytes: Option<Vec<u8>>| {
                        opt_bytes.map(|bytes| HashOf::new(vec_into_array(bytes)))
                    })?,
                    index: row.get(3)?,
                })
            })
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        let mut res = Vec::new();
        while let Some(hb) = blocks.next().map(|block| block.unwrap()) {
            res.push(hb)
        }
        Ok(res)
    }

    pub fn push(&mut self, hb: HashedBlock) -> Result<(), BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        Self::execute_push(&mut *connection, hb)
    }

    pub fn push_batch(&mut self, batch: Vec<HashedBlock>) -> Result<(), BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();

        connection
            .execute_batch("BEGIN TRANSACTION;")
            .map_err(|e| BlockStoreError::Other(format!("{}", e)))?;

        for hb in batch {
            match Self::execute_push(&mut *connection, hb) {
                Ok(_) => (),
                Err(e) => {
                    connection
                        .execute_batch("ROLLBACK TRANSACTION;")
                        .map_err(|e| BlockStoreError::Other(format!("{}", e)))?;
                    return Err(e);
                }
            }
        }

        connection
            .execute_batch("COMMIT TRANSACTION;")
            .map_err(|e| BlockStoreError::Other(format!("{}", e)))?;
        Ok(())
    }

    // FIXME: Make `prune` return `BlockStoreError` on error
    pub fn prune(&mut self, hb: &HashedBlock, balances: &BalanceBook) -> Result<(), String> {
        self.write_oldest_block_snapshot(hb, balances)?;
        let mut connection = self.connection.lock().unwrap();
        let tx = connection.transaction().expect("Cannot open transaction");
        // NB: An optimization would be to update only modified accounts.
        tx.execute(
            "DELETE FROM books WHERE block_idx > 0 AND block_idx < ?",
            params![hb.index],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "DELETE FROM balances WHERE block_idx > 0 AND block_idx < ?",
            params![hb.index],
        )
        .map_err(|e| e.to_string())?;
        tx.execute(
            "DELETE FROM blocks WHERE idx > 0 AND idx < ?",
            params![hb.index],
        )
        .map_err(|e| e.to_string())?;
        self.base_idx = hb.index;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn first_snapshot(&self) -> Option<(HashedBlock, BalanceBook)> {
        self.read_oldest_block_snapshot()
            .expect("Error while retrieving first snapshot.")
    }

    pub fn first(&self) -> Result<Option<HashedBlock>, BlockStoreError> {
        if let Some(first_block) = self.first_block.as_ref() {
            Ok(Some(first_block.clone()))
        } else {
            match self.get_at(0) {
                Ok(x) => Ok(Some(x)),
                Err(BlockStoreError::NotFound(_)) => Ok(None),
                Err(e) => Err(e),
            }
        }
    }

    pub fn last_verified(&self) -> Option<BlockHeight> {
        self.last_verified_idx
    }

    pub fn mark_last_verified(&mut self, block_height: BlockHeight) -> Result<(), BlockStoreError> {
        if let Some(hh) = self.last_verified_idx {
            if block_height < hh {
                panic!(
                    "New last verified index lower than the old one. New: {}, old: {}",
                    block_height, hh
                );
            }
            if block_height == hh {
                return Ok(());
            }
        }

        let connection = self.connection.lock().unwrap();
        let mut stmt = connection
            .prepare("UPDATE blocks SET verified = TRUE WHERE idx >= ? AND idx <= ?")
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        stmt.execute(params![
            self.last_verified_idx.map(|x| x + 1).unwrap_or(0),
            block_height
        ])
        .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        self.last_verified_idx = Some(block_height);
        Ok(())
    }
}
