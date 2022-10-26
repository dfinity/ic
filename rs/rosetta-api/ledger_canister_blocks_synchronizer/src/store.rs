use crate::balance_book::BalanceBook;
use ic_ledger_core::{
    block::{BlockIndex, BlockType, EncodedBlock, HashOf},
    Tokens,
};
use icp_ledger::AccountIdentifier;
use icp_ledger::Block;
use log::debug;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::path::Path;
use std::sync::Mutex;

mod database_access {
    use crate::store::{BlockStoreError, HashedBlock};
    use ic_ledger_canister_core::ledger::LedgerTransaction;
    use ic_ledger_core::block::{BlockType, EncodedBlock, HashOf};
    use icp_ledger::{Block, Operation};
    use rusqlite::{params, types::Null, Connection};

    use super::vec_into_array;

    pub fn push_hashed_block(
        con: &mut Connection,
        hb: &HashedBlock,
    ) -> Result<(), BlockStoreError> {
        let hash = hb.hash.into_bytes().to_vec();
        let parent_hash = hb.parent_hash.map(|ph| ph.into_bytes().to_vec());
        let command = "INSERT INTO blocks (hash, block, parent_hash, idx, verified) VALUES (?1, ?2, ?3, ?4, FALSE)";
        con.execute(
            command,
            params![hash, hb.block.clone().into_vec(), parent_hash, hb.index],
        )
        .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        Ok(())
    }
    pub fn push_transaction(
        connection: &mut Connection,
        tx: &icp_ledger::Transaction,
        index: &u64,
    ) -> Result<(), BlockStoreError> {
        let tx_hash = tx.hash().into_bytes().to_vec();
        let operation_type = tx.operation.clone();
        let command = "INSERT INTO transactions (block_idx,tx_hash,operation_type,from_account,to_account,amount,fee) VALUES (?1, ?2, ?3, ?4, ?5,?6,?7)";
        match operation_type {
            Operation::Burn { from, amount } => {
                let op_string: &'static str = operation_type.into();
                let from_account = from.to_hex();
                let tokens = amount.get_e8s();
                let to_account = Null;
                let fees = Null;
                connection
                    .execute(
                        command,
                        params![
                            index,
                            tx_hash,
                            op_string,
                            from_account,
                            to_account,
                            tokens,
                            fees
                        ],
                    )
                    .map_err(|e| BlockStoreError::Other(e.to_string()))?;
            }
            Operation::Mint { to, amount } => {
                let op_string: &'static str = operation_type.into();
                let from_account = Null;
                let tokens = amount.get_e8s();
                let to_account = to.to_hex();
                let fees = Null;
                connection
                    .execute(
                        command,
                        params![
                            index,
                            tx_hash,
                            op_string,
                            from_account,
                            to_account,
                            tokens,
                            fees
                        ],
                    )
                    .map_err(|e| BlockStoreError::Other(e.to_string()))?;
            }
            Operation::Transfer {
                from,
                to,
                amount,
                fee,
            } => {
                let op_string: &'static str = operation_type.into();
                let from_account = from.to_hex();
                let tokens = amount.get_e8s();
                let to_account = to.to_hex();
                let fees = fee.get_e8s();
                connection
                    .execute(
                        command,
                        params![
                            index,
                            tx_hash,
                            op_string,
                            from_account,
                            to_account,
                            tokens,
                            fees
                        ],
                    )
                    .map_err(|e| BlockStoreError::Other(e.to_string()))?;
            }
        }
        Ok(())
    }
    pub fn contains_block(
        connection: &mut Connection,
        block_idx: &u64,
    ) -> Result<bool, BlockStoreError> {
        let mut stmt = connection
            .prepare("SELECT * FROM blocks WHERE idx = ?")
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        let mut rows = stmt
            .query(params![block_idx])
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        let next = rows
            .next()
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        Ok(next.is_some())
    }
    pub fn get_transaction(
        connection: &mut Connection,
        block_idx: &u64,
    ) -> Result<Option<icp_ledger::Transaction>, BlockStoreError> {
        let command = "SELECT block from blocks where idx = ?";
        let mut stmt = connection
            .prepare(command)
            .map_err(|e| BlockStoreError::Other(e.to_string()))
            .unwrap();
        let block = stmt
            .query_map(params![block_idx], |row| {
                Ok(row
                    .get(0)
                    .map(|b| {
                        Block::decode(EncodedBlock::from_vec(b))
                            .unwrap()
                            .transaction
                    })
                    .unwrap())
            })
            .unwrap()
            .next()
            .ok_or(BlockStoreError::NotFound(*block_idx))
            .map(|block| block.unwrap())?;
        Ok(Some(block))
    }
    pub fn get_hashed_block(
        con: &mut Connection,
        block_idx: &u64,
    ) -> Result<Option<HashedBlock>, BlockStoreError> {
        let command = "SELECT  hash, block, parent_hash,idx from blocks where idx = ?";
        let mut stmt = con
            .prepare(command)
            .map_err(|e| BlockStoreError::Other(e.to_string()))
            .unwrap();
        let block = stmt
            .query_map(params![block_idx], |row| {
                Ok(HashedBlock {
                    hash: row.get(0).map(|bytes| HashOf::new(vec_into_array(bytes)))?,
                    block: row.get(1).map(EncodedBlock::from_vec)?,
                    parent_hash: row.get(2).map(|opt_bytes: Option<Vec<u8>>| {
                        opt_bytes.map(|bytes| HashOf::new(vec_into_array(bytes)))
                    })?,
                    index: row.get(3)?,
                })
            })
            .unwrap()
            .next()
            .ok_or(BlockStoreError::NotFound(*block_idx))
            .map(|block| block.unwrap())?;
        Ok(Some(block))
    }

    pub fn get_transaction_hash(
        connection: &mut Connection,
        block_idx: &u64,
    ) -> Result<Option<HashOf<icp_ledger::Transaction>>, BlockStoreError> {
        let command = "SELECT tx_hash from transactions where block_idx = ?";
        let mut stmt = connection
            .prepare(command)
            .map_err(|e| BlockStoreError::Other(e.to_string()))
            .unwrap();
        let block = stmt
            .query_map(params![block_idx], |row| {
                Ok(row
                    .get(0)
                    .map(|bytes| HashOf::new(vec_into_array(bytes)))
                    .unwrap())
            })
            .unwrap()
            .next()
            .ok_or(BlockStoreError::NotFound(*block_idx))
            .map(|block| block.unwrap())?;
        Ok(Some(block))
    }
}

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
        index: BlockIndex,
    ) -> HashedBlock {
        HashedBlock {
            hash: Block::block_hash(&block),
            block,
            parent_hash,
            index,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum BlockStoreError {
    NotFound(BlockIndex),
    NotAvailable(BlockIndex),
    Other(String),
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
    last_verified_idx: Option<BlockIndex>,
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
        store.check_table_coherance()?;
        Ok(store)
    }

    fn create_tables(&self) -> Result<(), rusqlite::Error> {
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
        connection.execute(
            r#"
            CREATE TABLE IF NOT EXISTS transactions (
                block_idx INTEGER NOT NULL,
                tx_hash BLOB NOT NULL,
                operation_type VARCHAR NOT NULL,
                from_account VARCHAR(64) ,
                to_account VARCHAR(64) ,
                amount INTEGER NOT NULL,
                fee INTEGER,
                PRIMARY KEY(tx_hash),
                FOREIGN KEY(block_idx) REFERENCES blocks(idx)
            )
            "#,
            [],
        )?;
        connection.execute(
            r#"
            CREATE UNIQUE INDEX IF NOT EXISTS block_hash_indexer
            ON blocks (hash);    
            "#,
            [],
        )?;

        connection.execute(
            r#"
            CREATE UNIQUE INDEX IF NOT EXISTS block_idx_indexer
            ON transactions (block_idx);    
            "#,
            [],
        )?;

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

    pub fn get_transaction_hash(
        &self,
        block_idx: &u64,
    ) -> Result<Option<HashOf<icp_ledger::Transaction>>, BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        if database_access::contains_block(&mut *connection, block_idx)? {
            //Returns Some if there exists a transaction in storage on that block, otherwise returns NotFound Error
            database_access::get_transaction_hash(&mut *connection, block_idx)
        } else {
            // If the database does not contain the block that is being searched for, the block is not available for queries
            Err(BlockStoreError::NotAvailable(*block_idx))
        }
    }

    pub fn get_transaction(
        &self,
        block_idx: &u64,
    ) -> Result<Option<icp_ledger::Transaction>, BlockStoreError> {
        if 0 < *block_idx && *block_idx < self.base_idx {
            return Err(BlockStoreError::NotAvailable(*block_idx));
        }
        let mut connection = self.connection.lock().unwrap();
        if database_access::contains_block(&mut *connection, block_idx)? {
            match database_access::get_transaction(&mut *connection, block_idx) {
                Ok(tx) => Ok(tx),
                Err(_) => Err(BlockStoreError::Other(format!(
                    "Block {} is available but no transaction can be found for block {}",
                    block_idx, block_idx
                ))),
            }
        } else {
            Err(BlockStoreError::NotFound(*block_idx))
        }
    }
    fn check_table_coherance(&self) -> Result<(), BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        let mut stmt = connection
            .prepare("SELECT idx FROM blocks")
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        let indexes = stmt
            .query_map(params![], |row| row.get(0))
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        //Get all indizes for table blocks
        let mut block_indexes: Vec<u64> = indexes.map(|x| x.unwrap()).collect();
        drop(stmt);

        let mut stmt = connection
            .prepare("SELECT block_idx FROM transactions")
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        let indexes = stmt
            .query_map(params![], |row| row.get(0))
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        let mut transaction_block_indexes: Vec<u64> = indexes.map(|x| x.unwrap()).collect();
        drop(stmt);

        let all_indixes: Vec<u64> = block_indexes
            .iter()
            .cloned()
            .chain(transaction_block_indexes.iter().cloned())
            .collect();
        block_indexes.sort_by(|a, b| a.partial_cmp(b).unwrap());
        block_indexes.dedup();
        transaction_block_indexes.sort_by(|a, b| a.partial_cmp(b).unwrap());
        transaction_block_indexes.dedup();
        if !all_indixes.is_empty() {
            assert!(
                all_indixes
                    .clone()
                    .into_iter()
                    .all(|item| block_indexes.contains(&item)),
                "Transaction Table has more unique block indizes than Blocks Table"
            );
            let difference_transaction_indixes: Vec<u64> = all_indixes
                .into_iter()
                .filter(|item| !transaction_block_indexes.contains(item))
                .collect();
            for missing_index in difference_transaction_indixes {
                let missing_block =
                    database_access::get_hashed_block(&mut *connection, &missing_index)?;
                database_access::push_transaction(
                    &mut *connection,
                    &Block::decode(
                        missing_block
                            .ok_or(BlockStoreError::NotFound(missing_index))?
                            .block,
                    )
                    .unwrap()
                    .transaction,
                    &missing_index,
                )?;
            }
        }
        Ok(())
    }

    pub fn get_at(&self, index: BlockIndex) -> Result<HashedBlock, BlockStoreError> {
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
        range: std::ops::Range<BlockIndex>,
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

    pub fn push(&self, hb: &HashedBlock) -> Result<(), BlockStoreError> {
        let mut con = self.connection.lock().unwrap();
        database_access::push_hashed_block(&mut *con, hb)?;
        database_access::push_transaction(
            &mut *con,
            &Block::decode(hb.block.clone()).unwrap().transaction,
            &hb.index,
        )?;
        //TODO: UPDATE ACCOUNT BALANCES

        Ok(())
    }

    pub fn push_batch(&mut self, batch: Vec<HashedBlock>) -> Result<(), BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        connection
            .execute_batch("BEGIN TRANSACTION;")
            .map_err(|e| BlockStoreError::Other(format!("{}", e)))?;
        for hb in batch {
            match database_access::push_hashed_block(&mut *connection, &hb) {
                Ok(_) => (),
                Err(e) => {
                    connection
                        .execute_batch("ROLLBACK TRANSACTION;")
                        .map_err(|e| BlockStoreError::Other(format!("{}", e)))?;
                    return Err(e);
                }
            };
            match database_access::push_transaction(
                &mut *connection,
                &Block::decode(hb.block.clone()).unwrap().transaction,
                &hb.index,
            ) {
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

    pub fn prune(&mut self, hb: &HashedBlock, balance_book: &BalanceBook) -> Result<(), String> {
        self.write_oldest_block_snapshot(hb, balance_book)?;
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
            "DELETE FROM transactions WHERE block_idx > 0 AND block_idx < ?",
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

    pub fn last_verified(&self) -> Option<BlockIndex> {
        self.last_verified_idx
    }

    pub fn mark_last_verified(&mut self, block_height: BlockIndex) -> Result<(), BlockStoreError> {
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
