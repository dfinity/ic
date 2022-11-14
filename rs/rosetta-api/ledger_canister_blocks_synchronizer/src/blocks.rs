use ic_ledger_core::block::{BlockIndex, BlockType, EncodedBlock, HashOf};
use icp_ledger::{AccountIdentifier, Block, Tokens};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::path::Path;
use std::sync::Mutex;

mod database_access {
    use super::vec_into_array;
    use crate::blocks::{BlockStoreError, HashedBlock};
    use ic_ledger_canister_core::ledger::LedgerTransaction;
    use ic_ledger_core::{
        block::{BlockType, EncodedBlock, HashOf},
        Tokens,
    };
    use icp_ledger::{AccountIdentifier, Block, Operation};
    use rusqlite::{params, types::Null, Connection, Error, Statement};

    pub fn push_hashed_block(
        con: &mut Connection,
        hb: &HashedBlock,
    ) -> Result<(), BlockStoreError> {
        let mut stmt = con
        .prepare("INSERT INTO blocks (hash, block, parent_hash, idx, verified) VALUES (?1, ?2, ?3, ?4, FALSE)")
        .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        push_hashed_block_execution(hb, &mut stmt)
    }

    pub fn push_hashed_block_execution(
        hb: &HashedBlock,
        stmt: &mut Statement,
    ) -> Result<(), BlockStoreError> {
        let hash = hb.hash.into_bytes().to_vec();
        let parent_hash = hb.parent_hash.map(|ph| ph.into_bytes().to_vec());
        stmt.execute(params![
            hash,
            hb.block.clone().into_vec(),
            parent_hash,
            hb.index
        ])
        .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        Ok(())
    }

    pub fn push_transaction(
        connection: &mut Connection,
        tx: &icp_ledger::Transaction,
        index: &u64,
    ) -> Result<(), BlockStoreError> {
        let mut stmt = connection
        .prepare("INSERT INTO transactions (block_idx,tx_hash,operation_type,from_account,to_account,amount,fee) VALUES (?1, ?2, ?3, ?4, ?5,?6,?7)")
        .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        push_transaction_execution(tx, &mut stmt, index)
    }

    pub fn push_transaction_execution(
        tx: &icp_ledger::Transaction,
        stmt: &mut Statement,
        index: &u64,
    ) -> Result<(), BlockStoreError> {
        let tx_hash = tx.hash().into_bytes().to_vec();
        let operation_type = tx.operation.clone();
        match operation_type {
            Operation::Burn { from, amount } => {
                let op_string: &str = operation_type.into();
                let from_account = from.to_hex();
                let tokens = amount.get_e8s();
                let to_account = Null;
                let fees = Null;
                stmt.execute(params![
                    index,
                    tx_hash,
                    op_string,
                    from_account,
                    to_account,
                    tokens,
                    fees
                ])
                .map_err(|e| BlockStoreError::Other(e.to_string()))?;
            }
            Operation::Mint { to, amount } => {
                let op_string: &str = operation_type.into();
                let from_account = Null;
                let tokens = amount.get_e8s();
                let to_account = to.to_hex();
                let fees = Null;
                stmt.execute(params![
                    index,
                    tx_hash,
                    op_string,
                    from_account,
                    to_account,
                    tokens,
                    fees
                ])
                .map_err(|e| BlockStoreError::Other(e.to_string()))?;
            }
            Operation::Transfer {
                from,
                to,
                amount,
                fee,
            } => {
                let op_string: &str = operation_type.into();
                let from_account = from.to_hex();
                let tokens = amount.get_e8s();
                let to_account = to.to_hex();
                let fees = fee.get_e8s();
                stmt.execute(params![
                    index,
                    tx_hash,
                    op_string,
                    from_account,
                    to_account,
                    tokens,
                    fees
                ])
                .map_err(|e| BlockStoreError::Other(e.to_string()))?;
            }
        }
        Ok(())
    }
    pub fn get_all_block_indices_from_blocks_table(
        connection: &mut Connection,
    ) -> Result<Vec<u64>, BlockStoreError> {
        let mut stmt = connection
            .prepare("SELECT idx from blocks")
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        let indices = stmt
            .query_map(params![], |row| row.get(0))
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        let block_indices: Vec<u64> = indices.map(|x| x.unwrap()).collect();
        Ok(block_indices)
    }
    pub fn get_all_block_indices_from_transactions_table(
        connection: &mut Connection,
    ) -> Result<Vec<u64>, BlockStoreError> {
        let mut stmt = connection
            .prepare("SELECT block_idx FROM transactions")
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        let indices = stmt
            .query_map(params![], |row| row.get(0))
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        let block_indices: Vec<u64> = indices.map(|x| x.unwrap()).collect();
        Ok(block_indices)
    }

    pub fn get_all_block_indices_from_account_balances_table(
        connection: &mut Connection,
    ) -> Result<Vec<u64>, BlockStoreError> {
        let mut stmt = connection
            .prepare("SELECT block_idx FROM account_balances")
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        let indices = stmt
            .query_map(params![], |row| row.get(0))
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        let block_indices: Vec<u64> = indices.map(|x| x.unwrap()).collect();
        Ok(block_indices)
    }

    pub fn contains_block(
        connection: &mut Connection,
        block_idx: &u64,
    ) -> Result<bool, BlockStoreError> {
        let mut stmt = connection
            .prepare("SELECT Null FROM blocks WHERE idx = ?")
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
    ) -> Result<icp_ledger::Transaction, BlockStoreError> {
        let command = "SELECT block from blocks where idx = ?";
        let mut stmt = connection
            .prepare(command)
            .map_err(|e| BlockStoreError::Other(e.to_string()))
            .unwrap();
        let mut transactions = stmt
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
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        match transactions.next() {
            Some(transaction) => transaction.map_err(|e| BlockStoreError::Other(e.to_string())),
            None => Err(BlockStoreError::NotFound(*block_idx)),
        }
    }
    pub fn get_hashed_block(
        con: &mut Connection,
        block_idx: &u64,
    ) -> Result<HashedBlock, BlockStoreError> {
        let command = format!(
            "SELECT  hash, block, parent_hash,idx from blocks where idx = {}",
            block_idx
        );
        let mut blocks = read_hashed_block(con, command.as_str())?.into_iter();
        match blocks.next() {
            Some(block) => block.map_err(|e| BlockStoreError::Other(e.to_string())),
            None => Err(BlockStoreError::NotFound(*block_idx)),
        }
    }

    fn read_hashed_block(
        con: &mut Connection,
        command: &str,
    ) -> Result<Vec<Result<HashedBlock, Error>>, BlockStoreError> {
        let mut stmt = con
            .prepare(command)
            .map_err(|e| BlockStoreError::Other(e.to_string()))
            .unwrap();
        let block = stmt
            .query_map(params![], |row| {
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
        Ok(block.collect())
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
        let mut transactions = stmt
            .query_map(params![block_idx], |row| {
                Ok(row
                    .get(0)
                    .map(|bytes| HashOf::new(vec_into_array(bytes)))
                    .unwrap())
            })
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        match transactions.next() {
            Some(transaction) => Ok(Some(
                transaction.map_err(|e| BlockStoreError::Other(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }
    pub fn get_block_idx_by_transaction_hash(
        connection: &mut Connection,
        hash: &HashOf<icp_ledger::Transaction>,
    ) -> Result<u64, BlockStoreError> {
        get_block_idx_by_hash(
            connection,
            &hash.into_bytes().to_vec(),
            "SELECT block_idx from transactions where tx_hash = ?",
        )
    }
    fn get_block_idx_by_hash(
        connection: &mut Connection,
        hash: &Vec<u8>,
        command: &str,
    ) -> Result<u64, BlockStoreError> {
        let mut stmt = connection
            .prepare(command)
            .map_err(|e| BlockStoreError::Other(e.to_string()))
            .unwrap();
        let block_idx = stmt
            .query_map(params![hash], |row| Ok(row.get(0).unwrap()))
            .unwrap()
            .next()
            .ok_or_else(|| BlockStoreError::Other("Hash Not Found".to_string()))
            .map(|block| block.unwrap())?;
        Ok(block_idx)
    }

    pub fn get_block_idx_by_block_hash(
        connection: &mut Connection,
        hash: &HashOf<EncodedBlock>,
    ) -> Result<u64, BlockStoreError> {
        get_block_idx_by_hash(
            connection,
            &hash.into_bytes().to_vec(),
            "SELECT idx from blocks where hash = ?",
        )
    }
    // The option is left None if both verified and unverified blocks should be querried. It is set to False for only unverified blocks and True for only verified blocks
    pub fn get_first_hashed_block(
        con: &mut Connection,
        verified: Option<bool>,
    ) -> Result<HashedBlock, BlockStoreError> {
        let command = match verified {
            Some(verified) => format!("SELECT  hash, block, parent_hash,idx from blocks WHERE verified = {} ORDER BY idx ASC Limit 2",verified),
            None => "SELECT  hash, block, parent_hash,idx from blocks ORDER BY idx ASC Limit 2".to_string()
        };
        let mut blocks = read_hashed_block(con, command.as_str())?.into_iter();
        match blocks.next() {
            Some(genesis_block) => match blocks.next() {
                Some(first_block) => {
                    let block = first_block.map_err(|e| BlockStoreError::Other(e.to_string()))?;
                    if block.index > 1 {
                        Ok(block)
                    } else {
                        Ok(genesis_block.map_err(|e| BlockStoreError::Other(e.to_string()))?)
                    }
                }
                None => Ok(genesis_block.map_err(|e| BlockStoreError::Other(e.to_string()))?),
            },
            None => Err(BlockStoreError::Other("Blockchain is empty".to_string())),
        }
    }
    // The option is left None if both verified and unverified blocks should be querried. It is set to False for only unverified blocks and True for only verified blocks

    pub fn get_latest_hashed_block(
        con: &mut Connection,
        verified: Option<bool>,
    ) -> Result<HashedBlock, BlockStoreError> {
        let command = match verified {
            Some(verified) => format!("SELECT  hash, block, parent_hash,idx from blocks WHERE verified = {} ORDER BY idx DESC Limit 1",verified),
            None => "SELECT  hash, block, parent_hash,idx from blocks ORDER BY idx DESC Limit 1".to_string()
        };
        let mut blocks = read_hashed_block(con, command.as_str())?.into_iter();
        match blocks.next() {
            Some(first_block) => {
                Ok(first_block.map_err(|e| BlockStoreError::Other(e.to_string()))?)
            }
            None => Err(BlockStoreError::Other("Blockchain is empty".to_string())),
        }
    }
    pub fn get_account_balance(
        connection: &mut Connection,
        block_idx: &u64,
        account: &AccountIdentifier,
    ) -> Result<Option<u64>, BlockStoreError> {
        let command = "SELECT tokens FROM account_balances WHERE block_idx<=?1 AND account=?2 ORDER BY block_idx DESC LIMIT 1";
        let mut stmt = connection
            .prepare(command)
            .map_err(|e| BlockStoreError::Other(e.to_string()))
            .unwrap();
        let amount = stmt
            .query_map(params![block_idx, account.to_hex()], |row| {
                Ok(row.get(0).unwrap())
            })
            .unwrap()
            .next();
        match amount {
            Some(tokens) => Ok(tokens.unwrap()),
            None => Ok(None),
        }
    }
    pub fn update_balance_book_execution(
        hb: &HashedBlock,
        stmt_select: &mut Statement,
        stmt_insert: &mut Statement,
    ) -> Result<(), BlockStoreError> {
        let block = Block::decode(hb.block.clone()).unwrap();
        let operation_type = block.transaction.operation;
        let mut new_balances: Vec<(String, u64)> = vec![];
        let mut extract_latest_balance =
            |account: AccountIdentifier| -> Result<Option<(String, u64)>, BlockStoreError> {
                let account_balance_opt = stmt_select
                    .query_map(params![account.to_hex(), hb.index], |row| {
                        Ok((
                            row.get(1).map(|x: String| x as String)?,
                            row.get(2).map(|x: u64| x as u64)?,
                        ))
                    })
                    .map_err(|e| BlockStoreError::Other(e.to_string()))?
                    .map(|x| x.unwrap())
                    .next();
                Ok(account_balance_opt)
            };
        match operation_type {
            Operation::Burn { from, amount } => {
                let account_balance_opt = extract_latest_balance(from)?;
                match account_balance_opt {
                    Some(mut balance) => {
                        if balance.1 >= amount.get_e8s() {
                            balance.1 -= amount.get_e8s();
                            new_balances.push(balance);
                        } else {
                            return Err(BlockStoreError::Other(format!("Trying to brun tokens from an account that has not enough tokens. Current balance is {}, burn amount is {}.",balance.1,amount.get_e8s())));
                        }
                    }
                    None => {
                        return Err(BlockStoreError::Other("Trying to burn tokens from an account that has not yet been allocated any tokens".to_string()));
                    }
                }
            }
            Operation::Mint { to, amount } => {
                let account_balance_opt = extract_latest_balance(to)?;
                match account_balance_opt {
                    Some(mut balance) => {
                        balance.1 += amount.get_e8s();
                        new_balances.push(balance);
                    }
                    None => {
                        new_balances.push((to.to_hex(), amount.get_e8s()));
                    }
                }
            }
            Operation::Transfer {
                from,
                to,
                amount,
                fee,
            } => {
                let account_balance_opt = extract_latest_balance(to)?;
                let self_transfer = from.to_hex() == to.to_hex();
                match account_balance_opt {
                    Some(mut balance) => {
                        balance.1 += amount.get_e8s();
                        if self_transfer {
                            balance.1 -= amount.get_e8s();
                            balance.1 -= fee.get_e8s();
                        }
                        new_balances.push(balance);
                    }
                    None => {
                        new_balances.push((to.to_hex(), amount.get_e8s()));
                    }
                }
                if !self_transfer {
                    let account_balance_opt = extract_latest_balance(from)?;
                    match account_balance_opt {
                        Some(mut balance) => {
                            let payable = amount.get_e8s() + fee.get_e8s();
                            if balance.1 >= payable {
                                balance.1 -= payable;
                                new_balances.push(balance);
                            } else {
                                return Err(BlockStoreError::Other(format!("Trying to transfer tokens from an account that has not enough tokens. Current balance is {}, payable amount is {}.",balance.1,payable)));
                            }
                        }
                        None => {
                            return Err(BlockStoreError::Other("Trying to transfer tokens from an account that has not yet been allocated any tokens".to_string()));
                        }
                    }
                }
            }
        }

        for (account, tokens) in new_balances {
            stmt_insert
                .execute(params![hb.index, account, tokens])
                .map_err(|e| {
                    BlockStoreError::Other(
                        e.to_string()
                            + format!(" | Block IDX: {} , Account {}", hb.index, account).as_str(),
                    )
                })?;
        }
        Ok(())
    }

    pub fn update_balance_book(
        con: &mut Connection,
        hb: &HashedBlock,
    ) -> Result<(), BlockStoreError> {
        let mut stmt_select =  con
        .prepare("SELECT block_idx,account,tokens FROM account_balances WHERE account=?1 AND block_idx<=?2 ORDER BY block_idx DESC LIMIT 1")
        .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        let mut stmt_insert = con
            .prepare("INSERT INTO account_balances (block_idx,account,tokens) VALUES (?1,?2,?3)")
            .expect("Couldn't prepare statement");
        update_balance_book_execution(hb, &mut stmt_select, &mut stmt_insert)
    }

    pub fn get_all_accounts(
        connection: &mut Connection,
    ) -> Result<Vec<AccountIdentifier>, BlockStoreError> {
        let mut accounts = vec![];
        let mut stmt = connection
            .prepare("SELECT DISTINCT account FROM account_balances")
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        let mut rows = stmt
            .query(params![])
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        while let Some(row) = rows.next().unwrap() {
            let account: String = row.get(0).unwrap();
            accounts.push(AccountIdentifier::from_hex(account.as_str()).unwrap());
        }
        Ok(accounts)
    }

    pub fn prune_account_balances(
        con: &mut Connection,
        block_idx: &u64,
    ) -> Result<(), BlockStoreError> {
        let mut stmt = con
            .prepare(
                "SELECT DISTINCT account FROM account_balances WHERE block_idx <= ?1 AND account IN (SELECT account FROM account_balances WHERE block_idx <= ?1 GROUP BY account HAVING COUNT(block_idx) > 1)",
            )
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        let mut rows = stmt
            .query(params![block_idx])
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        let get_last_involved_block_idx = |acc: &str| -> Result<u64, BlockStoreError> {
            let command = "SELECT block_idx FROM account_balances WHERE block_idx <= ?1 AND account = ?2 ORDER BY block_idx DESC LIMIT 1";
            let mut stmt = con
                .prepare(command)
                .map_err(|e| BlockStoreError::Other(e.to_string()))
                .unwrap();
            let mut block_idx = stmt
                .query_map(params![block_idx, acc], |row| {
                    Ok(row.get(0).map(|x: u64| x as u64).unwrap())
                })
                .map_err(|e| BlockStoreError::Other(e.to_string()))?;
            match block_idx.next() {
                Some(Ok(idx)) => Ok(idx),
                Some(Err(e)) => Err(BlockStoreError::Other(e.to_string())),
                None => Ok(0),
            }
        };
        while let Some(row) = rows.next().unwrap() {
            let account: String = row.get(0).unwrap();
            let last_block_idx = get_last_involved_block_idx(&account)?;
            con.execute(
                "DELETE FROM account_balances WHERE account = ?1 AND block_idx < ?2",
                params![account, last_block_idx],
            )
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        }
        Ok(())
    }

    pub fn get_account_balance_history(
        connection: &mut Connection,
        acc: &AccountIdentifier,
        max_block: Option<u64>,
    ) -> Result<Vec<(u64, Tokens)>, BlockStoreError> {
        let first_idx = get_first_hashed_block(connection, Some(true))?.index;

        let command = match max_block {
            Some(limit) => match first_idx {
                0 => {
                    format!( "SELECT block_idx,tokens from account_balances where account = ? AND block_idx<= {} ORDER BY block_idx DESC",limit)
                }
                _ => {
                    format!( "SELECT block_idx,tokens from account_balances where account = ? AND block_idx<= {} AND block_idx > {} ORDER BY block_idx DESC",limit,first_idx)
                }
            },
            None => match first_idx {
                0 => {
                    String::from("SELECT block_idx,tokens from account_balances where account = ? ORDER BY block_idx DESC")}

                _ => {
                    format!("SELECT block_idx,tokens from account_balances where account = ? AND block_idx > {} ORDER BY block_idx DESC",first_idx)
                }
                }
        };
        let account = acc.to_hex();
        let mut result = Vec::new();
        let mut stmt = connection
            .prepare(command.as_str())
            .map_err(|e| BlockStoreError::Other(e.to_string()))
            .unwrap();
        let account_history = stmt
            .query_map(params![account], |row| {
                Ok((
                    row.get(0).map(|x: u64| x as u64)?,
                    row.get(1).map(|x| Tokens::from_e8s(x))?,
                ))
            })
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        for tuple in account_history {
            result.push(tuple.unwrap());
        }
        Ok(result)
    }

    pub fn is_verified(con: &mut Connection, block_idx: &u64) -> Result<bool, BlockStoreError> {
        let command = "SELECT null from blocks WHERE verified=TRUE AND idx=?";
        let mut stmt = con
            .prepare(command)
            .map_err(|e| BlockStoreError::Other(e.to_string()))
            .unwrap();
        let mut blocks = stmt
            .query(params![block_idx])
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        match blocks
            .next()
            .map_err(|e| BlockStoreError::Other(e.to_string()))?
        {
            Some(_) => Ok(true),
            None => Ok(false),
        }
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

pub struct Blocks {
    connection: Mutex<rusqlite::Connection>,
}

impl Blocks {
    pub fn new_persistent(location: &Path) -> Result<Self, BlockStoreError> {
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
        let store = Self {
            connection: Mutex::new(connection),
        };
        store
            .connection
            .lock()
            .unwrap()
            .execute("PRAGMA foreign_keys = 1", [])
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        store.create_tables().map_err(|e| {
            BlockStoreError::Other(format!("Failed to initialize SQLite database: {}", e))
        })?;

        store.check_table_coherence()?;
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
            CREATE TABLE IF NOT EXISTS account_balances (
                block_idx INTEGER NOT NULL,
                account VARCHAR(64) NOT NULL,
                tokens INTEGER NOT NULL,
                PRIMARY KEY(account,block_idx)
            )
            "#,
            [],
        )?;

        Ok(())
    }

    pub fn prune(&mut self, hb: &HashedBlock) -> Result<(), BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        connection
            .execute_batch("BEGIN TRANSACTION;")
            .map_err(|e| BlockStoreError::Other(format!("{}", e)))?;

        connection
            .execute(
                "DELETE FROM transactions WHERE block_idx > 0 AND block_idx < ?",
                params![hb.index],
            )
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        database_access::prune_account_balances(&mut connection, &hb.index)?;
        connection
            .execute(
                "DELETE FROM blocks WHERE idx > 0 AND idx < ?",
                params![hb.index],
            )
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;

        connection
            .execute_batch("COMMIT TRANSACTION;")
            .map_err(|e| BlockStoreError::Other(format!("{}", e)))?;

        Ok(())
    }
    pub fn get_block_idx_by_block_hash(
        &self,
        hash: &HashOf<EncodedBlock>,
    ) -> Result<u64, BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();

        database_access::get_block_idx_by_block_hash(&mut *connection, hash)
    }

    pub fn get_block_idx_by_transaction_hash(
        &self,
        hash: &HashOf<icp_ledger::Transaction>,
    ) -> Result<u64, BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        database_access::get_block_idx_by_transaction_hash(&mut *connection, hash)
    }
    pub fn get_account_balance_history(
        &self,
        acc: &AccountIdentifier,
        limit_num_blocks: Option<u64>,
    ) -> Result<Vec<(u64, Tokens)>, BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        database_access::get_account_balance_history(&mut *connection, acc, limit_num_blocks)
    }

    /// Sanity check (sum of tokens equal pool size).
    fn sanity_check(&self, latest_hb: &HashedBlock) -> Result<(), BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        let accounts = database_access::get_all_accounts(&mut *connection)?;
        let mut total = Tokens::ZERO;
        for account in accounts {
            let amount = database_access::get_account_balance(
                &mut *connection,
                &latest_hb.index.clone(),
                &account,
            )?;
            total += Tokens::from_e8s(amount.unwrap());
        }
        assert!(total <= Tokens::MAX);
        Ok(())
    }

    pub fn get_transaction_hash(
        &self,
        block_idx: &u64,
    ) -> Result<Option<HashOf<icp_ledger::Transaction>>, BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();

        if database_access::contains_block(&mut *connection, block_idx)? {
            database_access::get_transaction_hash(&mut *connection, block_idx)
        } else {
            Err(BlockStoreError::NotAvailable(*block_idx))
        }
    }

    pub fn get_first_verified_hashed_block(&self) -> Result<HashedBlock, BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        database_access::get_first_hashed_block(&mut *connection, Some(true))
    }
    pub fn get_hashed_block(&self, block_idx: &u64) -> Result<HashedBlock, BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        database_access::get_hashed_block(&mut *connection, block_idx)
    }

    pub fn get_transaction(
        &self,
        block_idx: &u64,
    ) -> Result<icp_ledger::Transaction, BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        database_access::get_transaction(&mut *connection, block_idx)
    }
    fn check_table_coherence(&self) -> Result<(), BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        let mut block_indices =
            database_access::get_all_block_indices_from_blocks_table(&mut *connection)?;
        let mut transaction_block_indices =
            database_access::get_all_block_indices_from_transactions_table(&mut *connection)?;
        let mut account_balances_block_indices =
            database_access::get_all_block_indices_from_account_balances_table(&mut *connection)?;
        let vec_sorted_diff = |blocks_indices: &mut [u64],
                               other_indices: &mut [u64]|
         -> Result<Vec<u64>, BlockStoreError> {
            let mut result: Vec<u64> = Vec::new();
            let mut idx_b = 0;
            for item in blocks_indices {
                if idx_b >= other_indices.len() || *item < other_indices[idx_b] {
                    result.push(*item);
                    continue;
                }
                if *item == other_indices[idx_b] {
                    idx_b += 1;
                    continue;
                }
                if *item > other_indices[idx_b] {
                    /* Vector a is representative of the block_idxes in the blocks table and since other tables refer to the blocks
                    table with a forein key constraint it should not be possible for other tables to have a block idx that is
                    not present in the blocks table. */
                    while idx_b < other_indices.len() {
                        if *item == other_indices[idx_b] {
                            idx_b += 1;
                            break;
                        }
                        idx_b += 1;
                    }
                }
            }
            Ok(result)
        };
        let mut all_indices: Vec<u64> = block_indices
            .iter()
            .cloned()
            .chain(transaction_block_indices.iter().cloned())
            .collect();
        all_indices.sort_by(|a, b| a.partial_cmp(b).unwrap());
        all_indices.dedup();
        block_indices.sort_by(|a, b| a.partial_cmp(b).unwrap());
        block_indices.dedup();
        transaction_block_indices.sort_by(|a, b| a.partial_cmp(b).unwrap());
        transaction_block_indices.dedup();
        account_balances_block_indices.sort_by(|a, b| a.partial_cmp(b).unwrap());
        account_balances_block_indices.dedup();
        if !all_indices.is_empty() {
            let diff = vec_sorted_diff(all_indices.as_mut_slice(), block_indices.as_mut_slice())?;
            assert!(
                diff.is_empty(),
                "Transaction Table has more unique block indizes than Blocks Table"
            );
            let difference_transaction_indices: Vec<u64> = vec_sorted_diff(
                all_indices.as_mut_slice(),
                transaction_block_indices.as_mut_slice(),
            )?;
            for missing_index in difference_transaction_indices {
                let missing_block =
                    database_access::get_hashed_block(&mut *connection, &missing_index)?;
                database_access::push_transaction(
                    &mut *connection,
                    &Block::decode(missing_block.block).unwrap().transaction,
                    &missing_index,
                )?;
            }
            let difference_account_balances_indices: Vec<u64> = vec_sorted_diff(
                all_indices.as_mut_slice(),
                account_balances_block_indices.as_mut_slice(),
            )?;
            for missing_index in difference_account_balances_indices {
                let missing_block =
                    database_access::get_hashed_block(&mut *connection, &missing_index)?;
                database_access::update_balance_book(&mut *connection, &missing_block)?;
            }
        }
        Ok(())
    }
    pub fn is_verified_by_hash(
        &self,
        hash: &HashOf<EncodedBlock>,
    ) -> Result<bool, BlockStoreError> {
        let block_idx = self.get_block_idx_by_block_hash(hash)?;
        let mut con = self.connection.lock().unwrap();
        match database_access::contains_block(&mut con, &block_idx)? {
            true => database_access::is_verified(&mut *con, &block_idx),
            false => Err(BlockStoreError::NotFound(block_idx)),
        }
    }

    pub fn is_verified_by_idx(&self, idx: &u64) -> Result<bool, BlockStoreError> {
        let mut con = self.connection.lock().unwrap();
        match database_access::contains_block(&mut con, idx)? {
            true => database_access::is_verified(&mut *con, idx),
            false => Err(BlockStoreError::NotFound(*idx)),
        }
    }

    pub fn get_first_hashed_block(&self) -> Result<HashedBlock, BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();

        database_access::get_first_hashed_block(&mut *connection, None)
    }

    pub fn get_latest_hashed_block(&self) -> Result<HashedBlock, BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();

        database_access::get_latest_hashed_block(&mut *connection, None)
    }

    pub fn get_latest_verified_hashed_block(&self) -> Result<HashedBlock, BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        database_access::get_latest_hashed_block(&mut *connection, Some(true))
    }
    pub fn get_account_balance(
        &self,
        account: &AccountIdentifier,
        block_idx: &u64,
    ) -> Result<Tokens, BlockStoreError> {
        if self.is_verified_by_idx(block_idx)? {
            let mut connection = self.connection.lock().unwrap();
            let amount =
                database_access::get_account_balance(&mut *connection, block_idx, account)?;
            match amount {
                Some(a) => Ok(Tokens::from_e8s(a)),
                None => Ok(Tokens::ZERO),
            }
        } else {
            Err(BlockStoreError::NotAvailable(*block_idx))
        }
    }

    pub fn get_hashed_block_range(
        &self,
        range: std::ops::Range<BlockIndex>,
    ) -> Result<Vec<HashedBlock>, BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        if range.end > range.start
            && database_access::contains_block(&mut *connection, &range.start).unwrap_or(false)
        {
            let mut stmt = connection
                .prepare(
                    "SELECT hash, block, parent_hash, idx FROM blocks WHERE idx >= ? AND idx < ?",
                )
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
        } else {
            Err(BlockStoreError::Other(format!(
                "Given block range {}-{} is not allowed or not found in the block store",
                range.start, range.end
            )))
        }
    }

    pub fn push(&mut self, hb: &HashedBlock) -> Result<(), BlockStoreError> {
        let mut con = self.connection.lock().unwrap();
        con.execute_batch("BEGIN TRANSACTION;")
            .map_err(|e| BlockStoreError::Other(format!("{}", e)))?;
        database_access::push_hashed_block(&mut con, hb)?;
        database_access::push_transaction(
            &mut *con,
            &Block::decode(hb.block.clone()).unwrap().transaction,
            &hb.index,
        )?;
        database_access::update_balance_book(&mut *con, hb)?;
        con.execute_batch("COMMIT TRANSACTION;")
            .map_err(|e| BlockStoreError::Other(format!("{}", e)))?;
        drop(con);
        self.sanity_check(hb)?;
        Ok(())
    }
    pub fn get_all_accounts(&self) -> Result<Vec<AccountIdentifier>, BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        database_access::get_all_accounts(&mut *connection)
    }

    pub fn push_batch(&mut self, batch: Vec<HashedBlock>) -> Result<(), BlockStoreError> {
        let connection = self.connection.lock().unwrap();
        connection
            .execute_batch("BEGIN TRANSACTION;")
            .map_err(|e| BlockStoreError::Other(format!("{}", e)))?;
        let mut stmt_hb =  connection .prepare("INSERT INTO blocks (hash, block, parent_hash, idx, verified) VALUES (?1, ?2, ?3, ?4, FALSE)")
        .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        let mut stmt_tx = connection .prepare("INSERT INTO transactions (block_idx,tx_hash,operation_type,from_account,to_account,amount,fee) VALUES (?1, ?2, ?3, ?4, ?5,?6,?7)")
        .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        let mut stmt_select =  connection
        .prepare("SELECT block_idx,account,tokens FROM account_balances WHERE account=?1 AND block_idx<=?2 ORDER BY block_idx DESC LIMIT 1")
        .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        let mut stmt_insert = connection
            .prepare("INSERT INTO account_balances (block_idx,account,tokens) VALUES (?1,?2,?3)")
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;

        for hb in &batch {
            match database_access::push_hashed_block_execution(hb, &mut stmt_hb) {
                Ok(_) => (),
                Err(e) => {
                    connection
                        .execute_batch("ROLLBACK TRANSACTION;")
                        .map_err(|e| BlockStoreError::Other(format!("{}", e)))?;
                    return Err(e);
                }
            };
            match database_access::push_transaction_execution(
                &Block::decode(hb.block.clone()).unwrap().transaction,
                &mut stmt_tx,
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
            match database_access::update_balance_book_execution(
                hb,
                &mut stmt_select,
                &mut stmt_insert,
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

    pub fn try_prune(
        &mut self,
        max_blocks: &Option<u64>,
        prune_delay: u64,
    ) -> Result<(), BlockStoreError> {
        if let Some(block_limit) = max_blocks {
            let first_idx = self
                .get_first_hashed_block()
                .ok()
                .map(|hb| hb.index)
                .unwrap_or(0);
            let last_idx = self
                .get_latest_hashed_block()
                .ok()
                .map(|hb| hb.index)
                .unwrap_or(0);
            if first_idx + block_limit + prune_delay < last_idx {
                let new_first_idx = last_idx - block_limit;
                let hb = self.get_hashed_block(&new_first_idx).ok();
                match hb {
                    Some(b) => self.prune(&b)?,
                    None => return Err(BlockStoreError::NotFound(new_first_idx)),
                }
            }
        }
        Ok(())
    }

    pub fn set_hashed_block_to_verified(
        &self,
        block_height: &BlockIndex,
    ) -> Result<(), BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        let last_verified =
            database_access::get_latest_hashed_block(&mut *connection, Some(true)).ok();
        let last_block = database_access::get_latest_hashed_block(&mut *connection, None)?;
        match last_verified {
            Some(verified) => {
                assert!(verified.index <= *block_height);
                let height = if *block_height > last_block.index {
                    last_block.index
                } else {
                    *block_height
                };
                let mut stmt = connection
                    .prepare("UPDATE blocks SET verified = TRUE WHERE idx >= ?1 AND idx <= ?2")
                    .map_err(|e| BlockStoreError::Other(e.to_string()))?;
                stmt.execute(params![verified.index, height])
                    .map_err(|e| BlockStoreError::Other(e.to_string()))?;
                Ok(())
            }
            None => {
                let height = if *block_height > last_block.index {
                    last_block.index
                } else {
                    *block_height
                };
                let mut stmt = connection
                    .prepare("UPDATE blocks SET verified = TRUE WHERE idx <= ?")
                    .map_err(|e| BlockStoreError::Other(e.to_string()))?;
                stmt.execute(params![height])
                    .map_err(|e| BlockStoreError::Other(e.to_string()))?;
                Ok(())
            }
        }
    }
}
