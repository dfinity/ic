use crate::rosetta_block::RosettaBlock;
use crate::{iso8601_to_timestamp, timestamp_to_iso8601};
use ic_ledger_canister_core::ledger::LedgerTransaction;
use ic_ledger_core::block::{BlockIndex, BlockType, EncodedBlock};
use ic_ledger_core::tokens::CheckedAdd;
use ic_ledger_hash_of::HashOf;
use icp_ledger::{AccountIdentifier, Block, TimeStamp, Tokens, Transaction};
use rusqlite::{named_params, params, CachedStatement, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::convert::TryInto;
use std::path::Path;
use std::sync::Mutex;
use tracing::info;

mod database_access {
    use super::{sql_bytes_to_block, vec_into_array};
    use crate::{
        blocks::{BlockStoreError, HashedBlock},
        timestamp_to_iso8601,
    };
    use ic_ledger_canister_core::ledger::LedgerTransaction;
    use ic_ledger_core::{
        block::{BlockType, EncodedBlock},
        Tokens,
    };
    use ic_ledger_hash_of::HashOf;
    use icp_ledger::{AccountIdentifier, Block, Operation};
    use rusqlite::{named_params, params, Connection, Statement};

    pub fn push_hashed_block(
        con: &mut Connection,
        hb: &HashedBlock,
    ) -> Result<(), BlockStoreError> {
        let mut stmt = con.prepare("INSERT INTO blocks (block_hash, encoded_block, parent_hash, block_idx, verified, timestamp, tx_hash, operation_type, from_account, to_account, spender_account, amount, allowance, expected_allowance, fee, created_at_time, expires_at, memo, icrc1_memo) VALUES (
            :block_hash, :encoded_block, :parent_hash, :block_idx, FALSE, :timestamp, :tx_hash, :operation_type, :from_account, :to_account, :spender_account, :amount, :allowance, :expected_allowance, :fee, :created_at_time, :expires_at, :memo, :icrc1_memo
            )").map_err(|e| BlockStoreError::Other(e.to_string()))?;
        execute_insert_block_statement(&mut stmt, hb)
    }

    pub fn execute_insert_block_statement(
        stmt: &mut Statement,
        hb: &HashedBlock,
    ) -> Result<(), BlockStoreError> {
        let tx = Block::decode(hb.block.clone())
            .map_err(|e| BlockStoreError::Other(e.to_string()))?
            .transaction;
        let operation_type = tx.operation.clone();
        let mut from_account = None;
        let mut to_account = None;
        let mut spender_account = None;
        let mut amount: Option<String> = None;
        let mut allowance = None;
        let mut expected_allowance = None;
        let mut expires_at = None;
        let mut fee = None;

        match operation_type {
            Operation::Burn {
                from, amount: a, ..
            } => {
                from_account = Some(from.to_hex());
                amount = Some(a.get_e8s().to_string());
            }
            Operation::Mint { to, amount: a } => {
                amount = Some(a.get_e8s().to_string());
                to_account = Some(to.to_hex());
            }
            Operation::Approve {
                from,
                spender,
                allowance: al,
                expected_allowance: eal,
                expires_at: ea,
                fee: f,
            } => {
                from_account = Some(from.to_hex());
                allowance = Some(al.get_e8s().to_string());
                expected_allowance = eal.map(|eal| eal.get_e8s().to_string());
                spender_account = Some(spender.to_hex());
                expires_at = ea.map(timestamp_to_iso8601);
                fee = Some(f.get_e8s().to_string());
            }
            Operation::Transfer {
                from,
                to,
                amount: a,
                fee: f,
                spender,
            } => {
                from_account = Some(from.to_hex());
                amount = Some(a.get_e8s().to_string());
                to_account = Some(to.to_hex());
                fee = Some(f.get_e8s().to_string());
                spender_account = spender.map(|sp| sp.to_hex());
            }
        };
        let params = named_params! {
            ":block_hash": hb.hash.into_bytes().to_vec(),
            ":encoded_block": hb.block.clone().into_vec(),
            ":parent_hash": hb.parent_hash.map(|ph| ph.into_bytes().to_vec()),
            ":block_idx": hb.index,
            ":timestamp": timestamp_to_iso8601(hb.timestamp),
            ":tx_hash": tx.hash().into_bytes().to_vec(),
            ":operation_type": <Operation as Into<&str>>::into(operation_type),
            ":from_account": from_account,
            ":to_account": to_account,
            ":spender_account": spender_account,
            ":amount": amount,
            ":allowance": allowance,
            ":expected_allowance": expected_allowance,
            ":fee": fee,
            ":created_at_time": tx.created_at_time.map(timestamp_to_iso8601),
            ":expires_at": expires_at,
            ":memo": tx.memo.0.to_string(),
            ":icrc1_memo": tx.icrc1_memo.as_ref().map(|memo| memo.to_vec()),
        };
        stmt.execute(params)
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        Ok(())
    }

    pub fn get_all_block_indices_from_blocks_table(
        connection: &mut Connection,
    ) -> Result<Vec<u64>, BlockStoreError> {
        let mut stmt = connection
            .prepare("SELECT block_idx from blocks")
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
            .prepare("SELECT Null FROM blocks WHERE block_idx = ?")
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
        let command = "SELECT encoded_block from blocks where block_idx = ?";
        let mut stmt = connection
            .prepare(command)
            .map_err(|e| BlockStoreError::Other(e.to_string()))
            .unwrap();
        let mut transactions = stmt
            .query_map(params![block_idx], |row| {
                row.get(0)
                    .and_then(sql_bytes_to_block)
                    .map(|b| b.transaction)
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
        let mut statement = con
            .prepare_cached(
                r#"SELECT block_hash, encoded_block, parent_hash, block_idx, timestamp
                   FROM blocks
                   WHERE block_idx = :block_idx"#,
            )
            .map_err(|e| format!("Unable to prepare statement: {e:?}"))?;
        let mut blocks = statement
            .query_map(named_params! { ":block_idx": block_idx }, |row| {
                HashedBlock::try_from(row)
            })
            .map_err(|e| format!("Unable to query hashed block {block_idx}: {e:?}"))?;
        match blocks.next() {
            Some(block) => block.map_err(|e| BlockStoreError::Other(e.to_string())),
            None => Err(BlockStoreError::NotFound(*block_idx)),
        }
    }

    pub fn read_hashed_blocks<P>(
        stmt: &mut Statement,
        params: P,
    ) -> Result<Vec<HashedBlock>, BlockStoreError>
    where
        P: rusqlite::Params,
    {
        stmt.query_map(params, |row| HashedBlock::try_from(row))
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<HashedBlock>, rusqlite::Error>>()
            .map_err(|e| BlockStoreError::Other(e.to_string()))
    }

    pub fn get_transaction_hash(
        connection: &mut Connection,
        block_idx: &u64,
    ) -> Result<Option<HashOf<icp_ledger::Transaction>>, BlockStoreError> {
        let command = "SELECT tx_hash from blocks where block_idx = ?";
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
    ) -> Result<Vec<u64>, BlockStoreError> {
        let mut stmt = connection
            .prepare("SELECT block_idx from blocks where tx_hash = ?")
            .map_err(|e| BlockStoreError::Other(e.to_string()))
            .unwrap();
        let mut rows = stmt
            .query(params![&hash.into_bytes().to_vec()])
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;

        let mut result = vec![];
        while let Some(row) = rows.next().unwrap() {
            let block_idx: u64 = row
                .get(0)
                .map_err(|e| BlockStoreError::Other(e.to_string()))?;
            result.push(block_idx);
        }
        Ok(result)
    }

    pub fn get_block_idx_by_block_hash(
        connection: &mut Connection,
        hash: &HashOf<EncodedBlock>,
    ) -> Result<u64, BlockStoreError> {
        let mut stmt = connection
            .prepare("SELECT block_idx from blocks where block_hash = ?")
            .map_err(|e| BlockStoreError::Other(e.to_string()))
            .unwrap();
        let block_idx = stmt
            .query_map(params![&hash.into_bytes().to_vec()], |row| {
                Ok(row.get(0).unwrap())
            })
            .unwrap()
            .next()
            .ok_or_else(|| BlockStoreError::Other("Hash Not Found".to_string()))
            .map(|block| block.unwrap())?;
        Ok(block_idx)
    }
    // The option is left None if both verified and unverified blocks should be querried. It is set to False for only unverified blocks and True for only verified blocks
    pub fn get_first_hashed_block(
        con: &mut Connection,
        verified: Option<bool>,
    ) -> Result<HashedBlock, BlockStoreError> {
        let mut stmt = con.prepare_cached(&match verified {
            Some(verified) => format!("SELECT block_hash, encoded_block, parent_hash, block_idx, timestamp from blocks WHERE verified = {} ORDER BY block_idx ASC Limit 2",verified),
            None => "SELECT block_hash, encoded_block, parent_hash, block_idx, timestamp from blocks ORDER BY block_idx ASC Limit 2".to_string()
        }).map_err(|e| BlockStoreError::Other(e.to_string()))?;
        let mut blocks = read_hashed_blocks(&mut stmt, params![])?.into_iter();
        match blocks.next() {
            Some(genesis_block) => match blocks.next() {
                Some(first_block) => {
                    if first_block.index > 1 {
                        Ok(first_block)
                    } else {
                        Ok(genesis_block)
                    }
                }
                None => Ok(genesis_block),
            },
            None => Err(BlockStoreError::Other("Blockchain is empty".to_string())),
        }
    }
    // The option is left None if both verified and unverified blocks should be querried. It is set to False for only unverified blocks and True for only verified blocks

    pub fn get_latest_hashed_block(
        con: &mut Connection,
        verified: Option<bool>,
    ) -> Result<HashedBlock, BlockStoreError> {
        let mut stmt = con.prepare_cached(&match verified {
            Some(verified) => format!("SELECT block_hash, encoded_block, parent_hash, block_idx, timestamp from blocks WHERE verified = {} ORDER BY block_idx DESC Limit 1",verified),
            None => "SELECT block_hash, encoded_block, parent_hash, block_idx, timestamp from blocks ORDER BY block_idx DESC Limit 1".to_string()
        }).map_err(|e| BlockStoreError::Other(e.to_string()))?;
        let mut blocks = read_hashed_blocks(&mut stmt, params![])?.into_iter();
        match blocks.next() {
            Some(first_block) => Ok(first_block),
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
                        Ok((row.get(1).map(|x: String| x as String)?, row.get(2)?))
                    })
                    .map_err(|e| BlockStoreError::Other(e.to_string()))?
                    .map(|x| x.unwrap())
                    .next();
                Ok(account_balance_opt)
            };
        match operation_type {
            Operation::Burn { from, amount, .. } => {
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
            Operation::Approve { from, fee, .. } => {
                let account_balance_opt = extract_latest_balance(from)?;

                let make_error = || {
                    Err(BlockStoreError::Other(format!(
                        "Account {} does not have enough funds to pay for an approval",
                        from
                    )))
                };

                match account_balance_opt {
                    Some(mut balance) => {
                        if balance.1 < fee.get_e8s() {
                            return make_error();
                        }
                        balance.1 -= fee.get_e8s();
                        new_balances.push(balance);
                    }
                    None => {
                        return make_error();
                    }
                }
            }
            Operation::Transfer {
                from,
                to,
                amount,
                fee,
                ..
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
            let account: String = row
                .get(0)
                .map_err(|e| BlockStoreError::Other(e.to_string()))?;
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
                .query_map(params![block_idx, acc], |row| Ok(row.get(0).unwrap()))
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
                Ok((row.get(0)?, row.get(1).map(Tokens::from_e8s)?))
            })
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        for tuple in account_history {
            result.push(tuple.unwrap());
        }
        Ok(result)
    }

    pub fn is_verified(con: &mut Connection, block_idx: &u64) -> Result<bool, BlockStoreError> {
        let command = "SELECT null from blocks WHERE verified=TRUE AND block_idx=?";
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
    pub timestamp: TimeStamp,
}

impl HashedBlock {
    pub fn hash_block(
        block: EncodedBlock,
        parent_hash: Option<HashOf<EncodedBlock>>,
        index: BlockIndex,
        timestamp: TimeStamp,
    ) -> HashedBlock {
        HashedBlock {
            hash: Block::block_hash(&block),
            block,
            parent_hash,
            index,
            timestamp,
        }
    }
}

impl TryFrom<&Row<'_>> for HashedBlock {
    type Error = rusqlite::Error;

    fn try_from(row: &Row) -> Result<HashedBlock, Self::Error> {
        Ok(HashedBlock {
            hash: row.get(0).map(|bytes| HashOf::new(vec_into_array(bytes)))?,
            block: row.get(1).map(EncodedBlock::from_vec)?,
            parent_hash: row.get(2).map(|opt_bytes: Option<Vec<u8>>| {
                opt_bytes.map(|bytes| HashOf::new(vec_into_array(bytes)))
            })?,
            index: row.get(3)?,
            timestamp: iso8601_to_timestamp(row.get(4)?),
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum BlockStoreError {
    NotFound(BlockIndex),
    NotAvailable(BlockIndex),
    Other(String),
}

impl From<String> for BlockStoreError {
    fn from(error: String) -> Self {
        Self::Other(error)
    }
}

fn vec_into_array(v: Vec<u8>) -> [u8; 32] {
    let ba: Box<[u8; 32]> = match v.into_boxed_slice().try_into() {
        Ok(ba) => ba,
        Err(v) => panic!("Expected a Vec of length 32 but it was {}", v.len()),
    };
    *ba
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum RosettaBlocksMode {
    Disabled,
    Enabled { first_rosetta_block_index: u64 },
}

pub struct Blocks {
    connection: Mutex<rusqlite::Connection>,
    pub rosetta_blocks_mode: RosettaBlocksMode,
}

impl Blocks {
    pub fn new_persistent(
        location: &Path,
        enable_rosetta_blocks: bool,
    ) -> Result<Self, BlockStoreError> {
        std::fs::create_dir_all(location)
            .expect("Unable to create directory for SQLite on-disk store.");
        let path = location.join("db.sqlite");
        let connection =
            rusqlite::Connection::open(path).expect("Unable to open SQLite database connection");
        Self::new(connection, enable_rosetta_blocks)
    }

    /// Constructs a new SQLite in-memory store.
    pub fn new_in_memory(enable_rosetta_blocks: bool) -> Result<Self, BlockStoreError> {
        let connection = rusqlite::Connection::open_in_memory()
            .expect("Unable to open SQLite in-memory database connection");
        Self::new(connection, enable_rosetta_blocks)
    }

    fn new(
        connection: rusqlite::Connection,
        enable_rosetta_blocks: bool,
    ) -> Result<Self, BlockStoreError> {
        let mut store = Self {
            connection: Mutex::new(connection),
            rosetta_blocks_mode: RosettaBlocksMode::Disabled,
        };
        store
            .connection
            .lock()
            .unwrap()
            .execute("PRAGMA foreign_keys = 1", [])
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        store.create_tables(enable_rosetta_blocks).map_err(|e| {
            BlockStoreError::Other(format!("Failed to initialize SQLite database: {}", e))
        })?;
        store.cache_rosetta_blocks_mode().map_err(|e| {
            BlockStoreError::Other(format!(
                "Failed to determine the Rosetta Blocks Mode: {}",
                e
            ))
        })?;

        store.check_table_coherence()?;
        Ok(store)
    }

    fn create_tables(&self, enable_rosetta_blocks: bool) -> Result<(), rusqlite::Error> {
        let mut connection = self.connection.lock().unwrap();
        let tx = connection.transaction()?;
        tx.execute(
            r#"
            CREATE TABLE IF NOT EXISTS blocks (
                block_hash BLOB NOT NULL,
                encoded_block BLOB NOT NULL,
                parent_hash BLOB,
                block_idx INTEGER NOT NULL PRIMARY KEY,
                verified BOOLEAN,
                timestamp TEXT,
                tx_hash BLOB NOT NULL,
                operation_type VARCHAR NOT NULL,
                from_account VARCHAR(64),
                to_account VARCHAR(64),
                spender_account VARCHAR(64),
                amount TEXT,
                allowance TEXT,
                expected_allowance TEXT,
                fee TEXT,
                created_at_time TEXT,
                expires_at TEXT,
                memo TEXT,
                icrc1_memo BLOB
            )
            "#,
            [],
        )?;

        tx.execute(
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
        if enable_rosetta_blocks {
            // Use two tables for Rosetta Blocks. The first one contains
            // the metadata of the block while second one contains the
            // mapping Rosetta Block Index <-> Block Index
            tx.execute(
                r#"
                CREATE TABLE IF NOT EXISTS rosetta_blocks (
                    rosetta_block_idx INTEGER NOT NULL PRIMARY KEY,
                    parent_hash BLOB,
                    hash BLOB NOT NULL,
                    timestamp TEXT
                )
                "#,
                [],
            )?;
            tx.execute(
                r#"
                CREATE TABLE IF NOT EXISTS rosetta_blocks_transactions (
                    rosetta_block_idx INTEGER NOT NULL REFERENCES rosetta_blocks(rosetta_block_idx),
                    block_idx INTEGER NOT NULL REFERENCES blocks(block_idx),
                    PRIMARY KEY(rosetta_block_idx, block_idx)
                )
                "#,
                [],
            )?;
        }

        tx.execute(
            r#"
            CREATE INDEX IF NOT EXISTS block_idx_account_balances 
            ON account_balances(block_idx)
            "#,
            [],
        )?;

        tx.execute(
            r#"
        CREATE INDEX IF NOT EXISTS tx_hash_index 
        ON blocks(tx_hash)
        "#,
            [],
        )?;

        tx.execute(
            r#"
        CREATE INDEX IF NOT EXISTS block_hash_index 
        ON blocks(block_hash)
        "#,
            [],
        )?;

        tx.commit()
    }

    fn cache_rosetta_blocks_mode(&mut self) -> Result<(), rusqlite::Error> {
        // The Rosetta Blocks Mode is enabled if the rosetta_blocks table
        // exists.
        // See https://www.sqlite.org/fileformat2.html#storage_of_the_sql_database_schema/
        let connection = self.connection.lock().unwrap();

        // The query returns a single row if the table exists, no rows otherwise.
        // .optional() converts Err(QueryReturnedNoRows) to Ok(None)
        let is_rosetta_blocks_mode_enabled = connection
            .query_row(
                r#"SELECT 1
                   FROM sqlite_master
                   WHERE type='table'
                     AND name='rosetta_blocks'"#,
                [],
                |_| Ok(()),
            )
            .optional()
            .map(|opt| opt.is_some())?;
        if !is_rosetta_blocks_mode_enabled {
            self.rosetta_blocks_mode = RosettaBlocksMode::Disabled;
            return Ok(());
        }

        // From this point we know the table rosetta_blocks exists.
        // There are three potential states:
        //  1. if the table rosetta_blocks has at least one row then
        //     the first rosetta block index is the smallest index
        //     in that table
        //  2. else if the table blocks has at least one row then
        //     the first rosetta block index will be the highest index
        //     in the blocks table + 1, i.e. the next incoming block.
        //  3. else the first rosetta block index will be
        //     the lowest possible block index, i.e. 0.
        let first_rosetta_block_index = connection.query_row(
            "SELECT min(rosetta_block_idx) FROM rosetta_blocks",
            [],
            |row| row.get::<_, Option<u64>>(0),
        )?;
        let first_rosetta_block_index = match first_rosetta_block_index {
            Some(first_rosetta_block_index) => first_rosetta_block_index,
            None => connection
                .query_row("SELECT max(block_idx) + 1 FROM blocks", [], |row| {
                    row.get::<_, Option<u64>>(0)
                })?
                .unwrap_or(0),
        };
        info!(
            "Rosetta blocks mode enabled, first rosetta block index is {first_rosetta_block_index}"
        );
        self.rosetta_blocks_mode = RosettaBlocksMode::Enabled {
            first_rosetta_block_index,
        };
        Ok(())
    }

    pub fn prune(&mut self, hb: &HashedBlock) -> Result<(), BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        connection
            .execute_batch("BEGIN TRANSACTION;")
            .map_err(|e| BlockStoreError::Other(format!("{}", e)))?;

        database_access::prune_account_balances(&mut connection, &hb.index)?;
        connection
            .execute(
                "DELETE FROM blocks WHERE block_idx > 0 AND block_idx < ?",
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

        database_access::get_block_idx_by_block_hash(&mut connection, hash)
    }

    pub fn get_block_idxs_by_transaction_hash(
        &self,
        hash: &HashOf<icp_ledger::Transaction>,
    ) -> Result<Vec<u64>, BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        database_access::get_block_idx_by_transaction_hash(&mut connection, hash)
    }
    pub fn get_account_balance_history(
        &self,
        acc: &AccountIdentifier,
        limit_num_blocks: Option<u64>,
    ) -> Result<Vec<(u64, Tokens)>, BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        database_access::get_account_balance_history(&mut connection, acc, limit_num_blocks)
    }

    /// Sanity check (sum of tokens equal pool size).
    fn sanity_check(&self, latest_hb: &HashedBlock) -> Result<(), BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        let accounts = database_access::get_all_accounts(&mut connection)?;
        let mut total = Tokens::ZERO;
        for account in accounts {
            let amount = database_access::get_account_balance(
                &mut connection,
                &latest_hb.index.clone(),
                &account,
            )?;
            total = total
                .checked_add(&Tokens::from_e8s(amount.unwrap()))
                .unwrap();
        }
        assert!(total <= Tokens::MAX);
        Ok(())
    }

    pub fn get_transaction_hash(
        &self,
        block_idx: &u64,
    ) -> Result<Option<HashOf<icp_ledger::Transaction>>, BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();

        if database_access::contains_block(&mut connection, block_idx)? {
            database_access::get_transaction_hash(&mut connection, block_idx)
        } else {
            Err(BlockStoreError::NotAvailable(*block_idx))
        }
    }

    pub fn get_first_verified_hashed_block(&self) -> Result<HashedBlock, BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        database_access::get_first_hashed_block(&mut connection, Some(true))
    }
    pub fn get_hashed_block(&self, block_idx: &u64) -> Result<HashedBlock, BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        database_access::get_hashed_block(&mut connection, block_idx)
    }

    pub fn get_transaction(
        &self,
        block_idx: &u64,
    ) -> Result<icp_ledger::Transaction, BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        database_access::get_transaction(&mut connection, block_idx)
    }
    fn check_table_coherence(&self) -> Result<(), BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        let mut block_indices =
            database_access::get_all_block_indices_from_blocks_table(&mut connection)?;
        let mut account_balances_block_indices =
            database_access::get_all_block_indices_from_account_balances_table(&mut connection)?;
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

        block_indices.sort_by(|a, b| a.partial_cmp(b).unwrap());
        block_indices.dedup();

        account_balances_block_indices.sort_by(|a, b| a.partial_cmp(b).unwrap());
        account_balances_block_indices.dedup();
        if !block_indices.is_empty() {
            let difference_account_balances_indices: Vec<u64> = vec_sorted_diff(
                block_indices.as_mut_slice(),
                account_balances_block_indices.as_mut_slice(),
            )?;
            for missing_index in difference_account_balances_indices {
                let missing_block =
                    database_access::get_hashed_block(&mut connection, &missing_index)?;
                database_access::update_balance_book(&mut connection, &missing_block)?;
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
            true => database_access::is_verified(&mut con, &block_idx),
            false => Err(BlockStoreError::NotFound(block_idx)),
        }
    }

    pub fn is_verified_by_idx(&self, idx: &u64) -> Result<bool, BlockStoreError> {
        let mut con = self.connection.lock().unwrap();
        match database_access::contains_block(&mut con, idx)? {
            true => database_access::is_verified(&mut con, idx),
            false => Err(BlockStoreError::NotFound(*idx)),
        }
    }

    pub fn get_first_hashed_block(&self) -> Result<HashedBlock, BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        database_access::get_first_hashed_block(&mut connection, None)
    }

    pub fn get_latest_hashed_block(&self) -> Result<HashedBlock, BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        database_access::get_latest_hashed_block(&mut connection, None)
    }

    pub fn get_latest_verified_hashed_block(&self) -> Result<HashedBlock, BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        database_access::get_latest_hashed_block(&mut connection, Some(true))
    }

    pub fn get_account_balance(
        &self,
        account: &AccountIdentifier,
        block_idx: &u64,
    ) -> Result<Tokens, BlockStoreError> {
        if self.is_verified_by_idx(block_idx)? {
            let mut connection = self.connection.lock().unwrap();
            let amount = database_access::get_account_balance(&mut connection, block_idx, account)?;
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
            && database_access::contains_block(&mut connection, &range.start).unwrap_or(false)
        {
            let mut stmt = connection.prepare_cached(r#"SELECT block_hash, encoded_block, parent_hash, block_idx, timestamp FROM blocks WHERE block_idx >= :start AND block_idx < :end"#).map_err(|e| BlockStoreError::Other(e.to_string()))?;
            database_access::read_hashed_blocks(
                &mut stmt,
                named_params! {
                    ":start":range.start,
                    ":end":range.end
                },
            )
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
        database_access::update_balance_book(&mut con, hb)?;
        con.execute_batch("COMMIT TRANSACTION;")
            .map_err(|e| BlockStoreError::Other(format!("{}", e)))?;
        drop(con);
        self.sanity_check(hb)?;
        Ok(())
    }
    pub fn get_all_accounts(&self) -> Result<Vec<AccountIdentifier>, BlockStoreError> {
        let mut connection = self.connection.lock().unwrap();
        database_access::get_all_accounts(&mut connection)
    }

    pub fn push_batch(&mut self, batch: Vec<HashedBlock>) -> Result<(), BlockStoreError> {
        let connection = self.connection.lock().unwrap();
        connection
            .execute_batch("BEGIN TRANSACTION;")
            .map_err(|e| BlockStoreError::Other(format!("{}", e)))?;
        let mut stmt_hb = connection.prepare("INSERT INTO blocks (block_hash, encoded_block, parent_hash, block_idx, verified, timestamp, tx_hash, operation_type, from_account, to_account, spender_account, amount, allowance, expected_allowance, fee, created_at_time, expires_at, memo, icrc1_memo) VALUES (
            :block_hash, :encoded_block, :parent_hash, :block_idx, FALSE, :timestamp, :tx_hash, :operation_type, :from_account, :to_account, :spender_account, :amount, :allowance, :expected_allowance, :fee, :created_at_time, :expires_at, :memo, :icrc1_memo
            )").map_err(|e| BlockStoreError::Other(e.to_string()))?;
        let mut stmt_select =  connection
        .prepare("SELECT block_idx,account,tokens FROM account_balances WHERE account=?1 AND block_idx<=?2 ORDER BY block_idx DESC LIMIT 1")
        .map_err(|e| BlockStoreError::Other(e.to_string()))?;
        let mut stmt_insert = connection
            .prepare("INSERT INTO account_balances (block_idx,account,tokens) VALUES (?1,?2,?3)")
            .map_err(|e| BlockStoreError::Other(e.to_string()))?;

        for hb in &batch {
            match database_access::execute_insert_block_statement(&mut stmt_hb, hb) {
                Ok(_) => (),
                Err(e) => {
                    connection
                        .execute_batch("ROLLBACK TRANSACTION;")
                        .map_err(|e| BlockStoreError::Other(format!("{}", e)))?;
                    return Err(e);
                }
            };
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
            database_access::get_latest_hashed_block(&mut connection, Some(true)).ok();
        let last_block = database_access::get_latest_hashed_block(&mut connection, None)?;
        match last_verified {
            Some(verified) => {
                assert!(verified.index <= *block_height);
                let height = if *block_height > last_block.index {
                    last_block.index
                } else {
                    *block_height
                };
                let mut stmt = connection
                    .prepare("UPDATE blocks SET verified = TRUE WHERE block_idx >= ?1 AND block_idx <= ?2")
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
                    .prepare("UPDATE blocks SET verified = TRUE WHERE block_idx <= ?")
                    .map_err(|e| BlockStoreError::Other(e.to_string()))?;
                stmt.execute(params![height])
                    .map_err(|e| BlockStoreError::Other(e.to_string()))?;
                Ok(())
            }
        }
    }

    // Returns the index of the next Rosetta Block and of the first block
    // to be put inside the next Rosetta Block
    //
    // Note: this method requires that the rosetta blocks table exist but
    // it doesn't need them to be populated.
    fn get_next_rosetta_block_indices(
        &self,
    ) -> Result<Option<RosettaBlockIndices>, BlockStoreError> {
        let connection: std::sync::MutexGuard<rusqlite::Connection> = self
            .connection
            .lock()
            .map_err(|e| format!("Unable to acquire the connection mutex: {e:?}"))?;
        let last_rosetta_block_index: Option<BlockIndex> = connection
            .query_row(
                "SELECT max(rosetta_block_idx) FROM rosetta_blocks",
                [],
                |row| row.get(0),
            )
            .map_err(|e| format!("Unable to get the max index from the rosetta_blocks: {e:?}"))?;
        let last_rosetta_block_index = match last_rosetta_block_index {
            None => return Ok(None),
            Some(last_rosetta_block_index) => last_rosetta_block_index,
        };
        let last_block_index_in_rosetta_block: BlockIndex = connection.query_row(
            "SELECT max(block_idx) FROM rosetta_blocks_transactions WHERE rosetta_block_idx = :idx",
            named_params! { ":idx": last_rosetta_block_index },
            |row| row.get(0),
        ).map_err(|e| format!("Unable to get the max block index for the rosetta block {last_rosetta_block_index}: {e:?}"))?;
        Ok(Some(RosettaBlockIndices {
            rosetta_block_index: last_rosetta_block_index + 1,
            first_block_index: last_block_index_in_rosetta_block + 1,
        }))
    }

    pub fn make_rosetta_blocks_if_enabled(
        &self,
        certified_tip_index: BlockIndex,
    ) -> Result<(), BlockStoreError> {
        let next_block_indices = match self.rosetta_blocks_mode {
            RosettaBlocksMode::Disabled => return Ok(()),
            RosettaBlocksMode::Enabled {
                first_rosetta_block_index,
            } => self
                .get_next_rosetta_block_indices()?
                .unwrap_or(RosettaBlockIndices {
                    rosetta_block_index: first_rosetta_block_index,
                    first_block_index: first_rosetta_block_index,
                }),
        };

        // Keep track of how many rosetta blocks are being created
        let num_rosetta_blocks_created = RefCell::new(0);

        // We do not want duplicate transactions that were created in the same consensus round to be added to the same rosetta block. For this we keep track of the already added tx hashes for each rosetta block
        // We store all transactions for a single rosetta block in the values of this hashmap
        let icp_transactions_per_rosetta_block = RefCell::new(HashMap::new());

        // A list of all icp block indices that we need to convert to rosetta blocks
        let block_indices = next_block_indices.first_block_index..=certified_tip_index;

        // We fetch the first icp block to extract the timestamp, the first icp transaction and the first parent_hash of the first rosetta block created
        let current_rosetta_block_index = RefCell::new(next_block_indices.rosetta_block_index);
        let Block {
            parent_hash,
            timestamp,
            ..
        } = Block::decode(
            self.get_hashed_block(&next_block_indices.first_block_index)?
                .block,
        )?;

        let current_rosetta_block_parent_hash = RefCell::new(parent_hash);
        let current_rosetta_block_timestamp = RefCell::new(timestamp);
        let mut connection = self
            .connection
            .lock()
            .map_err(|e| format!("Unable to aquire the connection mutex: {e:?}"))?;

        let sql_tx = connection
            .transaction()
            .map_err(|e| format!("Unable to initialize a transaction: {e:?}"))?;

        let mut insert_rosetta_block_stmt = sql_tx
            .prepare_cached(
                r#"INSERT INTO rosetta_blocks (rosetta_block_idx, hash, timestamp)
                VALUES (:idx, :hash, :timestamp)"#,
            )
            .unwrap();
        let mut insert_rosetta_block_transaction_stmt = sql_tx
            .prepare_cached(
                r#"INSERT INTO rosetta_blocks_transactions (rosetta_block_idx, block_idx)
        VALUES (:idx, :block_idx)"#,
            )
            .unwrap();

        let mut select_hashed_blocks_stmt = sql_tx
            .prepare_cached(
                r#"SELECT block_hash, encoded_block, parent_hash, block_idx, timestamp
           FROM blocks WHERE block_idx >= :start AND block_idx <= :end"#,
            )
            .unwrap();

        // We cannot iterate over all blocks at once so we batch them into 100000 blocks per iteration round.
        // This way we only load 100000 blocks into memory at a time
        const ROSETTA_BLOCKS_PROCESSED_PER_ROUND: u64 = 100000;
        let mut hashed_block_idx_interval = std::ops::RangeInclusive::new(
            *block_indices.start(),
            std::cmp::min(
                *block_indices.end(),
                block_indices
                    .start()
                    .saturating_add(ROSETTA_BLOCKS_PROCESSED_PER_ROUND),
            ),
        );

        // A helper function to store the current rosetta block and reset the fields
        let mut flush_transactions =
            |current_icp_block_timestamp: TimeStamp| -> Result<(), BlockStoreError> {
                // We want the transactions to be sorted by their icp block index
                let mut transactions: Vec<(u64, Transaction)> = icp_transactions_per_rosetta_block
                    .take()
                    .into_values()
                    .collect();
                transactions.sort_by(|(idx1, _), (idx2, _)| idx1.cmp(idx2));
                let rosetta_block = RosettaBlock {
                    index: *current_rosetta_block_index.borrow(),
                    parent_hash: current_rosetta_block_parent_hash
                        .borrow()
                        .map(|hash| hash.into_bytes()),
                    timestamp: *current_rosetta_block_timestamp.borrow(),
                    transactions: transactions.into_iter().collect(),
                };

                // Set the fields to the next rosetta block
                *current_rosetta_block_index.borrow_mut() += 1;
                *num_rosetta_blocks_created.borrow_mut() += 1;
                current_rosetta_block_parent_hash.replace(Some(HashOf::new(rosetta_block.hash())));
                current_rosetta_block_timestamp.replace(current_icp_block_timestamp);
                icp_transactions_per_rosetta_block.replace(HashMap::new());

                self.store_rosetta_block(
                    rosetta_block,
                    &mut insert_rosetta_block_stmt,
                    &mut insert_rosetta_block_transaction_stmt,
                )?;
                Ok(())
            };

        loop {
            // We extract the icp block indices from the current interval
            let hashed_blocks = database_access::read_hashed_blocks(
                &mut select_hashed_blocks_stmt,
                named_params! {
                    ":start":hashed_block_idx_interval.start(),
                    ":end":hashed_block_idx_interval.end()
                },
            )?;

            for block in hashed_blocks.into_iter() {
                let transaction = Block::decode(block.block)?.transaction;
                let transaction_hash = transaction.hash();
                if icp_transactions_per_rosetta_block
                    .borrow()
                    .contains_key(&transaction_hash)
                    || block.timestamp != *current_rosetta_block_timestamp.borrow()
                {
                    // The break out criteria for when a rosetta block should be created is either when there are multiple transactions with the same transaction hash that were produced in the same consensus round (i.e. same block timestamp) or if the block timestamp changes (i.e. a new consensus round has started)
                    flush_transactions(block.timestamp)?;
                }

                (*icp_transactions_per_rosetta_block.borrow_mut())
                    .insert(transaction_hash, (block.index, transaction));
            }

            if *hashed_block_idx_interval.end() == *block_indices.end() {
                // It is possible that we have reached the end of the block indices but still have transactions that need to be added to a rosetta block
                flush_transactions(current_rosetta_block_timestamp.clone().into_inner())?;
                break;
            }

            // We update the interval to the next batch of blocks
            hashed_block_idx_interval = std::ops::RangeInclusive::new(
                hashed_block_idx_interval.end().saturating_add(1),
                std::cmp::min(
                    hashed_block_idx_interval
                        .end()
                        .saturating_add(ROSETTA_BLOCKS_PROCESSED_PER_ROUND),
                    *block_indices.end(),
                ),
            );
        }

        // We need to free up the prepared statements before we commit the transaction
        drop(insert_rosetta_block_stmt);
        drop(insert_rosetta_block_transaction_stmt);
        drop(select_hashed_blocks_stmt);
        sql_tx.commit().unwrap();

        tracing::debug!(
           "Created {} Rosetta Blocks. Ledger blocks indices {:?} added to Rosetta Blocks. Last Rosetta Block was at index {}",num_rosetta_blocks_created.into_inner(), next_block_indices.first_block_index..=certified_tip_index,current_rosetta_block_index.into_inner().saturating_sub(1));

        Ok(())
    }

    pub(crate) fn store_rosetta_block(
        &self,
        rosetta_block: RosettaBlock,
        insert_rosetta_block_stmt: &mut CachedStatement,
        insert_rosetta_block_transaction_stmt: &mut CachedStatement,
    ) -> Result<(), BlockStoreError> {
        // Store the metainfo of the rosetta block
        {
            let _ = insert_rosetta_block_stmt
                .execute(named_params! {
                    ":idx": rosetta_block.index,
                    ":hash": rosetta_block.hash(),
                    ":timestamp": timestamp_to_iso8601(rosetta_block.timestamp)
                })
                .map_err(|e| format!("Unable to insert into rosetta_blocks table: {e:?}"))?;
        }

        // Store the blocks that form this rosetta block
        {
            for block_index in rosetta_block.transactions.keys() {
                let _ = insert_rosetta_block_transaction_stmt
                    .execute(named_params! {
                        ":idx": rosetta_block.index,
                        ":block_idx": block_index,
                    })
                    .map_err(|e| {
                        format!("Unable to insert into rosetta_blocks_transactions table: {e:?}")
                    })?;
            }
        }

        Ok(())
    }

    pub fn get_rosetta_block(
        &self,
        rosetta_block_index: BlockIndex,
    ) -> Result<RosettaBlock, BlockStoreError> {
        let (parent_hash, timestamp) =
            self.get_rosetta_block_phash_timestamp(rosetta_block_index)?;
        let transactions: BTreeMap<u64, Transaction> =
            self.get_rosetta_block_transactions(rosetta_block_index)?;
        Ok(RosettaBlock {
            index: rosetta_block_index,
            parent_hash,
            timestamp,
            transactions,
        })
    }

    pub fn get_highest_rosetta_block_index(&self) -> Result<Option<u64>, BlockStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|e| format!("Unable to aquire the connection mutex: {e:?}"))?;
        let block_idx = match connection
            .prepare_cached(
                "SELECT rosetta_block_idx FROM rosetta_blocks ORDER BY rosetta_block_idx DESC LIMIT 1",
            )
            .map_err(|e| format!("Unable to prepare query: {e:?}"))?.query_map(params![], |row| 
                row.get(0)
            ).map_err(|e| BlockStoreError::Other(format!("Unable to select from rosetta_blocks: {e:?}")))?.next(){
                Some(Ok(block_idx)) => Some(block_idx),
                Some(Err(e)) => return Err(BlockStoreError::Other(e.to_string())),
                None =>  None,
            };
        Ok(block_idx)
    }

    fn get_rosetta_block_phash_timestamp(
        &self,
        rosetta_block_index: BlockIndex,
    ) -> Result<(Option<[u8; 32]>, TimeStamp), BlockStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|e| format!("Unable to aquire the connection mutex: {e:?}"))?;
        let mut statement = connection
            .prepare_cached(
                "SELECT parent_hash, timestamp FROM rosetta_blocks WHERE rosetta_block_idx=:idx",
            )
            .map_err(|e| format!("Unable to prepare query: {e:?}"))?;
        let mut blocks = statement
            .query_map(named_params! { ":idx": rosetta_block_index }, |row| {
                let parent_hash = row.get(0)?;
                let timestamp = row.get(1).map(iso8601_to_timestamp)?;
                Ok((parent_hash, timestamp))
            })
            .map_err(|e| {
                BlockStoreError::from(format!("Unable to select from rosetta_blocks: {e:?}"))
            })?;
        match blocks.next() {
            Some(block) => block.map_err(|e| BlockStoreError::Other(e.to_string())),
            None => Err(BlockStoreError::NotFound(rosetta_block_index)),
        }
    }

    fn get_rosetta_block_transactions(
        &self,
        rosetta_block_index: BlockIndex,
    ) -> Result<BTreeMap<BlockIndex, Transaction>, BlockStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|e| format!("Unable to aquire the connection mutex: {e:?}"))?;
        let mut statement = connection
            .prepare_cached(
                r#"SELECT blocks.block_idx, encoded_block
                   FROM rosetta_blocks_transactions JOIN blocks
                   ON rosetta_blocks_transactions.block_idx = blocks.block_idx
                   WHERE rosetta_blocks_transactions.rosetta_block_idx=:idx"#,
            )
            .map_err(|e| format!("Unable to select block: {e:?}"))?;
        let blocks = statement
            .query_map(named_params! { ":idx": rosetta_block_index }, |row| {
                let block_index: BlockIndex = row.get(0)?;
                let block = row.get(1).and_then(sql_bytes_to_block)?;
                Ok((block_index, block))
            })
            .map_err(|e| format!("Unable to select block: {e:?}"))?;
        let mut transactions = BTreeMap::new();
        for index_and_block in blocks {
            let (block_index, block) =
                index_and_block.map_err(|e| format!("Unable to select block: {e:?}"))?;
            let transaction = block.transaction;
            transactions.insert(block_index, transaction);
        }
        Ok(transactions)
    }

    pub fn contains_block(&self, block_idx: &BlockIndex) -> Result<bool, BlockStoreError> {
        let mut connection = self.connection.lock().map_err(|e| {
            BlockStoreError::Other(format!("Unable to acquire the connection mutex: {e:?}"))
        })?;
        database_access::contains_block(&mut connection, block_idx)
    }
}

fn sql_bytes_to_block(cell: Vec<u8>) -> Result<Block, rusqlite::Error> {
    let encoded_block = EncodedBlock::from(cell);
    Block::decode(encoded_block).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Blob,
            format!("Unable to decode block: {e:?}").into(),
        )
    })
}

struct RosettaBlockIndices {
    pub rosetta_block_index: BlockIndex,
    pub first_block_index: BlockIndex,
}

#[cfg(test)]
mod tests {
    use super::Blocks;
    use crate::rosetta_block::RosettaBlock;
    use candid::Principal;
    use ic_ledger_core::block::BlockType;
    use icp_ledger::{AccountIdentifier, Block, Memo, Operation, TimeStamp, Tokens, Transaction};

    #[test]
    fn test_store_load_rosetta_block() {
        let to = AccountIdentifier::new(ic_types::PrincipalId(Principal::anonymous()), None);
        let transaction0 = Transaction {
            operation: Operation::Mint {
                to,
                amount: Tokens::from_e8s(1),
            },
            memo: Memo(0),
            created_at_time: None,
            icrc1_memo: None,
        };
        let block0 = Block {
            parent_hash: None,
            transaction: transaction0.clone(),
            timestamp: TimeStamp::from_nanos_since_unix_epoch(1),
        };
        let encoded_block0 = block0.clone().encode();
        let hashed_block0 = crate::blocks::HashedBlock::hash_block(
            encoded_block0.clone(),
            block0.parent_hash,
            0,
            block0.timestamp,
        );
        let transaction1 = Transaction {
            operation: Operation::Mint {
                to,
                amount: Tokens::from_e8s(2),
            },
            memo: Memo(1),
            created_at_time: None,
            icrc1_memo: None,
        };
        let block1 = Block {
            parent_hash: Some(Block::block_hash(&encoded_block0)),
            transaction: transaction1.clone(),
            timestamp: TimeStamp::from_nanos_since_unix_epoch(1),
        };
        let encoded_block1 = block1.clone().encode();
        let hashed_block1 = crate::blocks::HashedBlock::hash_block(
            encoded_block1,
            block1.parent_hash,
            1,
            block1.timestamp,
        );
        let rosetta_block = RosettaBlock {
            index: 0,
            parent_hash: None,
            timestamp: TimeStamp::from_nanos_since_unix_epoch(1),
            transactions: [(0, transaction0), (1, transaction1)].into_iter().collect(),
        };

        let mut blocks = Blocks::new_in_memory(true).unwrap();
        blocks.push(&hashed_block0).unwrap();
        blocks.push(&hashed_block1).unwrap();
        let mut connection = blocks.connection.lock().unwrap();
        let transaction = connection.transaction().unwrap();

        let mut insert_rosetta_block_stmt = transaction
            .prepare_cached(
                r#"INSERT INTO rosetta_blocks (rosetta_block_idx, hash, timestamp)
        VALUES (:idx, :hash, :timestamp)"#,
            )
            .unwrap();
        let mut insert_rosetta_block_transaction_stmt = transaction
            .prepare_cached(
                r#"INSERT INTO rosetta_blocks_transactions (rosetta_block_idx, block_idx)
VALUES (:idx, :block_idx)"#,
            )
            .unwrap();

        blocks
            .store_rosetta_block(
                rosetta_block.clone(),
                &mut insert_rosetta_block_stmt,
                &mut insert_rosetta_block_transaction_stmt,
            )
            .unwrap();

        drop(insert_rosetta_block_stmt);
        drop(insert_rosetta_block_transaction_stmt);
        transaction.commit().unwrap();
        drop(connection);
        let actual_rosetta_block = blocks.get_rosetta_block(0).unwrap();
        assert_eq!(rosetta_block, actual_rosetta_block);
    }
}
