use crate::common::storage::types::{MetadataEntry, RosettaBlock};
use anyhow::{anyhow, bail};
use candid::Principal;
use ic_icrc1::{Operation, Transaction};
use ic_icrc1_tokens_u64::U64;
use ic_ledger_core::block::EncodedBlock;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::Memo;
use rusqlite::{params, Params};
use rusqlite::{Connection, Statement, ToSql};
use serde_bytes::ByteBuf;

type Tokens = U64;

pub fn store_metadata(connection: &Connection, metadata: Vec<MetadataEntry>) -> anyhow::Result<()> {
    connection.execute_batch("BEGIN TRANSACTION;")?;

    let mut stmt_metadata = connection.prepare("INSERT INTO metadata (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = excluded.value;")?;

    for entry in metadata.into_iter() {
        match execute(&mut stmt_metadata, params![entry.key.clone(), entry.value]) {
            Ok(_) => (),
            Err(e) => {
                connection.execute_batch("ROLLBACK TRANSACTION;")?;
                return Err(e);
            }
        };
    }

    connection.execute_batch("COMMIT TRANSACTION;")?;
    Ok(())
}

pub fn get_metadata(connection: &Connection) -> anyhow::Result<Vec<MetadataEntry>> {
    let mut stmt_metadata = connection.prepare("SELECT key, value FROM metadata")?;
    let rows = stmt_metadata.query_map(params![], |row| {
        Ok(MetadataEntry {
            key: row.get(0)?,
            value: row.get(1)?,
        })
    })?;
    let mut result = vec![];
    for row in rows {
        let entry = row?;
        result.push(entry);
    }
    Ok(result)
}

// Stores a batch of RosettaBlocks
pub fn store_blocks(
    connection: &Connection,
    rosetta_blocks: Vec<RosettaBlock>,
) -> anyhow::Result<()> {
    connection.execute_batch("BEGIN TRANSACTION;")?;
    let mut stmt_blocks = connection.prepare(
        "INSERT OR IGNORE INTO blocks (idx, hash, serialized_block, parent_hash, timestamp) VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;

    let mut stmt_transactions = connection.prepare(
        "INSERT OR IGNORE INTO transactions (block_idx,tx_hash,operation_type,from_principal,from_subaccount,to_principal,to_subaccount,spender_principal,spender_subaccount,memo,amount,expected_allowance,fee,transaction_created_at_time,approval_expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,?14,?15)",
    )?;
    for rosetta_block in rosetta_blocks.into_iter() {
        match execute(
            &mut stmt_blocks,
            params![
                rosetta_block.index,
                rosetta_block.block_hash.as_slice().to_vec(),
                rosetta_block.encoded_block.clone().into_vec(),
                rosetta_block
                    .parent_hash
                    .clone()
                    .map(|hash| hash.as_slice().to_vec()),
                rosetta_block.timestamp
            ],
        ) {
            Ok(_) => (),
            Err(e) => {
                connection.execute_batch("ROLLBACK TRANSACTION;")?;
                return Err(e);
            }
        };

        let transaction = rosetta_block.get_transaction()?;
        let (
            operation_type,
            from_principal,
            from_subaccount,
            to_principal,
            to_subaccount,
            spender_principal,
            spender_subaccount,
            amount,
            expected_allowance,
            fee,
            approval_expires_at,
        ) = match transaction.operation {
            ic_icrc1::Operation::Mint { to, amount } => (
                "mint",
                None,
                None,
                Some(to.owner),
                to.subaccount,
                None,
                None,
                amount,
                None,
                None,
                None,
            ),
            ic_icrc1::Operation::Transfer {
                from,
                to,
                amount,
                fee,
                ..
            } => (
                "transfer",
                Some(from.owner),
                from.subaccount,
                Some(to.owner),
                to.subaccount,
                None,
                None,
                amount,
                None,
                fee,
                None,
            ),
            ic_icrc1::Operation::Burn { from, amount, .. } => (
                "burn",
                Some(from.owner),
                from.subaccount,
                None,
                None,
                None,
                None,
                amount,
                None,
                None,
                None,
            ),
            ic_icrc1::Operation::Approve {
                from,
                spender,
                amount,
                expected_allowance,
                expires_at,
                fee,
            } => (
                "approve",
                Some(from.owner),
                from.subaccount,
                None,
                None,
                Some(spender.owner),
                spender.subaccount,
                amount,
                expected_allowance,
                fee,
                expires_at,
            ),
        };

        match execute(
            &mut stmt_transactions,
            params![
                rosetta_block.index,
                rosetta_block.transaction_hash.as_slice().to_vec(),
                operation_type,
                from_principal.map(|x| x.as_slice().to_vec()),
                from_subaccount,
                to_principal.map(|x| x.as_slice().to_vec()),
                to_subaccount,
                spender_principal.map(|x| x.as_slice().to_vec()),
                spender_subaccount,
                transaction.memo.map(|x| x.0.as_slice().to_vec()),
                amount.to_u64(),
                expected_allowance.map(Tokens::to_u64),
                fee.map(Tokens::to_u64),
                transaction.created_at_time,
                approval_expires_at
            ],
        ) {
            Ok(_) => (),
            Err(e) => {
                connection.execute_batch("ROLLBACK TRANSACTION;")?;
                return Err(e);
            }
        };
    }
    connection.execute_batch("COMMIT TRANSACTION;")?;
    Ok(())
}

// Returns a RosettaBlock if the block index exists in the database, else returns None.
// Returns an Error if the query fails.
pub fn get_block_at_idx(
    connection: &Connection,
    block_idx: u64,
) -> anyhow::Result<Option<RosettaBlock>> {
    let command = format!(
        "SELECT idx,serialized_block FROM blocks WHERE idx = {}",
        block_idx
    );
    let mut stmt = connection.prepare(&command)?;
    read_single_block(&mut stmt, params![])
}

// Returns a RosettaBlock if the block hash exists in the database, else returns None.
// Returns an Error if the query fails.
pub fn get_block_by_hash(
    connection: &Connection,
    hash: ByteBuf,
) -> anyhow::Result<Option<RosettaBlock>> {
    let mut stmt = connection.prepare("SELECT idx,serialized_block FROM blocks WHERE hash = ?1")?;
    read_single_block(&mut stmt, params![hash.as_slice().to_vec()])
}

pub fn get_block_with_highest_block_idx(
    connection: &Connection,
) -> anyhow::Result<Option<RosettaBlock>> {
    let command = "SELECT idx,serialized_block FROM blocks ORDER BY idx DESC LIMIT 1";
    let mut stmt = connection.prepare(command)?;
    read_single_block(&mut stmt, params![])
}

pub fn get_block_with_lowest_block_idx(
    connection: &Connection,
) -> anyhow::Result<Option<RosettaBlock>> {
    let command = "SELECT idx,serialized_block FROM blocks ORDER BY idx ASC LIMIT 1";
    let mut stmt = connection.prepare(command)?;
    read_single_block(&mut stmt, params![])
}

pub fn get_blocks_by_index_range(
    connection: &Connection,
    start_index: u64,
    end_index: u64,
) -> anyhow::Result<Vec<RosettaBlock>> {
    let command = "SELECT idx,serialized_block FROM blocks WHERE idx>= ?1 AND idx<=?2";
    let mut stmt = connection.prepare(command)?;
    read_blocks(&mut stmt, params![start_index, end_index])
}

pub fn get_blockchain_gaps(
    connection: &Connection,
) -> anyhow::Result<Vec<(RosettaBlock, RosettaBlock)>> {
    // If there exists a gap in the stored blockchain from (a,b) then this query will return all blocks which represent b in all the gaps that exist in the database
    let command =  "SELECT b1.idx,b1.serialized_block FROM blocks b1 LEFT JOIN blocks b2 ON b1.idx = b2.idx +1 WHERE b2.idx IS NULL AND b1.idx > (SELECT idx from blocks ORDER BY idx ASC LIMIT 1) ORDER BY b1.idx ASC";
    let mut stmt = connection.prepare(command)?;
    let upper_gap_limits = read_blocks(&mut stmt, params![])?;

    // If there exists a gap in the stored blockchain from (a,b) then this query will return all blocks which represent a in all the gaps that exist in the database
    let command =  "SELECT b1.idx,b1.serialized_block FROM  blocks b1 LEFT JOIN blocks b2 ON b1.idx + 1 = b2.idx WHERE b2.idx IS NULL AND b1.idx < (SELECT idx from blocks ORDER BY idx DESC LIMIT 1) ORDER BY b1.idx ASC";
    let mut stmt = connection.prepare(command)?;
    let lower_gap_limits = read_blocks(&mut stmt, params![])?;

    // Both block vectors are ordered and since a gap always has a upper and lower end, both vectors will have the same length.
    // If U is the vector of upper limits and L of lower limits then the first gap in the blockchain is (L[0],U[0]) the second gap is (L[1],U[1]) ...
    Ok(lower_gap_limits
        .into_iter()
        .zip(upper_gap_limits.into_iter())
        .collect())
}

// Returns a icrc1 Transaction if the block index exists in the database, else returns None.
// Returns an Error if the query fails.
pub fn get_transaction_at_idx(
    connection: &Connection,
    block_idx: u64,
) -> anyhow::Result<Option<Transaction<Tokens>>> {
    let command = format!("SELECT * FROM transactions WHERE block_idx = {}", block_idx);
    let mut stmt = connection.prepare(&command)?;
    read_single_transaction(&mut stmt, params![])
}

// Returns icrc1 Transactions if the transaction hash exists in the database, else returns None.
// Returns an Error if the query fails.
pub fn get_transactions_by_hash(
    connection: &Connection,
    hash: ByteBuf,
) -> anyhow::Result<Vec<Transaction<Tokens>>> {
    let mut stmt = connection.prepare("SELECT * FROM transactions WHERE tx_hash = ?1")?;
    read_transactions(&mut stmt, params![hash.as_slice().to_vec()])
}

fn read_single_block<P>(stmt: &mut Statement, params: P) -> anyhow::Result<Option<RosettaBlock>>
where
    P: Params,
{
    let blocks: Vec<RosettaBlock> = read_blocks(stmt, params)?;
    if blocks.len() == 1 {
        // Return the block if only one block was found
        Ok(Some(blocks[0].clone()))
    } else if blocks.is_empty() {
        // Return None if no block was found
        Ok(None)
    } else {
        // If more than one block was found return an error
        Err(anyhow::Error::msg(
            "Multiple blocks found with given parameters".to_owned(),
        ))
    }
}

// Executes the constructed statement that reads blocks. The statement expects two values: The serialized Block and the index of that block
fn read_blocks<P>(stmt: &mut Statement, params: P) -> anyhow::Result<Vec<RosettaBlock>>
where
    P: Params,
{
    let blocks = stmt.query_map(params, |row| {
        row.get(1).map(|x| {
            RosettaBlock::from_encoded_block(
                EncodedBlock::from_vec(x),
                row.get(0).map_err(|e| anyhow::Error::msg(e.to_string()))?,
            )
            .map_err(|e| anyhow::Error::msg(e.to_string()))
        })
    })?;
    let mut result = vec![];
    for block in blocks {
        result.push(block??);
    }
    Ok(result)
}

fn read_single_transaction<P>(
    stmt: &mut Statement,
    params: P,
) -> anyhow::Result<Option<Transaction<Tokens>>>
where
    P: Params,
{
    let transactions: Vec<Transaction<Tokens>> = read_transactions(stmt, params)?;
    if transactions.len() == 1 {
        // Return the block if only one block was found
        Ok(transactions.into_iter().next())
    } else if transactions.is_empty() {
        // Return None if no block was found
        Ok(None)
    } else {
        // If more than one block was found return an error
        bail!("Multiple transactions found with given parameters")
    }
}

// Executes the constructed statement that reads transactions.
fn read_transactions<P>(stmt: &mut Statement, params: P) -> anyhow::Result<Vec<Transaction<Tokens>>>
where
    P: Params,
{
    fn opt_bytes_to_principal(bytes: Option<Vec<u8>>) -> Option<Principal> {
        Some(Principal::from_slice(bytes?.as_slice()))
    }
    fn opt_bytes_to_memo(bytes: Option<Vec<u8>>) -> Option<Memo> {
        Some(Memo(ByteBuf::from(bytes?)))
    }

    let rows = stmt.query_map(params, |row| {
        Ok((
            row.get::<usize, String>(2)?,
            row.get(3).map(opt_bytes_to_principal)?,
            row.get(4)?,
            row.get(5).map(opt_bytes_to_principal)?,
            row.get(6)?,
            row.get(7).map(opt_bytes_to_principal)?,
            row.get(8)?,
            row.get(9).map(opt_bytes_to_memo)?,
            row.get(10)?,
            row.get::<usize, Option<u64>>(11)?,
            row.get::<usize, Option<u64>>(12)?,
            row.get::<usize, Option<u64>>(13)?,
            row.get::<usize, Option<u64>>(14)?,
        ))
    })?;
    let mut result = vec![];
    for row in rows {
        let (
            operation_type,
            maybe_from_principal,
            from_subaccount,
            maybe_to_principal,
            to_subaccount,
            maybe_spender_principal,
            spender_subaccount,
            memo,
            amount,
            expected_allowance,
            fee,
            transaction_created_at_time,
            approval_expires_at,
        ) = row?;
        result.push(Transaction {
            operation: match operation_type.as_str() {
                "mint" => Operation::Mint {
                    to: Account {
                        owner: maybe_to_principal.ok_or_else(|| {
                            anyhow!("a mint transaction is missing the to_principal field")
                        })?,
                        subaccount: to_subaccount,
                    },
                    amount: Tokens::new(amount),
                },
                "transfer" => Operation::Transfer {
                    from: Account {
                        owner: maybe_from_principal.ok_or_else(|| {
                            anyhow!("a transfer transaction is missing the from_principal field")
                        })?,
                        subaccount: from_subaccount,
                    },
                    to: Account {
                        owner: maybe_to_principal.ok_or_else(|| {
                            anyhow!("a transfer transaction is missing the to_principal field")
                        })?,
                        subaccount: to_subaccount,
                    },
                    spender: None,
                    amount: Tokens::new(amount),
                    fee: fee.map(Tokens::new),
                },
                "burn" => Operation::Burn {
                    from: Account {
                        owner: maybe_from_principal.ok_or_else(|| {
                            anyhow!("a burn transaction is missing the from_principal field")
                        })?,
                        subaccount: from_subaccount,
                    },
                    spender: None,
                    amount: Tokens::new(amount),
                },
                "approve" => Operation::Approve {
                    from: Account {
                        owner: maybe_from_principal.ok_or_else(|| {
                            anyhow!("an approve transaction is missing the from_principal field")
                        })?,
                        subaccount: from_subaccount,
                    },
                    spender: Account {
                        owner: maybe_spender_principal.ok_or_else(|| {
                            anyhow!("an approve transaction is missing the spender_principal field")
                        })?,
                        subaccount: spender_subaccount,
                    },
                    amount: Tokens::new(amount),
                    expected_allowance: expected_allowance.map(Tokens::new),
                    expires_at: approval_expires_at,
                    fee: fee.map(Tokens::new),
                },
                k => bail!("Operation type {} is not supported", k),
            },
            memo,
            created_at_time: transaction_created_at_time,
        });
    }
    Ok(result)
}

// Executes a constructed statement
fn execute(stmt: &mut Statement, params: &[&dyn ToSql]) -> anyhow::Result<()> {
    stmt.execute(params)
        .map_err(|e| anyhow::Error::msg(e.to_string()))?;
    Ok(())
}
