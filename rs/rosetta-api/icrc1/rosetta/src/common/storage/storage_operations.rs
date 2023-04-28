use crate::common::storage::types::RosettaBlock;
use ic_ledger_core::block::EncodedBlock;
use rusqlite::{params, Params};
use rusqlite::{Connection, Statement, ToSql};
use serde_bytes::ByteBuf;

// Stores a batch of RosettaBlocks
pub fn store_blocks(
    connection: &Connection,
    rosetta_blocks: Vec<RosettaBlock>,
) -> anyhow::Result<()> {
    connection.execute_batch("BEGIN TRANSACTION;")?;
    let mut stmt_blocks = connection.prepare(
        "INSERT OR IGNORE INTO blocks (idx, hash, serialized_block, parent_hash) VALUES (?1, ?2, ?3, ?4)",
    )?;
    for rosetta_block in rosetta_blocks.into_iter() {
        match execute(
            &mut stmt_blocks,
            params![
                rosetta_block.index,
                rosetta_block.block_hash.as_slice().to_vec(),
                rosetta_block.encoded_block.into_vec(),
                rosetta_block
                    .parent_hash
                    .map(|hash| hash.as_slice().to_vec())
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

// Exectures a constructed statement
fn execute(stmt: &mut Statement, params: &[&dyn ToSql]) -> anyhow::Result<()> {
    stmt.execute(params)
        .map_err(|e| anyhow::Error::msg(e.to_string()))?;
    Ok(())
}
