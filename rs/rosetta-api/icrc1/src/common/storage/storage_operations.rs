use crate::MetadataEntry;
use crate::common::storage::types::{RosettaBlock, RosettaCounter};
use anyhow::{Context, bail};
use candid::Nat;
use ic_base_types::PrincipalId;
use ic_ledger_core::tokens::Zero;
use ic_ledger_core::tokens::{CheckedAdd, CheckedSub};
use icrc_ledger_types::icrc1::account::Account;
use num_bigint::BigUint;
use rusqlite::Connection;
use rusqlite::{CachedStatement, Params, named_params, params};
use serde_bytes::ByteBuf;
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use tracing::{info, trace};

pub const METADATA_FEE_COL: &str = "fee_collector_107";
pub const METADATA_BLOCK_IDX: &str = "highest_processed_block_index";

/// Gets the current value of a counter from the database.
/// Returns None if the counter doesn't exist.
pub fn get_counter_value(
    connection: &Connection,
    counter: &RosettaCounter,
) -> anyhow::Result<Option<i64>> {
    let mut stmt = connection.prepare_cached("SELECT value FROM counters WHERE name = ?1")?;
    let mut rows = stmt.query(params![counter.name()])?;

    match rows.next()? {
        Some(row) => Ok(Some(row.get(0)?)),
        None => Ok(None),
    }
}

/// Sets the value of a counter in the database.
/// Creates the counter if it doesn't exist, updates it if it does.
pub fn set_counter_value(
    connection: &Connection,
    counter: &RosettaCounter,
    value: i64,
) -> anyhow::Result<()> {
    connection
        .prepare_cached("INSERT OR REPLACE INTO counters (name, value) VALUES (?1, ?2)")?
        .execute(params![counter.name(), value])?;
    Ok(())
}

/// Increments a counter by the specified amount.
/// Creates the counter with the increment value if it doesn't exist.
pub fn increment_counter(
    connection: &Connection,
    counter: &RosettaCounter,
    increment: i64,
) -> anyhow::Result<()> {
    connection
        .prepare_cached(
            "INSERT INTO counters (name, value) VALUES (?1, ?2)
             ON CONFLICT(name) DO UPDATE SET value = value + ?2",
        )?
        .execute(params![counter.name(), increment])?;
    Ok(())
}

/// Checks if a counter flag is set (value > 0).
/// Returns false if the counter doesn't exist.
pub fn is_counter_flag_set(
    connection: &Connection,
    counter: &RosettaCounter,
) -> anyhow::Result<bool> {
    if !counter.is_flag() {
        bail!("Counter {} is not a flag counter", counter.name());
    }

    Ok(get_counter_value(connection, counter)?.unwrap_or(0) > 0)
}

/// Sets a counter flag to true (value = 1).
/// Only works with flag counters.
pub fn set_counter_flag(connection: &Connection, counter: &RosettaCounter) -> anyhow::Result<()> {
    if !counter.is_flag() {
        bail!("Counter {} is not a flag counter", counter.name());
    }

    set_counter_value(connection, counter, 1)
}

/// Initializes a counter with its default value if it doesn't exist.
/// For SyncedBlocks, this sets it to the current block count.
pub fn initialize_counter_if_missing(
    connection: &Connection,
    counter: &RosettaCounter,
) -> anyhow::Result<()> {
    match counter {
        RosettaCounter::SyncedBlocks => {
            // Set to current block count if not exists
            connection
                .prepare_cached(
                    "INSERT OR IGNORE INTO counters (name, value) VALUES (?1, (SELECT COUNT(*) FROM blocks))"
                )?
                .execute(params![counter.name()])?;
        }
        RosettaCounter::CollectorBalancesFixed => {
            // Set to default value if not exists
            connection
                .prepare_cached("INSERT OR IGNORE INTO counters (name, value) VALUES (?1, ?2)")?
                .execute(params![counter.name(), counter.default_value()])?;
        }
    }
    Ok(())
}

pub fn get_107_fee_collector_or_legacy(
    rosetta_block: &RosettaBlock,
    connection: &Connection,
    fee_collector_107: Option<Option<Account>>,
) -> anyhow::Result<Option<Account>> {
    // First check if we have a 107 fee collector
    if let Some(fee_collector_107) = fee_collector_107 {
        return Ok(fee_collector_107);
    }

    // There is no 107 fee collector, check legacy fee collector in the block
    get_fee_collector_from_block(rosetta_block, connection)
}

// Helper function to resolve the fee collector account from a block
pub fn get_fee_collector_from_block(
    rosetta_block: &RosettaBlock,
    connection: &Connection,
) -> anyhow::Result<Option<Account>> {
    // First check if the fee collector is directly specified in the block
    if let Some(fee_collector) = rosetta_block.get_fee_collector() {
        return Ok(Some(fee_collector));
    }

    // If not, check if there's a fee_collector_block_index that points to another block
    if let Some(fee_collector_block_index) = rosetta_block.get_fee_collector_block_index() {
        let referenced_block = get_block_at_idx(connection, fee_collector_block_index)?
            .with_context(|| {
                format!(
                    "Block at index {} has fee_collector_block_index {} but there is no block at that index",
                    rosetta_block.index, fee_collector_block_index
                )
            })?;

        if let Some(fee_collector) = referenced_block.get_fee_collector() {
            return Ok(Some(fee_collector));
        } else {
            bail!(
                "Block at index {} has fee_collector_block_index {} but that block has no fee_collector set",
                rosetta_block.index,
                fee_collector_block_index
            );
        }
    }

    // No fee collector found
    Ok(None)
}

pub fn store_metadata(
    connection: &mut Connection,
    metadata: Vec<MetadataEntry>,
) -> anyhow::Result<()> {
    let insert_tx = connection.transaction()?;

    for entry in metadata.into_iter() {
        insert_tx.prepare_cached("INSERT INTO metadata (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = excluded.value;")?.execute(params![entry.key.clone(), entry.value])?;
    }
    insert_tx.commit()?;
    Ok(())
}

pub fn get_metadata(connection: &Connection) -> anyhow::Result<Vec<MetadataEntry>> {
    let mut stmt_metadata = connection.prepare_cached("SELECT key, value FROM metadata")?;
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

pub fn get_rosetta_metadata(connection: &Connection, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
    let mut stmt_metadata = connection.prepare_cached(&format!(
        "SELECT value FROM rosetta_metadata WHERE key = '{key}'"
    ))?;
    let rows = stmt_metadata.query_map(params![], |row| row.get(0))?;
    let mut result = vec![];
    for row in rows {
        let entry: Vec<u8> = row?;
        result.push(entry);
    }
    if result.len() == 1 {
        Ok(Some(result[0].clone()))
    } else if result.is_empty() {
        // Return None if no metadata entry found
        Ok(None)
    } else {
        // If more than one metadata entry was found return an error
        bail!(format!("Multiple metadata entries found for key: {key}"))
    }
}

pub fn update_account_balances(
    connection: &mut Connection,
    flush_cache_and_shrink_memory: bool,
    batch_size: u64,
) -> anyhow::Result<()> {
    // Utility method that tries to fetch the balance from the cache first and, if
    // no balance has been found, fetches it from the database
    fn get_account_balance_with_cache(
        account: &Account,
        index: u64,
        connection: &mut Connection,
        account_balances_cache: &mut HashMap<Account, BTreeMap<u64, Nat>>,
    ) -> anyhow::Result<Option<Nat>> {
        // Either fetch the balance from the cache or from the database
        match account_balances_cache.get(account).map(|balances| {
            balances
                .last_key_value()
                .map(|(_, balance)| balance.clone())
        }) {
            Some(balance) => Ok(balance),
            None => get_account_balance_at_block_idx(connection, account, index),
        }
    }

    fn debit(
        account: Account,
        amount: Nat,
        index: u64,
        connection: &mut Connection,
        account_balances_cache: &mut HashMap<Account, BTreeMap<u64, Nat>>,
    ) -> anyhow::Result<()> {
        let new_balance = if let Some(balance) =
            get_account_balance_with_cache(&account, index, connection, account_balances_cache)?
        {
            Nat(balance.0.checked_sub(&amount.0).with_context(|| {
                format!(
                    "Underflow while debiting account {account} for amount {amount} at index {index} (balance: {balance})"
                )
            })?)
        } else {
            bail!(
                "Trying to debit an account {} that has not yet been allocated any tokens (index: {})",
                account,
                index
            )
        };
        account_balances_cache
            .entry(account)
            .or_default()
            .insert(index, new_balance);
        Ok(())
    }

    fn credit(
        account: Account,
        amount: Nat,
        index: u64,
        connection: &mut Connection,
        account_balances_cache: &mut HashMap<Account, BTreeMap<u64, Nat>>,
    ) -> anyhow::Result<()> {
        let new_balance = if let Some(balance) =
            get_account_balance_with_cache(&account, index, connection, account_balances_cache)?
        {
            Nat(balance.0.checked_add(&amount.0).with_context(|| {
                format!(
                    "Overflow while crediting an account {account} for amount {amount} at index {index} (balance: {balance})"
                )
            })?)
        } else {
            amount
        };
        account_balances_cache
            .entry(account)
            .or_default()
            .insert(index, new_balance);
        Ok(())
    }

    // The next block to be updated is the highest block index in the account balance table + 1 if the table is not empty and 0 otherwise
    let next_block_to_be_updated =
        get_highest_processed_block_idx(connection)?.map_or(0, |idx| idx + 1);
    let highest_block_idx =
        get_block_with_highest_block_idx(connection)?.map_or(0, |block| block.index);

    // If the blocks and account_balance tables show the same max block height then there is nothing that needs to be synced
    if highest_block_idx < next_block_to_be_updated {
        return Ok(());
    }
    let mut batch_start_idx = next_block_to_be_updated;
    let mut batch_end_idx = batch_start_idx + batch_size;
    let mut rosetta_blocks = get_blocks_by_index_range(connection, batch_start_idx, batch_end_idx)?;

    // For faster inserts, keep a cache of the account balances within a batch range in memory
    // This also makes the inserting of the account balances batchable and therefore faster
    let mut account_balances_cache: HashMap<Account, BTreeMap<u64, Nat>> = HashMap::new();

    let mut current_fee_collector_107 = match get_rosetta_metadata(connection, METADATA_FEE_COL)? {
        Some(value) => {
            let fc: Option<Account> = candid::decode_one(&value)?;
            Some(fc)
        }
        None => None,
    };
    let collector_before = current_fee_collector_107;

    // As long as there are blocks to be fetched, keep on iterating over the blocks in the database with the given BATCH_SIZE interval
    while !rosetta_blocks.is_empty() {
        let mut last_block_index = batch_start_idx;
        for rosetta_block in rosetta_blocks {
            if rosetta_block.index < last_block_index {
                bail!(format!(
                    "Processing blocks not in order, previous processed block: {last_block_index}, current block {}",
                    rosetta_block.index
                ));
            }
            last_block_index = rosetta_block.index;
            match rosetta_block.get_transaction().operation {
                crate::common::storage::types::IcrcOperation::Burn {
                    from,
                    amount,
                    fee: _,
                    spender: _,
                } => {
                    let fee = rosetta_block
                        .get_fee_paid()?
                        .unwrap_or(Nat(BigUint::zero()));
                    let burn_amount = Nat(amount.0.checked_add(&fee.0)
                        .with_context(|| format!("Overflow while adding the fee {} to the amount {} for block at index {}",
                            fee, amount, rosetta_block.index
                    ))?);
                    debit(
                        from,
                        burn_amount,
                        rosetta_block.index,
                        connection,
                        &mut account_balances_cache,
                    )?;
                    if let Some(collector) = get_107_fee_collector_or_legacy(
                        &rosetta_block,
                        connection,
                        current_fee_collector_107,
                    )? {
                        credit(
                            collector,
                            fee,
                            rosetta_block.index,
                            connection,
                            &mut account_balances_cache,
                        )?;
                    }
                }
                crate::common::storage::types::IcrcOperation::Mint { to, amount, fee: _ } => {
                    let fee = rosetta_block
                        .get_fee_paid()?
                        .unwrap_or(Nat(BigUint::zero()));
                    let credit_amount = Nat(amount.0.checked_sub(&fee.0)
                        .with_context(|| format!("Underflow while subtracting the fee {} from the amount {} for block at index {}",
                            fee, amount, rosetta_block.index
                    ))?);
                    credit(
                        to,
                        credit_amount,
                        rosetta_block.index,
                        connection,
                        &mut account_balances_cache,
                    )?;
                    if let Some(collector) = get_107_fee_collector_or_legacy(
                        &rosetta_block,
                        connection,
                        current_fee_collector_107,
                    )? {
                        credit(
                            collector,
                            fee,
                            rosetta_block.index,
                            connection,
                            &mut account_balances_cache,
                        )?;
                    }
                }
                crate::common::storage::types::IcrcOperation::Approve {
                    from,
                    spender: _,
                    amount: _,
                    expected_allowance: _,
                    expires_at: _,
                    fee: _,
                } => {
                    let fee = rosetta_block
                        .get_fee_paid()?
                        .unwrap_or(Nat(BigUint::zero()));
                    debit(
                        from,
                        fee.clone(),
                        rosetta_block.index,
                        connection,
                        &mut account_balances_cache,
                    )?;

                    if let Some(Some(collector)) = current_fee_collector_107 {
                        credit(
                            collector,
                            fee,
                            rosetta_block.index,
                            connection,
                            &mut account_balances_cache,
                        )?;
                    }
                }
                crate::common::storage::types::IcrcOperation::Transfer {
                    from,
                    to,
                    amount,
                    spender: _,
                    fee: _,
                } => {
                    let fee = rosetta_block
                        .get_fee_paid()?
                        .unwrap_or(Nat(BigUint::zero()));
                    let payable_amount = Nat(amount.0.checked_add(&fee.0)
                        .with_context(|| format!("Overflow while adding the fee {} to the amount {} for block at index {}",
                            fee, amount, rosetta_block.index
                    ))?);

                    credit(
                        to,
                        amount,
                        rosetta_block.index,
                        connection,
                        &mut account_balances_cache,
                    )?;
                    debit(
                        from,
                        payable_amount,
                        rosetta_block.index,
                        connection,
                        &mut account_balances_cache,
                    )?;

                    if let Some(collector) = get_107_fee_collector_or_legacy(
                        &rosetta_block,
                        connection,
                        current_fee_collector_107,
                    )? {
                        credit(
                            collector,
                            fee,
                            rosetta_block.index,
                            connection,
                            &mut account_balances_cache,
                        )?;
                    }
                }
                crate::common::storage::types::IcrcOperation::FeeCollector {
                    fee_collector,
                    caller: _,
                } => {
                    current_fee_collector_107 = Some(fee_collector);
                }
            }
        }

        // Flush the cache
        let insert_tx = connection.transaction()?;
        for (account, block_idx_new_balances) in account_balances_cache.drain() {
            for (block_idx, new_balance) in block_idx_new_balances {
                insert_tx
                    .prepare_cached("INSERT INTO account_balances (block_idx, principal, subaccount, amount) VALUES (:block_idx, :principal, :subaccount, :amount)")?
                    .execute(named_params! {
                        ":block_idx": block_idx,
                        ":principal": account.owner.as_slice(),
                        ":subaccount": account.effective_subaccount().as_slice(),
                        ":amount": new_balance.to_string(),
                    })?;
            }
        }
        if collector_before != current_fee_collector_107
            && let Some(collector) = current_fee_collector_107
        {
            insert_tx.prepare_cached("INSERT INTO rosetta_metadata (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = excluded.value;")?.execute(params![METADATA_FEE_COL, candid::encode_one(collector)?])?;
        }
        let last_block_index_bytes = last_block_index.to_le_bytes();
        insert_tx.prepare_cached("INSERT INTO rosetta_metadata (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = excluded.value;")?.execute(params![METADATA_BLOCK_IDX, last_block_index_bytes])?;
        insert_tx.commit()?;

        if flush_cache_and_shrink_memory {
            trace!("flushing cache and shrinking memory");
            connection.cache_flush()?;
            connection.pragma_update(None, "shrink_memory", 1)?;
        }

        // Fetch the next batch of blocks
        batch_start_idx = get_highest_processed_block_idx(connection)?
            .context("No blocks in account balance table after inserting")?
            + 1;
        batch_end_idx = batch_start_idx + batch_size;
        rosetta_blocks = get_blocks_by_index_range(connection, batch_start_idx, batch_end_idx)?;
    }
    Ok(())
}

// Stores a batch of RosettaBlocks
pub fn store_blocks(
    connection: &mut Connection,
    rosetta_blocks: Vec<RosettaBlock>,
) -> anyhow::Result<()> {
    let insert_tx = connection.transaction()?;
    for rosetta_block in rosetta_blocks.into_iter() {
        let transaction: crate::common::storage::types::IcrcTransaction =
            rosetta_block.get_transaction();
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
            crate::common::storage::types::IcrcOperation::Mint { to, amount, fee } => (
                "mint",
                None,
                None,
                Some(to.owner),
                Some(*to.effective_subaccount()),
                None,
                None,
                amount,
                None,
                fee,
                None,
            ),
            crate::common::storage::types::IcrcOperation::Transfer {
                from,
                to,
                amount,
                fee,
                ..
            } => (
                "transfer",
                Some(from.owner),
                Some(*from.effective_subaccount()),
                Some(to.owner),
                Some(*to.effective_subaccount()),
                None,
                None,
                amount,
                None,
                fee,
                None,
            ),
            crate::common::storage::types::IcrcOperation::Burn {
                from, amount, fee, ..
            } => (
                "burn",
                Some(from.owner),
                Some(*from.effective_subaccount()),
                None,
                None,
                None,
                None,
                amount,
                None,
                fee,
                None,
            ),
            crate::common::storage::types::IcrcOperation::Approve {
                from,
                spender,
                amount,
                expected_allowance,
                expires_at,
                fee,
            } => (
                "approve",
                Some(from.owner),
                Some(*from.effective_subaccount()),
                None,
                None,
                Some(spender.owner),
                Some(*spender.effective_subaccount()),
                amount,
                expected_allowance,
                fee,
                expires_at,
            ),
            crate::common::storage::types::IcrcOperation::FeeCollector {
                fee_collector,
                caller,
            } => (
                "107feecol",
                caller,
                None,
                fee_collector.map(|fc| fc.owner),
                fee_collector.map(|fc| *fc.effective_subaccount()),
                None,
                None,
                Nat::from(0u64),
                None,
                None,
                None,
            ),
        };

        // SQLite doesn't support unsigned 64-bit integers. We need to convert the timestamps to signed
        // 64-bit integers before storing them.
        // TODO: Change the timestamps to a text type. Keeping timestamps as signed integers can cause
        // issues if someone tries to compare them directly in the DB.
        let timestamp = rosetta_block.get_timestamp();
        let timestamp_i64 = convert_timestamp_to_db(timestamp);
        let transaction_created_at_time_i64 =
            transaction.created_at_time.map(convert_timestamp_to_db);
        let approval_expires_at_i64 = approval_expires_at.map(convert_timestamp_to_db);

        insert_tx.prepare_cached(
        "INSERT OR IGNORE INTO blocks (idx, hash, serialized_block, parent_hash, timestamp,tx_hash,operation_type,from_principal,from_subaccount,to_principal,to_subaccount,spender_principal,spender_subaccount,memo,amount,expected_allowance,fee,transaction_created_at_time,approval_expires_at) VALUES (:idx, :hash, :serialized_block, :parent_hash, :timestamp,:tx_hash,:operation_type,:from_principal,:from_subaccount,:to_principal,:to_subaccount,:spender_principal,:spender_subaccount,:memo,:amount,:expected_allowance,:fee,:transaction_created_at_time,:approval_expires_at)")?
                    .execute(named_params! {
                        ":idx":rosetta_block.index,
                        ":hash":rosetta_block.clone().get_block_hash().as_slice().to_vec(),
                        ":serialized_block":rosetta_block.block,
                        ":parent_hash":rosetta_block.get_parent_hash().clone().map(|hash| hash.as_slice().to_vec()),
                        ":timestamp":timestamp_i64,
                        ":tx_hash":rosetta_block.clone().get_transaction_hash().as_slice().to_vec(),
                        ":operation_type":operation_type,
                        ":from_principal":from_principal.map(|x| x.as_slice().to_vec()),
                        ":from_subaccount":from_subaccount,
                        ":to_principal":to_principal.map(|x| x.as_slice().to_vec()),
                        ":to_subaccount":to_subaccount,
                        ":spender_principal":spender_principal.map(|x| x.as_slice().to_vec()),
                        ":spender_subaccount":spender_subaccount,
                        ":memo":transaction.memo.map(|x| x.0.as_slice().to_vec()),
                        ":amount":amount.to_string(),
                        ":expected_allowance":expected_allowance.map(|ea| ea.to_string()),
                        ":fee":fee.map(|fee| fee.to_string()),
                        ":transaction_created_at_time":transaction_created_at_time_i64,
                        ":approval_expires_at":approval_expires_at_i64
                    })?;
    }
    insert_tx.commit()?;
    Ok(())
}

// Helper function to convert u64 timestamp to i64 for database storage
fn convert_timestamp_to_db(timestamp: u64) -> i64 {
    // Check if timestamp exceeds i64::MAX
    if timestamp > i64::MAX as u64 {
        // For values exceeding i64::MAX, we need to preserve the lower bits
        // but represent them as a negative number in two's complement
        ((timestamp & 0x7fffffffffffffff) as i64) | i64::MIN
    } else {
        // Safe conversion when within i64 range
        timestamp as i64
    }
}

// Returns a RosettaBlock if the block index exists in the database, else returns None.
// Returns an Error if the query fails.
pub fn get_block_at_idx(
    connection: &Connection,
    block_idx: u64,
) -> anyhow::Result<Option<RosettaBlock>> {
    let command = format!("SELECT idx,serialized_block FROM blocks WHERE idx = {block_idx}");
    let mut stmt = connection.prepare_cached(&command)?;
    read_single_block(&mut stmt, params![])
}

// Returns a RosettaBlock with the smallest index larger than block_idx.
// Returns None if there are no blocks with larger index.
// Returns an Error if the query fails.
fn get_block_at_next_idx(
    connection: &Connection,
    block_idx: u64,
) -> anyhow::Result<Option<RosettaBlock>> {
    let command = format!(
        "SELECT idx,serialized_block FROM blocks WHERE idx > {block_idx} ORDER BY idx ASC LIMIT 1"
    );
    let mut stmt = connection.prepare_cached(&command)?;
    read_single_block(&mut stmt, params![])
}

// Returns a RosettaBlock if the block hash exists in the database, else returns None.
// Returns an Error if the query fails.
pub fn get_block_by_hash(
    connection: &Connection,
    hash: ByteBuf,
) -> anyhow::Result<Option<RosettaBlock>> {
    let mut stmt =
        connection.prepare_cached("SELECT idx,serialized_block FROM blocks WHERE hash = ?1")?;
    read_single_block(&mut stmt, params![hash.as_slice().to_vec()])
}

pub fn get_block_with_highest_block_idx(
    connection: &Connection,
) -> anyhow::Result<Option<RosettaBlock>> {
    let command =
        "SELECT idx,serialized_block FROM blocks WHERE idx = (SELECT MAX(idx) FROM blocks)";
    let mut stmt = connection.prepare_cached(command)?;
    read_single_block(&mut stmt, params![])
}

pub fn get_block_with_lowest_block_idx(
    connection: &Connection,
) -> anyhow::Result<Option<RosettaBlock>> {
    let command =
        "SELECT idx,serialized_block FROM blocks WHERE idx = (SELECT MIN(idx) FROM blocks)";
    let mut stmt = connection.prepare_cached(command)?;
    read_single_block(&mut stmt, params![])
}

pub fn get_blocks_by_index_range(
    connection: &Connection,
    start_index: u64,
    end_index: u64,
) -> anyhow::Result<Vec<RosettaBlock>> {
    let command = "SELECT idx,serialized_block FROM blocks WHERE idx>= ?1 AND idx<=?2";
    let mut stmt = connection.prepare_cached(command)?;
    read_blocks(&mut stmt, params![start_index, end_index])
}

pub fn get_blockchain_gaps(
    connection: &Connection,
) -> anyhow::Result<Vec<(RosettaBlock, RosettaBlock)>> {
    // Search for blocks, such that there is no block with index+1.
    let command = "SELECT b1.idx,b1.serialized_block FROM blocks b1 WHERE not exists(select 1 from blocks b2 where b2.idx = b1.idx + 1)";
    let mut stmt = connection.prepare_cached(command)?;
    let gap_starts = read_blocks(&mut stmt, params![])?;
    let mut gap_limits = vec![];

    for gap_start in gap_starts {
        let gap_end = get_block_at_next_idx(connection, gap_start.index)?;
        if let Some(gap_end) = gap_end {
            gap_limits.push((gap_start, gap_end));
        }
    }

    Ok(gap_limits)
}

pub fn get_block_count(connection: &Connection) -> anyhow::Result<u64> {
    let count = get_counter_value(connection, &RosettaCounter::SyncedBlocks)?.unwrap_or(0);
    Ok(count as u64)
}

// Returns icrc1 Transactions if the transaction hash exists in the database, else returns None.
// Returns an Error if the query fails.
pub fn get_blocks_by_transaction_hash(
    connection: &Connection,
    hash: ByteBuf,
) -> anyhow::Result<Vec<RosettaBlock>> {
    let mut stmt =
        connection.prepare_cached("SELECT idx,serialized_block FROM blocks WHERE tx_hash = ?1")?;
    read_blocks(&mut stmt, params![hash.as_slice().to_vec()])
}

pub fn get_highest_processed_block_idx(connection: &Connection) -> anyhow::Result<Option<u64>> {
    match get_rosetta_metadata(connection, METADATA_BLOCK_IDX)? {
        Some(value) => Ok(Some(u64::from_le_bytes(value.as_slice().try_into()?))),
        None => Ok(None),
    }
}

pub fn get_highest_block_idx_in_blocks_table(
    connection: &Connection,
) -> anyhow::Result<Option<u64>> {
    match connection
        .prepare_cached("SELECT MAX(idx) FROM blocks")?
        .query_map(params![], |row| row.get(0))?
        .next()
    {
        None => Ok(None),
        Some(res) => Ok(res?),
    }
}

pub fn get_account_balance_at_highest_block_idx(
    connection: &Connection,
    account: &Account,
) -> anyhow::Result<Option<Nat>> {
    get_account_balance_at_block_idx(connection, account, i64::MAX as u64)
}

pub fn get_account_balance_at_block_idx(
    connection: &Connection,
    account: &Account,
    block_idx: u64,
) -> anyhow::Result<Option<Nat>> {
    Ok(connection
        .prepare_cached(
            "SELECT amount \
             FROM account_balances \
             WHERE principal = :principal \
             AND subaccount = :subaccount \
             AND block_idx <= :block_idx \
             ORDER BY block_idx \
             DESC LIMIT 1",
        )?
        .query(named_params! {
            ":principal": account.owner.as_slice(),
            ":subaccount": account.effective_subaccount(),
            ":block_idx": block_idx
        })?
        .mapped(|row| row.get(0))
        .next()
        .transpose()
        .with_context(|| {
            format!("Unable to fetch balance of account {account} at index {block_idx}")
        })?
        .map(|x: String| Nat::from_str(&x))
        .transpose()?)
}

/// Gets the aggregated balance of all subaccounts for a given principal at a specific block index.
/// Returns the sum of all subaccount balances for the principal.
pub fn get_aggregated_balance_for_principal_at_block_idx(
    connection: &Connection,
    principal: &PrincipalId,
    block_idx: u64,
) -> anyhow::Result<Nat> {
    // Query to get the latest balance for each subaccount of the principal at or before the given block index
    let mut stmt = connection.prepare_cached(
        "SELECT a1.subaccount, a1.amount
         FROM account_balances a1
         WHERE a1.principal = :principal
         AND a1.block_idx = (
             SELECT MAX(a2.block_idx)
             FROM account_balances a2
             WHERE a2.principal = a1.principal
             AND a2.subaccount = a1.subaccount
             AND a2.block_idx <= :block_idx
         )",
    )?;

    let rows = stmt.query_map(
        named_params! {
            ":principal": principal.as_slice(),
            ":block_idx": block_idx
        },
        |row| {
            let amount_str: String = row.get(1)?;
            Nat::from_str(&amount_str).map_err(|_| {
                rusqlite::Error::InvalidColumnType(
                    1,
                    "amount".to_string(),
                    rusqlite::types::Type::Text,
                )
            })
        },
    )?;

    let mut total_balance = Nat(BigUint::zero());
    for balance_result in rows {
        let balance = balance_result?;
        total_balance = Nat(total_balance
            .0
            .checked_add(&balance.0)
            .with_context(|| "Overflow while aggregating balances")?);
    }

    Ok(total_balance)
}

pub fn get_blocks_by_custom_query<P>(
    connection: &Connection,
    sql_query: String,
    params: P,
) -> anyhow::Result<Vec<RosettaBlock>>
where
    P: Params,
{
    let mut stmt = connection.prepare_cached(&sql_query)?;
    read_blocks(&mut stmt, params)
}

pub fn reset_blocks_counter(connection: &Connection) -> anyhow::Result<()> {
    let block_count: i64 = connection
        .prepare_cached("SELECT COUNT(*) FROM blocks")?
        .query_row(params![], |row| row.get(0))?;

    set_counter_value(connection, &RosettaCounter::SyncedBlocks, block_count)
}

fn read_single_block<P>(
    stmt: &mut CachedStatement,
    params: P,
) -> anyhow::Result<Option<RosettaBlock>>
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
        bail!("Multiple blocks found with given parameters".to_owned(),)
    }
}

// Executes the constructed statement that reads blocks. The statement expects two values: The serialized Block and the index of that block
fn read_blocks<P>(stmt: &mut CachedStatement, params: P) -> anyhow::Result<Vec<RosettaBlock>>
where
    P: Params,
{
    let blocks = stmt.query_map(params, |row| {
        Ok(RosettaBlock {
            index: row.get(0)?,
            block: row.get(1)?,
        })
    })?;
    let mut result = vec![];
    for block in blocks {
        result.push(block?);
    }
    Ok(result)
}

/// Repairs account balances for databases created before the fee collector block index fix.
/// This function clears the account_balances table and rebuilds it from scratch using the
/// corrected fee collector resolution logic by reprocessing all blocks.
///
/// This function checks if the repair has already been performed by looking for a
/// "CollectorBalancesFixed" entry in the counters table. If found, it skips the repair.
/// If the repair is performed successfully, it adds the counter entry to prevent future runs.
///
/// This is safe to run multiple times - it will produce the same correct result each time.
pub fn repair_fee_collector_balances(
    connection: &mut Connection,
    balance_sync_batch_size: u64,
) -> anyhow::Result<()> {
    // Check if the repair has already been performed
    if is_counter_flag_set(connection, &RosettaCounter::CollectorBalancesFixed)? {
        // Repair has already been performed, skip it
        return Ok(());
    }

    // Get block count for logging
    let block_count = connection
        .prepare_cached("SELECT COUNT(*) FROM blocks")?
        .query_map(params![], |row| row.get::<_, i64>(0))?
        .next()
        .unwrap()?;

    info!("Starting balance reconciliation...");
    connection.execute("DELETE FROM account_balances", params![])?;
    connection.execute(
        &format!("DELETE FROM rosetta_metadata WHERE key = '{METADATA_BLOCK_IDX}' OR key = '{METADATA_FEE_COL}'"),
        params![],
    )?;

    if block_count > 0 {
        info!("Reprocessing all blocks...");
        update_account_balances(connection, false, balance_sync_batch_size)?;
        info!("Successfully reprocessed all blocks");
    } else {
        info!("No blocks to process (empty database)");
    }

    // Mark the repair as completed by setting the flag
    set_counter_flag(connection, &RosettaCounter::CollectorBalancesFixed)?;

    info!("Balance reconciliation completed successfully");

    Ok(())
}
