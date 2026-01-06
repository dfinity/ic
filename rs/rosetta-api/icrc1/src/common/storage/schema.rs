use crate::common::storage::{
    error::{Result, StorageError},
    storage_operations::{
        METADATA_SCHEMA_VERSION, get_rosetta_metadata, initialize_counter_if_missing,
    },
    types::RosettaCounter,
};
use rusqlite::{Connection, params};

pub const SCHEMA_VERSION: u64 = 1;

/// Creates all the necessary tables for the ICRC1 Rosetta storage system.
/// This function is used by both production code and tests to ensure consistency.
pub fn create_tables(connection: &Connection) -> Result<()> {
    // Metadata table
    connection.execute(
        r#"
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL
        );
        "#,
        [],
    )?;

    // Blocks table
    connection.execute(
        r#"
        CREATE TABLE IF NOT EXISTS blocks (
            idx INTEGER NOT NULL PRIMARY KEY,
            hash BLOB NOT NULL,
            serialized_block BLOB NOT NULL,
            parent_hash BLOB,
            timestamp INTEGER,
            verified BOOLEAN,
            tx_hash BLOB NOT NULL,
            operation_type VARCHAR(255) NOT NULL,
            from_principal BLOB,
            from_subaccount BLOB,
            to_principal BLOB,
            to_subaccount BLOB,
            spender_principal BLOB,
            spender_subaccount BLOB,
            memo BLOB,
            amount TEXT,
            expected_allowance TEXT,
            fee TEXT,
            transaction_created_at_time INTEGER,
            approval_expires_at INTEGER
        )
        "#,
        [],
    )?;

    // Account balances table
    connection.execute(
        r#"
        CREATE TABLE IF NOT EXISTS account_balances (
            block_idx INTEGER NOT NULL,
            principal BLOB NOT NULL,
            subaccount BLOB NOT NULL,
            amount TEXT NOT NULL,
            PRIMARY KEY(principal,subaccount,block_idx)
        )
        "#,
        [],
    )?;

    // Counters table
    // See RosettaCounter enum in types.rs for documentation of available counter values
    connection.execute(
        r#"
        CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL)
        "#,
        [],
    )?;

    // Initialize counters using the new counter management system
    initialize_counter_if_missing(connection, &RosettaCounter::SyncedBlocks)?;

    // The trigger increments the counter of `SyncedBlocks` by 1 whenever a new block is
    // inserted into the blocks table. For transactions that call `INSERT OR IGNORE` and try to
    // insert a block that already exists, the trigger will not be executed. The trigger is
    // executed once for each row that is inserted.
    connection.execute(
        r#"
        CREATE TRIGGER IF NOT EXISTS SyncedBlocksUpdate AFTER INSERT ON blocks
            BEGIN
                UPDATE counters SET value = value + 1 WHERE name = "SyncedBlocks";
            END
        "#,
        [],
    )?;

    // The rosetta_metadata table is meant to store values like the rosetta
    // database schema version, etc. This is different than the metadata
    // table above which stores the ICRC1 token metadata.
    connection.execute(
        r#"
        CREATE TABLE IF NOT EXISTS rosetta_metadata (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL
        );
        "#,
        [],
    )?;

    let stored_schema_version = match get_rosetta_metadata(connection, METADATA_SCHEMA_VERSION)? {
        Some(value) => u64::from_le_bytes(value.as_slice().try_into().map_err(|_| {
            StorageError::DataIntegrity("Invalid schema version bytes".to_string())
        })?),
        None => 0,
    };

    if stored_schema_version > SCHEMA_VERSION {
        return Err(StorageError::DataIntegrity(format!(
            "Selected database has schema version {stored_schema_version} which is incompatible with current schema version {SCHEMA_VERSION}."
        )));
    }

    if stored_schema_version != SCHEMA_VERSION {
        connection.execute(
        "INSERT INTO rosetta_metadata (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = excluded.value;",
        params![METADATA_SCHEMA_VERSION, SCHEMA_VERSION.to_le_bytes()],
    )?;
    }

    create_indexes(connection)
}

/// Creates all the necessary indexes for optimal query performance.
pub fn create_indexes(connection: &Connection) -> Result<()> {
    connection.execute(
        r#"
        CREATE INDEX IF NOT EXISTS block_idx_account_balances
        ON account_balances(block_idx)
        "#,
        [],
    )?;

    connection.execute(
        r#"
        CREATE INDEX IF NOT EXISTS tx_hash_index
        ON blocks(tx_hash)
        "#,
        [],
    )?;

    connection.execute(
        r#"
        CREATE INDEX IF NOT EXISTS block_hash_index
        ON blocks(hash)
        "#,
        [],
    )?;

    Ok(())
}
