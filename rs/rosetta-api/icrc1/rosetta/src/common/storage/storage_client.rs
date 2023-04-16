use super::{storage_operations, types::RosettaBlock};
use anyhow::Result;
use rusqlite::Connection;
use serde_bytes::ByteBuf;
use std::{path::Path, sync::Mutex};

#[derive(Debug)]
pub struct StorageClient {
    storage_connection: Mutex<Connection>,
}

impl StorageClient {
    /// Constructs a new SQLite in-persistent store.
    pub fn new_persistent(db_file_path: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(db_file_path.parent().unwrap())?;
        let connection = rusqlite::Connection::open(db_file_path)?;
        Self::new(connection)
    }

    /// Constructs a new SQLite in-memory store.
    pub fn new_in_memory() -> anyhow::Result<Self> {
        let connection = rusqlite::Connection::open_in_memory()?;
        Self::new(connection)
    }

    fn new(connection: rusqlite::Connection) -> anyhow::Result<Self> {
        let storage_client = Self {
            storage_connection: Mutex::new(connection),
        };
        storage_client
            .storage_connection
            .lock()
            .unwrap()
            .execute("PRAGMA foreign_keys = 1", [])?;
        storage_client.create_tables()?;
        Ok(storage_client)
    }

    // Gets a block with a certain index. Returns None if no block exists in the database with that index. Returns an error if multiple blocks with that index exist
    pub fn get_block_at_idx(&mut self, block_idx: u64) -> anyhow::Result<Option<RosettaBlock>> {
        let mut open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_block_at_idx(&mut open_connection, block_idx)
    }

    // Gets a block with a certain hash. Returns None if no block exists in the database with that hash. Returns an error if multiple blocks with that hash exist
    pub fn get_block_by_hash(&mut self, hash: ByteBuf) -> anyhow::Result<Option<RosettaBlock>> {
        let mut open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_block_by_hash(&mut open_connection, hash)
    }

    // Gets the block with the highest block index. Returns None if no block exists in the database
    pub fn get_block_with_highest_block_idx(&mut self) -> anyhow::Result<Option<RosettaBlock>> {
        let mut open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_block_with_highest_block_idx(&mut open_connection)
    }

    // Gets the block with the lowest block index. Returns None if no block exists in the database
    pub fn get_block_with_lowest_block_idx(&mut self) -> anyhow::Result<Option<RosettaBlock>> {
        let mut open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_block_with_lowest_block_idx(&mut open_connection)
    }

    // Returns a range of blocks including the start index and the end index
    // Returns an empty vector if the start index is outside of the range of the database
    // Returns a subsect of the blocks range [start_index,end_index] if the end_index is outside of the range of the database
    pub fn get_blocks_by_index_range(
        &mut self,
        start_index: u64,
        end_index: u64,
    ) -> anyhow::Result<Vec<RosettaBlock>> {
        let mut open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_blocks_by_index_range(&mut open_connection, start_index, end_index)
    }

    fn create_tables(&self) -> Result<(), rusqlite::Error> {
        let open_connection = self.storage_connection.lock().unwrap();
        open_connection.execute(
            r#"
            CREATE TABLE IF NOT EXISTS blocks (
                idx INTEGER NOT NULL PRIMARY KEY,
                hash BLOB NOT NULL,
                serialized_block BLOB NOT NULL,
                parent_hash BLOB,
                verified BOOLEAN)
            "#,
            [],
        )?;
        open_connection.execute(
            r#"
            CREATE TABLE IF NOT EXISTS transactions (
                block_idx INTEGER NOT NULL,
                tx_hash BLOB NOT NULL,
                operation_type VARCHAR(255) NOT NULL,
                from_principal BLOB,
                from_subaccount BLOB,
                to_principal BLOB,
                to_subaccount BLOB,
                memo BLOB,
                amount INTEGER,
                fee INTEGER,
                transaction_created_at_time INTEGER,
                PRIMARY KEY(block_idx),
                FOREIGN KEY(block_idx) REFERENCES blocks(idx)
            )
            "#,
            [],
        )?;
        open_connection.execute(
            r#"
            CREATE TABLE IF NOT EXISTS account_balance_history (
                principal BLOB NOT NULL,
                subaccount BLOB NOT NULL,
                block_idx  NOT NULL,
                tokens INTEGER NOT NULL,
                PRIMARY KEY(principal,subaccount,block_idx)
                FOREIGN KEY(block_idx) REFERENCES blocks(idx)
            )
            "#,
            [],
        )?;
        Ok(())
    }

    pub fn store_blocks(&mut self, blocks: Vec<RosettaBlock>) -> anyhow::Result<()> {
        let mut open_connection = self.storage_connection.lock().unwrap();
        storage_operations::store_blocks(&mut open_connection, blocks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::utils::unit_test_utils::create_tmp_dir;
    use crate::common::utils::unit_test_utils::strategies::blocks_strategy;
    use proptest::prelude::*;
    #[test]
    fn smoke_test() {
        let storage_client_memory = StorageClient::new_in_memory();
        assert!(storage_client_memory.is_ok());
        let tmpdir = create_tmp_dir();
        let file_path = tmpdir.path().join("db.sqlite");
        let storage_client_persistent = StorageClient::new_persistent(&file_path);
        assert!(storage_client_persistent.is_ok());
    }
    proptest! {
    #[test]
    fn test_read_and_write_blocks(block in blocks_strategy(),index in (0..10000u64)){
        let mut storage_client_memory = StorageClient::new_in_memory().unwrap();
            let rosetta_block = RosettaBlock::from_icrc_ledger_block(block,index).unwrap();
            storage_client_memory.store_blocks(vec![rosetta_block.clone()]).unwrap();
                let block_read = storage_client_memory.get_block_at_idx(index).unwrap().unwrap();
                assert_eq!(block_read,rosetta_block);
                let block_read = storage_client_memory.get_block_by_hash(rosetta_block.clone().block_hash).unwrap().unwrap();
                assert_eq!(block_read,rosetta_block);
            }

        #[test]
    fn test_highest_lowest_block_index(blocks in prop::collection::vec(blocks_strategy(),1..100)){
        let mut storage_client_memory = StorageClient::new_in_memory().unwrap();
        let mut rosetta_blocks = vec![];
        for (index,block) in blocks.clone().into_iter().enumerate(){
            rosetta_blocks.push(RosettaBlock::from_icrc_ledger_block(block,index as u64).unwrap());
        }
        storage_client_memory.store_blocks(rosetta_blocks).unwrap();
        let block_read = storage_client_memory.get_block_with_highest_block_idx().unwrap().unwrap();
        // Indexing starts at 0
        assert_eq!(block_read.index,(blocks.len() as u64)-1);
        let block_read = storage_client_memory.get_block_with_lowest_block_idx().unwrap().unwrap();
        assert_eq!(block_read.index,0);
        let blocks_read = storage_client_memory.get_blocks_by_index_range(0,blocks.len() as u64).unwrap();
        // Storage should return all blocks that are stored
        assert_eq!(blocks_read.len(),blocks.len());
        let blocks_read = storage_client_memory.get_blocks_by_index_range(blocks.len() as u64 +1,blocks.len() as u64 +2).unwrap();
        // Start index is outside of the index range of the blocks stored in the database -> Should return an empty vector
        assert!(blocks_read.is_empty());
        let blocks_read = storage_client_memory.get_blocks_by_index_range(1,blocks.len() as u64 + 2).unwrap();
        // End index is outside of the blocks stored in the database --> Returns subset of blocks stored in the database
        assert_eq!(blocks_read.len(),blocks.len().saturating_sub(1));
            }
        }
}
