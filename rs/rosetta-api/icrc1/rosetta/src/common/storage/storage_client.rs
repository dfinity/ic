use super::{storage_operations, types::RosettaBlock};
use anyhow::Result;
use ic_icrc1::Transaction;
use ic_icrc1_tokens_u64::U64;
use rusqlite::Connection;
use serde_bytes::ByteBuf;
use std::{path::Path, sync::Mutex};

type Tokens = U64;

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
    pub fn get_block_at_idx(&self, block_idx: u64) -> anyhow::Result<Option<RosettaBlock>> {
        let open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_block_at_idx(&open_connection, block_idx)
    }

    // Gets a block with a certain hash. Returns None if no block exists in the database with that hash. Returns an error if multiple blocks with that hash exist
    pub fn get_block_by_hash(&self, hash: ByteBuf) -> anyhow::Result<Option<RosettaBlock>> {
        let open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_block_by_hash(&open_connection, hash)
    }

    // Gets the block with the highest block index. Returns None if no block exists in the database
    pub fn get_block_with_highest_block_idx(&self) -> anyhow::Result<Option<RosettaBlock>> {
        let open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_block_with_highest_block_idx(&open_connection)
    }

    // Gets the block with the lowest block index. Returns None if no block exists in the database
    pub fn get_block_with_lowest_block_idx(&self) -> anyhow::Result<Option<RosettaBlock>> {
        let open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_block_with_lowest_block_idx(&open_connection)
    }

    // Returns a range of blocks including the start index and the end index
    // Returns an empty vector if the start index is outside of the range of the database
    // Returns a subsect of the blocks range [start_index,end_index] if the end_index is outside of the range of the database
    pub fn get_blocks_by_index_range(
        &self,
        start_index: u64,
        end_index: u64,
    ) -> anyhow::Result<Vec<RosettaBlock>> {
        let open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_blocks_by_index_range(&open_connection, start_index, end_index)
    }

    /// Returns all the gaps in the stored blockchain
    /// Gaps are defined as a range of blocks with indices [a+1,b-1] where the Blocks Block(a) and Block(b) exist in the database but the blocks with indices in the range (a,b) do not
    /// Exp.: If there exists exactly one gap betwen the indices [a+1,b-1], then this function will return a vector with a single entry that contains the tuple of blocks [(Block(a),Block(b))]
    pub fn get_blockchain_gaps(&self) -> anyhow::Result<Vec<(RosettaBlock, RosettaBlock)>> {
        let open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_blockchain_gaps(&open_connection)
    }

    // Gets a transaction with a certain hash. Returns [] if no transaction exists in the database with that hash. Returns a vector with multiple entries if more than one transaction
    // with the given transaction hash exists
    pub fn get_transaction_by_hash(
        &self,
        hash: ByteBuf,
    ) -> anyhow::Result<Vec<Transaction<Tokens>>> {
        let open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_transactions_by_hash(&open_connection, hash)
    }

    // Gets a transaction with a certain index. Returns None if no transaction exists in the database with that index. Returns an error if multiple transactions with that index exist
    pub fn get_transaction_at_idx(
        &self,
        block_idx: u64,
    ) -> anyhow::Result<Option<Transaction<Tokens>>> {
        let open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_transaction_at_idx(&open_connection, block_idx)
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
        Ok(())
    }

    pub fn store_blocks(&self, blocks: Vec<RosettaBlock>) -> anyhow::Result<()> {
        let open_connection = self.storage_connection.lock().unwrap();
        storage_operations::store_blocks(&open_connection, blocks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::utils::unit_test_utils::create_tmp_dir;
    use ic_icrc1::Block;
    use ic_icrc1_test_utils::{
        arb_small_amount, blocks_strategy, valid_blockchain_with_gaps_strategy,
    };
    use ic_ledger_core::block::BlockType;
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
       fn test_read_and_write_blocks(block in blocks_strategy(arb_small_amount()),index in (0..10000u64)){
           let storage_client_memory = StorageClient::new_in_memory().unwrap();
           let rosetta_block = RosettaBlock::from_icrc_ledger_block(block,index).unwrap();
           storage_client_memory.store_blocks(vec![rosetta_block.clone()]).unwrap();
           let block_read = storage_client_memory.get_block_at_idx(index).unwrap().unwrap();
           assert_eq!(block_read,rosetta_block);
           let block_read = storage_client_memory.get_block_by_hash(rosetta_block.clone().block_hash).unwrap().unwrap();
           assert_eq!(block_read,rosetta_block);
       }

       #[test]
       fn test_read_and_write_transactions(blockchain in valid_blockchain_with_gaps_strategy(1000)){
           let storage_client_memory = StorageClient::new_in_memory().unwrap();
           let mut rosetta_blocks = vec![];
           for (index,block) in blockchain.into_iter().enumerate(){
               rosetta_blocks.push(RosettaBlock::from_icrc_ledger_block(block,index as u64).unwrap());
           }
           storage_client_memory.store_blocks(rosetta_blocks.clone()).unwrap();
           for block in rosetta_blocks.clone(){
               let tx0 = Block::decode(block.encoded_block).unwrap().transaction;
               let tx1 = Block::decode(storage_client_memory.get_block_at_idx(block.index).unwrap().unwrap().encoded_block).unwrap().transaction;
               let tx2 = storage_client_memory.get_transaction_at_idx(block.index).unwrap().unwrap();
               let tx3 = &storage_client_memory.get_transaction_by_hash(block.transaction_hash).unwrap().clone()[0];
               assert_eq!(tx0,tx1);
               assert_eq!(tx1,tx2);
               assert_eq!(tx2,*tx3);
           }

           if !rosetta_blocks.is_empty() {
           // If the index is out of range the function should return None
           assert!(storage_client_memory.get_transaction_at_idx(rosetta_blocks[rosetta_blocks.len().saturating_sub(1)].index+1).unwrap().is_none());

           // Duplicate the last transaction generated
           let duplicate_tx_block = RosettaBlock::from_icrc_ledger_block(Block::decode(rosetta_blocks[rosetta_blocks.len().saturating_sub(1)].encoded_block.clone()).unwrap(),rosetta_blocks.len() as u64).unwrap();
           storage_client_memory.store_blocks([duplicate_tx_block.clone()].to_vec()).unwrap();

           // The hash of the duplicated transaction should still be the same --> There should be two transactions with the same transaction hash
           assert_eq!(storage_client_memory.get_transaction_by_hash(duplicate_tx_block.transaction_hash).unwrap().len(),2  );
           }
        }

       #[test]
       fn test_highest_lowest_block_index(blocks in prop::collection::vec(blocks_strategy(arb_small_amount()),1..100)){
           let storage_client_memory = StorageClient::new_in_memory().unwrap();
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

       #[test]
       fn test_deriving_gaps_from_storage(blockchain in valid_blockchain_with_gaps_strategy(1000)){
           let storage_client_memory = StorageClient::new_in_memory().unwrap();
           let mut rosetta_blocks = vec![];
           for (index,block) in blockchain.into_iter().enumerate(){
               rosetta_blocks.push(RosettaBlock::from_icrc_ledger_block(block,index as u64).unwrap());
           }

           storage_client_memory.store_blocks(rosetta_blocks.clone()).unwrap();

           // This function will return a list of all the non consecutive intervals
           let non_consecutive_intervals = |blocks: Vec<u64>| {
                   if blocks.is_empty() {
                   return vec![];
               }
               let mut block_ranges = vec![];
               for i in 1..blocks.len() {
                   if blocks[i] != blocks[i - 1] + 1 {
                        block_ranges.push((blocks[i - 1], blocks[i]));
                   }
               }
               block_ranges
           };

           // Fetch the database gaps and map them to indices tuples
           let derived_gaps = storage_client_memory.get_blockchain_gaps().unwrap().into_iter().map(|(a,b)| (a.index,b.index)).collect::<Vec<(u64,u64)>>();

           // If the database is empty the returned gaps vector should simply be empty
           if rosetta_blocks.last().is_some(){
               let gaps = non_consecutive_intervals(rosetta_blocks.clone().into_iter().map(|b|b.index).collect());

               // Compare the storage with the test function
               assert_eq!(gaps,derived_gaps);
           }
           else{
               assert!(derived_gaps.is_empty())
           }
        }
    }
}
