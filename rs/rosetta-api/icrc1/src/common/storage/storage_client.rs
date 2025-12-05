use super::storage_operations;
use crate::common::storage::types::{MetadataEntry, RosettaBlock};
use anyhow::{Result, bail};
use candid::Nat;
use ic_base_types::CanisterId;
use icrc_ledger_types::icrc1::account::Account;
use rosetta_core::metrics::RosettaMetrics;
use rusqlite::{Connection, OpenFlags};
use serde_bytes::ByteBuf;
use std::cmp::Ordering;
use std::{path::Path, sync::Mutex};
use tracing::warn;

const BALANCE_SYNC_BATCH_SIZE_DEFAULT: u64 = 100_000;

#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub symbol: String,
    pub decimals: u8,
    pub ledger_id: CanisterId,
    pub rosetta_metrics: RosettaMetrics,
}

// We use format "[symbol]-[canisterId[:5]]" so that it covers cases in which
// we track tokens with the same symbols while keeping it short by only showing
// the first 5 characters of the canister ID.
fn display_name(symbol: String, ledger_id: CanisterId) -> String {
    format!(
        "{}-{}",
        symbol,
        ledger_id
            .to_string()
            .as_str()
            .chars()
            .take(5)
            .collect::<String>()
    )
}

impl TokenInfo {
    pub fn new(symbol: String, decimals: u8, ledger_id: CanisterId) -> Self {
        let canister_id_str = ledger_id.to_string();
        Self {
            symbol: symbol.clone(),
            decimals,
            ledger_id,
            rosetta_metrics: RosettaMetrics::new(display_name(symbol, ledger_id), canister_id_str),
        }
    }

    pub fn display_name(&self) -> String {
        display_name(self.symbol.clone(), self.ledger_id)
    }
}

#[derive(Debug)]
pub struct StorageClient {
    storage_connection: Mutex<Connection>,
    token_info: Option<TokenInfo>,
    flush_cache_and_shrink_memory: bool,
    balance_sync_batch_size: u64,
}

impl StorageClient {
    /// Constructs a new SQLite in-persistent store.
    pub fn new_persistent(db_file_path: &Path) -> anyhow::Result<Self> {
        Self::new_persistent_with_cache_and_batch_size(
            db_file_path,
            None,
            false,
            Some(BALANCE_SYNC_BATCH_SIZE_DEFAULT),
        )
    }

    /// Constructs a new SQLite in-persistent store with custom cache size and batch size.
    pub fn new_persistent_with_cache_and_batch_size(
        db_file_path: &Path,
        cache_size_kb: Option<i64>,
        flush_cache_shrink_mem: bool,
        balance_sync_batch_size: Option<u64>,
    ) -> anyhow::Result<Self> {
        std::fs::create_dir_all(db_file_path.parent().unwrap())?;
        let connection = rusqlite::Connection::open(db_file_path)?;
        let batch_size = balance_sync_batch_size.unwrap_or(BALANCE_SYNC_BATCH_SIZE_DEFAULT);
        Self::new(
            connection,
            cache_size_kb,
            flush_cache_shrink_mem,
            batch_size,
        )
    }

    /// Constructs a new SQLite in-memory store.
    pub fn new_in_memory() -> anyhow::Result<Self> {
        let connection = rusqlite::Connection::open_in_memory()?;
        Self::new(connection, None, false, BALANCE_SYNC_BATCH_SIZE_DEFAULT)
    }

    /// Constructs a new SQLite in-memory store with a named DB that can be shared across instances.
    pub fn new_named_in_memory(name: &str) -> anyhow::Result<Self> {
        let connection = Connection::open_with_flags(
            format!("'file:{name}?mode=memory&cache=shared', uri=True"),
            OpenFlags::default(),
        )?;
        Self::new(connection, None, false, BALANCE_SYNC_BATCH_SIZE_DEFAULT)
    }

    pub fn get_token_display_name(&self) -> String {
        if let Some(token_info) = &self.token_info {
            token_info.display_name()
        } else {
            "unknown".to_string()
        }
    }

    pub fn get_metrics(&self) -> RosettaMetrics {
        if let Some(token_info) = &self.token_info {
            token_info.rosetta_metrics.clone()
        } else {
            RosettaMetrics::new("unknown".to_string(), "unknown".to_string())
        }
    }

    fn new(
        connection: rusqlite::Connection,
        cache_size_kb: Option<i64>,
        flush_cache_and_shrink_memory: bool,
        balance_sync_batch_size: u64,
    ) -> anyhow::Result<Self> {
        let storage_client = Self {
            storage_connection: Mutex::new(connection),
            token_info: None,
            flush_cache_and_shrink_memory,
            balance_sync_batch_size,
        };
        let conn = storage_client.storage_connection.lock().unwrap();

        conn.pragma_update(None, "foreign_keys", 1)?;

        match cache_size_kb {
            None => {
                tracing::info!("No cache size configured");
            }
            Some(cache_kb) => {
                let cache_size = -cache_kb; // Negative to specify KB
                conn.pragma_update(None, "cache_size", cache_size)?;
                tracing::info!("SQLite cache_size set to {} KB", cache_kb);
            }
        }

        match flush_cache_and_shrink_memory {
            true => {
                tracing::info!("Flushing cache and shrinking memory after updating balances.")
            }
            false => {
                tracing::info!("Not flushing cache and shrinking memory after updating balances.")
            }
        }

        tracing::info!("Using balance sync batch size {}", balance_sync_batch_size);

        drop(conn);

        storage_client.create_tables()?;

        // Run the fee collector balances repair if needed
        tracing::info!(
            "Storage initialization: Checking if fee collector balance repair is needed"
        );
        storage_client.repair_fee_collector_balances()?;

        Ok(storage_client)
    }

    pub fn initialize(&mut self, token_info: TokenInfo) {
        self.token_info = Some(token_info);
    }

    pub fn does_blockchain_have_gaps(&self) -> anyhow::Result<bool> {
        let Some(highest_block_idx) = self.get_highest_block_idx()? else {
            // If the blockchain is empty, there are no gaps.
            return Ok(false);
        };
        let block_count = self.get_block_count()?;
        match block_count.cmp(&highest_block_idx.saturating_add(1)) {
            Ordering::Equal => Ok(false),
            Ordering::Less => {
                warn!(
                    "block_count ({}) is less than highest_block_idx.saturating_add(1) ({}), indicating one of more gaps in the blockchain.",
                    block_count,
                    highest_block_idx.saturating_add(1)
                );
                Ok(true)
            }
            Ordering::Greater => {
                panic!(
                    "block_count ({}) is larger than highest_block_idx.saturating_add(1) ({}) -> invalid state!",
                    block_count,
                    highest_block_idx.saturating_add(1)
                );
            }
        }
    }

    // Gets a block with a certain index. Returns `None` if no block exists in the database with that index. Returns an error if multiple blocks with that index exist.
    pub fn get_block_at_idx(&self, block_idx: u64) -> anyhow::Result<Option<RosettaBlock>> {
        let open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_block_at_idx(&open_connection, block_idx)
    }

    // Gets a block with a certain hash. Returns `None` if no block exists in the database with that hash. Returns an error if multiple blocks with that hash exist.
    pub fn get_block_by_hash(&self, hash: ByteBuf) -> anyhow::Result<Option<RosettaBlock>> {
        let open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_block_by_hash(&open_connection, hash)
    }

    // Gets the block with the highest block index. Returns `None` if no block exists in the database.
    pub fn get_block_with_highest_block_idx(&self) -> anyhow::Result<Option<RosettaBlock>> {
        let open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_block_with_highest_block_idx(&open_connection)
    }

    // Gets the block with the lowest block index. Returns `None` if no block exists in the database.
    pub fn get_block_with_lowest_block_idx(&self) -> anyhow::Result<Option<RosettaBlock>> {
        let open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_block_with_lowest_block_idx(&open_connection)
    }

    // Returns a range of blocks including the start index and the end index.
    // Returns an empty vector if the start index is outside of the range of the database.
    // Returns a subsect of the blocks range [start_index,end_index] if the end_index is outside of the range of the database.
    pub fn get_blocks_by_index_range(
        &self,
        start_index: u64,
        end_index: u64,
    ) -> anyhow::Result<Vec<RosettaBlock>> {
        let open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_blocks_by_index_range(&open_connection, start_index, end_index)
    }

    /// Returns all the gaps in the stored blockchain.
    /// Gaps are defined as a range of blocks with indices [a+1,b-1] where the Blocks Block(a) and Block(b) exist in the database but the blocks with indices in the range (a,b) do not.
    /// Exp.: If there exists exactly one gap between the indices [a+1,b-1], then this function will return a vector with a single entry that contains the tuple of blocks [(Block(a),Block(b))].
    pub fn get_blockchain_gaps(&self) -> anyhow::Result<Vec<(RosettaBlock, RosettaBlock)>> {
        let open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_blockchain_gaps(&open_connection)
    }

    pub fn get_highest_block_idx(&self) -> Result<Option<u64>> {
        let open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_highest_block_idx_in_blocks_table(&open_connection)
    }

    // Gets a transaction with a certain hash. Returns [] if no transaction exists in the database with that hash. Returns a vector with multiple entries if more than one transaction
    // with the given transaction hash exists
    pub fn get_transactions_by_hash(
        &self,
        hash: ByteBuf,
    ) -> anyhow::Result<Vec<crate::common::storage::types::IcrcTransaction>> {
        Ok(self
            .get_blocks_by_transaction_hash(hash)?
            .into_iter()
            .map(|block| block.get_transaction())
            .collect::<Vec<crate::common::storage::types::IcrcTransaction>>())
    }

    pub fn get_blocks_by_custom_query<P>(
        &self,
        sql_query: String,
        params: P,
    ) -> anyhow::Result<Vec<RosettaBlock>>
    where
        P: rusqlite::Params,
    {
        let open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_blocks_by_custom_query(&open_connection, sql_query, params)
    }

    pub fn get_blocks_by_transaction_hash(
        &self,
        hash: ByteBuf,
    ) -> anyhow::Result<Vec<RosettaBlock>> {
        let open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_blocks_by_transaction_hash(&open_connection, hash)
    }

    // Gets a transaction with a certain index. Returns None if no transaction exists in the database with that index. Returns an error if multiple transactions with that index exist.
    pub fn get_transaction_at_idx(
        &self,
        block_idx: u64,
    ) -> anyhow::Result<Option<crate::common::storage::types::IcrcTransaction>> {
        Ok(self
            .get_block_at_idx(block_idx)?
            .map(|block| block.get_transaction()))
    }

    pub fn read_metadata(&self) -> anyhow::Result<Vec<MetadataEntry>> {
        let open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_metadata(&open_connection)
    }

    pub fn write_metadata(&self, metadata: Vec<MetadataEntry>) -> anyhow::Result<()> {
        let mut open_connection = self.storage_connection.lock().unwrap();
        storage_operations::store_metadata(&mut open_connection, metadata)
    }

    pub fn reset_blocks_counter(&self) -> Result<()> {
        let open_connection = self.storage_connection.lock().unwrap();
        storage_operations::reset_blocks_counter(&open_connection)
    }

    fn create_tables(&self) -> Result<(), rusqlite::Error> {
        let open_connection = self.storage_connection.lock().unwrap();
        super::schema::create_tables(&open_connection)
    }

    // Populates the blocks and transactions table by the Rosettablocks provided
    // This function does NOT populate the account_balance table.
    pub fn store_blocks(&self, blocks: Vec<RosettaBlock>) -> anyhow::Result<()> {
        let mut open_connection = self.storage_connection.lock().unwrap();
        storage_operations::store_blocks(&mut open_connection, blocks)
    }

    // Extracts the information from the transaction and blocks table and fills the account balance table with that information
    // Throws an error if there are gaps in the transaction or blocks table.
    pub fn update_account_balances(&self) -> anyhow::Result<()> {
        if self.does_blockchain_have_gaps()? {
            bail!("Tried to update account balances but there exist gaps in the database.",);
        }
        let mut open_connection = self.storage_connection.lock().unwrap();
        storage_operations::update_account_balances(
            &mut open_connection,
            self.flush_cache_and_shrink_memory,
            self.balance_sync_batch_size,
        )
    }

    /// Retrieves the highest block index in the account balance table.
    /// Returns None if the account balance table is empty.
    pub fn get_highest_block_idx_in_account_balance_table(&self) -> Result<Option<u64>> {
        let open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_highest_block_idx_in_account_balance_table(&open_connection)
    }

    // Retrieves the account balance at a certain block height
    // Returns None if the account does not exist in the database
    pub fn get_account_balance_at_block_idx(
        &self,
        account: &Account,
        block_idx: u64,
    ) -> anyhow::Result<Option<Nat>> {
        let open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_account_balance_at_block_idx(&open_connection, account, block_idx)
    }

    // Retrieves the account balance at the heighest block height in the database
    // Returns None if the account does not exist in the database
    pub fn get_account_balance(&self, account: &Account) -> anyhow::Result<Option<Nat>> {
        let open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_account_balance_at_highest_block_idx(&open_connection, account)
    }

    // Retrieves the aggregated balance of all subaccounts for a given principal at a specific block height
    pub fn get_aggregated_balance_for_principal_at_block_idx(
        &self,
        principal: &ic_base_types::PrincipalId,
        block_idx: u64,
    ) -> anyhow::Result<Nat> {
        let open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_aggregated_balance_for_principal_at_block_idx(
            &open_connection,
            principal,
            block_idx,
        )
    }

    pub fn get_block_count(&self) -> anyhow::Result<u64> {
        let open_connection = self.storage_connection.lock().unwrap();
        storage_operations::get_block_count(&open_connection)
    }

    /// Repairs account balances for databases created before the fee collector block index fix.
    /// This function identifies Transfer operations that used fee_collector_block_index but didn't
    /// properly credit the fee collector, and adds the missing fee credits.
    ///
    /// This is safe to run multiple times - it will only add missing credits and won't duplicate them.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the repair was successful, or an error if the repair failed.
    pub fn repair_fee_collector_balances(&self) -> anyhow::Result<()> {
        let mut open_connection = self.storage_connection.lock().unwrap();
        storage_operations::repair_fee_collector_balances(
            &mut open_connection,
            self.balance_sync_batch_size,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Metadata;
    use ic_icrc1::Block;
    use ic_icrc1::blocks::encoded_block_to_generic_block;
    use ic_icrc1::blocks::generic_block_to_encoded_block;
    use ic_icrc1_test_utils::{
        arb_amount, blocks_strategy, metadata_strategy, valid_blockchain_strategy,
        valid_blockchain_with_gaps_strategy,
    };
    use ic_icrc1_tokens_u64::U64;
    use ic_icrc1_tokens_u256::U256;
    use ic_ledger_canister_core::ledger::LedgerTransaction;
    use ic_ledger_core::block::BlockType;
    use proptest::prelude::*;

    fn create_tmp_dir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("test_tmp_")
            .tempdir_in(".")
            .unwrap()
    }

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
          fn test_read_and_write_blocks_u64(blockchain in valid_blockchain_strategy::<U64>(5)){
           let storage_client_memory = StorageClient::new_in_memory().unwrap();
           let mut rosetta_blocks = vec![];
           for (index,block) in blockchain.into_iter().enumerate(){
               // Make sure rosetta blocks store the correct transactions
               let rosetta_block = RosettaBlock::from_encoded_block(&block.clone().encode(),index as u64).unwrap();
               // Assert the block hashes match up
               assert_eq!(rosetta_block.clone().get_block_hash(),ByteBuf::from(<Block<U64> as BlockType>::block_hash(&block.clone().encode()).as_slice().to_vec()));
               let derived_encoded_block = generic_block_to_encoded_block(rosetta_block.get_generic_block()).unwrap();
               let derived_block = Block::<U64>::decode(derived_encoded_block.clone()).unwrap();
               // Assert that the transactions from the original U64 block and the derived one from rosetta block match up
               assert_eq!(derived_block.transaction,block.transaction.clone());
               assert_eq!(rosetta_block.clone().get_transaction_hash(),ByteBuf::from(block.transaction.hash().as_slice()));
               // Make sure the encoding and decoding works
               rosetta_blocks.push(rosetta_block)
           }

           storage_client_memory.store_blocks(rosetta_blocks.clone()).unwrap();
           for rosetta_block in rosetta_blocks.into_iter(){
               let block_read = storage_client_memory.get_block_at_idx(rosetta_block.clone().index).unwrap().unwrap();
               assert_eq!(block_read,rosetta_block);
               let block_read = storage_client_memory.get_block_by_hash(rosetta_block.clone().get_block_hash()).unwrap().unwrap();
               assert_eq!(block_read,rosetta_block);
           }
       }

       #[test]
       fn test_read_and_write_blocks_u256(blockchain in valid_blockchain_strategy::<U256>(5)){
        let storage_client_memory = StorageClient::new_in_memory().unwrap();
        let mut rosetta_blocks = vec![];
        for (index,block) in blockchain.into_iter().enumerate(){
               // Make sure rosetta blocks store the correct transactions
               let rosetta_block = RosettaBlock::from_encoded_block(&block.clone().encode(),index as u64).unwrap();
               // Assert the block hashes match up
               assert_eq!(rosetta_block.clone().get_block_hash(),ByteBuf::from(<Block<U256> as BlockType>::block_hash(&block.clone().encode()).as_slice().to_vec()));
               let derived_encoded_block = generic_block_to_encoded_block(rosetta_block.get_generic_block()).unwrap();
               let derived_block = Block::<U256>::decode(derived_encoded_block.clone()).unwrap();
               // Assert that the transactions from the original U256 block and the derived one from rosetta block match up
               assert_eq!(derived_block.transaction,block.transaction.clone());
               assert_eq!(rosetta_block.clone().get_transaction_hash(),ByteBuf::from(block.transaction.hash().as_slice()));
               // Make sure the encoding and decoding works
               rosetta_blocks.push(rosetta_block)
        }
        storage_client_memory.store_blocks(rosetta_blocks.clone()).unwrap();
        for rosetta_block in rosetta_blocks.into_iter(){
            let block_read = storage_client_memory.get_block_at_idx(rosetta_block.clone().index).unwrap().unwrap();
            assert_eq!(block_read,rosetta_block);
            let block_read = storage_client_memory.get_block_by_hash(rosetta_block.clone().get_block_hash()).unwrap().unwrap();
            assert_eq!(block_read,rosetta_block);
        }
    }

          #[test]
          fn test_read_and_write_transactions(blockchain in valid_blockchain_with_gaps_strategy::<U256>(1000)){
              let storage_client_memory = StorageClient::new_in_memory().unwrap();
              let rosetta_blocks: Vec<_> = blockchain.0.iter().zip(blockchain.1.iter())
                  .map(|(block, index)| RosettaBlock::from_generic_block(encoded_block_to_generic_block(&block.clone().encode()), *index as u64).unwrap())
                  .collect();
              storage_client_memory.store_blocks(rosetta_blocks.clone()).unwrap();
              for block in rosetta_blocks.clone(){
                  let tx0 = block.get_transaction();
                  let tx1 = storage_client_memory.get_block_at_idx(block.index).unwrap().unwrap().get_transaction();
                  let tx2 = storage_client_memory.get_transaction_at_idx(block.index).unwrap().unwrap();
                  let tx3 = &storage_client_memory.get_transactions_by_hash(block.clone().get_transaction_hash()).unwrap().clone()[0];
                  assert_eq!(tx0,tx1);
                  assert_eq!(tx1,tx2);
                  assert_eq!(tx2,*tx3);
              }

              if !rosetta_blocks.is_empty() {
               let last_block = &rosetta_blocks[rosetta_blocks.len().saturating_sub(1)];
              // If the index is out of range the function should return `None`.
              assert!(storage_client_memory.get_transaction_at_idx(last_block.index+1).unwrap().is_none());

              // Duplicate the last transaction generated
              let duplicate_tx_block = RosettaBlock::from_generic_block(last_block.get_generic_block(), last_block.index + 1).unwrap();
              let count_before = storage_client_memory.get_transactions_by_hash(duplicate_tx_block.clone().get_transaction_hash()).unwrap().len();
              storage_client_memory.store_blocks([duplicate_tx_block.clone()].to_vec()).unwrap();

              // The hash of the duplicated transaction should still be the same --> There should be one more transaction with the same transaction hash.
              assert_eq!(storage_client_memory.get_transactions_by_hash(duplicate_tx_block.clone().get_transaction_hash()).unwrap().len(), count_before + 1);
              //assert_eq!(storage_client_memory.get_transactions_by_hash(duplicate_tx_block.clone().get_transaction_hash()).unwrap().len(),2, "{}", format!("duplicate_tx_block: {:?}, hash {:?}",duplicate_tx_block, duplicate_tx_block.clone().get_transaction_hash()));
              }
           }

          #[test]
          fn test_highest_lowest_block_index(blocks in prop::collection::vec(blocks_strategy::<U256>(arb_amount::<U256>()),1..100)){
              let storage_client_memory = StorageClient::new_in_memory().unwrap();
              let mut rosetta_blocks = vec![];
              for (index,block) in blocks.clone().into_iter().enumerate(){
                  rosetta_blocks.push(RosettaBlock::from_generic_block(encoded_block_to_generic_block(&block.encode()),index as u64).unwrap());
              }
              storage_client_memory.store_blocks(rosetta_blocks).unwrap();
              let block_read = storage_client_memory.get_block_with_highest_block_idx().unwrap().unwrap();
              // Indexing starts at 0.
              assert_eq!(block_read.index,(blocks.len() as u64)-1);
              let block_read = storage_client_memory.get_block_with_lowest_block_idx().unwrap().unwrap();
              assert_eq!(block_read.index,0);
              let blocks_read = storage_client_memory.get_blocks_by_index_range(0,blocks.len() as u64).unwrap();
              // Storage should return all blocks that are stored.
              assert_eq!(blocks_read.len(),blocks.len());
              let blocks_read = storage_client_memory.get_blocks_by_index_range(blocks.len() as u64 +1,blocks.len() as u64 +2).unwrap();
              // Start index is outside of the index range of the blocks stored in the database -> Should return an empty vector.
              assert!(blocks_read.is_empty());
              let blocks_read = storage_client_memory.get_blocks_by_index_range(1,blocks.len() as u64 + 2).unwrap();
              // End index is outside of the blocks stored in the database --> Returns subset of blocks stored in the database.
              assert_eq!(blocks_read.len(),blocks.len().saturating_sub(1));
           }

          #[test]
          fn test_deriving_gaps_from_storage(blockchain in valid_blockchain_with_gaps_strategy::<U256>(1000).no_shrink()){
              let storage_client_memory = StorageClient::new_in_memory().unwrap();
              let mut rosetta_blocks = vec![];
              for i in 0..blockchain.0.len() {
               rosetta_blocks.push(RosettaBlock::from_generic_block(encoded_block_to_generic_block(&blockchain.0[i].clone().encode()),blockchain.1[i] as u64).unwrap());
              }

              storage_client_memory.store_blocks(rosetta_blocks.clone()).unwrap();

              // This function will return a list of all the non consecutive intervals.
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

              // Fetch the database gaps and map them to indices tuples.
              let derived_gaps = storage_client_memory.get_blockchain_gaps().unwrap().into_iter().map(|(a,b)| (a.index,b.index)).collect::<Vec<(u64,u64)>>();
              // Does the blockchain have gaps?
              let has_gaps = storage_client_memory.does_blockchain_have_gaps().unwrap();

              // If the database is empty the returned gaps vector should simply be empty.
              if rosetta_blocks.last().is_some(){
                  let gaps = non_consecutive_intervals(rosetta_blocks.clone().into_iter().map(|b|b.index).collect());

                  // Compare the storage with the test function.
                  assert_eq!(gaps,derived_gaps);

                  assert!(has_gaps);
              }
              else{
                  assert!(derived_gaps.is_empty());

                  assert!(!has_gaps);
              }
           }

           #[test]
           fn test_read_and_write_metadata(metadata in metadata_strategy()) {
               let storage_client_memory = StorageClient::new_in_memory().unwrap();
               let entries_write = metadata.iter().map(|(key, value)| MetadataEntry::from_metadata_value(key, value)).collect::<Result<Vec<MetadataEntry>>>().unwrap();
               let metadata_write = Metadata::from_metadata_entries(&entries_write).unwrap();
               storage_client_memory.write_metadata(entries_write).unwrap();
               let entries_read = storage_client_memory.read_metadata().unwrap();
               let metadata_read = Metadata::from_metadata_entries(&entries_read).unwrap();

               assert_eq!(metadata_write, metadata_read);
           }

           #[test]
           fn test_updating_account_balances_for_blockchain_with_gaps(blockchain in valid_blockchain_with_gaps_strategy::<U256>(1000)){
               let storage_client_memory = StorageClient::new_in_memory().unwrap();
               let mut rosetta_blocks = vec![];
               for i in 0..blockchain.0.len() {
                rosetta_blocks.push(RosettaBlock::from_encoded_block(&blockchain.0[i].clone().encode(),blockchain.1[i] as u64).unwrap());
               }

               storage_client_memory.store_blocks(rosetta_blocks.clone()).unwrap();

               if !storage_client_memory.get_blockchain_gaps().unwrap().is_empty(){
               // Updating of account balances should not be possible if the stored blockchain contains gaps
               assert!(storage_client_memory.update_account_balances().is_err())
               }
           }
       }
}
