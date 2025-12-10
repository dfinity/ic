use super::storage_operations;
use crate::common::storage::types::{MetadataEntry, RosettaBlock};
use anyhow::{Result, bail};
use candid::Nat;
use ic_base_types::CanisterId;
use icrc_ledger_types::icrc1::account::Account;
use rosetta_core::metrics::RosettaMetrics;
use serde_bytes::ByteBuf;
use std::cmp::Ordering;
use std::path::Path;
use tokio_rusqlite::Connection;
use tracing::warn;

const BALANCE_SYNC_BATCH_SIZE_DEFAULT: u64 = 100_000;

fn to_rusqlite_result<T>(result: anyhow::Result<T>) -> std::result::Result<T, rusqlite::Error> {
    result.map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))
}

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
    storage_connection: Connection,
    token_info: Option<TokenInfo>,
    flush_cache_and_shrink_memory: bool,
    balance_sync_batch_size: u64,
}

impl StorageClient {
    /// Constructs a new SQLite in-persistent store.
    pub async fn new_persistent(db_file_path: &Path) -> anyhow::Result<Self> {
        Self::new_persistent_with_cache_and_batch_size(
            db_file_path,
            None,
            false,
            Some(BALANCE_SYNC_BATCH_SIZE_DEFAULT),
        )
        .await
    }

    /// Constructs a new SQLite in-persistent store with custom cache size and batch size.
    pub async fn new_persistent_with_cache_and_batch_size(
        db_file_path: &Path,
        cache_size_kb: Option<i64>,
        flush_cache_shrink_mem: bool,
        balance_sync_batch_size: Option<u64>,
    ) -> anyhow::Result<Self> {
        std::fs::create_dir_all(db_file_path.parent().unwrap())?;
        let connection = Connection::open(db_file_path).await?;
        let batch_size = balance_sync_batch_size.unwrap_or(BALANCE_SYNC_BATCH_SIZE_DEFAULT);
        Self::new(
            connection,
            cache_size_kb,
            flush_cache_shrink_mem,
            batch_size,
        )
        .await
    }

    /// Constructs a new SQLite in-memory store.
    pub async fn new_in_memory() -> anyhow::Result<Self> {
        let connection = Connection::open_in_memory().await?;
        Self::new(connection, None, false, BALANCE_SYNC_BATCH_SIZE_DEFAULT).await
    }

    /// Constructs a new SQLite in-memory store with a name for shared access.
    /// This allows multiple connections to access the same in-memory database.
    pub async fn new_named_in_memory(name: &str) -> anyhow::Result<Self> {
        let uri = format!("file:{}?mode=memory&cache=shared", name);
        let connection = Connection::open(&uri).await?;
        Self::new(connection, None, false, BALANCE_SYNC_BATCH_SIZE_DEFAULT).await
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

    async fn new(
        connection: Connection,
        cache_size_kb: Option<i64>,
        flush_cache_and_shrink_memory: bool,
        balance_sync_batch_size: u64,
    ) -> anyhow::Result<Self> {
        connection
            .call(move |conn| {
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
                        tracing::info!(
                            "Flushing cache and shrinking memory after updating balances."
                        )
                    }
                    false => {
                        tracing::info!(
                            "Not flushing cache and shrinking memory after updating balances."
                        )
                    }
                }

                tracing::info!("Using balance sync batch size {}", balance_sync_batch_size);

                // Create tables
                super::schema::create_tables(conn)?;

                Ok(())
            })
            .await?;

        let storage_client = Self {
            storage_connection: connection,
            token_info: None,
            flush_cache_and_shrink_memory,
            balance_sync_batch_size,
        };

        // Run the fee collector balances repair if needed
        tracing::info!(
            "Storage initialization: Checking if fee collector balance repair is needed"
        );
        storage_client.repair_fee_collector_balances().await?;

        Ok(storage_client)
    }

    pub fn initialize(&mut self, token_info: TokenInfo) {
        self.token_info = Some(token_info);
    }

    pub async fn does_blockchain_have_gaps(&self) -> anyhow::Result<bool> {
        let Some(highest_block_idx) = self.get_highest_block_idx().await? else {
            // If the blockchain is empty, there are no gaps.
            return Ok(false);
        };
        let block_count = self.get_block_count().await?;
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
    pub async fn get_block_at_idx(&self, block_idx: u64) -> anyhow::Result<Option<RosettaBlock>> {
        Ok(self
            .storage_connection
            .call(move |conn| {
                to_rusqlite_result(storage_operations::get_block_at_idx(conn, block_idx))
            })
            .await?)
    }

    // Gets a block with a certain hash. Returns `None` if no block exists in the database with that hash. Returns an error if multiple blocks with that hash exist.
    pub async fn get_block_by_hash(&self, hash: ByteBuf) -> anyhow::Result<Option<RosettaBlock>> {
        Ok(self
            .storage_connection
            .call(move |conn| to_rusqlite_result(storage_operations::get_block_by_hash(conn, hash)))
            .await?)
    }

    // Gets the block with the highest block index. Returns `None` if no block exists in the database.
    pub async fn get_block_with_highest_block_idx(&self) -> anyhow::Result<Option<RosettaBlock>> {
        Ok(self
            .storage_connection
            .call(move |conn| {
                to_rusqlite_result(storage_operations::get_block_with_highest_block_idx(conn))
            })
            .await?)
    }

    // Gets the block with the lowest block index. Returns `None` if no block exists in the database.
    pub async fn get_block_with_lowest_block_idx(&self) -> anyhow::Result<Option<RosettaBlock>> {
        Ok(self
            .storage_connection
            .call(move |conn| {
                to_rusqlite_result(storage_operations::get_block_with_lowest_block_idx(conn))
            })
            .await?)
    }

    // Returns a range of blocks including the start index and the end index.
    // Returns an empty vector if the start index is outside of the range of the database.
    // Returns a subsect of the blocks range [start_index,end_index] if the end_index is outside of the range of the database.
    pub async fn get_blocks_by_index_range(
        &self,
        start_index: u64,
        end_index: u64,
    ) -> anyhow::Result<Vec<RosettaBlock>> {
        Ok(self
            .storage_connection
            .call(move |conn| {
                to_rusqlite_result(storage_operations::get_blocks_by_index_range(
                    conn,
                    start_index,
                    end_index,
                ))
            })
            .await?)
    }

    /// Returns all the gaps in the stored blockchain.
    /// Gaps are defined as a range of blocks with indices [a+1,b-1] where the Blocks Block(a) and Block(b) exist in the database but the blocks with indices in the range (a,b) do not.
    /// Exp.: If there exists exactly one gap between the indices [a+1,b-1], then this function will return a vector with a single entry that contains the tuple of blocks [(Block(a),Block(b))].
    pub async fn get_blockchain_gaps(&self) -> anyhow::Result<Vec<(RosettaBlock, RosettaBlock)>> {
        Ok(self
            .storage_connection
            .call(move |conn| to_rusqlite_result(storage_operations::get_blockchain_gaps(conn)))
            .await?)
    }

    pub async fn get_highest_block_idx(&self) -> Result<Option<u64>> {
        Ok(self
            .storage_connection
            .call(move |conn| {
                to_rusqlite_result(storage_operations::get_highest_block_idx_in_blocks_table(
                    conn,
                ))
            })
            .await?)
    }

    // Gets a transaction with a certain hash. Returns [] if no transaction exists in the database with that hash. Returns a vector with multiple entries if more than one transaction
    // with the given transaction hash exists
    pub async fn get_transactions_by_hash(
        &self,
        hash: ByteBuf,
    ) -> anyhow::Result<Vec<crate::common::storage::types::IcrcTransaction>> {
        Ok(self
            .get_blocks_by_transaction_hash(hash)
            .await?
            .into_iter()
            .map(|block| block.get_transaction())
            .collect::<Vec<crate::common::storage::types::IcrcTransaction>>())
    }

    pub async fn get_blocks_by_custom_query(
        &self,
        sql_query: String,
        params: Vec<(String, rusqlite::types::Value)>,
    ) -> anyhow::Result<Vec<RosettaBlock>> {
        Ok(self
            .storage_connection
            .call(move |conn| {
                // Convert Vec<(String, Value)> to the format rusqlite expects
                let params_refs: Vec<(&str, &dyn rusqlite::ToSql)> = params
                    .iter()
                    .map(|(k, v)| (k.as_str(), v as &dyn rusqlite::ToSql))
                    .collect();
                to_rusqlite_result(storage_operations::get_blocks_by_custom_query(
                    conn,
                    sql_query,
                    params_refs.as_slice(),
                ))
            })
            .await?)
    }

    pub async fn get_blocks_by_transaction_hash(
        &self,
        hash: ByteBuf,
    ) -> anyhow::Result<Vec<RosettaBlock>> {
        Ok(self
            .storage_connection
            .call(move |conn| {
                to_rusqlite_result(storage_operations::get_blocks_by_transaction_hash(
                    conn, hash,
                ))
            })
            .await?)
    }

    // Gets a transaction with a certain index. Returns None if no transaction exists in the database with that index. Returns an error if multiple transactions with that index exist.
    pub async fn get_transaction_at_idx(
        &self,
        block_idx: u64,
    ) -> anyhow::Result<Option<crate::common::storage::types::IcrcTransaction>> {
        Ok(self
            .get_block_at_idx(block_idx)
            .await?
            .map(|block| block.get_transaction()))
    }

    pub async fn read_metadata(&self) -> anyhow::Result<Vec<MetadataEntry>> {
        Ok(self
            .storage_connection
            .call(move |conn| to_rusqlite_result(storage_operations::get_metadata(conn)))
            .await?)
    }

    pub async fn write_metadata(&self, metadata: Vec<MetadataEntry>) -> anyhow::Result<()> {
        Ok(self
            .storage_connection
            .call(move |conn| {
                to_rusqlite_result(storage_operations::store_metadata(conn, metadata))
            })
            .await?)
    }

    pub async fn reset_blocks_counter(&self) -> Result<()> {
        Ok(self
            .storage_connection
            .call(move |conn| to_rusqlite_result(storage_operations::reset_blocks_counter(conn)))
            .await?)
    }

    // Populates the blocks and transactions table by the Rosettablocks provided
    // This function does NOT populate the account_balance table.
    pub async fn store_blocks(&self, blocks: Vec<RosettaBlock>) -> anyhow::Result<()> {
        Ok(self
            .storage_connection
            .call(move |conn| to_rusqlite_result(storage_operations::store_blocks(conn, blocks)))
            .await?)
    }

    // Extracts the information from the transaction and blocks table and fills the account balance table with that information
    // Throws an error if there are gaps in the transaction or blocks table.
    pub async fn update_account_balances(&self) -> anyhow::Result<()> {
        if self.does_blockchain_have_gaps().await? {
            bail!("Tried to update account balances but there exist gaps in the database.",);
        }
        let flush_cache_and_shrink_memory = self.flush_cache_and_shrink_memory;
        let balance_sync_batch_size = self.balance_sync_batch_size;
        Ok(self
            .storage_connection
            .call(move |conn| {
                to_rusqlite_result(storage_operations::update_account_balances(
                    conn,
                    flush_cache_and_shrink_memory,
                    balance_sync_batch_size,
                ))
            })
            .await?)
    }

    /// Retrieves the highest block index in the account balance table.
    /// Returns None if the account balance table is empty.
    pub async fn get_highest_block_idx_in_account_balance_table(&self) -> Result<Option<u64>> {
        Ok(self
            .storage_connection
            .call(move |conn| {
                to_rusqlite_result(
                    storage_operations::get_highest_block_idx_in_account_balance_table(conn),
                )
            })
            .await?)
    }

    // Retrieves the account balance at a certain block height
    // Returns None if the account does not exist in the database
    pub async fn get_account_balance_at_block_idx(
        &self,
        account: &Account,
        block_idx: u64,
    ) -> anyhow::Result<Option<Nat>> {
        let account = *account;
        Ok(self
            .storage_connection
            .call(move |conn| {
                to_rusqlite_result(storage_operations::get_account_balance_at_block_idx(
                    conn, &account, block_idx,
                ))
            })
            .await?)
    }

    // Retrieves the account balance at the heighest block height in the database
    // Returns None if the account does not exist in the database
    pub async fn get_account_balance(&self, account: &Account) -> anyhow::Result<Option<Nat>> {
        let account = *account;
        Ok(self
            .storage_connection
            .call(move |conn| {
                to_rusqlite_result(
                    storage_operations::get_account_balance_at_highest_block_idx(conn, &account),
                )
            })
            .await?)
    }

    // Retrieves the aggregated balance of all subaccounts for a given principal at a specific block height
    pub async fn get_aggregated_balance_for_principal_at_block_idx(
        &self,
        principal: &ic_base_types::PrincipalId,
        block_idx: u64,
    ) -> anyhow::Result<Nat> {
        let principal = *principal;
        Ok(self
            .storage_connection
            .call(move |conn| {
                to_rusqlite_result(
                    storage_operations::get_aggregated_balance_for_principal_at_block_idx(
                        conn, &principal, block_idx,
                    ),
                )
            })
            .await?)
    }

    pub async fn get_block_count(&self) -> anyhow::Result<u64> {
        Ok(self
            .storage_connection
            .call(move |conn| to_rusqlite_result(storage_operations::get_block_count(conn)))
            .await?)
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
    pub async fn repair_fee_collector_balances(&self) -> anyhow::Result<()> {
        let balance_sync_batch_size = self.balance_sync_batch_size;
        Ok(self
            .storage_connection
            .call(move |conn| {
                to_rusqlite_result(storage_operations::repair_fee_collector_balances(
                    conn,
                    balance_sync_batch_size,
                ))
            })
            .await?)
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
        arb_amount, blocks_strategy, metadata_strategy, valid_blockchain_with_gaps_strategy,
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
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let storage_client_memory = StorageClient::new_in_memory().await;
            assert!(storage_client_memory.is_ok());
            let tmpdir = create_tmp_dir();
            let file_path = tmpdir.path().join("db.sqlite");
            let storage_client_persistent = StorageClient::new_persistent(&file_path).await;
            assert!(storage_client_persistent.is_ok());
        });
    }

    proptest! {
          #[test]
          fn test_read_and_write_blocks_u64(blockchain in prop::collection::vec(blocks_strategy::<U64>(arb_amount()),0..5)){
           let rt = tokio::runtime::Runtime::new().unwrap();
           rt.block_on(async {
           let storage_client_memory = StorageClient::new_in_memory().await.unwrap();
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

           storage_client_memory.store_blocks(rosetta_blocks.clone()).await.unwrap();
           for rosetta_block in rosetta_blocks.into_iter(){
               let block_read = storage_client_memory.get_block_at_idx(rosetta_block.clone().index).await.unwrap().unwrap();
               assert_eq!(block_read,rosetta_block);
               let block_read = storage_client_memory.get_block_by_hash(rosetta_block.clone().get_block_hash()).await.unwrap().unwrap();
               assert_eq!(block_read,rosetta_block);
           }
           })
       }

       #[test]
       fn test_read_and_write_blocks_u256(blockchain in prop::collection::vec(blocks_strategy::<U256>(arb_amount()),0..5)){
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
        let storage_client_memory = StorageClient::new_in_memory().await.unwrap();
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
        storage_client_memory.store_blocks(rosetta_blocks.clone()).await.unwrap();
        for rosetta_block in rosetta_blocks.into_iter(){
            let block_read = storage_client_memory.get_block_at_idx(rosetta_block.clone().index).await.unwrap().unwrap();
            assert_eq!(block_read,rosetta_block);
            let block_read = storage_client_memory.get_block_by_hash(rosetta_block.clone().get_block_hash()).await.unwrap().unwrap();
            assert_eq!(block_read,rosetta_block);
        }
        })
    }

          #[test]
          fn test_read_and_write_transactions(blockchain in valid_blockchain_with_gaps_strategy::<U256>(1000)){
              let rt = tokio::runtime::Runtime::new().unwrap();
              rt.block_on(async {
              let storage_client_memory = StorageClient::new_in_memory().await.unwrap();
              let rosetta_blocks: Vec<_> = blockchain.0.iter().zip(blockchain.1.iter())
                  .map(|(block, index)| RosettaBlock::from_generic_block(encoded_block_to_generic_block(&block.clone().encode()), *index as u64).unwrap())
                  .collect();
              storage_client_memory.store_blocks(rosetta_blocks.clone()).await.unwrap();
              for block in rosetta_blocks.clone(){
                  let tx0 = block.get_transaction();
                  let tx1 = storage_client_memory.get_block_at_idx(block.index).await.unwrap().unwrap().get_transaction();
                  let tx2 = storage_client_memory.get_transaction_at_idx(block.index).await.unwrap().unwrap();
                  let tx3 = &storage_client_memory.get_transactions_by_hash(block.clone().get_transaction_hash()).await.unwrap().clone()[0];
                  assert_eq!(tx0,tx1);
                  assert_eq!(tx1,tx2);
                  assert_eq!(tx2,*tx3);
              }

              if !rosetta_blocks.is_empty() {
               let last_block = &rosetta_blocks[rosetta_blocks.len().saturating_sub(1)];
              // If the index is out of range the function should return `None`.
              assert!(storage_client_memory.get_transaction_at_idx(last_block.index+1).await.unwrap().is_none());

              // Duplicate the last transaction generated
              let duplicate_tx_block = RosettaBlock::from_generic_block(last_block.get_generic_block(), last_block.index + 1).unwrap();
              storage_client_memory.store_blocks([duplicate_tx_block.clone()].to_vec()).await.unwrap();

              // The hash of the duplicated transaction should still be the same --> There should be two transactions with the same transaction hash.
              assert_eq!(storage_client_memory.get_transactions_by_hash(duplicate_tx_block.clone().get_transaction_hash()).await.unwrap().len(),2);
              }
           })
           }

          #[test]
          fn test_highest_lowest_block_index(blocks in prop::collection::vec(blocks_strategy::<U256>(arb_amount::<U256>()),1..100)){
              let rt = tokio::runtime::Runtime::new().unwrap();
              rt.block_on(async {
              let storage_client_memory = StorageClient::new_in_memory().await.unwrap();
              let mut rosetta_blocks = vec![];
              for (index,block) in blocks.clone().into_iter().enumerate(){
                  rosetta_blocks.push(RosettaBlock::from_generic_block(encoded_block_to_generic_block(&block.encode()),index as u64).unwrap());
              }
              storage_client_memory.store_blocks(rosetta_blocks).await.unwrap();
              let block_read = storage_client_memory.get_block_with_highest_block_idx().await.unwrap().unwrap();
              // Indexing starts at 0.
              assert_eq!(block_read.index,(blocks.len() as u64)-1);
              let block_read = storage_client_memory.get_block_with_lowest_block_idx().await.unwrap().unwrap();
              assert_eq!(block_read.index,0);
              let blocks_read = storage_client_memory.get_blocks_by_index_range(0,blocks.len() as u64).await.unwrap();
              // Storage should return all blocks that are stored.
              assert_eq!(blocks_read.len(),blocks.len());
              let blocks_read = storage_client_memory.get_blocks_by_index_range(blocks.len() as u64 +1,blocks.len() as u64 +2).await.unwrap();
              // Start index is outside of the index range of the blocks stored in the database -> Should return an empty vector.
              assert!(blocks_read.is_empty());
              let blocks_read = storage_client_memory.get_blocks_by_index_range(1,blocks.len() as u64 + 2).await.unwrap();
              // End index is outside of the blocks stored in the database --> Returns subset of blocks stored in the database.
              assert_eq!(blocks_read.len(),blocks.len().saturating_sub(1));
           })
           }

          #[test]
          fn test_deriving_gaps_from_storage(blockchain in valid_blockchain_with_gaps_strategy::<U256>(1000).no_shrink()){
              let rt = tokio::runtime::Runtime::new().unwrap();
              rt.block_on(async {
              let storage_client_memory = StorageClient::new_in_memory().await.unwrap();
              let mut rosetta_blocks = vec![];
              for i in 0..blockchain.0.len() {
               rosetta_blocks.push(RosettaBlock::from_generic_block(encoded_block_to_generic_block(&blockchain.0[i].clone().encode()),blockchain.1[i] as u64).unwrap());
              }

              storage_client_memory.store_blocks(rosetta_blocks.clone()).await.unwrap();

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
              let derived_gaps = storage_client_memory.get_blockchain_gaps().await.unwrap().into_iter().map(|(a,b)| (a.index,b.index)).collect::<Vec<(u64,u64)>>();
              // Does the blockchain have gaps?
              let has_gaps = storage_client_memory.does_blockchain_have_gaps().await.unwrap();

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
           })
           }

           #[test]
           fn test_read_and_write_metadata(metadata in metadata_strategy()) {
               let rt = tokio::runtime::Runtime::new().unwrap();
               rt.block_on(async {
               let storage_client_memory = StorageClient::new_in_memory().await.unwrap();
               let entries_write = metadata.iter().map(|(key, value)| MetadataEntry::from_metadata_value(key, value)).collect::<Result<Vec<MetadataEntry>>>().unwrap();
               let metadata_write = Metadata::from_metadata_entries(&entries_write).unwrap();
               storage_client_memory.write_metadata(entries_write).await.unwrap();
               let entries_read = storage_client_memory.read_metadata().await.unwrap();
               let metadata_read = Metadata::from_metadata_entries(&entries_read).unwrap();

               assert_eq!(metadata_write, metadata_read);
               })
           }

           #[test]
           fn test_updating_account_balances_for_blockchain_with_gaps(blockchain in valid_blockchain_with_gaps_strategy::<U256>(1000)){
               let rt = tokio::runtime::Runtime::new().unwrap();
               rt.block_on(async {
               let storage_client_memory = StorageClient::new_in_memory().await.unwrap();
               let mut rosetta_blocks = vec![];
               for i in 0..blockchain.0.len() {
                rosetta_blocks.push(RosettaBlock::from_encoded_block(&blockchain.0[i].clone().encode(),blockchain.1[i] as u64).unwrap());
               }

               storage_client_memory.store_blocks(rosetta_blocks.clone()).await.unwrap();

               if !storage_client_memory.get_blockchain_gaps().await.unwrap().is_empty(){
               // Updating of account balances should not be possible if the stored blockchain contains gaps
               assert!(storage_client_memory.update_account_balances().await.is_err())
               }
           })
           }
       }
}
